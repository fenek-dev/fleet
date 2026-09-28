//! Bulk action engine (design §7.3).
//!
//! Runs one operation (or one per target) across many servers:
//!
//! - at most `concurrency` servers at a time (default 16);
//! - **canary**: the first target runs alone, then a [`HealthProbe`] must
//!   pass before the rest start; a canary failure always stops the run;
//! - **stop on failure**: once any server fails nothing new is dispatched
//!   (servers already running finish), the rest are skipped;
//! - a per-server timeout and a [`CancelToken`] (in-flight servers become
//!   `Cancelled`: their outcome is unknown, never reported as success);
//! - **dry run**: ops with a plan counterpart (`profile.apply` →
//!   `profile.plan`, `firewall.apply` → `firewall.get`) fetch it; others
//!   report the command that would be sent. Nothing is signed for a change;
//! - **approvals**: an Elevated run asks the [`Approver`] once, before
//!   anything runs, for one root approval whose Merkle tree covers every
//!   target (`fleet_crypto::approval::build_approvals`). Each server's
//!   command is still signed by the device key when it is dispatched
//!   (§6.4), so canary pacing never makes envelopes stale.
//!
//! Progress is reported per server through a callback. The engine is
//! executor-agnostic ([`BulkExecutor`]): the app uses [`ManagerHandle`],
//! tests use in-memory fakes, and SSH snippets plug in with [`run_with`].

use crate::escalate::{self, EscalationBatcher};
use crate::manager::{ManagerHandle, RequestError, RequestOpts};
use crate::session::ClientError;
use crate::signer::{DeviceSigner, KeyRole, RoleSigner, root_reason};
use crate::versions::{self, PROBE_VERSION, VersionSource};
use fleet_crypto::approval::{ApprovalParams, build_approvals, op_digest};
use fleet_proto::{
    Actor, ApprovalItem, DeviceId, ErrorCode, FleetId, Op, Payload, RootApproval, ServerId,
};
use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::Notify;

pub type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

pub const DEFAULT_CONCURRENCY: usize = 16;
pub const MAX_CONCURRENCY: usize = 64;
pub const MAX_TARGETS: usize = 1000;

/// Why one server's command failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The agent answered with a signed error code.
    Agent(ErrorCode),
    UnknownServer,
    NotReady(String),
    /// The app is locked (monitor session).
    Locked,
    Timeout,
    /// Sent, but no valid receipt came back: it may or may not have run.
    OutcomeUnknown,
    Transport(String),
    /// SSH exec finished with a non-zero (or no) exit status; `output` is
    /// the server's (untrusted) stdout+stderr, capped.
    ExitStatus {
        status: Option<u32>,
        output: String,
    },
}

/// What one server produced.
#[derive(Debug, Clone, PartialEq)]
pub enum Output {
    Payload(Payload),
    /// SSH exec (snippets run as the admin user).
    Exec {
        status: Option<u32>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    /// Dry runs only: the command that would be sent (no plan op).
    Command(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Plan {
    /// Answer of the `*.plan` counterpart (or current state to diff against).
    Fetched(Payload),
    /// No plan op: the command that would be sent.
    Command(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    StoppedAfterFailure,
    CanaryFailed,
    Cancelled,
    ApprovalDenied,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Succeeded(Output),
    Failed(Failure),
    Skipped(SkipReason),
    /// Cancelled while in flight: the outcome is unknown.
    Cancelled,
    Planned(Plan),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    CanaryFailed,
    HealthCheckFailed(String),
    Failure,
    Cancelled,
    ApprovalDenied(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum BulkEvent {
    Started { total: usize, needs_approval: bool },
    Approved { servers: usize },
    Running { server: ServerId },
    Finished { server: ServerId, outcome: Outcome },
    CanaryPassed { server: ServerId },
    Done(BulkSummary),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BulkSummary {
    pub succeeded: usize,
    pub failed: usize,
    pub skipped: usize,
    pub cancelled: usize,
    pub planned: usize,
    pub stop: Option<StopReason>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BulkReport {
    pub outcomes: Vec<(ServerId, Outcome)>,
    pub summary: BulkSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BulkError {
    #[error("no targets")]
    NoTargets,
    #[error("too many targets")]
    TooManyTargets,
    #[error("server {0} listed twice")]
    DuplicateTarget(String),
    #[error("stream operations can't run in bulk")]
    StreamOp,
    #[error("invalid arguments for {0}")]
    InvalidArgs(String),
}

// ---- pluggable parts ----

/// Sends one signed command and waits for its verified answer.
pub trait BulkExecutor: Send + Sync {
    fn execute(
        &self,
        server: ServerId,
        op: Op,
        actor: Actor,
        approval: Option<RootApproval>,
    ) -> BoxFut<Result<Payload, Failure>>;

    /// [`BulkExecutor::execute`] with envelope options. Executors that
    /// can't carry `expected_version` refuse rather than drop it.
    fn execute_with(
        &self,
        server: ServerId,
        op: Op,
        actor: Actor,
        opts: RequestOpts,
    ) -> BoxFut<Result<Payload, Failure>> {
        if opts.expected_version.is_some() {
            return Box::pin(async { Err(Failure::Agent(ErrorCode::Unsupported)) });
        }
        self.execute(server, op, actor, opts.approval)
    }
}

impl From<RequestError> for Failure {
    fn from(e: RequestError) -> Self {
        match e {
            RequestError::UnknownServer => Failure::UnknownServer,
            RequestError::NotReady(s) => Failure::NotReady(format!("{s:?}")),
            RequestError::Locked => Failure::Locked,
            RequestError::Timeout => Failure::Timeout,
            RequestError::Stopped => Failure::NotReady("stopped".into()),
            RequestError::Client(ClientError::Rejected(code)) => Failure::Agent(code),
            RequestError::Client(ClientError::OutcomeUnknown { .. }) => Failure::OutcomeUnknown,
            RequestError::Client(e) => Failure::Transport(e.to_string()),
        }
    }
}

impl BulkExecutor for ManagerHandle {
    fn execute(
        &self,
        server: ServerId,
        op: Op,
        actor: Actor,
        approval: Option<RootApproval>,
    ) -> BoxFut<Result<Payload, Failure>> {
        let h = self.clone();
        Box::pin(async move {
            let reply = h.request(&server, op, actor, approval).await?;
            reply.result.map_err(Failure::Agent)
        })
    }

    fn execute_with(
        &self,
        server: ServerId,
        op: Op,
        actor: Actor,
        opts: RequestOpts,
    ) -> BoxFut<Result<Payload, Failure>> {
        let h = self.clone();
        Box::pin(async move {
            let reply = h.request_with(&server, op, actor, opts).await?;
            reply.result.map_err(Failure::Agent)
        })
    }
}

/// Post-canary health check.
pub trait HealthProbe: Send + Sync {
    fn check(&self, server: ServerId) -> BoxFut<Result<(), String>>;
}

/// `agent.health` answers (signed) and no recovery is pending.
pub struct AgentHealthProbe {
    pub exec: Arc<dyn BulkExecutor>,
    pub actor: Actor,
}

impl HealthProbe for AgentHealthProbe {
    fn check(&self, server: ServerId) -> BoxFut<Result<(), String>> {
        let fut = self
            .exec
            .execute(server, Op::AgentHealth, self.actor.clone(), None);
        Box::pin(async move {
            match fut.await {
                Ok(Payload::AgentHealth(h)) if h.pending_recovery.is_none() => Ok(()),
                Ok(Payload::AgentHealth(_)) => Err("recovery pending".into()),
                Ok(_) => Err("unexpected health reply".into()),
                Err(f) => Err(format!("{f:?}")),
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApproveError {
    #[error("cancelled")]
    Cancelled,
    #[error("root key unavailable")]
    Unavailable,
    #[error("approval failed")]
    Failed,
}

/// One root-key decision over many items (blocking; may raise Touch ID).
/// Returns one `RootApproval` per item, in item order.
pub trait Approver: Send + Sync {
    fn approve(
        &self,
        what: &str,
        items: &[ApprovalItem],
    ) -> Result<Vec<RootApproval>, ApproveError>;
}

/// The Secure Enclave root key through [`DeviceSigner`]; the Touch ID
/// prompt names the operation and the number of servers.
pub struct RootApprover {
    pub keys: Arc<dyn DeviceSigner>,
    pub fleet_id: FleetId,
    pub device_id: DeviceId,
    /// At most 30 minutes (`MAX_APPROVAL_LIFETIME_MS`).
    pub lifetime_ms: u64,
}

impl Approver for RootApprover {
    fn approve(
        &self,
        what: &str,
        items: &[ApprovalItem],
    ) -> Result<Vec<RootApproval>, ApproveError> {
        let signer =
            RoleSigner::with_reason(&*self.keys, KeyRole::Root, root_reason(what, items.len()))
                .map_err(|e| match e {
                    crate::signer::SignerError::Cancelled => ApproveError::Cancelled,
                    _ => ApproveError::Unavailable,
                })?;
        let mut approval_id = [0u8; 16];
        fleet_crypto::random_bytes(&mut approval_id).map_err(|_| ApproveError::Failed)?;
        let now = crate::now_ms();
        let params = ApprovalParams {
            fleet_id: self.fleet_id,
            approval_id,
            issued_at_ms: now,
            expires_at_ms: now + self.lifetime_ms,
        };
        build_approvals(&signer, self.device_id, &params, items)
            .map_err(|_| ApproveError::Cancelled)
    }
}

/// Cooperative cancellation shared with the UI.
#[derive(Clone, Default)]
pub struct CancelToken(Arc<(AtomicBool, Notify)>, Arc<(AtomicBool, Notify)>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.0.store(true, Ordering::SeqCst);
        self.0.1.notify_waiters();
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.0.load(Ordering::SeqCst)
    }

    pub async fn cancelled(&self) {
        loop {
            let notified = self.0.1.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }

    /// Stops admitting new servers (running ones finish); [`Self::resume`]
    /// continues. Cancelling overrides a pause.
    pub fn pause(&self) {
        self.1.0.store(true, Ordering::SeqCst);
    }

    pub fn resume(&self) {
        self.1.0.store(false, Ordering::SeqCst);
        self.1.1.notify_waiters();
    }

    pub fn is_paused(&self) -> bool {
        self.1.0.load(Ordering::SeqCst)
    }

    /// Completes once not paused.
    pub async fn resumed(&self) {
        loop {
            let notified = self.1.1.notified();
            if !self.is_paused() {
                return;
            }
            notified.await;
        }
    }
}

#[derive(Clone)]
pub struct BulkOptions {
    pub concurrency: usize,
    pub canary: bool,
    /// Run after the canary succeeds (canary mode only).
    pub health: Option<Arc<dyn HealthProbe>>,
    pub stop_on_failure: bool,
    /// Rollout in batches: `concurrency` servers start together and the next
    /// batch waits until all of them finished (after the canary, if any).
    pub batch_barrier: bool,
    /// Per server; `None` leaves it to the executor (manager timeouts).
    pub per_server_timeout: Option<Duration>,
    pub dry_run: bool,
}

impl Default for BulkOptions {
    fn default() -> Self {
        Self {
            concurrency: DEFAULT_CONCURRENCY,
            canary: false,
            health: None,
            stop_on_failure: true,
            batch_barrier: false,
            per_server_timeout: None,
            dry_run: false,
        }
    }
}

pub struct BulkRequest {
    /// Operation name for prompts (`root_reason`).
    pub label: String,
    pub targets: Vec<(ServerId, Op)>,
    pub actor: Actor,
    pub options: BulkOptions,
    /// `expected_version` per server, as the caller saw it (e.g. the
    /// firewall editor). Version-checked ops on servers not listed read
    /// the current version before dispatch (`crate::versions`).
    pub expected_versions: HashMap<ServerId, u64>,
}

impl BulkRequest {
    /// The same `op` on every target.
    pub fn uniform(targets: Vec<ServerId>, op: Op, actor: Actor, options: BulkOptions) -> Self {
        Self {
            label: op.name().to_string(),
            targets: targets.into_iter().map(|s| (s, op.clone())).collect(),
            actor,
            options,
            expected_versions: HashMap::new(),
        }
    }

    pub fn needs_approval(&self) -> bool {
        !self.options.dry_run
            && self
                .targets
                .iter()
                .any(|(_, op)| crate::opspec::needs_approval(op))
    }
}

/// The read-only op a dry run fetches for `op`, if any.
pub fn plan_op(op: &Op) -> Option<Op> {
    match op {
        Op::ProfileApply { spec, .. } => Some(Op::ProfilePlan(spec.clone())),
        Op::FirewallApply(_) => Some(Op::FirewallGet),
        _ => None,
    }
}

/// Human-readable command for dry runs without a plan op.
pub fn describe(op: &Op) -> String {
    format!("{}: {op:?}", op.name())
}

fn validate(targets: &[ServerId]) -> Result<(), BulkError> {
    if targets.is_empty() {
        return Err(BulkError::NoTargets);
    }
    if targets.len() > MAX_TARGETS {
        return Err(BulkError::TooManyTargets);
    }
    let mut seen: Vec<&ServerId> = targets.iter().collect();
    seen.sort();
    for w in seen.windows(2) {
        if w[0] == w[1] {
            return Err(BulkError::DuplicateTarget(w[0].to_string()));
        }
    }
    Ok(())
}

/// Runs `req`: approval (if Elevated), then [`run_with`]. `emit` sees every
/// event, ending with [`BulkEvent::Done`].
pub async fn run<E: FnMut(BulkEvent) + Send>(
    exec: Arc<dyn BulkExecutor>,
    approver: Option<Arc<dyn Approver>>,
    req: BulkRequest,
    cancel: CancelToken,
    mut emit: E,
) -> Result<BulkReport, BulkError> {
    let servers: Vec<ServerId> = req.targets.iter().map(|(s, _)| s.clone()).collect();
    validate(&servers)?;
    for (s, op) in &req.targets {
        if op.is_stream() {
            return Err(BulkError::StreamOp);
        }
        op.check_args()
            .map_err(|_| BulkError::InvalidArgs(s.to_string()))?;
    }
    let needs_approval = req.needs_approval();
    emit(BulkEvent::Started {
        total: servers.len(),
        needs_approval,
    });

    if req.options.dry_run {
        let targets = req.targets.clone();
        let actor = req.actor.clone();
        let work = move |i: usize| -> BoxFut<Result<Output, Failure>> {
            let (server, op) = targets[i].clone();
            match plan_op(&op) {
                Some(p) => {
                    let fut = exec.execute(server, p, actor.clone(), None);
                    Box::pin(async move { fut.await.map(Output::Payload) })
                }
                None => {
                    let text = describe(&op);
                    Box::pin(async move { Ok(Output::Command(text)) })
                }
            }
        };
        let opts = BulkOptions {
            canary: false,
            stop_on_failure: false,
            ..req.options.clone()
        };
        let report = drive(servers, &opts, &work, &cancel, true, &mut emit).await;
        emit(BulkEvent::Done(report.summary.clone()));
        return Ok(report);
    }

    // Versions first: an approval item covers `(op, expected_version)`.
    let versions = resolve_versions(&*exec, &req, &cancel).await;
    let mut approvals: Vec<Option<RootApproval>> = vec![None; servers.len()];
    let mut approval_items: Vec<Option<ApprovalItem>> = vec![None; servers.len()];
    if needs_approval {
        let idx: Vec<usize> = (0..req.targets.len())
            .filter(|&i| {
                crate::opspec::needs_approval(&req.targets[i].1)
                    && !matches!(versions[i], Ver::Failed(_))
            })
            .collect();
        let items: Vec<ApprovalItem> = idx
            .iter()
            .map(|&i| ApprovalItem {
                server_id: req.targets[i].0.clone(),
                op_digest: op_digest(&req.targets[i].1, versions[i].initial()),
            })
            .collect();
        for (&i, item) in idx.iter().zip(&items) {
            approval_items[i] = Some(item.clone());
        }
        let granted = match approver.clone() {
            None => Err("no approver".to_string()),
            Some(a) => {
                let label = req.label.clone();
                tokio::task::spawn_blocking(move || a.approve(&label, &items))
                    .await
                    .map_err(|_| "approval task failed".to_string())
                    .and_then(|r| r.map_err(|e| e.to_string()))
            }
        };
        match granted {
            Ok(list) if list.len() == idx.len() => {
                for (i, a) in idx.into_iter().zip(list) {
                    approvals[i] = Some(a);
                }
                emit(BulkEvent::Approved {
                    servers: approvals.iter().filter(|a| a.is_some()).count(),
                });
            }
            other => {
                let why = other.err().unwrap_or_else(|| "approval count".into());
                let outcomes: Vec<(ServerId, Outcome)> = servers
                    .into_iter()
                    .map(|s| (s, Outcome::Skipped(SkipReason::ApprovalDenied)))
                    .collect();
                for (s, o) in &outcomes {
                    emit(BulkEvent::Finished {
                        server: s.clone(),
                        outcome: o.clone(),
                    });
                }
                let summary = summarize(&outcomes, Some(StopReason::ApprovalDenied(why)));
                emit(BulkEvent::Done(summary.clone()));
                return Ok(BulkReport { outcomes, summary });
            }
        }
    }

    let expires_at_ms = approvals
        .iter()
        .flatten()
        .filter_map(approval_expiry)
        .min()
        .unwrap_or(u64::MAX);
    let n = servers.len();
    let dispatch = Arc::new(Dispatch {
        escalation: EscalationBatcher::new(approver.clone(), &req.label, escalate::DEFAULT_WINDOW),
        exec,
        approver,
        actor: req.actor,
        targets: req.targets,
        versions,
        approvals: tokio::sync::Mutex::new(ApprovalState {
            list: approvals,
            items: approval_items,
            dispatched: vec![false; n],
            expires_at_ms,
            refresh_failed: false,
        }),
        refresh_margin_ms: APPROVAL_REFRESH_MARGIN_MS,
    });
    let work = move |i: usize| -> BoxFut<Result<Output, Failure>> {
        let d = dispatch.clone();
        Box::pin(async move { d.run(i).await.map(Output::Payload) })
    };
    let report = drive(servers, &req.options, &work, &cancel, false, &mut emit).await;
    emit(BulkEvent::Done(report.summary.clone()));
    Ok(report)
}

/// A long (canary) run asks for a fresh approval for the servers it
/// hasn't dispatched yet once the current one has less than this left.
pub const APPROVAL_REFRESH_MARGIN_MS: u64 = 5 * 60 * 1000;

/// Touch ID reason of that refresh.
pub const APPROVAL_REFRESH_LABEL: &str = "continue bulk run";

fn approval_expiry(a: &RootApproval) -> Option<u64> {
    a.decode_body().ok().map(|b| b.expires_at_ms)
}

/// Per-target `expected_version`.
#[derive(Debug, Clone)]
enum Ver {
    /// The op isn't version-checked.
    None,
    Known(u64),
    /// Send [`PROBE_VERSION`], retry once with the agent's current.
    Probe,
    /// Reading the version failed: the server fails with this.
    Failed(Failure),
}

impl Ver {
    fn initial(&self) -> Option<u64> {
        match self {
            Ver::Known(v) => Some(*v),
            Ver::Probe => Some(PROBE_VERSION),
            Ver::None | Ver::Failed(_) => None,
        }
    }
}

/// Explicit versions from the request, else a read per server (at most
/// `concurrency` at a time).
async fn resolve_versions(
    exec: &dyn BulkExecutor,
    req: &BulkRequest,
    cancel: &CancelToken,
) -> Vec<Ver> {
    let mut out: Vec<Ver> = Vec::with_capacity(req.targets.len());
    let mut reads = Vec::new();
    for (i, (server, op)) in req.targets.iter().enumerate() {
        let v = match (
            req.expected_versions.get(server),
            versions::version_source(op),
        ) {
            (_, None) => Ver::None,
            (Some(v), Some(_)) => Ver::Known(*v),
            (None, Some(VersionSource::Probe)) => Ver::Probe,
            (None, Some(VersionSource::Read(read))) => {
                let fut = exec.execute(server.clone(), read, req.actor.clone(), None);
                reads.push(async move { (i, fut.await) });
                Ver::None
            }
        };
        out.push(v);
    }
    let conc = req.options.concurrency.clamp(1, MAX_CONCURRENCY);
    let mut results = futures_util::stream::iter(reads).buffer_unordered(conc);
    loop {
        let next = tokio::select! {
            biased;
            _ = cancel.cancelled() => None,
            r = results.next() => r,
        };
        let Some((i, r)) = next else { break };
        let op = &req.targets[i].1;
        out[i] = match r {
            Ok(p) => versions::version_from(op, &p).map_or_else(
                || Ver::Failed(Failure::Transport("unexpected version read reply".into())),
                Ver::Known,
            ),
            Err(f) => Ver::Failed(f),
        };
    }
    // Cancelled before its read finished: dispatch never happens anyway,
    // but never send a version-checked op without a version.
    for (i, (_, op)) in req.targets.iter().enumerate() {
        if matches!(out[i], Ver::None) && op.requires_expected_version() {
            out[i] = Ver::Failed(Failure::Transport("version not read".into()));
        }
    }
    out
}

struct ApprovalState {
    list: Vec<Option<RootApproval>>,
    items: Vec<Option<ApprovalItem>>,
    dispatched: Vec<bool>,
    expires_at_ms: u64,
    /// The operator declined the refresh: don't ask on every dispatch.
    refresh_failed: bool,
}

/// What each dispatched target needs: envelope options, the approval
/// refresh, the version probe and escalation.
struct Dispatch {
    exec: Arc<dyn BulkExecutor>,
    approver: Option<Arc<dyn Approver>>,
    actor: Actor,
    targets: Vec<(ServerId, Op)>,
    versions: Vec<Ver>,
    approvals: tokio::sync::Mutex<ApprovalState>,
    escalation: Arc<EscalationBatcher>,
    refresh_margin_ms: u64,
}

impl Dispatch {
    async fn run(&self, i: usize) -> Result<Payload, Failure> {
        if let Ver::Failed(f) = &self.versions[i] {
            return Err(f.clone());
        }
        let (server, op) = self.targets[i].clone();
        let mut version = self.versions[i].initial();
        let approval = self.approval_for(i).await;
        let send = |approval: Option<RootApproval>, expected_version: Option<u64>| {
            self.exec.execute_with(
                server.clone(),
                op.clone(),
                self.actor.clone(),
                RequestOpts {
                    approval,
                    expected_version,
                },
            )
        };
        let mut r = send(approval.clone(), version).await;
        if matches!(self.versions[i], Ver::Probe)
            && let Err(Failure::Agent(ErrorCode::VersionConflict { current })) = r
        {
            version = Some(current);
            r = send(approval.clone(), version).await;
        }
        if approval.is_none()
            && op.may_escalate()
            && matches!(r, Err(Failure::Agent(ErrorCode::ApprovalRequired)))
            && let Ok(a) = self.escalation.approve(server.clone(), &op, version).await
        {
            r = send(Some(a), version).await;
        }
        r
    }

    /// This target's approval; first renews it (with every target not yet
    /// dispatched) when it expires within the refresh margin.
    async fn approval_for(&self, i: usize) -> Option<RootApproval> {
        let mut st = self.approvals.lock().await;
        st.dispatched[i] = true;
        st.list[i].as_ref()?;
        let due = crate::now_ms().saturating_add(self.refresh_margin_ms) >= st.expires_at_ms;
        if due
            && !st.refresh_failed
            && let Some(approver) = self.approver.clone()
        {
            let idx: Vec<usize> = (0..st.list.len())
                .filter(|&j| st.items[j].is_some() && (j == i || !st.dispatched[j]))
                .collect();
            let items: Vec<ApprovalItem> =
                idx.iter().filter_map(|&j| st.items[j].clone()).collect();
            let granted = tokio::task::spawn_blocking(move || {
                approver.approve(APPROVAL_REFRESH_LABEL, &items)
            })
            .await;
            match granted {
                Ok(Ok(list)) if list.len() == idx.len() => {
                    st.expires_at_ms = list.iter().filter_map(approval_expiry).min().unwrap_or(0);
                    for (j, a) in idx.into_iter().zip(list) {
                        st.list[j] = Some(a);
                    }
                    // A lifetime shorter than the margin would ask again
                    // on every dispatch: once is enough.
                    if crate::now_ms().saturating_add(self.refresh_margin_ms) >= st.expires_at_ms {
                        st.refresh_failed = true;
                    }
                }
                // The old approval stays; exec refuses it once expired.
                _ => st.refresh_failed = true,
            }
        }
        st.list[i].clone()
    }
}

/// The scheduler alone, for work that isn't a signed op (SSH snippets).
/// `work(i)` runs target `i`. Emits `Done` at the end.
pub async fn run_with<W, E>(
    targets: Vec<ServerId>,
    options: &BulkOptions,
    work: &W,
    cancel: &CancelToken,
    mut emit: E,
) -> Result<BulkReport, BulkError>
where
    W: Fn(usize) -> BoxFut<Result<Output, Failure>> + Sync,
    E: FnMut(BulkEvent) + Send,
{
    validate(&targets)?;
    emit(BulkEvent::Started {
        total: targets.len(),
        needs_approval: false,
    });
    let report = drive(targets, options, work, cancel, false, &mut emit).await;
    emit(BulkEvent::Done(report.summary.clone()));
    Ok(report)
}

fn summarize(outcomes: &[(ServerId, Outcome)], stop: Option<StopReason>) -> BulkSummary {
    let mut s = BulkSummary {
        stop,
        ..Default::default()
    };
    for (_, o) in outcomes {
        match o {
            Outcome::Succeeded(_) => s.succeeded += 1,
            Outcome::Failed(_) => s.failed += 1,
            Outcome::Skipped(_) => s.skipped += 1,
            Outcome::Cancelled => s.cancelled += 1,
            Outcome::Planned(_) => s.planned += 1,
        }
    }
    s
}

async fn one<W>(work: &W, i: usize, limit: Option<Duration>) -> (usize, Result<Output, Failure>)
where
    W: Fn(usize) -> BoxFut<Result<Output, Failure>> + Sync,
{
    let fut = work(i);
    let r = match limit {
        Some(d) => tokio::time::timeout(d, fut)
            .await
            .unwrap_or(Err(Failure::Timeout)),
        None => fut.await,
    };
    (i, r)
}

async fn drive<W, E>(
    targets: Vec<ServerId>,
    opts: &BulkOptions,
    work: &W,
    cancel: &CancelToken,
    planning: bool,
    emit: &mut E,
) -> BulkReport
where
    W: Fn(usize) -> BoxFut<Result<Output, Failure>> + Sync,
    E: FnMut(BulkEvent) + Send,
{
    let n = targets.len();
    let conc = opts.concurrency.clamp(1, MAX_CONCURRENCY);
    let mut outcomes: Vec<Option<Outcome>> = vec![None; n];
    let mut stop: Option<StopReason> = None;
    let mut next = 0usize;

    let finish = |outcomes: &mut Vec<Option<Outcome>>,
                  i: usize,
                  r: Result<Output, Failure>,
                  emit: &mut E|
     -> bool {
        let ok = r.is_ok();
        let o = match r {
            Ok(Output::Payload(p)) if planning => Outcome::Planned(Plan::Fetched(p)),
            Ok(Output::Command(c)) => Outcome::Planned(Plan::Command(c)),
            Ok(out) => Outcome::Succeeded(out),
            Err(f) => Outcome::Failed(f),
        };
        emit(BulkEvent::Finished {
            server: targets[i].clone(),
            outcome: o.clone(),
        });
        outcomes[i] = Some(o);
        ok
    };

    // Canary: one server alone, then the health probe.
    if opts.canary && n > 0 && !cancel.is_cancelled() {
        emit(BulkEvent::Running {
            server: targets[0].clone(),
        });
        next = 1;
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                outcomes[0] = Some(Outcome::Cancelled);
                emit(BulkEvent::Finished { server: targets[0].clone(), outcome: Outcome::Cancelled });
                stop = Some(StopReason::Cancelled);
            }
            (i, r) = one(work, 0, opts.per_server_timeout) => {
                if !finish(&mut outcomes, i, r, emit) {
                    stop = Some(StopReason::CanaryFailed);
                }
            }
        }
        if stop.is_none() && n > 1 {
            if let Some(probe) = &opts.health {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => stop = Some(StopReason::Cancelled),
                    r = probe.check(targets[0].clone()) => {
                        if let Err(e) = r {
                            stop = Some(StopReason::HealthCheckFailed(e));
                        }
                    }
                }
            }
            if stop.is_none() {
                emit(BulkEvent::CanaryPassed {
                    server: targets[0].clone(),
                });
            }
        }
    }

    let mut inflight = FuturesUnordered::new();
    let mut running: Vec<usize> = Vec::new();
    loop {
        // A batch fills only when nothing is in flight.
        let fill = !opts.batch_barrier || inflight.is_empty();
        while fill
            && stop.is_none()
            && !cancel.is_cancelled()
            && !cancel.is_paused()
            && next < n
            && inflight.len() < conc
        {
            emit(BulkEvent::Running {
                server: targets[next].clone(),
            });
            running.push(next);
            inflight.push(one(work, next, opts.per_server_timeout));
            next += 1;
        }
        if inflight.is_empty() {
            if stop.is_none() && next < n && cancel.is_paused() && !cancel.is_cancelled() {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {}
                    _ = cancel.resumed() => {}
                }
                continue;
            }
            if cancel.is_cancelled() && stop.is_none() && next < n {
                stop = Some(StopReason::Cancelled);
            }
            break;
        }
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                for &i in &running {
                    outcomes[i] = Some(Outcome::Cancelled);
                    emit(BulkEvent::Finished { server: targets[i].clone(), outcome: Outcome::Cancelled });
                }
                running.clear();
                inflight.clear();
                if stop.is_none() {
                    stop = Some(StopReason::Cancelled);
                }
                break;
            }
            Some((i, r)) = inflight.next() => {
                running.retain(|&j| j != i);
                if !finish(&mut outcomes, i, r, emit) && opts.stop_on_failure && stop.is_none() {
                    stop = Some(StopReason::Failure);
                }
            }
        }
    }
    drop(inflight);

    let skip = match &stop {
        Some(StopReason::CanaryFailed | StopReason::HealthCheckFailed(_)) => {
            SkipReason::CanaryFailed
        }
        Some(StopReason::Cancelled) => SkipReason::Cancelled,
        Some(StopReason::ApprovalDenied(_)) => SkipReason::ApprovalDenied,
        _ => SkipReason::StoppedAfterFailure,
    };
    let outcomes: Vec<(ServerId, Outcome)> = targets
        .iter()
        .cloned()
        .zip(outcomes)
        .map(|(s, o)| {
            let o = o.unwrap_or_else(|| {
                let o = Outcome::Skipped(skip);
                emit(BulkEvent::Finished {
                    server: s.clone(),
                    outcome: o.clone(),
                });
                o
            });
            (s, o)
        })
        .collect();
    let summary = summarize(&outcomes, stop);
    BulkReport { outcomes, summary }
}

#[cfg(test)]
#[path = "bulk_tests.rs"]
pub(crate) mod tests;
