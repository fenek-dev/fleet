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

use crate::manager::{ManagerHandle, RequestError};
use crate::session::ClientError;
use crate::signer::{DeviceSigner, KeyRole, RoleSigner, root_reason};
use fleet_crypto::approval::{ApprovalParams, build_approvals, op_digest};
use fleet_proto::{
    Actor, ApprovalItem, DeviceId, ErrorCode, FleetId, Op, Payload, RootApproval, ServerId,
};
use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
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
pub struct CancelToken(Arc<(AtomicBool, Notify)>);

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
}

#[derive(Clone)]
pub struct BulkOptions {
    pub concurrency: usize,
    pub canary: bool,
    /// Run after the canary succeeds (canary mode only).
    pub health: Option<Arc<dyn HealthProbe>>,
    pub stop_on_failure: bool,
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
}

impl BulkRequest {
    /// The same `op` on every target.
    pub fn uniform(targets: Vec<ServerId>, op: Op, actor: Actor, options: BulkOptions) -> Self {
        Self {
            label: op.name().to_string(),
            targets: targets.into_iter().map(|s| (s, op.clone())).collect(),
            actor,
            options,
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

    let mut approvals: Vec<Option<RootApproval>> = vec![None; servers.len()];
    if needs_approval {
        let idx: Vec<usize> = (0..req.targets.len())
            .filter(|&i| crate::opspec::needs_approval(&req.targets[i].1))
            .collect();
        let items: Vec<ApprovalItem> = idx
            .iter()
            .map(|&i| ApprovalItem {
                server_id: req.targets[i].0.clone(),
                op_digest: op_digest(&req.targets[i].1, None),
            })
            .collect();
        let granted = match approver {
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

    let targets = req.targets;
    let actor = req.actor;
    let work = move |i: usize| -> BoxFut<Result<Output, Failure>> {
        let (server, op) = targets[i].clone();
        let fut = exec.execute(server, op, actor.clone(), approvals[i].clone());
        Box::pin(async move { fut.await.map(Output::Payload) })
    };
    let report = drive(servers, &req.options, &work, &cancel, false, &mut emit).await;
    emit(BulkEvent::Done(report.summary.clone()));
    Ok(report)
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
        while stop.is_none() && !cancel.is_cancelled() && next < n && inflight.len() < conc {
            emit(BulkEvent::Running {
                server: targets[next].clone(),
            });
            running.push(next);
            inflight.push(one(work, next, opts.per_server_timeout));
            next += 1;
        }
        if inflight.is_empty() {
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
