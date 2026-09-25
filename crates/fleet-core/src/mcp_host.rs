//! The app side of the `fleetctl` socket (design §5.10, §8).
//!
//! Swift owns the listener: it checks the peer's code signature (only our
//! own signed `fleetctl`, via `LOCAL_PEERTOKEN`) and the parent process's
//! signature, then hands each frame body to [`McpHost::handle_frame`] with
//! the verified [`PeerInfo`]. [`McpHost::serve`] does the same over any
//! byte stream (tests, tools).
//!
//! Per request, in order: protocol version, **pause switch** (rejects
//! everything instantly), **pairing** (a client — parent code signature +
//! MCP client name — is approved once in the app with Touch ID, revocable),
//! **lock** (`Locked` while the app is locked), **rate limit** (per client,
//! the policy's `ai_commands_per_minute`), then the tool. Arguments are
//! validated with the protocol's types before anything is signed.
//! **Approvals**: Elevated operations and bulk actions on more than
//! `bulk_confirm_above` servers wait for the operator's decision in the app
//! (the prompt names the client, operation, arguments and servers);
//! Elevated runs then also get the root key's Touch ID (one approval for
//! all targets). Multi-server changes from AI always run in canary mode.
//!
//! Results: `summary` holds Mac-side data and fixed codes; everything a
//! server sent goes into `untrusted` items, control characters escaped,
//! secrets redacted and size-capped. Config files on a server's secret
//! list are never returned. Every command carries `Actor::Ai`.

use crate::bulk::{
    self, AgentHealthProbe, Approver, BulkExecutor, BulkOptions, BulkRequest, CancelToken, Failure,
    Outcome, Output, Plan, SkipReason, StopReason,
};
use crate::cache::McpClientRecord;
use crate::opspec;
use fleet_proto::args::{
    AbsPath, GrepPattern, JournalQuery, Priority, SearchQuery, SearchTerm, TimeRange,
};
use fleet_proto::op::{ProcessSort, Resolution, UpgradeScope};
use fleet_proto::{Actor, BoundedString, Op, Payload, ServerId, Tier};
use fleetctl_proto::msg::*;
use fleetctl_proto::untrusted::{self, MAX_ITEM_BYTES};
use fleetctl_proto::{FrameError, PROTO_VERSION, decode_body, encode_frame, frame_len};
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::oneshot;

/// What Swift verified about the connecting process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    /// Team id of `fleetctl`'s parent process ("" if unsigned).
    pub parent_team: String,
    /// Signing identifier of the parent (bundle id or binary name).
    pub parent_signing_id: String,
}

/// Pairing identity: parent code signature + MCP client name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdentity {
    pub client_name: String,
    pub parent_team: String,
    pub parent_signing_id: String,
}

impl ClientIdentity {
    pub fn key(&self) -> String {
        let mut h = blake3::Hasher::new();
        h.update(b"fleet-mcp-client-v1\0");
        for f in [
            &self.client_name,
            &self.parent_team,
            &self.parent_signing_id,
        ] {
            h.update(&(f.len() as u64).to_le_bytes());
            h.update(f.as_bytes());
        }
        hex::encode(&h.finalize().as_bytes()[..16])
    }

    pub fn label(&self) -> String {
        format!("{} via {}", self.client_name, self.parent_signing_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptKind {
    /// First connection of a new client; approve with Touch ID.
    Pairing { identity: ClientIdentity },
    /// An AI call that needs the operator.
    Approval {
        client: String,
        tool: String,
        op: String,
        /// Mac-rendered arguments (from the AI, validated).
        details: String,
        servers: Vec<String>,
        elevated: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    pub id: u64,
    pub kind: PromptKind,
}

/// The app UI: shows prompts; answers through [`McpHost::resolve_prompt`]
/// (after its own Touch ID for pairing and non-Elevated bulk approvals).
pub trait McpUi: Send + Sync {
    fn show_prompt(&self, prompt: Prompt);
    fn close_prompt(&self, id: u64);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSummary {
    pub id: ServerId,
    pub name: String,
    pub group: Option<String>,
    pub tags: Vec<String>,
    /// Connection state name (`Ready`, `Offline`, …).
    pub state: String,
}

/// What the host needs from the app.
pub trait McpBackend: Send + Sync {
    /// `NotRunning` while the core isn't started.
    fn executor(&self) -> Result<Arc<dyn BulkExecutor>, ProtoError>;
    fn approver(&self) -> Option<Arc<dyn Approver>>;
    fn locked(&self) -> bool;
    fn servers(&self) -> Vec<ServerSummary>;
    fn paired(&self, key: &str) -> bool;
    fn save_pairing(&self, rec: McpClientRecord) -> Result<(), ProtoError>;
}

#[derive(Debug, Clone)]
pub struct McpConfig {
    pub bulk_confirm_above: usize,
    pub per_minute: u32,
    pub prompt_timeout: Duration,
    pub app_version: String,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            bulk_confirm_above: 5,
            per_minute: 60,
            prompt_timeout: Duration::from_secs(120),
            app_version: env!("CARGO_PKG_VERSION").into(),
        }
    }
}

struct Bucket {
    tokens: f64,
    at: Instant,
}

struct Paired {
    identity: ClientIdentity,
    key: String,
    actor: Actor,
}

/// One connection's state.
pub struct McpSession {
    peer: PeerInfo,
    client: Option<Paired>,
}

impl McpSession {
    pub fn paired_label(&self) -> Option<String> {
        self.client.as_ref().map(|c| c.identity.label())
    }
}

pub struct McpHost {
    backend: Arc<dyn McpBackend>,
    ui: RwLock<Option<Arc<dyn McpUi>>>,
    paused: AtomicBool,
    cfg: McpConfig,
    prompts: Mutex<HashMap<u64, oneshot::Sender<bool>>>,
    next_prompt: AtomicU64,
    limiter: Mutex<HashMap<String, Bucket>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn invalid(field: &str) -> ProtoError {
    ProtoError::InvalidArgument {
        field: field.into(),
    }
}

fn agent_error(server: &ServerId, f: &Failure) -> ProtoError {
    ProtoError::Agent {
        server: server.to_string(),
        code: failure_code(f),
    }
}

fn failure_code(f: &Failure) -> String {
    match f {
        Failure::Agent(code) => format!("{code:?}"),
        Failure::UnknownServer => "UnknownServer".into(),
        Failure::NotReady(s) => format!("NotReady({s})"),
        Failure::Locked => "Locked".into(),
        Failure::Timeout => "Timeout".into(),
        Failure::OutcomeUnknown => "OutcomeUnknown".into(),
        // Transport detail is Mac-generated but may quote server text.
        Failure::Transport(_) => "Transport".into(),
        Failure::ExitStatus { status, .. } => format!("ExitStatus({status:?})"),
    }
}

fn payload_item(server: &ServerId, source: &str, p: &Payload) -> Option<UntrustedItem> {
    if matches!(p, Payload::Empty) {
        return None;
    }
    Some(untrusted::prepare(
        server.as_str(),
        source,
        &format!("{p:#?}"),
        MAX_ITEM_BYTES,
    ))
}

fn range(since_ms: Option<u64>, until_ms: Option<u64>) -> Result<TimeRange, ProtoError> {
    let r = TimeRange { since_ms, until_ms };
    r.validate().map_err(|_| invalid("since_ms/until_ms"))?;
    Ok(r)
}

impl McpHost {
    pub fn new(backend: Arc<dyn McpBackend>, cfg: McpConfig) -> Arc<Self> {
        Arc::new(Self {
            backend,
            ui: RwLock::new(None),
            paused: AtomicBool::new(false),
            cfg,
            prompts: Mutex::new(HashMap::new()),
            next_prompt: AtomicU64::new(1),
            limiter: Mutex::new(HashMap::new()),
        })
    }

    pub fn set_ui(&self, ui: Option<Arc<dyn McpUi>>) {
        *self.ui.write().unwrap_or_else(|e| e.into_inner()) = ui;
    }

    /// Global pause: rejects every call and declines open prompts.
    pub fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::SeqCst);
        if paused {
            let pending: Vec<(u64, oneshot::Sender<bool>)> = lock(&self.prompts).drain().collect();
            let ui = self.ui.read().unwrap_or_else(|e| e.into_inner()).clone();
            for (id, tx) in pending {
                let _ = tx.send(false);
                if let Some(ui) = &ui {
                    ui.close_prompt(id);
                }
            }
        }
    }

    pub fn paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    /// The operator's answer to a prompt. False if it's gone.
    pub fn resolve_prompt(&self, id: u64, approved: bool) -> bool {
        match lock(&self.prompts).remove(&id) {
            Some(tx) => tx.send(approved).is_ok(),
            None => false,
        }
    }

    pub fn session(&self, peer: PeerInfo) -> McpSession {
        McpSession { peer, client: None }
    }

    async fn ask(&self, kind: PromptKind, missing: ProtoError) -> Result<bool, ProtoError> {
        let ui = self
            .ui
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or(missing)?;
        let id = self.next_prompt.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        lock(&self.prompts).insert(id, tx);
        ui.show_prompt(Prompt { id, kind });
        let answer = tokio::time::timeout(self.cfg.prompt_timeout, rx).await;
        if lock(&self.prompts).remove(&id).is_some() {
            ui.close_prompt(id);
        }
        if self.paused() {
            return Err(ProtoError::Paused);
        }
        Ok(matches!(answer, Ok(Ok(true))))
    }

    fn take_token(&self, key: &str) -> Result<(), ProtoError> {
        let cap = f64::from(self.cfg.per_minute.max(1));
        let rate = cap / 60.0;
        let mut m = lock(&self.limiter);
        let now = Instant::now();
        let b = m.entry(key.to_string()).or_insert(Bucket {
            tokens: cap,
            at: now,
        });
        b.tokens = (b.tokens + now.duration_since(b.at).as_secs_f64() * rate).min(cap);
        b.at = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            Ok(())
        } else {
            Err(ProtoError::RateLimited {
                retry_after_ms: ((1.0 - b.tokens) / rate * 1000.0).ceil() as u64,
            })
        }
    }

    /// Handles one frame body; returns the full response frame.
    pub async fn handle_frame(&self, sess: &mut McpSession, body: &[u8]) -> Vec<u8> {
        let (id, result) = match decode_body::<Request>(body) {
            Ok(req) => (req.id, self.handle(sess, req).await),
            Err(_) => (0, Err(invalid("frame"))),
        };
        let resp = Response {
            v: PROTO_VERSION,
            id,
            body: result,
        };
        encode_frame(&resp).unwrap_or_else(|_| {
            encode_frame(&Response {
                v: PROTO_VERSION,
                id,
                body: Err(ProtoError::Internal),
            })
            .unwrap_or_default()
        })
    }

    /// Frame loop over a byte stream until it closes.
    pub async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        peer: PeerInfo,
        mut stream: S,
    ) -> Result<(), FrameError> {
        let mut sess = self.session(peer);
        loop {
            let mut header = [0u8; 4];
            if stream.read_exact(&mut header).await.is_err() {
                return Ok(());
            }
            let n = frame_len(header)?;
            let mut body = vec![0u8; n];
            stream
                .read_exact(&mut body)
                .await
                .map_err(|e| FrameError::Malformed(e.to_string()))?;
            let out = self.handle_frame(&mut sess, &body).await;
            stream
                .write_all(&out)
                .await
                .map_err(|e| FrameError::Malformed(e.to_string()))?;
        }
    }

    async fn handle(
        &self,
        sess: &mut McpSession,
        req: Request,
    ) -> Result<ResponseBody, ProtoError> {
        if req.v != PROTO_VERSION {
            return Err(ProtoError::Version {
                app: PROTO_VERSION,
                client: req.v,
            });
        }
        if self.paused() {
            return Err(ProtoError::Paused);
        }
        match req.body {
            RequestBody::Hello(h) => self.hello(sess, h).await,
            RequestBody::Call(call) => {
                let (key, actor, client) = match &sess.client {
                    Some(p) => (
                        p.key.clone(),
                        p.actor.clone(),
                        p.identity.client_name.clone(),
                    ),
                    None => return Err(ProtoError::PairingRequired),
                };
                // Revocation takes effect on the next call.
                if !self.backend.paired(&key) {
                    sess.client = None;
                    return Err(ProtoError::PairingRequired);
                }
                if self.backend.locked() {
                    return Err(ProtoError::Locked);
                }
                self.take_token(&key)?;
                self.call(&client, actor, call)
                    .await
                    .map(ResponseBody::Tool)
            }
        }
    }

    async fn hello(&self, sess: &mut McpSession, h: Hello) -> Result<ResponseBody, ProtoError> {
        let name_ok =
            (1..=64).contains(&h.client_name.len()) && !h.client_name.chars().any(char::is_control);
        if !name_ok {
            return Err(invalid("client_name"));
        }
        let session: [u8; 16] = hex::decode(&h.session)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| invalid("session"))?;
        let identity = ClientIdentity {
            client_name: h.client_name.clone(),
            parent_team: sess.peer.parent_team.clone(),
            parent_signing_id: sess.peer.parent_signing_id.clone(),
        };
        let key = identity.key();
        if !self.backend.paired(&key) {
            if self.backend.locked() {
                return Err(ProtoError::Locked);
            }
            let ok = self
                .ask(
                    PromptKind::Pairing {
                        identity: identity.clone(),
                    },
                    ProtoError::PairingRequired,
                )
                .await?;
            if !ok {
                return Err(ProtoError::PairingDenied);
            }
            self.backend.save_pairing(McpClientRecord {
                key: key.clone(),
                client_name: identity.client_name.clone(),
                parent_team: identity.parent_team.clone(),
                parent_signing_id: identity.parent_signing_id.clone(),
                paired_ms: crate::now_ms(),
            })?;
        }
        let actor = Actor::Ai {
            client: BoundedString::new(h.client_name.clone())
                .map_err(|_| invalid("client_name"))?,
            session,
        };
        let label = identity.label();
        sess.client = Some(Paired {
            identity,
            key,
            actor,
        });
        Ok(ResponseBody::Welcome(Welcome {
            app_version: self.cfg.app_version.clone(),
            client_label: label,
        }))
    }

    fn server(&self, s: &str) -> Result<ServerId, ProtoError> {
        let unknown = || ProtoError::UnknownServer {
            server: untrusted::truncate(&untrusted::escape_controls(s), 64).0,
        };
        let id = ServerId::new(s).map_err(|_| unknown())?;
        if self.backend.servers().iter().any(|x| x.id == id) {
            Ok(id)
        } else {
            Err(unknown())
        }
    }

    fn servers_arg(&self, list: &[String]) -> Result<Vec<ServerId>, ProtoError> {
        if list.is_empty() {
            return Err(invalid("servers"));
        }
        let ids = list
            .iter()
            .map(|s| self.server(s))
            .collect::<Result<Vec<_>, _>>()?;
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        if sorted.len() != ids.len() {
            return Err(invalid("servers"));
        }
        Ok(ids)
    }

    async fn single(
        &self,
        actor: Actor,
        server: ServerId,
        op: Op,
    ) -> Result<ToolOutput, ProtoError> {
        op.check_args().map_err(|_| invalid("arguments"))?;
        if op.tier() != Tier::Read {
            // Changes go through `change` (approval rules, canary).
            return Err(ProtoError::Internal);
        }
        let exec = self.backend.executor()?;
        let name = op.name();
        let p = exec
            .execute(server.clone(), op, actor, None)
            .await
            .map_err(|f| agent_error(&server, &f))?;
        Ok(ToolOutput {
            summary: json!({ "server": server.as_str(), "op": name, "ok": true }),
            untrusted: payload_item(&server, name, &p).into_iter().collect(),
        })
    }

    /// A change (or wide read) on `servers`: approval rules, canary for
    /// multi-server changes, per-server outcomes.
    #[allow(clippy::too_many_arguments)]
    async fn change(
        &self,
        client: &str,
        tool: &str,
        actor: Actor,
        servers: Vec<ServerId>,
        op: Op,
        stop_on_failure: bool,
        concurrency: Option<u16>,
    ) -> Result<ToolOutput, ProtoError> {
        op.check_args().map_err(|_| invalid("arguments"))?;
        let exec = self.backend.executor()?;
        let elevated = opspec::needs_approval(&op);
        let is_change = op.tier() != Tier::Read;
        if elevated || (is_change && servers.len() > self.cfg.bulk_confirm_above) {
            let (details, _) =
                untrusted::truncate(&untrusted::escape_controls(&format!("{op:?}")), 2000);
            let ok = self
                .ask(
                    PromptKind::Approval {
                        client: client.to_string(),
                        tool: tool.to_string(),
                        op: op.name().to_string(),
                        details,
                        servers: servers.iter().map(|s| s.to_string()).collect(),
                        elevated,
                    },
                    ProtoError::ApprovalRequired,
                )
                .await?;
            if !ok {
                return Err(ProtoError::ApprovalDenied);
            }
        }
        let canary = is_change && servers.len() > 1;
        let options = BulkOptions {
            concurrency: concurrency
                .map_or(bulk::DEFAULT_CONCURRENCY, usize::from)
                .clamp(1, bulk::DEFAULT_CONCURRENCY),
            canary,
            health: canary.then(|| {
                Arc::new(AgentHealthProbe {
                    exec: exec.clone(),
                    actor: actor.clone(),
                }) as Arc<dyn bulk::HealthProbe>
            }),
            stop_on_failure,
            per_server_timeout: None,
            dry_run: false,
        };
        let name = op.name();
        let approver = if elevated {
            self.backend.approver()
        } else {
            None
        };
        let req = BulkRequest::uniform(servers, op, actor, options);
        let report = bulk::run(exec, approver, req, CancelToken::new(), |_| {})
            .await
            .map_err(|e| invalid(&e.to_string()))?;
        let mut rows = Vec::new();
        let mut items = Vec::new();
        for (server, outcome) in &report.outcomes {
            let status = match outcome {
                Outcome::Succeeded(out) => {
                    if let Output::Payload(p) = out
                        && let Some(item) = payload_item(server, name, p)
                    {
                        items.push(item);
                    }
                    "succeeded".to_string()
                }
                Outcome::Failed(f) => format!("failed: {}", failure_code(f)),
                Outcome::Skipped(r) => format!(
                    "skipped: {}",
                    match r {
                        SkipReason::StoppedAfterFailure => "stopped after a failure",
                        SkipReason::CanaryFailed => "canary failed",
                        SkipReason::Cancelled => "cancelled",
                        SkipReason::ApprovalDenied => "approval denied",
                    }
                ),
                Outcome::Cancelled => "cancelled (outcome unknown)".into(),
                Outcome::Planned(Plan::Command(_) | Plan::Fetched(_)) => "planned".into(),
            };
            rows.push(json!({ "server": server.as_str(), "status": status }));
        }
        let s = &report.summary;
        if matches!(s.stop, Some(StopReason::ApprovalDenied(_))) {
            return Err(ProtoError::ApprovalDenied);
        }
        Ok(ToolOutput {
            summary: json!({
                "op": name,
                "canary": canary,
                "succeeded": s.succeeded,
                "failed": s.failed,
                "skipped": s.skipped,
                "cancelled": s.cancelled,
                "stopped": s.stop.as_ref().map(|r| match r {
                    StopReason::CanaryFailed => "canary failed".to_string(),
                    StopReason::HealthCheckFailed(_) => "canary health check failed".to_string(),
                    StopReason::Failure => "stopped after a failure".to_string(),
                    StopReason::Cancelled => "cancelled".to_string(),
                    StopReason::ApprovalDenied(_) => "approval denied".to_string(),
                }),
                "servers": rows,
            }),
            untrusted: items,
        })
    }

    async fn call(&self, client: &str, actor: Actor, call: Call) -> Result<ToolOutput, ProtoError> {
        let tool = call.tool_name();
        match call {
            Call::FleetListServers(a) => {
                let list: Vec<serde_json::Value> = self
                    .backend
                    .servers()
                    .into_iter()
                    .filter(|s| a.tag.as_ref().is_none_or(|t| s.tags.contains(t)))
                    .map(|s| {
                        json!({
                            "id": s.id.as_str(), "name": s.name, "group": s.group,
                            "tags": s.tags, "state": s.state,
                        })
                    })
                    .collect();
                Ok(ToolOutput {
                    summary: json!({ "servers": list }),
                    untrusted: vec![],
                })
            }
            Call::FleetSearch(a) => {
                let query = SearchQuery {
                    term: SearchTerm::new(a.term.as_str()).map_err(|_| invalid("term"))?,
                    case_sensitive: a.case_sensitive,
                    roots: Vec::new(),
                    range: TimeRange::default(),
                    limit: 200,
                };
                query.validate().map_err(|_| invalid("term"))?;
                let op = match a.kind {
                    SearchKind::Packages => Op::SearchPackages(query),
                    SearchKind::Ports => Op::SearchPorts(query),
                    SearchKind::Processes => Op::SearchProcesses(query),
                    SearchKind::Files => Op::SearchFiles(query),
                    SearchKind::Journal => Op::SearchJournal(query),
                    SearchKind::Users => Op::SearchUsers(query),
                };
                let servers = if a.servers.is_empty() {
                    self.backend
                        .servers()
                        .into_iter()
                        .filter(|s| s.state == "Ready")
                        .map(|s| s.id)
                        .collect()
                } else {
                    self.servers_arg(&a.servers)?
                };
                if servers.is_empty() {
                    return Ok(ToolOutput {
                        summary: json!({ "op": op.name(), "servers": [] }),
                        untrusted: vec![],
                    });
                }
                self.change(client, tool, actor, servers, op, false, None)
                    .await
            }
            Call::MetricsQuery(a) => {
                if a.series.len() > 256 {
                    return Err(invalid("series"));
                }
                let op = Op::MetricsQuery {
                    range: range(a.since_ms, a.until_ms)?,
                    resolution: if a.minute_resolution {
                        Resolution::Minute
                    } else {
                        Resolution::Raw
                    },
                    series: a.series,
                };
                self.single(actor, self.server(&a.server)?, op).await
            }
            Call::ProcessesList(a) => {
                if !(1..=1000).contains(&a.limit) {
                    return Err(invalid("limit"));
                }
                let sort = match a.sort {
                    ProcessSortArg::Cpu => ProcessSort::Cpu,
                    ProcessSortArg::Memory => ProcessSort::Memory,
                    ProcessSortArg::Io => ProcessSort::Io,
                    ProcessSortArg::Pid => ProcessSort::Pid,
                };
                let op = Op::ProcessesList {
                    sort,
                    limit: a.limit,
                };
                self.single(actor, self.server(&a.server)?, op).await
            }
            Call::LogsQuery(a) => {
                let units = a
                    .units
                    .iter()
                    .map(|u| {
                        fleet_proto::args::UnitName::new(u.as_str()).map_err(|_| invalid("units"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let q = JournalQuery {
                    units,
                    priority: a.priority.map(|p| match p {
                        LogPriorityArg::Emerg => Priority::Emerg,
                        LogPriorityArg::Alert => Priority::Alert,
                        LogPriorityArg::Crit => Priority::Crit,
                        LogPriorityArg::Err => Priority::Err,
                        LogPriorityArg::Warning => Priority::Warning,
                        LogPriorityArg::Notice => Priority::Notice,
                        LogPriorityArg::Info => Priority::Info,
                        LogPriorityArg::Debug => Priority::Debug,
                    }),
                    range: range(a.since_ms, a.until_ms)?,
                    grep: a
                        .grep
                        .as_deref()
                        .filter(|g| !g.is_empty())
                        .map(|g| GrepPattern::new(g).map_err(|_| invalid("grep")))
                        .transpose()?,
                    after_cursor: None,
                    limit: a.limit,
                };
                q.validate().map_err(|_| invalid("limit"))?;
                self.single(actor, self.server(&a.server)?, Op::JournalQuery(q))
                    .await
            }
            Call::LoginsQuery(a) => {
                if !(1..=10_000).contains(&a.limit) {
                    return Err(invalid("limit"));
                }
                let op = Op::LoginsQuery {
                    range: range(a.since_ms, a.until_ms)?,
                    failed_only: a.failed_only,
                    limit: a.limit,
                };
                self.single(actor, self.server(&a.server)?, op).await
            }
            Call::ServiceAction(a) => {
                let unit = opspec::unit(&a.unit).map_err(|_| invalid("unit"))?;
                let servers = self.servers_arg(&a.servers)?;
                let op = opspec::unit_op(unit, a.action);
                self.change(client, tool, actor, servers, op, true, None)
                    .await
            }
            Call::FirewallGet(a) => {
                self.single(actor, self.server(&a.server)?, Op::FirewallGet)
                    .await
            }
            Call::FirewallApply(a) => {
                self.server(&a.server)?;
                let rules: fleet_proto::args::FirewallRuleSet =
                    serde_json::from_value(a.ruleset).map_err(|_| invalid("ruleset"))?;
                Op::FirewallApply(rules)
                    .check_args()
                    .map_err(|_| invalid("ruleset"))?;
                // Needs `expected_version` in the envelope, which the
                // connection manager doesn't carry yet.
                Err(ProtoError::Unsupported {
                    what: "firewall_apply (version-checked commands not wired yet)".into(),
                })
            }
            Call::PackagesUpgrade(a) => {
                let servers = self.servers_arg(&a.servers)?;
                let op = Op::PkgUpgrade {
                    scope: if a.security_only {
                        UpgradeScope::SecurityOnly
                    } else {
                        UpgradeScope::All
                    },
                };
                self.change(client, tool, actor, servers, op, true, None)
                    .await
            }
            Call::DockerAction(a) => {
                let c = opspec::container(&a.container).map_err(|_| invalid("container"))?;
                let server = self.server(&a.server)?;
                let op = opspec::container_op(c, a.action);
                self.change(client, tool, actor, vec![server], op, true, None)
                    .await
            }
            Call::ComposeDeploy(a) => {
                let spec = fleetctl_proto::OpSpec::ComposeDeploy {
                    project: a.project,
                    compose_yaml: a.compose_yaml,
                    pull: a.pull,
                };
                let op = opspec::to_op(&spec).map_err(|e| invalid(&e.to_string()))?;
                let server = self.server(&a.server)?;
                self.change(client, tool, actor, vec![server], op, true, None)
                    .await
            }
            Call::ConfigDiff(a) => {
                let server = self.server(&a.server)?;
                let path = AbsPath::new(a.path.as_str()).map_err(|_| invalid("path"))?;
                self.refuse_secret(&actor, &server, &path).await?;
                let op = Op::ConfigDiff {
                    path,
                    from: a.from,
                    to: a.to,
                };
                self.single(actor, server, op).await
            }
            Call::ConfigRollback(a) => {
                let server = self.server(&a.server)?;
                let op = Op::ConfigRollback {
                    path: AbsPath::new(a.path.as_str()).map_err(|_| invalid("path"))?,
                    version: a.version,
                };
                self.change(client, tool, actor, vec![server], op, true, None)
                    .await
            }
            Call::BulkRun(a) => {
                let servers = self.servers_arg(&a.servers)?;
                let op = opspec::to_op(&a.op).map_err(|e| invalid(&e.to_string()))?;
                if a.concurrency == Some(0) {
                    return Err(invalid("concurrency"));
                }
                // `change` enforces canary mode for every multi-server change.
                self.change(
                    client,
                    tool,
                    actor,
                    servers,
                    op,
                    a.stop_on_failure,
                    a.concurrency,
                )
                .await
            }
            Call::ShellExec(a) => {
                let servers = self.servers_arg(&a.servers)?;
                let op = opspec::shell_exec(&a.user, &a.command, a.timeout_s)
                    .map_err(|e| invalid(&e.to_string()))?;
                self.change(client, tool, actor, servers, op, true, None)
                    .await
            }
            Call::ProfileCheck(a) => {
                let op = Op::ProfileCheck(opspec::profile_spec(a.level, &a.roles));
                self.single(actor, self.server(&a.server)?, op).await
            }
            Call::ExplainEvent(a) => {
                let op = Op::EventsQuery {
                    since_run_id: None,
                    since_seq: a.seq.saturating_sub(10),
                    limit: 21,
                };
                self.single(actor, self.server(&a.server)?, op).await
            }
        }
    }

    /// Config files on the server's secret list are never returned to AI.
    async fn refuse_secret(
        &self,
        actor: &Actor,
        server: &ServerId,
        path: &AbsPath,
    ) -> Result<(), ProtoError> {
        let exec = self.backend.executor()?;
        let p = exec
            .execute(server.clone(), Op::ConfigPathsGet, actor.clone(), None)
            .await
            .map_err(|f| agent_error(server, &f))?;
        let Payload::ConfigPaths(paths) = p else {
            return Err(ProtoError::Internal);
        };
        let secret = paths.builtin_secret.iter().chain(paths.secret.iter());
        for entry in secret {
            if is_secret_match(path.as_str(), entry) {
                return Err(ProtoError::Unsupported {
                    what: "secret config files are not available to AI".into(),
                });
            }
        }
        Ok(())
    }
}

/// `entry` is an absolute path, a directory, or a glob (prefix up to `*`).
fn is_secret_match(path: &str, entry: &str) -> bool {
    if let Some(star) = entry.find('*') {
        return path.starts_with(&entry[..star]);
    }
    match (AbsPath::new(path), AbsPath::new(entry)) {
        (Ok(p), Ok(e)) => p.is_under(&e),
        _ => path == entry,
    }
}

#[cfg(test)]
#[path = "mcp_host_tests.rs"]
mod tests;
