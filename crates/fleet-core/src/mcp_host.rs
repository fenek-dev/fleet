//! The app side of the `fleetctl` socket (design §5.10, §8).
//!
//! Swift owns the listener: it checks the peer's code signature (only our
//! own signed `fleetctl`, via `LOCAL_PEERTOKEN`) and the parent process's
//! signature, then hands each frame body to [`McpHost::handle_frame`] with
//! the verified [`PeerInfo`]. [`McpHost::serve`] does the same over any
//! byte stream (tests, tools).
//!
//! Per request, in order: protocol version, **pause switch** (rejects
//! everything instantly), **pairing** (a client — parent code signature
//! and cdhash + MCP client name — is approved once in the app with Touch
//! ID, revocable; unsigned, shell or interpreter parents are asked on every
//! connection and never persisted), **lock** (`Locked` while the app is
//! locked), **rate limit** (per client, the policy's
//! `ai_commands_per_minute`), then the tool. Arguments are validated with
//! the protocol's types before anything is signed.
//! **Approvals**: Elevated operations and changes on more than
//! `bulk_confirm_above` servers (counting the distinct servers the client
//! changed with the same op in the last 10 minutes) wait for the
//! operator's decision in the app. The prompt carries the full details
//! (never truncated: too large → `invalid_argument`) and a BLAKE3 digest
//! the answer must echo. Elevated runs then also get the root key's Touch
//! ID (one approval for all targets); may-escalate ops that exec answers
//! with `ApprovalRequired` get an operator prompt first, then the root
//! key. Root key prompts say "AI (<client>): …". Pausing declines open
//! prompts and cancels running calls; the AI approver re-checks the pause
//! right before Touch ID. Multi-server changes from AI always run in
//! canary mode.
//!
//! Results: `summary` holds Mac-side data and fixed codes; everything a
//! server sent is rendered as plain text per payload type
//! ([`render`]) and goes into `untrusted` items, invisible
//! characters escaped, secrets redacted and size-capped. Config files on a
//! server's secret list are never returned. Every command carries
//! `Actor::Ai`.

use crate::bulk::{
    self, AgentHealthProbe, ApproveError, Approver, BoxFut, BulkExecutor, BulkOptions, BulkRequest,
    CancelToken, Failure, Outcome, Output, Plan, SkipReason, StopReason,
};
use crate::cache::McpClientRecord;
use crate::opspec;
use fleet_proto::args::{
    AbsPath, GrepPattern, JournalQuery, Priority, SearchQuery, SearchTerm, TimeRange,
};
use fleet_proto::op::{ProcessSort, Resolution, UpgradeScope};
use fleet_proto::payload::PendingChange;
use fleet_proto::{
    Actor, ApprovalItem, BoundedString, ErrorCode, Op, Payload, RootApproval, ServerId, Tier,
};
use fleetctl_proto::msg::*;
use fleetctl_proto::untrusted::{self, MAX_ITEM_BYTES};
use fleetctl_proto::{FrameError, PROTO_VERSION, decode_body, encode_frame, frame_len};
use serde_json::json;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::oneshot;

/// Default largest approval details shown to the operator (a maximal
/// 256 KiB compose file fits, escaped). Larger requests are refused
/// rather than shown cut.
pub const MAX_APPROVAL_DETAILS: usize = 512 * 1024;
/// Error field for a request whose approval details exceed the limit.
pub const DETAILS_TOO_LARGE: &str = "approval_details_too_large";

/// What Swift verified about the connecting process.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeerInfo {
    /// Team id of `fleetctl`'s parent process ("" if unsigned).
    pub parent_team: String,
    /// Signing identifier of the parent (bundle id or binary name).
    pub parent_signing_id: String,
    /// The parent's cdhash (hex; "" when not available).
    pub parent_cdhash: String,
    /// Swift's verdict: ask the operator on every connection and never
    /// persist the pairing (see [`PeerInfo::ask_every_time`]).
    pub ask_every_time: bool,
}

impl PeerInfo {
    /// Unsigned (no team) or a shell/interpreter parent: its signature says
    /// nothing about what runs inside it, so a pairing can't be remembered.
    pub fn ask_every_time(&self) -> bool {
        self.ask_every_time
            || self.parent_team.is_empty()
            || is_interpreter(&self.parent_signing_id)
    }
}

/// Shells and script interpreters (by signing identifier, e.g.
/// `com.apple.zsh`, or binary name).
pub fn is_interpreter(signing_id: &str) -> bool {
    const EXACT: &[&str] = &[
        "sh",
        "bash",
        "zsh",
        "fish",
        "dash",
        "ksh",
        "tcsh",
        "csh",
        "env",
        "node",
        "nodejs",
        "deno",
        "bun",
        "osascript",
        "pwsh",
        "powershell",
        "tclsh",
        "wish",
        "expect",
        "script",
        "nohup",
        "xargs",
        "sudo",
        "su",
        "login",
        "screen",
        "tmux",
        "lua",
        "luajit",
        "swift",
    ];
    // Followed only by a version (`python3`, `ruby3`, `perl5`).
    const VERSIONED: &[&str] = &["python", "ruby", "perl", "php", "irb"];
    let lower = signing_id.to_ascii_lowercase();
    // `com.apple.zsh`, `/usr/bin/python3.12` (→ "python3", "12").
    let base = lower.rsplit('/').next().unwrap_or(&lower);
    base.split(['.', '-', '_']).any(|c| {
        EXACT.contains(&c)
            || VERSIONED.iter().any(|p| {
                c.strip_prefix(p)
                    .is_some_and(|rest| rest.bytes().all(|b| b.is_ascii_digit()))
            })
    })
}

/// Pairing identity: parent code signature (team, identifier, cdhash) +
/// MCP client name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdentity {
    pub client_name: String,
    pub parent_team: String,
    pub parent_signing_id: String,
    /// Binds the pairing to this exact build of the parent (an update of
    /// the MCP client pairs again). "" when unavailable.
    pub parent_cdhash: String,
}

impl ClientIdentity {
    pub fn key(&self) -> String {
        let mut h = blake3::Hasher::new();
        h.update(b"fleet-mcp-client-v2\0");
        for f in [
            &self.client_name,
            &self.parent_team,
            &self.parent_signing_id,
            &self.parent_cdhash,
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
    Pairing {
        identity: ClientIdentity,
        /// Unsigned/shell/interpreter parent: asked on every connection,
        /// not remembered; the UI shows a warning.
        ask_every_time: bool,
    },
    /// An AI call that needs the operator.
    Approval {
        client: String,
        tool: String,
        op: String,
        /// Mac-rendered arguments (from the AI, validated), complete (at
        /// most `McpConfig::max_approval_details`).
        details: String,
        /// Every target.
        servers: Vec<String>,
        /// The root key's Touch ID follows an approval.
        elevated: bool,
        /// Exec asked for a root approval of a may-escalate op.
        escalation: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    pub id: u64,
    /// BLAKE3 (hex) over everything the prompt shows; the answer must
    /// carry it ([`McpHost::resolve_prompt`]).
    pub digest: String,
    pub kind: PromptKind,
}

/// Why an auto-revert change could not be confirmed, as fixed codes (no
/// agent or transport text reaches the AI).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmFailure {
    /// The revert timer won: the previous state is back.
    Reverted,
    /// No fresh session before the deadline; the change reverts.
    NoConnection,
    /// The new login failed; the change reverts.
    ReconnectFailed,
    Agent(ErrorCode),
    RequestFailed,
    /// Confirmation isn't available (core not running).
    Unavailable,
}

impl ConfirmFailure {
    pub fn code(&self) -> String {
        match self {
            Self::Reverted => "reverted".into(),
            Self::NoConnection => "no_connection".into(),
            Self::ReconnectFailed => "reconnect_failed".into(),
            Self::Agent(c) => format!("agent_{c:?}"),
            Self::RequestFailed => "request_failed".into(),
            Self::Unavailable => "unavailable".into(),
        }
    }
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
    /// The `[actors]` AI limits of the policy this Mac last pushed to
    /// `server` (there is no policy read op; the Mac's copy is what the
    /// agent enforces). `None`: use [`McpConfig`]'s defaults.
    fn ai_limits(&self, _server: &ServerId) -> Option<AiLimits> {
        None
    }
    /// Whether the policy this Mac last pushed to `server` allows
    /// `shell.exec` as `user` (`capabilities.shell_exec` and
    /// `shell_exec_users`). `None`: no policy copy, the agent decides.
    fn shell_exec_allowed(&self, _server: &ServerId, _user: &str) -> Option<bool> {
        None
    }
    /// `change.confirm` of an auto-revert change over a fresh connection
    /// (`crate::autorevert::confirm_pending`, budget from the change's
    /// deadline), sent as `actor`. Without it the change reverts on its own.
    fn confirm_change(
        &self,
        _server: ServerId,
        _change: PendingChange,
        _actor: Actor,
    ) -> BoxFut<Result<(), ConfirmFailure>> {
        Box::pin(async { Err(ConfirmFailure::Unavailable) })
    }
}

/// AI limits from a policy's `[actors]` (design §5.4, §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AiLimits {
    pub commands_per_minute: u32,
    pub bulk_confirm_above: usize,
}

impl AiLimits {
    pub fn from_policy(p: &fleet_proto::Policy) -> Self {
        Self {
            commands_per_minute: p.actors.ai_commands_per_minute,
            bulk_confirm_above: p.actors.ai_bulk_confirm_above as usize,
        }
    }
}

#[derive(Debug, Clone)]
pub struct McpConfig {
    pub bulk_confirm_above: usize,
    pub per_minute: u32,
    pub prompt_timeout: Duration,
    pub app_version: String,
    /// Window over which a client's changes with the same op count
    /// together against `bulk_confirm_above` (distinct servers).
    pub wide_window: Duration,
    /// Approval details larger than this are refused, never cut.
    pub max_approval_details: usize,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            bulk_confirm_above: 5,
            per_minute: 60,
            prompt_timeout: Duration::from_secs(120),
            app_version: env!("CARGO_PKG_VERSION").into(),
            wide_window: Duration::from_secs(10 * 60),
            max_approval_details: MAX_APPROVAL_DETAILS,
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
    /// False for ask-every-time clients (nothing stored to revoke).
    persisted: bool,
}

/// The paired client behind one call.
struct Caller {
    key: String,
    client: String,
    actor: Actor,
}

struct PendingPrompt {
    tx: oneshot::Sender<bool>,
    digest: String,
    /// Pairing and non-Elevated approvals: the app is the only check, so
    /// the answer must say the operator passed Touch ID.
    needs_user: bool,
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
    me: Weak<McpHost>,
    backend: Arc<dyn McpBackend>,
    ui: RwLock<Option<Arc<dyn McpUi>>>,
    paused: AtomicBool,
    cfg: McpConfig,
    prompts: Mutex<HashMap<u64, PendingPrompt>>,
    next_prompt: AtomicU64,
    /// At most one pairing prompt open at a time.
    pairing_open: AtomicBool,
    limiter: Mutex<HashMap<String, Bucket>>,
    /// Cancel tokens of running calls (pause cancels them all).
    runs: Mutex<HashMap<u64, CancelToken>>,
    next_run: AtomicU64,
    /// (client key, op) → recent change targets, for the wide-change check.
    recent: Mutex<HashMap<(String, &'static str), RecentTargets>>,
}

/// When each target was changed, oldest first.
type RecentTargets = VecDeque<(Instant, ServerId)>;

/// Unregisters a call's cancel token.
struct RunGuard<'a> {
    host: &'a McpHost,
    id: u64,
}

impl Drop for RunGuard<'_> {
    fn drop(&mut self) {
        lock(&self.host.runs).remove(&self.id);
    }
}

/// Clears the open-pairing flag.
struct PairingGuard<'a>(&'a AtomicBool);

impl Drop for PairingGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// The root approver as used for AI calls: re-checks the pause right
/// before Touch ID, asks the operator first for escalations (with the full
/// details), and prefixes the root key's reason with the client.
struct AiApprover {
    host: Weak<McpHost>,
    inner: Arc<dyn Approver>,
    client: String,
    tool: String,
    op: Op,
    /// May-escalate (not Elevated) op: every root approval is an
    /// escalation the operator hasn't seen yet.
    escalation: bool,
    cancel: CancelToken,
}

impl Approver for AiApprover {
    /// Runs on a blocking thread (the bulk engine and the escalation
    /// batcher call approvers through `spawn_blocking`).
    fn approve(
        &self,
        what: &str,
        items: &[ApprovalItem],
    ) -> Result<Vec<RootApproval>, ApproveError> {
        let host = self.host.upgrade().ok_or(ApproveError::Unavailable)?;
        let stopped = || host.paused() || self.cancel.is_cancelled();
        if stopped() {
            return Err(ApproveError::Cancelled);
        }
        if self.escalation {
            let servers: Vec<ServerId> = items.iter().map(|i| i.server_id.clone()).collect();
            let rt =
                tokio::runtime::Handle::try_current().map_err(|_| ApproveError::Unavailable)?;
            let ok = rt
                .block_on(host.ask_approval(
                    &self.client,
                    &self.tool,
                    &self.op,
                    &servers,
                    true,
                    true,
                ))
                .unwrap_or(false);
            if !ok {
                return Err(ApproveError::Cancelled);
            }
        }
        // Right before the root key's Touch ID.
        if stopped() {
            return Err(ApproveError::Cancelled);
        }
        let what = if what == bulk::APPROVAL_REFRESH_LABEL {
            format!("{}: {what}", self.op.name())
        } else {
            what.to_string()
        };
        self.inner
            .approve(&format!("AI ({}): {what}", self.client), items)
    }
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
        code: failure_text(f, None),
    }
}

/// A fixed, human-readable reason (never Rust `Debug` text). `op` adds a
/// hint where the bare agent code says too little.
fn failure_text(f: &Failure, op: Option<&str>) -> String {
    match f {
        Failure::Agent(code) => match code {
            ErrorCode::Unauthorized => "not authorized on this server".into(),
            ErrorCode::SignatureInvalid => "the agent rejected the signature".into(),
            ErrorCode::Stale => "the request was too old; retry".into(),
            ErrorCode::Replay => "the agent rejected a replayed request".into(),
            ErrorCode::PolicyDenied => {
                "denied by the server's policy (the op is off, or the server is Agent-only)".into()
            }
            ErrorCode::ApprovalRequired => "needs a root-key approval".into(),
            ErrorCode::ApprovalInvalid => "the root approval was not valid".into(),
            ErrorCode::InvalidArgument => "the agent rejected the arguments".into(),
            ErrorCode::VersionConflict { .. } => {
                "changed since expected_version was read; read it again and retry".into()
            }
            ErrorCode::NotFound => "not found on the server".into(),
            ErrorCode::Busy => "the agent is busy; retry shortly".into(),
            ErrorCode::Timeout => "timed out on the server".into(),
            ErrorCode::Unsupported => "not supported on this server".into(),
            ErrorCode::Internal => match op {
                Some(o) if o.starts_with("docker.") || o.starts_with("compose.") => {
                    "the agent reported an internal error (is Docker installed and running?)".into()
                }
                _ => "the agent reported an internal error".into(),
            },
        },
        Failure::UnknownServer => "the server is not connected".into(),
        Failure::NotReady(s) => format!("the server is not ready ({s})"),
        Failure::Locked => "Fleet is locked; ask the operator to unlock it".into(),
        Failure::Timeout => "timed out".into(),
        Failure::OutcomeUnknown => "no receipt came back; the change may or may not have run".into(),
        // Transport detail is Mac-generated but may quote server text.
        Failure::Transport(_) => "connection problem".into(),
        Failure::ExitStatus { status, .. } => match status {
            Some(n) => format!("the command exited with status {n}"),
            None => "the command did not finish normally".into(),
        },
    }
}

fn payload_item(server: &ServerId, source: &str, p: &Payload) -> Option<UntrustedItem> {
    if matches!(p, Payload::Empty) {
        return None;
    }
    Some(untrusted::prepare(
        server.as_str(),
        source,
        &render::payload_text(p),
        MAX_ITEM_BYTES,
    ))
}

/// Everything an approval prompt shows, and its digest. Refused (not cut)
/// when the details exceed `max_details` bytes.
fn approval_prompt(
    client: &str,
    tool: &str,
    op: &Op,
    servers: &[ServerId],
    elevated: bool,
    escalation: bool,
    max_details: usize,
) -> Result<(PromptKind, String), ProtoError> {
    let details = untrusted::escape_controls(&describe::humanize(&format!("{op:?}")));
    if details.len() > max_details {
        return Err(invalid(DETAILS_TOO_LARGE));
    }
    let servers: Vec<String> = servers.iter().map(|s| s.to_string()).collect();
    let mut h = blake3::Hasher::new();
    h.update(b"fleet-mcp-approval-v1\0");
    h.update(&fleet_crypto::approval::op_digest(op, None));
    for f in [client, tool, op.name(), details.as_str()]
        .into_iter()
        .chain(servers.iter().map(String::as_str))
    {
        h.update(&(f.len() as u64).to_le_bytes());
        h.update(f.as_bytes());
    }
    h.update(&[u8::from(elevated), u8::from(escalation)]);
    let digest = hex::encode(h.finalize().as_bytes());
    Ok((
        PromptKind::Approval {
            client: client.to_string(),
            tool: tool.to_string(),
            op: op.name().to_string(),
            details,
            servers,
            elevated,
            escalation,
        },
        digest,
    ))
}

fn range(since_ms: Option<u64>, until_ms: Option<u64>) -> Result<TimeRange, ProtoError> {
    let r = TimeRange { since_ms, until_ms };
    r.validate().map_err(|_| invalid("since_ms/until_ms"))?;
    Ok(r)
}

impl McpHost {
    pub fn new(backend: Arc<dyn McpBackend>, cfg: McpConfig) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            backend,
            ui: RwLock::new(None),
            paused: AtomicBool::new(false),
            cfg,
            prompts: Mutex::new(HashMap::new()),
            next_prompt: AtomicU64::new(1),
            pairing_open: AtomicBool::new(false),
            limiter: Mutex::new(HashMap::new()),
            runs: Mutex::new(HashMap::new()),
            next_run: AtomicU64::new(1),
            recent: Mutex::new(HashMap::new()),
        })
    }

    pub fn set_ui(&self, ui: Option<Arc<dyn McpUi>>) {
        *self.ui.write().unwrap_or_else(|e| e.into_inner()) = ui;
    }

    /// Global pause: rejects every call, declines open prompts and cancels
    /// running calls (targets not yet dispatched are skipped; in-flight
    /// ones report an unknown outcome).
    pub fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::SeqCst);
        if paused {
            for token in lock(&self.runs).values() {
                token.cancel();
            }
            let pending: Vec<(u64, PendingPrompt)> = lock(&self.prompts).drain().collect();
            let ui = self.ui.read().unwrap_or_else(|e| e.into_inner()).clone();
            for (id, p) in pending {
                let _ = p.tx.send(false);
                if let Some(ui) = &ui {
                    ui.close_prompt(id);
                }
            }
        }
    }

    pub fn paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    /// The operator's answer to a prompt. `digest` is the one the prompt
    /// carried (an answer for anything else is a denial); `user_verified`
    /// says the app took the operator's Touch ID, required for pairing and
    /// non-Elevated approvals (the Swift side does the Touch ID; this
    /// catches a UI path that forgets it). True if the answer was taken as
    /// given; false if the prompt is gone or the answer became a denial.
    pub fn resolve_prompt(
        &self,
        id: u64,
        approved: bool,
        digest: &str,
        user_verified: bool,
    ) -> bool {
        let Some(p) = lock(&self.prompts).remove(&id) else {
            return false;
        };
        let ok = approved && p.digest == digest && (user_verified || !p.needs_user);
        p.tx.send(ok).is_ok() && ok == approved
    }

    pub fn session(&self, peer: PeerInfo) -> McpSession {
        McpSession { peer, client: None }
    }

    fn register_run(&self) -> (RunGuard<'_>, CancelToken) {
        let id = self.next_run.fetch_add(1, Ordering::Relaxed);
        let token = CancelToken::new();
        lock(&self.runs).insert(id, token.clone());
        // A pause between the caller's check and here still cancels.
        if self.paused() {
            token.cancel();
        }
        (RunGuard { host: self, id }, token)
    }

    async fn ask(
        &self,
        kind: PromptKind,
        digest: String,
        needs_user: bool,
        missing: ProtoError,
    ) -> Result<bool, ProtoError> {
        let ui = self
            .ui
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or(missing)?;
        if self.paused() {
            return Err(ProtoError::Paused);
        }
        let id = self.next_prompt.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        lock(&self.prompts).insert(
            id,
            PendingPrompt {
                tx,
                digest: digest.clone(),
                needs_user,
            },
        );
        ui.show_prompt(Prompt { id, digest, kind });
        let answer = tokio::time::timeout(self.cfg.prompt_timeout, rx).await;
        if lock(&self.prompts).remove(&id).is_some() {
            ui.close_prompt(id);
        }
        if self.paused() {
            return Err(ProtoError::Paused);
        }
        // No answer within the window is not a "no": the AI is told to
        // have the operator look at the Mac.
        if answer.is_err() {
            return Err(ProtoError::ApprovalTimedOut);
        }
        Ok(matches!(answer, Ok(Ok(true))))
    }

    /// An approval prompt with the full details; `Ok(false)` if declined.
    async fn ask_approval(
        &self,
        client: &str,
        tool: &str,
        op: &Op,
        servers: &[ServerId],
        elevated: bool,
        escalation: bool,
    ) -> Result<bool, ProtoError> {
        let (kind, digest) = approval_prompt(
            client,
            tool,
            op,
            servers,
            elevated,
            escalation,
            self.cfg.max_approval_details,
        )?;
        self.ask(kind, digest, !elevated, ProtoError::ApprovalRequired)
            .await
    }

    /// A server's AI limits: its pushed policy's, or the defaults.
    fn limits(&self, server: &ServerId) -> AiLimits {
        self.backend.ai_limits(server).unwrap_or(AiLimits {
            commands_per_minute: self.cfg.per_minute,
            bulk_confirm_above: self.cfg.bulk_confirm_above,
        })
    }

    /// The strictest `ai_commands_per_minute` over every server (servers
    /// without a pushed policy count with the default; the bucket is per
    /// client, calls can target any server).
    fn per_minute(&self) -> u32 {
        self.backend
            .servers()
            .iter()
            .map(|s| self.limits(&s.id).commands_per_minute)
            .min()
            .unwrap_or(self.cfg.per_minute)
    }

    /// The strictest `ai_bulk_confirm_above` over every server (missing
    /// policy: the default). Shown in Settings.
    pub fn strictest_bulk_confirm(&self) -> usize {
        let all: Vec<ServerId> = self.backend.servers().into_iter().map(|s| s.id).collect();
        self.bulk_confirm_above(&all)
    }

    /// The strictest `ai_bulk_confirm_above` among `servers` (missing
    /// policy: the default).
    fn bulk_confirm_above<'a>(&self, servers: impl IntoIterator<Item = &'a ServerId>) -> usize {
        servers
            .into_iter()
            .map(|s| self.limits(s).bulk_confirm_above)
            .min()
            .unwrap_or(self.cfg.bulk_confirm_above)
    }

    /// `servers` plus the distinct servers this client changed with `op`
    /// within the window: what the wide-change threshold is checked
    /// against, so a wide change split into small calls still asks.
    fn window_targets(
        &self,
        key: &str,
        op: &'static str,
        servers: &[ServerId],
    ) -> BTreeSet<ServerId> {
        let now = Instant::now();
        let mut m = lock(&self.recent);
        m.retain(|_, q| {
            while q
                .front()
                .is_some_and(|(at, _)| now.duration_since(*at) > self.cfg.wide_window)
            {
                q.pop_front();
            }
            !q.is_empty()
        });
        let mut all: BTreeSet<ServerId> = servers.iter().cloned().collect();
        if let Some(q) = m.get(&(key.to_string(), op)) {
            all.extend(q.iter().map(|(_, s)| s.clone()));
        }
        all
    }

    /// Counts `servers` into the window (`approved`: the operator has
    /// seen this client's recent changes with `op`; start over).
    fn record_targets(&self, key: &str, op: &'static str, servers: &[ServerId], approved: bool) {
        let mut m = lock(&self.recent);
        let k = (key.to_string(), op);
        if approved {
            m.remove(&k);
            return;
        }
        let now = Instant::now();
        let q = m.entry(k).or_default();
        q.extend(servers.iter().map(|s| (now, s.clone())));
        // Bounded: only distinctness within the window matters.
        while q.len() > 4096 {
            q.pop_front();
        }
    }

    fn take_token(&self, key: &str) -> Result<(), ProtoError> {
        let cap = f64::from(self.per_minute().max(1));
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
                let (caller, persisted) = match &sess.client {
                    Some(p) => (
                        Caller {
                            key: p.key.clone(),
                            client: p.identity.client_name.clone(),
                            actor: p.actor.clone(),
                        },
                        p.persisted,
                    ),
                    None => return Err(ProtoError::PairingRequired),
                };
                // Revocation takes effect on the next call.
                if persisted && !self.backend.paired(&caller.key) {
                    sess.client = None;
                    return Err(ProtoError::PairingRequired);
                }
                if self.backend.locked() {
                    return Err(ProtoError::Locked);
                }
                self.take_token(&caller.key)?;
                let out = self.call(&caller, call).await;
                // Paused while running: the call was cancelled.
                if self.paused() {
                    return Err(ProtoError::Paused);
                }
                out.map(ResponseBody::Tool)
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
            parent_cdhash: sess.peer.parent_cdhash.clone(),
        };
        let key = identity.key();
        // Unsigned or shell/interpreter parents: asked every time, never
        // stored (a stored pairing would cover any script they run).
        let ask_every_time = sess.peer.ask_every_time();
        let persisted = !ask_every_time;
        if ask_every_time || !self.backend.paired(&key) {
            if self.backend.locked() {
                return Err(ProtoError::Locked);
            }
            if self
                .pairing_open
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                // Another pairing prompt is open; the client retries.
                return Err(ProtoError::PairingRequired);
            }
            let _open = PairingGuard(&self.pairing_open);
            let ok = self
                .ask(
                    PromptKind::Pairing {
                        identity: identity.clone(),
                        ask_every_time,
                    },
                    key.clone(),
                    true,
                    ProtoError::PairingRequired,
                )
                .await
                .or_else(|e| match e {
                    ProtoError::ApprovalTimedOut => Ok(false),
                    e => Err(e),
                })?;
            if !ok {
                return Err(ProtoError::PairingDenied);
            }
            if persisted {
                self.backend.save_pairing(McpClientRecord {
                    key: key.clone(),
                    client_name: identity.client_name.clone(),
                    parent_team: identity.parent_team.clone(),
                    parent_signing_id: identity.parent_signing_id.clone(),
                    paired_ms: crate::now_ms(),
                })?;
            }
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
            persisted,
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
        let (_run, cancel) = self.register_run();
        let p = tokio::select! {
            r = exec.execute(server.clone(), op, actor, None) => {
                r.map_err(|f| agent_error(&server, &f))?
            }
            _ = cancel.cancelled() => return Err(ProtoError::Paused),
        };
        Ok(ToolOutput {
            summary: json!({ "server": server.as_str(), "op": name, "ok": true }),
            untrusted: payload_item(&server, name, &p).into_iter().collect(),
            is_error: false,
        })
    }

    /// A change (or wide read) on `servers`: approval rules, canary for
    /// multi-server changes, per-server outcomes.
    #[allow(clippy::too_many_arguments)]
    async fn change(
        &self,
        caller: &Caller,
        tool: &str,
        actor: Actor,
        servers: Vec<ServerId>,
        op: Op,
        stop_on_failure: bool,
        concurrency: Option<u16>,
    ) -> Result<ToolOutput, ProtoError> {
        self.change_with(
            caller,
            tool,
            actor,
            servers,
            op,
            stop_on_failure,
            concurrency,
            HashMap::new(),
        )
        .await
    }

    /// [`Self::change`] with the `expected_version`s the AI saw (servers
    /// not listed read theirs before dispatch, `crate::versions`). Changes
    /// answered with `ChangePending` are confirmed over a fresh connection.
    #[allow(clippy::too_many_arguments)]
    async fn change_with(
        &self,
        caller: &Caller,
        tool: &str,
        actor: Actor,
        servers: Vec<ServerId>,
        op: Op,
        stop_on_failure: bool,
        concurrency: Option<u16>,
        versions: HashMap<ServerId, u64>,
    ) -> Result<ToolOutput, ProtoError> {
        op.check_args().map_err(|_| invalid("arguments"))?;
        let exec = self.backend.executor()?;
        let client = caller.client.as_str();
        let elevated = opspec::needs_approval(&op);
        let is_change = op.tier() != Tier::Read;
        let wide = is_change && {
            let recent = self.window_targets(&caller.key, op.name(), &servers);
            recent.len() > self.bulk_confirm_above(&recent)
        };
        if elevated || wide {
            let ok = self
                .ask_approval(client, tool, &op, &servers, elevated, false)
                .await?;
            if !ok {
                return Err(ProtoError::ApprovalDenied);
            }
        }
        if is_change {
            self.record_targets(&caller.key, op.name(), &servers, wide);
        }
        let (_run, cancel) = self.register_run();
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
            batch_barrier: false,
            per_server_timeout: None,
            dry_run: false,
        };
        let name = op.name();
        // Also for may-escalate ops: exec's `ApprovalRequired` is answered
        // with the root key (Touch ID) and one retry (`crate::escalate`).
        // Escalations ask the operator first (full details), then the root
        // key; every root prompt names the AI client.
        let approver = if elevated || op.may_escalate() {
            self.backend.approver().map(|inner| {
                Arc::new(AiApprover {
                    host: self.me.clone(),
                    inner,
                    client: client.to_string(),
                    tool: tool.to_string(),
                    op: op.clone(),
                    escalation: !elevated,
                    cancel: cancel.clone(),
                }) as Arc<dyn Approver>
            })
        } else {
            None
        };
        let mut req = BulkRequest::uniform(servers, op, actor.clone(), options);
        req.expected_versions = versions;
        let report = bulk::run(exec, approver, req, cancel, |_| {})
            .await
            .map_err(|e| invalid(&e.to_string()))?;
        let mut rows = Vec::new();
        let mut items = Vec::new();
        for (server, outcome) in &report.outcomes {
            let status = match outcome {
                Outcome::Succeeded(out) => {
                    if let Output::Payload(p) = out
                        && let Some(item) = payload_item(server, name, p.result())
                    {
                        items.push(item);
                    }
                    match out {
                        Output::Payload(Payload::ChangePending { change, .. }) => {
                            match self
                                .backend
                                .confirm_change(server.clone(), change.clone(), actor.clone())
                                .await
                            {
                                Ok(()) => "succeeded (confirmed from a new connection)".into(),
                                Err(ConfirmFailure::Reverted) => {
                                    "applied, then reverted (reverted)".into()
                                }
                                Err(e) => format!(
                                    "applied, not confirmed ({}); reverts automatically",
                                    e.code()
                                ),
                            }
                        }
                        _ => "succeeded".to_string(),
                    }
                }
                Outcome::Failed(f) => format!("failed: {}", failure_text(f, Some(name))),
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
            // Any failed server: MCP clients must notice (`isError`).
            is_error: s.failed > 0,
        })
    }

    async fn call(&self, caller: &Caller, call: Call) -> Result<ToolOutput, ProtoError> {
        let actor = caller.actor.clone();
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
                    is_error: false,
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
                        is_error: false,
                    });
                }
                self.change(caller, tool, actor, servers, op, false, None)
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
                self.change(caller, tool, actor, servers, op, true, None)
                    .await
            }
            Call::FirewallGet(a) => {
                self.single(actor, self.server(&a.server)?, Op::FirewallGet)
                    .await
            }
            Call::FirewallApply(a) => {
                let server = self.server(&a.server)?;
                let rules: fleet_proto::args::FirewallRuleSet =
                    serde_json::from_value(a.ruleset).map_err(|_| invalid("ruleset"))?;
                let op = Op::FirewallApply(rules);
                op.check_args().map_err(|_| invalid("ruleset"))?;
                // The version the AI read with `firewall_get`: a concurrent
                // edit answers VersionConflict instead of being overwritten.
                let versions = HashMap::from([(server.clone(), a.expected_version)]);
                self.change_with(caller, tool, actor, vec![server], op, true, None, versions)
                    .await
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
                self.change(caller, tool, actor, servers, op, true, None)
                    .await
            }
            Call::DockerAction(a) => {
                let c = opspec::container(&a.container).map_err(|_| invalid("container"))?;
                let server = self.server(&a.server)?;
                let op = opspec::container_op(c, a.action);
                self.change(caller, tool, actor, vec![server], op, true, None)
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
                self.change(caller, tool, actor, vec![server], op, true, None)
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
                self.change(caller, tool, actor, vec![server], op, true, None)
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
                    caller,
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
                // The policy is checked before any approval: a call it
                // forbids must not raise a root Touch ID the operator can
                // only waste.
                if let Some(s) = servers
                    .iter()
                    .find(|s| self.backend.shell_exec_allowed(s, &a.user) == Some(false))
                {
                    return Err(ProtoError::Unsupported {
                        what: format!(
                            "shell.exec is off for user {} in the policy of server {s}",
                            untrusted::truncate(&untrusted::escape_controls(&a.user), 32).0
                        ),
                    });
                }
                self.change(caller, tool, actor, servers, op, true, None)
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

/// `entry` is an absolute path, a directory, or a glob (the agent's
/// matcher: `*`/`?` within a component, `**` across components). A glob
/// covers what it matches and everything below a match.
fn is_secret_match(path: &str, entry: &str) -> bool {
    if entry.contains(['*', '?']) {
        let comps: Vec<&str> = path.split('/').collect();
        let pat: Vec<&str> = entry.split('/').collect();
        return (1..=comps.len()).any(|n| glob_components(&pat, &comps[..n]));
    }
    match (AbsPath::new(path), AbsPath::new(entry)) {
        (Ok(p), Ok(e)) => p.is_under(&e),
        _ => path == entry,
    }
}

fn glob_components(p: &[&str], s: &[&str]) -> bool {
    match p.split_first() {
        None => s.is_empty(),
        Some((&"**", rest)) => (0..=s.len()).any(|i| glob_components(rest, &s[i..])),
        Some((first, rest)) => match s.split_first() {
            Some((c, srest)) => glob_component(first, c) && glob_components(rest, srest),
            None => false,
        },
    }
}

/// `*`/`?` wildcard match of one path component.
fn glob_component(pattern: &str, s: &str) -> bool {
    let (p, s): (Vec<char>, Vec<char>) = (pattern.chars().collect(), s.chars().collect());
    let (mut pi, mut si) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, si));
            pi += 1;
        } else if let Some((sp, ss)) = star {
            pi = sp + 1;
            si = ss + 1;
            star = Some((sp, ss + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

#[path = "mcp_describe.rs"]
mod describe;

#[path = "mcp_render.rs"]
pub mod render;

#[cfg(test)]
#[path = "mcp_host_tests.rs"]
mod tests;
