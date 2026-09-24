//! Records, enums and errors that cross the FFI.
//!
//! Strings in [`SystemInfoRow`], [`AgentEventRow`] and [`AlertInfo`] come
//! from servers and are untrusted data (rule 6): the app shows them, never
//! interprets them.

use fleet_core::manager::{self, RequestError};
use fleet_core::signer;
use fleet_proto::{AgentHealth, Event, SystemInfo, alert::Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum KeyRole {
    /// Touch ID on every use.
    Root,
    /// Usable while the app is unlocked.
    Device,
    /// Usable while locked (read-only sessions).
    Monitor,
    /// `ecdsa-sha2-nistp256` SSH client key.
    Ssh,
}

impl From<signer::KeyRole> for KeyRole {
    fn from(r: signer::KeyRole) -> Self {
        match r {
            signer::KeyRole::Root => Self::Root,
            signer::KeyRole::Device => Self::Device,
            signer::KeyRole::Monitor => Self::Monitor,
            signer::KeyRole::Ssh => Self::Ssh,
        }
    }
}

/// Why Swift could not sign (or load a key). Fixed codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum SignerError {
    /// Key missing, or not usable now (app locked).
    #[error("key unavailable")]
    Unavailable,
    /// Touch ID cancelled or failed.
    #[error("user cancelled")]
    Cancelled,
    #[error("signing failed")]
    Failed,
}

impl From<uniffi::UnexpectedUniFFICallbackError> for SignerError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Failed
    }
}

impl From<SignerError> for signer::SignerError {
    fn from(e: SignerError) -> Self {
        match e {
            SignerError::Unavailable => Self::Unavailable,
            SignerError::Cancelled => Self::Cancelled,
            SignerError::Failed => Self::Failed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ConnState {
    Disconnected,
    Connecting,
    Authenticating,
    Ready,
    Degraded,
    Offline,
}

impl From<manager::ConnState> for ConnState {
    fn from(s: manager::ConnState) -> Self {
        match s {
            manager::ConnState::Disconnected => Self::Disconnected,
            manager::ConnState::Connecting => Self::Connecting,
            manager::ConnState::Authenticating => Self::Authenticating,
            manager::ConnState::Ready => Self::Ready,
            manager::ConnState::Degraded => Self::Degraded,
            manager::ConnState::Offline => Self::Offline,
        }
    }
}

/// Monitor while locked, Device once unlocked (design §5.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SessionKind {
    Monitor,
    Device,
}

impl From<SessionKind> for manager::SessionKind {
    fn from(k: SessionKind) -> Self {
        match k {
            SessionKind::Monitor => Self::Monitor,
            SessionKind::Device => Self::Device,
        }
    }
}

impl From<manager::SessionKind> for SessionKind {
    fn from(k: manager::SessionKind) -> Self {
        match k {
            manager::SessionKind::Monitor => Self::Monitor,
            manager::SessionKind::Device => Self::Device,
        }
    }
}

/// Errors from [`crate::FleetCore`]. Messages are for logs; the app words
/// what the operator sees from the variant.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum FleetError {
    #[error("cache: {message}")]
    Cache { message: String },
    #[error("invalid {field}")]
    InvalidArgument { field: String },
    #[error("unknown server")]
    UnknownServer,
    /// No `fleet_id` / `device_id` in the cache yet (enrollment pending).
    #[error("this Mac is not enrolled")]
    NotEnrolled,
    #[error("connection manager not started")]
    NotStarted,
    #[error("connection manager already started")]
    AlreadyStarted,
    #[error("server not connected")]
    NotReady { state: ConnState },
    /// Needs a device session; the app is locked.
    #[error("locked")]
    Locked,
    #[error("timed out")]
    Timeout,
    #[error("server removed")]
    Stopped,
    /// The agent refused: a fixed protocol error code name.
    #[error("agent error {code}")]
    Agent { code: String },
    #[error("session: {message}")]
    Session { message: String },
    #[error("unexpected reply")]
    UnexpectedReply,
    #[error("key store: {error}")]
    Keys { error: SignerError },
    #[error("internal: {message}")]
    Internal { message: String },
}

impl From<fleet_core::cache::CacheError> for FleetError {
    fn from(e: fleet_core::cache::CacheError) -> Self {
        Self::Cache {
            message: e.to_string(),
        }
    }
}

impl From<RequestError> for FleetError {
    fn from(e: RequestError) -> Self {
        match e {
            RequestError::UnknownServer => Self::UnknownServer,
            RequestError::NotReady(s) => Self::NotReady { state: s.into() },
            RequestError::Locked => Self::Locked,
            RequestError::Timeout => Self::Timeout,
            RequestError::Stopped => Self::Stopped,
            RequestError::Client(c) => Self::Session {
                message: c.to_string(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GroupRow {
    pub id: String,
    pub name: String,
    pub sort: i64,
}

/// One row of the fleet table. Metric fields are `None` until telemetry
/// lands (design §4.3); the table shows a dash.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct ServerRow {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub group_id: Option<String>,
    pub tags: Vec<String>,
    pub state: ConnState,
    /// Agent Noise and signing keys are pinned (agent installed).
    pub agent_pinned: bool,
    pub cpu_percent: Option<f32>,
    pub mem_percent: Option<f32>,
    pub disk_percent: Option<f32>,
    pub uptime_s: Option<u64>,
    pub kernel: Option<String>,
    pub agent_version: Option<String>,
    pub pending_updates: Option<u32>,
    pub last_seen_ms: Option<u64>,
}

/// Input for [`crate::FleetCore::add_server`]; validated in Rust.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct NewServer {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub group_id: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SystemInfoRow {
    pub hostname: String,
    pub os_id: String,
    pub os_version: String,
    pub kernel: String,
    pub arch: String,
    pub cpu_count: u32,
    pub mem_total_bytes: u64,
    pub uptime_s: u64,
}

impl From<SystemInfo> for SystemInfoRow {
    fn from(v: SystemInfo) -> Self {
        Self {
            hostname: v.hostname,
            os_id: v.os_id,
            os_version: v.os_version,
            kernel: v.kernel,
            arch: v.arch,
            cpu_count: v.cpu_count,
            mem_total_bytes: v.mem_total_bytes,
            uptime_s: v.uptime_s,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AgentHealthRow {
    pub agent_version: String,
    pub proto_version: u16,
    pub uptime_s: u64,
    pub gate_rss_bytes: u64,
    pub exec_rss_bytes: u64,
    pub audit_seq: u64,
    pub roster_epoch: u32,
    pub roster_version: u64,
    pub policy_version: u64,
    pub recovery_pending: bool,
}

impl From<AgentHealth> for AgentHealthRow {
    fn from(v: AgentHealth) -> Self {
        let a = v.agent_version;
        Self {
            agent_version: format!("{}.{}.{}", a.major, a.minor, a.patch),
            proto_version: v.proto_version,
            uptime_s: v.uptime_s,
            gate_rss_bytes: v.gate_rss_bytes,
            exec_rss_bytes: v.exec_rss_bytes,
            audit_seq: v.audit_seq,
            roster_epoch: v.roster_epoch,
            roster_version: v.roster_version,
            policy_version: v.policy_version,
            recovery_pending: v.pending_recovery.is_some(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct StateChange {
    pub server_id: String,
    pub state: ConnState,
    pub kind: Option<SessionKind>,
    /// Why the last attempt failed (log text, not for display as-is).
    pub failure: Option<String>,
    /// No automatic retry until [`crate::FleetCore::reconnect`].
    pub fatal: bool,
}

/// A first-use SSH host key: show the fingerprint, then
/// [`crate::FleetCore::accept_host_key`] pins it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HostKeyPrompt {
    pub server_id: String,
    pub algorithm: String,
    /// `SHA256:…`, as `ssh-keygen -lf` prints it.
    pub fingerprint: String,
    /// A jump host was first-use too (not pinned by `accept_host_key` yet).
    pub via_jump_unpinned: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

impl From<Severity> for AlertSeverity {
    fn from(s: Severity) -> Self {
        match s {
            Severity::Info => Self::Info,
            Severity::Warning => Self::Warning,
            Severity::Critical => Self::Critical,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AlertInfo {
    pub rule_id: String,
    pub subject: String,
    /// `None` when cleared.
    pub severity: Option<AlertSeverity>,
    pub cleared: bool,
}

/// A verified agent event. Only alerts are broken out for now; other
/// events carry just their catalog name.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AgentEventRow {
    pub server_id: String,
    pub seq: u64,
    /// Catalog name, e.g. `alert.fired`.
    pub name: String,
    pub alert: Option<AlertInfo>,
}

impl AgentEventRow {
    pub fn new(server_id: String, seq: u64, event: &Event) -> Self {
        let alert = match event {
            Event::AlertFired {
                rule_id,
                severity,
                subject,
                ..
            } => Some(AlertInfo {
                rule_id: rule_id.clone(),
                subject: subject.clone(),
                severity: Some((*severity).into()),
                cleared: false,
            }),
            Event::AlertCleared { rule_id, subject } => Some(AlertInfo {
                rule_id: rule_id.clone(),
                subject: subject.clone(),
                severity: None,
                cleared: true,
            }),
            _ => None,
        };
        Self {
            server_id,
            seq,
            name: event.name().to_string(),
            alert,
        }
    }
}
