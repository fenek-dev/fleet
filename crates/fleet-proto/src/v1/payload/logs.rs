//! Results of `logs` and `security` ops. All text is untrusted server data.

use crate::v1::DeviceId;
use crate::v1::alert::Severity;
use crate::v1::args::Protocol;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    pub time_us: u64,
    /// syslog priority 0..=7.
    pub priority: u8,
    pub unit: Option<String>,
    pub identifier: Option<String>,
    pub pid: Option<u32>,
    pub message: String,
}

/// A page of `journal.query`, or one `journal.follow` stream item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntries {
    pub entries: Vec<JournalEntry>,
    /// Pass as `after_cursor` to continue.
    pub cursor: Option<String>,
}

/// One `logfile.tail` stream item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogLines {
    pub lines: Vec<String>,
    /// The file was truncated or rotated since the last item.
    pub rotated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogFile {
    pub path: String,
    pub size_bytes: u64,
    pub mtime_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogFiles {
    pub files: Vec<LogFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebLogSummary {
    pub requests: u64,
    pub by_status: Vec<(u16, u64)>,
    pub top_clients: Vec<(IpAddr, u64)>,
    pub top_paths: Vec<(String, u64)>,
    pub scanner_hits: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LoginMethod {
    PublicKey,
    Password,
    KeyboardInteractive,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginRecord {
    pub time_ms: u64,
    pub user: String,
    pub source: Option<IpAddr>,
    /// ISO country code when the Mac's lookup filled it in; `None` from the agent.
    pub country: Option<String>,
    pub success: bool,
    pub method: LoginMethod,
    /// `SHA256:…` fingerprint from `LogLevel VERBOSE`.
    pub key_fingerprint: Option<String>,
    /// The enrolled Mac the key belongs to, if any.
    pub device_id: Option<DeviceId>,
    pub session_end_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Logins {
    pub logins: Vec<LoginRecord>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BanReason {
    SshBruteForce,
    WebScanner,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BanEntry {
    pub addr: IpAddr,
    /// 32 for IPv4, 64 for IPv6 (design §4.7).
    pub prefix: u8,
    pub until_ms: u64,
    pub reason: BanReason,
    /// Offence count, drives escalation.
    pub strikes: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bans {
    pub bans: Vec<BanEntry>,
    /// Learned Mac addresses currently exempt.
    pub learned_exempt: Vec<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListeningPort {
    pub proto: Protocol,
    pub addr: IpAddr,
    pub port: u16,
    pub pid: Option<u32>,
    pub process: Option<String>,
    pub user: Option<String>,
    /// Whether Fleet's Managed chain lets it through (`None` in bans-only mode).
    pub reachable: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ports {
    pub ports: Vec<ListeningPort>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertInfo {
    /// File path or `host:port` it was found at.
    pub source: String,
    pub subjects: Vec<String>,
    pub issuer: String,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    pub sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certs {
    pub certs: Vec<CertInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModuleStatus {
    Compliant,
    Drifted,
    NotApplicable,
    /// Turned off by the profile or an accepted exception.
    Skipped,
    Error,
    /// Configured; takes effect at the next reboot (Strict's immutable
    /// audit rules, `/tmp` mounts). Counts as compliant in the score.
    PendingReboot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditFinding {
    pub module: String,
    pub status: ModuleStatus,
    pub severity: Severity,
    pub title: String,
    /// A one-click fix exists (`profile.apply` with `only = [module]`).
    pub fixable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditReport {
    /// 0..=100.
    pub score: u8,
    pub findings: Vec<AuditFinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IntegrityKind {
    Modified,
    Missing,
    Added,
    PermissionsChanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityViolation {
    pub path: String,
    pub kind: IntegrityKind,
    pub detected_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityStatus {
    pub checked_ms: u64,
    pub files_checked: u64,
    pub violations: Vec<IntegrityViolation>,
}
