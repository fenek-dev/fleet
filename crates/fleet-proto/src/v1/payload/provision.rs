//! Results of `profile`, `search`, `mesh`, `game` and `shell` ops. All text
//! is untrusted server data.

use super::admin::PendingChange;
use super::logs::ModuleStatus;
use crate::v1::Hash32;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

// ---- profile ----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleCheck {
    pub id: String,
    pub status: ModuleStatus,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileCheck {
    /// 0..=100.
    pub score: u8,
    pub modules: Vec<ModuleCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedChange {
    pub module: String,
    pub description: String,
    pub diff: String,
    /// Applied under auto-revert (SSH, firewall, network).
    pub auto_revert: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfilePlan {
    /// The `plan_hash` for `profile.apply`.
    pub plan_hash: Hash32,
    pub changes: Vec<PlannedChange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModuleOutcome {
    Applied,
    Unchanged,
    Skipped,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleResult {
    pub id: String,
    pub outcome: ModuleOutcome,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileApplied {
    pub modules: Vec<ModuleResult>,
    /// Set when an SSH/firewall step armed auto-revert.
    pub pending: Option<PendingChange>,
    pub score_before: u8,
    pub score_after: u8,
}

// ---- search ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SearchKind {
    Package,
    Port,
    Process,
    File,
    Journal,
    User,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchHit {
    pub kind: SearchKind,
    /// Package name, `proto/port`, process name, path, log line or user.
    pub primary: String,
    /// Version, owning process, pid, size, timestamp, …
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchResults {
    pub hits: Vec<SearchHit>,
    pub truncated: bool,
}

// ---- mesh ----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshPeerStatus {
    pub public_key: [u8; 32],
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<String>,
    pub last_handshake_ms: Option<u64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshStatus {
    pub joined: bool,
    pub public_key: Option<[u8; 32]>,
    pub address: Option<IpAddr>,
    pub listen_port: Option<u16>,
    pub peers: Vec<MeshPeerStatus>,
}

// ---- game ----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameInfo {
    pub name: String,
    pub template: String,
    pub running: bool,
    pub players: Option<u32>,
    pub version: Option<String>,
    pub last_backup_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Games {
    pub games: Vec<GameInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameBackup {
    pub id: u64,
    pub time_ms: u64,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameBackups {
    pub backups: Vec<GameBackup>,
}

// ---- shell ----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellResult {
    /// `None` when killed by a signal or the timeout.
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Output hit `output_cap`.
    pub truncated: bool,
    pub timed_out: bool,
}
