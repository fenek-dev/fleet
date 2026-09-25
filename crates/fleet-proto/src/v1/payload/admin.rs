//! Results of administration ops: services, firewall, packages, cron,
//! users, files and config history. All text is untrusted server data.

use crate::v1::args::{FirewallMode, FirewallRule};
use crate::v1::op::ChangeId;
use crate::v1::{DeviceId, Hash32};
use serde::{Deserialize, Serialize};

// ---- services ----

/// systemd `ActiveState`; states this build doesn't know map to `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UnitActiveState {
    Active,
    Reloading,
    Inactive,
    Failed,
    Activating,
    Deactivating,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitInfo {
    pub name: String,
    pub description: String,
    pub active: UnitActiveState,
    pub sub: String,
    /// `UnitFileState`, e.g. `enabled`, `disabled`, `static`.
    pub file_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Units {
    pub units: Vec<UnitInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitStatus {
    pub info: UnitInfo,
    pub main_pid: Option<u32>,
    pub since_ms: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub cpu_ns: Option<u64>,
    pub tasks: Option<u32>,
    pub restarts: u32,
}

// ---- firewall and auto-revert ----

/// Current firewall state; `version` is the `expected_version` for the
/// next `firewall.apply`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallState {
    pub mode: FirewallMode,
    pub version: u64,
    pub rules: Vec<FirewallRule>,
    pub banned: u32,
    /// `nft list ruleset` minus Fleet's table, shown read-only (bans-only
    /// mode keeps the existing firewall as the source of truth).
    pub foreign_ruleset: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChangeKind {
    Firewall,
    Ssh,
    Network,
    Mesh,
    Profile,
    AuthorizedKeys,
    AgentUpdate,
}

/// An applied change waiting for `change.confirm` (design §4.10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingChange {
    pub change_id: ChangeId,
    pub kind: ChangeKind,
    pub op_tag: u16,
    pub created_ms: u64,
    pub deadline_ms: u64,
    /// New version of the versioned state the op replaced, if any.
    pub new_version: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingChanges {
    pub changes: Vec<PendingChange>,
}

// ---- packages ----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub arch: String,
    pub held: bool,
    pub auto_installed: bool,
    /// Source package (`${source:Package}`), for matching per-source
    /// advisories (Debian security tracker, design §7.7).
    pub source: Option<String>,
    /// Source version (`${source:Version}`; differs from `version` for
    /// binNMUs and separately versioned binaries).
    pub source_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Packages {
    pub packages: Vec<PackageInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradablePackage {
    pub name: String,
    pub current: String,
    pub candidate: String,
    /// From a `-security` origin.
    pub security: bool,
    pub origin: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Upgradable {
    pub packages: Vec<UpgradablePackage>,
    pub reboot_required: bool,
    /// Time of the last successful `apt-get update`.
    pub lists_updated_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PkgAction {
    Install,
    Upgrade,
    Downgrade,
    Remove,
    Purge,
    Hold,
    Unhold,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageChange {
    pub name: String,
    pub action: PkgAction,
    pub from: Option<String>,
    pub to: Option<String>,
}

/// Result of `pkg.install/remove/upgrade/hold`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageChanges {
    pub changes: Vec<PackageChange>,
    pub reboot_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageHistoryEntry {
    pub time_ms: u64,
    pub change: PackageChange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageHistory {
    pub entries: Vec<PackageHistoryEntry>,
}

// ---- cron ----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CronLine {
    pub schedule: String,
    pub command: String,
    pub comment: Option<String>,
}

/// One crontab: a user's (`user: Some`) or a file in `/etc/cron.d`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CronTab {
    pub user: Option<String>,
    pub source: String,
    /// `expected_version` for the next `cron.set` of this user.
    pub version: u64,
    pub entries: Vec<CronLine>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CronTabs {
    pub tabs: Vec<CronTab>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimerInfo {
    pub unit: String,
    pub activates: String,
    pub schedule: String,
    pub next_ms: Option<u64>,
    pub last_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timers {
    pub timers: Vec<TimerInfo>,
}

// ---- users ----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfo {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
    pub groups: Vec<String>,
    pub locked: bool,
    /// Member of a privileged group (sudo, docker, …).
    pub privileged: bool,
    pub system: bool,
    pub last_login_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupInfo {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Users {
    pub users: Vec<UserInfo>,
    pub groups: Vec<GroupInfo>,
}

/// An entry in the roster section (read-only here; managed by roster
/// updates, design §5.9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterKey {
    pub device_id: Option<DeviceId>,
    pub line: String,
}

/// `/etc/fleet/authorized_keys/<user>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedKeys {
    pub user: String,
    /// `expected_version` for the next `authorized_keys.set`.
    pub version: u64,
    pub roster_section: Vec<RosterKey>,
    /// Raw lines of the extra section.
    pub extra: Vec<String>,
}

// ---- files ----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuEntry {
    pub path: String,
    pub bytes: u64,
    pub depth: u8,
    pub is_dir: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskUsage {
    pub root: String,
    pub total_bytes: u64,
    pub entries: Vec<DuEntry>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LargeFile {
    pub path: String,
    pub bytes: u64,
    pub mtime_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LargeFiles {
    pub files: Vec<LargeFile>,
    pub truncated: bool,
}

// ---- config history ----

/// Who wrote a config change (design §4.9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeSource {
    /// An exec operation, identified by its audit entry.
    Fleet { op_tag: u16, audit_seq: u64 },
    /// Another process, e.g. an editor in a terminal.
    External { process: Option<String> },
    /// Found by a full scan; the writer can't be known.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigVersion {
    pub path: String,
    pub version: u64,
    pub time_ms: u64,
    /// BLAKE3 of the content (also for secret files, whose content isn't kept).
    pub hash: Hash32,
    pub size: u64,
    pub source: ChangeSource,
    pub secret: bool,
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigHistory {
    pub versions: Vec<ConfigVersion>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigDiff {
    pub path: String,
    pub from: u64,
    pub to: Option<u64>,
    /// Unified diff; empty for binary files.
    pub unified: String,
    pub binary: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigPaths {
    /// Built-in plus role-specific tracked paths (read-only).
    pub builtin_tracked: Vec<String>,
    pub builtin_secret: Vec<String>,
    /// Operator-added (the `config.paths.set` state).
    pub tracked: Vec<String>,
    pub secret: Vec<String>,
    /// `expected_version` for the next `config.paths.set`.
    pub version: u64,
}
