//! FFI records for enrollment, install, terminals, files and the typed
//! server operations. Every string that came from a server is untrusted
//! (rule 6): the app displays it and never interprets it. Conversions run
//! such strings through `crate::text` (controls and bidi overrides
//! escaped); values the app passes back (paths, journal cursors) stay raw
//! next to a display form.

use crate::text;
use fleet_core::install::InstallStage;
use fleet_core::sftp::{EntryKind, RemoteEntry};
use fleet_proto::payload::{
    BanEntry, BanReason, CertInfo, FirewallState, JournalEntries, ListeningPort, LoginMethod,
    LoginRecord, MetricSeries, MetricUnit, MetricsHistory, MetricsSample, PackageChanges,
    PkgAction, ProcessInfo, UnitActiveState, UnitInfo, UnitStatus, Upgradable,
};

// ---- enrollment ----

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EnrollmentResult {
    /// `f_…` text form.
    pub fleet_id: String,
    pub device_id_hex: String,
    /// 0 with a strong passphrase, 72 h otherwise (design §5.3, §5.11).
    pub recovery_delay_s: u32,
}

// ---- install ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum InstallStep {
    /// One-time password setup: adding this Mac's SSH key.
    AddingKey,
    Connecting,
    Uploading,
    Verifying,
    Installing,
    Starting,
    CleaningUp,
    Pinning,
    WaitingForAgent,
    CheckingHealth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct InstallProgress {
    pub step: InstallStep,
    pub done_bytes: u64,
    pub total_bytes: u64,
}

impl From<InstallStage> for InstallProgress {
    fn from(s: InstallStage) -> Self {
        let (step, done_bytes, total_bytes) = match s {
            // Reported through `InstallListener::on_artifact` instead.
            InstallStage::AddingKey => (InstallStep::AddingKey, 0, 0),
            InstallStage::Connecting | InstallStage::Artifact(_) => (InstallStep::Connecting, 0, 0),
            InstallStage::Uploading { done, total } => (InstallStep::Uploading, done, total),
            InstallStage::Verifying => (InstallStep::Verifying, 0, 0),
            InstallStage::Installing => (InstallStep::Installing, 0, 0),
            InstallStage::Starting => (InstallStep::Starting, 0, 0),
            InstallStage::CleaningUp => (InstallStep::CleaningUp, 0, 0),
        };
        Self {
            step,
            done_bytes,
            total_bytes,
        }
    }
}

impl InstallProgress {
    pub fn step(step: InstallStep) -> Self {
        Self {
            step,
            done_bytes: 0,
            total_bytes: 0,
        }
    }
}

// ---- files ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FileKind {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RemoteFileRow {
    /// Display-safe (controls and bidi escaped, `crate::text`).
    pub name: String,
    /// The raw path, for passing back to file calls only; show
    /// `display_path`.
    pub path: String,
    /// `path`, display-safe.
    pub display_path: String,
    pub kind: FileKind,
    pub size: u64,
    /// Permission bits, e.g. `0o644`.
    pub mode: u32,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub mtime_s: Option<u32>,
}

impl From<RemoteEntry> for RemoteFileRow {
    fn from(e: RemoteEntry) -> Self {
        Self {
            name: text::line(e.name),
            display_path: text::line(e.path.clone()),
            path: e.path,
            kind: match e.kind {
                EntryKind::File => FileKind::File,
                EntryKind::Dir => FileKind::Directory,
                EntryKind::Symlink => FileKind::Symlink,
                EntryKind::Other => FileKind::Other,
            },
            size: e.size,
            mode: e.mode,
            owner: text::opt(e.user),
            group: text::opt(e.group),
            uid: e.uid,
            gid: e.gid,
            mtime_s: e.mtime_s,
        }
    }
}

/// A file loaded for editing; pass `size`/`mtime_s` back to `file_write`
/// so a concurrent change is detected.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FileContents {
    pub data: Vec<u8>,
    pub size: u64,
    pub mtime_s: Option<u32>,
}

// ---- metrics ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MetricUnitRow {
    Percent,
    Bytes,
    BytesPerSec,
    OpsPerSec,
    Count,
    Celsius,
    Ratio,
}

impl From<MetricUnit> for MetricUnitRow {
    fn from(u: MetricUnit) -> Self {
        match u {
            MetricUnit::Percent => Self::Percent,
            MetricUnit::Bytes => Self::Bytes,
            MetricUnit::BytesPerSec => Self::BytesPerSec,
            MetricUnit::OpsPerSec => Self::OpsPerSec,
            MetricUnit::Count => Self::Count,
            MetricUnit::Celsius => Self::Celsius,
            MetricUnit::Ratio => Self::Ratio,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MetricSeriesRow {
    pub id: u16,
    /// e.g. `cpu.busy`, `disk.used:/`, `net.rx:eth0` (untrusted suffix).
    pub name: String,
    pub unit: MetricUnitRow,
}

impl From<MetricSeries> for MetricSeriesRow {
    fn from(s: MetricSeries) -> Self {
        Self {
            id: s.id,
            name: text::line(s.name),
            unit: s.unit.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct MetricValueRow {
    pub id: u16,
    pub value: f32,
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct MetricsSampleRow {
    pub time_ms: u64,
    /// Only the series that changed since the previous sample.
    pub values: Vec<MetricValueRow>,
}

impl From<MetricsSample> for MetricsSampleRow {
    fn from(s: MetricsSample) -> Self {
        Self {
            time_ms: s.time_ms,
            values: s
                .values
                .into_iter()
                .map(|(id, v)| MetricValueRow { id, value: v.0 })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct SeriesRollupRow {
    pub id: u16,
    /// NaN marks a gap.
    pub min: Vec<f32>,
    pub avg: Vec<f32>,
    pub max: Vec<f32>,
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct MetricsHistoryRow {
    pub start_ms: u64,
    pub step_ms: u32,
    pub catalog: Vec<MetricSeriesRow>,
    pub series: Vec<SeriesRollupRow>,
}

impl From<MetricsHistory> for MetricsHistoryRow {
    fn from(h: MetricsHistory) -> Self {
        let f = |v: Vec<fleet_proto::F32>| v.into_iter().map(|x| x.0).collect();
        Self {
            start_ms: h.start_ms,
            step_ms: h.step_ms,
            catalog: h.catalog.into_iter().map(Into::into).collect(),
            series: h
                .series
                .into_iter()
                .map(|s| SeriesRollupRow {
                    id: s.id,
                    min: f(s.min),
                    avg: f(s.avg),
                    max: f(s.max),
                })
                .collect(),
        }
    }
}

/// Live fleet-table figures from the 10 s subscription.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct ServerMetricsRow {
    pub server_id: String,
    pub cpu_percent: Option<f32>,
    pub mem_percent: Option<f32>,
    pub disk_percent: Option<f32>,
    pub time_ms: u64,
}

/// State of a live stream, for the UI.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum StreamStatus {
    /// Stream open; items arriving.
    Live,
    /// Connection lost; reopening when the server is Ready again.
    Reconnecting,
    /// Over. `error` is `None` for a verified normal end.
    Ended { error: Option<String> },
}

// ---- processes ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ProcessSortRow {
    Cpu,
    Memory,
    Io,
    Pid,
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct ProcessRow {
    pub pid: u32,
    pub ppid: u32,
    pub user: String,
    pub name: String,
    pub cmdline: String,
    pub state: String,
    pub nice: i8,
    pub threads: u32,
    pub cpu_percent: f32,
    pub rss_bytes: u64,
    pub read_bps: u64,
    pub write_bps: u64,
    pub start_ms: u64,
}

impl From<ProcessInfo> for ProcessRow {
    fn from(p: ProcessInfo) -> Self {
        Self {
            pid: p.pid,
            ppid: p.ppid,
            user: text::line(p.user),
            name: text::line(p.name),
            cmdline: text::line(p.cmdline),
            state: char::from(p.state).to_string(),
            nice: p.nice,
            threads: p.threads,
            cpu_percent: p.cpu_pct.0,
            rss_bytes: p.rss_bytes,
            read_bps: p.read_bps,
            write_bps: p.write_bps,
            start_ms: p.start_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct ProcessListRow {
    pub total: u32,
    pub processes: Vec<ProcessRow>,
}

// ---- journal ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum LogPriority {
    Emerg,
    Alert,
    Crit,
    Err,
    Warning,
    Notice,
    Info,
    Debug,
}

/// `journal.query` / `journal.follow` arguments; validated in Rust.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct JournalQueryArgs {
    /// Unit names like `nginx.service`; at most 16.
    pub units: Vec<String>,
    pub priority: Option<LogPriority>,
    pub since_ms: Option<u64>,
    pub until_ms: Option<u64>,
    /// Literal substring.
    pub grep: Option<String>,
    pub after_cursor: Option<String>,
    /// 1..=10000.
    pub limit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct JournalEntryRow {
    pub time_us: u64,
    pub priority: u8,
    pub unit: Option<String>,
    pub identifier: Option<String>,
    pub pid: Option<u32>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct JournalPageRow {
    pub entries: Vec<JournalEntryRow>,
    pub cursor: Option<String>,
}

impl From<JournalEntries> for JournalPageRow {
    fn from(j: JournalEntries) -> Self {
        Self {
            entries: j
                .entries
                .into_iter()
                .map(|e| JournalEntryRow {
                    time_us: e.time_us,
                    priority: e.priority,
                    unit: text::opt(e.unit),
                    identifier: text::opt(e.identifier),
                    pid: e.pid,
                    message: text::line(e.message),
                })
                .collect(),
            cursor: j.cursor,
        }
    }
}

// ---- services ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum UnitActive {
    Active,
    Reloading,
    Inactive,
    Failed,
    Activating,
    Deactivating,
    Other,
}

impl From<UnitActiveState> for UnitActive {
    fn from(s: UnitActiveState) -> Self {
        match s {
            UnitActiveState::Active => Self::Active,
            UnitActiveState::Reloading => Self::Reloading,
            UnitActiveState::Inactive => Self::Inactive,
            UnitActiveState::Failed => Self::Failed,
            UnitActiveState::Activating => Self::Activating,
            UnitActiveState::Deactivating => Self::Deactivating,
            UnitActiveState::Other => Self::Other,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct UnitRow {
    pub name: String,
    pub description: String,
    pub active: UnitActive,
    pub sub: String,
    pub file_state: String,
}

impl From<UnitInfo> for UnitRow {
    fn from(u: UnitInfo) -> Self {
        Self {
            name: text::line(u.name),
            description: text::line(u.description),
            active: u.active.into(),
            sub: text::line(u.sub),
            file_state: text::line(u.file_state),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct UnitStatusRow {
    pub unit: UnitRow,
    pub main_pid: Option<u32>,
    pub since_ms: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub cpu_ns: Option<u64>,
    pub tasks: Option<u32>,
    pub restarts: u32,
}

impl From<UnitStatus> for UnitStatusRow {
    fn from(s: UnitStatus) -> Self {
        Self {
            unit: s.info.into(),
            main_pid: s.main_pid,
            since_ms: s.since_ms,
            memory_bytes: s.memory_bytes,
            cpu_ns: s.cpu_ns,
            tasks: s.tasks,
            restarts: s.restarts,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum UnitAction {
    Start,
    Stop,
    Restart,
    Reload,
    Enable,
    Disable,
}

// ---- packages ----

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct UpgradableRow {
    pub name: String,
    pub current: String,
    pub candidate: String,
    pub security: bool,
    pub origin: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct UpgradableListRow {
    pub packages: Vec<UpgradableRow>,
    pub reboot_required: bool,
    pub lists_updated_ms: Option<u64>,
}

impl From<Upgradable> for UpgradableListRow {
    fn from(u: Upgradable) -> Self {
        Self {
            packages: u
                .packages
                .into_iter()
                .map(|p| UpgradableRow {
                    name: text::line(p.name),
                    current: text::line(p.current),
                    candidate: text::line(p.candidate),
                    security: p.security,
                    origin: text::line(p.origin),
                })
                .collect(),
            reboot_required: u.reboot_required,
            lists_updated_ms: u.lists_updated_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PackageChangeRow {
    pub name: String,
    /// `install`, `upgrade`, `remove`, …
    pub action: String,
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PackageChangesRow {
    pub changes: Vec<PackageChangeRow>,
    pub reboot_required: bool,
}

impl From<PackageChanges> for PackageChangesRow {
    fn from(p: PackageChanges) -> Self {
        Self {
            changes: p
                .changes
                .into_iter()
                .map(|c| PackageChangeRow {
                    name: text::line(c.name),
                    action: match c.action {
                        PkgAction::Install => "install",
                        PkgAction::Upgrade => "upgrade",
                        PkgAction::Downgrade => "downgrade",
                        PkgAction::Remove => "remove",
                        PkgAction::Purge => "purge",
                        PkgAction::Hold => "hold",
                        PkgAction::Unhold => "unhold",
                    }
                    .into(),
                    from: text::opt(c.from),
                    to: text::opt(c.to),
                })
                .collect(),
            reboot_required: p.reboot_required,
        }
    }
}

// ---- security ----

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LoginRow {
    pub time_ms: u64,
    pub user: String,
    pub source: Option<String>,
    pub success: bool,
    /// `publickey`, `password`, `keyboard-interactive`, `other`.
    pub method: String,
    pub key_fingerprint: Option<String>,
    /// Hex id of the enrolled Mac whose key it was.
    pub device_id_hex: Option<String>,
    pub session_end_ms: Option<u64>,
}

impl From<LoginRecord> for LoginRow {
    fn from(l: LoginRecord) -> Self {
        Self {
            time_ms: l.time_ms,
            user: text::line(l.user),
            source: l.source.map(|a| a.to_string()),
            success: l.success,
            method: match l.method {
                LoginMethod::PublicKey => "publickey",
                LoginMethod::Password => "password",
                LoginMethod::KeyboardInteractive => "keyboard-interactive",
                LoginMethod::Other => "other",
            }
            .into(),
            key_fingerprint: text::opt(l.key_fingerprint),
            device_id_hex: l.device_id.map(|d| hex::encode(d.0)),
            session_end_ms: l.session_end_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LoginsRow {
    pub logins: Vec<LoginRow>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BanRow {
    pub addr: String,
    pub prefix: u8,
    pub until_ms: u64,
    /// `ssh-brute-force`, `web-scanner`, `manual`.
    pub reason: String,
    pub strikes: u16,
}

impl From<BanEntry> for BanRow {
    fn from(b: BanEntry) -> Self {
        Self {
            addr: b.addr.to_string(),
            prefix: b.prefix,
            until_ms: b.until_ms,
            reason: match b.reason {
                BanReason::SshBruteForce => "ssh-brute-force",
                BanReason::WebScanner => "web-scanner",
                BanReason::Manual => "manual",
            }
            .into(),
            strikes: b.strikes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BansRow {
    pub bans: Vec<BanRow>,
    pub learned_exempt: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PortRow {
    /// `tcp` / `udp`.
    pub proto: String,
    pub addr: String,
    pub port: u16,
    pub pid: Option<u32>,
    pub process: Option<String>,
    pub user: Option<String>,
    pub reachable: Option<bool>,
}

fn proto_name(p: fleet_proto::args::Protocol) -> String {
    match p {
        fleet_proto::args::Protocol::Tcp => "tcp",
        fleet_proto::args::Protocol::Udp => "udp",
    }
    .into()
}

impl From<ListeningPort> for PortRow {
    fn from(p: ListeningPort) -> Self {
        Self {
            proto: proto_name(p.proto),
            addr: p.addr.to_string(),
            port: p.port,
            pid: p.pid,
            process: text::opt(p.process),
            user: text::opt(p.user),
            reachable: p.reachable,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CertRow {
    pub source: String,
    pub subjects: Vec<String>,
    pub issuer: String,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    pub sha256_hex: String,
}

impl From<CertInfo> for CertRow {
    fn from(c: CertInfo) -> Self {
        Self {
            source: text::line(c.source),
            subjects: text::lines(c.subjects),
            issuer: text::line(c.issuer),
            not_before_ms: c.not_before_ms,
            not_after_ms: c.not_after_ms,
            sha256_hex: hex::encode(c.sha256),
        }
    }
}

// ---- firewall ----

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FirewallRuleRow {
    /// `input` / `forward`.
    pub chain: String,
    /// `accept` / `drop` / `reject`.
    pub action: String,
    pub proto: String,
    /// `22`, `8000-8100`, …
    pub ports: Vec<String>,
    /// CIDR, `None` for any source.
    pub source: Option<String>,
    /// `per_minute/burst`.
    pub rate_limit: Option<String>,
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FirewallRow {
    /// `true`: Fleet's table drops by default (managed); `false`: bans only.
    pub managed: bool,
    pub version: u64,
    pub rules: Vec<FirewallRuleRow>,
    pub banned: u32,
    pub foreign_ruleset: String,
}

impl From<FirewallState> for FirewallRow {
    fn from(f: FirewallState) -> Self {
        use fleet_proto::args::{FirewallMode, FwAction, FwChain};
        Self {
            managed: f.mode == FirewallMode::Managed,
            version: f.version,
            rules: f
                .rules
                .into_iter()
                .map(|r| FirewallRuleRow {
                    chain: match r.chain {
                        FwChain::Input => "input",
                        FwChain::Forward => "forward",
                    }
                    .into(),
                    action: match r.action {
                        FwAction::Accept => "accept",
                        FwAction::Drop => "drop",
                        FwAction::Reject => "reject",
                    }
                    .into(),
                    proto: proto_name(r.proto),
                    ports: r
                        .ports
                        .into_iter()
                        .map(|p| {
                            let (a, b) = (p.start().get(), p.end().get());
                            if a == b {
                                a.to_string()
                            } else {
                                format!("{a}-{b}")
                            }
                        })
                        .collect(),
                    source: r.source.map(|c| c.to_string()),
                    rate_limit: r
                        .rate_limit
                        .map(|l| format!("{}/{}", l.per_minute, l.burst)),
                    comment: text::line(r.comment.as_str().to_string()),
                })
                .collect(),
            banned: f.banned,
            foreign_ruleset: text::text(f.foreign_ruleset),
        }
    }
}
