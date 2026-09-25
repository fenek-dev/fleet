//! Response and stream payloads (design §6.2, §6.3).
//!
//! Tagged like `Op`: an app that doesn't know a tag gets
//! [`Payload::Unknown`] instead of a decode failure. A stream's `StreamData`
//! chunks each carry one postcard-encoded `Payload`. Every string in here
//! comes from the server and is untrusted (security rule 6).

mod admin;
mod docker;
mod logs;
mod provision;
mod system;

pub use admin::*;
pub use docker::*;
pub use logs::*;
pub use provision::*;
pub use system::*;

use super::alert::AlertRuleSet;
use super::op::BanConfig;
use super::{AgentHealth, Hash32, PendingRecovery, SignedRoster, SystemInfo};
use crate::tagged::tagged_enum;
use serde::{Deserialize, Serialize};

/// `f32` compared bit-for-bit, so payloads stay `Eq` (NaN marks a gap).
/// Encoded as 4 little-endian bytes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(transparent)]
pub struct F32(pub f32);

impl PartialEq for F32 {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bits() == other.0.to_bits()
    }
}

impl Eq for F32 {}

/// `roster.get`: the roster the agent enforces and the BLAKE3 hashes
/// (`fleet_crypto::roster::roster_hash`) of every roster it accepted in
/// that epoch, which a recovery roster's `prev_hash` may name (design
/// §5.3, §5.11). Signed by its Macs, so the receipt only proves which
/// roster this agent holds; the Mac still verifies the roster itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterState {
    pub roster: SignedRoster,
    /// Oldest first; includes the current roster's own hash.
    pub epoch_hashes: Vec<Hash32>,
}

impl Payload {
    /// The handler's result inside a `ChangePending`, or the payload
    /// itself for anything else.
    pub fn result(&self) -> &Payload {
        match self {
            Payload::ChangePending {
                inner: Some(inner), ..
            } => inner,
            p => p,
        }
    }
}

tagged_enum! {
    /// Successful response (and stream item) payloads.
    #[allow(clippy::large_enum_variant)]
    pub enum Payload, tags = payload_tag, expecting = "(payload tag, payload)" {
        Empty = EMPTY(0, "empty"),
        SystemInfo(v: SystemInfo) = SYSTEM_INFO(1, "system_info"),
        AgentHealth(v: AgentHealth) = AGENT_HEALTH(2, "agent_health"),
        RosterPending(v: Option<PendingRecovery>) = ROSTER_PENDING(3, "roster_pending"),
        /// `roster.get`.
        RosterState(v: Box<RosterState>) = ROSTER_STATE(4, "roster_state"),

        // system
        /// First `metrics.subscribe` item, and again when series change.
        MetricsCatalog(v: MetricsCatalog) = METRICS_CATALOG(10, "metrics_catalog"),
        /// `metrics.subscribe` item: changed values only.
        MetricsSample(v: MetricsSample) = METRICS_SAMPLE(11, "metrics_sample"),
        MetricsHistory(v: MetricsHistory) = METRICS_HISTORY(12, "metrics_history"),
        ProcessList(v: ProcessList) = PROCESS_LIST(13, "process_list"),
        ProcessHistory(v: ProcessHistory) = PROCESS_HISTORY(14, "process_history"),
        Connections(v: Connections) = CONNECTIONS(15, "connections"),
        Timeline(v: Timeline) = TIMELINE(16, "timeline"),
        HealthChecks(v: HealthChecks) = HEALTH_CHECKS(17, "health_checks"),
        /// `events.query`: the persisted signed event log.
        SignedEvents(v: SignedEventPage) = SIGNED_EVENTS(18, "signed_events"),

        // logs
        /// `journal.query` page and `journal.follow` item.
        JournalEntries(v: JournalEntries) = JOURNAL_ENTRIES(20, "journal_entries"),
        /// `logfile.tail` item.
        LogLines(v: LogLines) = LOG_LINES(21, "log_lines"),
        LogFiles(v: LogFiles) = LOG_FILES(22, "log_files"),
        WebLogSummary(v: WebLogSummary) = WEB_LOG_SUMMARY(23, "web_log_summary"),

        // security
        Logins(v: Logins) = LOGINS(30, "logins"),
        Bans(v: Bans) = BANS(31, "bans"),
        BanConfig(v: BanConfig) = BAN_CONFIG(32, "ban_config"),
        Ports(v: Ports) = PORTS(33, "ports"),
        Certs(v: Certs) = CERTS(34, "certs"),
        AuditReport(v: AuditReport) = AUDIT_REPORT(35, "audit_report"),
        IntegrityStatus(v: IntegrityStatus) = INTEGRITY_STATUS(36, "integrity_status"),

        // services
        Units(v: Units) = UNITS(40, "units"),
        UnitStatus(v: UnitStatus) = UNIT_STATUS(41, "unit_status"),

        // firewall and auto-revert
        Firewall(v: FirewallState) = FIREWALL(50, "firewall"),
        /// Result of every auto-revert op (`Op::auto_revert`) and of
        /// `agent.update.commit`. `inner` is the handler's own result when
        /// it has one (`ProfileApplied` for `profile.apply`); never itself
        /// a `ChangePending`.
        ChangePending { change: PendingChange, inner: Option<Box<Payload>> }
            = CHANGE_PENDING(51, "change_pending"),
        PendingChanges(v: PendingChanges) = PENDING_CHANGES(52, "pending_changes"),

        // packages
        Packages(v: Packages) = PACKAGES(60, "packages"),
        Upgradable(v: Upgradable) = UPGRADABLE(61, "upgradable"),
        PackageHistory(v: PackageHistory) = PACKAGE_HISTORY(62, "package_history"),
        PackageChanges(v: PackageChanges) = PACKAGE_CHANGES(63, "package_changes"),

        // docker
        Containers(v: Containers) = CONTAINERS(70, "containers"),
        ContainerDetail(v: ContainerDetail) = CONTAINER_DETAIL(71, "container_detail"),
        Images(v: Images) = IMAGES(72, "images"),
        Volumes(v: Volumes) = VOLUMES(73, "volumes"),
        Networks(v: Networks) = NETWORKS(74, "networks"),
        /// `docker.stats` item.
        DockerStats(v: DockerStats) = DOCKER_STATS(75, "docker_stats"),
        /// `docker.logs` item.
        DockerLogChunk(v: DockerLogChunk) = DOCKER_LOG_CHUNK(76, "docker_log_chunk"),
        ComposeProjects(v: ComposeProjects) = COMPOSE_PROJECTS(77, "compose_projects"),
        Pruned(v: Pruned) = PRUNED(78, "pruned"),

        // cron
        CronTabs(v: CronTabs) = CRON_TABS(80, "cron_tabs"),
        Timers(v: Timers) = TIMERS(81, "timers"),

        // users
        Users(v: Users) = USERS(90, "users"),
        AuthorizedKeys(v: AuthorizedKeys) = AUTHORIZED_KEYS(91, "authorized_keys"),

        // files
        DiskUsage(v: DiskUsage) = DISK_USAGE(100, "disk_usage"),
        LargeFiles(v: LargeFiles) = LARGE_FILES(101, "large_files"),

        // config
        ConfigHistory(v: ConfigHistory) = CONFIG_HISTORY(110, "config_history"),
        ConfigDiff(v: ConfigDiff) = CONFIG_DIFF(111, "config_diff"),
        ConfigPaths(v: ConfigPaths) = CONFIG_PATHS(112, "config_paths"),

        // profile
        ProfileCheck(v: ProfileCheck) = PROFILE_CHECK(120, "profile_check"),
        ProfilePlan(v: ProfilePlan) = PROFILE_PLAN(121, "profile_plan"),
        ProfileApplied(v: ProfileApplied) = PROFILE_APPLIED(122, "profile_applied"),

        // search, mesh, game
        SearchResults(v: SearchResults) = SEARCH_RESULTS(130, "search_results"),
        MeshStatus(v: MeshStatus) = MESH_STATUS(140, "mesh_status"),
        Games(v: Games) = GAMES(150, "games"),
        GameBackups(v: GameBackups) = GAME_BACKUPS(151, "game_backups"),
        RconOutput { text: String } = RCON_OUTPUT(152, "rcon_output"),

        // agent
        AlertRules(v: AlertRuleSet) = ALERT_RULES(160, "alert_rules"),

        // shell
        ShellResult(v: ShellResult) = SHELL_RESULT(170, "shell_result"),
    }
}

#[cfg(test)]
mod tests;
