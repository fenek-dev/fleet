//! Typed operations (design §4.2) and their extensible wire encoding (§6.2).
//!
//! **This module is the authoritative operation catalog.** Every operation's
//! wire tag, name, arguments, group (by tag range), tier and session rules
//! live here; handlers in `fleet-ops`/exec only implement them.
//!
//! On the wire an `Op` is the postcard tuple `(tag: u16 varint, payload: bytes)`,
//! where `payload` is the postcard encoding of the variant's fields in order.
//! A receiver that does not know `tag` skips the payload and yields
//! [`Op::Unknown`], so the frame still decodes and exec can answer
//! `Unsupported`.
//!
//! Tags are explicit constants in per-group ranges of 100 (sub-blocks of 10
//! per resource); never reorder or reuse them.

mod cron;
mod mesh;
mod meta;
mod packages;
mod profile;
mod security;
mod shell;
mod system;
mod users;

pub use cron::CronEntry;
pub use mesh::MeshConfig;
pub use packages::{PkgSpec, UpgradeScope};
pub use profile::{ProfileLevel, ProfilePhase, ProfileRole, ProfileSource, ProfileSpec};
pub use security::BanConfig;
pub use shell::ShellExec;
pub use system::{ProcessSort, Resolution, SampleInterval};
pub use users::LoginShell;

use super::alert::{AlertRuleSet, HealthCheckSet};
use super::args::{
    AbsPath, ComposeFile, ComposeProject, ContainerRef, DebPackageName, FirewallRuleSet, GameName,
    GameTemplateId, GroupName, ImageRef, JournalQuery, Label, Nice, Pid, RconCommand, SearchQuery,
    SearchTerm, Signal, SshPublicKey, SudoPasswordHash, TimeRange, UnitName, UserName, VolumeName,
    WgPeer,
};
use super::{AgentVersion, Hash32, SignedReleaseManifest, SignedRoster};
use crate::tagged::tagged_enum;
use core::ops::RangeInclusive;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Id of a pending auto-revert change (design §4.10).
pub type ChangeId = [u8; 16];

/// Catalog of operation names ([`Op::name`] of every known variant). Policy
/// `[elevated] extra` entries must be listed here.
pub const NAMES: &[&str] = tag::NAMES;

tagged_enum! {
    /// Every typed operation. See the module docs for the encoding; the
    /// methods in `meta.rs` give each variant's tier and session rules.
    #[allow(clippy::large_enum_variant)]
    pub enum Op, tags = tag, expecting = "(op tag, payload)" {
        // ---- system 0–99 ----
        SystemInfo = SYSTEM_INFO(0, "system.info"),
        /// Stream of `Payload::MetricsCatalog` then `Payload::MetricsSample`s.
        MetricsSubscribe { interval: SampleInterval } = METRICS_SUBSCRIBE(1, "metrics.subscribe"),
        /// `series` empty means every series; at most 256.
        MetricsQuery { range: TimeRange, resolution: Resolution, series: Vec<u16> }
            = METRICS_QUERY(2, "metrics.query"),
        /// `limit` 1..=1000.
        ProcessesList { sort: ProcessSort, limit: u16 } = PROCESSES_LIST(10, "processes.list"),
        ProcessSignal { pid: Pid, signal: Signal } = PROCESS_SIGNAL(11, "process.signal"),
        ProcessRenice { pid: Pid, nice: Nice } = PROCESS_RENICE(12, "process.renice"),
        /// Per-minute top-10 by CPU and memory (design §4.3).
        ProcessesHistory { range: TimeRange } = PROCESSES_HISTORY(13, "processes.history"),
        ConnectionsList = CONNECTIONS_LIST(20, "connections.list"),
        /// The agent's persisted event log (design §4.4, §4.5): signed
        /// events strictly after `(since_run_id, since_seq)`, oldest first,
        /// as `Payload::SignedEvents`. `None` (or a run no longer stored)
        /// starts at the oldest event kept. `limit` 1..=1000. Allowed in
        /// monitor sessions, so a Mac catches up on what happened while it
        /// was away or its live feed lagged.
        EventsQuery { since_run_id: Option<[u8; 16]>, since_seq: u64, limit: u32 }
            = EVENTS_QUERY(30, "events.query"),
        HealthChecksList = HEALTH_CHECKS_LIST(40, "health_checks.list"),
        HealthChecksUpdate(checks: HealthCheckSet) = HEALTH_CHECKS_UPDATE(41, "health_checks.update"),
        /// `delay_s` at most one hour.
        SystemReboot { delay_s: u32 } = SYSTEM_REBOOT(50, "system.reboot"),

        // ---- logs 100–199 ----
        JournalQuery(query: JournalQuery) = JOURNAL_QUERY(100, "journal.query"),
        /// Stream of `Payload::JournalEntries`.
        JournalFollow(query: JournalQuery) = JOURNAL_FOLLOW(101, "journal.follow"),
        LogfilesList = LOGFILES_LIST(110, "logfiles.list"),
        /// Stream of `Payload::LogLines`: the last `lines` (≤ 10000) lines,
        /// then new ones while `follow`. `path` must be on the agent's log
        /// allow-list (checked with `AllowedPath`).
        LogfileTail { path: AbsPath, lines: u16, follow: bool } = LOGFILE_TAIL(111, "logfile.tail"),
        /// Parsed web access logs (web role).
        WeblogQuery { range: TimeRange, limit: u32 } = WEBLOG_QUERY(120, "weblog.query"),

        // ---- security 200–299 ----
        LoginsQuery { range: TimeRange, failed_only: bool, limit: u32 } = LOGINS_QUERY(200, "logins.query"),
        BansList = BANS_LIST(210, "bans.list"),
        /// `duration_s` 60..=30 days. IPv6 bans cover the /64.
        BansAdd { addr: IpAddr, duration_s: u32, comment: Label } = BANS_ADD(211, "bans.add"),
        BansRemove { addr: IpAddr } = BANS_REMOVE(212, "bans.remove"),
        BansConfigGet = BANS_CONFIG_GET(213, "bans.config.get"),
        BansConfigSet(config: BanConfig) = BANS_CONFIG_SET(214, "bans.config.set"),
        PortsList = PORTS_LIST(220, "ports.list"),
        CertsList = CERTS_LIST(230, "certs.list"),
        /// Hardening audit: runs the profile modules' `check` only.
        AuditRun { level: ProfileLevel } = AUDIT_RUN(240, "audit.run"),
        IntegrityStatus = INTEGRITY_STATUS(250, "integrity.status"),

        // ---- services 300–399 (never on `fleet-*` units) ----
        UnitList = UNIT_LIST(300, "unit.list"),
        UnitStatus { unit: UnitName } = UNIT_STATUS(301, "unit.status"),
        UnitStart { unit: UnitName } = UNIT_START(310, "unit.start"),
        UnitStop { unit: UnitName } = UNIT_STOP(311, "unit.stop"),
        UnitRestart { unit: UnitName } = UNIT_RESTART(312, "unit.restart"),
        UnitReload { unit: UnitName } = UNIT_RELOAD(313, "unit.reload"),
        UnitEnable { unit: UnitName } = UNIT_ENABLE(314, "unit.enable"),
        UnitDisable { unit: UnitName } = UNIT_DISABLE(315, "unit.disable"),

        // ---- firewall 400–499 ----
        FirewallGet = FIREWALL_GET(400, "firewall.get"),
        /// Replaces Fleet's table; auto-revert armed. Needs
        /// `CommandBody::expected_version` (the version `firewall.get` returned).
        FirewallApply(ruleset: FirewallRuleSet) = FIREWALL_APPLY(401, "firewall.apply"),
        /// Confirms any pending auto-revert change (firewall, SSH, network,
        /// mesh, profile); must come over a fresh connection (design §4.10).
        ChangeConfirm { change_id: ChangeId } = CHANGE_CONFIRM(410, "change.confirm"),
        ChangesList = CHANGES_LIST(411, "changes.list"),

        // ---- packages 500–599 ----
        PkgList { filter: Option<SearchTerm> } = PKG_LIST(500, "pkg.list"),
        PkgUpgradable = PKG_UPGRADABLE(501, "pkg.upgradable"),
        PkgHistory { range: TimeRange, limit: u32 } = PKG_HISTORY(502, "pkg.history"),
        /// `apt-get update`.
        PkgRefresh = PKG_REFRESH(510, "pkg.refresh"),
        PkgUpgrade { scope: UpgradeScope } = PKG_UPGRADE(511, "pkg.upgrade"),
        /// 1..=256 packages.
        PkgInstall { packages: Vec<PkgSpec> } = PKG_INSTALL(512, "pkg.install"),
        PkgRemove { packages: Vec<DebPackageName>, purge: bool } = PKG_REMOVE(513, "pkg.remove"),
        /// Hold (`hold: true`) or unhold.
        PkgHold { packages: Vec<DebPackageName>, hold: bool } = PKG_HOLD(514, "pkg.hold"),

        // ---- docker 600–699 ----
        DockerContainersList { all: bool } = DOCKER_CONTAINERS_LIST(600, "docker.containers.list"),
        DockerContainersGet { container: ContainerRef } = DOCKER_CONTAINERS_GET(601, "docker.containers.get"),
        DockerContainersStart { container: ContainerRef } = DOCKER_CONTAINERS_START(602, "docker.containers.start"),
        DockerContainersStop { container: ContainerRef, timeout_s: u16 } = DOCKER_CONTAINERS_STOP(603, "docker.containers.stop"),
        DockerContainersRestart { container: ContainerRef, timeout_s: u16 } = DOCKER_CONTAINERS_RESTART(604, "docker.containers.restart"),
        DockerContainersRemove { container: ContainerRef, force: bool } = DOCKER_CONTAINERS_REMOVE(605, "docker.containers.remove"),
        /// Stream of `Payload::DockerLogChunk`: last `tail` (≤ 10000) lines,
        /// then new ones while `follow`.
        DockerLogs { container: ContainerRef, tail: u32, since_ms: Option<u64>, follow: bool }
            = DOCKER_LOGS(610, "docker.logs"),
        /// Stream of `Payload::DockerStats`; empty means every container.
        DockerStats { containers: Vec<ContainerRef> } = DOCKER_STATS(611, "docker.stats"),
        DockerImagesList = DOCKER_IMAGES_LIST(620, "docker.images.list"),
        DockerImagesPull { image: ImageRef } = DOCKER_IMAGES_PULL(621, "docker.images.pull"),
        DockerImagesRemove { image: ImageRef, force: bool } = DOCKER_IMAGES_REMOVE(622, "docker.images.remove"),
        DockerImagesPrune { all_unused: bool } = DOCKER_IMAGES_PRUNE(623, "docker.images.prune"),
        DockerVolumesList = DOCKER_VOLUMES_LIST(630, "docker.volumes.list"),
        DockerVolumesRemove { volume: VolumeName } = DOCKER_VOLUMES_REMOVE(631, "docker.volumes.remove"),
        DockerNetworksList = DOCKER_NETWORKS_LIST(640, "docker.networks.list"),
        ComposeList = COMPOSE_LIST(650, "compose.list"),
        ComposeStatus { project: ComposeProject } = COMPOSE_STATUS(651, "compose.status"),
        /// Writes `/srv/<project>/compose.yaml`, pulls and starts. Change,
        /// escalated to Elevated by exec when the file uses a deny-listed
        /// feature (see `Op::may_escalate`).
        ComposeDeploy { project: ComposeProject, file: ComposeFile, pull: bool }
            = COMPOSE_DEPLOY(652, "compose.deploy"),
        ComposePull { project: ComposeProject } = COMPOSE_PULL(653, "compose.pull"),
        ComposeRestart { project: ComposeProject } = COMPOSE_RESTART(654, "compose.restart"),
        ComposeDown { project: ComposeProject, remove_volumes: bool } = COMPOSE_DOWN(655, "compose.down"),

        // ---- cron 700–799 ----
        /// `None` lists every user's crontab plus `/etc/cron.d`.
        CronList { user: Option<UserName> } = CRON_LIST(700, "cron.list"),
        /// Replaces `user`'s crontab (≤ 256 entries). Elevated for root;
        /// exec escalates for sudo/privileged-group members.
        CronSet { user: UserName, entries: Vec<CronEntry> } = CRON_SET(701, "cron.set"),
        TimersList = TIMERS_LIST(710, "timers.list"),

        // ---- users 800–899 ----
        UsersList = USERS_LIST(800, "users.list"),
        /// Elevated when `groups` holds a privileged group (sudo, docker, …).
        UsersCreate { name: UserName, groups: Vec<GroupName>, shell: LoginShell, comment: Label }
            = USERS_CREATE(801, "users.create"),
        /// Lock (`locked: true`) or unlock the password and key login.
        UsersLock { name: UserName, locked: bool } = USERS_LOCK(802, "users.lock"),
        UsersDelete { name: UserName, remove_home: bool } = USERS_DELETE(803, "users.delete"),
        /// Replaces supplementary groups; Elevated like `users.create`.
        UsersGroupsSet { name: UserName, groups: Vec<GroupName> } = USERS_GROUPS_SET(804, "users.groups.set"),
        GroupsCreate { name: GroupName } = GROUPS_CREATE(810, "groups.create"),
        AuthorizedKeysGet { user: UserName } = AUTHORIZED_KEYS_GET(820, "authorized_keys.get"),
        /// Replaces the extra section of `/etc/fleet/authorized_keys/<user>`
        /// (≤ 64 keys). Elevated, auto-reverted, needs `expected_version`.
        AuthorizedKeysSet { user: UserName, keys: Vec<SshPublicKey> } = AUTHORIZED_KEYS_SET(821, "authorized_keys.set"),

        // ---- files 900–999 (file contents go over SFTP) ----
        /// `max_depth` ≤ 16, `limit` 1..=10000 entries.
        DuScan { path: AbsPath, max_depth: u8, limit: u32 } = DU_SCAN(900, "du.scan"),
        FindLarge { root: AbsPath, min_bytes: u64, limit: u32 } = FIND_LARGE(901, "find.large"),

        // ---- config 1000–1099 ----
        ConfigHistory { path: Option<AbsPath>, range: TimeRange, limit: u32 } = CONFIG_HISTORY(1000, "config.history"),
        /// `to: None` diffs against the current file.
        ConfigDiff { path: AbsPath, from: u64, to: Option<u64> } = CONFIG_DIFF(1001, "config.diff"),
        /// Elevated for protected paths; Fleet-owned paths are rejected.
        ConfigRollback { path: AbsPath, version: u64 } = CONFIG_ROLLBACK(1002, "config.rollback"),
        ConfigPathsGet = CONFIG_PATHS_GET(1010, "config.paths.get"),
        /// Operator-added tracked and secret paths (≤ 256 each).
        ConfigPathsSet { tracked: Vec<AbsPath>, secret: Vec<AbsPath> } = CONFIG_PATHS_SET(1011, "config.paths.set"),

        // ---- profile 1100–1199 ----
        ProfileCheck(spec: ProfileSpec) = PROFILE_CHECK(1100, "profile.check"),
        ProfilePlan(spec: ProfileSpec) = PROFILE_PLAN(1101, "profile.plan"),
        /// Applies the modules of `phase` only if a fresh plan of `spec`
        /// (every phase) still hashes to `plan_hash` (the operator saw it).
        /// Answers `ProfileApplied`; wrapped in `ChangePending` when the
        /// phase arms auto-revert (`ProfilePhase::arms_auto_revert`).
        /// `password_hash` sets the admin's sudo password (`Accounts`/`All`
        /// only); the audit log keeps only its BLAKE3.
        ProfileApply {
            spec: ProfileSpec,
            plan_hash: Hash32,
            phase: ProfilePhase,
            password_hash: Option<SudoPasswordHash>,
        } = PROFILE_APPLY(1102, "profile.apply"),

        // ---- search 1200–1299 ----
        SearchPackages(query: SearchQuery) = SEARCH_PACKAGES(1200, "search.packages"),
        SearchPorts(query: SearchQuery) = SEARCH_PORTS(1201, "search.ports"),
        SearchProcesses(query: SearchQuery) = SEARCH_PROCESSES(1202, "search.processes"),
        SearchFiles(query: SearchQuery) = SEARCH_FILES(1203, "search.files"),
        SearchJournal(query: SearchQuery) = SEARCH_JOURNAL(1204, "search.journal"),
        SearchUsers(query: SearchQuery) = SEARCH_USERS(1205, "search.users"),

        // ---- mesh 1300–1399 ----
        MeshStatus = MESH_STATUS(1300, "mesh.status"),
        MeshJoin(config: MeshConfig) = MESH_JOIN(1301, "mesh.join"),
        MeshLeave = MESH_LEAVE(1302, "mesh.leave"),
        MeshPeersSet { peers: Vec<WgPeer> } = MESH_PEERS_SET(1303, "mesh.peers.set"),

        // ---- game 1400–1499 ----
        /// `None` lists every game server.
        GameStatus { name: Option<GameName> } = GAME_STATUS(1400, "game.status"),
        GameInstall { name: GameName, template: GameTemplateId } = GAME_INSTALL(1401, "game.install"),
        GameUpdate { name: GameName } = GAME_UPDATE(1402, "game.update"),
        GameBackup { name: GameName } = GAME_BACKUP(1403, "game.backup"),
        GameRestore { name: GameName, backup_id: u64 } = GAME_RESTORE(1404, "game.restore"),
        GameRcon { name: GameName, command: RconCommand } = GAME_RCON(1405, "game.rcon"),
        GameBackupsList { name: GameName } = GAME_BACKUPS_LIST(1406, "game.backups.list"),
        GameRemove { name: GameName, keep_data: bool } = GAME_REMOVE(1407, "game.remove"),

        // ---- agent 1500–1599 ----
        AgentHealth = AGENT_HEALTH(1500, "agent.health"),
        RosterUpdate { roster: Box<SignedRoster> } = ROSTER_UPDATE(1510, "roster.update"),
        /// Reads the pending recovery state only, so it is tier Read.
        RosterPending = ROSTER_PENDING(1511, "roster.pending"),
        RosterVeto { pending_hash: Hash32 } = ROSTER_VETO(1512, "roster.veto"),
        /// The current `SignedRoster` plus the hashes of its epoch
        /// (`Payload::RosterState`): what a recovery roster chains to. The
        /// roster is public, so this is Read and allowed in recovery and
        /// monitor sessions (design §5.5, §5.11).
        RosterGet = ROSTER_GET(1513, "roster.get"),
        PolicyUpdate { policy_toml: String } = POLICY_UPDATE(1520, "policy.update"),
        /// Moves the upload `/var/lib/fleet/incoming/<hex(staged_path_hash)>`
        /// (admin-writable SFTP drop) into root-only
        /// `/var/lib/fleet/staging/` after checking it against the
        /// root-signed manifest (design §10.2): the copied bytes' BLAKE3
        /// must equal both `staged_path_hash` and `manifest.blake3`, the
        /// signer a Mac of the current roster, the version above the
        /// running one, the target this server's architecture.
        AgentUpdateStage { manifest: Box<SignedReleaseManifest>, staged_path_hash: Hash32 }
            = AGENT_UPDATE_STAGE(1530, "agent.update.stage"),
        /// Switches to the staged `version` under auto-revert
        /// (`ChangeKind::AgentUpdate`): the new build must be confirmed
        /// (`change.confirm` from a fresh connection, after `agent.health`)
        /// within the health window, else the timer restores the previous
        /// binary and restarts the units.
        AgentUpdateCommit { version: AgentVersion } = AGENT_UPDATE_COMMIT(1531, "agent.update.commit"),
        /// Manual rollback to the binary kept by the last confirmed update.
        AgentUpdateRollback = AGENT_UPDATE_ROLLBACK(1532, "agent.update.rollback"),
        /// Uninstall step 1 (design §10.3), under auto-revert
        /// (`ChangeKind::Ssh`): copies every user's keys from
        /// `/etc/fleet/authorized_keys/` back to `~/.ssh/authorized_keys`
        /// and drops Fleet's `AuthorizedKeysFile`, so SSH keeps working
        /// without the agent; confirmed from a fresh connection.
        AgentUninstallPrepare = AGENT_UNINSTALL_PREPARE(1533, "agent.uninstall.prepare"),
        /// Uninstall step 2, only after a confirmed prepare: schedules
        /// `fleet-agent uninstall` in a transient unit (it stops exec).
        /// `remove_firewall` deletes `table inet fleet` (it may be the
        /// only firewall); `keep_audit` keeps the database for the audit
        /// log.
        AgentUninstall { keep_audit: bool, remove_firewall: bool }
            = AGENT_UNINSTALL(1534, "agent.uninstall"),
        AlertRulesGet = ALERT_RULES_GET(1540, "alert_rules.get"),
        AlertRulesUpdate(rules: AlertRuleSet) = ALERT_RULES_UPDATE(1541, "alert_rules.update"),

        // ---- shell 1600–1699 ----
        ShellExec(req: ShellExec) = SHELL_EXEC(1600, "shell.exec"),
    }
}

/// Capability group, as named in the policy (design §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Group {
    System,
    Logs,
    Security,
    Services,
    Firewall,
    Packages,
    Docker,
    Cron,
    Users,
    Files,
    Config,
    Profile,
    Search,
    Mesh,
    Game,
    Agent,
    Shell,
}

impl Group {
    /// In tag-range order.
    pub const ALL: [Group; 17] = [
        Group::System,
        Group::Logs,
        Group::Security,
        Group::Services,
        Group::Firewall,
        Group::Packages,
        Group::Docker,
        Group::Cron,
        Group::Users,
        Group::Files,
        Group::Config,
        Group::Profile,
        Group::Search,
        Group::Mesh,
        Group::Game,
        Group::Agent,
        Group::Shell,
    ];

    pub fn tag_range(self) -> RangeInclusive<u16> {
        let start = self as u16 * 100;
        start..=start + 99
    }

    pub fn from_tag(tag: u16) -> Option<Group> {
        Self::ALL.get(usize::from(tag / 100)).copied()
    }
}

/// Risk tier (design §4.2). Ordered: `Read < Change < Elevated`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Tier {
    Read,
    Change,
    Elevated,
}

/// What exec must verify beyond the envelope's device-key signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Authorization {
    /// The envelope signature is enough.
    Envelope,
    /// A `RootApproval` covering this server and op is required.
    RootApproval,
    /// The payload carries its own root/recovery signature (design §6.4).
    SelfSigned,
}

#[cfg(test)]
mod tests;
