use super::*;
use crate::tagged::Bytes;
use crate::v1::alert::{AlertKind, AlertRule, HealthCheck, Probe, Severity};
use crate::v1::args::{
    Cidr, ContainerName, CronCommand, CronSpec, FirewallMode, FirewallRule, FwAction, FwChain,
    FwComment, GrepPattern, HttpPath, ModuleId, Port, PortRange, Priority, ProfileToml, Protocol,
    RuleId, ShellCommand, SshKeyAlgo, WgKey,
};
use crate::v1::{AgentVersion, DeviceId, ReleaseManifest, Signature};
use crate::{decode, encode};
use proptest::prelude::*;
use std::collections::{HashMap, HashSet};

fn unit(s: &str) -> UnitName {
    UnitName::new(s).unwrap()
}
fn user(s: &str) -> UserName {
    UserName::new(s).unwrap()
}
fn path(s: &str) -> AbsPath {
    AbsPath::new(s).unwrap()
}
fn project() -> ComposeProject {
    ComposeProject::new("app").unwrap()
}
fn container() -> ContainerRef {
    ContainerRef::Name(ContainerName::new("web").unwrap())
}
fn game() -> GameName {
    GameName::new("valheim").unwrap()
}
fn pkg(s: &str) -> DebPackageName {
    DebPackageName::new(s).unwrap()
}
fn range() -> TimeRange {
    TimeRange {
        since_ms: Some(1),
        until_ms: Some(2),
    }
}
fn search() -> SearchQuery {
    SearchQuery {
        term: SearchTerm::new("nginx").unwrap(),
        case_sensitive: false,
        roots: vec![],
        range: TimeRange::default(),
        limit: 50,
    }
}
fn journal() -> JournalQuery {
    JournalQuery {
        units: vec![unit("ssh.service")],
        priority: Some(Priority::Warning),
        range: range(),
        grep: Some(GrepPattern::new("Failed").unwrap()),
        after_cursor: None,
        limit: 100,
    }
}
fn spec() -> ProfileSpec {
    ProfileSpec {
        source: ProfileSource::Builtin {
            level: ProfileLevel::Baseline,
            roles: vec![ProfileRole::Docker],
        },
        only: vec![ModuleId::new("ssh.hardening").unwrap()],
    }
}
fn custom_spec() -> ProfileSpec {
    ProfileSpec {
        source: ProfileSource::Custom(
            ProfileToml::new("[profile]\nextends = \"baseline\"\n").unwrap(),
        ),
        only: vec![],
    }
}
fn peer() -> WgPeer {
    WgPeer {
        public_key: WgKey::new([3; 32]).unwrap(),
        endpoint: None,
        allowed_ips: vec!["10.9.0.2/32".parse().unwrap()],
        keepalive_s: 25,
    }
}
fn ssh_key() -> SshPublicKey {
    let mut blob = Vec::new();
    for part in [&b"ssh-ed25519"[..], &[0x42; 32][..]] {
        blob.extend_from_slice(&(part.len() as u32).to_be_bytes());
        blob.extend_from_slice(part);
    }
    SshPublicKey::new(SshKeyAlgo::Ed25519, blob, "laptop".into()).unwrap()
}
fn ruleset() -> FirewallRuleSet {
    FirewallRuleSet {
        mode: FirewallMode::Managed,
        rules: vec![FirewallRule {
            chain: FwChain::Input,
            action: FwAction::Accept,
            proto: Protocol::Tcp,
            ports: vec![PortRange::single(Port::new(443).unwrap())],
            source: None,
            rate_limit: None,
            comment: FwComment::new("https").unwrap(),
        }],
    }
}

/// One value per variant, with arguments that don't trigger a conditional
/// tier. The exhaustive match makes a new variant a compile error here until
/// it is added to `samples` (and so to every check below).
pub(super) fn samples() -> Vec<Op> {
    fn _exhaustive(op: &Op) {
        match op {
            Op::SystemInfo
            | Op::MetricsSubscribe { .. }
            | Op::MetricsQuery { .. }
            | Op::ProcessesList { .. }
            | Op::ProcessSignal { .. }
            | Op::ProcessRenice { .. }
            | Op::ProcessesHistory { .. }
            | Op::ConnectionsList
            | Op::EventsQuery { .. }
            | Op::HealthChecksList
            | Op::HealthChecksUpdate(_)
            | Op::SystemReboot { .. }
            | Op::SystemRebootSchedule { .. }
            | Op::SystemRebootCancel
            | Op::SystemRebootStatus
            | Op::JournalQuery(_)
            | Op::JournalFollow(_)
            | Op::LogfilesList
            | Op::LogfileTail { .. }
            | Op::WeblogQuery { .. }
            | Op::LoginsQuery { .. }
            | Op::BansList
            | Op::BansAdd { .. }
            | Op::BansRemove { .. }
            | Op::BansConfigGet
            | Op::BansConfigSet(_)
            | Op::PortsList
            | Op::CertsList
            | Op::AuditRun { .. }
            | Op::IntegrityStatus
            | Op::UnitList
            | Op::UnitStatus { .. }
            | Op::UnitStart { .. }
            | Op::UnitStop { .. }
            | Op::UnitRestart { .. }
            | Op::UnitReload { .. }
            | Op::UnitEnable { .. }
            | Op::UnitDisable { .. }
            | Op::FirewallGet
            | Op::FirewallCounters
            | Op::FirewallApply(_)
            | Op::ChangeConfirm { .. }
            | Op::ChangeRevert { .. }
            | Op::ChangesList
            | Op::PkgList { .. }
            | Op::PkgUpgradable
            | Op::PkgHistory { .. }
            | Op::PkgRefresh
            | Op::PkgUpgrade { .. }
            | Op::PkgInstall { .. }
            | Op::PkgRemove { .. }
            | Op::PkgHold { .. }
            | Op::DockerContainersList { .. }
            | Op::DockerContainersGet { .. }
            | Op::DockerContainersStart { .. }
            | Op::DockerContainersStop { .. }
            | Op::DockerContainersRestart { .. }
            | Op::DockerContainersRemove { .. }
            | Op::DockerLogs { .. }
            | Op::DockerStats { .. }
            | Op::DockerImagesList
            | Op::DockerImagesPull { .. }
            | Op::DockerImagesRemove { .. }
            | Op::DockerImagesPrune { .. }
            | Op::DockerVolumesList
            | Op::DockerVolumesRemove { .. }
            | Op::DockerNetworksList
            | Op::ComposeList
            | Op::ComposeStatus { .. }
            | Op::ComposeDeploy { .. }
            | Op::ComposePull { .. }
            | Op::ComposeRestart { .. }
            | Op::ComposeDown { .. }
            | Op::CronList { .. }
            | Op::CronSet { .. }
            | Op::TimersList
            | Op::UsersList
            | Op::UsersCreate { .. }
            | Op::UsersLock { .. }
            | Op::UsersDelete { .. }
            | Op::UsersGroupsSet { .. }
            | Op::GroupsCreate { .. }
            | Op::AuthorizedKeysGet { .. }
            | Op::AuthorizedKeysSet { .. }
            | Op::DuScan { .. }
            | Op::FindLarge { .. }
            | Op::ConfigHistory { .. }
            | Op::ConfigDiff { .. }
            | Op::ConfigRollback { .. }
            | Op::ConfigPathsGet
            | Op::ConfigPathsSet { .. }
            | Op::ProfileCheck(_)
            | Op::ProfilePlan(_)
            | Op::ProfileApply { .. }
            | Op::SearchPackages(_)
            | Op::SearchPorts(_)
            | Op::SearchProcesses(_)
            | Op::SearchFiles(_)
            | Op::SearchJournal(_)
            | Op::SearchUsers(_)
            | Op::MeshStatus
            | Op::MeshJoin(_)
            | Op::MeshLeave
            | Op::MeshPeersSet { .. }
            | Op::GameStatus { .. }
            | Op::GameInstall { .. }
            | Op::GameUpdate { .. }
            | Op::GameBackup { .. }
            | Op::GameRestore { .. }
            | Op::GameRcon { .. }
            | Op::GameBackupsList { .. }
            | Op::GameRemove { .. }
            | Op::AgentHealth
            | Op::RosterUpdate { .. }
            | Op::RosterPending
            | Op::RosterVeto { .. }
            | Op::RosterGet
            | Op::PolicyUpdate { .. }
            | Op::AgentUpdateStage { .. }
            | Op::AgentUpdateCommit { .. }
            | Op::AgentUpdateRollback
            | Op::AgentUninstallPrepare
            | Op::AgentUninstall { .. }
            | Op::AlertRulesGet
            | Op::AlertRulesUpdate(_)
            | Op::AuditQuery { .. }
            | Op::ShellExec(_)
            | Op::Unknown { .. } => {}
        }
    }
    let pid = Pid::new(1234).unwrap();
    let version = AgentVersion {
        major: 0,
        minor: 2,
        patch: 0,
    };
    vec![
        Op::SystemInfo,
        Op::MetricsSubscribe {
            interval: SampleInterval::OneSecond,
        },
        Op::MetricsQuery {
            range: range(),
            resolution: Resolution::Minute,
            series: vec![1, 2, 3],
        },
        Op::ProcessesList {
            sort: ProcessSort::Cpu,
            limit: 50,
        },
        Op::ProcessSignal {
            pid,
            signal: Signal::Term,
        },
        Op::ProcessRenice {
            pid,
            nice: Nice::new(10).unwrap(),
        },
        Op::ProcessesHistory { range: range() },
        Op::ConnectionsList,
        Op::EventsQuery {
            since_run_id: Some([7; 16]),
            since_seq: 41,
            limit: 500,
        },
        Op::HealthChecksList,
        Op::HealthChecksUpdate(HealthCheckSet {
            version: 2,
            checks: vec![HealthCheck {
                id: crate::v1::args::CheckId::new("api").unwrap(),
                probe: Probe::Http {
                    port: Port::new(8080).unwrap(),
                    ipv6: false,
                    tls: false,
                    path: HttpPath::new("/healthz").unwrap(),
                    expect_status: 200,
                },
                interval_s: 30,
                timeout_ms: 2000,
            }],
        }),
        Op::SystemReboot { delay_s: 60 },
        Op::SystemRebootSchedule {
            when: RebootWhen::Window {
                start_min: 180,
                end_min: 300,
            },
        },
        Op::SystemRebootCancel,
        Op::SystemRebootStatus,
        Op::JournalQuery(journal()),
        Op::JournalFollow(journal()),
        Op::LogfilesList,
        Op::LogfileTail {
            path: path("/var/log/nginx/access.log"),
            lines: 200,
            follow: true,
        },
        Op::WeblogQuery {
            range: range(),
            limit: 100,
            status: Some(StatusRange { min: 400, max: 499 }),
            path_prefix: Some(HttpPath::new("/api/").unwrap()),
            client: Some("203.0.113.9".parse().unwrap()),
        },
        Op::LoginsQuery {
            range: range(),
            failed_only: true,
            limit: 100,
        },
        Op::BansList,
        Op::BansAdd {
            addr: "203.0.113.9".parse().unwrap(),
            duration_s: 3600,
            comment: Label::new("scanner").unwrap(),
        },
        Op::BansRemove {
            addr: "2001:db8::1".parse().unwrap(),
        },
        Op::BansConfigGet,
        Op::BansConfigSet(BanConfig {
            threshold: 5,
            window_s: 600,
            ban_steps_s: vec![3600, 86_400, 7 * 86_400],
            exempt: vec!["198.51.100.0/24".parse().unwrap()],
            web_scanners: true,
        }),
        Op::PortsList,
        Op::CertsList,
        Op::AuditRun {
            level: ProfileLevel::Baseline,
        },
        Op::IntegrityStatus,
        Op::UnitList,
        Op::UnitStatus {
            unit: unit("nginx.service"),
        },
        Op::UnitStart {
            unit: unit("nginx.service"),
        },
        Op::UnitStop {
            unit: unit("nginx.service"),
        },
        Op::UnitRestart {
            unit: unit("nginx.service"),
        },
        Op::UnitReload {
            unit: unit("nginx.service"),
        },
        Op::UnitEnable {
            unit: unit("backup.timer"),
        },
        Op::UnitDisable {
            unit: unit("cups.socket"),
        },
        Op::FirewallGet,
        Op::FirewallCounters,
        Op::FirewallApply(ruleset()),
        Op::ChangeConfirm { change_id: [9; 16] },
        Op::ChangeRevert { change_id: [9; 16] },
        Op::ChangesList,
        Op::PkgList { filter: None },
        Op::PkgUpgradable,
        Op::PkgHistory {
            range: range(),
            limit: 100,
        },
        Op::PkgRefresh,
        Op::PkgUpgrade {
            scope: UpgradeScope::SecurityOnly,
        },
        Op::PkgInstall {
            packages: vec![PkgSpec {
                name: pkg("htop"),
                version: None,
            }],
        },
        Op::PkgRemove {
            packages: vec![pkg("telnet")],
            purge: true,
        },
        Op::PkgHold {
            packages: vec![pkg("linux-image-amd64")],
            hold: true,
        },
        Op::DockerContainersList { all: true },
        Op::DockerContainersGet {
            container: container(),
        },
        Op::DockerContainersStart {
            container: container(),
        },
        Op::DockerContainersStop {
            container: container(),
            timeout_s: 10,
        },
        Op::DockerContainersRestart {
            container: container(),
            timeout_s: 10,
        },
        Op::DockerContainersRemove {
            container: container(),
            force: false,
        },
        Op::DockerLogs {
            container: container(),
            tail: 100,
            since_ms: None,
            follow: true,
        },
        Op::DockerStats { containers: vec![] },
        Op::DockerImagesList,
        Op::DockerImagesPull {
            image: ImageRef::new("nginx:1.27").unwrap(),
        },
        Op::DockerImagesRemove {
            image: ImageRef::new("nginx:1.25").unwrap(),
            force: false,
        },
        Op::DockerImagesPrune { all_unused: false },
        Op::DockerVolumesList,
        Op::DockerVolumesRemove {
            volume: VolumeName::new("old_data").unwrap(),
        },
        Op::DockerNetworksList,
        Op::ComposeList,
        Op::ComposeStatus { project: project() },
        Op::ComposeDeploy {
            project: project(),
            file: ComposeFile::new("services:\n  web:\n    image: nginx\n").unwrap(),
            pull: true,
        },
        Op::ComposePull { project: project() },
        Op::ComposeRestart { project: project() },
        Op::ComposeDown {
            project: project(),
            remove_volumes: false,
        },
        Op::CronList { user: None },
        Op::CronSet {
            user: user("ops"),
            entries: vec![CronEntry {
                schedule: CronSpec::new("0 4 * * *").unwrap(),
                command: CronCommand::new("/usr/local/bin/backup").unwrap(),
                comment: Label::new("nightly").unwrap(),
            }],
        },
        Op::TimersList,
        Op::UsersList,
        Op::UsersCreate {
            name: user("deploy"),
            groups: vec![GroupName::new("www-data").unwrap()],
            shell: LoginShell::Bash,
            comment: Label::new("CI deploy").unwrap(),
        },
        Op::UsersLock {
            name: user("deploy"),
            locked: true,
        },
        Op::UsersDelete {
            name: user("deploy"),
            remove_home: false,
        },
        Op::UsersGroupsSet {
            name: user("deploy"),
            groups: vec![],
        },
        Op::GroupsCreate {
            name: GroupName::new("backup").unwrap(),
        },
        Op::AuthorizedKeysGet { user: user("ops") },
        Op::AuthorizedKeysSet {
            user: user("ops"),
            keys: vec![ssh_key()],
        },
        Op::DuScan {
            path: path("/var"),
            max_depth: 3,
            limit: 1000,
        },
        Op::FindLarge {
            root: path("/"),
            min_bytes: 100 << 20,
            limit: 100,
        },
        Op::ConfigHistory {
            path: Some(path("/etc/nginx/nginx.conf")),
            range: range(),
            limit: 100,
        },
        Op::ConfigDiff {
            path: path("/etc/nginx/nginx.conf"),
            from: 3,
            to: None,
        },
        Op::ConfigRollback {
            path: path("/etc/nginx/nginx.conf"),
            version: 3,
        },
        Op::ConfigPathsGet,
        Op::ConfigPathsSet {
            tracked: vec![path("/opt/app/config.yml")],
            secret: vec![path("/opt/app/secret.key")],
        },
        Op::ProfileCheck(spec()),
        Op::ProfilePlan(spec()),
        Op::ProfileApply {
            spec: spec(),
            plan_hash: [4; 32],
            phase: ProfilePhase::Access,
            password_hash: None,
        },
        Op::SearchPackages(search()),
        Op::SearchPorts(search()),
        Op::SearchProcesses(search()),
        Op::SearchFiles(SearchQuery {
            roots: vec![path("/srv")],
            ..search()
        }),
        Op::SearchJournal(search()),
        Op::SearchUsers(search()),
        Op::MeshStatus,
        Op::MeshJoin(MeshConfig {
            address: "10.9.0.1".parse().unwrap(),
            network: "10.9.0.0/24".parse().unwrap(),
            listen_port: Port::new(51820).unwrap(),
            peers: vec![peer()],
        }),
        Op::MeshLeave,
        Op::MeshPeersSet {
            peers: vec![peer()],
        },
        Op::GameStatus { name: None },
        Op::GameInstall {
            name: game(),
            template: GameTemplateId::new("valheim").unwrap(),
        },
        Op::GameUpdate { name: game() },
        Op::GameBackup { name: game() },
        Op::GameRestore {
            name: game(),
            backup_id: 1_750_000_000_000,
        },
        Op::GameRcon {
            name: game(),
            command: RconCommand::new("save").unwrap(),
        },
        Op::GameBackupsList { name: game() },
        Op::GameRemove {
            name: game(),
            keep_data: true,
        },
        Op::AgentHealth,
        Op::RosterUpdate {
            roster: Box::new(crate::v1::test_support::signed_roster()),
        },
        Op::RosterPending,
        Op::RosterVeto {
            pending_hash: [7; 32],
        },
        Op::RosterGet,
        Op::PolicyUpdate {
            policy_toml: "version = 1".into(),
        },
        Op::AgentUpdateStage {
            manifest: Box::new(SignedReleaseManifest {
                manifest: ReleaseManifest {
                    version,
                    blake3: [5; 32],
                    min_proto: 1,
                    target: crate::v1::AgentTarget::X86_64,
                },
                device_id: DeviceId([2; 16]),
                signature: Signature([6; 64]),
            }),
            staged_path_hash: [5; 32],
        },
        Op::AgentUpdateCommit { version },
        Op::AgentUpdateRollback,
        Op::AgentUninstallPrepare,
        Op::AgentUninstall {
            keep_audit: true,
            remove_firewall: false,
        },
        Op::AlertRulesGet,
        Op::AuditQuery {
            after_seq: 41,
            limit: 500,
        },
        Op::AlertRulesUpdate(AlertRuleSet {
            version: 4,
            rules: vec![AlertRule {
                id: RuleId::new("disk").unwrap(),
                kind: AlertKind::DiskUsage { mount: None },
                threshold: 900,
                for_s: 300,
                severity: Severity::Warning,
                enabled: true,
            }],
        }),
        Op::ShellExec(ShellExec {
            user: user("ops"),
            command: ShellCommand::new("uptime").unwrap(),
            cwd: None,
            timeout_s: 30,
            output_cap: 65_536,
        }),
    ]
}

#[test]
fn every_variant_has_a_mapping() {
    let mut tags = HashSet::new();
    let mut names = HashSet::new();
    for op in samples() {
        let name = op.name();
        assert!(tags.insert(op.tag()), "duplicate tag {}", op.tag());
        assert!(names.insert(name), "duplicate name {name}");
        let group = Group::from_tag(op.tag()).expect("tag inside a group range");
        assert_eq!(op.group(), group);
        assert!(group.tag_range().contains(&op.tag()));
        assert!(!matches!(op, Op::Unknown { .. }));
        assert!(Op::is_known_tag(op.tag()));
        // Self-signed and approval-gated ops must be Elevated, and back.
        if op.authorization() != Authorization::Envelope {
            assert_eq!(op.tier(), Tier::Elevated, "{name}");
        }
        if op.tier() == Tier::Elevated {
            assert_ne!(op.authorization(), Authorization::Envelope, "{name}");
        }
        if op.monitor_allowed() {
            assert_eq!(op.tier(), Tier::Read, "{name}");
        }
        if op.is_stream() {
            assert_eq!(op.tier(), Tier::Read, "{name}");
        }
        if op.auto_revert() || op.requires_expected_version() || op.may_escalate() {
            assert_ne!(op.tier(), Tier::Read, "{name}");
        }
        if op.recovery_allowed() {
            assert!(op.group() == Group::System || op.group() == Group::Agent);
        }
        assert_eq!(op.check_args(), Ok(()), "{name}");
        assert_eq!(decode::<Op>(&encode(&op)).unwrap(), op, "{name}");
        assert!(Op::is_known_name(name), "{name} missing from NAMES");
    }
    assert_eq!(
        names.len(),
        NAMES.len(),
        "NAMES lists an op with no variant"
    );
    assert_eq!(tag::ALL.len(), NAMES.len());
    assert!(!Op::is_known_name("unknown"));
}

/// Per group: sub-blocks of 10, names start with the group's name (or an
/// alias for the resources it owns).
#[test]
fn names_match_groups() {
    let prefixes: HashMap<Group, &[&str]> = HashMap::from([
        (
            Group::System,
            &[
                "system.",
                "metrics.",
                "process",
                "connections.",
                "events.",
                "health_checks.",
            ][..],
        ),
        (Group::Logs, &["journal.", "logfile", "weblog."][..]),
        (
            Group::Security,
            &[
                "logins.",
                "bans.",
                "ports.",
                "certs.",
                "audit.",
                "integrity.",
            ][..],
        ),
        (Group::Services, &["unit."][..]),
        (Group::Firewall, &["firewall.", "change"][..]),
        (Group::Packages, &["pkg."][..]),
        (Group::Docker, &["docker.", "compose."][..]),
        (Group::Cron, &["cron.", "timers."][..]),
        (Group::Users, &["users.", "groups.", "authorized_keys."][..]),
        (Group::Files, &["du.", "find."][..]),
        (Group::Config, &["config."][..]),
        (Group::Profile, &["profile."][..]),
        (Group::Search, &["search."][..]),
        (Group::Mesh, &["mesh."][..]),
        (Group::Game, &["game."][..]),
        (
            Group::Agent,
            &["agent.", "roster.", "policy.", "alert_rules.", "audit.query"][..],
        ),
        (Group::Shell, &["shell."][..]),
    ]);
    for op in samples() {
        let p = prefixes[&op.group()];
        assert!(
            p.iter().any(|p| op.name().starts_with(p)),
            "{} in {:?}",
            op.name(),
            op.group()
        );
    }
}

/// The tier table of design §4.2, pinned per operation.
#[test]
fn tier_table() {
    const READ: &[&str] = &[
        "system.info",
        "metrics.subscribe",
        "metrics.query",
        "processes.list",
        "processes.history",
        "connections.list",
        "events.query",
        "health_checks.list",
        "journal.query",
        "journal.follow",
        "logfiles.list",
        "logfile.tail",
        "weblog.query",
        "logins.query",
        "bans.list",
        "bans.config.get",
        "ports.list",
        "certs.list",
        "audit.run",
        "integrity.status",
        "unit.list",
        "unit.status",
        "firewall.get",
        "firewall.counters",
        "changes.list",
        "system.reboot.status",
        "pkg.list",
        "pkg.upgradable",
        "pkg.history",
        "docker.containers.list",
        "docker.containers.get",
        "docker.logs",
        "docker.stats",
        "docker.images.list",
        "docker.volumes.list",
        "docker.networks.list",
        "compose.list",
        "compose.status",
        "cron.list",
        "timers.list",
        "users.list",
        "authorized_keys.get",
        "du.scan",
        "find.large",
        "config.history",
        "config.diff",
        "config.paths.get",
        "profile.check",
        "profile.plan",
        "search.packages",
        "search.ports",
        "search.processes",
        "search.files",
        "search.journal",
        "search.users",
        "mesh.status",
        "game.status",
        "game.backups.list",
        "agent.health",
        "roster.pending",
        "roster.get",
        "alert_rules.get",
        "audit.query",
    ];
    const ELEVATED: &[&str] = &[
        "authorized_keys.set",
        "roster.update",
        "roster.veto",
        "policy.update",
        "agent.update.stage",
        "agent.update.commit",
        "agent.update.rollback",
        "agent.uninstall.prepare",
        "agent.uninstall",
        "alert_rules.update",
        "shell.exec",
    ];
    for op in samples() {
        let n = op.name();
        let want = if READ.contains(&n) {
            Tier::Read
        } else if ELEVATED.contains(&n) {
            Tier::Elevated
        } else {
            Tier::Change
        };
        assert_eq!(op.tier(), want, "{n}");
    }
    for n in READ.iter().chain(ELEVATED) {
        assert!(Op::is_known_name(n), "{n}");
    }
    // Every agent-group op that changes anything is Elevated (design §5.4).
    for op in samples() {
        if op.group() == Group::Agent && op.tier() != Tier::Read {
            assert_eq!(op.tier(), Tier::Elevated, "{}", op.name());
        }
    }
    let self_signed: Vec<_> = samples()
        .into_iter()
        .filter(|o| o.authorization() == Authorization::SelfSigned)
        .map(|o| o.name())
        .collect();
    assert_eq!(self_signed, ["roster.update", "agent.update.stage"]);
}

#[test]
fn conditional_tiers() {
    let cron = |u: &str| Op::CronSet {
        user: user(u),
        entries: vec![],
    };
    assert_eq!(cron("root").tier(), Tier::Elevated);
    assert_eq!(cron("ops").tier(), Tier::Change);
    assert!(cron("ops").may_escalate());

    let create = |g: &[&str]| Op::UsersCreate {
        name: user("bob"),
        groups: g.iter().map(|g| GroupName::new(*g).unwrap()).collect(),
        shell: LoginShell::Bash,
        comment: Label::new("").unwrap(),
    };
    assert_eq!(create(&["users"]).tier(), Tier::Change);
    assert_eq!(create(&["users", "sudo"]).tier(), Tier::Elevated);
    assert_eq!(create(&["docker"]).tier(), Tier::Elevated);
    assert_eq!(
        create(&["docker"]).authorization(),
        Authorization::RootApproval
    );
    let set_groups = Op::UsersGroupsSet {
        name: user("bob"),
        groups: vec![GroupName::new("sudo").unwrap()],
    };
    assert_eq!(set_groups.tier(), Tier::Elevated);
    // Sudoers-granted privilege is only known on the server.
    assert!(create(&["users"]).may_escalate());
    assert!(set_groups.may_escalate());

    let rollback = |p: &str| Op::ConfigRollback {
        path: path(p),
        version: 1,
    };
    assert_eq!(rollback("/etc/nginx/nginx.conf").tier(), Tier::Change);
    assert_eq!(rollback("/srv/app/compose.yaml").tier(), Tier::Change);
    for p in [
        "/etc/sudoers.d/ops",
        "/etc/ssh/sshd_config",
        "/etc/fleet/x",
        "/etc/shadow",
        // Outside `/srv` and `/etc`: Elevated by default.
        "/opt/app/config.yml",
        "/usr/local/etc/x.conf",
        "/root/.bashrc",
        "/etcetera/x",
    ] {
        assert_eq!(rollback(p).tier(), Tier::Elevated, "{p}");
    }

    let paths_set = |t: &[&str], s: &[&str]| Op::ConfigPathsSet {
        tracked: t.iter().map(|p| path(p)).collect(),
        secret: s.iter().map(|p| path(p)).collect(),
    };
    assert_eq!(
        paths_set(&["/etc/x", "/srv/a", "/opt/b", "/usr/local/etc/c"], &[]).tier(),
        Tier::Change
    );
    assert_eq!(paths_set(&["/root/x"], &[]).tier(), Tier::Elevated);
    assert_eq!(paths_set(&[], &["/home/u/.env"]).tier(), Tier::Elevated);
    assert_eq!(paths_set(&["/usr/local/bin/x"], &[]).tier(), Tier::Elevated);

    let apply = |spec| Op::ProfileApply {
        spec,
        plan_hash: [0; 32],
        phase: ProfilePhase::All,
        password_hash: None,
    };
    assert_eq!(apply(spec()).tier(), Tier::Change);
    assert_eq!(apply(custom_spec()).tier(), Tier::Elevated);
    assert_eq!(
        apply(custom_spec()).authorization(),
        Authorization::RootApproval
    );
    // Checking or planning a custom profile changes nothing.
    assert_eq!(Op::ProfilePlan(custom_spec()).tier(), Tier::Read);
    assert!(
        rollback("/etc/systemd/system/fleet-exec.service")
            .check_args()
            .is_err()
    );

    let deploy = samples()
        .into_iter()
        .find(|o| o.name() == "compose.deploy")
        .unwrap();
    assert_eq!(deploy.tier(), Tier::Change);
    assert!(deploy.may_escalate());
}

#[test]
fn check_args_rejects() {
    assert!(
        Op::UnitRestart {
            unit: unit("fleet-exec.service")
        }
        .check_args()
        .is_err()
    );
    assert!(
        Op::UnitStatus {
            unit: unit("fleet-exec.service")
        }
        .check_args()
        .is_ok()
    );
    assert!(
        Op::UsersDelete {
            name: user("root"),
            remove_home: false
        }
        .check_args()
        .is_err()
    );
    assert!(Op::PkgInstall { packages: vec![] }.check_args().is_err());
    assert!(
        Op::FirewallApply(FirewallRuleSet {
            mode: FirewallMode::BansOnly,
            ..ruleset()
        })
        .check_args()
        .is_err()
    );
    assert!(
        Op::MeshJoin(MeshConfig {
            address: "10.8.0.1".parse().unwrap(),
            network: "10.9.0.0/24".parse().unwrap(),
            listen_port: Port::new(51820).unwrap(),
            peers: vec![],
        })
        .check_args()
        .is_err()
    );
    let mesh = |ips: &[&str]| {
        Op::MeshJoin(MeshConfig {
            address: "10.9.0.1".parse().unwrap(),
            network: "10.9.0.0/16".parse().unwrap(),
            listen_port: Port::new(51820).unwrap(),
            peers: vec![WgPeer {
                allowed_ips: ips.iter().map(|c| c.parse().unwrap()).collect(),
                ..peer()
            }],
        })
    };
    assert!(mesh(&["10.9.0.2/32", "10.9.4.0/24"]).check_args().is_ok());
    assert!(mesh(&["10.9.0.0/16"]).check_args().is_ok());
    // Outside the mesh network, wider than it, or a default route.
    assert!(mesh(&["10.10.0.2/32"]).check_args().is_err());
    assert!(mesh(&["10.0.0.0/8"]).check_args().is_err());
    assert!(mesh(&["0.0.0.0/0"]).check_args().is_err());
    assert!(mesh(&["fd00::1/128"]).check_args().is_err());
    // The network itself: private, and no wider than /16 or /48.
    let net = |n: &str, a: &str| {
        Op::MeshJoin(MeshConfig {
            address: a.parse().unwrap(),
            network: n.parse().unwrap(),
            listen_port: Port::new(51820).unwrap(),
            peers: vec![],
        })
        .check_args()
        .is_ok()
    };
    assert!(net("10.9.0.0/16", "10.9.0.1"));
    assert!(net("172.20.0.0/24", "172.20.0.1"));
    assert!(net("192.168.50.0/24", "192.168.50.1"));
    assert!(net("100.100.0.0/16", "100.100.0.1"));
    assert!(net("fd12:3456:789a::/48", "fd12:3456:789a::1"));
    assert!(!net("10.0.0.0/8", "10.0.0.1"));
    assert!(!net("8.8.0.0/16", "8.8.0.1"));
    assert!(!net("172.32.0.0/16", "172.32.0.1"));
    assert!(!net("100.128.0.0/16", "100.128.0.1"));
    assert!(!net("fd00::/32", "fd00::1"));
    assert!(!net("2001:db8::/48", "2001:db8::1"));
    let peers = |ips: &[&str]| Op::MeshPeersSet {
        peers: vec![WgPeer {
            allowed_ips: ips.iter().map(|c| c.parse().unwrap()).collect(),
            ..peer()
        }],
    };
    assert!(
        peers(&["10.9.0.0/16", "fd00:1:2::/48"])
            .check_args()
            .is_ok()
    );
    for bad in ["0.0.0.0/0", "::/0", "10.0.0.0/15", "fd00::/47"] {
        assert!(peers(&[bad]).check_args().is_err(), "{bad}");
    }
    assert!(Op::SystemReboot { delay_s: 3601 }.check_args().is_err());
    let sched = |when| Op::SystemRebootSchedule { when };
    for ok in [
        RebootWhen::In { delay_s: 0 },
        RebootWhen::In {
            delay_s: REBOOT_MAX_LEAD_S,
        },
        RebootWhen::At { at_ms: 1 },
        RebootWhen::Window {
            start_min: 1380,
            end_min: 60,
        },
    ] {
        assert!(sched(ok).check_args().is_ok(), "{ok:?}");
    }
    for bad in [
        RebootWhen::In {
            delay_s: REBOOT_MAX_LEAD_S + 1,
        },
        RebootWhen::At { at_ms: 0 },
        RebootWhen::Window {
            start_min: 60,
            end_min: 60,
        },
        RebootWhen::Window {
            start_min: 1440,
            end_min: 60,
        },
        RebootWhen::Window {
            start_min: 0,
            end_min: 1440,
        },
    ] {
        assert!(sched(bad).check_args().is_err(), "{bad:?}");
    }
    let weblog = |limit, status| Op::WeblogQuery {
        range: TimeRange::default(),
        limit,
        status,
        path_prefix: None,
        client: None,
    };
    assert!(weblog(1000, None).check_args().is_ok());
    assert!(weblog(0, None).check_args().is_err());
    assert!(weblog(1001, None).check_args().is_err());
    for bad in [(500, 400), (99, 200), (200, 600)] {
        let s = StatusRange {
            min: bad.0,
            max: bad.1,
        };
        assert!(weblog(10, Some(s)).check_args().is_err(), "{bad:?}");
    }
    assert!(
        Op::AuditQuery {
            after_seq: 0,
            limit: 0
        }
        .check_args()
        .is_err()
    );
    assert_eq!(
        Op::AuditQuery {
            after_seq: 0,
            limit: 1
        }
        .tier(),
        Tier::Read
    );
    assert!(
        Op::ProcessesList {
            sort: ProcessSort::Pid,
            limit: 0
        }
        .check_args()
        .is_err()
    );
    assert!(
        Op::ShellExec(ShellExec {
            user: user("ops"),
            command: ShellCommand::new("true").unwrap(),
            cwd: None,
            timeout_s: 0,
            output_cap: 1,
        })
        .check_args()
        .is_err()
    );
}

#[test]
fn profile_apply_phases() {
    let only = |ids: &[&str]| ProfileSpec {
        only: ids.iter().map(|i| ModuleId::new(*i).unwrap()).collect(),
        ..spec()
    };
    let hash = SudoPasswordHash::crypt("$y$j9T$abcdefghijklmnop$ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
        .unwrap();
    let apply = |spec: ProfileSpec, phase, pw: Option<SudoPasswordHash>| Op::ProfileApply {
        spec,
        plan_hash: [0; 32],
        phase,
        password_hash: pw,
    };
    use ProfilePhase::*;
    // Auto-revert only when an SSH/firewall module may run.
    assert!(apply(only(&[]), Access, None).auto_revert());
    assert!(apply(only(&["firewall.baseline"]), All, None).auto_revert());
    assert!(!apply(only(&["sysctl"]), All, None).auto_revert());
    assert!(!apply(only(&[]), Accounts, None).auto_revert());
    assert!(!apply(only(&[]), System, None).auto_revert());
    for phase in [Accounts, Access, System] {
        assert!(apply(only(&[]), phase, None).check_args().is_ok());
    }
    // `All` names its modules, and never mixes access and other modules.
    assert!(apply(only(&[]), All, None).check_args().is_err());
    assert!(
        apply(only(&["sysctl", "firewall.baseline"]), All, None)
            .check_args()
            .is_err()
    );
    assert!(
        apply(only(&["ssh.hardening", "firewall.baseline"]), All, None)
            .check_args()
            .is_ok()
    );
    assert!(
        apply(only(&["sysctl", "auditd"]), All, None)
            .check_args()
            .is_ok()
    );
    // `only` must fit the phase (as far as access modules go).
    assert!(
        apply(only(&["ssh.hardening"]), System, None)
            .check_args()
            .is_err()
    );
    assert!(
        apply(only(&["firewall.baseline"]), Accounts, None)
            .check_args()
            .is_err()
    );
    assert!(apply(only(&["sysctl"]), Access, None).check_args().is_err());
    assert!(apply(only(&["sysctl"]), System, None).check_args().is_ok());
    // A password only where `admin.user` runs, never the audit form.
    assert!(
        apply(only(&[]), Accounts, Some(hash.clone()))
            .check_args()
            .is_ok()
    );
    assert!(
        apply(only(&["admin.user"]), All, Some(hash.clone()))
            .check_args()
            .is_ok()
    );
    assert!(
        apply(only(&[]), Access, Some(hash.clone()))
            .check_args()
            .is_err()
    );
    assert!(
        apply(only(&[]), System, Some(hash.clone()))
            .check_args()
            .is_err()
    );
    assert!(
        apply(only(&[]), Accounts, Some(hash.redacted()))
            .check_args()
            .is_err()
    );
    // Tier doesn't depend on the phase.
    assert_eq!(apply(only(&[]), System, None).tier(), Tier::Change);
    assert_eq!(apply(custom_spec(), Accounts, None).tier(), Tier::Elevated);
    // Setting the sudo password is Elevated even for a built-in profile.
    assert_eq!(
        apply(only(&[]), Accounts, Some(hash.clone())).tier(),
        Tier::Elevated
    );
}

#[test]
fn audit_summary_redacts_the_password_hash() {
    let crypt = "$6$saltsalt$0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJ./";
    let op = Op::ProfileApply {
        spec: spec(),
        plan_hash: [1; 32],
        phase: ProfilePhase::Accounts,
        password_hash: Some(SudoPasswordHash::crypt(crypt).unwrap()),
    };
    let s = crate::v1::OpSummary::from(&op);
    assert_eq!(s.tag, tag::PROFILE_APPLY);
    let hay = String::from_utf8_lossy(&s.args);
    assert!(!hay.contains("saltsalt"), "crypt hash in the audit args");
    assert!(
        !format!("{op:?}").contains("saltsalt"),
        "crypt hash in Debug"
    );
    // The audit args still decode, with the BLAKE3 in place of the hash.
    let Op::ProfileApply {
        password_hash: Some(h),
        phase,
        ..
    } = <Op as crate::tagged::Tagged>::from_wire(s.tag, &s.args).unwrap()
    else {
        panic!("audit args don't decode");
    };
    assert!(h.is_redacted());
    assert_eq!(phase, ProfilePhase::Accounts);
    assert_eq!(
        h.expose(),
        format!(
            "$blake3${}",
            hex::encode(blake3::hash(crypt.as_bytes()).as_bytes())
        )
    );
    // Everything else is the plain wire payload.
    assert_eq!(
        crate::v1::OpSummary::from(&Op::RosterGet).args,
        Op::RosterGet.payload()
    );
}

#[test]
fn stream_and_session_sets() {
    let names = |f: fn(&Op) -> bool| -> Vec<&'static str> {
        samples().into_iter().filter(f).map(|o| o.name()).collect()
    };
    assert_eq!(
        names(Op::is_stream),
        [
            "metrics.subscribe",
            "journal.follow",
            "logfile.tail",
            "docker.logs",
            "docker.stats"
        ]
    );
    assert_eq!(
        names(Op::monitor_allowed),
        [
            "metrics.subscribe",
            "events.query",
            "agent.health",
            "roster.get"
        ]
    );
    assert_eq!(
        names(Op::recovery_allowed),
        [
            "system.info",
            "roster.update",
            "roster.pending",
            "roster.get"
        ]
    );
    assert_eq!(
        names(Op::auto_revert),
        [
            "firewall.apply",
            "authorized_keys.set",
            "profile.apply",
            "mesh.join",
            "mesh.leave",
            "mesh.peers.set",
            "agent.update.commit",
            "agent.uninstall.prepare"
        ]
    );
}

#[test]
fn group_ranges() {
    assert_eq!(Group::from_tag(0), Some(Group::System));
    assert_eq!(Group::from_tag(1599), Some(Group::Agent));
    assert_eq!(Group::from_tag(1600), Some(Group::Shell));
    assert_eq!(Group::from_tag(1699), Some(Group::Shell));
    assert_eq!(Group::from_tag(1700), None);
    assert_eq!(Group::Firewall.tag_range(), 400..=499);
}

#[test]
fn phase0_tags_pinned() {
    assert_eq!(tag::SYSTEM_INFO, 0);
    assert_eq!(tag::AGENT_HEALTH, 1500);
    assert_eq!(tag::ROSTER_UPDATE, 1510);
    assert_eq!(tag::ROSTER_PENDING, 1511);
    assert_eq!(tag::ROSTER_VETO, 1512);
    assert_eq!(tag::POLICY_UPDATE, 1520);
}

#[test]
fn unknown_tag_decodes_and_skips_payload() {
    // tag 777 (cron range), 3-byte payload, followed by a trailing field.
    let bytes = encode(&(777u16, Bytes(&[1, 2, 3]), 42u8));
    let (op, rest): (Op, u8) = decode(&bytes).unwrap();
    assert_eq!(op, Op::Unknown { tag: 777 });
    assert_eq!(op.group(), Group::Cron);
    assert_eq!(op.tier(), Tier::Elevated);
    assert_eq!(op.authorization(), Authorization::RootApproval);
    assert_eq!(rest, 42);
}

#[test]
fn known_tag_rejects_bad_payload() {
    let bytes = encode(&(tag::SYSTEM_INFO, Bytes(&[0])));
    assert!(decode::<Op>(&bytes).is_err());
    let bytes = encode(&(tag::ROSTER_VETO, Bytes(&[0; 33])));
    assert!(decode::<Op>(&bytes).is_err());
    // A valid encoding of an invalid argument is a decode error too.
    let bytes = encode(&(tag::UNIT_START, Bytes(&encode("x.mount"))));
    assert!(decode::<Op>(&bytes).is_err());
    let bad_cidr = encode(&(std::net::IpAddr::from([10, 0, 0, 1]), 8u8));
    assert!(decode::<Cidr>(&bad_cidr).is_err());
}

/// Generated ops: every sample, plus variants built from generated
/// arguments, plus unknown tags.
fn op_strategy() -> impl Strategy<Value = Op> {
    let unit =
        "[a-z][a-z0-9@._-]{0,20}\\.(service|timer|socket)".prop_map(|s| UnitName::new(s).unwrap());
    let path = prop::collection::vec("[a-z0-9_-]{1,10}", 0..6)
        .prop_map(|p| AbsPath::new(format!("/{}", p.join("/"))).unwrap());
    let cidr = (any::<u32>(), 0u8..=32).prop_map(|(a, p)| {
        let m = if p == 0 {
            0
        } else {
            a & (u32::MAX << (32 - p))
        };
        Cidr::new(std::net::IpAddr::from(m.to_be_bytes()), p).unwrap()
    });
    prop_oneof![
        prop::sample::select(samples()),
        unit.prop_map(|unit| Op::UnitRestart { unit }),
        (path.clone(), any::<u64>())
            .prop_map(|(path, version)| Op::ConfigRollback { path, version }),
        (any::<[u8; 16]>()).prop_map(|change_id| Op::ChangeConfirm { change_id }),
        (prop::collection::vec(cidr, 0..20), any::<bool>()).prop_map(|(exempt, web)| {
            Op::BansConfigSet(BanConfig {
                threshold: 5,
                window_s: 600,
                ban_steps_s: vec![3600],
                exempt,
                web_scanners: web,
            })
        }),
        ("[0-5]?[0-9] [0-9] \\* \\* [0-6]", "[a-z/]{1,30}").prop_map(|(s, c)| Op::CronSet {
            user: UserName::new("ops").unwrap(),
            entries: vec![CronEntry {
                schedule: CronSpec::new(&s).unwrap(),
                command: CronCommand::new(format!("/{c}")).unwrap(),
                comment: Label::new("").unwrap(),
            }],
        }),
        (path, any::<u8>(), any::<u32>()).prop_map(|(path, max_depth, limit)| Op::DuScan {
            path,
            max_depth,
            limit
        }),
        any::<u16>()
            .prop_filter("unknown", |t| !Op::is_known_tag(*t))
            .prop_map(|tag| Op::Unknown { tag }),
    ]
}

proptest! {
    #[test]
    fn op_roundtrip(op in op_strategy()) {
        let bytes = encode(&op);
        let back: Op = decode(&bytes).unwrap();
        if let Op::Unknown { .. } = op {
            prop_assert_eq!(back, op);
        } else {
            prop_assert_eq!(&back, &op);
            prop_assert_eq!(encode(&back), bytes);
        }
    }

    #[test]
    fn arbitrary_payload_never_panics(t in prop::sample::select(tag::ALL.to_vec()), payload in prop::collection::vec(any::<u8>(), 0..64)) {
        if let Ok(op) = decode::<Op>(&encode(&(t, Bytes(&payload)))) {
            prop_assert_eq!(op.tag(), t);
            let again: Op = decode(&encode(&op)).unwrap();
            prop_assert_eq!(again, op);
        }
    }
}
