//! Per-operation metadata: group, tier, authorization, session rules and
//! argument checks. Every match is exhaustive, so a new variant fails to
//! compile until it is classified here.

use super::mesh::validate_peers;
use super::{Authorization, Group, NAMES, Op, Tier};
use crate::v1::args::{AbsPath, ArgError, at_most, ensure};

impl Op {
    /// Group by tag range. Unknown tags beyond every range map to `Shell`,
    /// the most restricted group; they are rejected as `Unsupported` anyway.
    pub fn group(&self) -> Group {
        Group::from_tag(self.tag()).unwrap_or(Group::Shell)
    }

    /// Tier computed from the operation and its arguments (design §4.2).
    /// A policy can raise it (`[elevated] extra`), never lower it; exec
    /// raises it further when [`Op::may_escalate`] and server state require
    /// (sudo membership for `cron.set`, the Compose deny-list).
    pub fn tier(&self) -> Tier {
        match self {
            Op::SystemInfo
            | Op::MetricsSubscribe { .. }
            | Op::MetricsQuery { .. }
            | Op::ProcessesList { .. }
            | Op::ProcessesHistory { .. }
            | Op::ConnectionsList
            | Op::EventsQuery { .. }
            | Op::HealthChecksList
            | Op::JournalQuery(_)
            | Op::JournalFollow(_)
            | Op::LogfilesList
            | Op::LogfileTail { .. }
            | Op::WeblogQuery { .. }
            | Op::LoginsQuery { .. }
            | Op::BansList
            | Op::BansConfigGet
            | Op::PortsList
            | Op::CertsList
            | Op::AuditRun { .. }
            | Op::IntegrityStatus
            | Op::UnitList
            | Op::UnitStatus { .. }
            | Op::FirewallGet
            | Op::ChangesList
            | Op::PkgList { .. }
            | Op::PkgUpgradable
            | Op::PkgHistory { .. }
            | Op::DockerContainersList { .. }
            | Op::DockerContainersGet { .. }
            | Op::DockerLogs { .. }
            | Op::DockerStats { .. }
            | Op::DockerImagesList
            | Op::DockerVolumesList
            | Op::DockerNetworksList
            | Op::ComposeList
            | Op::ComposeStatus { .. }
            | Op::CronList { .. }
            | Op::TimersList
            | Op::UsersList
            | Op::AuthorizedKeysGet { .. }
            | Op::DuScan { .. }
            | Op::FindLarge { .. }
            | Op::ConfigHistory { .. }
            | Op::ConfigDiff { .. }
            | Op::ConfigPathsGet
            | Op::ProfileCheck(_)
            | Op::ProfilePlan(_)
            | Op::SearchPackages(_)
            | Op::SearchPorts(_)
            | Op::SearchProcesses(_)
            | Op::SearchFiles(_)
            | Op::SearchJournal(_)
            | Op::SearchUsers(_)
            | Op::MeshStatus
            | Op::GameStatus { .. }
            | Op::GameBackupsList { .. }
            | Op::AgentHealth
            | Op::RosterPending
            | Op::RosterGet
            | Op::AlertRulesGet
            | Op::AuditQuery { .. } => Tier::Read,

            Op::ProcessSignal { .. }
            | Op::ProcessRenice { .. }
            | Op::HealthChecksUpdate(_)
            | Op::SystemReboot { .. }
            | Op::BansAdd { .. }
            | Op::BansRemove { .. }
            | Op::BansConfigSet(_)
            | Op::UnitStart { .. }
            | Op::UnitStop { .. }
            | Op::UnitRestart { .. }
            | Op::UnitReload { .. }
            | Op::UnitEnable { .. }
            | Op::UnitDisable { .. }
            | Op::FirewallApply(_)
            | Op::ChangeConfirm { .. }
            | Op::PkgRefresh
            | Op::PkgUpgrade { .. }
            | Op::PkgInstall { .. }
            | Op::PkgRemove { .. }
            | Op::PkgHold { .. }
            | Op::DockerContainersStart { .. }
            | Op::DockerContainersStop { .. }
            | Op::DockerContainersRestart { .. }
            | Op::DockerContainersRemove { .. }
            | Op::DockerImagesPull { .. }
            | Op::DockerImagesRemove { .. }
            | Op::DockerImagesPrune { .. }
            | Op::DockerVolumesRemove { .. }
            | Op::ComposeDeploy { .. }
            | Op::ComposePull { .. }
            | Op::ComposeRestart { .. }
            | Op::ComposeDown { .. }
            | Op::UsersLock { .. }
            | Op::UsersDelete { .. }
            | Op::GroupsCreate { .. }
            | Op::MeshJoin(_)
            | Op::MeshLeave
            | Op::MeshPeersSet { .. }
            | Op::GameInstall { .. }
            | Op::GameUpdate { .. }
            | Op::GameBackup { .. }
            | Op::GameRestore { .. }
            | Op::GameRcon { .. }
            | Op::GameRemove { .. } => Tier::Change,

            // Conditional (design §4.2).
            Op::CronSet { user, .. } => elevated_if(user.is_root()),
            Op::UsersCreate { groups, .. } | Op::UsersGroupsSet { groups, .. } => {
                elevated_if(groups.iter().any(|g| g.is_privileged()))
            }
            // Change only below `/srv` and for unprotected `/etc` files.
            Op::ConfigRollback { path, .. } => elevated_if(
                !(under_any(path, &["/srv"])
                    || (under_any(path, &["/etc"]) && !path.is_protected_config())),
            ),
            // Tracking a path outside the config roots exposes (and lets
            // `config.rollback` rewrite) arbitrary files.
            Op::ConfigPathsSet { tracked, secret } => elevated_if(
                tracked
                    .iter()
                    .chain(secret)
                    .any(|p| !under_any(p, &CONFIG_ROOTS)),
            ),
            // A custom profile can configure anything; built-ins are
            // reviewed with the agent release. Setting the admin's sudo
            // password is root-equivalent too (whoever knows it has sudo).
            Op::ProfileApply {
                spec,
                password_hash,
                ..
            } => elevated_if(spec.is_custom() || password_hash.is_some()),

            Op::AuthorizedKeysSet { .. }
            | Op::RosterUpdate { .. }
            | Op::RosterVeto { .. }
            | Op::PolicyUpdate { .. }
            | Op::AgentUpdateStage { .. }
            | Op::AgentUpdateCommit { .. }
            | Op::AgentUpdateRollback
            | Op::AgentUninstallPrepare
            | Op::AgentUninstall { .. }
            | Op::AlertRulesUpdate(_)
            | Op::ShellExec(_)
            | Op::Unknown { .. } => Tier::Elevated,
        }
    }

    /// Whether exec may raise the tier to Elevated from facts the arguments
    /// don't carry: `cron.set` for a user in `sudo` or another privileged
    /// group, `users.create`/`users.groups.set` whose groups grant privilege
    /// through sudoers, and `compose.deploy` whose parsed file uses a
    /// deny-listed feature (design §4.2). The Mac runs the same checks to
    /// know whether to attach a root approval; exec answers
    /// `ApprovalRequired` otherwise.
    pub fn may_escalate(&self) -> bool {
        matches!(
            self,
            Op::CronSet { .. }
                | Op::ComposeDeploy { .. }
                | Op::UsersCreate { .. }
                | Op::UsersGroupsSet { .. }
        )
    }

    /// Derived from the tier: Elevated needs a root approval unless the
    /// payload is itself root/recovery-signed.
    pub fn authorization(&self) -> Authorization {
        match self {
            Op::RosterUpdate { .. } | Op::AgentUpdateStage { .. } => Authorization::SelfSigned,
            _ if self.tier() == Tier::Elevated => Authorization::RootApproval,
            _ => Authorization::Envelope,
        }
    }

    /// Opened with `StreamOpen` (answered with `StreamData` chunks, each a
    /// postcard `Payload`), never with `Request`.
    pub fn is_stream(&self) -> bool {
        matches!(
            self,
            Op::MetricsSubscribe { .. }
                | Op::JournalFollow(_)
                | Op::LogfileTail { .. }
                | Op::DockerLogs { .. }
                | Op::DockerStats { .. }
        )
    }

    /// Accepted in a monitor session (design §5.2): telemetry subscriptions,
    /// the event log, `agent.health` and the (public) roster only.
    pub fn monitor_allowed(&self) -> bool {
        matches!(
            self,
            Op::AgentHealth | Op::MetricsSubscribe { .. } | Op::EventsQuery { .. } | Op::RosterGet
        )
    }

    /// Ops that would make Fleet take over host security: refused with
    /// `PolicyDenied` while the server's policy is `SecurityMode::AgentOnly`
    /// (design §5.4). Read-only ops (`bans.list`, `bans.config.get`,
    /// `authorized_keys.get`, `audit.run`) stay allowed since they never
    /// write anything.
    ///
    /// Mesh ops (`mesh.join`, `mesh.leave`, `mesh.peers.set`) are an
    /// explicit exception: they set up operator-initiated overlay
    /// connectivity between servers, not host security, so they stay
    /// allowed under Agent-only (design §4.6, §5.4).
    pub fn takes_over_security(&self) -> bool {
        match self {
            Op::FirewallApply(_)
            | Op::AuthorizedKeysSet { .. }
            | Op::ProfileApply { .. }
            | Op::BansAdd { .. }
            | Op::BansRemove { .. }
            | Op::BansConfigSet(_) => true,
            // A rollback that would rewrite sshd config (incl. drop-ins),
            // sudoers(.d), nftables or `/etc/fleet` is a security takeover
            // too, even though `config.rollback` itself isn't otherwise
            // security-specific.
            Op::ConfigRollback { path, .. } => {
                path.is_protected_config() || path.as_str() == "/etc/nftables.conf"
            }
            _ => false,
        }
    }

    /// Accepted in a recovery session (design §5.5).
    pub fn recovery_allowed(&self) -> bool {
        matches!(
            self,
            Op::SystemInfo | Op::RosterUpdate { .. } | Op::RosterPending | Op::RosterGet
        )
    }

    /// Arms an auto-revert timer and answers `Payload::ChangePending`
    /// (carrying the handler's own result); the change stays until
    /// `change.confirm` arrives over a fresh connection (design §4.10).
    /// `profile.apply` only when its phase may run an SSH or firewall
    /// module ([`super::ProfilePhase::arms_auto_revert`]).
    pub fn auto_revert(&self) -> bool {
        match self {
            Op::FirewallApply(_)
            | Op::AuthorizedKeysSet { .. }
            | Op::MeshJoin(_)
            | Op::MeshLeave
            | Op::MeshPeersSet { .. }
            | Op::AgentUpdateCommit { .. }
            | Op::AgentUninstallPrepare => true,
            Op::ProfileApply { spec, phase, .. } => phase.arms_auto_revert(spec),
            _ => false,
        }
    }

    /// Operation arguments as the audit log stores them
    /// (`OpSummary::args`): the wire payload, except that a sudo password
    /// hash is replaced by its BLAKE3 (`SudoPasswordHash::redacted`).
    pub fn audit_payload(&self) -> Vec<u8> {
        match self {
            Op::ProfileApply {
                spec,
                plan_hash,
                phase,
                password_hash: Some(h),
            } => Op::ProfileApply {
                spec: spec.clone(),
                plan_hash: *plan_hash,
                phase: *phase,
                password_hash: Some(h.redacted()),
            }
            .payload(),
            _ => self.payload(),
        }
    }

    /// Replaces versioned state wholesale, so exec rejects the command
    /// unless `CommandBody::expected_version` is `Some` and current
    /// (`VersionConflict` otherwise; design §2.6).
    pub fn requires_expected_version(&self) -> bool {
        matches!(
            self,
            Op::FirewallApply(_)
                | Op::AuthorizedKeysSet { .. }
                | Op::CronSet { .. }
                | Op::HealthChecksUpdate(_)
                | Op::AlertRulesUpdate(_)
                | Op::BansConfigSet(_)
                | Op::ConfigPathsSet { .. }
                | Op::MeshPeersSet { .. }
        )
    }

    /// Whether `name` is in this build's operation catalog ([`NAMES`]).
    pub fn is_known_name(name: &str) -> bool {
        NAMES.contains(&name)
    }

    /// Collection bounds and cross-field rules that the argument types can't
    /// express alone. Exec runs it before planning; failures are
    /// `InvalidArgument`. Scalar arguments were validated when decoded.
    pub fn check_args(&self) -> Result<(), ArgError> {
        match self {
            Op::MetricsQuery { range, series, .. } => {
                range.validate()?;
                at_most(series, 256, "series")
            }
            Op::ProcessesList { limit, .. } => ensure((1..=1000).contains(limit), "limit"),
            Op::ProcessesHistory { range } | Op::LoginsQuery { range, .. } => range.validate(),
            Op::WeblogQuery {
                range,
                limit,
                status,
                ..
            } => {
                range.validate()?;
                ensure((1..=1000).contains(limit), "limit")?;
                ensure(status.is_none_or(|s| s.is_valid()), "status range")
            }
            Op::EventsQuery { limit, .. } | Op::AuditQuery { limit, .. } => {
                ensure((1..=1000).contains(limit), "limit")
            }
            Op::PkgHistory { range, limit } => {
                range.validate()?;
                ensure((1..=10_000).contains(limit), "limit")
            }
            Op::HealthChecksUpdate(set) => set.validate(),
            Op::SystemReboot { delay_s } => ensure(*delay_s <= 3600, "reboot delay"),
            Op::JournalQuery(q) | Op::JournalFollow(q) => q.validate(),
            Op::LogfileTail { lines, .. } => ensure(*lines <= 10_000, "lines"),
            Op::BansAdd { duration_s, .. } => {
                ensure((60..=30 * 86_400).contains(duration_s), "ban duration")
            }
            Op::BansConfigSet(c) => c.validate(),
            Op::UnitStart { unit }
            | Op::UnitStop { unit }
            | Op::UnitRestart { unit }
            | Op::UnitReload { unit }
            | Op::UnitEnable { unit }
            | Op::UnitDisable { unit } => ensure(!unit.is_fleet(), "fleet unit"),
            Op::FirewallApply(set) => set.validate(),
            Op::PkgUpgrade { scope } => match scope {
                super::UpgradeScope::Packages(p) => {
                    ensure(!p.is_empty(), "packages")?;
                    at_most(p, 256, "packages")
                }
                _ => Ok(()),
            },
            Op::PkgInstall { packages } => {
                ensure(!packages.is_empty(), "packages")?;
                at_most(packages, 256, "packages")
            }
            Op::PkgRemove { packages, .. } | Op::PkgHold { packages, .. } => {
                ensure(!packages.is_empty(), "packages")?;
                at_most(packages, 256, "packages")
            }
            Op::DockerLogs { tail, .. } => ensure(*tail <= 10_000, "tail"),
            Op::DockerStats { containers } => at_most(containers, 256, "containers"),
            Op::CronSet { entries, .. } => at_most(entries, 256, "cron entries"),
            Op::UsersCreate { name, groups, .. } | Op::UsersGroupsSet { name, groups } => {
                ensure(!name.is_root(), "user")?;
                at_most(groups, 32, "groups")
            }
            Op::UsersDelete { name, .. } => ensure(!name.is_root(), "user"),
            Op::AuthorizedKeysSet { keys, .. } => at_most(keys, 64, "keys"),
            Op::DuScan {
                max_depth, limit, ..
            } => {
                ensure(*max_depth <= 16, "depth")?;
                ensure((1..=10_000).contains(limit), "limit")
            }
            Op::FindLarge { limit, .. } => ensure((1..=10_000).contains(limit), "limit"),
            Op::ConfigHistory { range, limit, .. } => {
                range.validate()?;
                ensure((1..=10_000).contains(limit), "limit")
            }
            Op::ConfigRollback { path, .. } => ensure(!path.is_fleet_owned(), "fleet path"),
            Op::ConfigPathsSet { tracked, secret } => {
                at_most(tracked, 256, "tracked paths")?;
                at_most(secret, 256, "secret paths")?;
                ensure(!tracked.iter().any(|p| p.is_fleet_owned()), "fleet path")
            }
            Op::ProfileCheck(spec) | Op::ProfilePlan(spec) => spec.validate(),
            Op::ProfileApply {
                spec,
                phase,
                password_hash,
                ..
            } => {
                spec.validate()?;
                phase.validate(spec, password_hash.as_ref())
            }
            Op::SearchPackages(q)
            | Op::SearchPorts(q)
            | Op::SearchProcesses(q)
            | Op::SearchFiles(q)
            | Op::SearchJournal(q)
            | Op::SearchUsers(q) => q.validate(),
            Op::MeshJoin(c) => c.validate(),
            Op::MeshPeersSet { peers } => validate_peers(peers),
            Op::AlertRulesUpdate(set) => set.validate(),
            Op::ShellExec(req) => req.validate(),

            Op::SystemInfo
            | Op::MetricsSubscribe { .. }
            | Op::ProcessSignal { .. }
            | Op::ProcessRenice { .. }
            | Op::ConnectionsList
            | Op::HealthChecksList
            | Op::LogfilesList
            | Op::BansList
            | Op::BansRemove { .. }
            | Op::BansConfigGet
            | Op::PortsList
            | Op::CertsList
            | Op::AuditRun { .. }
            | Op::IntegrityStatus
            | Op::UnitList
            | Op::UnitStatus { .. }
            | Op::FirewallGet
            | Op::ChangeConfirm { .. }
            | Op::ChangesList
            | Op::PkgList { .. }
            | Op::PkgUpgradable
            | Op::PkgRefresh
            | Op::DockerContainersList { .. }
            | Op::DockerContainersGet { .. }
            | Op::DockerContainersStart { .. }
            | Op::DockerContainersStop { .. }
            | Op::DockerContainersRestart { .. }
            | Op::DockerContainersRemove { .. }
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
            | Op::TimersList
            | Op::UsersList
            | Op::UsersLock { .. }
            | Op::GroupsCreate { .. }
            | Op::AuthorizedKeysGet { .. }
            | Op::ConfigDiff { .. }
            | Op::ConfigPathsGet
            | Op::MeshStatus
            | Op::MeshLeave
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
            | Op::RosterGet
            | Op::RosterVeto { .. }
            | Op::PolicyUpdate { .. }
            | Op::AgentUpdateStage { .. }
            | Op::AgentUpdateCommit { .. }
            | Op::AgentUpdateRollback
            | Op::AgentUninstallPrepare
            | Op::AgentUninstall { .. }
            | Op::AlertRulesGet
            | Op::Unknown { .. } => Ok(()),
        }
    }
}

fn elevated_if(cond: bool) -> Tier {
    if cond { Tier::Elevated } else { Tier::Change }
}

/// Roots whose files `config.paths.set` may track at tier Change; anything
/// else is Elevated (the handler enforces the same allow-list).
pub const CONFIG_ROOTS: [&str; 4] = ["/etc", "/srv", "/opt", "/usr/local/etc"];

fn under_any(p: &AbsPath, roots: &[&str]) -> bool {
    roots
        .iter()
        .any(|r| AbsPath::new(*r).is_ok_and(|r| p.is_under(&r)))
}

#[cfg(test)]
mod agent_only_tests {
    use super::*;

    #[test]
    fn takes_over_security_flags_the_security_takeover_ops() {
        // Read-only ops: never refused in Agent-only mode.
        assert!(!Op::FirewallGet.takes_over_security());
        assert!(!Op::BansList.takes_over_security());
        assert!(!Op::BansConfigGet.takes_over_security());
        // Mutating: these are what Agent-only refuses.
        assert!(Op::BansRemove {
            addr: "1.2.3.4".parse().unwrap()
        }
        .takes_over_security());
    }

    #[test]
    fn config_rollback_takes_over_security_only_for_security_relevant_paths() {
        let rollback = |p: &str| Op::ConfigRollback {
            path: AbsPath::new(p).unwrap(),
            version: 1,
        };
        // Security-relevant: sshd config (incl. drop-ins), sudoers(.d),
        // nftables, Fleet's own directory.
        for p in [
            "/etc/ssh/sshd_config",
            "/etc/ssh/sshd_config.d/00-fleet.conf",
            "/etc/sudoers",
            "/etc/sudoers.d/ops",
            "/etc/nftables.conf",
            "/etc/fleet/authorized_keys/admin",
        ] {
            assert!(rollback(p).takes_over_security(), "{p}");
        }
        // Not security-relevant: an ordinary tracked config file.
        assert!(!rollback("/etc/nginx/nginx.conf").takes_over_security());
        assert!(!rollback("/srv/app/config.yaml").takes_over_security());
    }

    #[test]
    fn mesh_ops_are_not_takeover_security() {
        // Explicit exception (design §4.6, §5.4): mesh sets up
        // operator-initiated overlay connectivity, not host security.
        assert!(!Op::MeshLeave.takes_over_security());
    }
}
