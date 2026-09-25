//! `OpSpec` (plain data from the bulk sheet, runbooks and `bulk_run`) to a
//! validated [`Op`]. Every string goes through the protocol's own
//! validated types, then [`Op::check_args`]; exec validates again (rule 3).

use fleet_proto::args::{
    AbsPath, ComposeFile, ComposeProject, ContainerId, ContainerName, ContainerRef, ShellCommand,
    UnitName, UserName,
};
use fleet_proto::op::{
    ProfileLevel, ProfileRole, ProfileSource, ProfileSpec, ShellExec, UpgradeScope,
};
use fleet_proto::{Op, Tier};
use fleetctl_proto::OpSpec;
use fleetctl_proto::msg::{
    ContainerActionKind, ProfileLevelArg, ProfileRoleArg, ServiceActionKind,
};

/// The argument that failed validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {0}")]
pub struct InvalidSpec(pub &'static str);

/// Output cap for `shell.exec` from bulk runs, snippets and MCP.
pub const SHELL_OUTPUT_CAP: u32 = 64 * 1024;

pub fn unit(name: &str) -> Result<UnitName, InvalidSpec> {
    let u = UnitName::new(name).map_err(|_| InvalidSpec("unit"))?;
    // Exec refuses these too; fail before signing.
    if u.is_fleet() {
        return Err(InvalidSpec("unit"));
    }
    Ok(u)
}

pub fn container(s: &str) -> Result<ContainerRef, InvalidSpec> {
    if let Ok(id) = ContainerId::new(s) {
        return Ok(ContainerRef::Id(id));
    }
    ContainerName::new(s)
        .map(ContainerRef::Name)
        .map_err(|_| InvalidSpec("container"))
}

pub fn unit_op(unit: UnitName, action: ServiceActionKind) -> Op {
    match action {
        ServiceActionKind::Start => Op::UnitStart { unit },
        ServiceActionKind::Stop => Op::UnitStop { unit },
        ServiceActionKind::Restart => Op::UnitRestart { unit },
        ServiceActionKind::Reload => Op::UnitReload { unit },
        ServiceActionKind::Enable => Op::UnitEnable { unit },
        ServiceActionKind::Disable => Op::UnitDisable { unit },
    }
}

pub fn container_op(container: ContainerRef, action: ContainerActionKind) -> Op {
    match action {
        ContainerActionKind::Start => Op::DockerContainersStart { container },
        ContainerActionKind::Stop => Op::DockerContainersStop {
            container,
            timeout_s: 10,
        },
        ContainerActionKind::Restart => Op::DockerContainersRestart {
            container,
            timeout_s: 10,
        },
    }
}

pub fn profile_spec(level: ProfileLevelArg, roles: &[ProfileRoleArg]) -> ProfileSpec {
    ProfileSpec {
        source: ProfileSource::Builtin {
            level: match level {
                ProfileLevelArg::Baseline => ProfileLevel::Baseline,
                ProfileLevelArg::Strict => ProfileLevel::Strict,
            },
            roles: roles
                .iter()
                .map(|r| match r {
                    ProfileRoleArg::Docker => ProfileRole::Docker,
                    ProfileRoleArg::Web => ProfileRole::Web,
                    ProfileRoleArg::Game => ProfileRole::Game,
                })
                .collect(),
        },
        only: Vec::new(),
    }
}

pub fn shell_exec(user: &str, command: &str, timeout_s: u32) -> Result<Op, InvalidSpec> {
    let req = ShellExec {
        user: UserName::new(user).map_err(|_| InvalidSpec("user"))?,
        command: ShellCommand::new(command).map_err(|_| InvalidSpec("command"))?,
        cwd: None,
        timeout_s,
        output_cap: SHELL_OUTPUT_CAP,
    };
    req.validate().map_err(|_| InvalidSpec("timeout_s"))?;
    Ok(Op::ShellExec(req))
}

/// Validated operation for `spec`. Stream ops can't be expressed.
pub fn to_op(spec: &OpSpec) -> Result<Op, InvalidSpec> {
    let op = match spec {
        OpSpec::AgentHealth => Op::AgentHealth,
        OpSpec::SystemInfo => Op::SystemInfo,
        OpSpec::Unit { unit: u, action } => unit_op(unit(u)?, *action),
        OpSpec::PkgRefresh => Op::PkgRefresh,
        OpSpec::PkgUpgrade { security_only } => Op::PkgUpgrade {
            scope: if *security_only {
                UpgradeScope::SecurityOnly
            } else {
                UpgradeScope::All
            },
        },
        OpSpec::Container {
            container: c,
            action,
        } => container_op(container(c)?, *action),
        OpSpec::ComposePull { project } => Op::ComposePull {
            project: ComposeProject::new(project).map_err(|_| InvalidSpec("project"))?,
        },
        OpSpec::ComposeRestart { project } => Op::ComposeRestart {
            project: ComposeProject::new(project).map_err(|_| InvalidSpec("project"))?,
        },
        OpSpec::ComposeDeploy {
            project,
            compose_yaml,
            pull,
        } => Op::ComposeDeploy {
            project: ComposeProject::new(project).map_err(|_| InvalidSpec("project"))?,
            file: ComposeFile::new(compose_yaml.as_str())
                .map_err(|_| InvalidSpec("compose_yaml"))?,
            pull: *pull,
        },
        OpSpec::ConfigRollback { path, version } => Op::ConfigRollback {
            path: AbsPath::new(path.as_str()).map_err(|_| InvalidSpec("path"))?,
            version: *version,
        },
        OpSpec::ProfileCheck { level, roles } => Op::ProfileCheck(profile_spec(*level, roles)),
        OpSpec::SystemReboot { delay_s } => {
            if *delay_s > 3600 {
                return Err(InvalidSpec("delay_s"));
            }
            Op::SystemReboot { delay_s: *delay_s }
        }
        OpSpec::ShellExec {
            user,
            command,
            timeout_s,
        } => shell_exec(user, command, *timeout_s)?,
    };
    op.check_args().map_err(|_| InvalidSpec("arguments"))?;
    if op.is_stream() {
        return Err(InvalidSpec("op"));
    }
    Ok(op)
}

/// Needs one root approval covering every target (design §6.4).
pub fn needs_approval(op: &Op) -> bool {
    op.tier() == Tier::Elevated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_and_validates() {
        let op = to_op(&OpSpec::Unit {
            unit: "nginx.service".into(),
            action: ServiceActionKind::Restart,
        })
        .unwrap();
        assert!(matches!(op, Op::UnitRestart { .. }));
        assert!(!needs_approval(&op));
        assert_eq!(
            to_op(&OpSpec::Unit {
                unit: "fleet-exec.service".into(),
                action: ServiceActionKind::Stop,
            }),
            Err(InvalidSpec("unit"))
        );
        assert_eq!(
            to_op(&OpSpec::Unit {
                unit: "nginx; rm -rf /".into(),
                action: ServiceActionKind::Stop,
            }),
            Err(InvalidSpec("unit"))
        );
        let sh = to_op(&OpSpec::ShellExec {
            user: "deploy".into(),
            command: "uptime".into(),
            timeout_s: 30,
        })
        .unwrap();
        assert!(needs_approval(&sh));
        assert!(
            to_op(&OpSpec::ShellExec {
                user: "deploy".into(),
                command: "uptime".into(),
                timeout_s: 0,
            })
            .is_err()
        );
        let c = to_op(&OpSpec::Container {
            container: "0123456789ab".into(),
            action: ContainerActionKind::Restart,
        })
        .unwrap();
        assert!(matches!(
            c,
            Op::DockerContainersRestart {
                container: ContainerRef::Id(_),
                ..
            }
        ));
        assert!(
            to_op(&OpSpec::ConfigRollback {
                path: "etc/x".into(),
                version: 1
            })
            .is_err()
        );
    }
}
