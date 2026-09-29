//! Operations that can run in bulk, from runbooks, or from `bulk_run`.
//!
//! Plain data (strings, numbers); the app turns an `OpSpec` into a
//! `fleet_proto::Op` with the protocol's validated types
//! (`fleet_core::opspec`) before anything is signed.

use crate::msg::{ContainerActionKind, ProfileLevelArg, ProfileRoleArg, ServiceActionKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum OpSpec {
    /// `agent.health`.
    AgentHealth,
    /// `system.info`.
    SystemInfo,
    /// `unit.start|stop|restart|reload|enable|disable`.
    Unit {
        unit: String,
        action: ServiceActionKind,
    },
    /// `pkg.refresh` (`apt-get update`).
    PkgRefresh,
    /// `pkg.upgrade`.
    PkgUpgrade {
        #[serde(default)]
        security_only: bool,
    },
    /// `docker.containers.start|stop|restart`.
    Container {
        container: String,
        action: ContainerActionKind,
    },
    ComposePull {
        project: String,
    },
    ComposeRestart {
        project: String,
    },
    ComposeDeploy {
        project: String,
        compose_yaml: String,
        #[serde(default)]
        pull: bool,
    },
    ConfigRollback {
        path: String,
        version: u64,
    },
    ProfileCheck {
        level: ProfileLevelArg,
        #[serde(default)]
        roles: Vec<ProfileRoleArg>,
    },
    /// `system.reboot` (Elevated).
    SystemReboot {
        #[serde(default)]
        delay_s: u32,
    },
    /// `system.reboot.schedule` for a daily window in the server's local
    /// time: minutes since local midnight (`0..1440`, start != end, an end
    /// before the start wraps past midnight). Reboots at the next window
    /// start, or right away when the window is open now.
    SystemRebootWindow { start_min: u16, end_min: u16 },
    /// `shell.exec` (Elevated, policy-gated).
    ShellExec {
        user: String,
        command: String,
        #[serde(default = "d60")]
        timeout_s: u32,
    },
}

fn d60() -> u32 {
    60
}

impl OpSpec {
    /// Operation name as in the catalog (design §4.2), for prompts.
    pub fn name(&self) -> &'static str {
        match self {
            OpSpec::AgentHealth => "agent.health",
            OpSpec::SystemInfo => "system.info",
            OpSpec::Unit { action, .. } => match action {
                ServiceActionKind::Start => "unit.start",
                ServiceActionKind::Stop => "unit.stop",
                ServiceActionKind::Restart => "unit.restart",
                ServiceActionKind::Reload => "unit.reload",
                ServiceActionKind::Enable => "unit.enable",
                ServiceActionKind::Disable => "unit.disable",
            },
            OpSpec::PkgRefresh => "pkg.refresh",
            OpSpec::PkgUpgrade { .. } => "pkg.upgrade",
            OpSpec::Container { action, .. } => match action {
                ContainerActionKind::Start => "docker.containers.start",
                ContainerActionKind::Stop => "docker.containers.stop",
                ContainerActionKind::Restart => "docker.containers.restart",
            },
            OpSpec::ComposePull { .. } => "compose.pull",
            OpSpec::ComposeRestart { .. } => "compose.restart",
            OpSpec::ComposeDeploy { .. } => "compose.deploy",
            OpSpec::ConfigRollback { .. } => "config.rollback",
            OpSpec::ProfileCheck { .. } => "profile.check",
            OpSpec::SystemReboot { .. } => "system.reboot",
            OpSpec::SystemRebootWindow { .. } => "system.reboot.schedule",
            OpSpec::ShellExec { .. } => "shell.exec",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_shape() {
        let s: OpSpec = serde_json::from_value(serde_json::json!({
            "op": "unit", "unit": "nginx.service", "action": "restart"
        }))
        .unwrap();
        assert_eq!(s.name(), "unit.restart");
        let s: OpSpec = serde_json::from_value(serde_json::json!({"op": "pkg_upgrade"})).unwrap();
        assert_eq!(
            s,
            OpSpec::PkgUpgrade {
                security_only: false
            }
        );
        assert!(
            serde_json::from_value::<OpSpec>(serde_json::json!({"op": "roster_update"})).is_err()
        );
    }
}
