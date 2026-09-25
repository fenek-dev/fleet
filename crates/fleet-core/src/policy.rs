//! Default per-server policy (design §5.4) written at agent install.

use fleet_proto::policy::{Actors, AiAccess, Capabilities, Elevated, Limits, Policy, Safety};
use fleet_proto::{FleetId, Group, ServerId};

/// Version 1: every allowable group, `shell.exec` off, AI full access
/// (the operator's current choice), the design's default limits.
pub fn default_policy(fleet_id: FleetId, server_id: ServerId) -> Policy {
    Policy {
        version: 1,
        fleet_id,
        server_id,
        capabilities: Capabilities {
            allow: Group::ALL
                .into_iter()
                .filter(|g| !matches!(g, Group::Agent | Group::Shell))
                .collect(),
            shell_exec: false,
            shell_exec_users: Vec::new(),
        },
        elevated: Elevated { extra: Vec::new() },
        actors: Actors {
            ai: AiAccess::Full,
            ai_bulk_confirm_above: 5,
            ai_commands_per_minute: 60,
        },
        limits: Limits {
            commands_per_minute: 240,
            max_stream_sessions: 32,
        },
        safety: Safety {
            auto_revert_seconds: 60,
        },
    }
}

/// TOML as `fleet-agent install --policy` and `policy.update` take it.
pub fn to_toml(p: &Policy) -> Result<String, String> {
    p.validate().map_err(|e| e.to_string())?;
    toml::to_string(p).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_round_trips_through_the_agent_parser() {
        let p = default_policy(FleetId([7; 16]), ServerId::new("srv_abc123def456").unwrap());
        let text = to_toml(&p).unwrap();
        assert_eq!(Policy::from_toml(&text).unwrap(), p);
        assert!(text.contains("shell_exec = false"));
        assert!(!p.capabilities.allow.contains(&Group::Shell));
    }
}
