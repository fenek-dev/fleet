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

/// Cache setting holding the policy this Mac last pushed to a server
/// (MAC'd like every setting). There is no policy read op, so this copy
/// is what the Mac knows the agent enforces (MCP limits, design §8).
fn setting_key(server: &ServerId) -> String {
    format!("policy/{server}")
}

/// Records `policy_toml` as pushed to `server` (install, `policy.update`).
pub fn remember_pushed(
    cache: &crate::cache::Cache,
    server: &ServerId,
    policy_toml: &str,
) -> Result<(), crate::cache::CacheError> {
    cache.set_setting(&setting_key(server), policy_toml.as_bytes())
}

/// The policy last pushed to `server`, if this Mac pushed one.
pub fn pushed(cache: &crate::cache::Cache, server: &ServerId) -> Option<Policy> {
    let raw = cache.setting(&setting_key(server)).ok().flatten()?;
    Policy::from_toml(std::str::from_utf8(&raw).ok()?).ok()
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

    #[test]
    fn pushed_copy_round_trips() {
        let cache = crate::cache::Cache::open_in_memory().unwrap();
        let s = ServerId::new("srv_abc123def456").unwrap();
        assert!(pushed(&cache, &s).is_none());
        let mut p = default_policy(FleetId([7; 16]), s.clone());
        p.actors.ai_bulk_confirm_above = 2;
        remember_pushed(&cache, &s, &to_toml(&p).unwrap()).unwrap();
        assert_eq!(pushed(&cache, &s).unwrap().actors.ai_bulk_confirm_above, 2);
    }
}
