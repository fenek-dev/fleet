//! Default per-server policy (design §5.4) written at agent install.

use fleet_proto::policy::{
    Actors, AiAccess, Capabilities, Elevated, Limits, Policy, Safety, SecurityMode,
};
use fleet_proto::{FleetId, Group, ServerId};

/// Version 1: every allowable group, `shell.exec` off, AI full access
/// (the operator's current choice), the design's default limits.
///
/// `security`: `Managed` (Fleet owns bans, `authorized_keys` and the
/// firewall) or `AgentOnly` (an already-configured server the operator
/// doesn't want Fleet to touch security on; design §5.4, §10.1). Switching
/// later is a normal `policy.update`.
pub fn default_policy(fleet_id: FleetId, server_id: ServerId, security: SecurityMode) -> Policy {
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
        security,
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

/// Flag: the server runs a policy this Mac never saw (adopted agent,
/// reinstall without a cached copy). Mac-side checks treat it as the
/// strictest until a real policy is pushed.
fn unknown_key(server: &ServerId) -> String {
    format!("policy-unknown/{server}")
}

/// Records `policy_toml` as pushed to `server` (install, `policy.update`).
pub fn remember_pushed(
    cache: &crate::cache::Cache,
    server: &ServerId,
    policy_toml: &str,
) -> Result<(), crate::cache::CacheError> {
    cache.set_setting(&setting_key(server), policy_toml.as_bytes())?;
    cache.set_setting(&unknown_key(server), b"")
}

/// The server keeps a policy this Mac didn't push: an already cached copy
/// stays as it is; without one the policy is marked unknown (never the
/// default, which may be looser than what the server enforces).
pub fn keep_or_mark_unknown(
    cache: &crate::cache::Cache,
    server: &ServerId,
) -> Result<(), crate::cache::CacheError> {
    if pushed(cache, server).is_some() {
        return Ok(());
    }
    cache.set_setting(&unknown_key(server), b"1")
}

/// The server's policy is unknown to this Mac (see
/// [`keep_or_mark_unknown`]); `false` once any policy is pushed.
pub fn is_unknown(cache: &crate::cache::Cache, server: &ServerId) -> bool {
    pushed(cache, server).is_none()
        && cache
            .setting(&unknown_key(server))
            .ok()
            .flatten()
            .is_some_and(|v| !v.is_empty())
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
        let p = default_policy(
            FleetId([7; 16]),
            ServerId::new("srv_abc123def456").unwrap(),
            SecurityMode::Managed,
        );
        let text = to_toml(&p).unwrap();
        assert_eq!(Policy::from_toml(&text).unwrap(), p);
        assert!(text.contains("shell_exec = false"));
        assert!(!p.capabilities.allow.contains(&Group::Shell));
        assert_eq!(p.security, SecurityMode::Managed);
    }

    #[test]
    fn default_agent_only_round_trips() {
        let p = default_policy(
            FleetId([7; 16]),
            ServerId::new("srv_abc123def456").unwrap(),
            SecurityMode::AgentOnly,
        );
        let text = to_toml(&p).unwrap();
        assert_eq!(Policy::from_toml(&text).unwrap(), p);
        assert_eq!(p.security, SecurityMode::AgentOnly);
    }

    #[test]
    fn kept_policy_is_unknown_unless_cached() {
        let cache = crate::cache::Cache::open_in_memory().unwrap();
        let s = ServerId::new("srv_abc123def456").unwrap();
        assert!(!is_unknown(&cache, &s));
        keep_or_mark_unknown(&cache, &s).unwrap();
        assert!(is_unknown(&cache, &s), "no cached copy: unknown, not default");
        let toml = to_toml(&default_policy(FleetId([7; 16]), s.clone(), SecurityMode::Managed))
            .unwrap();
        remember_pushed(&cache, &s, &toml).unwrap();
        assert!(!is_unknown(&cache, &s), "a pushed policy clears it");
        // With a cached copy it stays as it is.
        keep_or_mark_unknown(&cache, &s).unwrap();
        assert!(!is_unknown(&cache, &s));
        assert!(pushed(&cache, &s).is_some());
    }

    #[test]
    fn pushed_copy_round_trips() {
        let cache = crate::cache::Cache::open_in_memory().unwrap();
        let s = ServerId::new("srv_abc123def456").unwrap();
        assert!(pushed(&cache, &s).is_none());
        let mut p = default_policy(FleetId([7; 16]), s.clone(), SecurityMode::Managed);
        p.actors.ai_bulk_confirm_above = 2;
        remember_pushed(&cache, &s, &to_toml(&p).unwrap()).unwrap();
        assert_eq!(pushed(&cache, &s).unwrap().actors.ai_bulk_confirm_above, 2);
    }
}
