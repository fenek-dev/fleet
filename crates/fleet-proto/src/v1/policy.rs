//! Per-server policy, parsed from TOML (design §5.4).
//!
//! Unknown keys are rejected: a typo in a security policy must not silently
//! fall back to a default.

use super::{FleetId, Group, Op, ServerId, Tier};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("TOML: {0}")]
    Toml(String),
    #[error("group `{0}` cannot be listed in capabilities.allow")]
    GroupNotAllowable(&'static str),
    #[error("group listed twice in capabilities.allow")]
    DuplicateGroup,
    #[error("invalid user name `{0}` in shell_exec_users")]
    BadUser(String),
    #[error("invalid operation name `{0}` in elevated.extra")]
    BadOpName(String),
    #[error("unknown operation `{0}` in elevated.extra")]
    UnknownOp(String),
    #[error("`{0}` must be greater than zero")]
    Zero(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u64,
    pub fleet_id: FleetId,
    pub server_id: ServerId,
    pub capabilities: Capabilities,
    pub elevated: Elevated,
    pub actors: Actors,
    pub limits: Limits,
    pub safety: Safety,
    /// Managed vs. Agent-only (design §5.4). Absent in older/hand-written
    /// TOML means `Managed`, the behavior before this field existed.
    #[serde(default)]
    pub security: SecurityMode,
}

/// Whether the agent takes over host security (bans, `authorized_keys`,
/// firewall/profile ops) or leaves an already-configured server alone
/// (design §5.4, §10.1). Switching is a normal `policy.update`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityMode {
    #[default]
    Managed,
    AgentOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    /// `agent` is always allowed and `shell` is controlled by `shell_exec`,
    /// so neither may appear here.
    pub allow: Vec<Group>,
    pub shell_exec: bool,
    pub shell_exec_users: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Elevated {
    /// Operation names (`cron.set`) moved into the Elevated tier.
    pub extra: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AiAccess {
    Full,
    ReadOnly,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Actors {
    pub ai: AiAccess,
    pub ai_bulk_confirm_above: u32,
    pub ai_commands_per_minute: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub commands_per_minute: u32,
    pub max_stream_sessions: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Safety {
    pub auto_revert_seconds: u32,
}

impl Policy {
    pub fn from_toml(s: &str) -> Result<Policy, PolicyError> {
        let p: Policy = toml::from_str(s).map_err(|e| PolicyError::Toml(e.message().to_owned()))?;
        p.validate()?;
        Ok(p)
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        let allow = &self.capabilities.allow;
        for (i, g) in allow.iter().enumerate() {
            match g {
                Group::Agent => return Err(PolicyError::GroupNotAllowable("agent")),
                Group::Shell => return Err(PolicyError::GroupNotAllowable("shell")),
                _ if allow[..i].contains(g) => return Err(PolicyError::DuplicateGroup),
                _ => {}
            }
        }
        if let Some(u) = self
            .capabilities
            .shell_exec_users
            .iter()
            .find(|u| !valid_user(u))
        {
            return Err(PolicyError::BadUser(u.clone()));
        }
        if let Some(n) = self.elevated.extra.iter().find(|n| !valid_op_name(n)) {
            return Err(PolicyError::BadOpName(n.clone()));
        }
        // A typo would otherwise leave the intended op at its base tier.
        if let Some(n) = self.elevated.extra.iter().find(|n| !Op::is_known_name(n)) {
            return Err(PolicyError::UnknownOp(n.clone()));
        }
        let nonzero = [
            (
                self.actors.ai_commands_per_minute,
                "actors.ai_commands_per_minute",
            ),
            (
                self.limits.commands_per_minute,
                "limits.commands_per_minute",
            ),
            (
                self.limits.max_stream_sessions,
                "limits.max_stream_sessions",
            ),
            (
                self.safety.auto_revert_seconds,
                "safety.auto_revert_seconds",
            ),
        ];
        if let Some((_, name)) = nonzero.iter().find(|(v, _)| *v == 0) {
            return Err(PolicyError::Zero(name));
        }
        Ok(())
    }

    pub fn allows_group(&self, group: Group) -> bool {
        match group {
            Group::Agent => true,
            Group::Shell => self.capabilities.shell_exec,
            g => self.capabilities.allow.contains(&g),
        }
    }

    /// The op's tier after `[elevated] extra` (which can only raise it).
    pub fn effective_tier(&self, op: &Op) -> Tier {
        let base = op.tier();
        if self.elevated.extra.iter().any(|n| n == op.name()) {
            Tier::Elevated
        } else {
            base
        }
    }
}

/// Debian `NAME_REGEX` default: `^[a-z][-a-z0-9_]*$`, max 32.
fn valid_user(u: &str) -> bool {
    let mut b = u.bytes();
    u.len() <= 32
        && b.next().is_some_and(|c| c.is_ascii_lowercase())
        && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
}

/// Dotted lowercase segments, e.g. `agent.update.stage`.
fn valid_op_name(n: &str) -> bool {
    n.len() <= 64
        && n.contains('.')
        && n.split('.')
            .all(|seg| !seg.is_empty() && seg.bytes().all(|c| c.is_ascii_lowercase() || c == b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
version = 12
fleet_id = "f_2b810000000000000000000000000000"
server_id = "srv_7f3a9c"

[capabilities]
allow = ["system", "logs", "security", "services", "firewall", "packages",
         "docker", "cron", "users", "files", "config", "search", "profile",
         "mesh", "game"]
shell_exec = false
shell_exec_users = ["ops"]

[elevated]
extra = ["roster.pending"]

[actors]
ai = "full"
ai_bulk_confirm_above = 5
ai_commands_per_minute = 60

[limits]
commands_per_minute = 240
max_stream_sessions = 32

[safety]
auto_revert_seconds = 60
"#;

    #[test]
    fn parses_design_example() {
        let p = Policy::from_toml(EXAMPLE).unwrap();
        assert_eq!(p.version, 12);
        assert_eq!(p.server_id.as_str(), "srv_7f3a9c");
        assert_eq!(p.capabilities.allow.len(), 15);
        assert!(p.allows_group(Group::Agent));
        assert!(!p.allows_group(Group::Shell));
        assert!(p.allows_group(Group::Game));
        assert_eq!(p.actors.ai, AiAccess::Full);
        assert_eq!(p.effective_tier(&Op::SystemInfo), Tier::Read);
        // Absent from the example TOML: defaults to Managed.
        assert_eq!(p.security, SecurityMode::Managed);
    }

    #[test]
    fn security_mode_toml_round_trip() {
        let managed = Policy::from_toml(EXAMPLE).unwrap();
        assert_eq!(managed.security, SecurityMode::Managed);

        let toml = toml::to_string(&managed).unwrap();
        assert!(toml.contains("security = \"managed\""));
        assert_eq!(Policy::from_toml(&toml).unwrap(), managed);

        let mut agent_only = managed.clone();
        agent_only.security = SecurityMode::AgentOnly;
        let toml = toml::to_string(&agent_only).unwrap();
        assert!(toml.contains("security = \"agent-only\""));
        let reparsed = Policy::from_toml(&toml).unwrap();
        assert_eq!(reparsed, agent_only);
        assert_eq!(reparsed.security, SecurityMode::AgentOnly);
    }

    #[test]
    fn security_mode_postcard_round_trip() {
        for mode in [SecurityMode::Managed, SecurityMode::AgentOnly] {
            let mut p = Policy::from_toml(EXAMPLE).unwrap();
            p.security = mode;
            let bytes = crate::encode(&p);
            let back: Policy = crate::decode(&bytes).unwrap();
            assert_eq!(back, p);
            assert_eq!(back.security, mode);
        }
    }

    fn with(from: &str, to: &str) -> Result<Policy, PolicyError> {
        assert!(EXAMPLE.contains(from));
        Policy::from_toml(&EXAMPLE.replacen(from, to, 1))
    }

    #[test]
    fn rejects_bad_policies() {
        assert!(matches!(
            with("\"mesh\"", "\"meshh\""),
            Err(PolicyError::Toml(_))
        ));
        assert!(matches!(
            with("\"mesh\"", "\"shell\""),
            Err(PolicyError::GroupNotAllowable(_))
        ));
        assert!(matches!(
            with("\"mesh\"", "\"agent\""),
            Err(PolicyError::GroupNotAllowable(_))
        ));
        assert!(matches!(
            with("\"mesh\"", "\"game\""),
            Err(PolicyError::DuplicateGroup)
        ));
        assert!(matches!(
            with("[\"ops\"]", "[\"Ops;rm\"]"),
            Err(PolicyError::BadUser(_))
        ));
        assert!(matches!(
            with("[\"roster.pending\"]", "[\"cron\"]"),
            Err(PolicyError::BadOpName(_))
        ));
        // Well-formed but not in the op catalog (a typo or a future op).
        assert_eq!(
            with("[\"roster.pending\"]", "[\"roster.pendng\"]"),
            Err(PolicyError::UnknownOp("roster.pendng".into()))
        );
        assert!(matches!(
            with("[\"roster.pending\"]", "[\"cron.purge\"]"),
            Err(PolicyError::UnknownOp(_))
        ));
        // Catalog ops beyond Phase 0 are accepted.
        assert!(with("[\"roster.pending\"]", "[\"cron.set\"]").is_ok());
        assert!(matches!(with("= 240", "= 0"), Err(PolicyError::Zero(_))));
        assert!(matches!(
            with("ai = \"full\"", "ai = \"root\""),
            Err(PolicyError::Toml(_))
        ));
        assert!(matches!(
            with("shell_exec = false", "shell_exec = false\nx = 1"),
            Err(PolicyError::Toml(_))
        ));
        assert!(matches!(
            with("srv_7f3a9c", "srv_7F"),
            Err(PolicyError::Toml(_))
        ));
        assert!(matches!(
            with("f_2b81", "f_zz81"),
            Err(PolicyError::Toml(_))
        ));
    }

    #[test]
    fn extra_raises_tier() {
        let p = with("[\"roster.pending\"]", "[\"system.info\"]").unwrap();
        assert_eq!(p.effective_tier(&Op::SystemInfo), Tier::Elevated);
        assert_eq!(p.effective_tier(&Op::RosterPending), Tier::Read);
    }
}
