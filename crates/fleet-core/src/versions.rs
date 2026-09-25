//! `expected_version` for version-checked ops (design §2.6, §7.3).
//!
//! Ops that replace versioned state wholesale (`Op::requires_expected_version`)
//! must name the version they replace. When the caller didn't give one
//! (the bulk sheet, MCP), the Mac reads it right before dispatch:
//!
//! | op | read | version |
//! |---|---|---|
//! | `firewall.apply` | `firewall.get` | `FirewallState::version` |
//! | `authorized_keys.set` | `authorized_keys.get` | `AuthorizedKeys::version` |
//! | `cron.set` | `cron.list` (that user) | the user's `CronTab::version` (none: the empty file's) |
//! | `health_checks.update` | `health_checks.list` | `HealthCheckSet::version` |
//! | `alert_rules.update` | `alert_rules.get` | `AlertRuleSet::version` |
//! | `config.paths.set` | `config.paths.get` | `ConfigPaths::version` |
//! | `mesh.peers.set`, `bans.config.set` | none | probe |
//!
//! A **probe** sends [`PROBE_VERSION`]; a `VersionConflict { current }`
//! answer (nothing ran) is retried once with `current`. `mesh.status`
//! doesn't report the file version, and `bans.config.set` has no readable
//! version (its handler doesn't compare it). Both are Change-tier ops the
//! Mac computes from its own state, so the blind retry loses nothing.
//!
//! Reading the version just before sending closes the window only as far
//! as the read goes: a concurrent edit between read and apply still
//! answers `VersionConflict` and fails that server, never overwrites.

use fleet_proto::{Op, Payload};

/// Sent by a probe; no real content hashes to exactly zero in practice.
pub const PROBE_VERSION: u64 = 0;

/// Where a version-checked op's `expected_version` comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionSource {
    /// Send this read op and take the version from its answer
    /// ([`version_from`]).
    Read(Op),
    /// Send [`PROBE_VERSION`] and retry once on `VersionConflict`.
    Probe,
}

/// `None` for ops that don't need a version.
pub fn version_source(op: &Op) -> Option<VersionSource> {
    if !op.requires_expected_version() {
        return None;
    }
    Some(match op {
        Op::FirewallApply(_) => VersionSource::Read(Op::FirewallGet),
        Op::AuthorizedKeysSet { user, .. } => {
            VersionSource::Read(Op::AuthorizedKeysGet { user: user.clone() })
        }
        Op::CronSet { user, .. } => VersionSource::Read(Op::CronList {
            user: Some(user.clone()),
        }),
        Op::HealthChecksUpdate(_) => VersionSource::Read(Op::HealthChecksList),
        Op::AlertRulesUpdate(_) => VersionSource::Read(Op::AlertRulesGet),
        Op::ConfigPathsSet { .. } => VersionSource::Read(Op::ConfigPathsGet),
        _ => VersionSource::Probe,
    })
}

/// The agent's content version of a file (`fleet_ops::fswrite::version_of`):
/// the first 8 bytes (little-endian) of its BLAKE3.
pub fn content_version(bytes: &[u8]) -> u64 {
    let h = blake3::hash(bytes);
    let mut b = [0u8; 8];
    b.copy_from_slice(&h.as_bytes()[..8]);
    u64::from_le_bytes(b)
}

/// The current version of `op`'s state in the answer to its
/// [`VersionSource::Read`] op.
pub fn version_from(op: &Op, answer: &Payload) -> Option<u64> {
    match (op, answer) {
        (Op::FirewallApply(_), Payload::Firewall(f)) => Some(f.version),
        (Op::AuthorizedKeysSet { .. }, Payload::AuthorizedKeys(k)) => Some(k.version),
        (Op::CronSet { user, .. }, Payload::CronTabs(t)) => Some(
            t.tabs
                .iter()
                .find(|c| c.user.as_deref() == Some(user.as_str()))
                .map_or_else(|| content_version(b""), |c| c.version),
        ),
        (Op::HealthChecksUpdate(_), Payload::HealthChecks(h)) => Some(h.config.version),
        (Op::AlertRulesUpdate(_), Payload::AlertRules(r)) => Some(r.version),
        (Op::ConfigPathsSet { .. }, Payload::ConfigPaths(c)) => Some(c.version),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_proto::args::UserName;
    use fleet_proto::payload::{CronTab, CronTabs};

    #[test]
    fn sources_and_extraction() {
        let user = UserName::new("ops").unwrap();
        let op = Op::CronSet {
            user: user.clone(),
            entries: vec![],
        };
        assert_eq!(
            version_source(&op),
            Some(VersionSource::Read(Op::CronList { user: Some(user) }))
        );
        assert_eq!(version_source(&Op::FirewallGet), None);
        assert_eq!(
            version_source(&Op::MeshPeersSet { peers: vec![] }),
            Some(VersionSource::Probe)
        );
        let tabs = |v: Vec<CronTab>| Payload::CronTabs(CronTabs { tabs: v });
        // No crontab yet: the empty file's version (what exec compares).
        assert_eq!(version_from(&op, &tabs(vec![])), Some(content_version(b"")));
        let tab = CronTab {
            user: Some("ops".into()),
            source: "/var/spool/cron/crontabs/ops".into(),
            version: 42,
            entries: vec![],
        };
        assert_eq!(version_from(&op, &tabs(vec![tab])), Some(42));
        assert_eq!(version_from(&op, &Payload::Empty), None);
    }
}
