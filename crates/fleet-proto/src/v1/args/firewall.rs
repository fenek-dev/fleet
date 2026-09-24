//! Firewall rule model for `table inet fleet` (design §4.8).

use super::{ArgError, Cidr, FwComment, PortRange, Protocol, at_most, ensure};
use serde::{Deserialize, Serialize};

/// How Fleet's table behaves (design §4.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FirewallMode {
    /// Input chain drops by default; everything reachable is declared.
    Managed,
    /// Chains accept by default and hold only the ban sets.
    BansOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FwAction {
    Accept,
    Drop,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FwChain {
    /// Traffic to the host.
    Input,
    /// Published container ports, matched on `ct original proto-dst`.
    Forward,
}

/// Per-source rate limit (nftables meter), e.g. for game ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RateLimit {
    /// New connections per source per minute, 1..=100000.
    pub per_minute: u32,
    pub burst: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FirewallRule {
    pub chain: FwChain,
    pub action: FwAction,
    pub proto: Protocol,
    /// 1–16 ranges.
    pub ports: Vec<PortRange>,
    /// `None` means any source.
    pub source: Option<Cidr>,
    pub rate_limit: Option<RateLimit>,
    pub comment: FwComment,
}

impl FirewallRule {
    pub const MAX_PORTS: usize = 16;

    pub fn validate(&self) -> Result<(), ArgError> {
        ensure(!self.ports.is_empty(), "rule ports")?;
        at_most(&self.ports, Self::MAX_PORTS, "rule ports")?;
        if let Some(r) = self.rate_limit {
            ensure((1..=100_000).contains(&r.per_minute), "rate limit")?;
        }
        Ok(())
    }
}

/// The whole desired state of Fleet's table. `firewall.apply` replaces it
/// atomically (one nft transaction) under auto-revert; the version it
/// expects is `CommandBody::expected_version`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FirewallRuleSet {
    pub mode: FirewallMode,
    /// Empty in `BansOnly` mode; at most [`FirewallRuleSet::MAX_RULES`].
    pub rules: Vec<FirewallRule>,
}

impl FirewallRuleSet {
    pub const MAX_RULES: usize = 512;

    pub fn validate(&self) -> Result<(), ArgError> {
        at_most(&self.rules, Self::MAX_RULES, "firewall rules")?;
        if self.mode == FirewallMode::BansOnly {
            ensure(self.rules.is_empty(), "bans-only rules")?;
        }
        self.rules.iter().try_for_each(FirewallRule::validate)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Port, testutil::roundtrip};
    use super::*;
    use proptest::prelude::*;

    pub(crate) fn rule(ports: usize) -> FirewallRule {
        let p = Port::new(22).unwrap();
        FirewallRule {
            chain: FwChain::Input,
            action: FwAction::Accept,
            proto: Protocol::Tcp,
            ports: vec![PortRange::single(p); ports],
            source: Some("203.0.113.0/24".parse().unwrap()),
            rate_limit: None,
            comment: FwComment::new("ssh").unwrap(),
        }
    }

    #[test]
    fn examples() {
        let set = FirewallRuleSet {
            mode: FirewallMode::Managed,
            rules: vec![rule(1)],
        };
        assert!(set.validate().is_ok());
        roundtrip(&set);
        let bans_only = FirewallRuleSet {
            mode: FirewallMode::BansOnly,
            ..set.clone()
        };
        assert!(bans_only.validate().is_err());
        let limited = FirewallRule {
            rate_limit: Some(RateLimit {
                per_minute: 0,
                burst: 5,
            }),
            ..rule(1)
        };
        assert!(limited.validate().is_err());
    }

    proptest! {
        #[test]
        fn port_count(n in 0usize..40) {
            prop_assert_eq!(rule(n).validate().is_ok(), (1..=16).contains(&n));
        }
    }
}
