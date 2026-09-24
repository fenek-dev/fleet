//! Typed operations (design §4.2) and their extensible wire encoding (§6.2).
//!
//! On the wire an `Op` is the postcard tuple `(tag: u16 varint, payload: bytes)`,
//! where `payload` is the postcard encoding of the variant's fields. A receiver
//! that does not know `tag` skips the payload and yields [`Op::Unknown`], so the
//! frame still decodes and exec can answer `Unsupported`.
//!
//! Tags are explicit constants in per-group ranges; never reorder or reuse them.

use super::{Hash32, SignedRoster};
use crate::tagged::{Tagged, tagged_serde, unit};
use crate::{decode, encode};
use core::ops::RangeInclusive;
use serde::{Deserialize, Serialize};

/// Wire tags. Each group owns a block of 100 (see [`Group::tag_range`]).
pub mod tag {
    pub const SYSTEM_INFO: u16 = 0;
    pub const AGENT_HEALTH: u16 = 1500;
    pub const ROSTER_UPDATE: u16 = 1510;
    pub const ROSTER_PENDING: u16 = 1511;
    pub const ROSTER_VETO: u16 = 1512;
    pub const POLICY_UPDATE: u16 = 1520;
}

/// Catalog of operation names ([`Op::name`] of every known variant). Policy
/// `[elevated] extra` entries must be listed here. Kept in sync by a test.
pub const NAMES: &[&str] = &[
    "system.info",
    "agent.health",
    "roster.update",
    "roster.pending",
    "roster.veto",
    "policy.update",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    SystemInfo,
    AgentHealth,
    RosterUpdate {
        roster: Box<SignedRoster>,
    },
    RosterPending,
    RosterVeto {
        pending_hash: Hash32,
    },
    PolicyUpdate {
        policy_toml: String,
    },
    /// A tag this build doesn't know. Never executed; answered with `Unsupported`.
    Unknown {
        tag: u16,
    },
}

/// Capability group, as named in the policy (design §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Group {
    System,
    Logs,
    Security,
    Services,
    Firewall,
    Packages,
    Docker,
    Cron,
    Users,
    Files,
    Config,
    Profile,
    Search,
    Mesh,
    Game,
    Agent,
    Shell,
}

impl Group {
    /// In tag-range order.
    pub const ALL: [Group; 17] = [
        Group::System,
        Group::Logs,
        Group::Security,
        Group::Services,
        Group::Firewall,
        Group::Packages,
        Group::Docker,
        Group::Cron,
        Group::Users,
        Group::Files,
        Group::Config,
        Group::Profile,
        Group::Search,
        Group::Mesh,
        Group::Game,
        Group::Agent,
        Group::Shell,
    ];

    pub fn tag_range(self) -> RangeInclusive<u16> {
        let start = self as u16 * 100;
        start..=start + 99
    }

    pub fn from_tag(tag: u16) -> Option<Group> {
        Self::ALL.get(usize::from(tag / 100)).copied()
    }
}

/// Risk tier (design §4.2). Ordered: `Read < Change < Elevated`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Tier {
    Read,
    Change,
    Elevated,
}

/// What exec must verify beyond the envelope's device-key signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Authorization {
    /// The envelope signature is enough.
    Envelope,
    /// A `RootApproval` covering this server and op is required.
    RootApproval,
    /// The payload carries its own root/recovery signature (design §6.4).
    SelfSigned,
}

impl Op {
    pub fn tag(&self) -> u16 {
        match self {
            Op::SystemInfo => tag::SYSTEM_INFO,
            Op::AgentHealth => tag::AGENT_HEALTH,
            Op::RosterUpdate { .. } => tag::ROSTER_UPDATE,
            Op::RosterPending => tag::ROSTER_PENDING,
            Op::RosterVeto { .. } => tag::ROSTER_VETO,
            Op::PolicyUpdate { .. } => tag::POLICY_UPDATE,
            Op::Unknown { tag } => *tag,
        }
    }

    /// Catalog name, e.g. `system.info`. Used by `[elevated] extra` in policies.
    pub fn name(&self) -> &'static str {
        match self {
            Op::SystemInfo => "system.info",
            Op::AgentHealth => "agent.health",
            Op::RosterUpdate { .. } => "roster.update",
            Op::RosterPending => "roster.pending",
            Op::RosterVeto { .. } => "roster.veto",
            Op::PolicyUpdate { .. } => "policy.update",
            Op::Unknown { .. } => "unknown",
        }
    }

    /// Group by tag range. Unknown tags beyond every range map to `Shell`,
    /// the most restricted group; they are rejected as `Unsupported` anyway.
    pub fn group(&self) -> Group {
        Group::from_tag(self.tag()).unwrap_or(Group::Shell)
    }

    /// Base tier. A policy can raise it (`[elevated] extra`), never lower it.
    pub fn tier(&self) -> Tier {
        match self {
            Op::SystemInfo | Op::AgentHealth | Op::RosterPending => Tier::Read,
            Op::RosterUpdate { .. } | Op::RosterVeto { .. } | Op::PolicyUpdate { .. } => {
                Tier::Elevated
            }
            Op::Unknown { .. } => Tier::Elevated,
        }
    }

    pub fn authorization(&self) -> Authorization {
        match self {
            Op::SystemInfo | Op::AgentHealth | Op::RosterPending => Authorization::Envelope,
            Op::RosterUpdate { .. } => Authorization::SelfSigned,
            Op::RosterVeto { .. } | Op::PolicyUpdate { .. } | Op::Unknown { .. } => {
                Authorization::RootApproval
            }
        }
    }

    /// Accepted in a monitor session (design §5.2): telemetry, events, `agent.health`.
    pub fn monitor_allowed(&self) -> bool {
        matches!(self, Op::AgentHealth)
    }

    /// Accepted in a recovery session (design §5.5).
    pub fn recovery_allowed(&self) -> bool {
        matches!(
            self,
            Op::SystemInfo | Op::RosterUpdate { .. } | Op::RosterPending
        )
    }

    /// Whether `name` is in this build's operation catalog ([`NAMES`]).
    pub fn is_known_name(name: &str) -> bool {
        NAMES.contains(&name)
    }

    pub(crate) fn payload(&self) -> Vec<u8> {
        match self {
            Op::SystemInfo | Op::AgentHealth | Op::RosterPending | Op::Unknown { .. } => Vec::new(),
            Op::RosterUpdate { roster } => encode(roster),
            Op::RosterVeto { pending_hash } => encode(pending_hash),
            Op::PolicyUpdate { policy_toml } => encode(policy_toml),
        }
    }
}

/// `Op::Unknown` serializes with an empty payload (test and relay use only).
impl Tagged for Op {
    const EXPECTING: &'static str = "(op tag, payload)";

    fn wire_tag(&self) -> u16 {
        self.tag()
    }

    fn wire_payload(&self) -> Vec<u8> {
        self.payload()
    }

    fn from_wire(tag: u16, payload: &[u8]) -> Result<Op, crate::DecodeError> {
        match tag {
            tag::SYSTEM_INFO => unit(Op::SystemInfo, payload),
            tag::AGENT_HEALTH => unit(Op::AgentHealth, payload),
            tag::ROSTER_UPDATE => Ok(Op::RosterUpdate {
                roster: decode(payload)?,
            }),
            tag::ROSTER_PENDING => unit(Op::RosterPending, payload),
            tag::ROSTER_VETO => Ok(Op::RosterVeto {
                pending_hash: decode(payload)?,
            }),
            tag::POLICY_UPDATE => Ok(Op::PolicyUpdate {
                policy_toml: decode(payload)?,
            }),
            tag => Ok(Op::Unknown { tag }),
        }
    }
}

tagged_serde!(Op);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tagged::Bytes;
    use std::collections::HashSet;

    /// One value per variant. The exhaustive match makes a new variant a compile
    /// error here until it is added to `samples` (and so to every check below).
    fn samples() -> Vec<Op> {
        fn _exhaustive(op: &Op) {
            match op {
                Op::SystemInfo
                | Op::AgentHealth
                | Op::RosterUpdate { .. }
                | Op::RosterPending
                | Op::RosterVeto { .. }
                | Op::PolicyUpdate { .. }
                | Op::Unknown { .. } => {}
            }
        }
        vec![
            Op::SystemInfo,
            Op::AgentHealth,
            Op::RosterUpdate {
                roster: Box::new(crate::v1::test_support::signed_roster()),
            },
            Op::RosterPending,
            Op::RosterVeto {
                pending_hash: [7; 32],
            },
            Op::PolicyUpdate {
                policy_toml: "version = 1".into(),
            },
        ]
    }

    #[test]
    fn every_variant_has_a_mapping() {
        let mut tags = HashSet::new();
        let mut names = HashSet::new();
        for op in samples() {
            assert!(tags.insert(op.tag()), "duplicate tag {}", op.tag());
            assert!(names.insert(op.name()), "duplicate name {}", op.name());
            let group = Group::from_tag(op.tag()).expect("tag inside a group range");
            assert_eq!(op.group(), group);
            assert!(group.tag_range().contains(&op.tag()));
            assert!(!matches!(op, Op::Unknown { .. }));
            // Self-signed and approval-gated ops must be Elevated.
            if op.authorization() != Authorization::Envelope {
                assert_eq!(op.tier(), Tier::Elevated, "{}", op.name());
            }
            if op.tier() == Tier::Elevated {
                assert_ne!(op.authorization(), Authorization::Envelope, "{}", op.name());
            }
            if op.monitor_allowed() {
                assert_eq!(op.tier(), Tier::Read);
            }
            assert_eq!(decode::<Op>(&encode(&op)).unwrap(), op);
            assert!(
                Op::is_known_name(op.name()),
                "{} missing from NAMES",
                op.name()
            );
        }
        assert_eq!(
            names.len(),
            NAMES.len(),
            "NAMES lists an op with no variant"
        );
        assert!(!Op::is_known_name("unknown"));
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
    fn unknown_tag_decodes_and_skips_payload() {
        // tag 777 (cron range), 3-byte payload, followed by a trailing field.
        let bytes = encode(&(777u16, Bytes(&[1, 2, 3]), 42u8));
        let (op, rest): (Op, u8) = decode(&bytes).unwrap();
        assert_eq!(op, Op::Unknown { tag: 777 });
        assert_eq!(op.group(), Group::Cron);
        assert_eq!(op.tier(), Tier::Elevated);
        assert_eq!(rest, 42);
    }

    #[test]
    fn known_tag_rejects_bad_payload() {
        let bytes = encode(&(tag::SYSTEM_INFO, Bytes(&[0])));
        assert!(decode::<Op>(&bytes).is_err());
        let bytes = encode(&(tag::ROSTER_VETO, Bytes(&[0; 33])));
        assert!(decode::<Op>(&bytes).is_err());
    }
}
