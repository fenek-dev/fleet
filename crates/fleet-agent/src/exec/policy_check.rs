//! Policy re-verification at exec start (design §5.4).
//!
//! `policy.update` stores the policy TOML with the root approval it came
//! with, the command's `expected_version` (part of the approved op digest)
//! and the roster in force when it was accepted. At every start exec checks
//! the approval again: signature by a root key of that roster, fleet, and
//! the Merkle proof binding it to exactly this TOML for this server (the
//! approval's lifetime is not rechecked: it was valid when used). The
//! acceptance roster counts only if it is the current roster or one of the
//! current epoch's earlier rosters (`epoch_hashes`); the current roster is
//! tried too, so the approval of a Mac that is still enrolled survives a
//! recovery epoch.
//!
//! A policy that fails (edited TOML, forged approval, a roster that isn't
//! in the chain) is not enforced: exec starts with [`deny_all`] (only the
//! always-allowed `agent` group, so an operator can push a new policy, plus
//! the read-only monitor subset such as `events.query`) and emits a
//! critical `alert.fired` (`policy.rejected`), instead of refusing to start
//! and crash-looping under systemd.
//!
//! Not covered: the install-time policy has no approval (it is trusted
//! like the genesis roster), and policies stored before this check existed
//! lack the acceptance roster; both are accepted as stored.

use super::state::StoredPolicy;
use fleet_crypto::approval::{op_digest, verify_approval};
use fleet_crypto::roster::roster_hash;
use fleet_proto::policy::{Actors, AiAccess, Capabilities, Elevated, Limits, Safety, SecurityMode};
use fleet_proto::{Hash32, Op, Policy, ServerId, SignedRoster};
use serde::Deserialize;

/// Rule id of the critical alert for a rejected stored policy.
pub(super) const REJECTED_RULE: &str = "policy.rejected";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(super) enum PolicyCheckError {
    #[error("policy TOML doesn't parse or belongs to another fleet/server")]
    Invalid,
    #[error("approval doesn't verify against the acceptance or current roster")]
    Approval,
}

/// The pre-check layout of `MetaKey::Policy` (TOML and approval only).
#[derive(Deserialize)]
struct StoredPolicyV0 {
    toml: String,
    approval: Option<fleet_proto::RootApproval>,
}

/// Decodes `MetaKey::Policy` in the current layout or the old one.
pub(super) fn decode_stored(bytes: &[u8]) -> Option<StoredPolicy> {
    fleet_proto::decode::<StoredPolicy>(bytes).ok().or_else(|| {
        fleet_proto::decode::<StoredPolicyV0>(bytes)
            .ok()
            .map(|o| StoredPolicy {
                toml: o.toml,
                approval: o.approval,
                expected_version: None,
                roster: None,
            })
    })
}

/// Parses and re-verifies a stored policy (see the module docs).
pub(super) fn verify_stored(
    sp: &StoredPolicy,
    current: &SignedRoster,
    epoch_hashes: &[Hash32],
    server: &ServerId,
) -> Result<Policy, PolicyCheckError> {
    let p = Policy::from_toml(&sp.toml).map_err(|_| PolicyCheckError::Invalid)?;
    if p.fleet_id != current.roster.fleet_id || p.server_id != *server {
        return Err(PolicyCheckError::Invalid);
    }
    let (Some(approval), Some(accepted)) = (&sp.approval, &sp.roster) else {
        return Ok(p);
    };
    let body = approval
        .decode_body()
        .map_err(|_| PolicyCheckError::Approval)?;
    let digest = op_digest(
        &Op::PolicyUpdate {
            policy_toml: sp.toml.clone(),
        },
        sp.expected_version,
    );
    let in_chain = {
        let h = roster_hash(accepted);
        h == roster_hash(current) || epoch_hashes.contains(&h)
    };
    let rosters = [Some(current), in_chain.then_some(accepted)];
    let ok = rosters.into_iter().flatten().any(|r| {
        verify_approval(approval, &r.roster, server, &digest, body.issued_at_ms).is_ok()
    });
    if ok {
        Ok(p)
    } else {
        Err(PolicyCheckError::Approval)
    }
}

/// Nothing but the always-allowed `agent` group; version 0, so the next
/// approved `policy.update` of any version replaces it.
pub(super) fn deny_all(current: &SignedRoster, server: &ServerId) -> Policy {
    Policy {
        version: 0,
        fleet_id: current.roster.fleet_id,
        server_id: server.clone(),
        capabilities: Capabilities {
            allow: Vec::new(),
            shell_exec: false,
            shell_exec_users: Vec::new(),
        },
        elevated: Elevated { extra: Vec::new() },
        actors: Actors {
            ai: AiAccess::None,
            ai_bulk_confirm_above: 0,
            ai_commands_per_minute: 1,
        },
        limits: Limits {
            commands_per_minute: 240,
            max_stream_sessions: 8,
        },
        safety: Safety {
            auto_revert_seconds: 60,
        },
        security: SecurityMode::Managed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_both_layouts() {
        #[derive(serde::Serialize)]
        struct V0 {
            toml: String,
            approval: Option<fleet_proto::RootApproval>,
        }
        let old = fleet_proto::encode(&V0 {
            toml: "version = 1".into(),
            approval: None,
        });
        let sp = decode_stored(&old).unwrap();
        assert_eq!((sp.toml.as_str(), sp.roster.is_none()), ("version = 1", true));
        let new = fleet_proto::encode(&StoredPolicy {
            toml: "version = 2".into(),
            approval: None,
            expected_version: Some(1),
            roster: None,
        });
        assert_eq!(decode_stored(&new).unwrap().expected_version, Some(1));
        assert!(decode_stored(b"\xff\xff").is_none());
    }
}
