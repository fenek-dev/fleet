//! Root-key approvals for Elevated operations (design §6.4 "Approvals").
//!
//! One root signature covers a Merkle root over one `ApprovalItem` per target
//! server; each server's command carries its own proof.

use crate::merkle::{self, MerkleTree};
use crate::sig::{self, Signer};
use crate::{Error, blake3};
use fleet_proto::{
    ApprovalBody, ApprovalItem, CommandBody, DeviceId, ErrorCode, FleetId, Hash32, Op,
    RootApproval, Roster, ServerId, encode,
};

/// `expires_at_ms − issued_at_ms` may not exceed this.
pub const MAX_APPROVAL_LIFETIME_MS: u64 = 30 * 60 * 1000;
/// Tolerated clock skew for an approval's `issued_at_ms` lying in the future.
pub const APPROVAL_SKEW_MS: u64 = 30 * 1000;

#[derive(Debug, thiserror::Error)]
pub enum ApprovalError {
    #[error("approving device is not in the current roster")]
    SignerUnknown,
    #[error("approval signature invalid")]
    Signature,
    #[error("approval body malformed")]
    Malformed,
    #[error("approval is for another fleet")]
    WrongFleet,
    #[error("approval lifetime is invalid or longer than 30 minutes")]
    BadLifetime,
    #[error("approval issued in the future")]
    NotYetValid,
    #[error("approval expired")]
    Expired,
    #[error("proof does not lead from this server and op to items_root")]
    Proof,
    #[error("approval leaf already used")]
    LeafReused,
    #[error("no items, duplicate server, or too many items")]
    BadItems,
    #[error(transparent)]
    Crypto(#[from] Error),
}

impl ApprovalError {
    pub fn code(&self) -> ErrorCode {
        match self {
            ApprovalError::BadItems | ApprovalError::Crypto(_) => ErrorCode::Internal,
            // A replay: the leaf's first use may have run, so the Mac must
            // read this as "outcome unknown", not as a failure.
            ApprovalError::LeafReused => ErrorCode::Replay,
            _ => ErrorCode::ApprovalInvalid,
        }
    }
}

/// BLAKE3 of `postcard((op, expected_version))`; equals
/// `blake3(body.op_digest_input())` for a body with the same op.
pub fn op_digest(op: &Op, expected_version: Option<u64>) -> Hash32 {
    blake3(&encode(&(op, &expected_version)))
}

pub fn body_op_digest(body: &CommandBody) -> Hash32 {
    blake3(&body.op_digest_input())
}

/// What a successfully verified approval authorizes. The caller must record
/// `(approval_id, leaf)` until `expires_at_ms` (see `verify::ReplayStore`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalLeaf {
    pub approval_id: [u8; 16],
    /// Leaf hash. The replay key uses the hash, not the index, so the same
    /// item can't be spent twice under different proof shapes.
    pub leaf: Hash32,
    pub leaf_index: u32,
    pub expires_at_ms: u64,
    pub device_id: DeviceId,
}

/// Parameters of one approval decision (one Touch ID prompt).
#[derive(Debug, Clone)]
pub struct ApprovalParams {
    pub fleet_id: FleetId,
    pub approval_id: [u8; 16],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

/// Signs one approval over `items` (one per server, no duplicates) and returns
/// a `RootApproval` per item, in item order.
pub fn build_approvals(
    root: &(impl Signer + ?Sized),
    device_id: DeviceId,
    params: &ApprovalParams,
    items: &[ApprovalItem],
) -> Result<Vec<RootApproval>, ApprovalError> {
    check_lifetime(params.issued_at_ms, params.expires_at_ms)?;
    let mut servers: Vec<&ServerId> = items.iter().map(|i| &i.server_id).collect();
    servers.sort();
    servers.dedup();
    if servers.len() != items.len() {
        return Err(ApprovalError::BadItems);
    }
    let tree = MerkleTree::from_items(items).ok_or(ApprovalError::BadItems)?;
    let body = encode(&ApprovalBody {
        fleet_id: params.fleet_id,
        approval_id: params.approval_id,
        issued_at_ms: params.issued_at_ms,
        expires_at_ms: params.expires_at_ms,
        items_root: tree.root(),
    });
    let signature = sig::p256_sign(root, &RootApproval::signed_message(&body))?;
    Ok((0..tree.leaf_count())
        .map(|i| RootApproval {
            device_id,
            body: body.clone(),
            signature,
            proof: tree.proof(i).expect("index in range"),
        })
        .collect())
}

fn check_lifetime(issued: u64, expires: u64) -> Result<(), ApprovalError> {
    if expires <= issued || expires - issued > MAX_APPROVAL_LIFETIME_MS {
        return Err(ApprovalError::BadLifetime);
    }
    Ok(())
}

/// Verifies `approval` for this server and op against the current roster.
/// Does **not** check leaf reuse; `verify::verify_command` does that through
/// its `ReplayStore`.
pub fn verify_approval(
    approval: &RootApproval,
    roster: &Roster,
    server_id: &ServerId,
    op_digest: &Hash32,
    now_ms: u64,
) -> Result<ApprovalLeaf, ApprovalError> {
    let device = roster
        .device(&approval.device_id)
        .ok_or(ApprovalError::SignerUnknown)?;
    sig::p256_verify(
        &device.root_key,
        &RootApproval::signed_message(&approval.body),
        &approval.signature,
    )
    .map_err(|_| ApprovalError::Signature)?;
    let body = approval
        .decode_body()
        .map_err(|_| ApprovalError::Malformed)?;
    if body.fleet_id != roster.fleet_id {
        return Err(ApprovalError::WrongFleet);
    }
    check_lifetime(body.issued_at_ms, body.expires_at_ms)?;
    if body.issued_at_ms > now_ms.saturating_add(APPROVAL_SKEW_MS) {
        return Err(ApprovalError::NotYetValid);
    }
    if now_ms >= body.expires_at_ms {
        return Err(ApprovalError::Expired);
    }
    let leaf = merkle::leaf_hash(&ApprovalItem {
        server_id: server_id.clone(),
        op_digest: *op_digest,
    });
    if !merkle::verify_proof(&leaf, &approval.proof, &body.items_root) {
        return Err(ApprovalError::Proof);
    }
    Ok(ApprovalLeaf {
        approval_id: body.approval_id,
        leaf,
        leaf_index: approval.proof.leaf_index,
        expires_at_ms: body.expires_at_ms,
        device_id: approval.device_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    fn setup(n: usize) -> (Fixture, Vec<ApprovalItem>, Vec<RootApproval>) {
        let fx = Fixture::new(2);
        let op = Op::PolicyUpdate {
            policy_toml: "version = 2".into(),
        };
        let items: Vec<_> = (0..n)
            .map(|i| ApprovalItem {
                server_id: server(i),
                op_digest: op_digest(&op, Some(1)),
            })
            .collect();
        let apps = build_approvals(
            &fx.macs[0].root,
            fx.macs[0].id,
            &fx.approval_params(NOW),
            &items,
        )
        .unwrap();
        (fx, items, apps)
    }

    #[test]
    fn op_digest_matches_body() {
        let body = body_for(&server(0), Op::SystemInfo, NOW);
        assert_eq!(
            op_digest(&body.op, body.expected_version),
            body_op_digest(&body)
        );
    }

    #[test]
    fn every_server_verifies_own_leaf() {
        let (fx, items, apps) = setup(5);
        for (i, a) in apps.iter().enumerate() {
            let leaf = verify_approval(
                a,
                &fx.roster(),
                &items[i].server_id,
                &items[i].op_digest,
                NOW,
            )
            .unwrap();
            assert_eq!(leaf.leaf_index, i as u32);
            assert_eq!(leaf.leaf, merkle::leaf_hash(&items[i]));
        }
    }

    #[test]
    fn rejections() {
        let (fx, items, apps) = setup(3);
        let r = fx.roster();
        let (a, s, d) = (&apps[1], &items[1].server_id, &items[1].op_digest);
        let v = |a: &RootApproval, s: &ServerId, d: &Hash32, now| verify_approval(a, &r, s, d, now);

        assert!(matches!(
            v(a, s, d, NOW + MAX_APPROVAL_LIFETIME_MS),
            Err(ApprovalError::Expired)
        ));
        assert!(matches!(
            v(a, &server(0), d, NOW),
            Err(ApprovalError::Proof)
        ));
        assert!(matches!(v(a, s, &[0; 32], NOW), Err(ApprovalError::Proof)));
        assert!(matches!(
            v(a, s, d, NOW - 60_000),
            Err(ApprovalError::NotYetValid)
        ));

        let mut t = a.clone();
        t.proof.siblings[0][3] ^= 1;
        assert!(matches!(v(&t, s, d, NOW), Err(ApprovalError::Proof)));
        let mut t = a.clone();
        t.proof.leaf_index = 3;
        assert!(matches!(v(&t, s, d, NOW), Err(ApprovalError::Proof)));
        let mut t = a.clone();
        t.body[20] ^= 1;
        assert!(matches!(v(&t, s, d, NOW), Err(ApprovalError::Signature)));

        let mut t = a.clone();
        t.device_id = DeviceId([0xee; 16]);
        assert!(matches!(
            v(&t, s, d, NOW),
            Err(ApprovalError::SignerUnknown)
        ));

        // Signed by a Mac that has since been removed from the roster.
        let removed = fx.without(0);
        assert!(matches!(
            verify_approval(a, &removed, s, d, NOW),
            Err(ApprovalError::SignerUnknown)
        ));
    }

    #[test]
    fn builder_rejects_bad_input() {
        let fx = Fixture::new(1);
        let item = ApprovalItem {
            server_id: server(0),
            op_digest: [1; 32],
        };
        let m = &fx.macs[0];
        let mut p = fx.approval_params(NOW);
        let dup = [item.clone(), item.clone()];
        assert!(matches!(
            build_approvals(&m.root, m.id, &p, &dup),
            Err(ApprovalError::BadItems)
        ));
        assert!(matches!(
            build_approvals(&m.root, m.id, &p, &[]),
            Err(ApprovalError::BadItems)
        ));
        p.expires_at_ms = p.issued_at_ms + MAX_APPROVAL_LIFETIME_MS + 1;
        assert!(matches!(
            build_approvals(&m.root, m.id, &p, &[item]),
            Err(ApprovalError::BadLifetime)
        ));
    }
}
