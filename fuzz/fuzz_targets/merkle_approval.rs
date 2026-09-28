//! Batch approvals: honest Merkle proofs always verify (and only at their
//! own index); arbitrary `MerkleProof`/`RootApproval` bytes never panic.
//! Input: first byte = leaf count - 1, rest = decoded proof/approval.
#![no_main]

#[path = "common.rs"]
mod common;

use std::sync::LazyLock;

use fleet_crypto::approval::verify_approval;
use fleet_crypto::merkle::{MerkleTree, verify_proof};
use fleet_proto::{CommandBody, MerkleProof, RootApproval, SignedRoster, decode};
use libfuzzer_sys::fuzz_target;

static ROSTER: LazyLock<SignedRoster> = LazyLock::new(common::roster);
static BODY: LazyLock<CommandBody> =
    LazyLock::new(|| decode(&common::command().body).expect("golden body"));

fuzz_target!(|data: &[u8]| {
    let Some((&n, rest)) = data.split_first() else {
        return;
    };
    let count = u32::from(n) + 1;
    let leaves: Vec<[u8; 32]> = (0..count).map(|i| [i as u8; 32]).collect();
    let tree = MerkleTree::from_leaves(leaves.clone()).expect("non-empty");
    let root = tree.root();
    let probe = rest.first().map_or(0, |&b| u32::from(b) % count);
    let p = tree.proof(probe).expect("index in range");
    assert!(verify_proof(&leaves[probe as usize], &p, &root));
    for (j, l) in leaves.iter().enumerate() {
        if j as u32 != probe && *l != leaves[probe as usize] {
            assert!(!verify_proof(l, &p, &root), "proof {probe} verified leaf {j}");
        }
    }

    if let Ok(proof) = decode::<MerkleProof>(rest) {
        let _ = verify_proof(&leaves[0], &proof, &root);
    }
    if let Ok(a) = decode::<RootApproval>(rest) {
        let d = fleet_crypto::approval::body_op_digest(&BODY);
        let _ = verify_approval(&a, &ROSTER.roster, &BODY.server_id, &d, BODY.issued_at_ms);
        let _ = a.decode_body();
    }
});
