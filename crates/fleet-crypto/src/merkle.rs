//! BLAKE3 Merkle tree over `ApprovalItem`s (design §6.4 "Approvals").
//!
//! - leaf = BLAKE3(0x00 ‖ postcard(ApprovalItem))
//! - node = BLAKE3(0x01 ‖ left ‖ right)
//! - **Odd node rule:** when a level has an odd number of nodes, the last one
//!   is promoted to the next level unchanged (no self-pairing, no padding).
//!   A promoted step consumes no sibling, so the proof length is fully
//!   determined by `(leaf_index, leaf_count)` and the verifier rejects any
//!   other length.
//!
//! The 0x00/0x01 prefixes keep a leaf from ever equalling an inner node, so a
//! proof can't pass an inner node off as an item.

use crate::blake3;
use fleet_proto::{ApprovalItem, Hash32, MerkleProof, encode};

const LEAF: u8 = 0x00;
const NODE: u8 = 0x01;

pub fn leaf_hash(item: &ApprovalItem) -> Hash32 {
    let mut buf = vec![LEAF];
    buf.extend_from_slice(&encode(item));
    blake3(&buf)
}

pub fn node_hash(left: &Hash32, right: &Hash32) -> Hash32 {
    let mut buf = [0u8; 65];
    buf[0] = NODE;
    buf[1..33].copy_from_slice(left);
    buf[33..].copy_from_slice(right);
    blake3(&buf)
}

/// A built tree: every level, leaves first.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    levels: Vec<Vec<Hash32>>,
}

impl MerkleTree {
    /// Builds over leaf hashes. `None` for an empty set or more than `u32::MAX` leaves.
    pub fn from_leaves(leaves: Vec<Hash32>) -> Option<Self> {
        if leaves.is_empty() || u32::try_from(leaves.len()).is_err() {
            return None;
        }
        let mut levels = vec![leaves];
        while levels.last().is_some_and(|l| l.len() > 1) {
            let prev = levels.last().expect("non-empty");
            let next = prev
                .chunks(2)
                .map(|pair| match pair {
                    [l, r] => node_hash(l, r),
                    [odd] => *odd,
                    _ => unreachable!("chunks(2)"),
                })
                .collect();
            levels.push(next);
        }
        Some(Self { levels })
    }

    pub fn from_items(items: &[ApprovalItem]) -> Option<Self> {
        Self::from_leaves(items.iter().map(leaf_hash).collect())
    }

    pub fn root(&self) -> Hash32 {
        self.levels.last().expect("at least one level")[0]
    }

    pub fn leaf_count(&self) -> u32 {
        self.levels[0].len() as u32
    }

    /// Inclusion proof for leaf `index`, or `None` if out of range.
    pub fn proof(&self, index: u32) -> Option<MerkleProof> {
        let count = self.leaf_count();
        if index >= count {
            return None;
        }
        let mut siblings = Vec::new();
        let mut i = index as usize;
        for level in &self.levels[..self.levels.len() - 1] {
            let sib = i ^ 1;
            if sib < level.len() {
                siblings.push(level[sib]);
            }
            i /= 2;
        }
        Some(MerkleProof {
            leaf_index: index,
            leaf_count: count,
            siblings,
        })
    }
}

/// Checks that `leaf` sits at `proof.leaf_index` of a `proof.leaf_count`-leaf
/// tree with root `root`. Rejects an index out of range and any proof whose
/// sibling count differs from what the shape requires.
pub fn verify_proof(leaf: &Hash32, proof: &MerkleProof, root: &Hash32) -> bool {
    let (mut i, mut width) = (proof.leaf_index, proof.leaf_count);
    if width == 0 || i >= width {
        return false;
    }
    let mut acc = *leaf;
    let mut sibs = proof.siblings.iter();
    while width > 1 {
        let promoted = i == width - 1 && width % 2 == 1;
        if !promoted {
            let Some(s) = sibs.next() else {
                return false;
            };
            acc = if i % 2 == 0 {
                node_hash(&acc, s)
            } else {
                node_hash(s, &acc)
            };
        }
        i /= 2;
        width = width.div_ceil(2);
    }
    sibs.next().is_none() && acc == *root
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_proto::ServerId;

    fn items(n: usize) -> Vec<ApprovalItem> {
        (0..n)
            .map(|i| ApprovalItem {
                server_id: ServerId::new(format!("srv_{i:06}")).unwrap(),
                op_digest: [i as u8; 32],
            })
            .collect()
    }

    #[test]
    fn every_proof_verifies_for_many_sizes() {
        for n in 1..=17 {
            let its = items(n);
            let tree = MerkleTree::from_items(&its).unwrap();
            for (i, it) in its.iter().enumerate() {
                let p = tree.proof(i as u32).unwrap();
                assert!(
                    verify_proof(&leaf_hash(it), &p, &tree.root()),
                    "n={n} i={i}"
                );
                // Wrong leaf or wrong position fails.
                let other = leaf_hash(&its[(i + 1) % n]);
                if n > 1 {
                    assert!(!verify_proof(&other, &p, &tree.root()));
                }
            }
            assert!(tree.proof(n as u32).is_none());
        }
    }

    #[test]
    fn single_leaf_root_is_leaf() {
        let its = items(1);
        let tree = MerkleTree::from_items(&its).unwrap();
        assert_eq!(tree.root(), leaf_hash(&its[0]));
        assert!(tree.proof(0).unwrap().siblings.is_empty());
        assert!(MerkleTree::from_items(&[]).is_none());
    }

    #[test]
    fn three_leaves_promote_last() {
        let its = items(3);
        let l: Vec<_> = its.iter().map(leaf_hash).collect();
        let tree = MerkleTree::from_items(&its).unwrap();
        assert_eq!(tree.root(), node_hash(&node_hash(&l[0], &l[1]), &l[2]));
        assert_eq!(tree.proof(2).unwrap().siblings.len(), 1);
    }

    #[test]
    fn rejects_bad_shapes() {
        let its = items(5);
        let tree = MerkleTree::from_items(&its).unwrap();
        let root = tree.root();
        let leaf = leaf_hash(&its[1]);
        let good = tree.proof(1).unwrap();
        assert!(verify_proof(&leaf, &good, &root));

        let mut p = good.clone();
        p.leaf_index = 5;
        assert!(!verify_proof(&leaf, &p, &root), "index == count");
        p.leaf_count = 0;
        p.leaf_index = 0;
        assert!(!verify_proof(&leaf, &p, &root), "count 0");

        let mut p = good.clone();
        p.siblings.push([0; 32]);
        assert!(!verify_proof(&leaf, &p, &root), "extra sibling");
        let mut p = good.clone();
        p.siblings.pop();
        assert!(!verify_proof(&leaf, &p, &root), "missing sibling");
        let mut p = good.clone();
        p.siblings[0][0] ^= 1;
        assert!(!verify_proof(&leaf, &p, &root), "tampered sibling");
        let mut p = good;
        p.leaf_count = 2;
        assert!(
            !verify_proof(&leaf, &p, &root),
            "count implying another length"
        );
    }
}
