//! Signed commands and root-key approvals (design §6.4).

use super::{Actor, DeviceId, FleetId, Hash32, KeyKind, Op, ServerId, Signature};
use crate::{DecodeError, decode, domain, encode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandBody {
    /// Protocol version the body was built for.
    pub v: u16,
    pub fleet_id: FleetId,
    pub server_id: ServerId,
    pub issued_at_ms: u64,
    pub ttl_ms: u32,
    pub nonce: [u8; 16],
    pub actor: Actor,
    pub op: Op,
    pub expected_version: Option<u64>,
}

impl CommandBody {
    /// Input to `ApprovalItem::op_digest`: `postcard((op, expected_version))`.
    pub fn op_digest_input(&self) -> Vec<u8> {
        encode(&(&self.op, &self.expected_version))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCommand {
    /// `postcard(CommandBody)`, signed exactly as sent.
    pub body: Vec<u8>,
    pub device_id: DeviceId,
    pub key: KeyKind,
    /// Over [`SignedCommand::signed_message`].
    pub signature: Signature,
    /// Required for ops whose authorization is `RootApproval`.
    pub approval: Option<RootApproval>,
}

impl SignedCommand {
    /// `domain::CMD ‖ postcard(key) ‖ device_id (16) ‖ body`.
    /// `postcard(key)` is one byte; `device_id` is raw, so the envelope's
    /// signer identity (and replay key) is covered by the signature.
    pub fn signed_message(key: KeyKind, device_id: &DeviceId, body: &[u8]) -> Vec<u8> {
        domain::concat(domain::CMD, &[&encode(&key), &device_id.0, body])
    }

    pub fn decode_body(&self) -> Result<CommandBody, DecodeError> {
        decode(&self.body)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootApproval {
    /// The Mac whose root key signed.
    pub device_id: DeviceId,
    /// `postcard(ApprovalBody)`, signed exactly as sent.
    pub body: Vec<u8>,
    /// Root key over `domain::APPROVE ‖ body`.
    pub signature: Signature,
    /// From this command's `ApprovalItem` to `items_root`.
    pub proof: MerkleProof,
}

impl RootApproval {
    pub fn signed_message(body: &[u8]) -> Vec<u8> {
        domain::concat(domain::APPROVE, &[body])
    }

    pub fn decode_body(&self) -> Result<ApprovalBody, DecodeError> {
        decode(&self.body)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalBody {
    pub fleet_id: FleetId,
    pub approval_id: [u8; 16],
    pub issued_at_ms: u64,
    /// At most 30 minutes after `issued_at_ms`.
    pub expires_at_ms: u64,
    /// Merkle root over `ApprovalItem` hashes.
    pub items_root: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalItem {
    pub server_id: ServerId,
    /// BLAKE3 of [`CommandBody::op_digest_input`].
    pub op_digest: Hash32,
}

/// Inclusion proof. Hashing rules are defined in fleet-crypto.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: u32,
    pub leaf_count: u32,
    /// Bottom-up sibling hashes.
    pub siblings: Vec<Hash32>,
}
