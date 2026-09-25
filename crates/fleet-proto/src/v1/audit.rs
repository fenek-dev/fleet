//! Receipts (design §5.6), audit entries and checkpoints (§5.8).
//! Signed events live in `message` next to `Event`.

use super::{Actor, DeviceId, ErrorCode, Hash32, Op, ServerId, Signature};
use crate::{domain, encode};
use serde::{Deserialize, Serialize};

/// Final outcome of an executed command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Ok,
    Failed(ErrorCode),
    Interrupted,
    /// Applied, then rolled back by the auto-revert timer (design §4.10).
    Reverted,
}

/// Exec's signed statement about how it answered one command (design §5.6).
/// Exec signs one for **every** response to a command it could decode,
/// success or error, reads included, so a compromised gate can neither forge
/// a result nor turn a success into a failure (or the reverse).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub server_id: ServerId,
    /// BLAKE3 of the `SignedCommand` encoding.
    pub command_hash: Hash32,
    /// Seq of the audit `Result` entry; `None` when the command was rejected
    /// before an intent was written (verification, policy, arguments) or is a
    /// read that isn't audited.
    pub audit_seq: Option<u64>,
    /// `Ok` for an `Ok` response, `Failed(code)` for `Err(code)`.
    pub outcome: Outcome,
    /// BLAKE3 of `postcard(Payload)` for an `Ok` response; all zeros for errors.
    pub payload_hash: Hash32,
    /// Agent clock when the receipt was signed (Unix ms).
    pub time_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedReceipt {
    pub receipt: Receipt,
    /// Agent signing key (Ed25519) over `domain::RECEIPT ‖ postcard(receipt)`.
    pub signature: Signature,
}

impl SignedReceipt {
    pub fn signed_message(receipt: &Receipt) -> Vec<u8> {
        domain::concat(domain::RECEIPT, &[&encode(receipt)])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    Intent,
    Result,
}

/// Operation plus arguments. `args` is the op's wire payload, so the entry
/// keeps the full arguments (the full command text for `shell.exec`),
/// except secrets: a sudo password hash is stored as its BLAKE3
/// ([`Op::audit_payload`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpSummary {
    pub tag: u16,
    pub args: Vec<u8>,
}

impl From<&Op> for OpSummary {
    fn from(op: &Op) -> Self {
        Self {
            tag: op.tag(),
            args: op.audit_payload(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResultSummary {
    /// Intent entries: not run yet.
    Pending,
    Done(Outcome),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    /// Unix milliseconds.
    pub time: u64,
    pub prev_hash: Hash32,
    pub actor: Actor,
    pub device_id: DeviceId,
    /// BLAKE3 of the `SignedCommand` encoding.
    pub command_hash: Hash32,
    /// The device signature, stored for later verification.
    pub signature: Signature,
    pub op: OpSummary,
    pub phase: Phase,
    pub result: ResultSummary,
}

/// Hourly signed pointer into the audit chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub server_id: ServerId,
    pub seq: u64,
    pub entry_hash: Hash32,
    pub time_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCheckpoint {
    pub checkpoint: Checkpoint,
    /// Agent signing key over `domain::CHECKPOINT ‖ postcard(checkpoint)`.
    pub signature: Signature,
}

impl SignedCheckpoint {
    pub fn signed_message(checkpoint: &Checkpoint) -> Vec<u8> {
        domain::concat(domain::CHECKPOINT, &[&encode(checkpoint)])
    }
}
