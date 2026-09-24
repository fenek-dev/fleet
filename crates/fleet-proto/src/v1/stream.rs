//! Stream seal wire types (design §6.3). Every `StreamData.chunk` is
//! `postcard(StreamChunk)`; exec signs a [`StreamSeal`] with the agent key
//! over `domain::STREAM ‖ postcard(seal)` at least every
//! [`CHECKPOINT_EVERY`] data chunks and once more at the end. The running
//! hash, the sealer and the Mac-side verifier are in `fleet_crypto::stream`.

use crate::domain;
use crate::v1::{Hash32, Outcome, ServerId, Signature};
use serde::{Deserialize, Serialize};

/// Exec emits a checkpoint seal after at most this many data chunks; the
/// verifier refuses a stream that goes longer without one.
pub const CHECKPOINT_EVERY: u64 = 32;

/// The content of one `StreamData.chunk`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamChunk {
    /// `postcard(Payload)`, hashed as sent (an older Mac can still check an
    /// item whose payload tag it doesn't know).
    Data(Vec<u8>),
    /// Signed state after `seal.count` data chunks; `seal.outcome` is `None`.
    Checkpoint(SignedStreamSeal),
    /// Last chunk before `StreamEnd`; `seal.outcome` is `Some`.
    Final(SignedStreamSeal),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamSeal {
    pub server_id: ServerId,
    /// BLAKE3 of the `SignedCommand` from `StreamOpen`.
    pub command_hash: Hash32,
    /// Checkpoints: the audit intent. Final: the audit result entry, `None`
    /// when the open was rejected before an intent.
    pub audit_seq: Option<u64>,
    /// Data chunks covered.
    pub count: u64,
    /// `chain_n = BLAKE3(chain_{n-1} ‖ n: u64 BE ‖ BLAKE3(data_n))`, from
    /// `[0; 32]` (`fleet_crypto::stream::chain_step`).
    pub chain: Hash32,
    /// `None` for checkpoints; how the stream ended for the final seal.
    pub outcome: Option<Outcome>,
    pub time_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedStreamSeal {
    pub seal: StreamSeal,
    /// Agent signing key over `domain::STREAM ‖ postcard(seal)`.
    pub signature: Signature,
}

impl SignedStreamSeal {
    pub fn signed_message(seal: &StreamSeal) -> Vec<u8> {
        domain::concat(domain::STREAM, &[&crate::encode(seal)])
    }
}
