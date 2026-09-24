//! Stream authenticity (design §5.6, §6.3): what exec signs so the Mac can
//! tell a real stream from one a compromised gate injected into, reordered,
//! truncated or cut short.
//!
//! Every `StreamData.chunk` is `postcard(StreamChunk)`. Data chunks carry an
//! encoded `Payload`; exec folds each one into a running hash
//! ([`chain_step`]) and signs a [`StreamSeal`] over `(command_hash, count,
//! chain)` at least every [`CHECKPOINT_EVERY`] data chunks and once more at
//! the end (`outcome` set). [`StreamVerifier`] is the Mac side.
//!
//! The wire types and the domain live in `fleet_proto::stream` and
//! `fleet_proto::domain::STREAM`; they are re-exported here.

use crate::sig::{self, Ed25519Signer};
use crate::{Error, blake3};
use fleet_proto::{Ed25519Public, Hash32, Outcome, ServerId};

pub use fleet_proto::stream::{CHECKPOINT_EVERY, SignedStreamSeal, StreamChunk, StreamSeal};

/// Domain for stream seals (`fleet_proto::domain::STREAM`).
pub const STREAM_DOMAIN: &[u8] = fleet_proto::domain::STREAM;

/// `chain' = BLAKE3(chain ‖ index: u64 BE ‖ BLAKE3(data))`, `index` counting
/// data chunks from 1.
pub fn chain_step(chain: &Hash32, index: u64, data: &[u8]) -> Hash32 {
    let mut buf = [0u8; 72];
    buf[..32].copy_from_slice(chain);
    buf[32..40].copy_from_slice(&index.to_be_bytes());
    buf[40..].copy_from_slice(&blake3(data));
    blake3(&buf)
}

/// Agent side: running state of one stream.
#[derive(Debug, Clone)]
pub struct StreamSealer {
    server_id: ServerId,
    command_hash: Hash32,
    count: u64,
    chain: Hash32,
    since_checkpoint: u64,
}

impl StreamSealer {
    pub fn new(server_id: ServerId, command_hash: Hash32) -> Self {
        Self {
            server_id,
            command_hash,
            count: 0,
            chain: [0; 32],
            since_checkpoint: 0,
        }
    }

    /// Folds in one data chunk (exactly the bytes sent in `StreamChunk::Data`).
    pub fn push(&mut self, data: &[u8]) {
        self.count += 1;
        self.since_checkpoint += 1;
        self.chain = chain_step(&self.chain, self.count, data);
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    /// Data chunks since the last checkpoint.
    pub fn since_checkpoint(&self) -> u64 {
        self.since_checkpoint
    }

    pub fn checkpoint(
        &mut self,
        audit_seq: Option<u64>,
        time_ms: u64,
        key: &Ed25519Signer,
    ) -> SignedStreamSeal {
        self.since_checkpoint = 0;
        self.seal(audit_seq, None, time_ms, key)
    }

    pub fn finish(
        &self,
        audit_seq: Option<u64>,
        outcome: Outcome,
        time_ms: u64,
        key: &Ed25519Signer,
    ) -> SignedStreamSeal {
        self.seal(audit_seq, Some(outcome), time_ms, key)
    }

    fn seal(
        &self,
        audit_seq: Option<u64>,
        outcome: Option<Outcome>,
        time_ms: u64,
        key: &Ed25519Signer,
    ) -> SignedStreamSeal {
        let seal = StreamSeal {
            server_id: self.server_id.clone(),
            command_hash: self.command_hash,
            audit_seq,
            count: self.count,
            chain: self.chain,
            outcome,
            time_ms,
        };
        let signature = key.sign(&SignedStreamSeal::signed_message(&seal));
        SignedStreamSeal { seal, signature }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StreamError {
    #[error("chunk does not decode")]
    Decode,
    #[error("StreamData seq out of order")]
    Seq,
    #[error("seal signature invalid")]
    Signature,
    #[error("seal is for another server or command")]
    Binding,
    #[error("seal does not match the data received")]
    Chain,
    #[error("too many data chunks without a checkpoint")]
    NoCheckpoint,
    #[error("data after the final seal")]
    Finished,
}

/// What one verified `StreamData` chunk was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamItem {
    /// `postcard(Payload)`. Provisional until the next checkpoint or final
    /// seal covers it (at most [`CHECKPOINT_EVERY`] chunks later).
    Data(Vec<u8>),
    /// Everything up to `count` is now authenticated.
    Checkpoint { count: u64 },
    /// The stream really ended like this. A `StreamEnd` without a verified
    /// final seal before it is unsigned (a gate refusal or a cut stream):
    /// "outcome unknown".
    Final {
        outcome: Outcome,
        audit_seq: Option<u64>,
        count: u64,
    },
}

/// Mac side: checks one stream's chunks in order.
#[derive(Debug, Clone)]
pub struct StreamVerifier {
    agent_key: Ed25519Public,
    server_id: ServerId,
    command_hash: Hash32,
    next_seq: u64,
    count: u64,
    chain: Hash32,
    since_checkpoint: u64,
    done: bool,
}

impl StreamVerifier {
    pub fn new(agent_key: Ed25519Public, server_id: ServerId, command_hash: Hash32) -> Self {
        Self {
            agent_key,
            server_id,
            command_hash,
            next_seq: 0,
            count: 0,
            chain: [0; 32],
            since_checkpoint: 0,
            done: false,
        }
    }

    /// Whether a verified final seal was seen.
    pub fn finished(&self) -> bool {
        self.done
    }

    /// `seq` and `chunk` of one `StreamData`, in arrival order.
    pub fn accept(&mut self, seq: u64, chunk: &[u8]) -> Result<StreamItem, StreamError> {
        if self.done {
            return Err(StreamError::Finished);
        }
        if seq != self.next_seq {
            return Err(StreamError::Seq);
        }
        self.next_seq += 1;
        let c: StreamChunk = fleet_proto::decode(chunk).map_err(|_| StreamError::Decode)?;
        match c {
            StreamChunk::Data(d) => {
                if self.since_checkpoint >= CHECKPOINT_EVERY {
                    return Err(StreamError::NoCheckpoint);
                }
                self.count += 1;
                self.since_checkpoint += 1;
                self.chain = chain_step(&self.chain, self.count, &d);
                Ok(StreamItem::Data(d))
            }
            StreamChunk::Checkpoint(s) => {
                if s.seal.outcome.is_some() {
                    return Err(StreamError::Binding);
                }
                self.check(&s)?;
                self.since_checkpoint = 0;
                Ok(StreamItem::Checkpoint { count: self.count })
            }
            StreamChunk::Final(s) => {
                let outcome = s.seal.outcome.ok_or(StreamError::Binding)?;
                self.check(&s)?;
                self.done = true;
                Ok(StreamItem::Final {
                    outcome,
                    audit_seq: s.seal.audit_seq,
                    count: self.count,
                })
            }
        }
    }

    fn check(&self, s: &SignedStreamSeal) -> Result<(), StreamError> {
        verify_seal(s, &self.agent_key).map_err(|_| StreamError::Signature)?;
        if s.seal.server_id != self.server_id || s.seal.command_hash != self.command_hash {
            return Err(StreamError::Binding);
        }
        if s.seal.count != self.count || s.seal.chain != self.chain {
            return Err(StreamError::Chain);
        }
        Ok(())
    }
}

/// Signature only, against the pinned agent signing key.
pub fn verify_seal(s: &SignedStreamSeal, agent_key: &Ed25519Public) -> Result<(), Error> {
    sig::ed25519_verify(
        agent_key,
        &SignedStreamSeal::signed_message(&s.seal),
        &s.signature,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_proto::ErrorCode;

    fn setup() -> (Ed25519Signer, ServerId, StreamSealer, StreamVerifier) {
        let key = Ed25519Signer::from_seed(&[7; 32]);
        let server = ServerId::new("srv_stream01").unwrap();
        let sealer = StreamSealer::new(server.clone(), [1; 32]);
        let v = StreamVerifier::new(key.public(), server.clone(), [1; 32]);
        (key, server, sealer, v)
    }

    fn enc(c: &StreamChunk) -> Vec<u8> {
        fleet_proto::encode(c)
    }

    #[test]
    fn domain_is_distinct() {
        for d in [
            fleet_proto::domain::CMD,
            fleet_proto::domain::AUTH,
            fleet_proto::domain::APPROVE,
            fleet_proto::domain::ROSTER,
            fleet_proto::domain::RECEIPT,
            fleet_proto::domain::CHECKPOINT,
            fleet_proto::domain::RELEASE,
            fleet_proto::domain::EVENT,
        ] {
            assert!(!d.starts_with(STREAM_DOMAIN) && !STREAM_DOMAIN.starts_with(d));
        }
    }

    #[test]
    fn round_trip_with_checkpoint_and_final() {
        let (key, _, mut s, mut v) = setup();
        let mut seq = 0;
        for i in 0..3u8 {
            s.push(&[i]);
            let item = v.accept(seq, &enc(&StreamChunk::Data(vec![i]))).unwrap();
            assert_eq!(item, StreamItem::Data(vec![i]));
            seq += 1;
        }
        let cp = s.checkpoint(Some(4), 1, &key);
        assert_eq!(
            v.accept(seq, &enc(&StreamChunk::Checkpoint(cp))).unwrap(),
            StreamItem::Checkpoint { count: 3 }
        );
        seq += 1;
        let fin = s.finish(Some(5), Outcome::Ok, 2, &key);
        assert!(matches!(
            v.accept(seq, &enc(&StreamChunk::Final(fin))).unwrap(),
            StreamItem::Final {
                outcome: Outcome::Ok,
                count: 3,
                ..
            }
        ));
        assert!(v.finished());
    }

    #[test]
    fn dropped_reordered_or_forged_data_fails() {
        let (key, _, mut s, mut v) = setup();
        s.push(b"a");
        s.push(b"b");
        // The gate drops "a" and renumbers.
        v.accept(0, &enc(&StreamChunk::Data(b"b".to_vec())))
            .unwrap();
        let fin = s.finish(None, Outcome::Ok, 0, &key);
        assert_eq!(
            v.accept(1, &enc(&StreamChunk::Final(fin.clone()))),
            Err(StreamError::Chain)
        );
        // Seq gap.
        let (_, _, _, mut v2) = setup();
        assert_eq!(
            v2.accept(1, &enc(&StreamChunk::Data(vec![]))),
            Err(StreamError::Seq)
        );
        // Forged seal.
        let (_, _, _, mut v3) = setup();
        let mut bad = fin;
        bad.seal.count = 0;
        bad.seal.chain = [0; 32];
        assert_eq!(
            v3.accept(0, &enc(&StreamChunk::Final(bad))),
            Err(StreamError::Signature)
        );
    }

    #[test]
    fn wrong_command_and_missing_checkpoint() {
        let (key, server, _, mut v) = setup();
        let other = StreamSealer::new(server, [2; 32]).finish(
            None,
            Outcome::Failed(ErrorCode::Stale),
            0,
            &key,
        );
        assert_eq!(
            v.accept(0, &enc(&StreamChunk::Final(other))),
            Err(StreamError::Binding)
        );
        let (_, _, _, mut v) = setup();
        for i in 0..CHECKPOINT_EVERY {
            v.accept(i, &enc(&StreamChunk::Data(vec![]))).unwrap();
        }
        assert_eq!(
            v.accept(CHECKPOINT_EVERY, &enc(&StreamChunk::Data(vec![]))),
            Err(StreamError::NoCheckpoint)
        );
    }
}
