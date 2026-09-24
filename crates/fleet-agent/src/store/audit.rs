//! Hash-chained audit log (design §5.8).
//!
//! Tables:
//! - `audit`: seq → `postcard(AuditEntry)`. Seqs start at 1 and are
//!   contiguous; seq 0 means "empty chain".
//! - `audit_open`: intent seqs still waiting for their result.
//! - `audit_head`: the single row `(seq, entry_hash)` of the last entry.
//!
//! `entry_hash = BLAKE3(prev_hash ‖ postcard(entry))`; the genesis entry has
//! `prev_hash = [0; 32]`. Integrity comes from the chain and from checkpoints
//! held by Macs, not from redb.

use super::{Result, StoreError};
use fleet_proto::{
    Actor, AuditEntry, Checkpoint, DeviceId, Hash32, OpSummary, Outcome, Phase, ResultSummary,
    ServerId, Signature, SignedCheckpoint, decode, encode,
};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction};

const ENTRIES: TableDefinition<u64, &[u8]> = TableDefinition::new("audit");
const OPEN: TableDefinition<u64, ()> = TableDefinition::new("audit_open");
/// Key is always `()`; value is `seq (u64 BE) ‖ entry_hash`.
const HEAD: TableDefinition<(), &[u8; 40]> = TableDefinition::new("audit_head");

pub(super) fn create_tables(tx: &WriteTransaction) -> Result<()> {
    tx.open_table(ENTRIES)?;
    tx.open_table(OPEN)?;
    tx.open_table(HEAD)?;
    Ok(())
}

/// Signs checkpoint messages with the agent signing key.
pub trait CheckpointSigner {
    /// `msg` is already domain-separated (`fleet/checkpoint/v1 ‖ postcard`).
    fn sign(&self, msg: &[u8]) -> Signature;
}

/// The fields of an intent entry that come from the verified command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    pub time_ms: u64,
    pub actor: Actor,
    pub device_id: DeviceId,
    /// BLAKE3 of the `SignedCommand` encoding.
    pub command_hash: Hash32,
    pub signature: Signature,
    pub op: OpSummary,
}

/// Last entry of the chain. `seq == 0` with a zero hash for an empty chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainHead {
    pub seq: u64,
    pub entry_hash: Hash32,
}

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("gap in audit chain: expected seq {expected}, found {found}")]
    Gap { expected: u64, found: u64 },
    #[error("audit entry {0} does not link to its predecessor")]
    Broken(u64),
    #[error("audit head does not match the last entry")]
    HeadMismatch,
}

pub fn entry_hash(entry: &AuditEntry) -> Hash32 {
    let mut h = blake3::Hasher::new();
    h.update(&entry.prev_hash);
    h.update(&encode(entry));
    *h.finalize().as_bytes()
}

pub struct AuditLog<'a> {
    db: &'a Database,
}

impl<'a> AuditLog<'a> {
    pub(super) fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Appends an intent entry. Returns its seq.
    pub fn append_intent(&self, intent: Intent) -> Result<u64> {
        let tx = self.db.begin_write()?;
        let seq = append(
            &tx,
            intent.time_ms,
            intent.actor,
            intent.device_id,
            intent.command_hash,
            intent.signature,
            intent.op,
            Phase::Intent,
            ResultSummary::Pending,
        )?;
        tx.open_table(OPEN)?.insert(seq, ())?;
        tx.commit()?;
        Ok(seq)
    }

    /// Appends the result for an open intent. Returns the result entry's seq.
    pub fn append_result(&self, intent_seq: u64, time_ms: u64, outcome: Outcome) -> Result<u64> {
        let tx = self.db.begin_write()?;
        if tx.open_table(OPEN)?.remove(intent_seq)?.is_none() {
            return Err(StoreError::NotOpenIntent(intent_seq));
        }
        let seq = append_result_for(&tx, intent_seq, time_ms, outcome)?;
        tx.commit()?;
        Ok(seq)
    }

    /// Records the automatic revert of a change made by command `origin_seq`
    /// (design §4.10): an `Actor::System` result entry that copies the
    /// originating command's device, hash, signature and op, with
    /// `Outcome::Reverted`, or `Failed(Internal)` if restoring failed.
    pub fn append_revert(&self, origin_seq: u64, time_ms: u64, restored: bool) -> Result<u64> {
        let outcome = if restored {
            Outcome::Reverted
        } else {
            Outcome::Failed(fleet_proto::ErrorCode::Internal)
        };
        let tx = self.db.begin_write()?;
        let origin = {
            let t = tx.open_table(ENTRIES)?;
            let v = t
                .get(origin_seq)?
                .ok_or(StoreError::NotOpenIntent(origin_seq))?;
            decode_entry(v.value())?
        };
        let seq = append(
            &tx,
            time_ms,
            Actor::System,
            origin.device_id,
            origin.command_hash,
            origin.signature,
            origin.op,
            Phase::Result,
            ResultSummary::Done(outcome),
        )?;
        tx.commit()?;
        Ok(seq)
    }

    /// Records an agent-originated action with no signed command behind it
    /// (e.g. activating a pending recovery roster once its delay passed):
    /// `Actor::System`, zero device id and signature.
    pub fn append_system(
        &self,
        time_ms: u64,
        command_hash: Hash32,
        op: OpSummary,
        outcome: Outcome,
    ) -> Result<u64> {
        let tx = self.db.begin_write()?;
        let seq = append(
            &tx,
            time_ms,
            Actor::System,
            DeviceId([0; 16]),
            command_hash,
            Signature([0; 64]),
            op,
            Phase::Result,
            ResultSummary::Done(outcome),
        )?;
        tx.commit()?;
        Ok(seq)
    }

    /// Startup step (design §5.6): every intent without a result gets
    /// `Result: Interrupted`. Returns the intent seqs that were closed.
    pub fn mark_interrupted_on_start(&self, time_ms: u64) -> Result<Vec<u64>> {
        let tx = self.db.begin_write()?;
        let open: Vec<u64> = {
            let t = tx.open_table(OPEN)?;
            t.iter()?
                .map(|r| r.map(|(k, _)| k.value()))
                .collect::<std::result::Result<_, _>>()?
        };
        for &seq in &open {
            append_result_for(&tx, seq, time_ms, Outcome::Interrupted)?;
        }
        tx.open_table(OPEN)?.retain(|_, _| false)?;
        tx.commit()?;
        Ok(open)
    }

    pub fn head(&self) -> Result<ChainHead> {
        let tx = self.db.begin_read()?;
        read_head(&tx.open_table(HEAD)?)
    }

    pub fn get(&self, seq: u64) -> Result<Option<AuditEntry>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(ENTRIES)?;
        t.get(seq)?.map(|v| decode_entry(v.value())).transpose()
    }

    /// Up to `limit` entries with `seq > after`, in order. For streaming to
    /// Macs and for sync.
    pub fn entries_since(&self, after: u64, limit: usize) -> Result<Vec<AuditEntry>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(ENTRIES)?;
        let mut out = Vec::new();
        for row in t.range(after.saturating_add(1)..)?.take(limit) {
            let (_, v) = row?;
            out.push(decode_entry(v.value())?);
        }
        Ok(out)
    }

    /// Verifies the chain from `from_seq` to the head. If `from_seq`'s
    /// predecessor is present (or `from_seq` is the genesis entry), the first
    /// link is checked too; otherwise the first entry's `prev_hash` is the
    /// anchor (entries before it were archived).
    pub fn verify_chain(&self, from_seq: u64) -> std::result::Result<ChainHead, ChainError> {
        let tx = self.db.begin_read().map_err(StoreError::from)?;
        let t = tx.open_table(ENTRIES).map_err(StoreError::from)?;
        let head = read_head(&tx.open_table(HEAD).map_err(StoreError::from)?)?;
        let from_seq = from_seq.max(1);

        let mut expected_prev: Option<Hash32> = if from_seq == 1 {
            Some([0; 32])
        } else {
            match t.get(from_seq - 1).map_err(StoreError::from)? {
                Some(v) => Some(entry_hash(&decode_entry(v.value())?)),
                None => None,
            }
        };
        let mut last = ChainHead {
            seq: from_seq - 1,
            entry_hash: expected_prev.unwrap_or([0; 32]),
        };
        for row in t.range(from_seq..).map_err(StoreError::from)? {
            let (k, v) = row.map_err(StoreError::from)?;
            let entry = decode_entry(v.value())?;
            let expected = last.seq + 1;
            if k.value() != expected || entry.seq != expected {
                return Err(ChainError::Gap {
                    expected,
                    found: entry.seq,
                });
            }
            if let Some(prev) = expected_prev
                && entry.prev_hash != prev
            {
                return Err(ChainError::Broken(entry.seq));
            }
            let h = entry_hash(&entry);
            expected_prev = Some(h);
            last = ChainHead {
                seq: entry.seq,
                entry_hash: h,
            };
        }
        if last.seq >= head.seq && last != head {
            return Err(ChainError::HeadMismatch);
        }
        if last.seq < head.seq {
            // Entries after the last one found are missing (truncation).
            return Err(ChainError::Gap {
                expected: last.seq + 1,
                found: head.seq,
            });
        }
        Ok(last)
    }

    /// Signs the current head (design §5.8).
    pub fn checkpoint(
        &self,
        server_id: ServerId,
        time_ms: u64,
        signer: &dyn CheckpointSigner,
    ) -> Result<SignedCheckpoint> {
        let head = self.head()?;
        let checkpoint = Checkpoint {
            server_id,
            seq: head.seq,
            entry_hash: head.entry_hash,
            time_ms,
        };
        let signature = signer.sign(&SignedCheckpoint::signed_message(&checkpoint));
        Ok(SignedCheckpoint {
            checkpoint,
            signature,
        })
    }

    /// Test hook: overwrites a stored entry without fixing the chain.
    #[doc(hidden)]
    pub fn tamper_for_test(&self, entry: &AuditEntry) -> Result<()> {
        let tx = self.db.begin_write()?;
        tx.open_table(ENTRIES)?
            .insert(entry.seq, encode(entry).as_slice())?;
        tx.commit()?;
        Ok(())
    }
}

fn decode_entry(bytes: &[u8]) -> Result<AuditEntry> {
    decode(bytes).map_err(|_| StoreError::Corrupt("audit"))
}

fn read_head(t: &impl ReadableTable<(), &'static [u8; 40]>) -> Result<ChainHead> {
    Ok(match t.get(())? {
        None => ChainHead {
            seq: 0,
            entry_hash: [0; 32],
        },
        Some(v) => {
            let b = v.value();
            let mut seq = [0u8; 8];
            seq.copy_from_slice(&b[..8]);
            let mut entry_hash = [0u8; 32];
            entry_hash.copy_from_slice(&b[8..]);
            ChainHead {
                seq: u64::from_be_bytes(seq),
                entry_hash,
            }
        }
    })
}

fn append_result_for(
    tx: &WriteTransaction,
    intent_seq: u64,
    time_ms: u64,
    outcome: Outcome,
) -> Result<u64> {
    let intent = {
        let t = tx.open_table(ENTRIES)?;
        let v = t
            .get(intent_seq)?
            .ok_or(StoreError::NotOpenIntent(intent_seq))?;
        decode_entry(v.value())?
    };
    if intent.phase != Phase::Intent {
        return Err(StoreError::NotOpenIntent(intent_seq));
    }
    append(
        tx,
        time_ms,
        intent.actor,
        intent.device_id,
        intent.command_hash,
        intent.signature,
        intent.op,
        Phase::Result,
        ResultSummary::Done(outcome),
    )
}

#[allow(clippy::too_many_arguments)]
fn append(
    tx: &WriteTransaction,
    time: u64,
    actor: Actor,
    device_id: DeviceId,
    command_hash: Hash32,
    signature: Signature,
    op: OpSummary,
    phase: Phase,
    result: ResultSummary,
) -> Result<u64> {
    let mut head_t = tx.open_table(HEAD)?;
    let head = read_head(&head_t)?;
    let entry = AuditEntry {
        seq: head.seq + 1,
        time,
        prev_hash: head.entry_hash,
        actor,
        device_id,
        command_hash,
        signature,
        op,
        phase,
        result,
    };
    let h = entry_hash(&entry);
    tx.open_table(ENTRIES)?
        .insert(entry.seq, encode(&entry).as_slice())?;
    let mut row = [0u8; 40];
    row[..8].copy_from_slice(&entry.seq.to_be_bytes());
    row[8..].copy_from_slice(&h);
    head_t.insert((), &row)?;
    Ok(entry.seq)
}
