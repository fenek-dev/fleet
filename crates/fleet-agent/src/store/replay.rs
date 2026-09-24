//! `replay` (design §4.4, §5.6): accepted `(device_id, nonce)` pairs and used
//! approval leaves, each kept until its expiry. Stored as two tables with
//! packed fixed-size keys; the value is the expiry in Unix milliseconds. A
//! third table keeps the response to each accepted command for as long as
//! its nonce (design §5.6).

use super::Result;
use fleet_proto::DeviceId;
use redb::{ReadableDatabase, TableDefinition, WriteTransaction};

/// `device_id (16) ‖ nonce (16)` → expiry_ms.
const NONCES: TableDefinition<&[u8; 32], u64> = TableDefinition::new("replay_nonce");
/// `approval_id (16) ‖ leaf hash (32)` → expiry_ms. The leaf hash, not its
/// index, so one item can't be spent twice under different proof shapes.
const LEAVES: TableDefinition<&[u8; 48], u64> = TableDefinition::new("replay_leaf");
/// `command_hash` → `expiry_ms (8, big-endian) ‖ response`: the answer
/// (result and signed receipt, encoded by exec) to a command that consumed
/// its nonce, kept as long as the nonce. A replay of the identical command
/// gets this original answer back instead of a signed `Replay` failure.
const RESPONSES: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("replay_response");

pub(super) fn create_tables(tx: &WriteTransaction) -> Result<()> {
    tx.open_table(NONCES)?;
    tx.open_table(LEAVES)?;
    tx.open_table(RESPONSES)?;
    Ok(())
}

pub struct ReplayCache<'a> {
    db: super::DbRead<'a>,
}

impl<'a> ReplayCache<'a> {
    pub(super) fn new(db: super::DbRead<'a>) -> Self {
        Self { db }
    }

    /// Records the pair if unseen. Returns `true` if it was fresh (and is now
    /// stored durably), `false` if it was already present — even if that
    /// entry has expired but not been pruned yet.
    pub fn check_and_insert_nonce(
        &self,
        device_id: &DeviceId,
        nonce: &[u8; 16],
        expires_ms: u64,
    ) -> Result<bool> {
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(&device_id.0);
        key[16..].copy_from_slice(nonce);
        self.insert_new(NONCES, &key, expires_ms)
    }

    /// Same contract as [`Self::check_and_insert_nonce`] for approval leaves.
    pub fn check_and_insert_leaf(
        &self,
        approval_id: &[u8; 16],
        leaf: &fleet_proto::Hash32,
        expires_ms: u64,
    ) -> Result<bool> {
        let mut key = [0u8; 48];
        key[..16].copy_from_slice(approval_id);
        key[16..].copy_from_slice(leaf);
        self.insert_new(LEAVES, &key, expires_ms)
    }

    /// Stores the response to `command_hash` until `expires_ms` (durable).
    pub fn put_response(
        &self,
        command_hash: &fleet_proto::Hash32,
        expires_ms: u64,
        response: &[u8],
    ) -> Result<()> {
        let mut v = Vec::with_capacity(8 + response.len());
        v.extend_from_slice(&expires_ms.to_be_bytes());
        v.extend_from_slice(response);
        let tx = self.db.begin_write()?;
        tx.open_table(RESPONSES)?.insert(command_hash, &v[..])?;
        tx.commit()?;
        Ok(())
    }

    /// The stored response to `command_hash`, if any (expired but not yet
    /// pruned included: its nonce is still recorded too).
    pub fn get_response(&self, command_hash: &fleet_proto::Hash32) -> Result<Option<Vec<u8>>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(RESPONSES)?;
        let Some(v) = redb::ReadableTable::get(&t, command_hash)? else {
            return Ok(None);
        };
        let v = v.value();
        if v.len() < 8 {
            return Err(super::StoreError::Corrupt("replay_response"));
        }
        Ok(Some(v[8..].to_vec()))
    }

    /// Removes every entry whose expiry is before `now_ms`. Returns the count.
    /// Commits (and fsyncs) only when something was removed.
    pub fn prune(&self, now_ms: u64) -> Result<u64> {
        let tx = self.db.begin_write()?;
        let mut removed = 0u64;
        {
            let mut t = tx.open_table(NONCES)?;
            t.retain(|_, exp| {
                let keep = exp >= now_ms;
                removed += u64::from(!keep);
                keep
            })?;
            let mut t = tx.open_table(LEAVES)?;
            t.retain(|_, exp| {
                let keep = exp >= now_ms;
                removed += u64::from(!keep);
                keep
            })?;
            let mut t = tx.open_table(RESPONSES)?;
            t.retain(|_, v| {
                // A malformed value (no expiry) is dropped.
                let keep = v
                    .get(..8)
                    .and_then(|b| <[u8; 8]>::try_from(b).ok())
                    .is_some_and(|b| u64::from_be_bytes(b) >= now_ms);
                removed += u64::from(!keep);
                keep
            })?;
        }
        if removed == 0 {
            tx.abort()?;
        } else {
            tx.commit()?;
        }
        Ok(removed)
    }

    /// Number of stored entries (both tables). For tests and health output.
    pub fn len(&self) -> Result<u64> {
        use redb::ReadableTableMetadata;
        let tx = self.db.begin_read()?;
        Ok(tx.open_table(NONCES)?.len()? + tx.open_table(LEAVES)?.len()?)
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    fn contains<const N: usize>(
        &self,
        def: TableDefinition<&[u8; N], u64>,
        key: &[u8; N],
    ) -> Result<bool> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(def)?;
        Ok(redb::ReadableTable::get(&t, key)?.is_some())
    }

    fn insert_new<const N: usize>(
        &self,
        def: TableDefinition<&[u8; N], u64>,
        key: &[u8; N],
        expires_ms: u64,
    ) -> Result<bool> {
        let tx = self.db.begin_write()?;
        let fresh = {
            let mut t = tx.open_table(def)?;
            let seen = redb::ReadableTable::get(&t, key)?.is_some();
            if !seen {
                t.insert(key, expires_ms)?;
            }
            !seen
        };
        if fresh {
            tx.commit()?;
        } else {
            tx.abort()?;
        }
        Ok(fresh)
    }
}

/// Glue for `fleet_crypto::verify::verify_command`. A database error counts
/// as "seen" (fail closed): the command is rejected as a replay rather than
/// run without a durable replay record.
impl fleet_crypto::verify::ReplayStore for ReplayCache<'_> {
    // Read-only lookups for verify_command; commit() does the inserts.
    fn contains_nonce(&self, device_id: DeviceId, nonce: [u8; 16]) -> bool {
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(&device_id.0);
        key[16..].copy_from_slice(&nonce);
        self.contains(NONCES, &key).unwrap_or(true)
    }

    fn contains_leaf(&self, approval_id: [u8; 16], leaf: fleet_proto::Hash32) -> bool {
        let mut key = [0u8; 48];
        key[..16].copy_from_slice(&approval_id);
        key[16..].copy_from_slice(&leaf);
        self.contains(LEAVES, &key).unwrap_or(true)
    }

    fn check_and_insert_nonce(
        &mut self,
        device_id: DeviceId,
        nonce: [u8; 16],
        expires_at_ms: u64,
    ) -> bool {
        ReplayCache::check_and_insert_nonce(self, &device_id, &nonce, expires_at_ms)
            .unwrap_or(false)
    }

    fn check_and_insert_leaf(
        &mut self,
        approval_id: [u8; 16],
        leaf: fleet_proto::Hash32,
        expires_at_ms: u64,
    ) -> bool {
        ReplayCache::check_and_insert_leaf(self, &approval_id, &leaf, expires_at_ms)
            .unwrap_or(false)
    }
}
