//! The audit mirror (design §5.8, §7.4): `audit_entries` (raw entry bytes
//! and entry hash per server and seq) and `audit_checkpoints` (per server:
//! the verified mirror head and the last checkpoint seen). Filled by
//! [`crate::audit_mirror`] after verifying chain continuity; the timeline
//! reads the newest entries. Rows are MAC'd (schema v4): a mismatch is
//! [`CacheError::Integrity`].

use super::{Cache, CacheError, F};
use fleet_proto::ServerId;
use rusqlite::{OptionalExtension, params};

fn seq_i64(seq: u64) -> Result<i64, CacheError> {
    i64::try_from(seq).map_err(|_| CacheError::Corrupt("audit seq".into()))
}

impl Cache {
    fn audit_entry_mac(&self, id: &ServerId, seq: u64, entry: &[u8], hash: &[u8]) -> [u8; 32] {
        self.mac(
            "audit_entries",
            &[
                F::B(id.as_str().as_bytes()),
                F::B(&seq.to_be_bytes()),
                F::B(entry),
                F::B(hash),
            ],
        )
    }

    fn audit_checkpoint_mac(&self, id: &ServerId, seq: u64, blob: &[u8]) -> [u8; 32] {
        self.mac(
            "audit_checkpoints",
            &[
                F::B(id.as_str().as_bytes()),
                F::B(&seq.to_be_bytes()),
                F::B(blob),
            ],
        )
    }

    /// Stores one mirrored entry (raw `AuditEntry` encoding and its hash).
    pub fn put_audit_entry(
        &self,
        id: &ServerId,
        seq: u64,
        entry: &[u8],
        entry_hash: &[u8; 32],
    ) -> Result<(), CacheError> {
        let mac = self.audit_entry_mac(id, seq, entry, entry_hash);
        self.conn.execute(
            "INSERT OR REPLACE INTO audit_entries (server_id, seq, entry, entry_hash, mac)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id.as_str(), seq_i64(seq)?, entry, &entry_hash[..], &mac[..]],
        )?;
        Ok(())
    }

    /// The newest `limit` mirrored entries of `id`, newest first:
    /// `(seq, raw entry)`. Every row's MAC is checked.
    pub fn audit_mirror(
        &self,
        id: &ServerId,
        limit: usize,
    ) -> Result<Vec<(u64, Vec<u8>)>, CacheError> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut st = self.conn.prepare_cached(
            "SELECT seq, entry, entry_hash, mac FROM audit_entries WHERE server_id = ?1
             ORDER BY seq DESC LIMIT ?2",
        )?;
        let rows = st
            .query_map(params![id.as_str(), limit], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, Option<Vec<u8>>>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut out = Vec::with_capacity(rows.len());
        for (s, entry, hash, mac) in rows {
            let seq = u64::try_from(s).map_err(|_| CacheError::Corrupt("audit seq".into()))?;
            self.check_mac(
                "audit entry",
                self.audit_entry_mac(id, seq, &entry, &hash),
                mac,
            )?;
            out.push((seq, entry));
        }
        Ok(out)
    }

    /// Stores the per-server mirror state blob (`crate::audit_mirror`),
    /// keyed by its head seq.
    pub fn put_audit_checkpoint(
        &self,
        id: &ServerId,
        seq: u64,
        blob: &[u8],
        verified_at_ms: u64,
    ) -> Result<(), CacheError> {
        let mac = self.audit_checkpoint_mac(id, seq, blob);
        self.conn.execute(
            "INSERT INTO audit_checkpoints (server_id, seq, checkpoint, verified_at_ms, mac)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(server_id) DO UPDATE SET seq = excluded.seq,
                checkpoint = excluded.checkpoint, verified_at_ms = excluded.verified_at_ms,
                mac = excluded.mac",
            params![
                id.as_str(),
                seq_i64(seq)?,
                blob,
                i64::try_from(verified_at_ms).unwrap_or(i64::MAX),
                &mac[..]
            ],
        )?;
        Ok(())
    }

    /// The mirror state blob of `id` and its seq, MAC checked.
    pub fn audit_checkpoint(&self, id: &ServerId) -> Result<Option<(u64, Vec<u8>)>, CacheError> {
        let row: Option<(i64, Vec<u8>, Option<Vec<u8>>)> = self
            .conn
            .query_row(
                "SELECT seq, checkpoint, mac FROM audit_checkpoints WHERE server_id = ?1",
                [id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((s, blob, mac)) = row else {
            return Ok(None);
        };
        let seq = u64::try_from(s).map_err(|_| CacheError::Corrupt("audit seq".into()))?;
        self.check_mac(
            "audit checkpoint",
            self.audit_checkpoint_mac(id, seq, &blob),
            mac,
        )?;
        Ok(Some((seq, blob)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::ServerRecord;
    use crate::ssh::SshTarget;

    fn cache_with(id: &ServerId) -> Cache {
        let mut c = Cache::open_in_memory().unwrap();
        c.upsert_server(&ServerRecord {
            id: id.clone(),
            name: "a".into(),
            target: SshTarget::new("192.0.2.1", 22, "root"),
            group: None,
            tags: vec![],
        })
        .unwrap();
        c
    }

    #[test]
    fn newest_first() {
        let id = ServerId::new("srv_aaaaaaaaaaaa").unwrap();
        let c = cache_with(&id);
        for s in 1..=5u64 {
            c.put_audit_entry(&id, s, &[s as u8], &[0; 32]).unwrap();
        }
        let got = c.audit_mirror(&id, 3).unwrap();
        assert_eq!(got, [(5, vec![5]), (4, vec![4]), (3, vec![3])]);
        let other = ServerId::new("srv_bbbbbbbbbbbb").unwrap();
        assert!(c.audit_mirror(&other, 3).unwrap().is_empty());
    }

    #[test]
    fn rows_are_macd() {
        let id = ServerId::new("srv_aaaaaaaaaaaa").unwrap();
        let c = cache_with(&id);
        c.put_audit_entry(&id, 1, &[1], &[7; 32]).unwrap();
        c.put_audit_checkpoint(&id, 1, b"state", 5).unwrap();
        assert_eq!(c.audit_checkpoint(&id).unwrap(), Some((1, b"state".to_vec())));
        c.conn
            .execute("UPDATE audit_entries SET entry = x'02'", [])
            .unwrap();
        assert!(matches!(
            c.audit_mirror(&id, 10),
            Err(CacheError::Integrity(_))
        ));
        c.conn
            .execute("UPDATE audit_checkpoints SET seq = 9", [])
            .unwrap();
        assert!(matches!(
            c.audit_checkpoint(&id),
            Err(CacheError::Integrity(_))
        ));
    }
}
