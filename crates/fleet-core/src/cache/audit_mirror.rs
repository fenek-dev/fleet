//! The audit mirror (`audit_entries`, design §7.4): raw entry bytes per
//! server and seq. The offline mirror that fills it syncs entries from
//! servers; the timeline reads the newest ones.

use super::{Cache, CacheError};
use fleet_proto::ServerId;
use rusqlite::params;

impl Cache {
    /// Stores one mirrored entry (raw `AuditEntry` encoding and its hash).
    pub fn put_audit_entry(
        &self,
        id: &ServerId,
        seq: u64,
        entry: &[u8],
        entry_hash: &[u8; 32],
    ) -> Result<(), CacheError> {
        let seq = i64::try_from(seq).map_err(|_| CacheError::Corrupt("audit seq".into()))?;
        self.conn.execute(
            "INSERT OR REPLACE INTO audit_entries (server_id, seq, entry, entry_hash)
             VALUES (?1, ?2, ?3, ?4)",
            params![id.as_str(), seq, entry, &entry_hash[..]],
        )?;
        Ok(())
    }

    /// The newest `limit` mirrored entries of `id`, newest first:
    /// `(seq, raw entry)`.
    pub fn audit_mirror(
        &self,
        id: &ServerId,
        limit: usize,
    ) -> Result<Vec<(u64, Vec<u8>)>, CacheError> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut st = self.conn.prepare_cached(
            "SELECT seq, entry FROM audit_entries WHERE server_id = ?1
             ORDER BY seq DESC LIMIT ?2",
        )?;
        let rows = st
            .query_map(params![id.as_str(), limit], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows
            .into_iter()
            .filter_map(|(s, e)| u64::try_from(s).ok().map(|s| (s, e)))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::ServerRecord;
    use crate::ssh::SshTarget;

    #[test]
    fn newest_first() {
        let mut c = Cache::open_in_memory().unwrap();
        let id = ServerId::new("srv_aaaaaaaaaaaa").unwrap();
        c.upsert_server(&ServerRecord {
            id: id.clone(),
            name: "a".into(),
            target: SshTarget::new("192.0.2.1", 22, "root"),
            group: None,
            tags: vec![],
        })
        .unwrap();
        for s in 1..=5u64 {
            c.put_audit_entry(&id, s, &[s as u8], &[0; 32]).unwrap();
        }
        let got = c.audit_mirror(&id, 3).unwrap();
        assert_eq!(got, [(5, vec![5]), (4, vec![4]), (3, vec![3])]);
        let other = ServerId::new("srv_bbbbbbbbbbbb").unwrap();
        assert!(c.audit_mirror(&other, 3).unwrap().is_empty());
    }
}
