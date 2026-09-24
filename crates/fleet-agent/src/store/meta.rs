//! `meta`: raw bytes of exec's persistent state (roster, policy, ids).
//! Nothing here is trusted blindly; exec re-validates on load.

use super::Result;
use redb::{ReadableDatabase, TableDefinition, WriteTransaction};

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

pub(super) fn create_tables(tx: &WriteTransaction) -> Result<()> {
    tx.open_table(META)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetaKey {
    /// `postcard(SignedRoster)` currently in force.
    Roster,
    /// `postcard(Vec<Hash32>)`: hashes of every roster accepted in the
    /// current epoch (recovery rosters may chain off any of them).
    EpochHashes,
    /// `postcard(u64)`: local recovery-grace time remaining for the current
    /// `prev_recovery`, counted down on the monotonic clock (absent: none).
    GraceRemaining,
    /// `postcard(StoredPending)`: a recovery roster waiting out its delay.
    PendingRecovery,
    /// `postcard(StoredPolicy)`: policy TOML plus the approval it came with.
    Policy,
    /// UTF-8 server id, set by `install`.
    ServerId,
    /// UTF-8 admin login whose `authorized_keys` roster section exec writes.
    AdminUser,
    /// `postcard(SignedCheckpoint)`: the latest hourly checkpoint.
    Checkpoint,
}

impl MetaKey {
    fn as_str(self) -> &'static str {
        match self {
            Self::Roster => "roster",
            Self::EpochHashes => "epoch_hashes",
            Self::GraceRemaining => "grace_remaining",
            Self::PendingRecovery => "pending_recovery",
            Self::Policy => "policy",
            Self::ServerId => "server_id",
            Self::AdminUser => "admin_user",
            Self::Checkpoint => "checkpoint",
        }
    }
}

pub struct Meta<'a> {
    db: super::DbRead<'a>,
}

impl<'a> Meta<'a> {
    pub(super) fn new(db: super::DbRead<'a>) -> Self {
        Self { db }
    }

    pub fn get(&self, key: MetaKey) -> Result<Option<Vec<u8>>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(META)?;
        Ok(t.get(key.as_str())?.map(|v| v.value().to_vec()))
    }

    pub fn set(&self, key: MetaKey, value: &[u8]) -> Result<()> {
        self.update(&[(key, Some(value))])
    }

    /// Sets (`Some`) or removes (`None`) several keys in one transaction.
    pub fn update(&self, changes: &[(MetaKey, Option<&[u8]>)]) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(META)?;
            for (k, v) in changes {
                match v {
                    Some(v) => {
                        t.insert(k.as_str(), *v)?;
                    }
                    None => {
                        t.remove(k.as_str())?;
                    }
                }
            }
        }
        tx.commit()?;
        Ok(())
    }
}
