//! Exec's redb database at `state.redb` (design §4.4).
//!
//! Every write is its own durable transaction: commands are rare, and a
//! replay-cache or audit entry that is lost on crash would reopen a hole.
//! [`Store`] owns the database; the table groups are thin borrowed views.

//! Pending auto-revert changes are not here: they are plain files
//! (`crate::pending`) so the separate `revert` process can read them.

mod audit;
mod audit_archive;
mod config;
mod events;
mod meta;
mod metrics;
mod replay;
pub mod schema;
mod security;

pub use audit::{AuditLog, ChainError, ChainHead, CheckpointSigner, Intent};
pub use audit_archive::{
    AUDIT_RETENTION_MS, AnchorState, ArchiveError, ArchiveRecord, MAX_ARCHIVE_ENTRIES,
    read_archive,
};
pub use config::ConfigDb;
pub use events::{EventLog, MAX_EVENTS, RETENTION_MS as EVENT_RETENTION_MS, StoredEvent};
pub use meta::{Meta, MetaKey};
pub use metrics::MetricsDb;
pub use replay::ReplayCache;
pub use security::{SecurityDb, SecurityKey};

use redb::Database;
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard};

/// The database, shared by the views and the owning handles
/// ([`MetricsDb`], [`SecurityDb`]). Views hold the read side only for the
/// duration of a call; [`Store::compact`] takes the write side, which is
/// only free when no view is alive (exec is single-threaded).
type Db = Arc<RwLock<Database>>;
type DbRead<'a> = RwLockReadGuard<'a, Database>;

fn read(db: &Db) -> DbRead<'_> {
    // A panic while holding a guard can't leave the database itself
    // inconsistent (redb transactions are atomic).
    db.read().unwrap_or_else(PoisonError::into_inner)
}

/// Compaction doesn't run below this much unused space.
pub const COMPACT_MIN_FREE: u64 = 8 << 20;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database: {0}")]
    Db(#[from] redb::Error),
    #[error("corrupt record in table {0}")]
    Corrupt(&'static str),
    #[error("audit seq {0} is not an open intent")]
    NotOpenIntent(u64),
}

macro_rules! from_redb {
    ($($t:ty),*) => {$(
        impl From<$t> for StoreError {
            fn from(e: $t) -> Self {
                Self::Db(e.into())
            }
        }
    )*};
}
from_redb!(
    redb::DatabaseError,
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError,
    redb::CompactionError
);

pub type Result<T> = std::result::Result<T, StoreError>;

pub struct Store {
    /// Shared with [`MetricsDb`] (the telemetry sampler task) and
    /// [`SecurityDb`] (event sources).
    db: Db,
    path: PathBuf,
}

/// What [`Store::compact`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compaction {
    /// Unused space below the threshold.
    NotNeeded {
        file: u64,
        free: u64,
    },
    /// A view or transaction was alive; try again later.
    Busy,
    Done {
        before: u64,
        after: u64,
    },
}

impl Store {
    /// Opens or creates the database and makes sure every table exists, so
    /// read transactions never see a missing table.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = redb::Database::create(path.as_ref())?;
        let tx = db.begin_write()?;
        replay::create_tables(&tx)?;
        audit::create_tables(&tx)?;
        meta::create_tables(&tx)?;
        metrics::create_tables(&tx)?;
        security::create_tables(&tx)?;
        config::create_tables(&tx)?;
        events::create_tables(&tx)?;
        tx.commit()?;
        Ok(Self {
            db: Arc::new(RwLock::new(db)),
            path: path.as_ref().to_owned(),
        })
    }

    pub fn metrics(&self) -> MetricsDb {
        MetricsDb::new(self.db.clone())
    }

    pub fn security(&self) -> SecurityDb {
        SecurityDb::new(self.db.clone())
    }

    pub fn config(&self) -> ConfigDb {
        ConfigDb::new(self.db.clone())
    }

    pub fn replay(&self) -> ReplayCache<'_> {
        ReplayCache::new(read(&self.db))
    }

    pub fn audit(&self) -> AuditLog<'_> {
        AuditLog::new(read(&self.db))
    }

    pub fn meta(&self) -> Meta<'_> {
        Meta::new(read(&self.db))
    }

    pub fn events(&self) -> EventLog<'_> {
        EventLog::new(read(&self.db))
    }

    /// Compacts the file if at least `min_free` bytes, and a quarter of
    /// the file, are unused (design §4.4). See [`Compactor::compact`].
    pub fn compact(&self, min_free: u64) -> Result<Compaction> {
        self.compactor().compact(min_free)
    }

    /// A `Send` handle for compacting on the blocking pool.
    pub fn compactor(&self) -> Compactor {
        Compactor {
            db: self.db.clone(),
            path: self.path.clone(),
        }
    }
}

/// Compacts the database from another thread ([`Store::compactor`]).
pub struct Compactor {
    db: Db,
    path: PathBuf,
}

impl Compactor {
    /// Never waits for the write side: `Busy` if a view or transaction is
    /// alive. While it runs, every other database user waits for it
    /// (bounded by the database budget, 64 MB). Exec runs it on the
    /// blocking pool, so its own thread (watchdog, sockets) only stalls if
    /// it touches the database meanwhile.
    pub fn compact(&self, min_free: u64) -> Result<Compaction> {
        let Ok(mut db) = self.db.try_write() else {
            return Ok(Compaction::Busy);
        };
        let file = std::fs::metadata(&self.path).map_or(0, |m| m.len());
        let used = {
            let tx = db.begin_write()?;
            let s = tx.stats()?;
            tx.abort()?;
            s.allocated_pages().saturating_mul(s.page_size() as u64)
        };
        let free = file.saturating_sub(used);
        if free < min_free.max(file / 4) {
            return Ok(Compaction::NotNeeded { file, free });
        }
        // `false` = nothing left to move; either way the file is done.
        db.compact()?;
        let after = std::fs::metadata(&self.path).map_or(0, |m| m.len());
        Ok(Compaction::Done {
            before: file,
            after,
        })
    }
}
