//! Exec's redb database at `state.redb` (design §4.4).
//!
//! Every write is its own durable transaction: commands are rare, and a
//! replay-cache or audit entry that is lost on crash would reopen a hole.
//! [`Store`] owns the database; the table groups are thin borrowed views.

//! Pending auto-revert changes are not here: they are plain files
//! (`crate::pending`) so the separate `revert` process can read them.

mod audit;
mod config;
mod meta;
mod metrics;
mod replay;

pub use audit::{AuditLog, ChainError, ChainHead, CheckpointSigner, Intent};
pub use config::ConfigDb;
pub use meta::{Meta, MetaKey};
pub use metrics::MetricsDb;
pub use replay::ReplayCache;

use std::path::Path;

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
    redb::CommitError
);

pub type Result<T> = std::result::Result<T, StoreError>;

pub struct Store {
    /// Shared with [`MetricsDb`] (the telemetry sampler task).
    db: std::sync::Arc<redb::Database>,
}

impl Store {
    /// Opens or creates the database and makes sure every table exists, so
    /// read transactions never see a missing table.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = redb::Database::create(path)?;
        let tx = db.begin_write()?;
        replay::create_tables(&tx)?;
        audit::create_tables(&tx)?;
        meta::create_tables(&tx)?;
        metrics::create_tables(&tx)?;
        config::create_tables(&tx)?;
        tx.commit()?;
        Ok(Self { db: db.into() })
    }

    pub fn metrics(&self) -> MetricsDb {
        MetricsDb::new(self.db.clone())
    }

    pub fn config(&self) -> ConfigDb {
        ConfigDb::new(self.db.clone())
    }

    pub fn replay(&self) -> ReplayCache<'_> {
        ReplayCache::new(&self.db)
    }

    pub fn audit(&self) -> AuditLog<'_> {
        AuditLog::new(&self.db)
    }

    pub fn meta(&self) -> Meta<'_> {
        Meta::new(&self.db)
    }
}
