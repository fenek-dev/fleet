//! `security`: persisted intrusion-blocking and integrity state (design
//! §4.4, §4.7): ban state (active bans, strikes, learned Mac addresses,
//! config), the integrity baseline, known login sources, and the sshd
//! journal cursor. Values are postcard (the cursor UTF-8); exec
//! re-validates everything on load.

use super::Result;
use redb::{ReadableDatabase, TableDefinition, WriteTransaction};

const SECURITY: TableDefinition<&str, &[u8]> = TableDefinition::new("security");

pub(super) fn create_tables(tx: &WriteTransaction) -> Result<()> {
    tx.open_table(SECURITY)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityKey {
    /// `postcard(fleet_ops::security::BanState)`.
    Bans,
    /// `postcard(fleet_ops::security::integrity::Baseline)`.
    IntegrityBaseline,
    /// `postcard(Vec<(IpAddr, u64)>)`: sources of successful logins.
    LoginSources,
    /// UTF-8 journal cursor of the last sshd entry processed.
    SshdCursor,
}

impl SecurityKey {
    fn as_str(self) -> &'static str {
        match self {
            Self::Bans => "bans",
            Self::IntegrityBaseline => "integrity_baseline",
            Self::LoginSources => "login_sources",
            Self::SshdCursor => "sshd_cursor",
        }
    }
}

/// Owns a database handle, so exec's event sources keep it without
/// borrowing exec's state.
#[derive(Clone)]
pub struct SecurityDb {
    db: super::Db,
}

impl SecurityDb {
    pub(super) fn new(db: super::Db) -> Self {
        Self { db }
    }

    pub fn get(&self, key: SecurityKey) -> Result<Option<Vec<u8>>> {
        let tx = super::read(&self.db).begin_read()?;
        let t = tx.open_table(SECURITY)?;
        Ok(t.get(key.as_str())?.map(|v| v.value().to_vec()))
    }

    pub fn set(&self, key: SecurityKey, value: &[u8]) -> Result<()> {
        let tx = super::read(&self.db).begin_write()?;
        tx.open_table(SECURITY)?.insert(key.as_str(), value)?;
        tx.commit()?;
        Ok(())
    }
}
