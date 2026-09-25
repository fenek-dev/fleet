//! Local copy of the synced records: its own SQLite file (not a cache
//! migration), every row encrypted at rest with AES-256-GCM under a key
//! derived from the Keychain-held cache key (so sudo passwords and pins
//! never sit in plaintext on disk). The AAD binds each row to its table,
//! collection and key; a row moved or edited outside the app fails to
//! open and reads as an integrity error.

use super::{Collection, Hlc, SignedRecord, SyncError};
use fleet_crypto::Zeroizing;
use fleet_proto::{decode, encode};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS records (
    collection INTEGER NOT NULL,
    key        TEXT NOT NULL,
    sealed     BLOB NOT NULL,
    dirty      INTEGER NOT NULL,
    synced     BLOB,
    PRIMARY KEY (collection, key)
);
CREATE TABLE IF NOT EXISTS conflicts (
    collection INTEGER NOT NULL,
    key        TEXT NOT NULL,
    sealed     BLOB NOT NULL,
    PRIMARY KEY (collection, key)
);
CREATE TABLE IF NOT EXISTS pin_changes (
    key    TEXT PRIMARY KEY,
    sealed BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);";

/// One stored record with its sync state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub signed: SignedRecord,
    /// Local change not yet pushed.
    pub dirty: bool,
    /// Stamp of the version last received from or pushed to the cloud.
    pub synced: Option<Hlc>,
}

pub struct SyncStore {
    conn: Connection,
    key: Zeroizing<[u8; 32]>,
}

impl SyncStore {
    /// `cache_key`: the cache integrity key bytes (Keychain).
    pub fn open(path: &Path, cache_key: &[u8; 32]) -> Result<Self, SyncError> {
        Self::init(Connection::open(path)?, cache_key)
    }

    pub fn open_in_memory(cache_key: &[u8; 32]) -> Result<Self, SyncError> {
        Self::init(Connection::open_in_memory()?, cache_key)
    }

    fn init(conn: Connection, cache_key: &[u8; 32]) -> Result<Self, SyncError> {
        let _mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
        conn.execute_batch(SCHEMA)?;
        let key = Zeroizing::new(blake3::derive_key("fleet sync store v1", cache_key));
        Ok(Self { conn, key })
    }

    fn aad(table: &str, collection: u8, key: &str) -> Vec<u8> {
        let mut a = table.as_bytes().to_vec();
        a.push(0);
        a.push(collection);
        a.extend_from_slice(key.as_bytes());
        a
    }

    fn seal(&self, aad: &[u8], v: &[u8]) -> Result<Vec<u8>, SyncError> {
        Ok(fleet_crypto::aead::seal(&self.key, aad, v)?)
    }

    fn open_blob(&self, aad: &[u8], v: &[u8]) -> Result<Zeroizing<Vec<u8>>, SyncError> {
        fleet_crypto::aead::open(&self.key, aad, v)
            .map(Zeroizing::new)
            .map_err(|_| SyncError::Cache(crate::cache::CacheError::Integrity("sync store")))
    }

    fn open_signed(&self, aad: &[u8], v: &[u8]) -> Result<SignedRecord, SyncError> {
        decode(&self.open_blob(aad, v)?).map_err(|_| SyncError::Malformed)
    }

    pub fn put(&self, row: &Row) -> Result<(), SyncError> {
        let r = &row.signed.record;
        let c = r.collection.tag();
        let sealed = self.seal(&Self::aad("records", c, &r.key), &encode(&row.signed))?;
        self.conn.execute(
            "INSERT INTO records (collection, key, sealed, dirty, synced) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(collection, key) DO UPDATE SET
               sealed = excluded.sealed, dirty = excluded.dirty, synced = excluded.synced",
            params![c, r.key, sealed, row.dirty, row.synced.map(|h| encode(&h))],
        )?;
        Ok(())
    }

    /// Drops a row (it no longer verifies against the roster chain).
    pub fn remove(&self, collection: Collection, key: &str) -> Result<(), SyncError> {
        self.conn.execute(
            "DELETE FROM records WHERE collection = ?1 AND key = ?2",
            params![collection.tag(), key],
        )?;
        Ok(())
    }

    pub fn get(&self, collection: Collection, key: &str) -> Result<Option<Row>, SyncError> {
        let c = collection.tag();
        let row: Option<(Vec<u8>, bool, Option<Vec<u8>>)> = self
            .conn
            .query_row(
                "SELECT sealed, dirty, synced FROM records WHERE collection = ?1 AND key = ?2",
                params![c, key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        row.map(|(sealed, dirty, synced)| self.row(c, key, &sealed, dirty, synced))
            .transpose()
    }

    fn row(
        &self,
        c: u8,
        key: &str,
        sealed: &[u8],
        dirty: bool,
        synced: Option<Vec<u8>>,
    ) -> Result<Row, SyncError> {
        let signed = self.open_signed(&Self::aad("records", c, key), sealed)?;
        let synced = synced
            .map(|b| decode(&b).map_err(|_| SyncError::Malformed))
            .transpose()?;
        Ok(Row {
            signed,
            dirty,
            synced,
        })
    }

    /// Every row of `collection`, or of all collections.
    pub fn rows(&self, collection: Option<Collection>) -> Result<Vec<Row>, SyncError> {
        let mut st = self.conn.prepare(
            "SELECT collection, key, sealed, dirty, synced FROM records
             WHERE ?1 IS NULL OR collection = ?1 ORDER BY collection, key",
        )?;
        type Raw = (u8, String, Vec<u8>, bool, Option<Vec<u8>>);
        let raw: Vec<Raw> = st
            .query_map(params![collection.map(Collection::tag)], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<Result<_, _>>()?;
        raw.into_iter()
            .map(|(c, k, s, d, y)| self.row(c, &k, &s, d, y))
            .collect()
    }

    pub fn put_conflict(&self, remote: &SignedRecord) -> Result<(), SyncError> {
        let r = &remote.record;
        let c = r.collection.tag();
        let sealed = self.seal(&Self::aad("conflicts", c, &r.key), &encode(remote))?;
        self.conn.execute(
            "INSERT OR REPLACE INTO conflicts (collection, key, sealed) VALUES (?1, ?2, ?3)",
            params![c, r.key, sealed],
        )?;
        Ok(())
    }

    pub fn take_conflict(
        &self,
        collection: Collection,
        key: &str,
    ) -> Result<Option<SignedRecord>, SyncError> {
        let c = collection.tag();
        let s: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT sealed FROM conflicts WHERE collection = ?1 AND key = ?2",
                params![c, key],
                |r| r.get(0),
            )
            .optional()?;
        let Some(s) = s else { return Ok(None) };
        let sr = self.open_signed(&Self::aad("conflicts", c, key), &s)?;
        self.conn.execute(
            "DELETE FROM conflicts WHERE collection = ?1 AND key = ?2",
            params![c, key],
        )?;
        Ok(Some(sr))
    }

    pub fn conflicts(&self) -> Result<Vec<SignedRecord>, SyncError> {
        let mut st = self
            .conn
            .prepare("SELECT collection, key, sealed FROM conflicts ORDER BY collection, key")?;
        let raw: Vec<(u8, String, Vec<u8>)> = st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<_, _>>()?;
        raw.into_iter()
            .map(|(c, k, s)| self.open_signed(&Self::aad("conflicts", c, &k), &s))
            .collect()
    }

    pub fn put_pin_change(&self, remote: &SignedRecord) -> Result<(), SyncError> {
        let k = &remote.record.key;
        let sealed = self.seal(&Self::aad("pin_changes", 0, k), &encode(remote))?;
        self.conn.execute(
            "INSERT OR REPLACE INTO pin_changes (key, sealed) VALUES (?1, ?2)",
            params![k, sealed],
        )?;
        Ok(())
    }

    pub fn take_pin_change(&self, key: &str) -> Result<Option<SignedRecord>, SyncError> {
        let s: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT sealed FROM pin_changes WHERE key = ?1",
                [key],
                |r| r.get(0),
            )
            .optional()?;
        let Some(s) = s else { return Ok(None) };
        let sr = self.open_signed(&Self::aad("pin_changes", 0, key), &s)?;
        self.conn
            .execute("DELETE FROM pin_changes WHERE key = ?1", [key])?;
        Ok(Some(sr))
    }

    pub fn pin_changes(&self) -> Result<Vec<SignedRecord>, SyncError> {
        let mut st = self
            .conn
            .prepare("SELECT key, sealed FROM pin_changes ORDER BY key")?;
        let raw: Vec<(String, Vec<u8>)> = st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        raw.into_iter()
            .map(|(k, s)| self.open_signed(&Self::aad("pin_changes", 0, &k), &s))
            .collect()
    }

    pub fn set_meta(&self, key: &str, value: &[u8]) -> Result<(), SyncError> {
        let sealed = self.seal(&Self::aad("meta", 0, key), value)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
            params![key, sealed],
        )?;
        Ok(())
    }

    pub fn meta(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SyncError> {
        let s: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()?;
        s.map(|s| self.open_blob(&Self::aad("meta", 0, key), &s))
            .transpose()
    }
}
