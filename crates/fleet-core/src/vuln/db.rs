//! The vulnerability table: its own SQLite file (`vulns.sqlite` next to
//! the cache), because it is bulk public data rebuilt daily and nothing
//! in it decides whom the Mac trusts (no MACs, no sync).
//!
//! ```text
//! advisories  distro, release, package, id, fixed (NULL: no fix), severity
//! aliases     distro, id, alias            (CVEs of a USN)
//! feeds       key, etag, last_modified, attempted_ms, fetched_ms,
//!             updated_ms, rows, last_error
//! ```
//!
//! A feed's rows are replaced in one transaction ([`VulnDb::replace_feed`]);
//! a failed parse rolls back and the previous data stays.

use super::feed::{FeedError, Source, Stats};
use super::{Advisory, Distro, Severity};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

const SCHEMA_VERSION: i64 = 1;

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS advisories (
        distro    TEXT NOT NULL,
        release   TEXT NOT NULL,
        package   TEXT NOT NULL,
        id        TEXT NOT NULL,
        fixed     TEXT,
        severity  INTEGER NOT NULL,
        PRIMARY KEY (distro, release, package, id)
    ) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS aliases (
        distro  TEXT NOT NULL,
        id      TEXT NOT NULL,
        alias   TEXT NOT NULL,
        PRIMARY KEY (distro, id, alias)
    ) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS feeds (
        key            TEXT PRIMARY KEY,
        etag           TEXT,
        last_modified  TEXT,
        attempted_ms   INTEGER,
        fetched_ms     INTEGER,
        updated_ms     INTEGER,
        rows           INTEGER NOT NULL DEFAULT 0,
        last_error     TEXT
    );";

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("vulnerability database v{0} is newer than this app")]
    TooNew(i64),
}

/// Bookkeeping for one feed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeedMeta {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    /// Last download attempt (success or not).
    pub attempted_ms: Option<u64>,
    /// Last successful check (new data or `304 Not Modified`).
    pub fetched_ms: Option<u64>,
    /// Last time new data was loaded.
    pub updated_ms: Option<u64>,
    pub rows: u64,
    pub last_error: Option<String>,
}

pub struct VulnDb {
    conn: Connection,
}

fn ms(v: Option<i64>) -> Option<u64> {
    v.and_then(|v| u64::try_from(v).ok())
}

fn sql_ms(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

impl VulnDb {
    pub fn open(path: &Path) -> Result<Self, DbError> {
        Self::init(Connection::open(path)?)
    }

    pub fn open_in_memory() -> Result<Self, DbError> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self, DbError> {
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        let v: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if v > SCHEMA_VERSION {
            return Err(DbError::TooNew(v));
        }
        conn.execute_batch(SCHEMA)?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        Ok(Self { conn })
    }

    /// Deletes `distro`'s rows and inserts what `fill` emits, atomically.
    /// Any error (from `fill` or SQLite) rolls back.
    pub fn replace_feed<F>(&mut self, distro: Distro, fill: F) -> Result<Stats, FeedError>
    where
        F: FnOnce(&mut dyn FnMut(Advisory) -> Result<(), String>) -> Result<Stats, FeedError>,
    {
        let tx = self.conn.transaction().map_err(DbError::from)?;
        let d = distro.as_str();
        tx.execute("DELETE FROM advisories WHERE distro = ?1", [d])
            .map_err(DbError::from)?;
        tx.execute("DELETE FROM aliases WHERE distro = ?1", [d])
            .map_err(DbError::from)?;
        let stats = {
            let mut adv = tx
                .prepare(
                    "INSERT OR REPLACE INTO advisories
                     (distro, release, package, id, fixed, severity)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .map_err(DbError::from)?;
            let mut alias = tx
                .prepare("INSERT OR IGNORE INTO aliases (distro, id, alias) VALUES (?1, ?2, ?3)")
                .map_err(DbError::from)?;
            let mut last_aliased = String::new();
            let mut sink = |a: Advisory| -> Result<(), String> {
                if a.distro != distro {
                    return Err("advisory for another distribution".into());
                }
                adv.execute(params![
                    d,
                    a.release,
                    a.package,
                    a.id,
                    a.fixed,
                    a.severity.as_i64()
                ])
                .map_err(|e| e.to_string())?;
                if !a.aliases.is_empty() && a.id != last_aliased {
                    for x in &a.aliases {
                        alias
                            .execute(params![d, a.id, x])
                            .map_err(|e| e.to_string())?;
                    }
                    last_aliased = a.id;
                }
                Ok(())
            };
            fill(&mut sink)?
        };
        tx.commit().map_err(DbError::from)?;
        Ok(stats)
    }

    /// Advisories for `package` in `distro`/`release`, with aliases.
    pub fn lookup(
        &self,
        distro: Distro,
        release: &str,
        package: &str,
    ) -> Result<Vec<Advisory>, DbError> {
        let mut st = self.conn.prepare_cached(
            "SELECT id, fixed, severity FROM advisories
             WHERE distro = ?1 AND release = ?2 AND package = ?3",
        )?;
        let rows = st
            .query_map(params![distro.as_str(), release, package], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut al = self.conn.prepare_cached(
            "SELECT alias FROM aliases WHERE distro = ?1 AND id = ?2 ORDER BY alias",
        )?;
        rows.into_iter()
            .map(|(id, fixed, sev)| {
                let aliases = al
                    .query_map(params![distro.as_str(), id], |r| r.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Advisory {
                    distro,
                    release: release.to_string(),
                    package: package.to_string(),
                    id,
                    aliases,
                    fixed,
                    severity: Severity::from_i64(sev),
                })
            })
            .collect()
    }

    /// Row count for `distro`.
    pub fn count(&self, distro: Distro) -> Result<u64, DbError> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM advisories WHERE distro = ?1",
            [distro.as_str()],
            |r| r.get(0),
        )?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    pub fn meta(&self, source: Source) -> Result<FeedMeta, DbError> {
        Ok(self
            .conn
            .query_row(
                "SELECT etag, last_modified, attempted_ms, fetched_ms, updated_ms, rows, last_error
                 FROM feeds WHERE key = ?1",
                [source.key()],
                |r| {
                    Ok(FeedMeta {
                        etag: r.get(0)?,
                        last_modified: r.get(1)?,
                        attempted_ms: ms(r.get(2)?),
                        fetched_ms: ms(r.get(3)?),
                        updated_ms: ms(r.get(4)?),
                        rows: u64::try_from(r.get::<_, i64>(5)?).unwrap_or(0),
                        last_error: r.get(6)?,
                    })
                },
            )
            .optional()?
            .unwrap_or_default())
    }

    pub fn set_meta(&self, source: Source, m: &FeedMeta) -> Result<(), DbError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO feeds
             (key, etag, last_modified, attempted_ms, fetched_ms, updated_ms, rows, last_error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                source.key(),
                m.etag,
                m.last_modified,
                m.attempted_ms.map(sql_ms),
                m.fetched_ms.map(sql_ms),
                m.updated_ms.map(sql_ms),
                sql_ms(m.rows),
                m.last_error,
            ],
        )?;
        Ok(())
    }
}
