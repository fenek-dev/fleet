//! Local cache (design §7.4): SQLite via `rusqlite`, WAL mode.
//!
//! The cache is a convenience copy. Pins are the exception that matters for
//! security: host keys and agent keys pinned here are what the transport
//! and session check against. Audit mirrors hold raw entry bytes plus their
//! hash so they can be re-verified against signed checkpoints later.
//!
//! Schema changes are append-only migrations recorded in
//! `schema_migrations`; a database from a newer app version is refused.

use crate::ssh::{HostKey, SshError, SshTarget};
use fleet_proto::{Ed25519Public, ServerId, X25519Public};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

/// `MIGRATIONS[i]` brings the schema to version `i + 1`.
const MIGRATIONS: &[&str] = &[
    // v1
    "CREATE TABLE groups (
        id    TEXT PRIMARY KEY,
        name  TEXT NOT NULL,
        sort  INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE servers (
        id          TEXT PRIMARY KEY,
        name        TEXT NOT NULL,
        host        TEXT NOT NULL,
        port        INTEGER NOT NULL,
        user        TEXT NOT NULL,
        proxy_jump  TEXT,
        group_id    TEXT REFERENCES groups(id) ON DELETE SET NULL
    );
    CREATE TABLE server_tags (
        server_id  TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
        tag        TEXT NOT NULL,
        PRIMARY KEY (server_id, tag)
    );
    CREATE TABLE pinned_keys (
        server_id      TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
        host_key       BLOB,
        agent_noise    BLOB,
        agent_signing  BLOB,
        updated_ms     INTEGER NOT NULL
    );
    CREATE TABLE jump_host_keys (
        host      TEXT NOT NULL,
        port      INTEGER NOT NULL,
        host_key  BLOB NOT NULL,
        PRIMARY KEY (host, port)
    );
    CREATE TABLE audit_entries (
        server_id   TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
        seq         INTEGER NOT NULL,
        entry       BLOB NOT NULL,
        entry_hash  BLOB NOT NULL,
        PRIMARY KEY (server_id, seq)
    ) WITHOUT ROWID;
    CREATE TABLE audit_checkpoints (
        server_id       TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
        seq             INTEGER NOT NULL,
        checkpoint      BLOB NOT NULL,
        verified_at_ms  INTEGER NOT NULL
    );
    CREATE TABLE metrics_1m (
        server_id  TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
        metric     TEXT NOT NULL,
        minute_ms  INTEGER NOT NULL,
        value      REAL NOT NULL,
        PRIMARY KEY (server_id, metric, minute_ms)
    ) WITHOUT ROWID;
    CREATE TABLE settings (
        key    TEXT PRIMARY KEY,
        value  BLOB NOT NULL
    );
    CREATE TABLE roster_chain (
        epoch    INTEGER NOT NULL,
        version  INTEGER NOT NULL,
        hash     BLOB NOT NULL,
        signed   BLOB NOT NULL,
        PRIMARY KEY (epoch, version)
    );",
];

/// Metrics older than this are pruned (design §7.4: 24 h at 1-minute resolution).
pub const METRICS_RETENTION_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("database schema v{found} is newer than this app (v{supported})")]
    TooNew { found: u32, supported: u32 },
    #[error("corrupt row: {0}")]
    Corrupt(String),
}

impl From<SshError> for CacheError {
    fn from(e: SshError) -> Self {
        CacheError::Corrupt(e.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRecord {
    pub id: String,
    pub name: String,
    pub sort: i64,
}

/// A managed server. `target.proxy_jump` hops get their pins from
/// `jump_host_keys`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerRecord {
    pub id: ServerId,
    pub name: String,
    pub target: SshTarget,
    pub group: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PinnedKeys {
    pub host_key: Option<HostKey>,
    pub agent_noise: Option<X25519Public>,
    pub agent_signing: Option<Ed25519Public>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRow {
    pub seq: u64,
    pub entry: Vec<u8>,
    pub entry_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointRow {
    pub seq: u64,
    pub checkpoint: Vec<u8>,
    pub verified_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterRow {
    pub epoch: u32,
    pub version: u64,
    pub hash: [u8; 32],
    pub signed: Vec<u8>,
}

pub struct Cache {
    conn: Connection,
}

fn arr32(v: Vec<u8>, what: &str) -> Result<[u8; 32], CacheError> {
    v.try_into()
        .map_err(|_| CacheError::Corrupt(format!("{what}: not 32 bytes")))
}

fn server_id(s: String) -> Result<ServerId, CacheError> {
    ServerId::new(s).map_err(|e| CacheError::Corrupt(format!("server id: {e:?}")))
}

/// `user@host:port` hops, first hop first (OpenSSH `-J` order).
fn jump_spec(t: &SshTarget) -> Option<String> {
    let mut hops = Vec::new();
    let mut cur = t.proxy_jump.as_deref();
    while let Some(j) = cur {
        hops.push(format!("{}@{}:{}", j.user, j.host, j.port));
        cur = j.proxy_jump.as_deref();
    }
    if hops.is_empty() {
        return None;
    }
    hops.reverse();
    Some(hops.join(","))
}

fn parse_hop(s: &str) -> Result<SshTarget, CacheError> {
    let bad = || CacheError::Corrupt(format!("proxy_jump hop {s:?}"));
    let (user, rest) = s.split_once('@').ok_or_else(bad)?;
    let (host, port) = rest.rsplit_once(':').ok_or_else(bad)?;
    let port = port.parse().map_err(|_| bad())?;
    Ok(SshTarget::new(host, port, user))
}

impl Cache {
    pub fn open(path: &Path) -> Result<Self, CacheError> {
        Self::init(Connection::open(path)?)
    }

    pub fn open_in_memory() -> Result<Self, CacheError> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self, CacheError> {
        // WAL: the UI reads while the core writes metrics. In-memory
        // databases stay in "memory" mode.
        let _mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS schema_migrations (
                 version        INTEGER PRIMARY KEY,
                 applied_at_ms  INTEGER NOT NULL
             );",
        )?;
        let mut cache = Self { conn };
        cache.migrate()?;
        Ok(cache)
    }

    pub fn schema_version(&self) -> Result<u32, CacheError> {
        Ok(self.conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |r| r.get(0),
        )?)
    }

    fn migrate(&mut self) -> Result<(), CacheError> {
        let current = self.schema_version()?;
        let supported = MIGRATIONS.len() as u32;
        if current > supported {
            return Err(CacheError::TooNew {
                found: current,
                supported,
            });
        }
        for (i, sql) in MIGRATIONS.iter().enumerate().skip(current as usize) {
            let tx = self.conn.transaction()?;
            tx.execute_batch(sql)?;
            tx.execute(
                "INSERT INTO schema_migrations (version, applied_at_ms) VALUES (?1, ?2)",
                params![i as u32 + 1, crate::now_ms() as i64],
            )?;
            tx.commit()?;
        }
        Ok(())
    }

    // ---- groups ----

    pub fn upsert_group(&self, g: &GroupRecord) -> Result<(), CacheError> {
        self.conn.execute(
            "INSERT INTO groups (id, name, sort) VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET name = excluded.name, sort = excluded.sort",
            params![g.id, g.name, g.sort],
        )?;
        Ok(())
    }

    pub fn delete_group(&self, id: &str) -> Result<(), CacheError> {
        self.conn
            .execute("DELETE FROM groups WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn groups(&self) -> Result<Vec<GroupRecord>, CacheError> {
        let mut st = self
            .conn
            .prepare("SELECT id, name, sort FROM groups ORDER BY sort, name")?;
        let rows = st.query_map([], |r| {
            Ok(GroupRecord {
                id: r.get(0)?,
                name: r.get(1)?,
                sort: r.get(2)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    // ---- servers ----

    /// Inserts or replaces a server with its tags; pins are kept.
    pub fn upsert_server(&mut self, s: &ServerRecord) -> Result<(), CacheError> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO servers (id, name, host, port, user, proxy_jump, group_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET name = excluded.name, host = excluded.host,
               port = excluded.port, user = excluded.user,
               proxy_jump = excluded.proxy_jump, group_id = excluded.group_id",
            params![
                s.id.as_str(),
                s.name,
                s.target.host,
                s.target.port,
                s.target.user,
                jump_spec(&s.target),
                s.group,
            ],
        )?;
        tx.execute(
            "DELETE FROM server_tags WHERE server_id = ?1",
            [s.id.as_str()],
        )?;
        for tag in &s.tags {
            tx.execute(
                "INSERT OR IGNORE INTO server_tags (server_id, tag) VALUES (?1, ?2)",
                params![s.id.as_str(), tag],
            )?;
        }
        // Jump host pins travel with the target.
        let mut cur = s.target.proxy_jump.as_deref();
        while let Some(j) = cur {
            if let Some(k) = &j.host_key {
                tx.execute(
                    "INSERT INTO jump_host_keys (host, port, host_key) VALUES (?1, ?2, ?3)
                     ON CONFLICT(host, port) DO UPDATE SET host_key = excluded.host_key",
                    params![j.host, j.port, k.blob()],
                )?;
            }
            cur = j.proxy_jump.as_deref();
        }
        tx.commit()?;
        Ok(())
    }

    pub fn delete_server(&self, id: &ServerId) -> Result<(), CacheError> {
        self.conn
            .execute("DELETE FROM servers WHERE id = ?1", [id.as_str()])?;
        Ok(())
    }

    fn jump_key(&self, host: &str, port: u16) -> Result<Option<HostKey>, CacheError> {
        let blob: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT host_key FROM jump_host_keys WHERE host = ?1 AND port = ?2",
                params![host, port],
                |r| r.get(0),
            )
            .optional()?;
        Ok(blob.map(|b| HostKey::from_blob(&b)).transpose()?)
    }

    fn build_target(
        &self,
        host: String,
        port: u16,
        user: String,
        jump: Option<String>,
    ) -> Result<SshTarget, CacheError> {
        let mut target = SshTarget::new(host, port, user);
        let mut chain: Option<SshTarget> = None;
        for hop in jump
            .as_deref()
            .unwrap_or("")
            .split(',')
            .filter(|h| !h.is_empty())
        {
            let mut t = parse_hop(hop)?;
            t.host_key = self.jump_key(&t.host, t.port)?;
            t.proxy_jump = chain.take().map(Box::new);
            chain = Some(t);
        }
        target.proxy_jump = chain.map(Box::new);
        Ok(target)
    }

    fn tags(&self, id: &str) -> Result<Vec<String>, CacheError> {
        let mut st = self
            .conn
            .prepare("SELECT tag FROM server_tags WHERE server_id = ?1 ORDER BY tag")?;
        let rows = st.query_map([id], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn server(&self, id: &ServerId) -> Result<Option<ServerRecord>, CacheError> {
        Ok(self.servers_where(Some(id))?.pop())
    }

    pub fn servers(&self) -> Result<Vec<ServerRecord>, CacheError> {
        self.servers_where(None)
    }

    fn servers_where(&self, id: Option<&ServerId>) -> Result<Vec<ServerRecord>, CacheError> {
        type Row = (
            String,
            String,
            String,
            u16,
            String,
            Option<String>,
            Option<String>,
        );
        let mut st = self.conn.prepare(
            "SELECT id, name, host, port, user, proxy_jump, group_id FROM servers
             WHERE ?1 IS NULL OR id = ?1 ORDER BY name, id",
        )?;
        let rows: Vec<Row> = st
            .query_map([id.map(|i| i.as_str())], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            })?
            .collect::<Result<_, _>>()?;
        rows.into_iter()
            .map(|(id, name, host, port, user, jump, group)| {
                Ok(ServerRecord {
                    tags: self.tags(&id)?,
                    target: self.build_target(host, port, user, jump)?,
                    id: server_id(id)?,
                    name,
                    group,
                })
            })
            .collect()
    }

    // ---- pins ----

    pub fn set_pins(&self, id: &ServerId, pins: &PinnedKeys) -> Result<(), CacheError> {
        self.conn.execute(
            "INSERT INTO pinned_keys (server_id, host_key, agent_noise, agent_signing, updated_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(server_id) DO UPDATE SET host_key = excluded.host_key,
               agent_noise = excluded.agent_noise, agent_signing = excluded.agent_signing,
               updated_ms = excluded.updated_ms",
            params![
                id.as_str(),
                pins.host_key.as_ref().map(|k| k.blob().to_vec()),
                pins.agent_noise.map(|k| k.0.to_vec()),
                pins.agent_signing.map(|k| k.0.to_vec()),
                crate::now_ms() as i64,
            ],
        )?;
        Ok(())
    }

    /// Replaces only the host key pin (first-use confirmation, or a key
    /// rotation reported over the Noise session, design §3.2).
    pub fn pin_host_key(&self, id: &ServerId, key: &HostKey) -> Result<(), CacheError> {
        let mut pins = self.pins(id)?.unwrap_or_default();
        pins.host_key = Some(key.clone());
        self.set_pins(id, &pins)
    }

    pub fn pins(&self, id: &ServerId) -> Result<Option<PinnedKeys>, CacheError> {
        type Row = (Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>);
        let row: Option<Row> = self
            .conn
            .query_row(
                "SELECT host_key, agent_noise, agent_signing FROM pinned_keys WHERE server_id = ?1",
                [id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((host, noise, signing)) = row else {
            return Ok(None);
        };
        Ok(Some(PinnedKeys {
            host_key: host.map(|b| HostKey::from_blob(&b)).transpose()?,
            agent_noise: noise
                .map(|b| arr32(b, "agent_noise").map(X25519Public))
                .transpose()?,
            agent_signing: signing
                .map(|b| arr32(b, "agent_signing").map(Ed25519Public))
                .transpose()?,
        }))
    }

    // ---- audit mirror ----

    /// Appends entries (idempotent per seq). Callers verify the chain first.
    pub fn append_audit(&mut self, id: &ServerId, rows: &[AuditRow]) -> Result<(), CacheError> {
        let tx = self.conn.transaction()?;
        {
            let mut st = tx.prepare(
                "INSERT OR IGNORE INTO audit_entries (server_id, seq, entry, entry_hash)
                 VALUES (?1, ?2, ?3, ?4)",
            )?;
            for r in rows {
                st.execute(params![
                    id.as_str(),
                    r.seq as i64,
                    r.entry,
                    r.entry_hash.to_vec()
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn last_audit_seq(&self, id: &ServerId) -> Result<Option<u64>, CacheError> {
        let v: Option<i64> = self.conn.query_row(
            "SELECT MAX(seq) FROM audit_entries WHERE server_id = ?1",
            [id.as_str()],
            |r| r.get(0),
        )?;
        Ok(v.map(|v| v as u64))
    }

    /// Entries with `seq >= from`, ascending, at most `limit`.
    pub fn audit_range(
        &self,
        id: &ServerId,
        from: u64,
        limit: u32,
    ) -> Result<Vec<AuditRow>, CacheError> {
        let mut st = self.conn.prepare(
            "SELECT seq, entry, entry_hash FROM audit_entries
             WHERE server_id = ?1 AND seq >= ?2 ORDER BY seq LIMIT ?3",
        )?;
        let rows: Vec<(i64, Vec<u8>, Vec<u8>)> = st
            .query_map(params![id.as_str(), from as i64, limit], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?
            .collect::<Result<_, _>>()?;
        rows.into_iter()
            .map(|(seq, entry, hash)| {
                Ok(AuditRow {
                    seq: seq as u64,
                    entry,
                    entry_hash: arr32(hash, "entry_hash")?,
                })
            })
            .collect()
    }

    pub fn set_checkpoint(&self, id: &ServerId, c: &CheckpointRow) -> Result<(), CacheError> {
        self.conn.execute(
            "INSERT INTO audit_checkpoints (server_id, seq, checkpoint, verified_at_ms)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(server_id) DO UPDATE SET seq = excluded.seq,
               checkpoint = excluded.checkpoint, verified_at_ms = excluded.verified_at_ms",
            params![
                id.as_str(),
                c.seq as i64,
                c.checkpoint,
                c.verified_at_ms as i64
            ],
        )?;
        Ok(())
    }

    pub fn checkpoint(&self, id: &ServerId) -> Result<Option<CheckpointRow>, CacheError> {
        Ok(self
            .conn
            .query_row(
                "SELECT seq, checkpoint, verified_at_ms FROM audit_checkpoints WHERE server_id = ?1",
                [id.as_str()],
                |r| {
                    Ok(CheckpointRow {
                        seq: r.get::<_, i64>(0)? as u64,
                        checkpoint: r.get(1)?,
                        verified_at_ms: r.get::<_, i64>(2)? as u64,
                    })
                },
            )
            .optional()?)
    }

    // ---- metrics (1-minute rollups) ----

    /// Stores one rollup; `at_ms` is truncated to its minute.
    pub fn put_metric(
        &self,
        id: &ServerId,
        metric: &str,
        at_ms: u64,
        value: f64,
    ) -> Result<(), CacheError> {
        let minute = at_ms - at_ms % 60_000;
        self.conn.execute(
            "INSERT INTO metrics_1m (server_id, metric, minute_ms, value) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(server_id, metric, minute_ms) DO UPDATE SET value = excluded.value",
            params![id.as_str(), metric, minute as i64, value],
        )?;
        Ok(())
    }

    /// `(minute_ms, value)` since `since_ms`, ascending.
    pub fn metrics(
        &self,
        id: &ServerId,
        metric: &str,
        since_ms: u64,
    ) -> Result<Vec<(u64, f64)>, CacheError> {
        let mut st = self.conn.prepare(
            "SELECT minute_ms, value FROM metrics_1m
             WHERE server_id = ?1 AND metric = ?2 AND minute_ms >= ?3 ORDER BY minute_ms",
        )?;
        let rows = st.query_map(params![id.as_str(), metric, since_ms as i64], |r| {
            Ok((r.get::<_, i64>(0)? as u64, r.get(1)?))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Drops rollups older than [`METRICS_RETENTION_MS`]; returns rows removed.
    pub fn prune_metrics(&self, now_ms: u64) -> Result<usize, CacheError> {
        let cutoff = now_ms.saturating_sub(METRICS_RETENTION_MS);
        Ok(self.conn.execute(
            "DELETE FROM metrics_1m WHERE minute_ms < ?1",
            [cutoff as i64],
        )?)
    }

    // ---- settings ----

    pub fn set_setting(&self, key: &str, value: &[u8]) -> Result<(), CacheError> {
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn setting(&self, key: &str) -> Result<Option<Vec<u8>>, CacheError> {
        Ok(self
            .conn
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    // ---- roster chain copies (a cache; servers are authoritative) ----

    pub fn put_roster(&self, r: &RosterRow) -> Result<(), CacheError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO roster_chain (epoch, version, hash, signed) VALUES (?1, ?2, ?3, ?4)",
            params![r.epoch, r.version as i64, r.hash.to_vec(), r.signed],
        )?;
        Ok(())
    }

    /// The whole chain, oldest first.
    pub fn roster_chain(&self) -> Result<Vec<RosterRow>, CacheError> {
        let mut st = self.conn.prepare(
            "SELECT epoch, version, hash, signed FROM roster_chain ORDER BY epoch, version",
        )?;
        let rows: Vec<(u32, i64, Vec<u8>, Vec<u8>)> = st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<Result<_, _>>()?;
        rows.into_iter()
            .map(|(epoch, version, hash, signed)| {
                Ok(RosterRow {
                    epoch,
                    version: version as u64,
                    hash: arr32(hash, "roster hash")?,
                    signed,
                })
            })
            .collect()
    }
}
