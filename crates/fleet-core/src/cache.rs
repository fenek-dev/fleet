//! Local cache (design §7.4): SQLite via `rusqlite`, WAL mode.
//!
//! The cache is a convenience copy. Pins are the exception that matters for
//! security: host keys and agent keys pinned here are what the transport
//! and session check against.
//!
//! **Integrity.** Rows that decide whom the Mac trusts carry a keyed
//! BLAKE3 MAC (`mac` column) over their contents, with a 32-byte
//! [`CacheKey`] that lives in the Keychain (this device only), not in the
//! database: server address rows (id, host, port, user, jump chain),
//! pinned host/agent keys, jump host pins, `settings` and `roster_chain`.
//! Every read of such a row checks the MAC; a mismatch or a missing MAC is
//! [`CacheError::Integrity`], which the app treats as a hard error (another
//! process wrote the file). Deleting a row can't be detected, but only
//! leads back to first-use confirmation. Databases from before the MACs
//! (schema v1) are sealed once on upgrade with the key they are opened
//! with (trust on upgrade).
//!
//! Jump host pins are keyed by the route to the hop (the `host:port` hops
//! before it), its host and port: the same address behind a different
//! bastion is a different machine.
//!
//! Schema changes are append-only migrations recorded in
//! `schema_migrations`; a database from a newer app version is refused.
//! The audit-mirror and metrics tables of v1 are not used yet (the offline
//! audit mirror comes later).

use crate::ssh::{HostKey, SshError, SshTarget};
use fleet_crypto::Zeroizing;
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
    // v2: integrity MACs; jump pins keyed by route. Old jump pins were
    // keyed by host and port only and can't be attributed to a route:
    // they are dropped (those hops go back to first-use confirmation).
    "ALTER TABLE servers ADD COLUMN mac BLOB;
    ALTER TABLE pinned_keys ADD COLUMN mac BLOB;
    ALTER TABLE settings ADD COLUMN mac BLOB;
    ALTER TABLE roster_chain ADD COLUMN mac BLOB;
    DROP TABLE jump_host_keys;
    CREATE TABLE jump_pins (
        route     TEXT NOT NULL,
        host      TEXT NOT NULL,
        port      INTEGER NOT NULL,
        host_key  BLOB NOT NULL,
        mac       BLOB NOT NULL,
        PRIMARY KEY (route, host, port)
    );",
];

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("database schema v{found} is newer than this app (v{supported})")]
    TooNew { found: u32, supported: u32 },
    #[error("corrupt row: {0}")]
    Corrupt(String),
    /// A security-sensitive row's MAC is missing or wrong: the file was
    /// changed outside the app (or the Keychain key was replaced).
    #[error("cache integrity check failed: {0}")]
    Integrity(&'static str),
}

impl From<SshError> for CacheError {
    fn from(e: SshError) -> Self {
        CacheError::Corrupt(e.to_string())
    }
}

/// The 32-byte integrity key (Keychain, this device only).
pub struct CacheKey(Zeroizing<[u8; 32]>);

impl CacheKey {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(Zeroizing::new(b))
    }

    pub fn generate() -> Result<Self, fleet_crypto::Error> {
        let mut b = Zeroizing::new([0u8; 32]);
        fleet_crypto::random_bytes(&mut *b)?;
        Ok(Self(b))
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRecord {
    pub id: String,
    pub name: String,
    pub sort: i64,
}

/// A managed server. `target.proxy_jump` hops get their pins from
/// `jump_pins`.
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
pub struct RosterRow {
    pub epoch: u32,
    pub version: u64,
    pub hash: [u8; 32],
    pub signed: Vec<u8>,
}

/// Read access to the audit mirror (timeline).
mod audit_mirror;

pub struct Cache {
    conn: Connection,
    key: CacheKey,
    upgraded: bool,
}

fn arr32(v: Vec<u8>, what: &str) -> Result<[u8; 32], CacheError> {
    v.try_into()
        .map_err(|_| CacheError::Corrupt(format!("{what}: not 32 bytes")))
}

fn server_id(s: String) -> Result<ServerId, CacheError> {
    ServerId::new(s).map_err(|e| CacheError::Corrupt(format!("server id: {e:?}")))
}

/// Jump hops, first hop first (OpenSSH `-J` order).
fn hops(t: &SshTarget) -> Vec<&SshTarget> {
    let mut v = Vec::new();
    let mut cur = t.proxy_jump.as_deref();
    while let Some(j) = cur {
        v.push(j);
        cur = j.proxy_jump.as_deref();
    }
    v.reverse();
    v
}

/// `user@host:port` hops, first hop first.
fn jump_spec(t: &SshTarget) -> Option<String> {
    let h = hops(t);
    (!h.is_empty()).then(|| {
        h.iter()
            .map(|j| format!("{}@{}:{}", j.user, j.host, j.port))
            .collect::<Vec<_>>()
            .join(",")
    })
}

/// Route key of a hop: the `host:port` of every hop before it.
fn route(before: &[&SshTarget]) -> String {
    before
        .iter()
        .map(|j| format!("{}:{}", j.host, j.port))
        .collect::<Vec<_>>()
        .join(",")
}

fn parse_hop(s: &str) -> Result<SshTarget, CacheError> {
    let bad = || CacheError::Corrupt(format!("proxy_jump hop {s:?}"));
    let (user, rest) = s.split_once('@').ok_or_else(bad)?;
    let (host, port) = rest.rsplit_once(':').ok_or_else(bad)?;
    let port = port.parse().map_err(|_| bad())?;
    Ok(SshTarget::new(host, port, user))
}

/// One MAC input field; `None` and `Some(empty)` differ.
enum F<'a> {
    B(&'a [u8]),
    Opt(Option<&'a [u8]>),
}

impl Cache {
    /// Opens (or creates) the cache, checking rows with `key`. A v1
    /// database is upgraded and sealed with `key` ([`Cache::upgraded`]).
    pub fn open(path: &Path, key: CacheKey) -> Result<Self, CacheError> {
        Self::init(Connection::open(path)?, key)
    }

    /// In-memory, with a random key (tests, tools).
    pub fn open_in_memory() -> Result<Self, CacheError> {
        let key = CacheKey::generate().map_err(|_| CacheError::Corrupt("rng".into()))?;
        Self::init(Connection::open_in_memory()?, key)
    }

    fn init(conn: Connection, key: CacheKey) -> Result<Self, CacheError> {
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
        let mut cache = Self {
            conn,
            key,
            upgraded: false,
        };
        cache.migrate()?;
        Ok(cache)
    }

    /// This open upgraded a database written before integrity MACs, and
    /// sealed its rows with the current key.
    pub fn upgraded(&self) -> bool {
        self.upgraded
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
        if current == 1 {
            self.seal_all()?;
            self.upgraded = true;
        }
        Ok(())
    }

    // ---- integrity ----

    fn mac(&self, table: &str, fields: &[F<'_>]) -> [u8; 32] {
        let mut h = blake3::Hasher::new_keyed(self.key.bytes());
        h.update(b"fleet-cache-mac-v1\0");
        h.update(&(table.len() as u64).to_le_bytes());
        h.update(table.as_bytes());
        for f in fields {
            let (tag, b): (u8, &[u8]) = match f {
                F::B(b) => (0, b),
                F::Opt(None) => (1, &[]),
                F::Opt(Some(b)) => (2, b),
            };
            h.update(&[tag]);
            h.update(&(b.len() as u64).to_le_bytes());
            h.update(b);
        }
        *h.finalize().as_bytes()
    }

    /// Checks a stored MAC over `fields`.
    fn check(
        &self,
        what: &'static str,
        table: &str,
        fields: &[F<'_>],
        stored: Option<Vec<u8>>,
    ) -> Result<(), CacheError> {
        self.check_mac(what, self.mac(table, fields), stored)
    }

    fn server_mac(
        &self,
        id: &str,
        host: &str,
        port: u16,
        user: &str,
        jump: Option<&str>,
    ) -> [u8; 32] {
        self.mac(
            "servers",
            &[
                F::B(id.as_bytes()),
                F::B(host.as_bytes()),
                F::B(&port.to_be_bytes()),
                F::B(user.as_bytes()),
                F::Opt(jump.map(str::as_bytes)),
            ],
        )
    }

    fn pins_mac(
        &self,
        id: &str,
        host: Option<&[u8]>,
        noise: Option<&[u8]>,
        signing: Option<&[u8]>,
    ) -> [u8; 32] {
        self.mac(
            "pinned_keys",
            &[
                F::B(id.as_bytes()),
                F::Opt(host),
                F::Opt(noise),
                F::Opt(signing),
            ],
        )
    }

    fn jump_mac(&self, route: &str, host: &str, port: u16, key: &[u8]) -> [u8; 32] {
        self.mac(
            "jump_pins",
            &[
                F::B(route.as_bytes()),
                F::B(host.as_bytes()),
                F::B(&port.to_be_bytes()),
                F::B(key),
            ],
        )
    }

    fn setting_mac(&self, key: &str, value: &[u8]) -> [u8; 32] {
        self.mac("settings", &[F::B(key.as_bytes()), F::B(value)])
    }

    fn roster_mac(&self, epoch: u32, version: u64, hash: &[u8], signed: &[u8]) -> [u8; 32] {
        self.mac(
            "roster_chain",
            &[
                F::B(&epoch.to_be_bytes()),
                F::B(&version.to_be_bytes()),
                F::B(hash),
                F::B(signed),
            ],
        )
    }

    /// Writes MACs for every row of a database upgraded from v1.
    fn seal_all(&mut self) -> Result<(), CacheError> {
        type SrvRow = (String, String, u16, String, Option<String>);
        let servers: Vec<SrvRow> = self
            .conn
            .prepare("SELECT id, host, port, user, proxy_jump FROM servers")?
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<Result<_, _>>()?;
        type PinRow = (String, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>);
        let pins: Vec<PinRow> = self
            .conn
            .prepare("SELECT server_id, host_key, agent_noise, agent_signing FROM pinned_keys")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<Result<_, _>>()?;
        let settings: Vec<(String, Vec<u8>)> = self
            .conn
            .prepare("SELECT key, value FROM settings")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        type RosRow = (u32, i64, Vec<u8>, Vec<u8>);
        let rosters: Vec<RosRow> = self
            .conn
            .prepare("SELECT epoch, version, hash, signed FROM roster_chain")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<Result<_, _>>()?;
        let macs_s: Vec<_> = servers
            .iter()
            .map(|(id, h, p, u, j)| (id, self.server_mac(id, h, *p, u, j.as_deref())))
            .collect();
        let macs_p: Vec<_> = pins
            .iter()
            .map(|(id, h, n, s)| {
                (
                    id,
                    self.pins_mac(id, h.as_deref(), n.as_deref(), s.as_deref()),
                )
            })
            .collect();
        let macs_k: Vec<_> = settings
            .iter()
            .map(|(k, v)| (k, self.setting_mac(k, v)))
            .collect();
        let macs_r: Vec<_> = rosters
            .iter()
            .map(|(e, v, h, s)| (e, v, self.roster_mac(*e, *v as u64, h, s)))
            .collect();
        let tx = self.conn.transaction()?;
        for (id, m) in macs_s {
            tx.execute(
                "UPDATE servers SET mac = ?2 WHERE id = ?1",
                params![id, m.to_vec()],
            )?;
        }
        for (id, m) in macs_p {
            tx.execute(
                "UPDATE pinned_keys SET mac = ?2 WHERE server_id = ?1",
                params![id, m.to_vec()],
            )?;
        }
        for (k, m) in macs_k {
            tx.execute(
                "UPDATE settings SET mac = ?2 WHERE key = ?1",
                params![k, m.to_vec()],
            )?;
        }
        for (e, v, m) in macs_r {
            tx.execute(
                "UPDATE roster_chain SET mac = ?3 WHERE epoch = ?1 AND version = ?2",
                params![e, v, m.to_vec()],
            )?;
        }
        tx.commit()?;
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

    /// Inserts or replaces a server with its tags; pins are kept. Jump
    /// hops that carry a `host_key` are pinned for their route.
    pub fn upsert_server(&mut self, s: &ServerRecord) -> Result<(), CacheError> {
        let jump = jump_spec(&s.target);
        let mac = self.server_mac(
            s.id.as_str(),
            &s.target.host,
            s.target.port,
            &s.target.user,
            jump.as_deref(),
        );
        let hop_list = hops(&s.target);
        let mut jump_rows = Vec::new();
        for (i, j) in hop_list.iter().enumerate() {
            if let Some(k) = &j.host_key {
                let r = route(&hop_list[..i]);
                let m = self.jump_mac(&r, &j.host, j.port, k.blob());
                jump_rows.push((r, j.host.clone(), j.port, k.blob().to_vec(), m));
            }
        }
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO servers (id, name, host, port, user, proxy_jump, group_id, mac)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET name = excluded.name, host = excluded.host,
               port = excluded.port, user = excluded.user,
               proxy_jump = excluded.proxy_jump, group_id = excluded.group_id,
               mac = excluded.mac",
            params![
                s.id.as_str(),
                s.name,
                s.target.host,
                s.target.port,
                s.target.user,
                jump,
                s.group,
                mac.to_vec(),
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
        for (r, host, port, key, m) in jump_rows {
            tx.execute(
                "INSERT INTO jump_pins (route, host, port, host_key, mac)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(route, host, port) DO UPDATE SET host_key = excluded.host_key,
                   mac = excluded.mac",
                params![r, host, port, key, m.to_vec()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn delete_server(&self, id: &ServerId) -> Result<(), CacheError> {
        self.conn
            .execute("DELETE FROM servers WHERE id = ?1", [id.as_str()])?;
        Ok(())
    }

    fn jump_key(&self, route: &str, host: &str, port: u16) -> Result<Option<HostKey>, CacheError> {
        let row: Option<(Vec<u8>, Option<Vec<u8>>)> = self
            .conn
            .query_row(
                "SELECT host_key, mac FROM jump_pins WHERE route = ?1 AND host = ?2 AND port = ?3",
                params![route, host, port],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((blob, mac)) = row else {
            return Ok(None);
        };
        self.check(
            "jump host pin",
            "jump_pins",
            &[
                F::B(route.as_bytes()),
                F::B(host.as_bytes()),
                F::B(&port.to_be_bytes()),
                F::B(&blob),
            ],
            mac,
        )?;
        Ok(Some(HostKey::from_blob(&blob)?))
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
        let mut before: Vec<String> = Vec::new();
        for hop in jump
            .as_deref()
            .unwrap_or("")
            .split(',')
            .filter(|h| !h.is_empty())
        {
            let mut t = parse_hop(hop)?;
            t.host_key = self.jump_key(&before.join(","), &t.host, t.port)?;
            before.push(format!("{}:{}", t.host, t.port));
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
            Option<Vec<u8>>,
        );
        let mut st = self.conn.prepare(
            "SELECT id, name, host, port, user, proxy_jump, group_id, mac FROM servers
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
                    r.get(7)?,
                ))
            })?
            .collect::<Result<_, _>>()?;
        rows.into_iter()
            .map(|(id, name, host, port, user, jump, group, mac)| {
                let want = self.server_mac(&id, &host, port, &user, jump.as_deref());
                self.check_mac("server address", want, mac)?;
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

    /// Constant-time comparison of a stored MAC with the expected one; a
    /// missing MAC fails too.
    fn check_mac(
        &self,
        what: &'static str,
        want: [u8; 32],
        stored: Option<Vec<u8>>,
    ) -> Result<(), CacheError> {
        let stored = stored
            .and_then(|s| <[u8; 32]>::try_from(s.as_slice()).ok())
            .ok_or(CacheError::Integrity(what))?;
        // `blake3::Hash` equality is constant-time.
        if blake3::Hash::from_bytes(stored) == blake3::Hash::from_bytes(want) {
            Ok(())
        } else {
            Err(CacheError::Integrity(what))
        }
    }

    // ---- pins ----

    pub fn set_pins(&self, id: &ServerId, pins: &PinnedKeys) -> Result<(), CacheError> {
        let host = pins.host_key.as_ref().map(|k| k.blob().to_vec());
        let noise = pins.agent_noise.map(|k| k.0.to_vec());
        let signing = pins.agent_signing.map(|k| k.0.to_vec());
        let mac = self.pins_mac(
            id.as_str(),
            host.as_deref(),
            noise.as_deref(),
            signing.as_deref(),
        );
        self.conn.execute(
            "INSERT INTO pinned_keys (server_id, host_key, agent_noise, agent_signing, updated_ms, mac)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(server_id) DO UPDATE SET host_key = excluded.host_key,
               agent_noise = excluded.agent_noise, agent_signing = excluded.agent_signing,
               updated_ms = excluded.updated_ms, mac = excluded.mac",
            params![
                id.as_str(),
                host,
                noise,
                signing,
                crate::now_ms() as i64,
                mac.to_vec(),
            ],
        )?;
        Ok(())
    }

    /// Replaces only the host key pin (first-use confirmation, or an
    /// operator-confirmed key change).
    pub fn pin_host_key(&self, id: &ServerId, key: &HostKey) -> Result<(), CacheError> {
        let mut pins = self.pins(id)?.unwrap_or_default();
        pins.host_key = Some(key.clone());
        self.set_pins(id, &pins)
    }

    pub fn pins(&self, id: &ServerId) -> Result<Option<PinnedKeys>, CacheError> {
        type Row = (
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
        );
        let row: Option<Row> = self
            .conn
            .query_row(
                "SELECT host_key, agent_noise, agent_signing, mac FROM pinned_keys
                 WHERE server_id = ?1",
                [id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((host, noise, signing, mac)) = row else {
            return Ok(None);
        };
        let want = self.pins_mac(
            id.as_str(),
            host.as_deref(),
            noise.as_deref(),
            signing.as_deref(),
        );
        self.check_mac("pinned keys", want, mac)?;
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

    // ---- settings ----

    pub fn set_setting(&self, key: &str, value: &[u8]) -> Result<(), CacheError> {
        let mac = self.setting_mac(key, value);
        self.conn.execute(
            "INSERT INTO settings (key, value, mac) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, mac = excluded.mac",
            params![key, value, mac.to_vec()],
        )?;
        Ok(())
    }

    pub fn setting(&self, key: &str) -> Result<Option<Vec<u8>>, CacheError> {
        let row: Option<(Vec<u8>, Option<Vec<u8>>)> = self
            .conn
            .query_row(
                "SELECT value, mac FROM settings WHERE key = ?1",
                [key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((value, mac)) = row else {
            return Ok(None);
        };
        self.check(
            "setting",
            "settings",
            &[F::B(key.as_bytes()), F::B(&value)],
            mac,
        )?;
        Ok(Some(value))
    }

    // ---- roster chain copies (a cache; servers are authoritative) ----

    pub fn put_roster(&self, r: &RosterRow) -> Result<(), CacheError> {
        let mac = self.roster_mac(r.epoch, r.version, &r.hash, &r.signed);
        self.conn.execute(
            "INSERT OR IGNORE INTO roster_chain (epoch, version, hash, signed, mac)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                r.epoch,
                r.version as i64,
                r.hash.to_vec(),
                r.signed,
                mac.to_vec()
            ],
        )?;
        Ok(())
    }

    /// The whole chain, oldest first.
    pub fn roster_chain(&self) -> Result<Vec<RosterRow>, CacheError> {
        let mut st = self.conn.prepare(
            "SELECT epoch, version, hash, signed, mac FROM roster_chain ORDER BY epoch, version",
        )?;
        type Row = (u32, i64, Vec<u8>, Vec<u8>, Option<Vec<u8>>);
        let rows: Vec<Row> = st
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<Result<_, _>>()?;
        rows.into_iter()
            .map(|(epoch, version, hash, signed, mac)| {
                let want = self.roster_mac(epoch, version as u64, &hash, &signed);
                self.check_mac("roster chain", want, mac)?;
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
