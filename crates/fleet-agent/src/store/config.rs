//! Config history tables (design §4.4, §4.9) behind
//! `fleet_ops::confighist::ConfigStore`.
//!
//! | Table | Key | Value |
//! |---|---|---|
//! | `config_log` | (path, version) | `postcard(VersionRecord)` |
//! | `config_blobs` | BLAKE3 hash | DEFLATE-compressed content |
//! | `config_blob_refs` | BLAKE3 hash | versions referencing the blob |
//! | `config_time` | (time ms, path, version) | `()` (timeline index) |
//! | `config_files` | path | `postcard(FileState)` (last observed) |
//! | `config_meta` | `"paths"` / `"blob_bytes"` | operator paths / total blob bytes (u64 LE) |
//!
//! Every mutation is one write transaction, so a version, its blob
//! reference, its timeline row and the file state appear together.

use super::StoreError;
use fleet_ops::confighist::{
    ConfigStore, FileState, OperatorPaths, StoreResult, TimelineVisitor, VersionRecord,
};
use fleet_proto::Hash32;
use redb::{ReadableDatabase, ReadableTable, Table, TableDefinition, WriteTransaction};

const LOG: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("config_log");
const BLOBS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("config_blobs");
const REFS: TableDefinition<&[u8], u32> = TableDefinition::new("config_blob_refs");
const TIME: TableDefinition<(u64, &str, u64), ()> = TableDefinition::new("config_time");
const FILES: TableDefinition<&str, &[u8]> = TableDefinition::new("config_files");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("config_meta");

const PATHS_KEY: &str = "paths";
const BYTES_KEY: &str = "blob_bytes";

pub(super) fn create_tables(tx: &WriteTransaction) -> super::Result<()> {
    tx.open_table(LOG)?;
    tx.open_table(BLOBS)?;
    tx.open_table(REFS)?;
    tx.open_table(TIME)?;
    tx.open_table(FILES)?;
    tx.open_table(META)?;
    Ok(())
}

fn err(e: impl Into<StoreError>) -> String {
    e.into().to_string()
}

fn corrupt(table: &'static str) -> String {
    StoreError::Corrupt(table).to_string()
}

fn decode<T: serde::de::DeserializeOwned>(b: &[u8], table: &'static str) -> StoreResult<T> {
    fleet_proto::decode(b).map_err(|_| corrupt(table))
}

/// Config history over exec's database (shared handle, like `MetricsDb`).
pub struct ConfigDb {
    db: super::Db,
}

impl ConfigDb {
    pub(super) fn new(db: super::Db) -> Self {
        Self { db }
    }

    fn write<T>(&self, f: impl FnOnce(&WriteTransaction) -> StoreResult<T>) -> StoreResult<T> {
        let tx = super::read(&self.db).begin_write().map_err(err)?;
        let out = f(&tx)?;
        tx.commit().map_err(err)?;
        Ok(out)
    }
}

fn add_bytes(meta: &mut Table<'_, &'static str, &'static [u8]>, delta: i64) -> StoreResult<()> {
    let cur = meta
        .get(BYTES_KEY)
        .map_err(err)?
        .and_then(|v| <[u8; 8]>::try_from(v.value()).ok())
        .map_or(0, u64::from_le_bytes);
    let new = if delta >= 0 {
        cur.saturating_add(delta.unsigned_abs())
    } else {
        cur.saturating_sub(delta.unsigned_abs())
    };
    meta.insert(BYTES_KEY, new.to_le_bytes().as_slice())
        .map_err(err)?;
    Ok(())
}

/// Drops one reference to `hash`, deleting the blob at zero.
fn unref(tx: &WriteTransaction, hash: &Hash32) -> StoreResult<()> {
    let mut refs = tx.open_table(REFS).map_err(err)?;
    let n = refs
        .get(hash.as_slice())
        .map_err(err)?
        .map_or(0, |v| v.value());
    if n > 1 {
        refs.insert(hash.as_slice(), n - 1).map_err(err)?;
        return Ok(());
    }
    refs.remove(hash.as_slice()).map_err(err)?;
    let mut blobs = tx.open_table(BLOBS).map_err(err)?;
    let len = blobs
        .remove(hash.as_slice())
        .map_err(err)?
        .map_or(0, |v| v.value().len());
    let mut meta = tx.open_table(META).map_err(err)?;
    add_bytes(&mut meta, -i64::try_from(len).unwrap_or(i64::MAX))
}

impl ConfigStore for ConfigDb {
    fn file(&self, path: &str) -> StoreResult<Option<FileState>> {
        let tx = super::read(&self.db).begin_read().map_err(err)?;
        let t = tx.open_table(FILES).map_err(err)?;
        t.get(path)
            .map_err(err)?
            .map(|v| decode(v.value(), "config_files"))
            .transpose()
    }

    fn files(&self) -> StoreResult<Vec<(String, FileState)>> {
        let tx = super::read(&self.db).begin_read().map_err(err)?;
        let t = tx.open_table(FILES).map_err(err)?;
        let mut out = Vec::new();
        for row in t.iter().map_err(err)? {
            let (k, v) = row.map_err(err)?;
            out.push((k.value().to_owned(), decode(v.value(), "config_files")?));
        }
        Ok(out)
    }

    fn put_file(&self, path: &str, state: &FileState) -> StoreResult<()> {
        self.write(|tx| {
            let mut t = tx.open_table(FILES).map_err(err)?;
            t.insert(path, fleet_proto::encode(state).as_slice())
                .map_err(err)?;
            Ok(())
        })
    }

    fn append(
        &self,
        path: &str,
        version: u64,
        rec: &VersionRecord,
        blob: Option<&[u8]>,
        state: &FileState,
    ) -> StoreResult<()> {
        self.write(|tx| {
            if rec.has_content() {
                let data = blob.ok_or("content record without blob")?;
                let key = rec.hash.as_slice();
                let mut refs = tx.open_table(REFS).map_err(err)?;
                let n = refs.get(key).map_err(err)?.map_or(0, |v| v.value());
                refs.insert(key, n.saturating_add(1)).map_err(err)?;
                if n == 0 {
                    let mut blobs = tx.open_table(BLOBS).map_err(err)?;
                    blobs.insert(key, data).map_err(err)?;
                    let mut meta = tx.open_table(META).map_err(err)?;
                    add_bytes(&mut meta, i64::try_from(data.len()).unwrap_or(i64::MAX))?;
                }
            }
            tx.open_table(LOG)
                .map_err(err)?
                .insert((path, version), fleet_proto::encode(rec).as_slice())
                .map_err(err)?;
            tx.open_table(TIME)
                .map_err(err)?
                .insert((rec.time_ms, path, version), ())
                .map_err(err)?;
            tx.open_table(FILES)
                .map_err(err)?
                .insert(path, fleet_proto::encode(state).as_slice())
                .map_err(err)?;
            Ok(())
        })
    }

    fn record(&self, path: &str, version: u64) -> StoreResult<Option<VersionRecord>> {
        let tx = super::read(&self.db).begin_read().map_err(err)?;
        let t = tx.open_table(LOG).map_err(err)?;
        t.get((path, version))
            .map_err(err)?
            .map(|v| decode(v.value(), "config_log"))
            .transpose()
    }

    fn versions(&self, path: &str) -> StoreResult<Vec<(u64, VersionRecord)>> {
        let tx = super::read(&self.db).begin_read().map_err(err)?;
        let t = tx.open_table(LOG).map_err(err)?;
        let mut out = Vec::new();
        for row in t.range((path, 0u64)..=(path, u64::MAX)).map_err(err)? {
            let (k, v) = row.map_err(err)?;
            out.push((k.value().1, decode(v.value(), "config_log")?));
        }
        Ok(out)
    }

    fn timeline(
        &self,
        since_ms: u64,
        until_ms: u64,
        newest_first: bool,
        f: &mut TimelineVisitor<'_>,
    ) -> StoreResult<()> {
        if since_ms >= until_ms {
            return Ok(());
        }
        let tx = super::read(&self.db).begin_read().map_err(err)?;
        let t = tx.open_table(TIME).map_err(err)?;
        // `("", 0)` sorts first, so the bounds are whole milliseconds.
        let mut range = t
            .range((since_ms, "", 0u64)..(until_ms, "", 0u64))
            .map_err(err)?;
        loop {
            let row = if newest_first {
                range.next_back()
            } else {
                range.next()
            };
            let Some(row) = row else { break };
            let (k, _) = row.map_err(err)?;
            let (time, path, version) = k.value();
            if !f(time, path, version) {
                break;
            }
        }
        Ok(())
    }

    fn blob(&self, hash: &Hash32) -> StoreResult<Option<Vec<u8>>> {
        let tx = super::read(&self.db).begin_read().map_err(err)?;
        let t = tx.open_table(BLOBS).map_err(err)?;
        Ok(t.get(hash.as_slice())
            .map_err(err)?
            .map(|v| v.value().to_vec()))
    }

    fn remove(&self, victims: &[(String, u64)]) -> StoreResult<()> {
        if victims.is_empty() {
            return Ok(());
        }
        self.write(|tx| {
            for (path, version) in victims {
                let rec: Option<VersionRecord> = {
                    let mut log = tx.open_table(LOG).map_err(err)?;
                    let removed = log.remove((path.as_str(), *version)).map_err(err)?;
                    removed
                        .map(|v| decode(v.value(), "config_log"))
                        .transpose()?
                };
                let Some(rec) = rec else { continue };
                tx.open_table(TIME)
                    .map_err(err)?
                    .remove((rec.time_ms, path.as_str(), *version))
                    .map_err(err)?;
                if rec.has_content() {
                    unref(tx, &rec.hash)?;
                }
            }
            Ok(())
        })
    }

    fn strip_content(&self, path: &str) -> StoreResult<()> {
        let versions = self.versions(path)?;
        if !versions.iter().any(|(_, r)| r.has_content()) {
            return Ok(());
        }
        self.write(|tx| {
            for (v, mut rec) in versions {
                if !rec.has_content() {
                    continue;
                }
                let hash = rec.hash;
                rec.stored = 0;
                rec.secret = true;
                tx.open_table(LOG)
                    .map_err(err)?
                    .insert((path, v), fleet_proto::encode(&rec).as_slice())
                    .map_err(err)?;
                unref(tx, &hash)?;
            }
            Ok(())
        })
    }

    fn blob_bytes(&self) -> StoreResult<u64> {
        let tx = super::read(&self.db).begin_read().map_err(err)?;
        let t = tx.open_table(META).map_err(err)?;
        Ok(t.get(BYTES_KEY)
            .map_err(err)?
            .and_then(|v| <[u8; 8]>::try_from(v.value()).ok())
            .map_or(0, u64::from_le_bytes))
    }

    fn load_paths(&self) -> StoreResult<Option<OperatorPaths>> {
        let tx = super::read(&self.db).begin_read().map_err(err)?;
        let t = tx.open_table(META).map_err(err)?;
        t.get(PATHS_KEY)
            .map_err(err)?
            .map(|v| decode(v.value(), "config_meta"))
            .transpose()
    }

    fn save_paths(&self, p: &OperatorPaths) -> StoreResult<()> {
        self.write(|tx| {
            tx.open_table(META)
                .map_err(err)?
                .insert(PATHS_KEY, fleet_proto::encode(p).as_slice())
                .map_err(err)?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::Store;
    use super::*;
    use fleet_proto::payload::ChangeSource;

    fn rec(t: u64, content: &[u8], stored: bool) -> VersionRecord {
        VersionRecord {
            time_ms: t,
            hash: *blake3::hash(content).as_bytes(),
            size: content.len() as u64,
            mode: 0o644,
            uid: 0,
            gid: 0,
            source: ChangeSource::Unknown,
            secret: !stored,
            deleted: false,
            stored: if stored { 3 } else { 0 },
        }
    }

    fn state(v: u64) -> FileState {
        FileState {
            version: v,
            size: 1,
            mtime_ns: 5,
            ino: 9,
            mode: 0o644,
            uid: 0,
            gid: 0,
            hash: [1; 32],
            deleted: false,
        }
    }

    #[test]
    fn roundtrip_refcounts_and_timeline() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path().join("state.redb")).unwrap();
        let db = s.config();
        let a = rec(10, b"aaa", true);
        let b = rec(20, b"bbb", true);
        let a2 = rec(30, b"aaa", true);
        db.append("/etc/x", 1, &a, Some(b"zzA"), &state(1)).unwrap();
        db.append("/etc/x", 2, &b, Some(b"zzB"), &state(2)).unwrap();
        db.append("/etc/x", 3, &a2, Some(b"zzA"), &state(3))
            .unwrap();
        db.append("/etc/y", 1, &rec(15, b"s", false), None, &state(1))
            .unwrap();
        assert_eq!(db.file("/etc/x").unwrap(), Some(state(3)));
        assert_eq!(db.files().unwrap().len(), 2);
        assert_eq!(db.record("/etc/x", 2).unwrap(), Some(b.clone()));
        let vs: Vec<u64> = db.versions("/etc/x").unwrap().iter().map(|v| v.0).collect();
        assert_eq!(vs, [1, 2, 3]);
        // Shared blob stored once.
        assert_eq!(db.blob_bytes().unwrap(), 6);
        let mut rows = Vec::new();
        db.timeline(0, u64::MAX, true, &mut |t, p, v| {
            rows.push((t, p.to_owned(), v));
            true
        })
        .unwrap();
        assert_eq!(
            rows,
            [
                (30, "/etc/x".into(), 3),
                (20, "/etc/x".into(), 2),
                (15, "/etc/y".into(), 1),
                (10, "/etc/x".into(), 1)
            ]
        );
        let mut n = 0;
        db.timeline(15, 30, false, &mut |_, _, _| {
            n += 1;
            true
        })
        .unwrap();
        assert_eq!(n, 2);
        // Removing one of two references keeps the blob.
        db.remove(&[("/etc/x".into(), 1)]).unwrap();
        assert_eq!(db.blob(&a.hash).unwrap().as_deref(), Some(&b"zzA"[..]));
        db.remove(&[("/etc/x".into(), 3), ("/etc/x".into(), 9)])
            .unwrap();
        assert!(db.blob(&a.hash).unwrap().is_none());
        assert_eq!(db.blob_bytes().unwrap(), 3);
        // Stripping content drops the last blob.
        db.strip_content("/etc/x").unwrap();
        assert!(db.blob(&b.hash).unwrap().is_none());
        let r = db.record("/etc/x", 2).unwrap().unwrap();
        assert!(r.secret && !r.has_content());
        assert_eq!(db.blob_bytes().unwrap(), 0);
        // Operator paths.
        assert_eq!(db.load_paths().unwrap(), None);
        let p = OperatorPaths {
            tracked: vec!["/opt/a".into()],
            secret: vec![],
            version: 4,
        };
        db.save_paths(&p).unwrap();
        drop(db);
        drop(s);
        let s = Store::open(dir.path().join("state.redb")).unwrap();
        assert_eq!(s.config().load_paths().unwrap(), Some(p));
    }
}
