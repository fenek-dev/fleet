//! What config history persists, behind [`ConfigStore`] (exec's redb
//! tables in production, [`MemStore`] in tests).

use fleet_proto::Hash32;
use fleet_proto::payload::ChangeSource;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

pub type StoreResult<T> = Result<T, String>;

/// One version of one tracked file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionRecord {
    pub time_ms: u64,
    /// BLAKE3 of the content (all zero for a deletion).
    pub hash: Hash32,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub source: ChangeSource,
    pub secret: bool,
    pub deleted: bool,
    /// Compressed bytes kept in the blob table under `hash`; 0 when no
    /// content is kept (secret, too large, deleted).
    pub stored: u32,
}

impl VersionRecord {
    pub fn has_content(&self) -> bool {
        self.stored > 0
    }
}

/// The last observed state of a tracked path (scan fast path and the base
/// for the next version).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileState {
    /// Latest version number (1-based).
    pub version: u64,
    pub size: u64,
    pub mtime_ns: i64,
    pub ino: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub hash: Hash32,
    pub deleted: bool,
}

/// Operator additions (`config.paths.set`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorPaths {
    pub tracked: Vec<String>,
    pub secret: Vec<String>,
    pub version: u64,
}

/// Visitor over `(time_ms, path, version)` rows; `false` stops.
pub type TimelineVisitor<'a> = dyn FnMut(u64, &str, u64) -> bool + 'a;

pub trait ConfigStore {
    fn file(&self, path: &str) -> StoreResult<Option<FileState>>;
    fn files(&self) -> StoreResult<Vec<(String, FileState)>>;
    /// Metadata refresh without a new version.
    fn put_file(&self, path: &str, state: &FileState) -> StoreResult<()>;
    /// Appends `rec` as `version` of `path` and sets its state, in one
    /// transaction. `blob` (compressed content) is stored under `rec.hash`
    /// unless already present; each version holding content counts one
    /// reference on its blob.
    fn append(
        &self,
        path: &str,
        version: u64,
        rec: &VersionRecord,
        blob: Option<&[u8]>,
        state: &FileState,
    ) -> StoreResult<()>;
    fn record(&self, path: &str, version: u64) -> StoreResult<Option<VersionRecord>>;
    /// Every kept version of `path`, oldest first.
    fn versions(&self, path: &str) -> StoreResult<Vec<(u64, VersionRecord)>>;
    /// Rows with `since <= time < until`, in time order (reversed when
    /// `newest_first`).
    fn timeline(
        &self,
        since_ms: u64,
        until_ms: u64,
        newest_first: bool,
        f: &mut TimelineVisitor<'_>,
    ) -> StoreResult<()>;
    /// Compressed content.
    fn blob(&self, hash: &Hash32) -> StoreResult<Option<Vec<u8>>>;
    /// Drops versions (and blobs no version references any more).
    fn remove(&self, victims: &[(String, u64)]) -> StoreResult<()>;
    /// Forgets the kept content of every version of `path` (it became a
    /// secret); the records stay, hash only.
    fn strip_content(&self, path: &str) -> StoreResult<()>;
    /// Compressed bytes of all blobs.
    fn blob_bytes(&self) -> StoreResult<u64>;
    fn load_paths(&self) -> StoreResult<Option<OperatorPaths>>;
    fn save_paths(&self, p: &OperatorPaths) -> StoreResult<()>;
}

#[derive(Default)]
struct Mem {
    files: BTreeMap<String, FileState>,
    log: BTreeMap<(String, u64), VersionRecord>,
    time: BTreeSet<(u64, String, u64)>,
    blobs: BTreeMap<Hash32, (u32, Vec<u8>)>,
    paths: Option<OperatorPaths>,
}

impl Mem {
    fn unref(&mut self, hash: &Hash32) {
        if let Some((refs, _)) = self.blobs.get_mut(hash) {
            *refs = refs.saturating_sub(1);
            if *refs == 0 {
                self.blobs.remove(hash);
            }
        }
    }
}

/// In-memory store (tests; exec uses redb).
#[derive(Default)]
pub struct MemStore(RefCell<Mem>);

impl ConfigStore for MemStore {
    fn file(&self, path: &str) -> StoreResult<Option<FileState>> {
        Ok(self.0.borrow().files.get(path).copied())
    }

    fn files(&self) -> StoreResult<Vec<(String, FileState)>> {
        Ok(self
            .0
            .borrow()
            .files
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect())
    }

    fn put_file(&self, path: &str, state: &FileState) -> StoreResult<()> {
        self.0.borrow_mut().files.insert(path.to_owned(), *state);
        Ok(())
    }

    fn append(
        &self,
        path: &str,
        version: u64,
        rec: &VersionRecord,
        blob: Option<&[u8]>,
        state: &FileState,
    ) -> StoreResult<()> {
        let mut m = self.0.borrow_mut();
        if rec.has_content() {
            let data = blob.ok_or("content record without blob")?;
            m.blobs
                .entry(rec.hash)
                .and_modify(|(r, _)| *r += 1)
                .or_insert_with(|| (1, data.to_vec()));
        }
        m.log.insert((path.to_owned(), version), rec.clone());
        m.time.insert((rec.time_ms, path.to_owned(), version));
        m.files.insert(path.to_owned(), *state);
        Ok(())
    }

    fn record(&self, path: &str, version: u64) -> StoreResult<Option<VersionRecord>> {
        Ok(self
            .0
            .borrow()
            .log
            .get(&(path.to_owned(), version))
            .cloned())
    }

    fn versions(&self, path: &str) -> StoreResult<Vec<(u64, VersionRecord)>> {
        let m = self.0.borrow();
        Ok(m.log
            .range((path.to_owned(), 0)..=(path.to_owned(), u64::MAX))
            .map(|((_, v), r)| (*v, r.clone()))
            .collect())
    }

    fn timeline(
        &self,
        since_ms: u64,
        until_ms: u64,
        newest_first: bool,
        f: &mut TimelineVisitor<'_>,
    ) -> StoreResult<()> {
        let m = self.0.borrow();
        let rows = m
            .time
            .iter()
            .filter(|(t, _, _)| *t >= since_ms && *t < until_ms);
        let rows: Vec<_> = if newest_first {
            rows.rev().collect()
        } else {
            rows.collect()
        };
        for (t, p, v) in rows {
            if !f(*t, p, *v) {
                break;
            }
        }
        Ok(())
    }

    fn blob(&self, hash: &Hash32) -> StoreResult<Option<Vec<u8>>> {
        Ok(self.0.borrow().blobs.get(hash).map(|(_, b)| b.clone()))
    }

    fn remove(&self, victims: &[(String, u64)]) -> StoreResult<()> {
        let mut m = self.0.borrow_mut();
        for (p, v) in victims {
            if let Some(rec) = m.log.remove(&(p.clone(), *v)) {
                m.time.remove(&(rec.time_ms, p.clone(), *v));
                if rec.has_content() {
                    m.unref(&rec.hash);
                }
            }
        }
        Ok(())
    }

    fn strip_content(&self, path: &str) -> StoreResult<()> {
        let mut m = self.0.borrow_mut();
        let keys: Vec<(String, u64)> = m
            .log
            .range((path.to_owned(), 0)..=(path.to_owned(), u64::MAX))
            .map(|(k, _)| k.clone())
            .collect();
        for k in keys {
            let hash = match m.log.get_mut(&k) {
                Some(rec) if rec.has_content() => {
                    rec.stored = 0;
                    rec.secret = true;
                    rec.hash
                }
                _ => continue,
            };
            m.unref(&hash);
        }
        Ok(())
    }

    fn blob_bytes(&self) -> StoreResult<u64> {
        Ok(self
            .0
            .borrow()
            .blobs
            .values()
            .map(|(_, b)| b.len() as u64)
            .sum())
    }

    fn load_paths(&self) -> StoreResult<Option<OperatorPaths>> {
        Ok(self.0.borrow().paths.clone())
    }

    fn save_paths(&self, p: &OperatorPaths) -> StoreResult<()> {
        self.0.borrow_mut().paths = Some(p.clone());
        Ok(())
    }
}
