//! Config history (design §4.9): every change to tracked files, whoever
//! made it, versioned in exec's database, with diffs and rollback.
//!
//! - [`ConfigTracker`] observes paths ([`ConfigTracker::observe`]) and
//!   records a version when content, mode or owner changed. Content is a
//!   BLAKE3-addressed, DEFLATE-compressed blob (≤ [`content::MAX_BLOB`]);
//!   secrets ([`rules`]) and files holding a PEM private key are recorded
//!   by hash only: their content is never stored, diffed or returned.
//! - Change detection: an inotify watch on every tracked directory
//!   ([`watch`], Linux) plus a full scan every [`SCAN_INTERVAL`] (size,
//!   mtime and inode first; hashing only on a mismatch; bounded entries,
//!   time and read bytes). See [`attrib`] for attribution.
//! - Retention ([`Retention`]): 90 days or 200 versions per file, the
//!   latest version always kept, then oldest content dropped until the
//!   blobs fit the disk budget.
//! - Ops ([`ops::ConfigOps`]): `config.history`, `config.diff`,
//!   `config.rollback`, `config.paths.get`, `config.paths.set`.
//!
//! Exec owns the store (redb tables `config_*`), builds the tracker, spawns
//! [`ConfigTracker::run`] and registers [`ops::ConfigOps`] on [`TAGS`].

pub mod attrib;
pub mod content;
pub mod diff;
pub mod ops;
pub mod rules;
pub mod store;
pub mod watch;
pub mod write;

#[cfg(test)]
mod tests;

pub use attrib::{AttributionContext, Unattributed, attribute, parse_op_scope};
pub use ops::{ConfigOps, TAGS};
pub use rules::PathRules;
pub use store::{
    ConfigStore, FileState, MemStore, OperatorPaths, StoreResult, TimelineVisitor, VersionRecord,
};

use crate::ctx::SysCtx;
use crate::files::Pacer;
use crate::files::walk::{self, Ev, Kind, WalkOpts, Walker, glob_match, open_file};
use crate::handler::OpError;
use crate::security::EventSink;
use fleet_proto::payload::{ChangeSource, ConfigVersion};
use fleet_proto::{ErrorCode, Event};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::io;
use std::rc::Rc;
use std::time::Duration;

pub const SCAN_INTERVAL: Duration = Duration::from_secs(300);
pub const PRUNE_INTERVAL_MS: u64 = 3_600_000;
/// Files a full scan looks at.
pub const MAX_SCAN_FILES: usize = 20_000;
/// Directory entries a full scan walks.
pub const MAX_SCAN_ENTRIES: usize = 100_000;
/// Wall time of one full scan.
pub const SCAN_TIME_BUDGET: Duration = Duration::from_secs(30);
/// Bytes one full scan reads for hashing.
pub const SCAN_IO_BUDGET: u64 = 256 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    pub max_age_ms: u64,
    pub max_versions: usize,
    /// Compressed blob bytes.
    pub disk_budget: u64,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            max_age_ms: 90 * 86_400_000,
            max_versions: 200,
            disk_budget: 32 << 20,
        }
    }
}

/// Result of a full scan.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanReport {
    pub files: usize,
    pub changed: usize,
    /// Files that couldn't be read or recorded.
    pub errors: usize,
    /// A bound cut the scan short (deletions aren't inferred then).
    pub truncated: bool,
}

fn store_err(e: String) -> OpError {
    OpError::internal(format!("config store: {e}"))
}

pub fn to_version(path: &str, version: u64, r: &VersionRecord) -> ConfigVersion {
    ConfigVersion {
        path: path.to_owned(),
        version,
        time_ms: r.time_ms,
        hash: r.hash,
        size: r.size,
        source: r.source.clone(),
        secret: r.secret,
        deleted: r.deleted,
    }
}

/// Drops kept content (hashes and metadata stay) of every path `rules`
/// calls secret.
fn strip_secrets(store: &dyn ConfigStore, rules: &PathRules) -> Result<(), OpError> {
    for (path, _) in store.files().map_err(store_err)? {
        if rules.is_secret(&path) {
            store.strip_content(&path).map_err(store_err)?;
        }
    }
    Ok(())
}

pub struct ConfigTracker {
    store: Rc<dyn ConfigStore>,
    sink: Rc<dyn EventSink>,
    attrib: Rc<dyn AttributionContext>,
    rules: RefCell<PathRules>,
    retention: Retention,
    last_prune_ms: Cell<u64>,
}

impl ConfigTracker {
    pub fn new(
        store: Rc<dyn ConfigStore>,
        sink: Rc<dyn EventSink>,
        attrib: Rc<dyn AttributionContext>,
    ) -> Result<Rc<Self>, OpError> {
        Self::with_retention(store, sink, attrib, Retention::default())
    }

    pub fn with_retention(
        store: Rc<dyn ConfigStore>,
        sink: Rc<dyn EventSink>,
        attrib: Rc<dyn AttributionContext>,
        retention: Retention,
    ) -> Result<Rc<Self>, OpError> {
        let operator = store.load_paths().map_err(store_err)?.unwrap_or_default();
        let rules = PathRules::new(operator);
        // The secret list may have grown since this history was written.
        strip_secrets(store.as_ref(), &rules)?;
        Ok(Rc::new(Self {
            store,
            sink,
            attrib,
            rules: RefCell::new(rules),
            retention,
            last_prune_ms: Cell::new(0),
        }))
    }

    pub fn store(&self) -> &Rc<dyn ConfigStore> {
        &self.store
    }

    pub fn rules(&self) -> PathRules {
        self.rules.borrow().clone()
    }

    pub fn attribution(&self) -> &Rc<dyn AttributionContext> {
        &self.attrib
    }

    /// Replaces the operator rules; kept content of paths that became
    /// secret is dropped at once.
    pub fn set_operator_paths(&self, p: OperatorPaths) -> Result<(), OpError> {
        self.store.save_paths(&p).map_err(store_err)?;
        let rules = PathRules::new(p);
        strip_secrets(self.store.as_ref(), &rules)?;
        *self.rules.borrow_mut() = rules;
        Ok(())
    }

    /// Records a write made by exec's operation `(op_tag, audit_seq)`
    /// (handlers call this right after writing a tracked file).
    pub fn note_write(
        &self,
        ctx: &SysCtx,
        path: &str,
        op_tag: u16,
        audit_seq: u64,
    ) -> Result<Option<ConfigVersion>, OpError> {
        self.observe(ctx, path, ChangeSource::Fleet { op_tag, audit_seq }, true)
    }

    /// Looks at `path` now and records a version if it changed (content,
    /// deletion, mode or owner). `emit` sends `config.changed`. Untracked
    /// paths are ignored (`Ok(None)`).
    pub fn observe(
        &self,
        ctx: &SysCtx,
        path: &str,
        source: ChangeSource,
        emit: bool,
    ) -> Result<Option<ConfigVersion>, OpError> {
        self.observe_counted(ctx, path, source, emit)
            .map(|(v, _)| v)
    }

    fn observe_counted(
        &self,
        ctx: &SysCtx,
        path: &str,
        source: ChangeSource,
        emit: bool,
    ) -> Result<(Option<ConfigVersion>, u64), OpError> {
        let (tracked, secret_path) = {
            let r = self.rules.borrow();
            (r.is_tracked(path), r.is_secret(path))
        };
        if !tracked {
            return Ok((None, 0));
        }
        let prev = self.store.file(path).map_err(store_err)?;
        let now = ctx.clock.now_ms();
        let seen = match open_file(ctx, path) {
            Ok((f, meta)) => Some(
                content::observe(f, meta, !secret_path, path)
                    .map_err(|e| OpError::internal(format!("read {path}: {e}")))?,
            ),
            Err(e)
                if matches!(e.kind(), io::ErrorKind::NotFound)
                    || e.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error())
                    || e.raw_os_error() == Some(rustix::io::Errno::NOTDIR.raw_os_error())
                    || e.kind() == io::ErrorKind::Other =>
            {
                // Missing, a symlink, or not a regular file: not content.
                None
            }
            Err(e) => return Err(OpError::internal(format!("open {path}: {e}"))),
        };
        let read = seen.as_ref().map_or(0, |o| o.read);
        let version = prev.map_or(1, |p| p.version + 1);
        let (rec, blob, state) = match (prev, seen) {
            (None, None) => return Ok((None, read)),
            (Some(p), None) if p.deleted => return Ok((None, read)),
            (Some(p), None) => {
                let rec = VersionRecord {
                    time_ms: now,
                    hash: [0; 32],
                    size: 0,
                    mode: 0,
                    uid: 0,
                    gid: 0,
                    source,
                    secret: secret_path,
                    deleted: true,
                    stored: 0,
                };
                let state = FileState {
                    version,
                    deleted: true,
                    size: 0,
                    mtime_ns: 0,
                    ino: 0,
                    hash: [0; 32],
                    ..p
                };
                (rec, None, state)
            }
            (prev, Some(o)) => {
                let m = o.meta;
                let state = FileState {
                    version,
                    size: m.size,
                    mtime_ns: m.mtime_ns,
                    ino: m.ino,
                    mode: m.mode,
                    uid: m.uid,
                    gid: m.gid,
                    hash: o.hash,
                    deleted: false,
                };
                if let Some(p) = prev
                    && !p.deleted
                    && p.hash == o.hash
                    && (p.mode, p.uid, p.gid) == (m.mode, m.uid, m.gid)
                {
                    let refreshed = FileState {
                        version: p.version,
                        ..state
                    };
                    if refreshed != p {
                        self.store.put_file(path, &refreshed).map_err(store_err)?;
                    }
                    return Ok((None, read));
                }
                let secret = secret_path || o.secret;
                let blob = if secret {
                    None
                } else {
                    o.data.as_deref().map(content::compress)
                };
                let rec = VersionRecord {
                    time_ms: now,
                    hash: o.hash,
                    size: m.size,
                    mode: m.mode,
                    uid: m.uid,
                    gid: m.gid,
                    source,
                    secret,
                    deleted: false,
                    stored: blob
                        .as_ref()
                        .map_or(0, |b| u32::try_from(b.len()).unwrap_or(u32::MAX).max(1)),
                };
                (rec, blob, state)
            }
        };
        self.store
            .append(path, version, &rec, blob.as_deref(), &state)
            .map_err(store_err)?;
        if emit {
            self.sink.emit(Event::ConfigChanged {
                path: path.to_owned(),
                version,
                source: rec.source.clone(),
                secret: rec.secret,
            });
        }
        Ok((Some(to_version(path, version, &rec)), read))
    }

    /// Full scan of every tracked rule. Changes are `Unknown` (the writer
    /// can't be known). The very first scan (empty history) records the
    /// baseline without events.
    pub async fn scan(&self, ctx: &SysCtx) -> Result<ScanReport, OpError> {
        let rules = self.rules();
        let known: HashMap<String, FileState> =
            self.store.files().map_err(store_err)?.into_iter().collect();
        let baseline = known.is_empty();
        let deadline = ctx.clock.monotonic() + SCAN_TIME_BUDGET;
        let mut report = ScanReport::default();
        let mut found: Vec<(String, walk::FileMeta)> = Vec::new();
        let mut entries = 0usize;
        let mut pace = Pacer::new();
        for root in rules.walk_roots() {
            let opts = WalkOpts::new(MAX_SCAN_ENTRIES.saturating_sub(entries), root.max_depth)
                .deadline(deadline);
            let mut w = match Walker::new(ctx, &root.root, opts) {
                Ok(w) => w,
                Err(e) if e.code() == ErrorCode::NotFound => continue,
                Err(_) => {
                    report.truncated = true;
                    continue;
                }
            };
            while let Some(ev) = w.next() {
                pace.tick().await;
                if let Ev::Entry(e) = ev
                    && e.meta.kind == Kind::File
                    && root
                        .pattern
                        .as_deref()
                        .is_none_or(|p| glob_match(p, &e.path))
                    && rules.is_tracked(&e.path)
                {
                    if found.len() >= MAX_SCAN_FILES {
                        report.truncated = true;
                        break;
                    }
                    found.push((e.path, e.meta));
                }
            }
            entries += w.entries();
            report.truncated |= w.truncated();
        }
        let mut seen: HashSet<String> = HashSet::with_capacity(found.len());
        let mut read = 0u64;
        for (path, meta) in found {
            pace.tick().await;
            let unchanged = known.get(&path).is_some_and(|s| {
                !s.deleted
                    && s.size == meta.size
                    && s.mtime_ns == meta.mtime_ns
                    && s.ino == meta.ino
                    && (s.mode, s.uid, s.gid) == (meta.mode, meta.uid, meta.gid)
            });
            report.files += 1;
            if unchanged {
                seen.insert(path);
                continue;
            }
            if read > SCAN_IO_BUDGET || ctx.clock.monotonic() >= deadline {
                report.truncated = true;
                break;
            }
            // One unreadable file doesn't stop the scan (it stays as last
            // recorded, and isn't inferred deleted).
            seen.insert(path.clone());
            match self.observe_counted(ctx, &path, ChangeSource::Unknown, !baseline) {
                Ok((v, n)) => {
                    read += n;
                    report.changed += usize::from(v.is_some());
                }
                Err(_) => report.errors += 1,
            }
        }
        if !report.truncated {
            for (path, st) in &known {
                if !st.deleted && !seen.contains(path) && rules.is_tracked(path) {
                    pace.tick().await;
                    match self.observe_counted(ctx, path, ChangeSource::Unknown, true) {
                        Ok((v, _)) => report.changed += usize::from(v.is_some()),
                        Err(_) => report.errors += 1,
                    }
                }
            }
        }
        Ok(report)
    }

    /// Applies [`Retention`]. Returns the versions dropped.
    pub fn prune(&self, now_ms: u64) -> Result<usize, OpError> {
        let r = self.retention;
        let mut victims: Vec<(String, u64)> = Vec::new();
        // (time, path, version, stored) of droppable versions with content.
        let mut spare: Vec<(u64, String, u64, u32)> = Vec::new();
        for (path, st) in self.store.files().map_err(store_err)? {
            let vs = self.store.versions(&path).map_err(store_err)?;
            let n = vs.len();
            for (i, (ver, rec)) in vs.into_iter().enumerate() {
                if ver == st.version {
                    continue;
                }
                let too_many = n - i > r.max_versions;
                let too_old = now_ms.saturating_sub(rec.time_ms) > r.max_age_ms;
                if too_many || too_old {
                    victims.push((path.clone(), ver));
                } else if rec.has_content() {
                    spare.push((rec.time_ms, path.clone(), ver, rec.stored));
                }
            }
        }
        self.store.remove(&victims).map_err(store_err)?;
        let mut dropped = victims.len();
        let mut bytes = self.store.blob_bytes().map_err(store_err)?;
        if bytes > r.disk_budget {
            spare.sort();
            let mut more = Vec::new();
            for (_, path, ver, stored) in spare {
                if bytes <= r.disk_budget {
                    break;
                }
                bytes = bytes.saturating_sub(u64::from(stored));
                more.push((path, ver));
            }
            self.store.remove(&more).map_err(store_err)?;
            dropped += more.len();
        }
        self.last_prune_ms.set(now_ms);
        Ok(dropped)
    }

    fn prune_due(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.last_prune_ms.get()) >= PRUNE_INTERVAL_MS
    }

    /// Exec's background task: a scan at start, then inotify batches and a
    /// full scan every [`SCAN_INTERVAL`], pruning hourly. Errors are
    /// reported through `log` and never end the task.
    pub async fn run(self: Rc<Self>, ctx: SysCtx, log: fn(&str, &str)) {
        let report = |what: &str, r: Result<ScanReport, OpError>| match r {
            Err(e) => log(what, &e.to_string()),
            Ok(r) if r.errors > 0 || r.truncated => log(what, &format!("{r:?}")),
            Ok(_) => {}
        };
        report("config scan", self.scan(&ctx).await);
        if let Err(e) = self.prune(ctx.clock.now_ms()) {
            log("config prune", &e.to_string());
        }
        let mut watcher = watch::Watcher::new(&ctx, &self.rules().watch_roots());
        if watcher.is_none() {
            log("config watch", "inotify unavailable; full scans only");
        }
        let mut tick = tokio::time::interval(SCAN_INTERVAL);
        tick.tick().await;
        loop {
            let batch = async {
                match watcher.as_mut() {
                    Some(w) => w.next().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = tick.tick() => {
                    report("config scan", self.scan(&ctx).await);
                }
                b = batch => match b {
                    watch::Batch::Paths(paths) => {
                        for p in paths {
                            let src = attribute(&ctx, None, self.attrib.as_ref());
                            if let Err(e) = self.observe(&ctx, &p, src, true) {
                                log("config observe", &e.to_string());
                            }
                        }
                    }
                    watch::Batch::Rescan => report("config scan", self.scan(&ctx).await),
                    watch::Batch::Failed => {
                        log("config watch", "inotify failed; full scans only");
                        watcher = None;
                    }
                },
            }
            let now = ctx.clock.now_ms();
            if self.prune_due(now)
                && let Err(e) = self.prune(now)
            {
                log("config prune", &e.to_string());
            }
        }
    }
}
