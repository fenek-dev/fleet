//! `files` group (design §2.5): `du.scan` and `find.large`. File contents
//! go over SFTP; these ops only report names and sizes.
//!
//! Both walk with [`walk::Walker`]: no symlink is followed, the walk stays
//! on the start path's filesystem (so `/proc`, `/sys` and other mounts are
//! reported but not entered), and it stops at [`MAX_ENTRIES`] entries or
//! [`TIME_BUDGET`], answering `truncated: true`. The walk yields to exec's
//! loop every [`YIELD_EVERY`] entries. Answers fit one frame: rows past
//! [`MAX_REPLY_BYTES`] of paths are dropped (also `truncated`).
//!
//! The catalog marks both as requests (`Op::is_stream` is false), so the
//! bounded answer comes in one `Response`.

pub mod walk;

use crate::ctx::SysCtx;
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, Registry};
use fleet_proto::op::tag;
use fleet_proto::payload::{DiskUsage, DuEntry, LargeFile, LargeFiles};
use fleet_proto::{ErrorCode, Op, Payload};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};
use std::rc::Rc;
use std::time::Duration;
use walk::{Ev, Kind, WalkOpts, Walker};

/// Entries visited per walk.
pub const MAX_ENTRIES: usize = 2_000_000;
/// Wall time per walk.
pub const TIME_BUDGET: Duration = Duration::from_secs(20);
/// Entries between yields to the exec loop.
pub const YIELD_EVERY: usize = 512;
/// Path bytes per answer (the frame is 1 MiB).
pub const MAX_REPLY_BYTES: usize = 768 * 1024;
/// Hard-linked inodes remembered to count them once.
const MAX_LINKS: usize = 200_000;

/// Yields every [`YIELD_EVERY`] calls.
pub(crate) struct Pacer(usize);

impl Pacer {
    pub(crate) fn new() -> Self {
        Self(0)
    }

    pub(crate) async fn tick(&mut self) {
        self.0 += 1;
        if self.0.is_multiple_of(YIELD_EVERY) {
            tokio::task::yield_now().await;
        }
    }
}

fn opts(ctx: &SysCtx, max_depth: usize) -> WalkOpts {
    WalkOpts::new(MAX_ENTRIES, max_depth).deadline(ctx.clock.monotonic() + TIME_BUDGET)
}

/// Keeps the `limit` largest rows (ties: smaller path first).
struct TopN<T: Ord> {
    heap: BinaryHeap<Reverse<T>>,
    limit: usize,
    dropped: bool,
}

impl<T: Ord> TopN<T> {
    fn new(limit: usize) -> Self {
        Self {
            heap: BinaryHeap::new(),
            limit,
            dropped: false,
        }
    }

    fn push(&mut self, v: T) {
        if self.heap.len() < self.limit {
            self.heap.push(Reverse(v));
        } else if self.heap.peek().is_some_and(|m| v > m.0) {
            self.heap.pop();
            self.heap.push(Reverse(v));
            self.dropped = true;
        } else {
            self.dropped = true;
        }
    }

    /// Largest first.
    fn into_sorted(self) -> Vec<T> {
        let mut v: Vec<T> = self.heap.into_iter().map(|r| r.0).collect();
        v.sort_by(|a, b| b.cmp(a));
        v
    }
}

/// Cuts `rows` once their paths exceed [`MAX_REPLY_BYTES`]; true if cut.
fn fit<T>(rows: &mut Vec<T>, path: impl Fn(&T) -> &str) -> bool {
    let mut total = 0usize;
    for (i, r) in rows.iter().enumerate() {
        total += path(r).len() + 32;
        if total > MAX_REPLY_BYTES {
            rows.truncate(i);
            return true;
        }
    }
    false
}

/// `du.scan`: allocated bytes per directory (and file) down to
/// `max_depth` below `path`, largest `limit` rows. Totals include
/// everything below, however deep; hard links count once.
pub async fn du_scan(
    ctx: &SysCtx,
    path: &str,
    max_depth: u8,
    limit: u32,
) -> Result<DiskUsage, OpError> {
    let max_depth = usize::from(max_depth);
    let mut w = Walker::new(ctx, path, opts(ctx, walk::MAX_WALK_DEPTH))?;
    let mut top: TopN<(u64, Reverse<String>, u8, bool)> =
        TopN::new(usize::try_from(limit).unwrap_or(usize::MAX));
    // Running totals of the open directories, by depth.
    let mut acc: Vec<u64> = Vec::new();
    let mut links: HashSet<(u64, u64)> = HashSet::new();
    let mut total = 0u64;
    let mut pace = Pacer::new();
    while let Some(ev) = w.next() {
        pace.tick().await;
        match ev {
            Ev::Entry(e) => {
                let mut bytes = e.meta.alloc;
                if e.meta.kind != Kind::Dir && e.meta.nlink > 1 {
                    if links.contains(&(e.meta.dev, e.meta.ino)) {
                        bytes = 0;
                    } else if links.len() < MAX_LINKS {
                        links.insert((e.meta.dev, e.meta.ino));
                    }
                }
                if e.meta.kind == Kind::Dir {
                    acc.truncate(e.depth);
                    acc.resize(e.depth + 1, 0);
                    acc[e.depth] = bytes;
                } else {
                    if let Some(parent) = e.depth.checked_sub(1).and_then(|d| acc.get_mut(d)) {
                        *parent = parent.saturating_add(bytes);
                    } else {
                        total = bytes;
                    }
                    if e.depth <= max_depth && e.depth > 0 {
                        top.push((bytes, Reverse(e.path), e.depth as u8, false));
                    }
                }
            }
            Ev::Leave { path, depth, .. } => {
                let bytes = acc.get(depth).copied().unwrap_or(0);
                acc.truncate(depth);
                if let Some(parent) = depth.checked_sub(1).and_then(|d| acc.get_mut(d)) {
                    *parent = parent.saturating_add(bytes);
                } else {
                    total = bytes;
                }
                if depth <= max_depth {
                    top.push((bytes, Reverse(path), depth as u8, true));
                }
            }
        }
    }
    let dropped = top.dropped;
    let mut entries: Vec<DuEntry> = top
        .into_sorted()
        .into_iter()
        .map(|(bytes, Reverse(path), depth, is_dir)| DuEntry {
            path,
            bytes,
            depth,
            is_dir,
        })
        .collect();
    let cut = fit(&mut entries, |e| &e.path);
    Ok(DiskUsage {
        root: path.to_owned(),
        total_bytes: total,
        entries,
        truncated: w.truncated() || dropped || cut,
    })
}

/// `find.large`: regular files of at least `min_bytes` below `root`,
/// largest `limit` of them.
pub async fn find_large(
    ctx: &SysCtx,
    root: &str,
    min_bytes: u64,
    limit: u32,
) -> Result<LargeFiles, OpError> {
    let mut w = Walker::new(ctx, root, opts(ctx, walk::MAX_WALK_DEPTH))?;
    let mut top: TopN<(u64, Reverse<String>, u64)> =
        TopN::new(usize::try_from(limit).unwrap_or(usize::MAX));
    let mut pace = Pacer::new();
    while let Some(ev) = w.next() {
        pace.tick().await;
        if let Ev::Entry(e) = ev
            && e.meta.kind == Kind::File
            && e.meta.size >= min_bytes
        {
            top.push((e.meta.size, Reverse(e.path), e.meta.mtime_ms()));
        }
    }
    let dropped = top.dropped;
    let mut files: Vec<LargeFile> = top
        .into_sorted()
        .into_iter()
        .map(|(bytes, Reverse(path), mtime_ms)| LargeFile {
            path,
            bytes,
            mtime_ms,
        })
        .collect();
    let cut = fit(&mut files, |f| &f.path);
    Ok(LargeFiles {
        files,
        truncated: w.truncated() || dropped || cut,
    })
}

/// `du.scan` and `find.large`.
pub struct FilesHandler;

pub const TAGS: [u16; 2] = [tag::DU_SCAN, tag::FIND_LARGE];

impl OpHandler for FilesHandler {
    fn validate(&self, _ctx: &SysCtx, op: &Op, _meta: &OpMeta) -> Result<(), OpError> {
        match op {
            Op::DuScan { .. } | Op::FindLarge { .. } => {
                op.check_args().map_err(ErrorCode::from)?;
                Ok(())
            }
            _ => Err(ErrorCode::Unsupported.into()),
        }
    }

    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        op: &'a Op,
        _meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            let p = match op {
                Op::DuScan {
                    path,
                    max_depth,
                    limit,
                } => Payload::DiskUsage(du_scan(ctx, path.as_str(), *max_depth, *limit).await?),
                Op::FindLarge {
                    root,
                    min_bytes,
                    limit,
                } => Payload::LargeFiles(find_large(ctx, root.as_str(), *min_bytes, *limit).await?),
                _ => return Err(ErrorCode::Unsupported.into()),
            };
            Ok(OpOutput::Payload(p))
        })
    }
}

pub fn register(r: &mut Registry) {
    let h: Rc<dyn OpHandler> = Rc::new(FilesHandler);
    for t in TAGS {
        r.register(t, h.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{block, ctx, meta};
    use fleet_proto::args::AbsPath;
    use std::os::unix::fs::symlink;

    fn tree() -> (tempfile::TempDir, SysCtx) {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        std::fs::create_dir_all(r.join("data/a/deep/er")).unwrap();
        std::fs::create_dir_all(r.join("data/b")).unwrap();
        std::fs::create_dir_all(r.join("elsewhere")).unwrap();
        std::fs::write(r.join("data/a/deep/er/big"), vec![1u8; 300_000]).unwrap();
        std::fs::write(r.join("data/b/mid"), vec![1u8; 100_000]).unwrap();
        std::fs::write(r.join("data/small"), b"x").unwrap();
        std::fs::write(r.join("elsewhere/huge"), vec![1u8; 2_000_000]).unwrap();
        symlink(r.join("elsewhere"), r.join("data/link")).unwrap();
        let c = ctx(r, Rc::new(crate::FakeRunner::new()));
        (d, c)
    }

    #[test]
    fn du_totals_nest_and_skip_symlinks() {
        let (_d, c) = tree();
        let du = block(du_scan(&c, "/data", 1, 100)).unwrap();
        let get = |p: &str| du.entries.iter().find(|e| e.path == p).map(|e| e.bytes);
        let a = get("/data/a").unwrap();
        let b = get("/data/b").unwrap();
        assert!(a >= 300_000, "{a}");
        assert!((100_000..300_000).contains(&b), "{b}");
        // Depth 1 only: nothing deeper is listed, but it counts above.
        assert!(get("/data/a/deep").is_none());
        // The symlink target (2 MB) is never counted.
        assert!(du.total_bytes < 1_000_000, "{}", du.total_bytes);
        assert!(du.total_bytes >= a + b);
        assert_eq!(du.entries[0].path, "/data");
        assert!(!du.truncated);
        // limit bounds rows.
        let du = block(du_scan(&c, "/data", 16, 2)).unwrap();
        assert_eq!(du.entries.len(), 2);
        assert!(du.truncated);
    }

    #[test]
    fn find_large_bounds() {
        let (_d, c) = tree();
        let f = block(find_large(&c, "/data", 50_000, 10)).unwrap();
        let paths: Vec<&str> = f.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["/data/a/deep/er/big", "/data/b/mid"]);
        assert!(!f.truncated);
        let f = block(find_large(&c, "/data", 1, 1)).unwrap();
        assert_eq!(f.files.len(), 1);
        assert!(f.truncated);
        // Missing root.
        assert_eq!(
            block(find_large(&c, "/nope", 1, 1)).unwrap_err().code(),
            ErrorCode::NotFound
        );
    }

    #[test]
    fn handler_validates_and_dispatches() {
        let (_d, c) = tree();
        let op = Op::DuScan {
            path: AbsPath::new("/data").unwrap(),
            max_depth: 17,
            limit: 10,
        };
        let m = meta(op.clone(), None);
        assert_eq!(
            FilesHandler.validate(&c, &op, &m).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
        let op = Op::FindLarge {
            root: AbsPath::new("/data").unwrap(),
            min_bytes: 1,
            limit: 5,
        };
        let m = meta(op.clone(), Some(1));
        FilesHandler.validate(&c, &op, &m).unwrap();
        let out = block(FilesHandler.handle(&c, &op, &m)).unwrap();
        assert!(matches!(out, OpOutput::Payload(Payload::LargeFiles(_))));
    }
}
