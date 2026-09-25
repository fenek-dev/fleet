//! inotify watches on tracked directories (Linux).
//!
//! `rustix` 1.x has no fanotify binding and the agent adds no FFI of its
//! own, so change events come from inotify (one watch per directory,
//! [`MAX_WATCHES`] at most). inotify carries no writer pid; attribution is
//! done by [`super::attrib::attribute`] without one. Events are batched
//! for [`DEBOUNCE`] so an editor's temp-file-and-rename is one change. A
//! queue overflow, or a directory moved or deleted, asks for a full scan.
//! Directories created later get watches of their own, and their files are
//! reported.
//!
//! Elsewhere (macOS tests) [`Watcher::new`] returns `None` and the tracker
//! relies on its periodic scan.

#[cfg(not(target_os = "linux"))]
use crate::ctx::SysCtx;
use std::time::Duration;

/// Directories watched at most.
pub const MAX_WATCHES: usize = 8192;
/// Quiet time before a batch is handed over.
pub const DEBOUNCE: Duration = Duration::from_millis(300);
/// Paths per batch; more becomes a rescan.
pub const MAX_BATCH: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Batch {
    /// Files (absolute system paths) that may have changed.
    Paths(Vec<String>),
    /// Too much happened to follow; scan everything.
    Rescan,
    /// The watch is broken; stop using it.
    Failed,
}

#[cfg(target_os = "linux")]
pub use linux::Watcher;

#[cfg(not(target_os = "linux"))]
pub struct Watcher(());

#[cfg(not(target_os = "linux"))]
impl Watcher {
    pub fn new(_ctx: &SysCtx, _roots: &[String]) -> Option<Self> {
        None
    }

    pub async fn next(&mut self) -> Batch {
        std::future::pending().await
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{Batch, DEBOUNCE, MAX_BATCH, MAX_WATCHES};
    use crate::ctx::SysCtx;
    use crate::files::walk::{Ev, Kind, MAX_WALK_DEPTH, WalkOpts, Walker, join};
    use rustix::fs::inotify::{self, CreateFlags, ReadFlags, WatchFlags};
    use rustix::io::Errno;
    use std::collections::{BTreeSet, HashMap};
    use std::mem::MaybeUninit;
    use std::os::fd::OwnedFd;
    use tokio::io::unix::AsyncFd;

    pub struct Watcher {
        fd: AsyncFd<OwnedFd>,
        dirs: HashMap<i32, String>,
        ctx: SysCtx,
        buf: Vec<MaybeUninit<u8>>,
    }

    fn mask() -> WatchFlags {
        WatchFlags::CLOSE_WRITE
            | WatchFlags::MOVED_TO
            | WatchFlags::MOVED_FROM
            | WatchFlags::CREATE
            | WatchFlags::DELETE
            | WatchFlags::ATTRIB
            | WatchFlags::DELETE_SELF
            | WatchFlags::MOVE_SELF
            | WatchFlags::DONT_FOLLOW
            | WatchFlags::ONLYDIR
    }

    enum Outcome {
        Paths(BTreeSet<String>),
        Rescan,
    }

    impl Watcher {
        pub fn new(ctx: &SysCtx, roots: &[String]) -> Option<Self> {
            let fd = inotify::init(CreateFlags::NONBLOCK | CreateFlags::CLOEXEC).ok()?;
            let mut w = Self {
                fd: AsyncFd::new(fd).ok()?,
                dirs: HashMap::new(),
                ctx: ctx.clone(),
                buf: vec![MaybeUninit::uninit(); 64 * 1024],
            };
            for r in roots {
                w.watch_tree(r, &mut Vec::new());
            }
            (!w.dirs.is_empty()).then_some(w)
        }

        /// Watches `root` and every directory below it; files found are
        /// pushed to `files` (a directory that just appeared).
        fn watch_tree(&mut self, root: &str, files: &mut Vec<String>) {
            let Ok(mut walk) = Walker::new(
                &self.ctx,
                root,
                WalkOpts::new(super::super::MAX_SCAN_ENTRIES, MAX_WALK_DEPTH),
            ) else {
                return;
            };
            while let Some(ev) = walk.next() {
                let Ev::Entry(e) = ev else { continue };
                match e.meta.kind {
                    Kind::Dir => {
                        if self.dirs.len() >= MAX_WATCHES {
                            walk.prune();
                            continue;
                        }
                        let Some(real) = self.ctx.path(&e.path) else {
                            continue;
                        };
                        match inotify::add_watch(self.fd.get_ref(), real.as_path(), mask()) {
                            Ok(wd) => {
                                self.dirs.insert(wd, e.path);
                            }
                            Err(_) => walk.prune(),
                        }
                    }
                    Kind::File if files.len() < MAX_BATCH => files.push(e.path),
                    _ => {}
                }
            }
        }

        /// Reads everything queued now. `Err` when the fd is unusable.
        fn drain(&mut self, out: &mut Option<Outcome>) -> Result<(), Errno> {
            let mut new_dirs = Vec::new();
            {
                let mut r = inotify::Reader::new(self.fd.get_ref(), &mut self.buf);
                loop {
                    let ev = match r.next() {
                        Ok(ev) => ev,
                        Err(Errno::AGAIN) => break,
                        Err(Errno::INTR) => continue,
                        Err(e) => return Err(e),
                    };
                    let flags = ev.events();
                    if flags.contains(ReadFlags::QUEUE_OVERFLOW) {
                        *out = Some(Outcome::Rescan);
                        continue;
                    }
                    let Some(dir) = self.dirs.get(&ev.wd()).cloned() else {
                        continue;
                    };
                    if flags.contains(ReadFlags::IGNORED) {
                        self.dirs.remove(&ev.wd());
                        continue;
                    }
                    if flags.intersects(ReadFlags::DELETE_SELF | ReadFlags::MOVE_SELF) {
                        *out = Some(Outcome::Rescan);
                        continue;
                    }
                    let Some(name) = ev.file_name() else { continue };
                    let path = join(&dir, &name.to_string_lossy());
                    if flags.contains(ReadFlags::ISDIR) {
                        if flags.intersects(ReadFlags::CREATE | ReadFlags::MOVED_TO) {
                            new_dirs.push(path);
                        } else if flags.intersects(ReadFlags::MOVED_FROM | ReadFlags::DELETE) {
                            *out = Some(Outcome::Rescan);
                        }
                        continue;
                    }
                    match out {
                        Some(Outcome::Rescan) => {}
                        Some(Outcome::Paths(p)) => {
                            if p.len() >= MAX_BATCH {
                                *out = Some(Outcome::Rescan);
                            } else {
                                p.insert(path);
                            }
                        }
                        None => *out = Some(Outcome::Paths(BTreeSet::from([path]))),
                    }
                }
            }
            for d in new_dirs {
                let mut files = Vec::new();
                self.watch_tree(&d, &mut files);
                match out {
                    Some(Outcome::Rescan) => {}
                    Some(Outcome::Paths(p)) => p.extend(files),
                    None => *out = Some(Outcome::Paths(files.into_iter().collect())),
                }
            }
            Ok(())
        }

        /// The next batch of changes.
        pub async fn next(&mut self) -> Batch {
            let mut out: Option<Outcome> = None;
            loop {
                let waited = if out.is_some() {
                    tokio::time::timeout(DEBOUNCE, self.fd.readable())
                        .await
                        .ok()
                } else {
                    Some(self.fd.readable().await)
                };
                match waited {
                    // Quiet for DEBOUNCE: hand the batch over.
                    None => {
                        return match out.take() {
                            Some(Outcome::Rescan) => Batch::Rescan,
                            Some(Outcome::Paths(p)) => Batch::Paths(p.into_iter().collect()),
                            None => Batch::Paths(Vec::new()),
                        };
                    }
                    Some(Err(_)) => return Batch::Failed,
                    Some(Ok(mut guard)) => {
                        guard.clear_ready();
                        drop(guard);
                        if self.drain(&mut out).is_err() {
                            return Batch::Failed;
                        }
                    }
                }
            }
        }
    }
}
