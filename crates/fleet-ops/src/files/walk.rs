//! Symlink-safe filesystem access below the [`SysCtx`] root.
//!
//! Every path is resolved one component at a time with
//! `openat(dirfd, name, O_NOFOLLOW)` from a directory fd, so a directory
//! swapped for a symlink mid-walk can't redirect a read (or a rollback
//! write) outside the tree. Only the context root itself is opened by path
//! (`/` in production; a temp directory in tests).
//!
//! [`Walker`] is a resumable depth-first walk: the caller pulls one
//! [`Ev`] at a time, so async handlers yield to exec's single-threaded
//! loop between batches. Bounds: entry count, wall-clock deadline (from
//! the context clock), descent depth and, optionally, one filesystem.

use crate::ctx::SysCtx;
use crate::handler::OpError;
use fleet_proto::ErrorCode;
use rustix::fs::{self as rfs, AtFlags, Dir, FileType, Mode, OFlags};
use std::collections::VecDeque;
use std::ffi::CStr;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::time::Instant;

/// Deepest descent any walk makes (well past real trees; bounds open fds).
pub const MAX_WALK_DEPTH: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
    Other,
}

/// What a walk needs from `stat`, in fixed widths on every platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMeta {
    pub kind: Kind,
    pub dev: u64,
    pub ino: u64,
    /// Apparent size.
    pub size: u64,
    /// Allocated bytes (`st_blocks × 512`), what `du` reports.
    pub alloc: u64,
    /// Permission bits (`0o7777`).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime_ns: i64,
    pub nlink: u64,
}

impl FileMeta {
    pub fn mtime_ms(&self) -> u64 {
        u64::try_from(self.mtime_ns / 1_000_000).unwrap_or(0)
    }
}

/// `stat` field widths differ per platform and backend; the casts only
/// widen or reinterpret kernel values.
#[allow(
    clippy::unnecessary_cast,
    clippy::useless_conversion,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
pub fn meta_of(st: &rfs::Stat) -> FileMeta {
    let kind = match FileType::from_raw_mode(st.st_mode as _) {
        FileType::RegularFile => Kind::File,
        FileType::Directory => Kind::Dir,
        FileType::Symlink => Kind::Symlink,
        _ => Kind::Other,
    };
    let size = st.st_size as i64;
    let blocks = st.st_blocks as i64;
    FileMeta {
        kind,
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
        size: size.max(0) as u64,
        alloc: (blocks.max(0) as u64).saturating_mul(512),
        mode: (st.st_mode as u32) & 0o7777,
        uid: st.st_uid as u32,
        gid: st.st_gid as u32,
        mtime_ns: (st.st_mtime as i64)
            .saturating_mul(1_000_000_000)
            .saturating_add(st.st_mtime_nsec as i64),
        nlink: st.st_nlink as u64,
    }
}

pub(crate) fn io_code(e: &io::Error) -> ErrorCode {
    match e.kind() {
        io::ErrorKind::NotFound => ErrorCode::NotFound,
        _ if e.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) => {
            ErrorCode::InvalidArgument
        }
        _ if e.raw_os_error() == Some(rustix::io::Errno::NOTDIR.raw_os_error()) => {
            ErrorCode::NotFound
        }
        _ => ErrorCode::Internal,
    }
}

pub(crate) fn io_err(e: io::Error, what: &'static str) -> OpError {
    OpError::new(io_code(&e)).with_detail(format!("{what}: {e}"))
}

/// The normal components of an absolute path; `None` for relative paths
/// or any `.`/`..`/empty component.
pub fn components(abs: &str) -> Option<Vec<&str>> {
    let rest = abs.strip_prefix('/')?;
    if rest.is_empty() {
        return Some(Vec::new());
    }
    let comps: Vec<&str> = rest.split('/').collect();
    if comps
        .iter()
        .any(|c| c.is_empty() || *c == "." || *c == "..")
    {
        return None;
    }
    Some(comps)
}

fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// The context root (trusted; symlinks in it are followed).
pub fn open_root(ctx: &SysCtx) -> io::Result<OwnedFd> {
    Ok(rfs::open(
        ctx.root(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

/// Opens directory `name` in `dir` without following a symlink.
pub fn open_dir_at(dir: impl AsFd, name: impl rustix::path::Arg) -> io::Result<OwnedFd> {
    Ok(rfs::openat(dir, name, dir_flags(), Mode::empty())?)
}

/// Opens the directory `abs` component by component, never following a
/// symlink below the context root.
pub fn open_dir(ctx: &SysCtx, abs: &str) -> io::Result<OwnedFd> {
    let comps = components(abs).ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut fd = open_root(ctx)?;
    for c in comps {
        fd = open_dir_at(&fd, c)?;
    }
    Ok(fd)
}

/// The parent directory of `abs` (opened as in [`open_dir`]) and the final
/// component. `/` has no parent.
pub fn open_parent<'a>(ctx: &SysCtx, abs: &'a str) -> io::Result<(OwnedFd, &'a str)> {
    let comps = components(abs).ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let Some((last, dirs)) = comps.split_last() else {
        return Err(io::ErrorKind::InvalidInput.into());
    };
    let mut fd = open_root(ctx)?;
    for c in dirs {
        fd = open_dir_at(&fd, *c)?;
    }
    Ok((fd, last))
}

/// `lstat` of `name` in `dir`.
pub fn stat_at(dir: impl AsFd, name: impl rustix::path::Arg) -> io::Result<FileMeta> {
    Ok(meta_of(&rfs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?))
}

/// `lstat` of an absolute path (parents resolved without symlinks).
pub fn stat_path(ctx: &SysCtx, abs: &str) -> io::Result<FileMeta> {
    if abs == "/" {
        return Ok(meta_of(&rfs::fstat(open_root(ctx)?)?));
    }
    let (dir, name) = open_parent(ctx, abs)?;
    stat_at(&dir, name)
}

/// Opens a regular file for reading: `O_NOFOLLOW` (a symlink is `ELOOP`),
/// `O_NONBLOCK` (a FIFO swapped in can't hang exec), and `fstat` must say
/// regular file. Returns the file and its metadata.
pub fn open_file_at(
    dir: impl AsFd,
    name: impl rustix::path::Arg,
) -> io::Result<(std::fs::File, FileMeta)> {
    let fd = rfs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let meta = meta_of(&rfs::fstat(&fd)?);
    if meta.kind != Kind::File {
        return Err(io::Error::other("not a regular file"));
    }
    Ok((std::fs::File::from(fd), meta))
}

/// [`open_file_at`] for an absolute path.
pub fn open_file(ctx: &SysCtx, abs: &str) -> io::Result<(std::fs::File, FileMeta)> {
    let (dir, name) = open_parent(ctx, abs)?;
    open_file_at(&dir, name)
}

/// The host path `abs` names once the context root is canonicalized (the
/// root is trusted; `/` in production). What `/proc/self/fd` reports for a
/// file opened through the fd-relative helpers.
pub fn host_path(ctx: &SysCtx, abs: &str) -> io::Result<std::path::PathBuf> {
    let comps = components(abs).ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut p = ctx.root().canonicalize()?;
    p.extend(comps);
    Ok(p)
}

/// Post-open check: `/proc/self/fd/<fd>` must name exactly `expected` (a
/// canonical host path), so a file reached through a raced rename or a
/// swapped directory is refused (`PermissionDenied`).
#[cfg(target_os = "linux")]
pub fn check_fd_path(fd: impl AsFd, expected: &std::path::Path) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let real = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd()))?;
    if real == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "opened file is not at the expected path",
        ))
    }
}

/// No `/proc` here (macOS test builds): nothing to compare against.
#[cfg(not(target_os = "linux"))]
pub fn check_fd_path(_: impl AsFd, _: &std::path::Path) -> io::Result<()> {
    Ok(())
}

/// Joins a directory path and a child name.
pub fn join(dir: &str, name: &str) -> String {
    if dir == "/" {
        format!("/{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// Walk bounds.
#[derive(Debug, Clone, Copy)]
pub struct WalkOpts {
    /// Entries visited (the root included) before the walk stops.
    pub max_entries: usize,
    /// Directories deeper than this are reported but not entered (root = 0).
    pub max_depth: usize,
    /// Stop at the root's filesystem boundary (mount points are reported,
    /// not entered).
    pub one_fs: bool,
    pub deadline: Option<Instant>,
}

impl WalkOpts {
    pub fn new(max_entries: usize, max_depth: usize) -> Self {
        Self {
            max_entries,
            max_depth: max_depth.min(MAX_WALK_DEPTH),
            one_fs: true,
            deadline: None,
        }
    }

    pub fn deadline(mut self, d: Instant) -> Self {
        self.deadline = Some(d);
        self
    }
}

/// One visited entry. Symlinks are reported as symlinks, never followed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub depth: usize,
    pub meta: FileMeta,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ev {
    Entry(Entry),
    /// Every directory `Entry` is followed by exactly one `Leave` (after
    /// its children, or right away when it wasn't entered).
    Leave {
        path: String,
        depth: usize,
        entered: bool,
    },
}

struct Frame {
    dir: Dir,
    path: String,
    depth: usize,
}

/// A directory reported but not yet entered.
struct PendingDir {
    fd: Option<OwnedFd>,
    parent: Option<usize>,
    name: Vec<u8>,
    path: String,
    depth: usize,
}

pub struct Walker {
    stack: Vec<Frame>,
    pending: Option<PendingDir>,
    queued: VecDeque<Ev>,
    root_dev: u64,
    opts: WalkOpts,
    ctx: SysCtx,
    entries: usize,
    truncated: bool,
}

impl Walker {
    /// Starts at `root` (an absolute system path). The first event is the
    /// root itself; a root that is a symlink is reported, not followed.
    pub fn new(ctx: &SysCtx, root: &str, opts: WalkOpts) -> Result<Self, OpError> {
        let meta = stat_path(ctx, root).map_err(|e| io_err(e, "walk root"))?;
        let mut w = Self {
            stack: Vec::new(),
            pending: None,
            queued: VecDeque::new(),
            root_dev: meta.dev,
            opts,
            ctx: ctx.clone(),
            entries: 1,
            truncated: false,
        };
        let entry = Entry {
            path: root.to_owned(),
            depth: 0,
            meta,
        };
        if meta.kind == Kind::Dir && opts.max_depth > 0 {
            let fd = if root == "/" {
                open_root(ctx)
            } else {
                open_dir(ctx, root)
            }
            .map_err(|e| io_err(e, "walk root"))?;
            w.pending = Some(PendingDir {
                fd: Some(fd),
                parent: None,
                name: Vec::new(),
                path: root.to_owned(),
                depth: 0,
            });
        }
        let is_dir = meta.kind == Kind::Dir;
        w.queued.push_back(Ev::Entry(entry));
        if is_dir && w.pending.is_none() {
            // Reported, never entered: its Leave follows the Entry.
            w.queued.push_back(Ev::Leave {
                path: root.to_owned(),
                depth: 0,
                entered: false,
            });
        }
        Ok(w)
    }

    /// Whether a bound (entries, deadline) cut the walk short.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    pub fn entries(&self) -> usize {
        self.entries
    }

    /// Don't enter the directory just reported.
    pub fn prune(&mut self) {
        if let Some(p) = self.pending.take() {
            self.queued.push_back(Ev::Leave {
                path: p.path,
                depth: p.depth,
                entered: false,
            });
        }
    }

    fn over_budget(&mut self) -> bool {
        if self.entries >= self.opts.max_entries
            || self
                .opts
                .deadline
                .is_some_and(|d| self.ctx.clock.monotonic() >= d)
        {
            self.truncated = true;
        }
        self.truncated
    }

    fn enter_pending(&mut self) -> Option<Ev> {
        let p = self.pending.take()?;
        let fd = match p.fd {
            Some(fd) => Ok(fd),
            None => {
                let parent = &self.stack[p.parent?].dir;
                match parent.fd() {
                    Ok(pfd) => match CStr::from_bytes_with_nul(&p.name) {
                        Ok(c) => open_dir_at(pfd, c),
                        Err(_) => Err(io::ErrorKind::InvalidInput.into()),
                    },
                    Err(e) => Err(e.into()),
                }
            }
        };
        match fd.and_then(|fd| Ok(Dir::new(fd)?)) {
            Ok(dir) => {
                self.stack.push(Frame {
                    dir,
                    path: p.path,
                    depth: p.depth,
                });
                None
            }
            // Unreadable (permissions, raced away, now a symlink): report
            // it as not entered.
            Err(_) => Some(Ev::Leave {
                path: p.path,
                depth: p.depth,
                entered: false,
            }),
        }
    }

    /// The next event; `None` when done (or cut short: every entered
    /// directory still gets its `Leave` first).
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<Ev> {
        if let Some(ev) = self.queued.pop_front() {
            return Some(ev);
        }
        if self.pending.is_some() {
            if !self.over_budget() {
                if let Some(ev) = self.enter_pending() {
                    return Some(ev);
                }
            } else {
                self.prune();
                return self.queued.pop_front();
            }
        }
        loop {
            let top_idx = self.stack.len().checked_sub(1)?;
            if self.over_budget() {
                let f = self.stack.pop()?;
                return Some(Ev::Leave {
                    path: f.path,
                    depth: f.depth,
                    entered: true,
                });
            }
            let top = &mut self.stack[top_idx];
            let item = match top.dir.read() {
                None | Some(Err(_)) => {
                    let f = self.stack.pop()?;
                    return Some(Ev::Leave {
                        path: f.path,
                        depth: f.depth,
                        entered: true,
                    });
                }
                Some(Ok(de)) => de,
            };
            let name = item.file_name();
            let bytes = name.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            self.entries += 1;
            let Ok(dfd) = top.dir.fd() else { continue };
            let Ok(meta) = stat_at(dfd, name) else {
                continue;
            };
            let path = join(&top.path, &String::from_utf8_lossy(bytes));
            let depth = top.depth + 1;
            if meta.kind == Kind::Dir {
                let crosses = self.opts.one_fs && meta.dev != self.root_dev;
                if depth < self.opts.max_depth && !crosses {
                    self.pending = Some(PendingDir {
                        fd: None,
                        parent: Some(top_idx),
                        name: name.to_bytes_with_nul().to_vec(),
                        path: path.clone(),
                        depth,
                    });
                } else {
                    self.queued.push_back(Ev::Leave {
                        path: path.clone(),
                        depth,
                        entered: false,
                    });
                }
            }
            return Some(Ev::Entry(Entry { path, depth, meta }));
        }
    }
}

/// Small glob: `*` and `?` within one component, `**` for any number of
/// components (zero included). Everything else is literal.
pub fn glob_match(pattern: &str, path: &str) -> bool {
    let p: Vec<&str> = pattern.split('/').collect();
    let s: Vec<&str> = path.split('/').collect();
    match_components(&p, &s)
}

fn match_components(p: &[&str], s: &[&str]) -> bool {
    match p.split_first() {
        None => s.is_empty(),
        Some((&"**", rest)) => (0..=s.len()).any(|i| match_components(rest, &s[i..])),
        Some((first, rest)) => match s.split_first() {
            Some((c, srest)) => component_match(first, c) && match_components(rest, srest),
            None => false,
        },
    }
}

/// `*`/`?` wildcard match of one component (iterative, linear backtrack).
pub fn component_match(pattern: &str, s: &str) -> bool {
    let (p, s): (Vec<char>, Vec<char>) = (pattern.chars().collect(), s.chars().collect());
    let (mut pi, mut si) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, si));
            pi += 1;
        } else if let Some((sp, ss)) = star {
            pi = sp + 1;
            si = ss + 1;
            star = Some((sp, ss + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// Whether `s` has glob metacharacters.
pub fn is_glob(s: &str) -> bool {
    s.contains(['*', '?'])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ctx;
    use std::os::unix::fs::symlink;
    use std::rc::Rc;

    fn walk_all(ctx: &SysCtx, root: &str, opts: WalkOpts) -> (Vec<Ev>, bool) {
        let mut w = Walker::new(ctx, root, opts).unwrap();
        let mut v = Vec::new();
        while let Some(ev) = w.next() {
            v.push(ev);
        }
        (v, w.truncated())
    }

    fn entry_paths(evs: &[Ev]) -> Vec<String> {
        let mut v: Vec<String> = evs
            .iter()
            .filter_map(|e| match e {
                Ev::Entry(e) => Some(e.path.clone()),
                Ev::Leave { .. } => None,
            })
            .collect();
        v.sort();
        v
    }

    #[test]
    fn walks_without_following_symlinks() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        std::fs::create_dir_all(r.join("srv/a/b")).unwrap();
        std::fs::create_dir_all(r.join("etc")).unwrap();
        std::fs::write(r.join("srv/a/b/f"), "x").unwrap();
        std::fs::write(r.join("etc/shadow"), "secret").unwrap();
        symlink(r.join("etc"), r.join("srv/a/link")).unwrap();
        let c = ctx(r, Rc::new(crate::FakeRunner::new()));
        let (evs, trunc) = walk_all(&c, "/srv", WalkOpts::new(1000, 16));
        assert!(!trunc);
        assert_eq!(
            entry_paths(&evs),
            ["/srv", "/srv/a", "/srv/a/b", "/srv/a/b/f", "/srv/a/link"]
        );
        let link = evs
            .iter()
            .find_map(|e| match e {
                Ev::Entry(e) if e.path == "/srv/a/link" => Some(e.meta.kind),
                _ => None,
            })
            .unwrap();
        assert_eq!(link, Kind::Symlink);
        // Leaves balance directory entries.
        let dirs = evs
            .iter()
            .filter(|e| matches!(e, Ev::Entry(e) if e.meta.kind == Kind::Dir))
            .count();
        let leaves = evs.iter().filter(|e| matches!(e, Ev::Leave { .. })).count();
        assert_eq!(dirs, leaves);
        // A symlinked root is reported, not entered.
        let (evs, _) = walk_all(&c, "/srv/a/link", WalkOpts::new(1000, 16));
        assert_eq!(entry_paths(&evs), ["/srv/a/link"]);
        // Symlinked parent components are refused.
        assert!(Walker::new(&c, "/srv/a/link/shadow", WalkOpts::new(10, 4)).is_err());
    }

    #[test]
    fn bounds_depth_and_entries() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        std::fs::create_dir_all(r.join("x/1/2/3")).unwrap();
        for i in 0..20 {
            std::fs::write(r.join(format!("x/f{i}")), "").unwrap();
        }
        let c = ctx(r, Rc::new(crate::FakeRunner::new()));
        let (evs, trunc) = walk_all(&c, "/x", WalkOpts::new(1000, 1));
        assert!(!trunc);
        let p = entry_paths(&evs);
        assert!(p.contains(&"/x/1".to_owned()));
        assert!(!p.contains(&"/x/1/2".to_owned()));
        let (evs, trunc) = walk_all(&c, "/x", WalkOpts::new(5, 16));
        assert!(trunc);
        assert!(entry_paths(&evs).len() <= 5);
    }

    #[test]
    fn globs() {
        assert!(glob_match(
            "/etc/ssh/ssh_host_*_key",
            "/etc/ssh/ssh_host_rsa_key"
        ));
        assert!(!glob_match(
            "/etc/ssh/ssh_host_*_key",
            "/etc/ssh/ssh_host_rsa_key.pub"
        ));
        assert!(glob_match(
            "/etc/letsencrypt/**/privkey*",
            "/etc/letsencrypt/archive/x.org/privkey3.pem"
        ));
        assert!(glob_match("/srv/**/.env", "/srv/.env"));
        assert!(glob_match("/srv/**/.env", "/srv/app/deep/.env"));
        assert!(!glob_match("/srv/**/.env", "/srv/app/.envrc"));
        assert!(glob_match("/srv/*/compose.yaml", "/srv/app/compose.yaml"));
        assert!(!glob_match("/srv/*/compose.yaml", "/srv/a/b/compose.yaml"));
        assert!(component_match("a*b?c", "aXXbYc"));
        assert!(!component_match("a*b", "ac"));
        assert_eq!(components("/a/b"), Some(vec!["a", "b"]));
        assert_eq!(components("/a/../b"), None);
        assert_eq!(components("a"), None);
    }
}
