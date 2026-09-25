//! Opening files named by `AbsPath` arguments under an allow-list of roots
//! (`logfile.tail`, `du.scan`, config reads; design §4.2), without following
//! symlinks out of the root.
//!
//! [`open_allowed`]:
//!
//! 1. picks the longest allowed root the path is lexically under
//!    (`AllowedPath`), and canonicalizes that root: roots are Fleet's own
//!    configuration, so a symlinked root (`/var/run` → `/run`) is trusted;
//! 2. opens the root, then every directory below it from the previous
//!    directory fd with `openat(O_NOFOLLOW | O_DIRECTORY)`
//!    ([`crate::files::walk`]), so no symlink below the root is followed
//!    and nothing swapped in mid-walk can redirect the open;
//! 3. opens the file itself from its parent fd with `O_NOFOLLOW |
//!    O_NONBLOCK` (a FIFO swapped in can't block exec) and requires `fstat`
//!    to say regular file;
//! 4. refuses a file with more than one hard link when any directory from
//!    the root down is writable by a non-root user: a hard link is not a
//!    symlink, so such a user could otherwise link a file from outside the
//!    root (`/etc/shadow`) into it;
//! 5. on Linux, reads `/proc/self/fd/<fd>` and requires it to name exactly
//!    the expected path under the canonical root.

use crate::ctx::SysCtx;
use crate::files::walk::{self, FileMeta, Kind};
use crate::handler::OpError;
use fleet_proto::ErrorCode;
use fleet_proto::args::{AbsPath, AllowedPath};
use rustix::fs::{self as rfs, Mode, OFlags};
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;

fn io_err(e: io::Error, what: &'static str) -> OpError {
    let code = match e.kind() {
        io::ErrorKind::NotFound => ErrorCode::NotFound,
        // ELOOP from O_NOFOLLOW: a symlink appeared in the last component.
        _ if e.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) => {
            ErrorCode::InvalidArgument
        }
        _ => ErrorCode::Internal,
    };
    OpError::new(code).with_detail(format!("{what}: {e}"))
}

fn refused(detail: &'static str) -> OpError {
    OpError::new(ErrorCode::InvalidArgument).with_detail(detail)
}

/// A user other than root can add entries (hard links) to this directory.
fn writable_by_non_root(m: &FileMeta) -> bool {
    (m.uid != 0 && m.mode & 0o200 != 0) || m.mode & 0o022 != 0
}

fn fstat_meta(fd: &OwnedFd) -> Result<FileMeta, OpError> {
    rfs::fstat(fd)
        .map(|st| walk::meta_of(&st))
        .map_err(|e| io_err(e.into(), "fstat"))
}

/// Opens `path` read-only if it's a regular file under one of `roots`
/// with no symlink below the root (see the module docs).
/// `InvalidArgument` for a path outside the roots, a symlink, a refused
/// hard link or anything but a regular file; `NotFound` if it doesn't
/// exist.
pub fn open_allowed<'a>(
    ctx: &SysCtx,
    path: &AbsPath,
    roots: impl IntoIterator<Item = &'a AbsPath>,
) -> Result<(AllowedPath, File), OpError> {
    let root = roots
        .into_iter()
        .filter(|r| path.is_under(r))
        .max_by_key(|r| r.as_str().len())
        .ok_or_else(|| refused("path outside the allowed roots"))?;
    let allowed = AllowedPath::new(path, [root]).map_err(|_| refused("not allowed"))?;
    let root_real = ctx
        .path(root.as_str())
        .ok_or_else(|| refused("root"))?
        .canonicalize()
        .map_err(|e| io_err(e, "allowed root"))?;
    let rest = path.as_str()[root.as_str().len()..].trim_start_matches('/');
    let comps: Vec<&str> = rest.split('/').filter(|c| !c.is_empty()).collect();
    let Some((last, dirs)) = comps.split_last() else {
        return Err(refused("the root itself is not a file"));
    };
    let mut dir = rfs::open(
        &root_real,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| io_err(e.into(), "allowed root"))?;
    let mut writable = writable_by_non_root(&fstat_meta(&dir)?);
    for c in dirs {
        dir = match walk::open_dir_at(&dir, *c) {
            Ok(fd) => fd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(io_err(e, "open")),
            Err(e) => {
                return Err(match walk::stat_at(&dir, *c) {
                    Ok(m) if m.kind == Kind::Symlink => refused("symlink in path"),
                    Ok(m) if m.kind != Kind::Dir => {
                        OpError::new(ErrorCode::NotFound).with_detail("not a directory")
                    }
                    _ => io_err(e, "open"),
                });
            }
        };
        writable |= writable_by_non_root(&fstat_meta(&dir)?);
    }
    let fd = rfs::openat(
        &dir,
        *last,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| io_err(e.into(), "open"))?;
    let meta = fstat_meta(&fd)?;
    if meta.kind != Kind::File {
        return Err(refused("not a regular file"));
    }
    if meta.nlink > 1 && writable {
        return Err(refused(
            "hard-linked file under a non-root-writable directory",
        ));
    }
    let mut expected = root_real;
    expected.extend(&comps);
    walk::check_fd_path(&fd, &expected).map_err(|e| match e.kind() {
        io::ErrorKind::PermissionDenied => refused("opened file is not at the expected path"),
        _ => io_err(e, "/proc/self/fd"),
    })?;
    Ok((allowed, File::from(fd)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FakeRunner, ManualClock};
    use std::io::Read;
    use std::os::unix::fs::symlink;
    use std::rc::Rc;

    fn p(s: &str) -> AbsPath {
        AbsPath::new(s).unwrap()
    }

    fn setup() -> (tempfile::TempDir, SysCtx) {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        std::fs::create_dir_all(r.join("var/log/nginx")).unwrap();
        std::fs::create_dir_all(r.join("etc")).unwrap();
        std::fs::write(r.join("var/log/syslog"), "hello").unwrap();
        std::fs::write(r.join("var/log/nginx/access.log"), "get").unwrap();
        std::fs::write(r.join("etc/shadow"), "secret").unwrap();
        symlink(r.join("etc/shadow"), r.join("var/log/evil")).unwrap();
        symlink(r.join("etc"), r.join("var/log/etcdir")).unwrap();
        std::fs::create_dir_all(r.join("srv")).unwrap();
        symlink(r.join("var/log"), r.join("srv/logs")).unwrap();
        let ctx = SysCtx::new(r, Rc::new(FakeRunner::new()), Rc::new(ManualClock::new(0)));
        (dir, ctx)
    }

    fn open(ctx: &SysCtx, path: &str, roots: &[AbsPath]) -> Result<String, ErrorCode> {
        let (_, mut f) = open_allowed(ctx, &p(path), roots).map_err(|e| e.code())?;
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        Ok(s)
    }

    #[test]
    fn opens_regular_files_under_the_root() {
        let (_d, ctx) = setup();
        let roots = [p("/var/log")];
        assert_eq!(open(&ctx, "/var/log/syslog", &roots).unwrap(), "hello");
        assert_eq!(
            open(&ctx, "/var/log/nginx/access.log", &roots).unwrap(),
            "get"
        );
        assert_eq!(
            open(&ctx, "/var/log/missing", &roots),
            Err(ErrorCode::NotFound)
        );
    }

    #[test]
    fn refuses_symlinks_dirs_and_outside_paths() {
        let (_d, ctx) = setup();
        let roots = [p("/var/log")];
        let bad = ErrorCode::InvalidArgument;
        assert_eq!(open(&ctx, "/etc/shadow", &roots), Err(bad));
        assert_eq!(open(&ctx, "/var/log/evil", &roots), Err(bad));
        assert_eq!(open(&ctx, "/var/log/etcdir/shadow", &roots), Err(bad));
        assert_eq!(open(&ctx, "/var/log/nginx", &roots), Err(bad));
        assert_eq!(open(&ctx, "/var/log", &roots), Err(bad));
        assert_eq!(open(&ctx, "/var/logs/x", &roots), Err(bad));
    }

    #[test]
    fn symlinked_root_is_trusted() {
        let (_d, ctx) = setup();
        let roots = [p("/srv/logs")];
        assert_eq!(open(&ctx, "/srv/logs/syslog", &roots).unwrap(), "hello");
        assert_eq!(
            open(&ctx, "/srv/logs/evil", &roots),
            Err(ErrorCode::InvalidArgument)
        );
    }

    /// Test directories are owned by the (non-root) test user, so they
    /// count as non-root-writable: hard-linked files are refused.
    #[test]
    fn refuses_hard_links_under_user_writable_roots() {
        let (d, ctx) = setup();
        let roots = [p("/var/log")];
        std::fs::hard_link(d.path().join("etc/shadow"), d.path().join("var/log/hl")).unwrap();
        assert_eq!(
            open(&ctx, "/var/log/hl", &roots),
            Err(ErrorCode::InvalidArgument)
        );
        // The original is now nlink 2 as well.
        assert_eq!(
            open(&ctx, "/etc/shadow", &[p("/etc")]),
            Err(ErrorCode::InvalidArgument)
        );
        let meta = |uid, mode| FileMeta {
            kind: Kind::Dir,
            dev: 0,
            ino: 0,
            size: 0,
            alloc: 0,
            mode,
            uid,
            gid: 0,
            mtime_ns: 0,
            nlink: 2,
        };
        for (uid, mode, w) in [
            (0, 0o755, false),
            (0, 0o775, true),
            (0, 0o1777, true),
            (1000, 0o755, true),
            (1000, 0o555, false),
        ] {
            assert_eq!(writable_by_non_root(&meta(uid, mode)), w, "{uid} {mode:o}");
        }
    }

    #[test]
    fn longest_root_wins() {
        let (_d, ctx) = setup();
        let roots = [p("/var"), p("/var/log/nginx")];
        let (a, _) = open_allowed(&ctx, &p("/var/log/nginx/access.log"), &roots).unwrap();
        assert_eq!(a.path().as_str(), "/var/log/nginx/access.log");
    }
}
