//! Root-side file writes for handlers (Compose projects, authorized keys):
//! symlink-refusing directory walks, atomic writes, content versions.
//!
//! Rules (design §4.1): every path is resolved from a directory fd, one
//! component at a time, with `openat(O_NOFOLLOW | O_DIRECTORY)` (the
//! helpers in [`crate::files::walk`]), so no component below the context
//! root can be a symlink and nothing swapped in mid-walk can redirect a
//! root write. Every *ancestor* directory is `fstat`ed on the fd the walk
//! continues from and must be owned by root (or the current euid, which is
//! root in production) and must not be group/world-writable unless sticky:
//! otherwise someone else could swap its entries. The final component is
//! only symlink-checked, so a container-chowned bind directory still
//! works. Files are replaced by an `O_EXCL | O_NOFOLLOW` temp file created
//! in the parent fd + fsync + `renameat`, with mode and owner set on the
//! open handle. Owner `root:root` is applied only when running as root
//! (tests run unprivileged).

use crate::ctx::SysCtx;
use crate::files::walk::{self, FileMeta, Kind};
use crate::handler::OpError;
use fleet_proto::ErrorCode;
use rustix::fs::{self as rfs, AtFlags, Gid, Mode, OFlags, Uid};
use std::io::{ErrorKind, Read, Write};
use std::os::fd::OwnedFd;
use std::path::PathBuf;

/// The `expected_version` of a replaced file or section
/// ([`fleet_proto::version::content_version`]).
pub fn version_of(bytes: &[u8]) -> u64 {
    fleet_proto::version::content_version(bytes)
}

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn refused(what: impl Into<String>) -> OpError {
    OpError::new(ErrorCode::PolicyDenied).with_detail(what.into())
}

fn invalid(what: impl Into<String>) -> OpError {
    OpError::new(ErrorCode::InvalidArgument).with_detail(what.into())
}

fn io(abs: &str, e: &std::io::Error) -> OpError {
    OpError::internal(format!("{abs}: {e}"))
}

fn mode_of(m: u32) -> Mode {
    Mode::from_bits_truncate((m & 0o7777) as _)
}

/// Whether an ancestor directory is safe to resolve through: owned by root
/// (or the current euid) and not writable by group/others unless sticky.
fn check_ancestor(m: &FileMeta, euid: u32, shown: &str) -> Result<(), OpError> {
    if m.uid != 0 && m.uid != euid {
        return Err(refused(format!("directory not root-owned: {shown}")));
    }
    if m.mode & 0o022 != 0 && m.mode & 0o1000 == 0 {
        return Err(refused(format!(
            "directory writable by others without sticky bit: {shown}"
        )));
    }
    Ok(())
}

/// Opens directory `name` in `dir` without following a symlink. `None` if
/// it doesn't exist; a symlink is `PolicyDenied`, a non-directory
/// `InvalidArgument`.
fn child_dir(dir: &OwnedFd, name: &str, shown: &str) -> Result<Option<OwnedFd>, OpError> {
    match walk::open_dir_at(dir, name) {
        Ok(fd) => Ok(Some(fd)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => match walk::stat_at(dir, name) {
            Ok(m) if m.kind == Kind::Symlink => Err(refused(format!("symlink in path: {shown}"))),
            Ok(m) if m.kind != Kind::Dir => Err(invalid(format!("not a directory: {shown}"))),
            _ => Err(io(shown, &e)),
        },
    }
}

/// `child_dir`, then the ancestor checks on the opened fd.
fn ancestor_dir(dir: &OwnedFd, name: &str, shown: &str) -> Result<Option<OwnedFd>, OpError> {
    let Some(fd) = child_dir(dir, name, shown)? else {
        return Ok(None);
    };
    let m = walk::meta_of(&rfs::fstat(&fd).map_err(|e| io(shown, &e.into()))?);
    check_ancestor(&m, euid(), shown)?;
    Ok(Some(fd))
}

fn comps_of(abs: &str) -> Result<Vec<&str>, OpError> {
    walk::components(abs).ok_or_else(|| invalid(abs.to_owned()))
}

/// Opens every directory of `dirs` below the context root as an ancestor.
/// `None` if one is missing.
fn open_ancestors(ctx: &SysCtx, dirs: &[&str]) -> Result<Option<OwnedFd>, OpError> {
    let mut fd = walk::open_root(ctx).map_err(|e| io("/", &e))?;
    let mut shown = String::from("/");
    for c in dirs {
        shown = walk::join(&shown, c);
        match ancestor_dir(&fd, c, &shown)? {
            Some(next) => fd = next,
            None => return Ok(None),
        }
    }
    Ok(Some(fd))
}

/// The parent fd of `abs` (ancestors checked) and the final component's
/// `lstat`, `None` where missing.
struct Resolved<'a> {
    parent: Option<OwnedFd>,
    name: &'a str,
    last: Option<FileMeta>,
}

fn resolve<'a>(ctx: &SysCtx, abs: &'a str) -> Result<Resolved<'a>, OpError> {
    let comps = comps_of(abs)?;
    let Some((name, dirs)) = comps.split_last() else {
        return Err(invalid("the root itself"));
    };
    let Some(parent) = open_ancestors(ctx, dirs)? else {
        return Ok(Resolved {
            parent: None,
            name,
            last: None,
        });
    };
    let last = match walk::stat_at(&parent, *name) {
        Ok(m) => Some(m),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => return Err(io(abs, &e)),
    };
    Ok(Resolved {
        parent: Some(parent),
        name,
        last,
    })
}

/// Result of [`walk`]: the host path and whether it exists.
pub struct Walked {
    pub path: PathBuf,
    pub exists: bool,
}

/// Resolves `abs` below the context root. Any symlink is `PolicyDenied`; a
/// missing component ends the walk (`exists: false`). Ancestors must pass
/// the ownership/permission checks; the final component is only
/// symlink-checked.
pub fn walk(ctx: &SysCtx, abs: &str) -> Result<Walked, OpError> {
    let path = ctx.path(abs).ok_or_else(|| invalid(abs.to_owned()))?;
    if abs == "/" {
        return Ok(Walked { path, exists: true });
    }
    let r = resolve(ctx, abs)?;
    let exists = match r.last {
        None => false,
        Some(m) if m.kind == Kind::Symlink => {
            return Err(refused(format!("symlink in path: {abs}")));
        }
        Some(_) => true,
    };
    Ok(Walked { path, exists })
}

/// Creates `abs` (and missing parents, 0755) with `mode`, refusing symlinks
/// anywhere on the way. An existing `abs` must be a directory; its mode is
/// left alone.
pub fn ensure_dir(ctx: &SysCtx, abs: &str, mode: u32) -> Result<PathBuf, OpError> {
    let path = ctx.path(abs).ok_or_else(|| invalid(abs.to_owned()))?;
    let comps = comps_of(abs)?;
    let mut fd = walk::open_root(ctx).map_err(|e| io("/", &e))?;
    let mut shown = String::from("/");
    let n = comps.len();
    for (i, c) in comps.iter().enumerate() {
        shown = walk::join(&shown, c);
        let last = i + 1 == n;
        let m = if last { mode } else { 0o755 };
        let next = match child_dir(&fd, c, &shown)? {
            Some(next) => next,
            None => {
                match rfs::mkdirat(&fd, *c, mode_of(m)) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(e) => return Err(io(abs, &e.into())),
                }
                let next = child_dir(&fd, c, &shown)?
                    .ok_or_else(|| OpError::internal(format!("{shown} vanished")))?;
                rfs::fchmod(&next, mode_of(m)).map_err(|e| io(abs, &e.into()))?;
                if euid() == 0 {
                    rfs::fchown(&next, Some(Uid::ROOT), Some(Gid::ROOT))
                        .map_err(|e| io(abs, &e.into()))?;
                }
                next
            }
        };
        if !last {
            let meta = walk::meta_of(&rfs::fstat(&next).map_err(|e| io(abs, &e.into()))?);
            check_ancestor(&meta, euid(), &shown)?;
        }
        fd = next;
    }
    Ok(path)
}

/// Reads a regular file (not a symlink) of at most `max` bytes; `None` if
/// it doesn't exist.
pub fn read_regular(ctx: &SysCtx, abs: &str, max: u64) -> Result<Option<Vec<u8>>, OpError> {
    let r = resolve(ctx, abs)?;
    let (Some(parent), Some(_)) = (r.parent, r.last) else {
        return Ok(None);
    };
    let fd = match rfs::openat(
        &parent,
        r.name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(rustix::io::Errno::LOOP) => return Err(refused(format!("symlink in path: {abs}"))),
        Err(e) => return Err(io(abs, &e.into())),
    };
    let m = walk::meta_of(&rfs::fstat(&fd).map_err(|e| io(abs, &e.into()))?);
    if m.kind != Kind::File {
        return Err(invalid(format!("not a regular file: {abs}")));
    }
    if m.size > max {
        return Err(invalid(format!("too large: {abs}")));
    }
    let mut buf = Vec::new();
    std::fs::File::from(fd)
        .take(max + 1)
        .read_to_end(&mut buf)
        .map_err(|e| io(abs, &e))?;
    if buf.len() as u64 > max {
        return Err(invalid(format!("too large: {abs}")));
    }
    Ok(Some(buf))
}

/// Replaces `abs` atomically with `bytes` (mode `mode`, owner root when
/// running as root). The parent directory must exist and pass the ancestor
/// checks; the final `renameat` replaces a symlink at `abs` rather than
/// following it.
pub fn write_atomic(ctx: &SysCtx, abs: &str, bytes: &[u8], mode: u32) -> Result<(), OpError> {
    let comps = comps_of(abs)?;
    let Some((name, dirs)) = comps.split_last() else {
        return Err(invalid("the root itself"));
    };
    let Some(dir) = open_ancestors(ctx, dirs)? else {
        let parent = abs.rsplit_once('/').map_or("/", |(p, _)| p);
        return Err(OpError::new(ErrorCode::NotFound).with_detail(parent.to_owned()));
    };
    let mut rnd = [0u8; 8];
    fleet_crypto::random_bytes(&mut rnd).map_err(OpError::internal)?;
    let suffix: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    let tmp = format!(".{name}.{suffix}.tmp");
    let fd = rfs::openat(
        &dir,
        tmp.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        mode_of(mode),
    )
    .map_err(|e| io(abs, &e.into()))?;
    let res = (|| -> std::io::Result<()> {
        rfs::fchmod(&fd, mode_of(mode))?;
        if euid() == 0 {
            rfs::fchown(&fd, Some(Uid::ROOT), Some(Gid::ROOT))?;
        }
        let mut f = std::fs::File::from(fd);
        f.write_all(bytes)?;
        f.sync_all()?;
        rfs::renameat(&dir, tmp.as_str(), &dir, *name)?;
        Ok(rfs::fsync(&dir)?)
    })();
    if let Err(e) = res {
        let _ = rfs::unlinkat(&dir, tmp.as_str(), AtFlags::empty());
        return Err(io(abs, &e));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FakeRunner;
    use crate::testutil::ctx;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::rc::Rc;

    fn chmod(p: &Path, m: u32) {
        fs::set_permissions(p, fs::Permissions::from_mode(m)).unwrap();
    }

    #[test]
    fn walk_refuses_symlinks_and_creates_dirs() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path(), Rc::new(FakeRunner::new()));
        let p = ensure_dir(&c, "/srv/app", 0o750).unwrap();
        let m = fs::metadata(&p).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o750);
        assert!(walk(&c, "/srv/app/x").map(|w| !w.exists).unwrap());
        assert!(walk(&c, "/srv/app").unwrap().exists);

        std::os::unix::fs::symlink("/etc", d.path().join("srv/evil")).unwrap();
        for abs in ["/srv/evil", "/srv/evil/x"] {
            assert_eq!(walk(&c, abs).err().unwrap().code(), ErrorCode::PolicyDenied);
        }
        assert_eq!(
            ensure_dir(&c, "/srv/evil/sub", 0o750).unwrap_err().code(),
            ErrorCode::PolicyDenied
        );
        assert_eq!(
            ensure_dir(&c, "/srv/evil", 0o750).unwrap_err().code(),
            ErrorCode::PolicyDenied
        );
        assert!(!Path::new("/etc/sub").exists());
        fs::write(d.path().join("srv/file"), "x").unwrap();
        assert_eq!(
            walk(&c, "/srv/file/x").err().unwrap().code(),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn ancestor_checks_table() {
        let me = 1000;
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
        for (uid, mode, ok) in [
            (0, 0o755, true),
            (me, 0o700, true),
            (0, 0o1777, true),  // /tmp
            (0, 0o1730, true),  // crontabs
            (0, 0o775, false),  // group-writable
            (0, 0o757, false),  // world-writable
            (0, 0o2775, false), // setgid is not sticky
            (1001, 0o755, false),
            (1001, 0o1777, false),
        ] {
            assert_eq!(
                check_ancestor(&meta(uid, mode), me, "/x").is_ok(),
                ok,
                "{uid} {mode:o}"
            );
        }
    }

    /// Writable-without-sticky ancestors are refused; the final component
    /// (a container bind dir, say) isn't permission-checked.
    #[test]
    fn writable_ancestor_refused_final_dir_free() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path(), Rc::new(FakeRunner::new()));
        ensure_dir(&c, "/srv/app/data", 0o755).unwrap();
        let app = d.path().join("srv/app");
        let data = app.join("data");
        chmod(&data, 0o777);
        assert!(walk(&c, "/srv/app/data").unwrap().exists);
        write_atomic(&c, "/srv/app/f", b"x", 0o640).unwrap();
        for (mode, ok) in [
            (0o777, false),
            (0o775, false),
            (0o1777, true),
            (0o755, true),
        ] {
            chmod(&app, mode);
            let code = |r: Result<(), OpError>| r.err().map(|e| e.code());
            let want = if ok {
                None
            } else {
                Some(ErrorCode::PolicyDenied)
            };
            assert_eq!(
                code(walk(&c, "/srv/app/data").map(|_| ())),
                want,
                "{mode:o}"
            );
            assert_eq!(code(read_regular(&c, "/srv/app/f", 9).map(|_| ())), want);
            assert_eq!(code(write_atomic(&c, "/srv/app/f", b"y", 0o640)), want);
            assert_eq!(
                code(ensure_dir(&c, "/srv/app/new", 0o755).map(|_| ())),
                want
            );
        }
    }

    #[test]
    fn atomic_write_replaces_symlink_instead_of_following() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path(), Rc::new(FakeRunner::new()));
        ensure_dir(&c, "/etc/x", 0o755).unwrap();
        let target = d.path().join("target");
        fs::write(&target, "keep").unwrap();
        std::os::unix::fs::symlink(&target, d.path().join("etc/x/f")).unwrap();
        assert_eq!(
            read_regular(&c, "/etc/x/f", 10).unwrap_err().code(),
            ErrorCode::PolicyDenied
        );
        write_atomic(&c, "/etc/x/f", b"new", 0o644).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep");
        assert_eq!(read_regular(&c, "/etc/x/f", 10).unwrap().unwrap(), b"new");
        let m = fs::symlink_metadata(d.path().join("etc/x/f")).unwrap();
        assert!(m.is_file());
        assert_eq!(m.permissions().mode() & 0o777, 0o644);
        assert_eq!(
            read_regular(&c, "/etc/x/f", 2).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
        assert!(read_regular(&c, "/etc/x/none", 2).unwrap().is_none());
        assert!(read_regular(&c, "/etc/y/none", 2).unwrap().is_none());
        assert_eq!(
            write_atomic(&c, "/etc/y/f", b"", 0o644).unwrap_err().code(),
            ErrorCode::NotFound
        );
        // No temp files left behind.
        let names: Vec<_> = fs::read_dir(d.path().join("etc/x"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["f"]);
        assert_ne!(version_of(b"a"), version_of(b"b"));
    }

    #[test]
    fn symlinked_parent_refused_for_writes() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path(), Rc::new(FakeRunner::new()));
        ensure_dir(&c, "/etc", 0o755).unwrap();
        let out = d.path().join("out");
        fs::create_dir(&out).unwrap();
        std::os::unix::fs::symlink(&out, d.path().join("etc/fleet")).unwrap();
        assert_eq!(
            write_atomic(&c, "/etc/fleet/k", b"x", 0o644)
                .unwrap_err()
                .code(),
            ErrorCode::PolicyDenied
        );
        assert!(fs::read_dir(&out).unwrap().next().is_none());
    }
}
