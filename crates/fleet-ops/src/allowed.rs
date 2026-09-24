//! Opening files named by `AbsPath` arguments under an allow-list of roots
//! (`logfile.tail`, `du.scan`, config reads; design §4.2), without following
//! symlinks out of the root.
//!
//! `std` has no `openat`, so there's no component-by-component walk on
//! directory handles. Instead, [`open_allowed`]:
//!
//! 1. picks the longest allowed root the path is lexically under
//!    (`AllowedPath`), and canonicalizes that root: roots are Fleet's own
//!    configuration, so a symlinked root (`/var/run` → `/run`) is trusted;
//! 2. `lstat`s every component below the root and refuses any symlink, and
//!    requires the last one to be a regular file;
//! 3. opens the file with `O_NOFOLLOW | O_NONBLOCK` (a FIFO swapped in can't
//!    block exec) and checks that `fstat` is the same regular file (`dev`,
//!    `ino`) that step 2 saw;
//! 4. on Linux, reads `/proc/self/fd/<fd>` and requires the file actually
//!    opened to lie under the canonical root.
//!
//! **Residual TOCTOU.** A writer inside the root can swap an intermediate
//! directory for a symlink between steps 2 and 3. Step 4 catches that on
//! Linux (the only target), so the result is always a file under the root;
//! without `/proc` (macOS test builds) that window stays open. Hard links
//! are not symlinks: a file hard-linked into the root from elsewhere is
//! opened (Debian's default `fs.protected_hardlinks = 1` stops unprivileged
//! users from linking files they don't own).

use crate::ctx::SysCtx;
use crate::handler::OpError;
use fleet_proto::ErrorCode;
use fleet_proto::args::{AbsPath, AllowedPath};
use std::fs::File;
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

fn io_err(e: io::Error, what: &'static str) -> OpError {
    let code = match e.kind() {
        io::ErrorKind::NotFound => ErrorCode::NotFound,
        // ELOOP from O_NOFOLLOW: a symlink appeared in the last component.
        _ if e.raw_os_error() == Some(libc::ELOOP) => ErrorCode::InvalidArgument,
        _ => ErrorCode::Internal,
    };
    OpError::new(code).with_detail(format!("{what}: {e}"))
}

fn refused(detail: &'static str) -> OpError {
    OpError::new(ErrorCode::InvalidArgument).with_detail(detail)
}

/// Opens `path` read-only if it's a regular file under one of `roots`
/// with no symlink below the root (see the module docs).
/// `InvalidArgument` for a path outside the roots, a symlink, or anything
/// but a regular file; `NotFound` if it doesn't exist.
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
    let mut cur = root_real.clone();
    for c in dirs {
        cur.push(c);
        let m = std::fs::symlink_metadata(&cur).map_err(|e| io_err(e, "lstat"))?;
        if m.file_type().is_symlink() {
            return Err(refused("symlink in path"));
        }
        if !m.is_dir() {
            return Err(OpError::new(ErrorCode::NotFound).with_detail("not a directory"));
        }
    }
    cur.push(last);
    let before = std::fs::symlink_metadata(&cur).map_err(|e| io_err(e, "lstat"))?;
    if !before.file_type().is_file() {
        return Err(refused("not a regular file"));
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&cur)
        .map_err(|e| io_err(e, "open"))?;
    let after = file.metadata().map_err(|e| io_err(e, "fstat"))?;
    if !after.is_file() || after.dev() != before.dev() || after.ino() != before.ino() {
        return Err(refused("file changed while opening"));
    }
    check_opened_under(&file, &root_real)?;
    Ok((allowed, file))
}

#[cfg(target_os = "linux")]
fn check_opened_under(file: &File, root: &Path) -> Result<(), OpError> {
    use std::os::fd::AsRawFd;
    let real = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(|e| io_err(e, "/proc/self/fd"))?;
    if real.starts_with(root) {
        Ok(())
    } else {
        Err(refused("opened file is outside the root"))
    }
}

/// No `/proc` here (tests on macOS): see the residual TOCTOU note.
#[cfg(not(target_os = "linux"))]
fn check_opened_under(_: &File, _: &Path) -> Result<(), OpError> {
    Ok(())
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

    #[test]
    fn longest_root_wins() {
        let (_d, ctx) = setup();
        let roots = [p("/var"), p("/var/log/nginx")];
        let (a, _) = open_allowed(&ctx, &p("/var/log/nginx/access.log"), &roots).unwrap();
        assert_eq!(a.path().as_str(), "/var/log/nginx/access.log");
    }
}
