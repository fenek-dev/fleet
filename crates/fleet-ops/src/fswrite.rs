//! Root-side file writes for handlers (Compose projects, authorized keys):
//! symlink-refusing directory walks, atomic writes, content versions.
//!
//! Rules (design §4.1): no path component below the context root may be a
//! symlink (a container or user could plant one to redirect a root write);
//! files are replaced by `O_EXCL | O_NOFOLLOW` temp file + fsync + rename,
//! with mode and owner set on the open handle. Owner `root:root` is applied
//! only when running as root (tests run unprivileged).

use crate::ctx::SysCtx;
use crate::handler::OpError;
use fleet_proto::ErrorCode;
use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// First 8 bytes (LE) of BLAKE3: the `expected_version` of a replaced
/// file or section.
pub fn version_of(bytes: &[u8]) -> u64 {
    let h = blake3::hash(bytes);
    let mut b = [0u8; 8];
    b.copy_from_slice(&h.as_bytes()[..8]);
    u64::from_le_bytes(b)
}

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn refused(what: impl Into<String>) -> OpError {
    OpError::new(ErrorCode::PolicyDenied).with_detail(what.into())
}

fn io(abs: &str, e: &std::io::Error) -> OpError {
    OpError::internal(format!("{abs}: {e}"))
}

/// Result of [`walk`]: the host path and whether it exists.
pub struct Walked {
    pub path: PathBuf,
    pub exists: bool,
}

/// `lstat`s every component of `abs` below the context root. Any symlink
/// is `PolicyDenied`; a missing component ends the walk (`exists: false`).
/// Every existing directory on the way must be owned by root (or, in
/// tests, by the current user) so nobody else can swap its entries.
pub fn walk(ctx: &SysCtx, abs: &str) -> Result<Walked, OpError> {
    let path = ctx
        .path(abs)
        .ok_or_else(|| OpError::new(ErrorCode::InvalidArgument).with_detail(abs.to_owned()))?;
    let rel = path.strip_prefix(ctx.root()).unwrap_or(&path).to_path_buf();
    let mut cur = ctx.root().to_path_buf();
    let n = rel.components().count();
    for (i, c) in rel.components().enumerate() {
        cur.push(c);
        let m = match fs::symlink_metadata(&cur) {
            Ok(m) => m,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Ok(Walked {
                    path,
                    exists: false,
                });
            }
            Err(e) => return Err(io(abs, &e)),
        };
        if m.file_type().is_symlink() {
            return Err(refused(format!("symlink in path: {}", cur.display())));
        }
        let last = i + 1 == n;
        if !last && !m.is_dir() {
            return Err(OpError::new(ErrorCode::InvalidArgument)
                .with_detail(format!("not a directory: {}", cur.display())));
        }
        if m.is_dir() && m.uid() != 0 && m.uid() != euid() {
            return Err(refused(format!(
                "directory not root-owned: {}",
                cur.display()
            )));
        }
    }
    Ok(Walked { path, exists: true })
}

/// Creates `abs` (and missing parents, 0755) with `mode`, refusing symlinks
/// anywhere on the way. An existing `abs` must be a directory; its mode is
/// left alone.
pub fn ensure_dir(ctx: &SysCtx, abs: &str, mode: u32) -> Result<PathBuf, OpError> {
    let w = walk(ctx, abs)?;
    if w.exists {
        if !fs::symlink_metadata(&w.path)
            .map_err(|e| io(abs, &e))?
            .is_dir()
        {
            return Err(OpError::new(ErrorCode::InvalidArgument)
                .with_detail(format!("not a directory: {abs}")));
        }
        return Ok(w.path);
    }
    let rel = w.path.strip_prefix(ctx.root()).unwrap_or(&w.path);
    let mut cur = ctx.root().to_path_buf();
    let n = rel.components().count();
    for (i, c) in rel.components().enumerate() {
        cur.push(c);
        let m = if i + 1 == n { mode } else { 0o755 };
        match fs::DirBuilder::new().mode(m).create(&cur) {
            Ok(()) => {
                fs::set_permissions(&cur, fs::Permissions::from_mode(m))
                    .map_err(|e| io(abs, &e))?;
                if euid() == 0 {
                    std::os::unix::fs::lchown(&cur, Some(0), Some(0)).map_err(|e| io(abs, &e))?;
                }
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io(abs, &e)),
        }
    }
    // Re-check: a component could have been swapped for a symlink while
    // creating.
    walk(ctx, abs)?;
    Ok(w.path)
}

/// Reads a regular file (not a symlink) of at most `max` bytes; `None` if
/// it doesn't exist.
pub fn read_regular(ctx: &SysCtx, abs: &str, max: u64) -> Result<Option<Vec<u8>>, OpError> {
    let w = walk(ctx, abs)?;
    if !w.exists {
        return Ok(None);
    }
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&w.path)
        .map_err(|e| io(abs, &e))?;
    let m = f.metadata().map_err(|e| io(abs, &e))?;
    if !m.is_file() {
        return Err(OpError::new(ErrorCode::InvalidArgument)
            .with_detail(format!("not a regular file: {abs}")));
    }
    if m.len() > max {
        return Err(
            OpError::new(ErrorCode::InvalidArgument).with_detail(format!("too large: {abs}"))
        );
    }
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(&f, max + 1), &mut buf)
        .map_err(|e| io(abs, &e))?;
    Ok(Some(buf))
}

/// Replaces `abs` atomically with `bytes` (mode `mode`, owner root when
/// running as root). The parent directory must exist and pass [`walk`];
/// the final rename replaces a symlink at `abs` rather than following it.
pub fn write_atomic(ctx: &SysCtx, abs: &str, bytes: &[u8], mode: u32) -> Result<(), OpError> {
    let path = ctx
        .path(abs)
        .ok_or_else(|| OpError::new(ErrorCode::InvalidArgument).with_detail(abs.to_owned()))?;
    let dir = path.parent().ok_or_else(|| OpError::internal(abs))?;
    let parent_abs = Path::new(abs)
        .parent()
        .and_then(Path::to_str)
        .ok_or_else(|| OpError::internal(abs))?;
    if !walk(ctx, parent_abs)?.exists {
        return Err(OpError::new(ErrorCode::NotFound).with_detail(parent_abs.to_owned()));
    }
    let name = path
        .file_name()
        .ok_or_else(|| OpError::internal(abs))?
        .to_string_lossy()
        .into_owned();
    let mut rnd = [0u8; 8];
    fleet_crypto::random_bytes(&mut rnd).map_err(OpError::internal)?;
    let suffix: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    let tmp = dir.join(format!(".{name}.{suffix}.tmp"));
    let res = (|| -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(mode)
            .open(&tmp)?;
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        if euid() == 0 {
            std::os::unix::fs::fchown(&f, Some(0), Some(0))?;
        }
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, &path)?;
        fs::File::open(dir)?.sync_all()
    })();
    if let Err(e) = res {
        let _ = fs::remove_file(&tmp);
        return Err(io(abs, &e));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FakeRunner;
    use crate::testutil::ctx;
    use std::rc::Rc;

    #[test]
    fn walk_refuses_symlinks_and_creates_dirs() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path(), Rc::new(FakeRunner::new()));
        let p = ensure_dir(&c, "/srv/app", 0o750).unwrap();
        let m = fs::metadata(&p).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o750);
        assert!(walk(&c, "/srv/app/x").map(|w| !w.exists).unwrap());

        std::os::unix::fs::symlink("/etc", d.path().join("srv/evil")).unwrap();
        for abs in ["/srv/evil", "/srv/evil/x"] {
            assert_eq!(walk(&c, abs).err().unwrap().code(), ErrorCode::PolicyDenied);
        }
        assert_eq!(
            ensure_dir(&c, "/srv/evil/sub", 0o750).unwrap_err().code(),
            ErrorCode::PolicyDenied
        );
        assert!(!Path::new("/etc/sub").exists());
    }

    #[test]
    fn atomic_write_replaces_symlink_instead_of_following() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path(), Rc::new(FakeRunner::new()));
        ensure_dir(&c, "/etc/x", 0o755).unwrap();
        let target = d.path().join("target");
        fs::write(&target, "keep").unwrap();
        std::os::unix::fs::symlink(&target, d.path().join("etc/x/f")).unwrap();
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
        assert_ne!(version_of(b"a"), version_of(b"b"));
    }
}
