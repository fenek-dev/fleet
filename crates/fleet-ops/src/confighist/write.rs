//! Atomic, symlink-safe file replacement for `config.rollback`.

use crate::ctx::SysCtx;
use crate::files::walk::{Kind, open_parent, stat_at};
use rustix::fs::{self as rfs, AtFlags, Gid, Mode, OFlags, Uid};
use std::io::{self, Write};

use super::rules::TMP_MARKER;

/// Ownership and permissions to give a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Perms {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

#[allow(clippy::cast_possible_truncation, clippy::unnecessary_cast)]
fn mode(bits: u32) -> Mode {
    Mode::from_raw_mode((bits & 0o7777) as _)
}

/// Replaces `abs` with `data`: parent resolved without symlinks, temp file
/// `O_CREAT|O_EXCL|O_NOFOLLOW` in the same directory, owner and mode set
/// before the content becomes visible, `fsync`, `renameat` over the
/// target, `fsync` of the directory. An existing target keeps its own
/// mode and owner; `fallback` (special bits masked off) applies when it's
/// missing. A target that is
/// a symlink, directory or anything but a regular file is refused.
pub fn replace(
    ctx: &SysCtx,
    abs: &str,
    data: &[u8],
    fallback: Perms,
    tag: u64,
) -> io::Result<Perms> {
    let (dir, name) = open_parent(ctx, abs)?;
    let perms = match stat_at(&dir, name) {
        Ok(m) if m.kind == Kind::File => Perms {
            mode: m.mode,
            uid: m.uid,
            gid: m.gid,
        },
        Ok(_) => return Err(io::Error::other("target is not a regular file")),
        // Recreated from history: never setuid, setgid or sticky.
        Err(e) if e.kind() == io::ErrorKind::NotFound => Perms {
            mode: fallback.mode & 0o777,
            ..fallback
        },
        Err(e) => return Err(e),
    };
    let tmp = format!(".{name}{TMP_MARKER}{tag}");
    let fd = rfs::openat(
        &dir,
        tmp.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        mode(0o600),
    )?;
    let result = (|| -> io::Result<()> {
        let mut f = std::fs::File::from(fd);
        f.write_all(data)?;
        let cur = crate::files::walk::meta_of(&rfs::fstat(&f)?);
        if (cur.uid, cur.gid) != (perms.uid, perms.gid) {
            rfs::fchown(
                &f,
                Some(Uid::from_raw(perms.uid)),
                Some(Gid::from_raw(perms.gid)),
            )?;
        }
        rfs::fchmod(&f, mode(perms.mode))?;
        f.sync_all()?;
        rfs::renameat(&dir, tmp.as_str(), &dir, name)?;
        Ok(())
    })();
    if let Err(e) = result {
        let _ = rfs::unlinkat(&dir, tmp.as_str(), AtFlags::empty());
        return Err(e);
    }
    let _ = rfs::fsync(&dir);
    Ok(perms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ctx;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::rc::Rc;

    #[test]
    fn replaces_atomically_keeping_mode() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        std::fs::create_dir_all(r.join("etc")).unwrap();
        std::fs::write(r.join("etc/a.conf"), "old").unwrap();
        std::fs::set_permissions(r.join("etc/a.conf"), std::fs::Permissions::from_mode(0o640))
            .unwrap();
        let c = ctx(r, Rc::new(crate::FakeRunner::new()));
        let me = crate::files::walk::stat_path(&c, "/etc/a.conf").unwrap();
        let fb = Perms {
            mode: 0o644,
            uid: me.uid,
            gid: me.gid,
        };
        let p = replace(&c, "/etc/a.conf", b"new", fb, 1).unwrap();
        assert_eq!(p.mode, 0o640);
        assert_eq!(std::fs::read(r.join("etc/a.conf")).unwrap(), b"new");
        let m = std::fs::metadata(r.join("etc/a.conf")).unwrap();
        assert_eq!(m.permissions().mode() & 0o7777, 0o640);
        // Missing target: fallback perms.
        replace(&c, "/etc/b.conf", b"b", fb, 2).unwrap();
        let m = std::fs::metadata(r.join("etc/b.conf")).unwrap();
        assert_eq!(m.permissions().mode() & 0o7777, 0o644);
        // Recreated with setuid/setgid/sticky in the version: masked off.
        for (bits, want) in [(0o4755, 0o755), (0o2750, 0o750), (0o1777, 0o777)] {
            std::fs::remove_file(r.join("etc/b.conf")).unwrap();
            let p = replace(&c, "/etc/b.conf", b"b", Perms { mode: bits, ..fb }, 3).unwrap();
            assert_eq!(p.mode, want);
            let m = std::fs::metadata(r.join("etc/b.conf")).unwrap();
            assert_eq!(m.permissions().mode() & 0o7777, want, "{bits:o}");
        }
        // No temp files left.
        let names: Vec<_> = std::fs::read_dir(r.join("etc"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names.len(), 2, "{names:?}");
    }

    #[test]
    fn refuses_symlinks() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        std::fs::create_dir_all(r.join("etc/real")).unwrap();
        std::fs::create_dir_all(r.join("outside")).unwrap();
        std::fs::write(r.join("outside/target"), "keep").unwrap();
        symlink(r.join("outside/target"), r.join("etc/link")).unwrap();
        symlink(r.join("outside"), r.join("etc/dirlink")).unwrap();
        let c = ctx(r, Rc::new(crate::FakeRunner::new()));
        let fb = Perms {
            mode: 0o644,
            uid: 0,
            gid: 0,
        };
        assert!(replace(&c, "/etc/link", b"x", fb, 1).is_err());
        assert!(replace(&c, "/etc/dirlink/target", b"x", fb, 1).is_err());
        assert!(replace(&c, "/etc/real", b"x", fb, 1).is_err());
        assert_eq!(std::fs::read(r.join("outside/target")).unwrap(), b"keep");
    }
}
