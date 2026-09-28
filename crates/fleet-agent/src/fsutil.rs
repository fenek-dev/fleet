//! Small filesystem helpers: atomic writes, modes, ownership, uid lookup.
//! No `unsafe`: uids come from file metadata, `/etc/passwd` and `/etc/group`.
//!
//! Symlink rules (design §4.1): root code never follows a path component an
//! unprivileged user can write. Ownership changes use [`lchown`]
//! (`std::os::unix::fs::lchown`), modes are set on paths inside root-only
//! directories or on open file descriptors, and key files are opened with
//! [`O_NOFOLLOW`].

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub use std::os::unix::fs::lchown;

/// `O_NOFOLLOW` for this target (libc is not a dependency; the value is a
/// fixed part of each kernel ABI).
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "powerpc",
        target_arch = "powerpc64"
    )
))]
pub const O_NOFOLLOW: i32 = 0o100000;
#[cfg(all(
    target_os = "linux",
    not(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "powerpc",
        target_arch = "powerpc64"
    ))
))]
pub const O_NOFOLLOW: i32 = 0o400000;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const O_NOFOLLOW: i32 = 0x0100;

/// Writes `bytes` to `path` atomically: a temp file in the same directory
/// (created with `mode`), fsync, rename, fsync of the directory.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    write_atomic_owned(path, bytes, mode, None)
}

/// [`write_atomic`], optionally setting `(uid, gid)` on the temp file before
/// the rename. The temp file is created `O_EXCL | O_NOFOLLOW`, and mode and
/// ownership are set on the open handle (`fchmod`, `fchown`), so they go to
/// the file just created, never through a planted symlink.
/// The final rename replaces a symlink at `path` rather than following it.
pub fn write_atomic_owned(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    owner: Option<(Option<u32>, Option<u32>)>,
) -> std::io::Result<()> {
    let dir = path.parent().ok_or(std::io::ErrorKind::InvalidInput)?;
    let name = path
        .file_name()
        .ok_or(std::io::ErrorKind::InvalidInput)?
        .to_string_lossy();
    let mut rnd = [0u8; 8];
    fleet_crypto::random_bytes(&mut rnd).map_err(|_| std::io::ErrorKind::Other)?;
    let tmp = dir.join(format!(".{name}.{}.tmp", hex::encode(rnd)));
    let res = (|| {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(O_NOFOLLOW)
            .mode(mode)
            .open(&tmp)?;
        // The umask may have narrowed `mode`; set it exactly (fchmod).
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        if let Some((uid, gid)) = owner {
            // Through the open handle (fchown): no path is resolved again,
            // so a rename-and-replace of `tmp` can't redirect it.
            std::os::unix::fs::fchown(&f, uid, gid)?;
        }
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        fs::File::open(dir)?.sync_all()
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

/// Reads a 32-byte key file straight into a wiped buffer, refusing symlinks
/// and any other length. `Ok(None)` if the file does not exist.
pub fn read_key32(path: &Path) -> std::io::Result<Option<fleet_crypto::Zeroizing<[u8; 32]>>> {
    let mut f = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let md = f.metadata()?;
    if !md.is_file() || md.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "key file is not 32 bytes",
        ));
    }
    let mut key = fleet_crypto::Zeroizing::new([0u8; 32]);
    f.read_exact(&mut key[..])?;
    Ok(Some(key))
}

/// Binds a listening Unix socket at `path` with `mode` and optional group.
///
/// The socket is bound as `<tmp_dir>/<name>.new`, given its mode and group
/// there, then renamed into place, so a client that sees `path` never gets
/// `ECONNREFUSED` or a too-permissive socket. `tmp_dir` must be writable
/// only by this process's user: `chmod`/`lchown` act on a path no other
/// user can swap for a symlink. `tmp_dir` and `path` must share a filesystem.
pub fn bind_socket(
    path: &Path,
    tmp_dir: &Path,
    mode: u32,
    gid: Option<u32>,
) -> std::io::Result<tokio::net::UnixListener> {
    let name = path
        .file_name()
        .ok_or(std::io::ErrorKind::InvalidInput)?
        .to_string_lossy();
    let tmp = tmp_dir.join(format!("{name}.new"));
    let _ = fs::remove_file(&tmp);
    let listener = tokio::net::UnixListener::bind(&tmp)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    if let Some(gid) = gid {
        lchown(&tmp, None, Some(gid))?;
    }
    fs::rename(&tmp, path)?;
    Ok(listener)
}

/// Creates `dir` (and parents) and sets its mode exactly. Refuses if `dir`
/// is a symlink. Callers only use it on directories whose parent is not
/// writable by another user, so the check can't be raced.
pub fn ensure_dir(dir: &Path, mode: u32) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    if !fs::symlink_metadata(dir)?.file_type().is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a directory", dir.display()),
        ));
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(mode))
}

/// The effective uid of this process, without creating any file.
///
/// Linux: the owner of `/proc/self` (the process's euid; `root` also when
/// the process is non-dumpable, which only happens for privileged
/// processes). Elsewhere (macOS development): the owner of an anonymous
/// pipe this process just created (`fstat` reports the creator's euid).
pub fn current_uid() -> std::io::Result<u32> {
    if let Ok(md) = fs::metadata("/proc/self") {
        return Ok(md.uid());
    }
    let (r, _w) = std::io::pipe()?;
    let f = fs::File::from(std::os::fd::OwnedFd::from(r));
    Ok(f.metadata()?.uid())
}

/// Parses `name:x:<id>:...` lines (passwd uid, group gid: third field).
fn lookup_id(file: &Path, name: &str) -> Option<u32> {
    let text = fs::read_to_string(file).ok()?;
    text.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next()? == name).then_some(())?;
        f.next()?;
        f.next()?.parse().ok()
    })
}

/// Looks up a user's uid in `passwd` (e.g. `/etc/passwd`).
pub fn lookup_uid(passwd: &Path, user: &str) -> Option<u32> {
    lookup_id(passwd, user)
}

/// Looks up a group's gid in `group` (e.g. `/etc/group`).
pub fn lookup_gid(group: &Path, name: &str) -> Option<u32> {
    lookup_id(group, name)
}

/// One `/etc/passwd` entry's ids and home.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserEntry {
    pub uid: u32,
    pub gid: u32,
    pub home: String,
}

/// `user`'s uid, primary gid and home directory.
pub fn lookup_user(passwd: &Path, user: &str) -> Option<UserEntry> {
    let text = fs::read_to_string(passwd).ok()?;
    text.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() < 7 || f[0] != user {
            return None;
        }
        Some(UserEntry {
            uid: f[2].parse().ok()?,
            gid: f[3].parse().ok()?,
            home: f[5].to_owned(),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_mode_and_passwd() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x.bin");
        write_atomic(&p, b"one", 0o600).unwrap();
        write_atomic(&p, b"two", 0o600).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        assert_eq!(fs::metadata(&p).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1, "no temp left");

        let pw = d.path().join("passwd");
        fs::write(
            &pw,
            "root:x:0:0::/root:/bin/sh\nfleet-gate:x:998:997::/:/usr/sbin/nologin\n",
        )
        .unwrap();
        assert_eq!(lookup_uid(&pw, "fleet-gate"), Some(998));
        assert_eq!(lookup_uid(&pw, "fleet"), None);
        let gr = d.path().join("group");
        fs::write(&gr, "root:x:0:\nfleet:x:996:admin\nfleet-gate:x:997:\n").unwrap();
        assert_eq!(lookup_gid(&gr, "fleet"), Some(996));
        assert_eq!(lookup_gid(&gr, "fleet-gate"), Some(997));
        assert_eq!(lookup_gid(&gr, "nope"), None);
        assert_eq!(current_uid().unwrap(), fs::metadata(&p).unwrap().uid());
    }

    #[test]
    fn key_reads_refuse_symlinks_and_bad_lengths() {
        let d = tempfile::tempdir().unwrap();
        let k = d.path().join("k");
        assert!(read_key32(&k).unwrap().is_none());
        fs::write(&k, [7u8; 32]).unwrap();
        assert_eq!(*read_key32(&k).unwrap().unwrap(), [7u8; 32]);
        let l = d.path().join("l");
        std::os::unix::fs::symlink(&k, &l).unwrap();
        assert!(read_key32(&l).is_err());
        fs::write(&k, [7u8; 31]).unwrap();
        assert!(read_key32(&k).is_err());
        // write_atomic replaces a planted symlink instead of following it.
        let target = d.path().join("target");
        fs::write(&target, b"keep").unwrap();
        let p = d.path().join("p");
        std::os::unix::fs::symlink(&target, &p).unwrap();
        write_atomic(&p, b"new", 0o600).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"keep");
        assert!(!fs::symlink_metadata(&p).unwrap().file_type().is_symlink());
    }
}
