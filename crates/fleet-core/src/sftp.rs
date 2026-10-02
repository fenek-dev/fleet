//! SFTP file access (design §2.3) over the server's one SSH connection.
//!
//! File contents never go through the agent (design §4.2: "file contents go
//! over SFTP"); everything read here is untrusted server data (rule 6).
//! Remote paths are validated ([`remote_path`]) before they reach the
//! protocol; names, owners and contents are shown, never interpreted.

use crate::ssh::{SshConnection, SshError};
use russh_sftp::client::error::Error as RawError;
use russh_sftp::client::{RawSftpSession, SftpSession};
use russh_sftp::protocol::{FileAttributes, FileType, OpenFlags, Packet, StatusCode};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Largest file the in-place editor loads.
pub const MAX_EDIT_BYTES: u64 = 4 * 1024 * 1024;
/// PATH_MAX.
pub const MAX_PATH: usize = 4096;
const COPY_BUF: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SftpError {
    #[error("invalid remote path")]
    InvalidPath,
    #[error("no such file")]
    NotFound,
    #[error("permission denied")]
    PermissionDenied,
    #[error("already exists")]
    Exists,
    /// Larger than the caller's limit.
    #[error("file too large ({size} bytes)")]
    TooLarge { size: u64 },
    /// Changed on the server since it was read (edit-in-place conflict).
    #[error("file changed on the server")]
    Changed,
    #[error("local file: {0}")]
    Local(String),
    #[error("sftp: {0}")]
    Failed(String),
}

impl From<RawError> for SftpError {
    fn from(e: RawError) -> Self {
        match &e {
            RawError::Status(s) => match s.status_code {
                StatusCode::NoSuchFile => SftpError::NotFound,
                StatusCode::PermissionDenied => SftpError::PermissionDenied,
                _ => SftpError::Failed(e.to_string()),
            },
            _ => SftpError::Failed(e.to_string()),
        }
    }
}

impl From<SshError> for SftpError {
    fn from(e: SshError) -> Self {
        SftpError::Failed(e.to_string())
    }
}

/// An absolute path without NUL, at most [`MAX_PATH`] bytes.
pub fn remote_path(p: &str) -> Result<String, SftpError> {
    if p.starts_with('/') && p.len() <= MAX_PATH && !p.contains('\0') {
        Ok(p.to_string())
    } else {
        Err(SftpError::InvalidPath)
    }
}

/// `parent` + `/` + one path component (no `/`, not `.`/`..`).
pub fn join(parent: &str, name: &str) -> Result<String, SftpError> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(SftpError::InvalidPath);
    }
    let parent = remote_path(parent)?;
    let sep = if parent.ends_with('/') { "" } else { "/" };
    remote_path(&format!("{parent}{sep}{name}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    Other,
}

/// One directory entry or `stat` result. Untrusted strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteEntry {
    pub name: String,
    pub path: String,
    pub kind: EntryKind,
    pub size: u64,
    /// Permission bits (`mode & 0o7777`).
    pub mode: u32,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub mtime_s: Option<u32>,
}

fn entry(name: String, path: String, a: &FileAttributes) -> RemoteEntry {
    let kind = match a.file_type() {
        FileType::Dir => EntryKind::Dir,
        FileType::File => EntryKind::File,
        FileType::Symlink => EntryKind::Symlink,
        FileType::Other => EntryKind::Other,
    };
    RemoteEntry {
        name,
        path,
        kind,
        size: a.size.unwrap_or(0),
        mode: a.permissions.unwrap_or(0) & 0o7777,
        uid: a.uid,
        gid: a.gid,
        user: a.user.clone(),
        group: a.group.clone(),
        mtime_s: a.mtime,
    }
}

fn base_name(path: &str) -> String {
    path.rsplit('/')
        .find(|s| !s.is_empty())
        .unwrap_or("/")
        .to_string()
}

/// `posix-rename@openssh.com` (replaces the target atomically; plain SFTP v3
/// rename refuses an existing target).
const POSIX_RENAME: &str = "posix-rename@openssh.com";

/// SSH `string` encoding.
fn put_string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// `dir` and base name of an absolute path.
fn split_parent(path: &str) -> Result<(&str, &str), SftpError> {
    let (dir, name) = path.rsplit_once('/').ok_or(SftpError::InvalidPath)?;
    if name.is_empty() || name == "." || name == ".." {
        return Err(SftpError::InvalidPath);
    }
    Ok((if dir.is_empty() { "/" } else { dir }, name))
}

/// SFTP subsystem channels: the high-level session, plus a raw one for the
/// `posix-rename@openssh.com` extension the high-level API lacks.
pub struct Sftp {
    s: SftpSession,
    raw: RawSftpSession,
    posix_rename: bool,
}

impl Sftp {
    pub async fn open(conn: &SshConnection) -> Result<Self, SftpError> {
        let s = conn.open_sftp().await?;
        let raw = conn.open_raw_sftp().await?;
        let version = raw.init().await?;
        let posix_rename = version
            .extensions
            .get(POSIX_RENAME)
            .is_some_and(|v| v == "1");
        Ok(Self {
            s,
            raw,
            posix_rename,
        })
    }

    /// Atomic replace: `from` takes `to`'s place in one step.
    async fn posix_rename(&self, from: &str, to: &str) -> Result<(), SftpError> {
        if !self.posix_rename {
            return Err(SftpError::Failed(
                "server lacks posix-rename@openssh.com (atomic save)".into(),
            ));
        }
        let mut data = Vec::with_capacity(8 + from.len() + to.len());
        put_string(&mut data, from);
        put_string(&mut data, to);
        match self.raw.extended(POSIX_RENAME, data).await? {
            Packet::Status(st) if st.status_code == StatusCode::Ok => Ok(()),
            Packet::Status(st) => Err(RawError::Status(st).into()),
            _ => Err(SftpError::Failed("unexpected reply to posix-rename".into())),
        }
    }

    /// The login user's home (`realpath .`).
    pub async fn home(&self) -> Result<String, SftpError> {
        Ok(self.s.canonicalize(".").await?)
    }

    /// Entries of `dir`: directories first, then by name.
    pub async fn list(&self, dir: &str) -> Result<Vec<RemoteEntry>, SftpError> {
        let dir = remote_path(dir)?;
        let mut out: Vec<RemoteEntry> = self
            .s
            .read_dir(dir.clone())
            .await?
            .map(|e| {
                let name = e.file_name();
                let path = join(&dir, &name).unwrap_or_default();
                entry(name, path, &e.metadata())
            })
            .filter(|e| !e.path.is_empty())
            .collect();
        out.sort_by(|a, b| {
            (a.kind != EntryKind::Dir, &a.name).cmp(&(b.kind != EntryKind::Dir, &b.name))
        });
        Ok(out)
    }

    /// `lstat`: a symlink is reported as a symlink.
    pub async fn stat(&self, path: &str) -> Result<RemoteEntry, SftpError> {
        let path = remote_path(path)?;
        let a = self.s.symlink_metadata(path.clone()).await?;
        Ok(entry(base_name(&path), path, &a))
    }

    /// Whole file, refused above `max` bytes.
    pub async fn read_file(&self, path: &str, max: u64) -> Result<Vec<u8>, SftpError> {
        let path = remote_path(path)?;
        let size = self.s.metadata(path.clone()).await?.size.unwrap_or(0);
        if size > max {
            return Err(SftpError::TooLarge { size });
        }
        let mut f = self.s.open(path).await?;
        let mut buf = Vec::with_capacity(size as usize);
        // A file growing meanwhile is cut at `max + 1` and refused.
        (&mut f)
            .take(max + 1)
            .read_to_end(&mut buf)
            .await
            .map_err(|e| SftpError::Failed(e.to_string()))?;
        if buf.len() as u64 > max {
            return Err(SftpError::TooLarge {
                size: buf.len() as u64,
            });
        }
        Ok(buf)
    }

    /// Replaces an existing file's contents **atomically**: the data goes
    /// to a new temp file in the same directory (`O_EXCL`), which gets the
    /// original's mode and owner, and then replaces the file with
    /// `posix-rename@openssh.com`. A crash or dropped connection leaves the
    /// old file intact (and at worst a `.fleet-*.tmp` next to it). A
    /// symlink is followed: its target is replaced, the link stays. With
    /// `expect`, refuses when the file's `(size, mtime)` changed since it
    /// was read. If the owner can't be kept (not root, file owned by
    /// someone else), nothing is replaced.
    pub async fn write_file(
        &self,
        path: &str,
        data: &[u8],
        expect: Option<(u64, Option<u32>)>,
    ) -> Result<(), SftpError> {
        let path = remote_path(&self.s.canonicalize(remote_path(path)?).await?)?;
        let orig = self.s.metadata(path.clone()).await?;
        if let Some((size, mtime)) = expect
            && (orig.size.unwrap_or(0) != size || orig.mtime != mtime)
        {
            return Err(SftpError::Changed);
        }
        let (dir, name) = split_parent(&path)?;
        let mut suffix = [0u8; 8];
        fleet_crypto::random_bytes(&mut suffix).map_err(|_| SftpError::Failed("rng".into()))?;
        let tmp = join(dir, &format!(".{name}.fleet-{}.tmp", hex::encode(suffix)))?;
        let mut attrs = FileAttributes::empty();
        attrs.permissions = Some(0o600);
        let mut f = self
            .s
            .open_with_flags_and_attributes(
                tmp.clone(),
                OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE,
                attrs,
            )
            .await?;
        let result = async {
            f.write_all(data)
                .await
                .map_err(|e| SftpError::Failed(e.to_string()))?;
            f.shutdown()
                .await
                .map_err(|e| SftpError::Failed(e.to_string()))?;
            let written = self.s.metadata(tmp.clone()).await?;
            if (orig.uid, orig.gid) != (written.uid, written.gid) {
                let mut own = FileAttributes::empty();
                own.uid = orig.uid;
                own.gid = orig.gid;
                self.s.set_metadata(tmp.clone(), own).await?;
            }
            let mut mode = FileAttributes::empty();
            mode.permissions = Some(orig.permissions.unwrap_or(0o644) & 0o7777);
            self.s.set_metadata(tmp.clone(), mode).await?;
            self.posix_rename(&tmp, &path).await
        }
        .await;
        if result.is_err() {
            let _ = self.s.remove_file(tmp).await;
        }
        result
    }

    /// Writes `data` to `path` (created if missing, else replaced) through a
    /// new `O_EXCL` temp file in the same directory with permission bits
    /// `mode`, renamed into place: readers see the old or the new file,
    /// never a partial one, and a dropped connection leaves the old file
    /// (and at worst a `.fleet-*.tmp`). The caller has checked what is at
    /// `path` (a rename replaces a symlink, never follows it). Without
    /// `posix-rename@openssh.com` only a missing target can be written.
    pub async fn write_atomic(&self, path: &str, data: &[u8], mode: u32) -> Result<(), SftpError> {
        let path = remote_path(path)?;
        let (dir, name) = split_parent(&path)?;
        let mut suffix = [0u8; 8];
        fleet_crypto::random_bytes(&mut suffix).map_err(|_| SftpError::Failed("rng".into()))?;
        let tmp = join(dir, &format!(".{name}.fleet-{}.tmp", hex::encode(suffix)))?;
        let mut attrs = FileAttributes::empty();
        attrs.permissions = Some(mode & 0o7777);
        let mut f = self
            .s
            .open_with_flags_and_attributes(
                tmp.clone(),
                OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE,
                attrs,
            )
            .await?;
        let result = async {
            f.write_all(data)
                .await
                .map_err(|e| SftpError::Failed(e.to_string()))?;
            f.shutdown()
                .await
                .map_err(|e| SftpError::Failed(e.to_string()))?;
            // The server's umask may have narrowed the create mode.
            self.chmod(&tmp, mode).await?;
            if self.posix_rename {
                self.posix_rename(&tmp, &path).await
            } else {
                self.rename(&tmp, &path).await
            }
        }
        .await;
        if result.is_err() {
            let _ = self.s.remove_file(tmp).await;
        }
        result
    }

    pub async fn rename(&self, from: &str, to: &str) -> Result<(), SftpError> {
        Ok(self.s.rename(remote_path(from)?, remote_path(to)?).await?)
    }

    pub async fn mkdir(&self, path: &str) -> Result<(), SftpError> {
        Ok(self.s.create_dir(remote_path(path)?).await?)
    }

    /// Removes a file, symlink or empty directory.
    pub async fn remove(&self, path: &str) -> Result<(), SftpError> {
        let path = remote_path(path)?;
        if self.stat(&path).await?.kind == EntryKind::Dir {
            Ok(self.s.remove_dir(path).await?)
        } else {
            Ok(self.s.remove_file(path).await?)
        }
    }

    /// Sets permission bits (`mode & 0o7777`).
    pub async fn chmod(&self, path: &str, mode: u32) -> Result<(), SftpError> {
        let mut a = FileAttributes::empty();
        a.permissions = Some(mode & 0o7777);
        Ok(self.s.set_metadata(remote_path(path)?, a).await?)
    }

    /// Copies a remote file to `local` (created or truncated).
    /// `progress(done, total)` after every block.
    pub async fn download(
        &self,
        remote: &str,
        local: &Path,
        mut progress: impl FnMut(u64, u64),
    ) -> Result<u64, SftpError> {
        let remote = remote_path(remote)?;
        let total = self.s.metadata(remote.clone()).await?.size.unwrap_or(0);
        let mut src = self.s.open(remote).await?;
        let mut dst = tokio::fs::File::create(local)
            .await
            .map_err(|e| SftpError::Local(e.to_string()))?;
        let mut buf = vec![0u8; COPY_BUF];
        let mut done = 0u64;
        loop {
            let n = src
                .read(&mut buf)
                .await
                .map_err(|e| SftpError::Failed(e.to_string()))?;
            if n == 0 {
                break;
            }
            dst.write_all(&buf[..n])
                .await
                .map_err(|e| SftpError::Local(e.to_string()))?;
            done += n as u64;
            progress(done, total.max(done));
        }
        dst.flush()
            .await
            .map_err(|e| SftpError::Local(e.to_string()))?;
        Ok(done)
    }

    /// Copies `local` to `remote`. `exclusive` refuses an existing target
    /// (`O_EXCL`: safe in shared directories like `/tmp`); `mode` is set at
    /// creation.
    pub async fn upload(
        &self,
        local: &Path,
        remote: &str,
        mode: Option<u32>,
        exclusive: bool,
        mut progress: impl FnMut(u64, u64) + Send,
    ) -> Result<u64, SftpError> {
        // Streamed in blocks: large files never sit in memory whole.
        let mut file = tokio::fs::File::open(local)
            .await
            .map_err(|e| SftpError::Local(e.to_string()))?;
        let total = file
            .metadata()
            .await
            .map_err(|e| SftpError::Local(e.to_string()))?
            .len();
        self.upload_reader(&mut file, total, remote, mode, exclusive, &mut progress)
            .await
    }

    /// [`Sftp::upload`] from memory.
    pub async fn upload_bytes(
        &self,
        data: &[u8],
        remote: &str,
        mode: Option<u32>,
        exclusive: bool,
        progress: &mut (dyn FnMut(u64, u64) + Send),
    ) -> Result<u64, SftpError> {
        let mut r = data;
        self.upload_reader(&mut r, data.len() as u64, remote, mode, exclusive, progress)
            .await
    }

    /// Copies `src` (about `total` bytes, for progress) to `remote`.
    async fn upload_reader<R: tokio::io::AsyncRead + Unpin + Send>(
        &self,
        src: &mut R,
        total: u64,
        remote: &str,
        mode: Option<u32>,
        exclusive: bool,
        progress: &mut (dyn FnMut(u64, u64) + Send),
    ) -> Result<u64, SftpError> {
        let remote = remote_path(remote)?;
        let mut flags = OpenFlags::WRITE | OpenFlags::CREATE;
        flags |= if exclusive {
            OpenFlags::EXCLUDE
        } else {
            OpenFlags::TRUNCATE
        };
        let mut attrs = FileAttributes::empty();
        attrs.permissions = mode.map(|m| m & 0o7777);
        let mut f = self
            .s
            .open_with_flags_and_attributes(remote, flags, attrs)
            .await
            .map_err(|e| match SftpError::from(e) {
                SftpError::Failed(m) if exclusive => SftpError::Failed(format!("{m} (exists?)")),
                other => other,
            })?;
        let mut buf = vec![0u8; COPY_BUF];
        let mut done = 0u64;
        loop {
            let n = src
                .read(&mut buf)
                .await
                .map_err(|e| SftpError::Local(e.to_string()))?;
            if n == 0 {
                break;
            }
            f.write_all(&buf[..n])
                .await
                .map_err(|e| SftpError::Failed(e.to_string()))?;
            done += n as u64;
            progress(done, total.max(done));
        }
        f.shutdown()
            .await
            .map_err(|e| SftpError::Failed(e.to_string()))?;
        Ok(done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert!(remote_path("/etc/nginx/nginx.conf").is_ok());
        assert!(remote_path("relative").is_err());
        assert!(remote_path("/a\0b").is_err());
        assert!(remote_path(&format!("/{}", "a".repeat(MAX_PATH))).is_err());
        assert_eq!(join("/", "etc").unwrap(), "/etc");
        assert_eq!(join("/etc", "hosts").unwrap(), "/etc/hosts");
        assert_eq!(join("/etc/", "hosts").unwrap(), "/etc/hosts");
        for bad in ["", ".", "..", "a/b"] {
            assert!(join("/etc", bad).is_err(), "{bad}");
        }
        assert_eq!(base_name("/etc/hosts"), "hosts");
        assert_eq!(base_name("/etc/"), "etc");
        assert_eq!(base_name("/"), "/");
        assert_eq!(split_parent("/etc/hosts").unwrap(), ("/etc", "hosts"));
        assert_eq!(split_parent("/hosts").unwrap(), ("/", "hosts"));
        assert!(split_parent("/etc/").is_err());
        let mut v = Vec::new();
        put_string(&mut v, "ab");
        assert_eq!(v, [0, 0, 0, 2, b'a', b'b']);
    }
}
