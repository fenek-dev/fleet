//! Pending auto-revert changes as files (design §4.4, §4.10).
//!
//! redb locks its database for one process, so the independent `revert <id>`
//! process (started by a transient systemd timer) could not open `state.redb`
//! while exec runs. Each pending change is therefore its own file:
//!
//! - `pending/<id>.bin`: `postcard(PendingChange)`, written atomically
//!   (temp + fsync + rename), mode 0600.
//! - `reverted/<id>.bin`: `postcard(RevertedMarker)`, written by `revert`
//!   after restoring; exec appends the `Actor::System` audit entry, emits
//!   `Event::ChangeReverted` and deletes the marker.
//!
//! `revert` never touches redb, so exec is the only audit writer.
//!
//! **Claiming.** Whoever reverts a change (the timer's `revert <id>` or exec's
//! maintenance once the deadline passed) first renames `<id>.bin` to
//! `<id>.claimed`. `rename` is atomic, so exactly one of them wins; the
//! loser sees `NotFound` and does nothing. A `.claimed` file found at exec
//! startup belongs to a revert that crashed midway and is finished there.

use crate::fsutil;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

/// Identifies a pending change. Rendered as 32 lowercase hex characters in
/// file names, unit names (`fleet-revert-<hex>`) and on the `revert` command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChangeId(pub [u8; 16]);

impl ChangeId {
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    /// Strict: exactly 32 lowercase hex characters.
    pub fn parse(s: &str) -> Option<Self> {
        if s.len() != 32
            || !s
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        let mut out = [0u8; 16];
        hex::decode_to_slice(s, &mut out).ok()?;
        Some(Self(out))
    }
}

impl fmt::Display for ChangeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// What a snapshot restores (the wire enum, also in `changes.list`).
pub use fleet_proto::payload::ChangeKind;

/// Exec's per-connection session id: random per gate connection, i.e. per
/// authenticated Noise session (design §4.10 step 3).
pub type SessionId = [u8; 16];

/// Who applied a change and how; `change.confirm` checks it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeOrigin {
    pub device_id: fleet_proto::DeviceId,
    /// The session that applied it; confirming needs a different one.
    pub session: SessionId,
    pub op_tag: u16,
    pub created_ms: u64,
    /// `ChangePending::new_version` as the handler reported it.
    pub new_version: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingChange {
    pub kind: ChangeKind,
    pub origin: ChangeOrigin,
    /// Opaque state captured before the change was applied.
    pub snapshot: Vec<u8>,
    /// Unix milliseconds after which the change is reverted.
    pub deadline_ms: u64,
    /// Audit seq of the intent that made the change.
    pub audit_seq: u64,
}

/// Left by `revert <id>` for exec to audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevertedMarker {
    pub kind: ChangeKind,
    /// Audit seq of the intent that made the change.
    pub origin_audit_seq: u64,
    /// `false` if restoring the snapshot failed.
    pub restored: bool,
    pub time_ms: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum PendingError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("corrupt file {0}")]
    Corrupt(PathBuf),
}

pub type Result<T> = std::result::Result<T, PendingError>;

/// The `pending/` and `reverted/` directories.
#[derive(Debug, Clone)]
pub struct PendingDir {
    pending: PathBuf,
    reverted: PathBuf,
}

const MODE: u32 = 0o600;

impl PendingDir {
    pub fn new(pending: impl Into<PathBuf>, reverted: impl Into<PathBuf>) -> Self {
        Self {
            pending: pending.into(),
            reverted: reverted.into(),
        }
    }

    pub fn from_paths(p: &crate::paths::Paths) -> Self {
        Self::new(&p.pending_dir, &p.reverted_dir)
    }

    /// Creates both directories (0700).
    pub fn create(&self) -> std::io::Result<()> {
        fsutil::ensure_dir(&self.pending, 0o700)?;
        fsutil::ensure_dir(&self.reverted, 0o700)
    }

    fn file(dir: &Path, id: ChangeId) -> PathBuf {
        dir.join(format!("{id}.bin"))
    }

    fn claimed_file(&self, id: ChangeId) -> PathBuf {
        self.pending.join(format!("{id}.claimed"))
    }

    /// Atomically takes ownership of a pending change (`<id>.bin` →
    /// `<id>.claimed`). `Ok(false)` if someone else claimed it or it was
    /// confirmed meanwhile.
    pub fn claim(&self, id: ChangeId) -> Result<bool> {
        match std::fs::rename(Self::file(&self.pending, id), self.claimed_file(id)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    pub fn get_claimed(&self, id: ChangeId) -> Result<Option<PendingChange>> {
        read(&self.claimed_file(id))
    }

    pub fn remove_claimed(&self, id: ChangeId) -> Result<bool> {
        remove(&self.claimed_file(id))
    }

    /// Every `pending/` entry, pending or claimed, decoding each file on its
    /// own: an unreadable one is reported with `change: None` instead of
    /// failing the whole scan (exec quarantines it).
    pub fn scan(&self) -> std::io::Result<Vec<Entry<PendingChange>>> {
        scan(&self.pending, &[(".bin", false), (".claimed", true)])
    }

    /// Every `reverted/` marker, decoded one by one like [`Self::scan`].
    pub fn scan_markers(&self) -> std::io::Result<Vec<Entry<RevertedMarker>>> {
        scan(&self.reverted, &[(".bin", false)])
    }

    pub fn insert(&self, id: ChangeId, change: &PendingChange) -> Result<()> {
        let bytes = fleet_proto::encode(change);
        Ok(fsutil::write_atomic(
            &Self::file(&self.pending, id),
            &bytes,
            MODE,
        )?)
    }

    pub fn get(&self, id: ChangeId) -> Result<Option<PendingChange>> {
        read(&Self::file(&self.pending, id))
    }

    /// Removes the pending file. `Ok(false)` if it was already gone.
    pub fn remove(&self, id: ChangeId) -> Result<bool> {
        remove(&Self::file(&self.pending, id))
    }

    /// Every pending change, in no particular order. Files with other names
    /// (temp files) are ignored.
    pub fn list(&self) -> Result<Vec<(ChangeId, PendingChange)>> {
        list(&self.pending)
    }

    /// Entries whose deadline is at or before `now_ms` (startup, §4.10 step 5).
    pub fn expired(&self, now_ms: u64) -> Result<Vec<(ChangeId, PendingChange)>> {
        let mut v = self.list()?;
        v.retain(|(_, c)| c.deadline_ms <= now_ms);
        Ok(v)
    }

    pub fn write_marker(&self, id: ChangeId, m: &RevertedMarker) -> Result<()> {
        let bytes = fleet_proto::encode(m);
        Ok(fsutil::write_atomic(
            &Self::file(&self.reverted, id),
            &bytes,
            MODE,
        )?)
    }

    pub fn has_marker(&self, id: ChangeId) -> bool {
        Self::file(&self.reverted, id).exists()
    }

    pub fn markers(&self) -> Result<Vec<(ChangeId, RevertedMarker)>> {
        list(&self.reverted)
    }

    pub fn remove_marker(&self, id: ChangeId) -> Result<bool> {
        remove(&Self::file(&self.reverted, id))
    }
}

/// One file found by [`PendingDir::scan`] / [`PendingDir::scan_markers`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry<T> {
    pub id: ChangeId,
    /// `<id>.claimed` rather than `<id>.bin`.
    pub claimed: bool,
    pub path: PathBuf,
    /// `None`: unreadable or corrupt.
    pub value: Option<T>,
}

fn scan<T: serde::de::DeserializeOwned>(
    dir: &Path,
    suffixes: &[(&str, bool)],
) -> std::io::Result<Vec<Entry<T>>> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some((id, claimed)) = suffixes.iter().find_map(|(sfx, claimed)| {
            let id = ChangeId::parse(name.strip_suffix(sfx)?)?;
            Some((id, *claimed))
        }) else {
            continue;
        };
        let path = entry.path();
        let value = read(&path).ok().flatten();
        out.push(Entry {
            id,
            claimed,
            path,
            value,
        });
    }
    Ok(out)
}

/// Moves `path` into `qdir` (created 0700) under a unique name.
pub fn quarantine(path: &Path, qdir: &Path) -> std::io::Result<PathBuf> {
    fsutil::ensure_dir(qdir, 0o700)?;
    let name = path
        .file_name()
        .ok_or(std::io::ErrorKind::InvalidInput)?
        .to_string_lossy();
    let mut rnd = [0u8; 4];
    fleet_crypto::random_bytes(&mut rnd).map_err(|_| std::io::ErrorKind::Other)?;
    let dest = qdir.join(format!("{name}.{}", hex::encode(rnd)));
    std::fs::rename(path, &dest)?;
    Ok(dest)
}

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match std::fs::read(path) {
        Ok(b) => fleet_proto::decode(&b)
            .map(Some)
            .map_err(|_| PendingError::Corrupt(path.to_owned())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn remove(path: &Path) -> Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn list<T: serde::de::DeserializeOwned>(dir: &Path) -> Result<Vec<(ChangeId, T)>> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e.into()),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(id) = name
            .to_str()
            .and_then(|n| n.strip_suffix(".bin"))
            .and_then(ChangeId::parse)
        else {
            continue;
        };
        if let Some(v) = read(&entry.path())? {
            out.push((id, v));
        }
    }
    Ok(out)
}
