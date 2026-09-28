//! Audit archiving and pruning (design §5.8).
//!
//! Entries older than [`AUDIT_RETENTION_MS`] move out of redb into
//! `/var/lib/fleet/exec/audit-archive/<from>-<to>.bin` (root, 0600, in a
//! 0700 directory): DEFLATE (`miniz_oxide`) of `postcard(ArchiveFile)`,
//! which carries the server id, the hash the first archived entry links
//! to, and the entries. One run archives a contiguous prefix of the chain,
//! oldest first, stopping at the first entry that is recent enough or still
//! an open intent, and at most [`MAX_ARCHIVE_ENTRIES`].
//!
//! The chain anchor ([`AnchorState`], `MetaKey::AuditAnchor`) keeps the
//! last archived entry's seq and hash, so [`AuditLog::verify_chain`] and
//! Macs verifying from an older checkpoint still see continuity, plus a
//! record of every archive file with its BLAKE3 (integrity of the files
//! themselves). The file is written (temp + fsync + rename) before the
//! entries are removed; the removal and the anchor update are one redb
//! transaction. A crash in between leaves an unreferenced file, replaced
//! by the next run.
//!
//! A chain that doesn't verify from the anchor is never archived (that
//! would launder a rewrite into a file nobody checks).

use super::audit::{ENTRIES, OPEN};
use super::{AuditLog, MetaKey, Result, StoreError, meta};
use crate::fsutil;
use fleet_proto::{AuditEntry, Hash32, ServerId, decode, encode};
use redb::{ReadableDatabase, ReadableTable};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub const AUDIT_RETENTION_MS: u64 = 90 * 24 * 3600 * 1000;
pub const MAX_ARCHIVE_ENTRIES: usize = 50_000;
/// Archive files recorded in the anchor (oldest records dropped beyond;
/// the files stay on disk).
pub const MAX_ARCHIVE_RECORDS: usize = 4096;
const DEFLATE_LEVEL: u8 = 6;
/// Largest decompressed archive accepted by [`read_archive`].
const MAX_ARCHIVE_BYTES: usize = 512 << 20;
const FILE_VERSION: u8 = 1;

/// One archive file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveRecord {
    pub from_seq: u64,
    pub to_seq: u64,
    pub from_ms: u64,
    pub to_ms: u64,
    /// File name inside the archive directory.
    pub file: String,
    /// BLAKE3 of the file bytes.
    pub blake3: Hash32,
    pub bytes: u64,
}

/// `MetaKey::AuditAnchor`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorState {
    /// Last archived seq (0: nothing archived).
    pub seq: u64,
    /// Hash of entry `seq`: the next stored entry's `prev_hash`.
    pub entry_hash: Hash32,
    pub archives: Vec<ArchiveRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ArchiveFile {
    version: u8,
    server_id: ServerId,
    /// `prev_hash` of the first entry (the anchor before this archive).
    prev_hash: Hash32,
    entries: Vec<AuditEntry>,
}

#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("archive file: {0}")]
    Io(#[from] std::io::Error),
    #[error("audit chain broken at seq {0}; not archiving")]
    Broken(u64),
    #[error("archive {0} doesn't match its record")]
    Mismatch(String),
}

pub(super) fn anchor_in(tx: &redb::ReadTransaction) -> Result<Option<AnchorState>> {
    meta::get_in(tx, MetaKey::AuditAnchor)?
        .map(|b| decode(&b).map_err(|_| StoreError::Corrupt("audit anchor")))
        .transpose()
}

/// `<from>-<to>.bin`, zero-padded so names sort by seq.
pub fn file_name(from: u64, to: u64) -> String {
    format!("{from:020}-{to:020}.bin")
}

impl AuditLog<'_> {
    /// The archive anchor, `None` before the first archive.
    pub fn anchor(&self) -> Result<Option<AnchorState>> {
        let tx = self.db().begin_read()?;
        anchor_in(&tx)
    }

    /// Archives the entries older than `cutoff_ms` (see the module docs).
    /// `Ok(None)` when there was nothing to archive.
    pub fn archive_before(
        &self,
        dir: &Path,
        server_id: &ServerId,
        cutoff_ms: u64,
        max: usize,
    ) -> std::result::Result<Option<ArchiveRecord>, ArchiveError> {
        let anchor = self.anchor()?.unwrap_or_default();
        let entries = {
            let tx = self.db().begin_read().map_err(StoreError::from)?;
            let t = tx.open_table(ENTRIES).map_err(StoreError::from)?;
            let open: HashSet<u64> = tx
                .open_table(OPEN)
                .map_err(StoreError::from)?
                .iter()
                .map_err(StoreError::from)?
                .map(|r| r.map(|(k, _)| k.value()))
                .collect::<std::result::Result<_, _>>()
                .map_err(StoreError::from)?;
            let mut out: Vec<AuditEntry> = Vec::new();
            let mut prev = anchor.entry_hash;
            for row in t.range(anchor.seq + 1..).map_err(StoreError::from)?.take(max) {
                let (k, v) = row.map_err(StoreError::from)?;
                let e: AuditEntry =
                    decode(v.value()).map_err(|_| StoreError::Corrupt("audit"))?;
                if e.time >= cutoff_ms || open.contains(&e.seq) {
                    break;
                }
                let want = anchor.seq + 1 + out.len() as u64;
                if k.value() != want || e.seq != want || e.prev_hash != prev {
                    return Err(ArchiveError::Broken(want));
                }
                prev = e.entry_hash();
                out.push(e);
            }
            out
        };
        let (Some(first), Some(last)) = (entries.first(), entries.last()) else {
            return Ok(None);
        };
        let (from, to) = (first.seq, last.seq);
        let (from_ms, to_ms) = (first.time, last.time);
        let last_hash = last.entry_hash();
        let bytes = miniz_oxide::deflate::compress_to_vec(
            &encode(&ArchiveFile {
                version: FILE_VERSION,
                server_id: server_id.clone(),
                prev_hash: anchor.entry_hash,
                entries,
            }),
            DEFLATE_LEVEL,
        );
        fsutil::ensure_dir(dir, 0o700)?;
        remove_stale(dir, from)?;
        let file = file_name(from, to);
        fsutil::write_atomic(&dir.join(&file), &bytes, 0o600)?;
        let record = ArchiveRecord {
            from_seq: from,
            to_seq: to,
            from_ms,
            to_ms,
            file,
            blake3: *blake3::hash(&bytes).as_bytes(),
            bytes: bytes.len() as u64,
        };
        let mut next = AnchorState {
            seq: to,
            entry_hash: last_hash,
            archives: anchor.archives,
        };
        next.archives.push(record.clone());
        if next.archives.len() > MAX_ARCHIVE_RECORDS {
            let drop = next.archives.len() - MAX_ARCHIVE_RECORDS;
            next.archives.drain(..drop);
        }
        let tx = self.db().begin_write().map_err(StoreError::from)?;
        {
            let mut t = tx.open_table(ENTRIES).map_err(StoreError::from)?;
            for seq in from..=to {
                t.remove(seq).map_err(StoreError::from)?;
            }
        }
        meta::set_in(&tx, MetaKey::AuditAnchor, &encode(&next))?;
        tx.commit().map_err(StoreError::from)?;
        Ok(Some(record))
    }
}

/// Removes files for `from` that a crashed run left (not referenced).
fn remove_stale(dir: &Path, from: u64) -> std::io::Result<()> {
    let prefix = format!("{from:020}-");
    for e in std::fs::read_dir(dir)?.flatten() {
        let name = e.file_name();
        if name.to_str().is_some_and(|n| n.starts_with(&prefix)) {
            std::fs::remove_file(e.path())?;
        }
    }
    Ok(())
}

/// Reads and checks one archive file against its record: file hash, and
/// the entries chain from the file's `prev_hash` to `record.to_seq`.
pub fn read_archive(
    dir: &Path,
    record: &ArchiveRecord,
) -> std::result::Result<(Hash32, Vec<AuditEntry>), ArchiveError> {
    let path: PathBuf = dir.join(&record.file);
    let bytes = std::fs::read(&path)?;
    let bad = || ArchiveError::Mismatch(record.file.clone());
    if *blake3::hash(&bytes).as_bytes() != record.blake3 {
        return Err(bad());
    }
    let raw = miniz_oxide::inflate::decompress_to_vec_with_limit(&bytes, MAX_ARCHIVE_BYTES)
        .map_err(|_| bad())?;
    let f: ArchiveFile = decode(&raw).map_err(|_| bad())?;
    if f.version != FILE_VERSION {
        return Err(bad());
    }
    let mut prev = f.prev_hash;
    for (i, e) in f.entries.iter().enumerate() {
        if e.seq != record.from_seq + i as u64 || e.prev_hash != prev {
            return Err(bad());
        }
        prev = e.entry_hash();
    }
    if f.entries.last().map(|e| e.seq) != Some(record.to_seq) {
        return Err(bad());
    }
    Ok((f.prev_hash, f.entries))
}
