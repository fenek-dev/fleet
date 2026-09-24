//! Package change event source (design §4.5): tails `/var/log/dpkg.log`
//! and turns new `install/upgrade/remove/purge` lines into
//! `Event::PackagesChanged`. Poll-based; the caller's event loop calls
//! [`DpkgLogWatcher::poll`] on its tick.

use super::parse::parse_dpkg_log_line;
use crate::ctx::SysCtx;
use fleet_proto::Event;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

/// Bytes read per poll; the rest waits for the next one.
const MAX_READ: u64 = 1 << 20;
/// Changes per event.
pub const MAX_CHANGES_PER_EVENT: usize = 256;
/// Longest partial line kept between polls.
const MAX_PARTIAL: usize = 4096;

pub struct DpkgLogWatcher {
    path: Option<PathBuf>,
    inode: u64,
    offset: u64,
    partial: Vec<u8>,
}

impl DpkgLogWatcher {
    /// Starts at the current end of the log (history is `pkg.history`).
    pub fn new(ctx: &SysCtx) -> Self {
        let path = ctx.path(super::DPKG_LOG);
        let (inode, offset) = path
            .as_ref()
            .and_then(|p| std::fs::metadata(p).ok())
            .map_or((0, 0), |m| (m.ino(), m.len()));
        Self {
            path,
            inode,
            offset,
            partial: Vec::new(),
        }
    }

    /// Events for lines appended since the last poll. A rotated (new inode)
    /// or truncated log is read from its start.
    pub fn poll(&mut self) -> Vec<Event> {
        let Some(path) = &self.path else {
            return Vec::new();
        };
        let Ok(mut f) = std::fs::File::open(path) else {
            return Vec::new();
        };
        let Ok(meta) = f.metadata() else {
            return Vec::new();
        };
        if meta.ino() != self.inode || meta.len() < self.offset {
            self.inode = meta.ino();
            self.offset = 0;
            self.partial.clear();
        }
        if meta.len() == self.offset || f.seek(SeekFrom::Start(self.offset)).is_err() {
            return Vec::new();
        }
        let mut buf = Vec::new();
        let Ok(n) = f.take(MAX_READ).read_to_end(&mut buf) else {
            return Vec::new();
        };
        self.offset += n as u64;
        self.partial.extend_from_slice(&buf);
        // Keep an unterminated last line for the next poll.
        let complete = match self.partial.iter().rposition(|&b| b == b'\n') {
            Some(i) => self.partial.drain(..=i).collect::<Vec<u8>>(),
            None => {
                if self.partial.len() > MAX_PARTIAL {
                    self.partial.clear();
                }
                return Vec::new();
            }
        };
        if self.partial.len() > MAX_PARTIAL {
            self.partial.clear();
        }
        let text = String::from_utf8_lossy(&complete);
        let changes: Vec<_> = text
            .lines()
            .filter_map(parse_dpkg_log_line)
            .map(|e| e.change)
            .collect();
        changes
            .chunks(MAX_CHANGES_PER_EVENT)
            .map(|c| Event::PackagesChanged {
                changes: c.to_vec(),
            })
            .collect()
    }
}
