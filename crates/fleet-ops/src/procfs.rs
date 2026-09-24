//! Reads `/proc`, `/sys` and small `/etc` files under the context root.
//! Every read is size-capped; every parser tolerates missing files (so the
//! agent also runs on macOS during development) and returns `None`.

use crate::ctx::rooted;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Largest file read through [`Procfs::read`].
pub const MAX_READ: u64 = 1 << 20;

#[derive(Debug, Clone)]
pub struct Procfs {
    root: PathBuf,
}

impl Procfs {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }

    /// Reads an absolute system path under the root, at most [`MAX_READ`]
    /// bytes, as UTF-8 (lossy).
    pub fn read(&self, abs: &str) -> Option<String> {
        let p = rooted(&self.root, abs)?;
        let mut buf = Vec::new();
        std::fs::File::open(p)
            .ok()?
            .take(MAX_READ)
            .read_to_end(&mut buf)
            .ok()?;
        Some(String::from_utf8_lossy(&buf).into_owned())
    }

    /// A `Key:   123 kB` line of `/proc/meminfo`-style files, in KiB.
    pub fn kib_field(&self, abs: &str, key: &str) -> Option<u64> {
        kib_field(&self.read(abs)?, key)
    }

    pub fn mem_total_bytes(&self) -> Option<u64> {
        self.kib_field("/proc/meminfo", "MemTotal:")
            .map(|k| k * 1024)
    }

    /// Resident set size of the calling process.
    pub fn self_rss_bytes(&self) -> Option<u64> {
        self.kib_field("/proc/self/status", "VmRSS:")
            .map(|k| k * 1024)
    }

    /// Whole seconds since boot.
    pub fn uptime_s(&self) -> Option<u64> {
        self.read("/proc/uptime")?
            .split(['.', ' '])
            .next()?
            .trim()
            .parse()
            .ok()
    }
}

pub fn kib_field(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|l| {
        l.strip_prefix(key)?
            .trim()
            .strip_suffix("kB")?
            .trim()
            .parse()
            .ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_under_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("proc/self")).unwrap();
        std::fs::write(
            dir.path().join("proc/meminfo"),
            "MemTotal:       16384 kB\nMemFree: 1 kB\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("proc/self/status"), "VmRSS:\t  8 kB\n").unwrap();
        std::fs::write(dir.path().join("proc/uptime"), "1234.56 99.0\n").unwrap();
        let p = Procfs::new(dir.path());
        assert_eq!(p.mem_total_bytes(), Some(16384 * 1024));
        assert_eq!(p.self_rss_bytes(), Some(8 * 1024));
        assert_eq!(p.uptime_s(), Some(1234));
        assert_eq!(p.read("/proc/missing"), None);
        assert_eq!(p.read("/proc/../etc"), None);
    }
}
