//! Vulnerability matching (design §2.4, §7.7).
//!
//! The Mac downloads two public feeds daily while the app runs (agents
//! never contact the internet for this):
//!
//! - **Debian Security Tracker** JSON (`feed::Source::DebianTracker`):
//!   per source package, per CVE, per release: status, fixed version,
//!   urgency. ~12 MB gzip, ~80 MB JSON.
//! - **Ubuntu USN database** (`feed::Source::UbuntuUsn`): every Ubuntu
//!   Security Notice with the fixed version of each binary package per
//!   release. ~45 MB bzip2. (The OSV `Ubuntu/all.zip` export is ~740 MB,
//!   too large to fetch daily.)
//!
//! Both are stream-parsed ([`debian`], [`ubuntu`]) into a compact SQLite
//! table ([`db`]) in its own file next to the cache, replaced atomically
//! per feed. [`matcher`] compares a server's installed packages against
//! it with dpkg's version order ([`dpkgver`]).
//!
//! Feed data is untrusted input: every field is length- and
//! charset-checked, versions must parse, decompressed size is capped, and
//! a feed that fails to parse leaves the previous data in place.

pub mod db;
pub mod debian;
pub mod dpkgver;
pub mod feed;
pub mod matcher;
pub mod release;
pub mod ubuntu;

#[cfg(feature = "fetch")]
pub mod fetch;

/// Severity on one scale for both feeds. Debian urgencies
/// (`unimportant`, `low`, `medium`, `high`) and Ubuntu priorities
/// (`negligible` … `critical`) map onto it; anything else is `Unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Unknown,
    Negligible,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_i64(self) -> i64 {
        self as i64
    }

    pub fn from_i64(v: i64) -> Self {
        match v {
            1 => Self::Negligible,
            2 => Self::Low,
            3 => Self::Medium,
            4 => Self::High,
            5 => Self::Critical,
            _ => Self::Unknown,
        }
    }

    /// Debian tracker urgency; a trailing `*`/`**` (unconfirmed) is
    /// ignored. `not yet assigned` and `end-of-life` are `Unknown`.
    pub fn from_urgency(s: &str) -> Self {
        match s.trim_end_matches('*').trim() {
            "unimportant" | "negligible" => Self::Negligible,
            "low" => Self::Low,
            "medium" => Self::Medium,
            "high" => Self::High,
            "critical" => Self::Critical,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Distro {
    Debian,
    Ubuntu,
}

impl Distro {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Debian => "debian",
            Self::Ubuntu => "ubuntu",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "debian" => Some(Self::Debian),
            "ubuntu" => Some(Self::Ubuntu),
            _ => None,
        }
    }
}

/// One feed row: `id` affects `package` in `distro`/`release` until
/// `fixed` (`None`: no fix released yet).
///
/// `package` is the Debian **source** package (tracker) or the Ubuntu
/// **binary** package (USN database).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advisory {
    pub distro: Distro,
    pub release: String,
    pub package: String,
    /// `CVE-…`, `TEMP-…` (Debian) or `USN-…` (Ubuntu).
    pub id: String,
    /// CVEs a USN fixes; empty for Debian rows.
    pub aliases: Vec<String>,
    pub fixed: Option<String>,
    pub severity: Severity,
}

/// Most aliases kept per advisory (kernel USNs list hundreds of CVEs).
pub const MAX_ALIASES: usize = 64;

/// Debian package names: `[a-z0-9][a-z0-9+.-]+`, at most 128 bytes.
pub(crate) fn valid_package(s: &str) -> bool {
    (2..=128).contains(&s.len())
        && s.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && s.bytes().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'+' | b'.' | b'-')
        })
}

/// Advisory ids and release names: short, `[A-Za-z0-9._-]`.
pub(crate) fn valid_token(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

pub(crate) fn valid_version(s: &str) -> bool {
    dpkgver::Version::parse(s).is_ok()
}

#[cfg(test)]
mod tests;
