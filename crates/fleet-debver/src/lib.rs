//! Debian package versions: `[epoch:]upstream[-revision]`, ordered exactly
//! like `dpkg --compare-versions` (dpkg `verrevcmp`, Debian Policy §5.6.12).
//!
//! - The epoch is compared numerically; a missing epoch is `0`.
//! - The upstream version and the revision are compared with the same
//!   algorithm: alternate runs of non-digits and digits. Non-digit runs are
//!   compared character by character, where `~` sorts before everything
//!   (even the end of the string), then the end of the string, then
//!   letters, then every other character (by ASCII value). Digit runs are
//!   compared as integers (leading zeros ignored, no overflow).
//! - The epoch ends at the first `:`, the revision starts after the last
//!   `-`. A missing revision equals the revision `0`.
//!
//! [`compare`] accepts any string (it never panics and is a total order,
//! like dpkg's comparison on unchecked input). [`Version::parse`] checks
//! the Policy syntax, for data that must be well-formed (vulnerability
//! feeds).
#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::fmt;

/// Parse failure for [`Version::parse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionError {
    Empty,
    /// The epoch is not a number (or does not fit in a `u32`).
    BadEpoch,
    /// The upstream part is empty or does not start with a digit.
    BadUpstream,
    /// `-` with nothing after it.
    EmptyRevision,
    /// A character Policy does not allow in that part.
    BadChar,
    /// Longer than [`Version::MAX_LEN`].
    TooLong,
}

impl fmt::Display for VersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Empty => "empty version",
            Self::BadEpoch => "bad epoch",
            Self::BadUpstream => "upstream version must start with a digit",
            Self::EmptyRevision => "empty revision",
            Self::BadChar => "invalid character",
            Self::TooLong => "version too long",
        };
        f.write_str(s)
    }
}

impl std::error::Error for VersionError {}

/// A syntactically valid Debian version, borrowing its parts.
#[derive(Debug, Clone, Copy)]
pub struct Version<'a> {
    pub epoch: u32,
    pub upstream: &'a str,
    /// Empty when absent.
    pub revision: &'a str,
}

impl<'a> Version<'a> {
    /// Longest accepted version string (dpkg has no limit; feeds never
    /// come close).
    pub const MAX_LEN: usize = 256;

    pub fn parse(s: &'a str) -> Result<Self, VersionError> {
        if s.is_empty() {
            return Err(VersionError::Empty);
        }
        if s.len() > Self::MAX_LEN {
            return Err(VersionError::TooLong);
        }
        let (epoch, rest) = match s.split_once(':') {
            Some((e, r)) => {
                if e.is_empty() || !e.bytes().all(|c| c.is_ascii_digit()) {
                    return Err(VersionError::BadEpoch);
                }
                (e.parse().map_err(|_| VersionError::BadEpoch)?, r)
            }
            None => (0, s),
        };
        let (upstream, revision) = match rest.rsplit_once('-') {
            Some((u, r)) => {
                if r.is_empty() {
                    return Err(VersionError::EmptyRevision);
                }
                (u, r)
            }
            None => (rest, ""),
        };
        if !upstream.starts_with(|c: char| c.is_ascii_digit()) {
            return Err(VersionError::BadUpstream);
        }
        // Hyphens are allowed in upstream only because a revision follows
        // (the split took the last one).
        let up_ok = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'+' | b'~' | b'-');
        let rev_ok = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'+' | b'~');
        if !upstream.bytes().all(up_ok) || !revision.bytes().all(rev_ok) {
            return Err(VersionError::BadChar);
        }
        Ok(Self {
            epoch,
            upstream,
            revision,
        })
    }
}

impl PartialEq for Version<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version<'_> {}

impl PartialOrd for Version<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.epoch
            .cmp(&other.epoch)
            .then_with(|| verrevcmp(self.upstream.as_bytes(), other.upstream.as_bytes()))
            .then_with(|| verrevcmp(self.revision.as_bytes(), other.revision.as_bytes()))
    }
}

impl fmt::Display for Version<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.epoch != 0 {
            write!(f, "{}:", self.epoch)?;
        }
        f.write_str(self.upstream)?;
        if !self.revision.is_empty() {
            write!(f, "-{}", self.revision)?;
        }
        Ok(())
    }
}

/// Lenient split for [`compare`]: an epoch that is not a number counts as
/// `0` (its text is dropped), like dpkg on unchecked input.
fn split(v: &str) -> (u64, &str, &str) {
    let (epoch, rest) = match v.split_once(':') {
        Some((e, r)) => (e.parse().unwrap_or(0), r),
        None => (0, v),
    };
    match rest.rsplit_once('-') {
        Some((u, r)) => (epoch, u, r),
        None => (epoch, rest, ""),
    }
}

/// dpkg's character weight inside a non-digit run.
fn order(c: Option<u8>) -> i32 {
    match c {
        None => 0,
        Some(b'~') => -1,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => i32::from(c),
        Some(c) => i32::from(c) + 256,
    }
}

fn is_digit(c: Option<&u8>) -> bool {
    c.is_some_and(u8::is_ascii_digit)
}

/// dpkg `verrevcmp`, on bytes.
fn verrevcmp(a: &[u8], b: &[u8]) -> Ordering {
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        while (i < a.len() && !a[i].is_ascii_digit()) || (j < b.len() && !b[j].is_ascii_digit()) {
            let (ac, bc) = (order(a.get(i).copied()), order(b.get(j).copied()));
            if ac != bc {
                return ac.cmp(&bc);
            }
            i += 1;
            j += 1;
        }
        while a.get(i) == Some(&b'0') {
            i += 1;
        }
        while b.get(j) == Some(&b'0') {
            j += 1;
        }
        let mut first_diff = Ordering::Equal;
        while is_digit(a.get(i)) && is_digit(b.get(j)) {
            if first_diff == Ordering::Equal {
                first_diff = a[i].cmp(&b[j]);
            }
            i += 1;
            j += 1;
        }
        if is_digit(a.get(i)) {
            return Ordering::Greater;
        }
        if is_digit(b.get(j)) {
            return Ordering::Less;
        }
        if first_diff != Ordering::Equal {
            return first_diff;
        }
    }
    Ordering::Equal
}

/// Debian version order (`dpkg --compare-versions`) on any two strings.
pub fn compare(a: &str, b: &str) -> Ordering {
    let (ea, ua, ra) = split(a);
    let (eb, ub, rb) = split(b);
    ea.cmp(&eb)
        .then_with(|| verrevcmp(ua.as_bytes(), ub.as_bytes()))
        .then_with(|| verrevcmp(ra.as_bytes(), rb.as_bytes()))
}

#[cfg(test)]
mod tests;
