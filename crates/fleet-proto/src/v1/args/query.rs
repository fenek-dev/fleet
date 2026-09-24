//! Query arguments: time ranges, journal and fleet search queries.

use super::{AbsPath, ArgError, GrepPattern, JournalCursor, SearchTerm, UnitName, at_most, ensure};
use serde::{Deserialize, Serialize};

/// Half-open `[since_ms, until_ms)` in Unix milliseconds; `None` is unbounded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TimeRange {
    pub since_ms: Option<u64>,
    pub until_ms: Option<u64>,
}

impl TimeRange {
    pub fn validate(&self) -> Result<(), ArgError> {
        match (self.since_ms, self.until_ms) {
            (Some(a), Some(b)) => ensure(a <= b, "time range"),
            _ => Ok(()),
        }
    }
}

/// syslog priority; a query returns this level and everything more severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Priority {
    Emerg,
    Alert,
    Crit,
    Err,
    Warning,
    Notice,
    Info,
    Debug,
}

/// `journal.query` / `journal.follow` arguments (design §4.6).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JournalQuery {
    /// At most 16; empty means every unit.
    pub units: Vec<UnitName>,
    pub priority: Option<Priority>,
    pub range: TimeRange,
    /// Literal substring filter on the message.
    pub grep: Option<GrepPattern>,
    /// Resume after this cursor (paging and follow reconnects).
    pub after_cursor: Option<JournalCursor>,
    /// 1..=[`JournalQuery::MAX_LIMIT`] entries (per stream batch for follow).
    pub limit: u32,
}

impl JournalQuery {
    pub const MAX_UNITS: usize = 16;
    pub const MAX_LIMIT: u32 = 10_000;

    pub fn validate(&self) -> Result<(), ArgError> {
        at_most(&self.units, Self::MAX_UNITS, "units")?;
        self.range.validate()?;
        ensure((1..=Self::MAX_LIMIT).contains(&self.limit), "limit")
    }
}

/// `search.*` arguments (design §2.7).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SearchQuery {
    pub term: SearchTerm,
    pub case_sensitive: bool,
    /// `search.files` only: at most 8 roots, empty means the default roots.
    pub roots: Vec<AbsPath>,
    /// `search.journal` only.
    pub range: TimeRange,
    /// 1..=[`SearchQuery::MAX_LIMIT`] hits.
    pub limit: u32,
}

impl SearchQuery {
    pub const MAX_ROOTS: usize = 8;
    pub const MAX_LIMIT: u32 = 1_000;

    pub fn validate(&self) -> Result<(), ArgError> {
        at_most(&self.roots, Self::MAX_ROOTS, "search roots")?;
        self.range.validate()?;
        ensure((1..=Self::MAX_LIMIT).contains(&self.limit), "limit")
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::roundtrip;
    use super::*;
    use proptest::prelude::*;

    fn journal(units: usize, limit: u32, range: TimeRange) -> JournalQuery {
        JournalQuery {
            units: vec![UnitName::new("ssh.service").unwrap(); units],
            priority: Some(Priority::Warning),
            range,
            grep: Some(GrepPattern::new("Failed password").unwrap()),
            after_cursor: None,
            limit,
        }
    }

    #[test]
    fn examples() {
        assert!(journal(16, 100, TimeRange::default()).validate().is_ok());
        assert!(journal(17, 100, TimeRange::default()).validate().is_err());
        assert!(journal(1, 0, TimeRange::default()).validate().is_err());
        assert!(journal(1, 10_001, TimeRange::default()).validate().is_err());
        let backwards = TimeRange {
            since_ms: Some(2),
            until_ms: Some(1),
        };
        assert!(journal(1, 1, backwards).validate().is_err());
        assert!(Priority::Err < Priority::Info);
        roundtrip(&journal(2, 5, TimeRange::default()));
        let q = SearchQuery {
            term: SearchTerm::new("nginx").unwrap(),
            case_sensitive: false,
            roots: vec![AbsPath::new("/etc").unwrap(); 9],
            range: TimeRange::default(),
            limit: 10,
        };
        assert_eq!(q.validate(), Err(ArgError::TooMany("search roots")));
        roundtrip(&q);
    }

    proptest! {
        #[test]
        fn journal_limits(units in 0usize..24, limit in 0u32..20_000, a in any::<Option<u64>>(), b in any::<Option<u64>>()) {
            let range = TimeRange { since_ms: a, until_ms: b };
            let ok = units <= 16
                && (1..=10_000).contains(&limit)
                && !matches!((a, b), (Some(a), Some(b)) if a > b);
            prop_assert_eq!(journal(units, limit, range).validate().is_ok(), ok);
        }
    }
}
