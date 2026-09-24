//! Persistence behind [`super::Telemetry`]. Exec implements it on its redb
//! database (`fleet-agent` `store::metrics`); [`MemStore`] backs tests.
//!
//! Reads are visitors so a 7-day query never materializes every row.

use super::series::SeriesEntry;
use fleet_proto::alert::AlertRuleSet;
use fleet_proto::payload::TopProcessMinute;
use std::cell::RefCell;
use std::rc::Rc;

/// Error detail for the local log (callers answer `Internal`).
pub type StoreResult<T> = Result<T, String>;

/// One frame's `(series id, value)` pairs, sorted by id.
pub type Values = Vec<(u16, f32)>;

/// Receives raw frames: `(time_ms, values)`.
pub type RawVisitor<'a> = dyn FnMut(u64, &[(u16, f32)]) + 'a;

/// One sampling tick: every live series, sorted by id.
#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    pub time_ms: u64,
    pub values: Vec<(u16, f32)>,
    /// [`super::series::Catalog::version`] the ids belong to.
    pub catalog_version: u64,
}

/// One series' minute.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rollup {
    pub id: u16,
    pub min: f32,
    pub avg: f32,
    pub max: f32,
}

/// Everything written by one flush, in one transaction.
#[derive(Default)]
pub struct Batch<'a> {
    pub raw: &'a [Rc<Frame>],
    /// (minute start ms, rollups of that minute).
    pub minutes: &'a [(u64, Vec<Rollup>)],
    pub top: &'a [TopProcessMinute],
    /// The known series set, when it changed.
    pub catalog: Option<&'a [SeriesEntry]>,
}

pub trait MetricsStore {
    fn load_catalog(&self) -> StoreResult<Vec<SeriesEntry>>;
    fn load_rules(&self) -> StoreResult<Option<AlertRuleSet>>;
    fn save_rules(&self, rules: &AlertRuleSet) -> StoreResult<()>;
    fn write(&self, batch: &Batch<'_>) -> StoreResult<()>;
    /// Raw frames with `since <= time < until`, in time order.
    fn raw(&self, since_ms: u64, until_ms: u64, f: &mut RawVisitor<'_>) -> StoreResult<()>;
    /// Minute rollups of `ids` (sorted) with `since <= minute < until`.
    fn minutes(
        &self,
        since_ms: u64,
        until_ms: u64,
        ids: &[u16],
        f: &mut dyn FnMut(u64, Rollup),
    ) -> StoreResult<()>;
    /// Top-process minutes in range, newest `limit` of them, oldest first.
    fn top_procs(
        &self,
        since_ms: u64,
        until_ms: u64,
        limit: usize,
    ) -> StoreResult<Vec<TopProcessMinute>>;
    /// Drops data past retention (raw 1 h, rollups and top 7 days).
    fn prune(&self, now_ms: u64) -> StoreResult<()>;
}

pub const RAW_RETENTION_MS: u64 = 3_600_000;
pub const ROLLUP_RETENTION_MS: u64 = 7 * 86_400_000;

/// In-memory store for tests.
#[derive(Default)]
pub struct MemStore {
    pub catalog: RefCell<Vec<SeriesEntry>>,
    pub rules: RefCell<Option<AlertRuleSet>>,
    pub raw: RefCell<Vec<(u64, Values)>>,
    pub minutes: RefCell<Vec<(u64, Rollup)>>,
    pub top: RefCell<Vec<TopProcessMinute>>,
    pub writes: std::cell::Cell<usize>,
}

impl MetricsStore for MemStore {
    fn load_catalog(&self) -> StoreResult<Vec<SeriesEntry>> {
        Ok(self.catalog.borrow().clone())
    }

    fn load_rules(&self) -> StoreResult<Option<AlertRuleSet>> {
        Ok(self.rules.borrow().clone())
    }

    fn save_rules(&self, rules: &AlertRuleSet) -> StoreResult<()> {
        *self.rules.borrow_mut() = Some(rules.clone());
        Ok(())
    }

    fn write(&self, b: &Batch<'_>) -> StoreResult<()> {
        self.writes.set(self.writes.get() + 1);
        self.raw
            .borrow_mut()
            .extend(b.raw.iter().map(|f| (f.time_ms, f.values.clone())));
        for (m, rs) in b.minutes {
            self.minutes
                .borrow_mut()
                .extend(rs.iter().map(|r| (*m, *r)));
        }
        self.top.borrow_mut().extend(b.top.iter().cloned());
        if let Some(c) = b.catalog {
            *self.catalog.borrow_mut() = c.to_vec();
        }
        Ok(())
    }

    fn raw(&self, since_ms: u64, until_ms: u64, f: &mut RawVisitor<'_>) -> StoreResult<()> {
        for (t, v) in self.raw.borrow().iter() {
            if (since_ms..until_ms).contains(t) {
                f(*t, v);
            }
        }
        Ok(())
    }

    fn minutes(
        &self,
        since_ms: u64,
        until_ms: u64,
        ids: &[u16],
        f: &mut dyn FnMut(u64, Rollup),
    ) -> StoreResult<()> {
        for (m, r) in self.minutes.borrow().iter() {
            if (since_ms..until_ms).contains(m) && ids.binary_search(&r.id).is_ok() {
                f(*m, *r);
            }
        }
        Ok(())
    }

    fn top_procs(
        &self,
        since_ms: u64,
        until_ms: u64,
        limit: usize,
    ) -> StoreResult<Vec<TopProcessMinute>> {
        let v: Vec<_> = self
            .top
            .borrow()
            .iter()
            .filter(|t| (since_ms..until_ms).contains(&t.time_ms))
            .cloned()
            .collect();
        Ok(v[v.len().saturating_sub(limit)..].to_vec())
    }

    fn prune(&self, now_ms: u64) -> StoreResult<()> {
        let raw_cut = now_ms.saturating_sub(RAW_RETENTION_MS);
        let cut = now_ms.saturating_sub(ROLLUP_RETENTION_MS);
        self.raw.borrow_mut().retain(|(t, _)| *t >= raw_cut);
        self.minutes.borrow_mut().retain(|(t, _)| *t >= cut);
        self.top.borrow_mut().retain(|t| t.time_ms >= cut);
        Ok(())
    }
}
