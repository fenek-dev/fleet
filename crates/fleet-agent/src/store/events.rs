//! `events` (design §4.4, §4.5): every signed event exec emitted, so a Mac
//! that was offline (or whose live feed lagged) catches up with
//! `events.query`. Agents record events while Macs are offline.
//!
//! | Table | Key | Value |
//! |---|---|---|
//! | `events` | (run ordinal, seq) | (time ms, `postcard(SignedEvent)`) |
//! | `event_runs` | `run_id` | run ordinal |
//! | `event_meta` | `"next_run"` | next run ordinal |
//!
//! Run ordinals count exec starts, so key order is emission order across
//! restarts even though `run_id` is random. Kept 7 days and at most
//! [`MAX_EVENTS`] rows; pruned oldest first.

use super::Result;
use redb::{
    ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition, WriteTransaction,
};
use std::ops::Bound;

const EVENTS: TableDefinition<(u64, u64), (u64, &[u8])> = TableDefinition::new("events");
const RUNS: TableDefinition<&[u8; 16], u64> = TableDefinition::new("event_runs");
const META: TableDefinition<&str, u64> = TableDefinition::new("event_meta");

/// Retention (design §4.4: 7 days of history).
pub const RETENTION_MS: u64 = 7 * 24 * 3_600_000;
/// Row cap (a few MB at typical event sizes); the oldest go first.
pub const MAX_EVENTS: u64 = 20_000;
/// Rows removed per prune call, so one call stays short.
const PRUNE_BATCH: usize = 5_000;

pub(super) fn create_tables(tx: &WriteTransaction) -> Result<()> {
    tx.open_table(EVENTS)?;
    tx.open_table(RUNS)?;
    tx.open_table(META)?;
    Ok(())
}

/// One stored event: where it sits and its encoded `SignedEvent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvent {
    pub run: u64,
    pub seq: u64,
    pub time_ms: u64,
    pub bytes: Vec<u8>,
}

pub struct EventLog<'a> {
    db: super::DbRead<'a>,
}

impl<'a> EventLog<'a> {
    pub(super) fn new(db: super::DbRead<'a>) -> Self {
        Self { db }
    }

    /// Registers a new exec run; returns its ordinal.
    pub fn begin_run(&self, run_id: &[u8; 16]) -> Result<u64> {
        let tx = self.db.begin_write()?;
        let ord = {
            let mut m = tx.open_table(META)?;
            let ord = m.get("next_run")?.map_or(0, |v| v.value());
            m.insert("next_run", ord + 1)?;
            tx.open_table(RUNS)?.insert(run_id, ord)?;
            ord
        };
        tx.commit()?;
        Ok(ord)
    }

    pub fn append(&self, run: u64, seq: u64, time_ms: u64, bytes: &[u8]) -> Result<()> {
        let tx = self.db.begin_write()?;
        tx.open_table(EVENTS)?
            .insert((run, seq), (time_ms, bytes))?;
        tx.commit()?;
        Ok(())
    }

    /// Events strictly after `(run_id, seq)`, oldest first, at most `limit`
    /// and about `max_bytes`; whether more follow. An unknown or `None`
    /// run starts at the oldest event kept.
    pub fn after(
        &self,
        run_id: Option<&[u8; 16]>,
        seq: u64,
        limit: usize,
        max_bytes: usize,
    ) -> Result<(Vec<StoredEvent>, bool)> {
        let tx = self.db.begin_read()?;
        let run = match run_id {
            Some(r) => tx.open_table(RUNS)?.get(r)?.map(|v| v.value()),
            None => None,
        };
        let start = match run {
            Some(ord) => Bound::Excluded((ord, seq)),
            None => Bound::Unbounded,
        };
        let t = tx.open_table(EVENTS)?;
        let mut out = Vec::new();
        let mut bytes = 0usize;
        for row in t.range::<(u64, u64)>((start, Bound::Unbounded))? {
            let (k, v) = row?;
            let ((run, seq), (time_ms, b)) = (k.value(), v.value());
            if out.len() >= limit || (!out.is_empty() && bytes + b.len() > max_bytes) {
                return Ok((out, true));
            }
            bytes += b.len();
            out.push(StoredEvent {
                run,
                seq,
                time_ms,
                bytes: b.to_vec(),
            });
        }
        Ok((out, false))
    }

    /// Events of run ordinal `run` with a seq above `seq` (live-feed catch
    /// up after a lag), at most `limit`.
    pub fn in_run_after(&self, run: u64, seq: u64, limit: usize) -> Result<Vec<StoredEvent>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(EVENTS)?;
        let mut out = Vec::new();
        let range = (
            Bound::Excluded((run, seq)),
            Bound::Included((run, u64::MAX)),
        );
        for row in t.range::<(u64, u64)>(range)?.take(limit) {
            let (k, v) = row?;
            let ((run, seq), (time_ms, b)) = (k.value(), v.value());
            out.push(StoredEvent {
                run,
                seq,
                time_ms,
                bytes: b.to_vec(),
            });
        }
        Ok(out)
    }

    /// Drops events older than `cutoff_ms` and the oldest beyond
    /// `max_rows`, then runs with no events left (except `keep_run`).
    /// Returns the rows removed; commits only if something was.
    pub fn prune(&self, cutoff_ms: u64, max_rows: u64, keep_run: u64) -> Result<u64> {
        let tx = self.db.begin_write()?;
        let removed;
        {
            let mut t = tx.open_table(EVENTS)?;
            let excess = t.len()?.saturating_sub(max_rows);
            let mut doomed = Vec::new();
            for row in t.iter()? {
                let (k, v) = row?;
                let old = v.value().0 < cutoff_ms;
                if doomed.len() >= PRUNE_BATCH || !(old || (doomed.len() as u64) < excess) {
                    break;
                }
                doomed.push(k.value());
            }
            for k in &doomed {
                t.remove(k)?;
            }
            removed = doomed.len() as u64;
            if removed > 0 {
                let first_run = t.first()?.map(|(k, _)| k.value().0);
                let mut runs = tx.open_table(RUNS)?;
                runs.retain(|_, ord| ord == keep_run || first_run.is_some_and(|f| ord >= f))?;
            }
        }
        if removed == 0 {
            tx.abort()?;
        } else {
            tx.commit()?;
        }
        Ok(removed)
    }

    pub fn len(&self) -> Result<u64> {
        let tx = self.db.begin_read()?;
        Ok(tx.open_table(EVENTS)?.len()?)
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
}
