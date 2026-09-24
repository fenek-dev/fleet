//! Telemetry (design §4.3–§4.5): collectors, the adaptive sampler, the
//! metric history pipeline, per-minute top processes and the alert engine,
//! plus the `system` group handlers ([`handlers`]).
//!
//! [`Telemetry`] is the hub exec owns (one per agent): [`Telemetry::run`]
//! samples every second while any `metrics.subscribe` asks for 1-second
//! resolution and every 10 seconds otherwise. Each tick:
//!
//! 1. [`collect::Collector`] reads `/proc`, `/sys` and `statvfs` under the
//!    context root into a [`collect::Snapshot`];
//! 2. [`series`] names the values (capped at 256) and maps them to stable
//!    ids;
//! 3. the frame is published to subscribers (a `watch` channel: each stream
//!    sends only values that changed since its last item);
//! 4. the frame joins the unflushed ring and the running minute's min/avg/max;
//! 5. [`alert::AlertEngine`] evaluates metric rules and advances timers of
//!    rules fed by other sources.
//!
//! At each minute boundary the minute's rollups and the top 10 processes by
//! CPU and memory are finalized and everything unflushed goes to the
//! [`store::MetricsStore`] in **one** batch (so at most one write
//! transaction per minute). Retention is pruned hourly.
//!
//! Cost per tick (estimate, fixture-sized host: 4 cores, 2 disks, 3
//! interfaces, 2 filesystems, 3 sensors): 5 `/proc` files + 2 `statvfs` +
//! ~8 small `/sys` reads, ~30 syscalls and ~40 short allocations (names are
//! rebuilt per tick), well under 100 µs of CPU. At 10-second sampling that
//! is ~0.001 % of a core; at 1 second ~0.01 %. The minute's process scan
//! (3 small files per process) dominates: ~1 ms per 100 processes.

pub mod alert;
pub mod collect;
pub mod handlers;
pub mod parse;
pub mod procs;
pub mod series;
pub mod store;

pub use alert::{AlertEngine, AlertInput, AlertSink, Observation, VecSink};
pub use collect::{Collector, FsStat, RealSys, Snapshot, Syscalls};
pub use handlers::{TAGS, TelemetryOps};
pub use store::{Batch, Frame, MemStore, MetricsStore, Rollup, StoreResult};

use crate::ctx::SysCtx;
use fleet_proto::alert::AlertRuleSet;
use fleet_proto::payload::{MetricSeries, TopProcessMinute};
use procs::ProcTracker;
use series::Catalog;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::Duration;
use tokio::sync::{Notify, watch};

/// Sampling while a Mac shows the server.
pub const FAST: Duration = Duration::from_secs(1);
/// Background sampling.
pub const SLOW: Duration = Duration::from_secs(10);
const MINUTE_MS: u64 = 60_000;
const PRUNE_EVERY_MS: u64 = 3_600_000;
/// Frames kept unflushed if the store keeps failing (bounded memory).
const MAX_PENDING_FRAMES: usize = 600;

fn log(what: &str, e: impl std::fmt::Display) {
    eprintln!("fleet-exec: telemetry: {what}: {e}");
}

/// Running min/max/sum of one series in the current minute.
#[derive(Debug, Clone, Copy)]
struct Acc {
    min: f32,
    max: f32,
    sum: f64,
    n: u32,
}

struct Inner {
    collector: Collector,
    catalog: Catalog,
    engine: AlertEngine,
    rules: AlertRuleSet,
    /// Minute start → accumulators.
    minute: Option<(u64, BTreeMap<u16, Acc>)>,
    pending_raw: Vec<Rc<Frame>>,
    pending_minutes: Vec<(u64, Vec<store::Rollup>)>,
    pending_top: Vec<TopProcessMinute>,
    top_tracker: ProcTracker,
    last_prune_ms: Option<u64>,
}

pub struct Telemetry {
    sys: Rc<dyn Syscalls>,
    store: Rc<dyn MetricsStore>,
    sink: Rc<dyn AlertSink>,
    inner: RefCell<Inner>,
    /// `processes.list` rates (separate from the per-minute scan).
    pub(crate) list_tracker: RefCell<ProcTracker>,
    latest: watch::Sender<Option<Rc<Frame>>>,
    fast_subscribers: Cell<usize>,
    wake: Notify,
}

impl Telemetry {
    /// Loads the series catalog and alert rules from `store` (a corrupt or
    /// unreadable entry starts empty, logged).
    pub fn new(
        sys: Rc<dyn Syscalls>,
        store: Rc<dyn MetricsStore>,
        sink: Rc<dyn AlertSink>,
    ) -> Rc<Self> {
        let known = store.load_catalog().unwrap_or_else(|e| {
            log("load series catalog", e);
            Vec::new()
        });
        let rules = store
            .load_rules()
            .unwrap_or_else(|e| {
                log("load alert rules", e);
                None
            })
            .unwrap_or(AlertRuleSet {
                version: 0,
                rules: Vec::new(),
            });
        Rc::new(Self {
            sys,
            store,
            sink,
            inner: RefCell::new(Inner {
                collector: Collector::new(),
                catalog: Catalog::new(known),
                engine: AlertEngine::new(&rules),
                rules,
                minute: None,
                pending_raw: Vec::new(),
                pending_minutes: Vec::new(),
                pending_top: Vec::new(),
                top_tracker: ProcTracker::new(),
                last_prune_ms: None,
            }),
            list_tracker: RefCell::new(ProcTracker::new()),
            latest: watch::channel(None).0,
            fast_subscribers: Cell::new(0),
            wake: Notify::new(),
        })
    }

    pub fn sys(&self) -> &dyn Syscalls {
        &*self.sys
    }

    pub fn store(&self) -> &dyn MetricsStore {
        &*self.store
    }

    /// Current sampling interval.
    pub fn interval(&self) -> Duration {
        if self.fast_subscribers.get() > 0 {
            FAST
        } else {
            SLOW
        }
    }

    /// Samples forever at the adaptive interval. Spawn on exec's LocalSet.
    pub async fn run(self: Rc<Self>, ctx: SysCtx) {
        loop {
            self.tick(&ctx);
            tokio::select! {
                () = tokio::time::sleep(self.interval()) => {}
                () = self.wake.notified() => {}
            }
        }
    }

    /// One sampling tick at `ctx.clock.now_ms()`.
    pub fn tick(&self, ctx: &SysCtx) {
        let now = ctx.clock.now_ms();
        let mut g = self.inner.borrow_mut();
        let inner = &mut *g;
        let snap = inner.collector.collect(ctx, &*self.sys, now);
        let named = series::named_values(&snap);
        let values = inner.catalog.resolve(&named, now);
        let frame = Rc::new(Frame {
            time_ms: now,
            values,
            catalog_version: inner.catalog.version(),
        });

        let minute = now / MINUTE_MS * MINUTE_MS;
        match &inner.minute {
            None => {
                // Prime the process tracker so the first minute has rates.
                inner.top_tracker.scan(ctx, now, false);
                inner.minute = Some((minute, BTreeMap::new()));
            }
            Some((start, _)) if *start != minute => {
                let start = *start;
                self.finish_minute(inner, ctx, start, now);
                inner.minute = Some((minute, BTreeMap::new()));
            }
            Some(_) => {}
        }
        if let Some((_, accs)) = &mut inner.minute {
            for &(id, v) in &frame.values {
                accs.entry(id)
                    .and_modify(|a| {
                        a.min = a.min.min(v);
                        a.max = a.max.max(v);
                        a.sum += f64::from(v);
                        a.n += 1;
                    })
                    .or_insert(Acc {
                        min: v,
                        max: v,
                        sum: f64::from(v),
                        n: 1,
                    });
            }
        }
        if inner.pending_raw.len() >= MAX_PENDING_FRAMES {
            inner.pending_raw.remove(0);
        }
        inner.pending_raw.push(frame.clone());
        inner.engine.evaluate(&snap, &*self.sink);

        if inner
            .last_prune_ms
            .is_none_or(|t| now.saturating_sub(t) >= PRUNE_EVERY_MS)
        {
            inner.last_prune_ms = Some(now);
            inner.catalog.touch(now);
            if let Err(e) = self.store.prune(now) {
                log("prune", e);
            }
        }
        drop(g);
        self.latest.send_replace(Some(frame));
    }

    /// Closes minute `start`: rollups, top processes, one batch write.
    fn finish_minute(&self, inner: &mut Inner, ctx: &SysCtx, start: u64, now: u64) {
        if let Some((_, accs)) = inner.minute.take() {
            let rollups: Vec<store::Rollup> = accs
                .into_iter()
                .map(|(id, a)| store::Rollup {
                    id,
                    min: a.min,
                    avg: (a.sum / f64::from(a.n.max(1))) as f32,
                    max: a.max,
                })
                .collect();
            if !rollups.is_empty() {
                inner.pending_minutes.push((start, rollups));
            }
        }
        let scan = inner.top_tracker.scan(ctx, now, false);
        let (by_cpu, by_memory) = procs::top_n(&scan);
        if !by_cpu.is_empty() || !by_memory.is_empty() {
            inner.pending_top.push(TopProcessMinute {
                time_ms: start,
                by_cpu,
                by_memory,
            });
        }
        let batch = Batch {
            raw: &inner.pending_raw,
            minutes: &inner.pending_minutes,
            top: &inner.pending_top,
            catalog: inner.catalog.take_dirty(),
        };
        if let Err(e) = self.store.write(&batch) {
            // Dropped rather than retried forever: memory stays bounded.
            log("flush", e);
        }
        inner.pending_raw.clear();
        inner.pending_minutes.clear();
        inner.pending_top.clear();
    }

    /// Latest frame (none before the first tick).
    pub fn latest(&self) -> Option<Rc<Frame>> {
        self.latest.borrow().clone()
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<Option<Rc<Frame>>> {
        self.latest.subscribe()
    }

    pub fn catalog_live(&self) -> Vec<MetricSeries> {
        self.inner.borrow().catalog.live()
    }

    pub(crate) fn catalog_version(&self) -> u64 {
        self.inner.borrow().catalog.version()
    }

    /// Ids sorted: the requested ones that exist, or every live one.
    pub(crate) fn resolve_ids(&self, requested: &[u16]) -> Vec<MetricSeries> {
        let g = self.inner.borrow();
        let mut ids: Vec<u16> = if requested.is_empty() {
            g.catalog.live_ids().to_vec()
        } else {
            requested.to_vec()
        };
        ids.sort_unstable();
        ids.dedup();
        ids.iter()
            .filter_map(|id| g.catalog.get(*id).cloned())
            .collect()
    }

    /// Unflushed frames (not yet in the store).
    pub(crate) fn pending_raw(&self) -> Vec<Rc<Frame>> {
        self.inner.borrow().pending_raw.clone()
    }

    pub(crate) fn pending_minutes(&self) -> Vec<(u64, Vec<store::Rollup>)> {
        self.inner.borrow().pending_minutes.clone()
    }

    pub(crate) fn pending_top(&self) -> Vec<TopProcessMinute> {
        self.inner.borrow().pending_top.clone()
    }

    pub fn rules(&self) -> AlertRuleSet {
        self.inner.borrow().rules.clone()
    }

    /// Persists and applies a new rule set (version checks are the
    /// handler's). Fired alerts of changed or removed rules are cleared.
    pub fn set_rules(&self, rules: AlertRuleSet) -> StoreResult<()> {
        self.store.save_rules(&rules)?;
        let mut g = self.inner.borrow_mut();
        g.engine.set_rules(&rules, &*self.sink);
        g.rules = rules;
        Ok(())
    }

    /// Currently fired alerts: (rule id, subject).
    pub fn fired(&self) -> Vec<(String, String)> {
        self.inner.borrow().engine.fired()
    }

    pub(crate) fn fast_guard(self: &Rc<Self>) -> FastGuard {
        self.fast_subscribers.set(self.fast_subscribers.get() + 1);
        self.wake.notify_one();
        FastGuard(self.clone())
    }
}

impl AlertInput for Telemetry {
    fn observe(&self, obs: Observation, now_ms: u64) {
        self.inner
            .borrow_mut()
            .engine
            .observe(&obs, now_ms, &*self.sink);
    }
}

/// Keeps 1-second sampling on while a 1-second subscription lives.
pub(crate) struct FastGuard(Rc<Telemetry>);

impl Drop for FastGuard {
    fn drop(&mut self) {
        let n = &self.0.fast_subscribers;
        n.set(n.get().saturating_sub(1));
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::collect::tests::{bump_stat, ctx_at, fake_sys, temp_root};
    use super::*;
    use crate::ManualClock;
    use fleet_proto::Event;
    use fleet_proto::alert::{AlertKind, AlertRule, Severity};
    use fleet_proto::args::RuleId;

    pub(crate) struct Rig {
        pub dir: tempfile::TempDir,
        pub clock: Rc<ManualClock>,
        pub ctx: SysCtx,
        pub store: Rc<MemStore>,
        pub sink: Rc<VecSink>,
        pub sys: Rc<super::collect::tests::FakeSys>,
        pub tel: Rc<Telemetry>,
    }

    pub(crate) fn rig() -> Rig {
        let dir = temp_root();
        // 00:00:05 of some day, so minute boundaries are predictable.
        let clock = Rc::new(ManualClock::new(
            1_700_000_005_000 / 60_000 * 60_000 + 5_000,
        ));
        let mut ctx = ctx_at(dir.path());
        ctx.clock = clock.clone();
        let store = Rc::new(MemStore::default());
        let sink = Rc::new(VecSink::default());
        let sys = Rc::new(fake_sys());
        let tel = Telemetry::new(sys.clone(), store.clone(), sink.clone());
        Rig {
            dir,
            clock,
            ctx,
            store,
            sink,
            sys,
            tel,
        }
    }

    #[test]
    fn ticks_flush_once_per_minute() {
        let r = rig();
        for _ in 0..7 {
            bump_stat(r.dir.path(), 10, 80, 10);
            r.tel.tick(&r.ctx);
            r.clock.advance(SLOW);
        }
        // 5 s + 6 × 10 s: crossed one minute boundary → one write.
        assert_eq!(r.store.writes.get(), 1);
        assert_eq!(r.store.raw.borrow().len(), 6);
        let busy = r
            .tel
            .catalog_live()
            .into_iter()
            .find(|s| s.name == "cpu.busy")
            .unwrap();
        let m = r.store.minutes.borrow();
        let (_, roll) = m.iter().find(|(_, x)| x.id == busy.id).unwrap();
        assert!((roll.avg - 20.0).abs() < 0.01, "{roll:?}");
        assert!(!r.store.catalog.borrow().is_empty());
        assert_eq!(r.tel.pending_raw().len(), 1);
        let f = r.tel.latest().unwrap();
        assert!(f.values.len() > 20);
    }

    #[test]
    fn rules_fire_through_sink_and_persist() {
        let r = rig();
        let set = AlertRuleSet {
            version: 3,
            rules: vec![AlertRule {
                id: RuleId::new("disk").unwrap(),
                kind: AlertKind::DiskUsage { mount: None },
                threshold: 900,
                for_s: 0,
                severity: Severity::Critical,
                enabled: true,
            }],
        };
        r.tel.set_rules(set.clone()).unwrap();
        assert_eq!(r.store.rules.borrow().as_ref(), Some(&set));
        r.tel.tick(&r.ctx);
        let ev = r.sink.0.borrow();
        assert!(
            matches!(&ev[..], [Event::AlertFired { subject, value: 947, .. }] if subject == "/"),
            "{ev:?}"
        );
        // Reload from the store.
        let t2 = Telemetry::new(Rc::new(fake_sys()), r.store.clone(), r.sink.clone());
        assert_eq!(t2.rules(), set);
    }

    #[test]
    fn fast_guard_switches_interval() {
        let r = rig();
        assert_eq!(r.tel.interval(), SLOW);
        let g = r.tel.fast_guard();
        assert_eq!(r.tel.interval(), FAST);
        drop(g);
        assert_eq!(r.tel.interval(), SLOW);
    }
}
