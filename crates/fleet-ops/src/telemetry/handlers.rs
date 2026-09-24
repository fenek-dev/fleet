//! `system` group handlers on the [`Telemetry`] hub: `metrics.subscribe`,
//! `metrics.query`, `processes.list`, `processes.history`,
//! `process.signal`, `process.renice`, and `alert_rules.get`/`update`.

use super::procs::{self, ProcTracker};
use super::store::{RAW_RETENTION_MS, ROLLUP_RETENTION_MS, Rollup};
use super::{FastGuard, Frame, Telemetry};
use crate::ctx::SysCtx;
use crate::handler::{Invocation, LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, OpStream};
use fleet_proto::alert::AlertRuleSet;
use fleet_proto::args::TimeRange;
use fleet_proto::op::{Resolution, SampleInterval, tag};
use fleet_proto::payload::{
    MetricsCatalog, MetricsHistory, MetricsSample, ProcessHistory, ProcessList, SeriesRollup,
};
use fleet_proto::{ErrorCode, F32, Op, Payload};
use std::collections::HashMap;
use std::rc::Rc;
use std::time::Duration;
use tokio::sync::watch;

/// Tags handled by [`TelemetryOps`].
pub const TAGS: [u16; 8] = [
    tag::METRICS_SUBSCRIBE,
    tag::METRICS_QUERY,
    tag::PROCESSES_LIST,
    tag::PROCESS_SIGNAL,
    tag::PROCESS_RENICE,
    tag::PROCESSES_HISTORY,
    tag::ALERT_RULES_GET,
    tag::ALERT_RULES_UPDATE,
];

/// Points per `metrics.query` answer (× 12 bytes for min/avg/max): keeps
/// the response well inside one 1 MiB frame.
pub const MAX_POINTS: usize = 60_000;
/// Minutes per `processes.history` answer (newest kept).
pub const MAX_TOP_MINUTES: usize = 1000;
/// A `processes.list` without a recent previous scan measures over this.
pub const LIST_SETTLE: Duration = Duration::from_millis(250);
/// A previous list scan older than this is not used for rates.
const LIST_MAX_AGE_MS: u64 = 30_000;

pub struct TelemetryOps(pub Rc<Telemetry>);

fn io_code(e: &std::io::Error) -> OpError {
    // ESRCH: the process exited in between.
    if e.raw_os_error() == Some(3) {
        OpError::new(ErrorCode::NotFound)
    } else {
        OpError::internal(e)
    }
}

impl TelemetryOps {
    fn current_version(&self) -> u64 {
        self.0.rules().version
    }

    fn check_rules(&self, set: &AlertRuleSet, meta: &OpMeta) -> Result<(), OpError> {
        set.validate()
            .map_err(|_| OpError::new(ErrorCode::InvalidArgument))?;
        let current = self.current_version();
        // Versioned state (design §2.6): the sender must name the version
        // it replaces, and the new one must be newer.
        if meta.command.body.expected_version != Some(current) || set.version <= current {
            return Err(ErrorCode::VersionConflict { current }.into());
        }
        Ok(())
    }
}

impl OpHandler for TelemetryOps {
    fn supports(&self, op: &Op, invocation: Invocation) -> bool {
        match op {
            Op::MetricsSubscribe { .. } => invocation == Invocation::Stream,
            _ => invocation == Invocation::Request,
        }
    }

    fn validate(&self, ctx: &SysCtx, op: &Op, meta: &OpMeta) -> Result<(), OpError> {
        op.check_args()
            .map_err(|_| OpError::new(ErrorCode::InvalidArgument))?;
        match op {
            Op::ProcessSignal { pid, .. } | Op::ProcessRenice { pid, .. } => {
                procs::check_target(ctx, self.0.sys().self_pid(), pid.get())?;
                Ok(())
            }
            Op::AlertRulesUpdate(set) => self.check_rules(set, meta),
            _ => Ok(()),
        }
    }

    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        op: &'a Op,
        meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            let now = meta.now_ms;
            let p = match op {
                Op::MetricsSubscribe { interval } => {
                    return Ok(OpOutput::Stream(Box::new(MetricsStream::new(
                        &self.0, *interval,
                    ))));
                }
                Op::MetricsQuery {
                    range,
                    resolution,
                    series,
                } => Payload::MetricsHistory(query(&self.0, now, range, *resolution, series)?),
                Op::ProcessesList { sort, limit } => {
                    let scan = list_scan(&self.0, ctx, now).await;
                    let (total, processes) = procs::list(ctx, scan, *sort, usize::from(*limit));
                    Payload::ProcessList(ProcessList { total, processes })
                }
                Op::ProcessesHistory { range } => {
                    Payload::ProcessHistory(history(&self.0, now, range)?)
                }
                Op::ProcessSignal { pid, signal } => {
                    procs::check_target(ctx, self.0.sys().self_pid(), pid.get())?;
                    self.0
                        .sys()
                        .kill(pid.get(), *signal)
                        .map_err(|e| io_code(&e))?;
                    Payload::Empty
                }
                Op::ProcessRenice { pid, nice } => {
                    procs::check_target(ctx, self.0.sys().self_pid(), pid.get())?;
                    self.0
                        .sys()
                        .renice(pid.get(), nice.get())
                        .map_err(|e| io_code(&e))?;
                    Payload::Empty
                }
                Op::AlertRulesGet => Payload::AlertRules(self.0.rules()),
                Op::AlertRulesUpdate(set) => {
                    self.check_rules(set, meta)?;
                    self.0.set_rules(set.clone()).map_err(OpError::internal)?;
                    Payload::Empty
                }
                _ => return Err(ErrorCode::Unsupported.into()),
            };
            Ok(OpOutput::Payload(p))
        })
    }
}

/// A scan with rates: against the previous list call when recent, else
/// two scans [`LIST_SETTLE`] apart.
async fn list_scan(
    tel: &Telemetry,
    ctx: &SysCtx,
    now: u64,
) -> Vec<(procs::ProcSample, procs::Rates)> {
    let fresh = tel
        .list_tracker
        .borrow()
        .last_scan_ms()
        .is_some_and(|t| now.saturating_sub(t) <= LIST_MAX_AGE_MS && t < now);
    if !fresh {
        let mut t = ProcTracker::new();
        t.scan(ctx, ctx.clock.now_ms(), true);
        *tel.list_tracker.borrow_mut() = t;
        tokio::time::sleep(LIST_SETTLE).await;
    }
    // The clock may be manual (tests): never measure over zero time.
    let at = ctx.clock.now_ms().max(
        tel.list_tracker
            .borrow()
            .last_scan_ms()
            .map_or(0, |t| t + LIST_SETTLE.as_millis() as u64),
    );
    tel.list_tracker.borrow_mut().scan(ctx, at, true)
}

fn window(now: u64, range: &TimeRange, retention: u64) -> (u64, u64) {
    let until = range
        .until_ms
        .unwrap_or(u64::MAX)
        .min(now.saturating_add(1));
    let floor = now.saturating_sub(retention);
    let since = range.since_ms.unwrap_or(floor).max(floor);
    (since, until)
}

#[derive(Clone, Copy)]
struct Acc {
    min: f32,
    max: f32,
    sum: f64,
    n: u32,
}

impl Acc {
    const EMPTY: Acc = Acc {
        min: f32::INFINITY,
        max: f32::NEG_INFINITY,
        sum: 0.0,
        n: 0,
    };

    fn add(&mut self, min: f32, avg: f32, max: f32) {
        self.min = self.min.min(min);
        self.max = self.max.max(max);
        self.sum += f64::from(avg);
        self.n += 1;
    }
}

/// `metrics.query`: a regular grid over the stored samples (raw frames, or
/// minute rollups), widened when the answer would exceed [`MAX_POINTS`].
/// For `Raw` at native step the three vectors are equal; a widened raw
/// grid carries the real min/avg/max of each bucket.
pub fn query(
    tel: &Telemetry,
    now: u64,
    range: &TimeRange,
    resolution: Resolution,
    requested: &[u16],
) -> Result<MetricsHistory, OpError> {
    let catalog = tel.resolve_ids(requested);
    let ids: Vec<u16> = catalog.iter().map(|s| s.id).collect();
    let retention = match resolution {
        Resolution::Raw => RAW_RETENTION_MS,
        Resolution::Minute => ROLLUP_RETENTION_MS,
    };
    let (since, until) = window(now, range, retention);
    let pending = tel.pending_raw();
    // Native step: 1 s if any two raw frames in range are closer than 10 s.
    let native: u64 = match resolution {
        Resolution::Minute => 60_000,
        Resolution::Raw => {
            let mut prev: Option<u64> = None;
            let mut min_gap = u64::MAX;
            let mut gap = |t: u64| {
                if let Some(p) = prev {
                    min_gap = min_gap.min(t.saturating_sub(p));
                }
                prev = Some(t);
            };
            tel.store()
                .raw(since, until, &mut |t, _| gap(t))
                .map_err(OpError::internal)?;
            for f in pending
                .iter()
                .filter(|f| (since..until).contains(&f.time_ms))
            {
                gap(f.time_ms);
            }
            if min_gap < 9_500 { 1_000 } else { 10_000 }
        }
    };
    let span = until.saturating_sub(since);
    let start = since / native * native;
    let mut step = native;
    if !ids.is_empty() {
        let need = (span / native + 1) as usize * ids.len();
        if need > MAX_POINTS {
            let factor = need.div_ceil(MAX_POINTS) as u64;
            step = native * factor;
        }
    }
    let n = if span == 0 {
        0
    } else {
        (until - start).div_ceil(step) as usize
    };
    let mut acc = vec![Acc::EMPTY; n * ids.len()];
    let bucket = |t: u64| ((t.saturating_sub(start)) / step) as usize;
    let mut put = |t: u64, id: u16, min: f32, avg: f32, max: f32| {
        if let Ok(i) = ids.binary_search(&id) {
            let b = bucket(t);
            if b < n {
                acc[i * n + b].add(min, avg, max);
            }
        }
    };
    match resolution {
        Resolution::Raw => {
            let mut frame = |t: u64, values: &[(u16, f32)]| {
                for &(id, v) in values {
                    put(t, id, v, v, v);
                }
            };
            tel.store()
                .raw(since, until, &mut frame)
                .map_err(OpError::internal)?;
            for f in pending
                .iter()
                .filter(|f| (since..until).contains(&f.time_ms))
            {
                frame(f.time_ms, &f.values);
            }
        }
        Resolution::Minute => {
            let mut roll = |m: u64, r: Rollup| put(m, r.id, r.min, r.avg, r.max);
            tel.store()
                .minutes(since, until, &ids, &mut roll)
                .map_err(OpError::internal)?;
            for (m, rs) in tel.pending_minutes() {
                if (since..until).contains(&m) {
                    rs.iter().for_each(|r| roll(m, *r));
                }
            }
        }
    }
    let series = ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            let cells = &acc[i * n..(i + 1) * n];
            let pick = |f: fn(&Acc) -> f32| {
                cells
                    .iter()
                    .map(|a| F32(if a.n == 0 { f32::NAN } else { f(a) }))
                    .collect()
            };
            SeriesRollup {
                id: *id,
                min: pick(|a| a.min),
                avg: pick(|a| (a.sum / f64::from(a.n)) as f32),
                max: pick(|a| a.max),
            }
        })
        .collect();
    Ok(MetricsHistory {
        resolution,
        start_ms: start,
        step_ms: u32::try_from(step).unwrap_or(u32::MAX),
        catalog,
        series,
    })
}

fn history(tel: &Telemetry, now: u64, range: &TimeRange) -> Result<ProcessHistory, OpError> {
    let (since, until) = window(now, range, ROLLUP_RETENTION_MS);
    let mut minutes = tel
        .store()
        .top_procs(since, until, MAX_TOP_MINUTES)
        .map_err(OpError::internal)?;
    minutes.extend(
        tel.pending_top()
            .into_iter()
            .filter(|m| (since..until).contains(&m.time_ms)),
    );
    let cut = minutes.len().saturating_sub(MAX_TOP_MINUTES);
    minutes.drain(..cut);
    Ok(ProcessHistory { minutes })
}

/// `metrics.subscribe`: the catalog, then one item per tick (every tick for
/// 1-second subscriptions, at most every 10 s otherwise) carrying only the
/// values that changed since this stream's previous item. A catalog change
/// re-sends the catalog and then every value. `latest_only`: a slow client
/// skips items, and since each item is diffed against what this stream
/// *produced*, a dropped item can leave the Mac one value stale until that
/// value changes again — bounded by the next catalog or by the 10-minute
/// full refresh.
pub struct MetricsStream {
    tel: Rc<Telemetry>,
    rx: watch::Receiver<Option<Rc<Frame>>>,
    _fast: Option<FastGuard>,
    catalog_version: Option<u64>,
    last: HashMap<u16, u32>,
    min_gap_ms: u64,
    last_emit_ms: Option<u64>,
    last_full_ms: u64,
    pending: Option<Rc<Frame>>,
    started: bool,
}

/// Every value is re-sent this often, repairing items dropped under
/// backpressure.
const FULL_REFRESH_MS: u64 = 600_000;

impl MetricsStream {
    pub fn new(tel: &Rc<Telemetry>, interval: SampleInterval) -> Self {
        let (fast, min_gap_ms) = match interval {
            SampleInterval::OneSecond => (Some(tel.fast_guard()), 0),
            // Half a second of slack for tick jitter.
            SampleInterval::TenSeconds => (None, super::SLOW.as_millis() as u64 - 500),
        };
        Self {
            tel: tel.clone(),
            rx: tel.subscribe(),
            _fast: fast,
            catalog_version: None,
            last: HashMap::new(),
            min_gap_ms,
            last_emit_ms: None,
            last_full_ms: 0,
            pending: None,
            started: false,
        }
    }

    async fn next_frame(&mut self) -> Option<Rc<Frame>> {
        if let Some(f) = self.pending.take() {
            return Some(f);
        }
        loop {
            if !self.started {
                self.started = true;
                if let Some(f) = self.rx.borrow_and_update().clone() {
                    return Some(f);
                }
            }
            self.rx.changed().await.ok()?;
            if let Some(f) = self.rx.borrow_and_update().clone() {
                return Some(f);
            }
        }
    }

    async fn next_item(&mut self) -> Option<Payload> {
        loop {
            let frame = self.next_frame().await?;
            if self.catalog_version != Some(frame.catalog_version) {
                // The hub's catalog is at least as new as the frame; a newer
                // one just means another catalog item follows.
                self.catalog_version = Some(self.tel.catalog_version());
                self.last.clear();
                self.pending = Some(frame);
                return Some(Payload::MetricsCatalog(MetricsCatalog {
                    series: self.tel.catalog_live(),
                }));
            }
            if self
                .last_emit_ms
                .is_some_and(|t| frame.time_ms < t.saturating_add(self.min_gap_ms))
            {
                continue;
            }
            if frame.time_ms.saturating_sub(self.last_full_ms) >= FULL_REFRESH_MS {
                self.last.clear();
                self.last_full_ms = frame.time_ms;
            }
            let values: Vec<(u16, F32)> = frame
                .values
                .iter()
                .filter(|(id, v)| self.last.get(id) != Some(&v.to_bits()))
                .map(|&(id, v)| (id, F32(v)))
                .collect();
            for (id, v) in &values {
                self.last.insert(*id, v.0.to_bits());
            }
            self.last_emit_ms = Some(frame.time_ms);
            return Some(Payload::MetricsSample(MetricsSample {
                time_ms: frame.time_ms,
                values,
            }));
        }
    }
}

impl OpStream for MetricsStream {
    fn next(&mut self) -> LocalBoxFuture<'_, Option<Result<Payload, OpError>>> {
        Box::pin(async move { self.next_item().await.map(Ok) })
    }

    fn latest_only(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Clock;
    use crate::telemetry::SLOW;
    use crate::telemetry::collect::tests::bump_stat;
    use crate::telemetry::tests::{Rig, rig};
    use fleet_crypto::verify::VerifiedCommand;
    use fleet_proto::alert::{AlertKind, AlertRule, Severity};
    use fleet_proto::args::{Nice, Pid, RuleId, Signal};
    use fleet_proto::op::ProcessSort;
    use fleet_proto::{Actor, CommandBody, DeviceId, FleetId, KeyKind, ServerId};

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn meta(r: &Rig, op: &Op, expected_version: Option<u64>) -> OpMeta {
        let command = VerifiedCommand {
            body: CommandBody {
                v: 1,
                fleet_id: FleetId([0; 16]),
                server_id: ServerId::new("srv_test01").unwrap(),
                issued_at_ms: 0,
                ttl_ms: 0,
                nonce: [0; 16],
                actor: Actor::Human,
                op: op.clone(),
                expected_version,
            },
            device_id: DeviceId([0; 16]),
            key: KeyKind::Device,
            approval: None,
            command_hash: [0; 32],
            nonce_expires_at_ms: 0,
        };
        OpMeta {
            command,
            approval: None,
            audit_seq: Some(1),
            now_ms: r.clock.now_ms(),
            invocation: Invocation::Request,
        }
    }

    fn run(r: &Rig, op: Op, ev: Option<u64>) -> Result<Payload, OpError> {
        let h = TelemetryOps(r.tel.clone());
        let m = meta(r, &op, ev);
        h.validate(&r.ctx, &op, &m)?;
        match rt().block_on(h.handle(&r.ctx, &op, &m))? {
            OpOutput::Payload(p) => Ok(p),
            OpOutput::Stream(_) => panic!("stream"),
        }
    }

    fn ticks(r: &Rig, n: usize, every: Duration) {
        for _ in 0..n {
            bump_stat(r.dir.path(), 10, 80, 10);
            r.tel.tick(&r.ctx);
            r.clock.advance(every);
        }
    }

    #[test]
    fn query_raw_and_minutes() {
        let r = rig();
        ticks(&r, 13, SLOW); // two minute boundaries
        let busy = r
            .tel
            .catalog_live()
            .into_iter()
            .find(|s| s.name == "cpu.busy")
            .unwrap();
        let Payload::MetricsHistory(h) = run(
            &r,
            Op::MetricsQuery {
                range: TimeRange::default(),
                resolution: Resolution::Raw,
                series: vec![busy.id, 60_000],
            },
            None,
        )
        .unwrap() else {
            panic!()
        };
        assert_eq!(h.step_ms, 10_000);
        assert_eq!(h.catalog, std::slice::from_ref(&busy)); // unknown id ignored
        let s = &h.series[0];
        let vals: Vec<f32> = s.avg.iter().map(|v| v.0).filter(|v| !v.is_nan()).collect();
        assert_eq!(vals.len(), 12); // first tick has no CPU delta
        assert!(vals.iter().all(|v| (v - 20.0).abs() < 0.01));
        assert_eq!(s.min, s.avg);

        let Payload::MetricsHistory(h) = run(
            &r,
            Op::MetricsQuery {
                range: TimeRange {
                    since_ms: Some(r.clock.now_ms() - 3_600_000),
                    until_ms: None,
                },
                resolution: Resolution::Minute,
                series: vec![],
            },
            None,
        )
        .unwrap() else {
            panic!()
        };
        assert_eq!(h.step_ms, 60_000);
        assert_eq!(h.catalog.len(), r.tel.catalog_live().len());
        let i = h.catalog.iter().position(|c| c.id == busy.id).unwrap();
        let done: Vec<f32> = h.series[i]
            .avg
            .iter()
            .map(|v| v.0)
            .filter(|v| !v.is_nan())
            .collect();
        assert_eq!(done.len(), 2);
    }

    #[test]
    fn query_widens_step_to_fit() {
        let r = rig();
        ticks(&r, 400, Duration::from_secs(1));
        let Payload::MetricsHistory(h) = run(
            &r,
            Op::MetricsQuery {
                range: TimeRange::default(),
                resolution: Resolution::Raw,
                series: vec![],
            },
            None,
        )
        .unwrap() else {
            panic!()
        };
        let points: usize = h.series.iter().map(|s| s.avg.len()).sum();
        assert!(points <= MAX_POINTS, "{points}");
        assert!(h.step_ms >= 1000 && h.step_ms % 1000 == 0);
        // 1 s samples: native step detected.
        let few = query(
            &r.tel,
            r.clock.now_ms(),
            &TimeRange::default(),
            Resolution::Raw,
            &[0],
        )
        .unwrap();
        assert_eq!(few.step_ms, 1000);
    }

    #[test]
    fn subscribe_sends_catalog_then_changes() {
        let r = rig();
        let rt = rt();
        let mut s = MetricsStream::new(&r.tel, SampleInterval::OneSecond);
        assert_eq!(r.tel.interval(), crate::telemetry::FAST);
        assert!(s.latest_only());
        ticks(&r, 2, Duration::from_secs(1));
        rt.block_on(async {
            let Some(Payload::MetricsCatalog(c)) = s.next_item().await else {
                panic!()
            };
            assert!(!c.series.is_empty());
            let Some(Payload::MetricsSample(first)) = s.next_item().await else {
                panic!()
            };
            assert!(first.values.len() > 20);
            // Same load again: memory, load, disk and CPU values are
            // unchanged and not re-sent.
            bump_stat(r.dir.path(), 10, 80, 10);
            r.tel.tick(&r.ctx);
            let Some(Payload::MetricsSample(second)) = s.next_item().await else {
                panic!()
            };
            assert!(second.values.len() < first.values.len());
        });
        drop(s);
        assert_eq!(r.tel.interval(), SLOW);
    }

    #[test]
    fn slow_subscription_skips_fast_frames() {
        let r = rig();
        let rt = rt();
        let _fast = r.tel.fast_guard();
        let mut s = MetricsStream::new(&r.tel, SampleInterval::TenSeconds);
        // Two ticks: CPU series exist from the second on (stable catalog).
        ticks(&r, 2, Duration::from_secs(1));
        rt.block_on(async {
            assert!(matches!(
                s.next_item().await,
                Some(Payload::MetricsCatalog(_))
            ));
            let Some(Payload::MetricsSample(a)) = s.next_item().await else {
                panic!()
            };
            // 1 s ticks: the next item is ≥ 9.5 s later.
            let tel = r.tel.clone();
            let ctx = r.ctx.clone();
            let clock = r.clock.clone();
            let root = r.dir.path().to_owned();
            let feed = async move {
                for _ in 0..12 {
                    clock.advance(Duration::from_secs(1));
                    bump_stat(&root, 10, 80, 10);
                    tel.tick(&ctx);
                    tokio::task::yield_now().await;
                }
            };
            let (b, ()) = tokio::join!(s.next_item(), feed);
            let Some(Payload::MetricsSample(b)) = b else {
                panic!()
            };
            assert!(
                b.time_ms - a.time_ms >= 9_500,
                "{} {}",
                a.time_ms,
                b.time_ms
            );
        });
    }

    #[test]
    fn processes_list_and_history() {
        let r = rig();
        let Payload::ProcessList(l) = run(
            &r,
            Op::ProcessesList {
                sort: ProcessSort::Memory,
                limit: 10,
            },
            None,
        )
        .unwrap() else {
            panic!()
        };
        assert_eq!(l.total, 2);
        assert_eq!(l.processes[0].pid, 4242);

        ticks(&r, 7, SLOW);
        let Payload::ProcessHistory(h) = run(
            &r,
            Op::ProcessesHistory {
                range: TimeRange::default(),
            },
            None,
        )
        .unwrap() else {
            panic!()
        };
        assert_eq!(h.minutes.len(), 1);
        assert_eq!(h.minutes[0].by_memory[0].pid, 4242);
    }

    #[test]
    fn signal_and_renice_guarded() {
        let r = rig();
        let sig = |pid| Op::ProcessSignal {
            pid: Pid::new(pid).unwrap(),
            signal: Signal::Term,
        };
        assert_eq!(run(&r, sig(4242), None), Ok(Payload::Empty));
        assert_eq!(
            run(&r, sig(7), None).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            run(&r, sig(99), None).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            run(&r, sig(5000), None).unwrap_err().code(),
            ErrorCode::NotFound
        );
        let renice = Op::ProcessRenice {
            pid: Pid::new(4242).unwrap(),
            nice: Nice::new(10).unwrap(),
        };
        assert_eq!(run(&r, renice, None), Ok(Payload::Empty));
        assert_eq!(*r.sys.calls.borrow(), ["kill 4242 15", "renice 4242 10"]);
    }

    #[test]
    fn alert_rules_update_versions() {
        let r = rig();
        let set = |v| AlertRuleSet {
            version: v,
            rules: vec![AlertRule {
                id: RuleId::new("mem").unwrap(),
                kind: AlertKind::MemoryUsage,
                threshold: 900,
                for_s: 300,
                severity: Severity::Warning,
                enabled: true,
            }],
        };
        let conflict = |c| Err(OpError::new(ErrorCode::VersionConflict { current: c }));
        // No expected_version, or a stale one: conflict.
        assert_eq!(run(&r, Op::AlertRulesUpdate(set(1)), None), conflict(0));
        assert_eq!(run(&r, Op::AlertRulesUpdate(set(1)), Some(5)), conflict(0));
        assert_eq!(
            run(&r, Op::AlertRulesUpdate(set(1)), Some(0)),
            Ok(Payload::Empty)
        );
        // Not newer.
        assert_eq!(run(&r, Op::AlertRulesUpdate(set(1)), Some(1)), conflict(1));
        assert_eq!(
            run(&r, Op::AlertRulesGet, None),
            Ok(Payload::AlertRules(set(1)))
        );
        assert_eq!(r.store.rules.borrow().as_ref().map(|s| s.version), Some(1));
    }
}
