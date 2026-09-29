//! `system.reboot`, `system.reboot.schedule`, `system.reboot.cancel` and
//! `system.reboot.status` (design §9; `system` group, tiers Change / Read):
//! `systemctl reboot` armed through one transient systemd timer, so the
//! command's receipt reaches the Mac before the machine goes down and the
//! reboot survives exec itself stopping.
//!
//! `systemd-run --on-active=<s>s --timer-property=AccuracySec=1s
//! --unit=fleet-reboot --collect --description="Fleet scheduled reboot
//! at=<ms>" /usr/bin/systemctl reboot`, after stopping any earlier
//! `fleet-reboot` timer (the newest schedule wins). The lead time is at
//! least [`MIN_DELAY_S`]. The target time travels in the timer's
//! description (`at=<unix ms>`), so `system.reboot.status` needs no state
//! of its own and a status read after an exec restart still knows.
//! Emits `reboot.scheduled`; the audit log has the command like any other.
//!
//! **Windows** are daily and in the server's local time. One
//! `date +%H:%M:%S` call tells whether the window is open now (then the
//! one-shot above, at the floor, unless the window closes within the
//! floor); otherwise `--on-calendar='*-*-* HH:MM:00'` at the window start,
//! which systemd resolves with the server's time zone rules, so DST
//! changes before the start are handled. `system.reboot.status` reads
//! systemd's `NextElapseUSecRealtime` for such a timer. No shell string is
//! built anywhere: fixed binary paths and argument lists.

use crate::ctx::SysCtx;
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput};
use crate::runner::{CommandSpec, SYSTEMCTL};
use crate::scope::SYSTEMD_RUN;
use crate::security::EventSink;
use fleet_proto::op::{MINUTES_PER_DAY, REBOOT_MAX_LEAD_S, RebootWhen};
use fleet_proto::payload::RebootStatus;
use fleet_proto::{ErrorCode, Event, Op, Payload};
use std::rc::Rc;
use std::time::Duration;

pub const UNIT: &str = "fleet-reboot";
pub const DATE: &str = "/usr/bin/date";
/// The receipt must leave first.
pub const MIN_DELAY_S: u32 = 5;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
/// `systemctl stop` of a unit that isn't loaded.
const NOT_LOADED: i32 = 5;
const DESCRIPTION_PREFIX: &str = "Fleet scheduled reboot at=";

/// `systemctl stop fleet-reboot.timer fleet-reboot.service`.
pub fn cancel_command() -> CommandSpec {
    CommandSpec::new(SYSTEMCTL)
        .args(["stop", "fleet-reboot.timer", "fleet-reboot.service"])
        .timeout(COMMAND_TIMEOUT)
}

/// Arms the timer `secs` from now; `at_ms` is the resulting wall-clock
/// time, recorded in the description for `system.reboot.status`.
pub fn schedule_command(secs: u32, at_ms: u64) -> CommandSpec {
    CommandSpec::new(SYSTEMD_RUN)
        .args([
            format!("--on-active={secs}s"),
            "--timer-property=AccuracySec=1s".to_owned(),
            format!("--unit={UNIT}"),
            "--collect".to_owned(),
            format!("--description={DESCRIPTION_PREFIX}{at_ms}"),
            SYSTEMCTL.to_owned(),
            "reboot".to_owned(),
        ])
        .timeout(COMMAND_TIMEOUT)
}

/// `systemctl show fleet-reboot.timer` for the two properties status reads.
pub fn status_command() -> CommandSpec {
    CommandSpec::new(SYSTEMCTL)
        .args([
            "show",
            "fleet-reboot.timer",
            "--property=ActiveState",
            "--property=Description",
            "--property=NextElapseUSecRealtime",
            "--timestamp=utc",
        ])
        .timeout(COMMAND_TIMEOUT)
}

/// `date +%H:%M:%S`: the server's local time of day. Only "is the window
/// open right now" needs it; the future start is left to systemd's
/// calendar (which follows the server's time zone rules, DST included).
pub fn local_time_command() -> CommandSpec {
    CommandSpec::new(DATE)
        .arg("+%H:%M:%S")
        .timeout(COMMAND_TIMEOUT)
}

/// Seconds since local midnight from `date +%H:%M:%S` output.
pub fn parse_local_seconds(out: &str) -> Option<u32> {
    let mut parts = out.trim().split(':');
    let mut field = |max: u32| {
        let p = parts.next()?;
        if p.len() != 2 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        p.parse::<u32>().ok().filter(|v| *v <= max)
    };
    // 60: a leap second.
    let (h, m, s) = (field(23)?, field(59)?, field(60)?);
    parts.next().is_none().then_some(h * 3600 + m * 60 + s)
}

/// `--on-calendar` for the window start (server-local, DST-aware).
pub fn calendar_command(start_min: u16) -> CommandSpec {
    CommandSpec::new(SYSTEMD_RUN)
        .args([
            format!(
                "--on-calendar=*-*-* {:02}:{:02}:00",
                start_min / 60,
                start_min % 60
            ),
            "--timer-property=AccuracySec=1s".to_owned(),
            format!("--unit={UNIT}"),
            "--collect".to_owned(),
            "--description=Fleet scheduled reboot window".to_owned(),
            SYSTEMCTL.to_owned(),
            "reboot".to_owned(),
        ])
        .timeout(COMMAND_TIMEOUT)
}

/// What a window means right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowPlan {
    /// Open now with room to spare: reboot after the floor.
    Now,
    /// Closed, or closing within the floor: at the next start, `wait_s`
    /// from now by the local clock (an estimate; systemd decides).
    Next { wait_s: u32 },
}

/// `local_s`: seconds since local midnight. A reboot armed `MIN_DELAY_S`
/// from now must still land before the window's (exclusive) end, else the
/// next day's window is used.
pub fn plan_window(start_min: u16, end_min: u16, local_s: u32) -> WindowPlan {
    let day = i64::from(MINUTES_PER_DAY) * 60;
    let (s, e, now) = (
        i64::from(start_min) * 60,
        i64::from(end_min) * 60,
        i64::from(local_s),
    );
    let inside = if s < e {
        (s..e).contains(&now)
    } else {
        now >= s || now < e
    };
    let left = (e - now).rem_euclid(day);
    if inside && left > i64::from(MIN_DELAY_S) {
        return WindowPlan::Now;
    }
    let wait = (s - now).rem_euclid(day);
    // Equal (inside, about to close, at the start second): a full day.
    let wait = if wait == 0 { day } else { wait };
    WindowPlan::Next {
        wait_s: u32::try_from(wait).unwrap_or(u32::MAX),
    }
}

/// Lead time in seconds for `In` and `At` (`InvalidArgument` for an `At`
/// in the past or beyond 30 days). Windows go through [`plan_window`].
pub fn lead_seconds(when: &RebootWhen, now_ms: u64) -> Result<u32, ErrorCode> {
    let floor = |s: u64| u32::try_from(s).unwrap_or(u32::MAX).max(MIN_DELAY_S);
    match *when {
        RebootWhen::In { delay_s } => Ok(floor(u64::from(delay_s))),
        RebootWhen::At { at_ms } => {
            if at_ms < now_ms {
                return Err(ErrorCode::InvalidArgument);
            }
            let secs = (at_ms - now_ms).div_ceil(1000);
            if secs > u64::from(REBOOT_MAX_LEAD_S) {
                return Err(ErrorCode::InvalidArgument);
            }
            Ok(floor(secs))
        }
        RebootWhen::Window { .. } => Err(ErrorCode::Internal),
    }
}

/// Unix seconds of systemd's `--timestamp=utc` form, `Tue 2026-09-29
/// 04:43:00 UTC` (a weekday name, `YYYY-MM-DD`, `HH:MM:SS`, `UTC`; the
/// weekday is not checked). `None` for anything else, dates before 1970
/// and the `n/a` systemd prints for no next elapse.
pub fn parse_utc_timestamp(s: &str) -> Option<u64> {
    let mut it = s.split(' ').filter(|p| !p.is_empty());
    let (wd, date, time, tz) = (it.next()?, it.next()?, it.next()?, it.next()?);
    if it.next().is_some()
        || tz != "UTC"
        || wd.len() != 3
        || !wd.bytes().all(|b| b.is_ascii_alphabetic())
    {
        return None;
    }
    let num = |p: &str, len: usize| {
        (p.len() == len && p.bytes().all(|b| b.is_ascii_digit()))
            .then(|| p.parse::<i64>().ok())
            .flatten()
    };
    let mut d = date.split('-');
    let (y, m, day) = (num(d.next()?, 4)?, num(d.next()?, 2)?, num(d.next()?, 2)?);
    let mut t = time.split(':');
    let (hh, mm, ss) = (num(t.next()?, 2)?, num(t.next()?, 2)?, num(t.next()?, 2)?);
    if d.next().is_some()
        || t.next().is_some()
        || !(1970..=9999).contains(&y)
        || !(1..=12).contains(&m)
        || !(1..=31).contains(&day)
        || hh > 23
        || mm > 59
        || ss > 60
    {
        return None;
    }
    // Days from civil (Howard Hinnant's algorithm).
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + hh * 3600 + mm * 60 + ss).ok()
}

/// Reads `systemctl show` output: `None` when no active timer. The target
/// is the description's `at=<ms>` (our own one-shot timers); a calendar
/// timer has none, so `NextElapseUSecRealtime` (systemd's own next elapse,
/// DST-correct, in `--timestamp=utc` form) stands in. An active timer with neither
/// answers `Some(0)`: scheduled, time unknown.
pub fn parse_status(text: &str) -> RebootStatus {
    let mut active = false;
    let mut at = None;
    let mut next = None;
    let digits = |d: &str| {
        (!d.is_empty() && d.len() <= 20 && d.bytes().all(|b| b.is_ascii_digit()))
            .then(|| d.parse::<u64>().ok())
            .flatten()
    };
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("ActiveState=") {
            active = v.trim() == "active";
        } else if let Some(v) = line.strip_prefix("Description=") {
            at = v
                .trim()
                .strip_prefix(DESCRIPTION_PREFIX)
                .and_then(digits);
        } else if let Some(v) = line.strip_prefix("NextElapseUSecRealtime=") {
            next = parse_utc_timestamp(v.trim()).and_then(|s| s.checked_mul(1000));
        }
    }
    RebootStatus {
        at_ms: active.then_some(at.or(next).unwrap_or(0)),
    }
}

pub struct RebootHandler {
    sink: Rc<dyn EventSink>,
}

impl RebootHandler {
    pub fn new(sink: Rc<dyn EventSink>) -> Self {
        Self { sink }
    }

    /// Replaces any earlier timer with one firing in `secs`.
    async fn arm(&self, ctx: &SysCtx, secs: u32, meta: &OpMeta) -> Result<OpOutput, OpError> {
        let at_ms = ctx.clock.now_ms() + u64::from(secs) * 1000;
        self.arm_with(ctx, schedule_command(secs, at_ms), at_ms, meta)
            .await
    }

    /// Stops any earlier timer, runs `arm` (a `systemd-run` spec) and
    /// announces `at_ms` (an estimate for calendar timers).
    async fn arm_with(
        &self,
        ctx: &SysCtx,
        arm: CommandSpec,
        at_ms: u64,
        meta: &OpMeta,
    ) -> Result<OpOutput, OpError> {
        let out = ctx.runner.run(cancel_command()).await?;
        if !out.success() && out.code != Some(NOT_LOADED) {
            return Err(OpError::internal(format!(
                "stop earlier reboot timer: exit {:?}",
                out.code
            )));
        }
        let out = ctx.runner.run(arm).await?;
        if !out.success() {
            return Err(OpError::internal(format!(
                "systemd-run reboot timer: exit {:?}",
                out.code
            )));
        }
        self.sink.emit(Event::RebootScheduled {
            at_ms,
            audit_seq: meta.audit_seq.unwrap_or(0),
        });
        Ok(OpOutput::Payload(Payload::Empty))
    }

    async fn local_seconds(&self, ctx: &SysCtx) -> Result<u32, OpError> {
        let out = ctx.runner.run(local_time_command()).await?;
        if !out.success() {
            return Err(OpError::internal(format!("date: exit {:?}", out.code)));
        }
        parse_local_seconds(&String::from_utf8_lossy(&out.stdout))
            .ok_or_else(|| OpError::internal("date: unexpected local time"))
    }
}

impl OpHandler for RebootHandler {
    fn validate(&self, _ctx: &SysCtx, op: &Op, _meta: &OpMeta) -> Result<(), OpError> {
        match op {
            Op::SystemReboot { .. }
            | Op::SystemRebootSchedule { .. }
            | Op::SystemRebootCancel
            | Op::SystemRebootStatus => Ok(()),
            _ => Err(ErrorCode::Unsupported.into()),
        }
    }

    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        op: &'a Op,
        meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            match op {
                Op::SystemReboot { delay_s } => {
                    self.arm(ctx, (*delay_s).max(MIN_DELAY_S), meta).await
                }
                Op::SystemRebootSchedule { when } => {
                    if let RebootWhen::Window { start_min, end_min } = *when {
                        let local = self.local_seconds(ctx).await?;
                        return match plan_window(start_min, end_min, local) {
                            WindowPlan::Now => self.arm(ctx, MIN_DELAY_S, meta).await,
                            WindowPlan::Next { wait_s } => {
                                let at = ctx.clock.now_ms() + u64::from(wait_s) * 1000;
                                self.arm_with(ctx, calendar_command(start_min), at, meta)
                                    .await
                            }
                        };
                    }
                    let secs = lead_seconds(when, ctx.clock.now_ms())?;
                    self.arm(ctx, secs, meta).await
                }
                Op::SystemRebootCancel => {
                    // Idempotent: nothing scheduled is fine.
                    let out = ctx.runner.run(cancel_command()).await?;
                    if !out.success() && out.code != Some(NOT_LOADED) {
                        return Err(OpError::internal(format!(
                            "stop reboot timer: exit {:?}",
                            out.code
                        )));
                    }
                    Ok(OpOutput::Payload(Payload::Empty))
                }
                Op::SystemRebootStatus => {
                    let out = ctx.runner.run(status_command()).await?;
                    if !out.success() {
                        return Err(OpError::internal(format!(
                            "systemctl show: exit {:?}",
                            out.code
                        )));
                    }
                    Ok(OpOutput::Payload(Payload::RebootStatus(parse_status(
                        &String::from_utf8_lossy(&out.stdout),
                    ))))
                }
                _ => Err(ErrorCode::Unsupported.into()),
            }
        })
    }
}

/// Registers every reboot tag on one handler.
pub fn register(r: &mut crate::handler::Registry, sink: Rc<dyn EventSink>) {
    use fleet_proto::op::tag;
    let h = Rc::new(RebootHandler::new(sink));
    for t in [
        tag::SYSTEM_REBOOT,
        tag::SYSTEM_REBOOT_SCHEDULE,
        tag::SYSTEM_REBOOT_CANCEL,
        tag::SYSTEM_REBOOT_STATUS,
    ] {
        r.register(t, h.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::{CommandOutput, RunError};
    use crate::testutil::{T0, block, ctx_at, meta};
    use crate::FakeRunner;
    use std::cell::RefCell;

    #[derive(Default)]
    struct Sink(RefCell<Vec<Event>>);

    impl EventSink for Sink {
        fn emit(&self, event: Event) {
            self.0.borrow_mut().push(event);
        }
    }

    const STOP: &[&str] = &["stop", "fleet-reboot.timer", "fleet-reboot.service"];
    const SHOW: &[&str] = &[
        "show",
        "fleet-reboot.timer",
        "--property=ActiveState",
        "--property=Description",
        "--property=NextElapseUSecRealtime",
        "--timestamp=utc",
    ];

    fn run_args(secs: &str, at_ms: u64) -> Vec<String> {
        vec![
            format!("--on-active={secs}"),
            "--timer-property=AccuracySec=1s".into(),
            "--unit=fleet-reboot".into(),
            "--collect".into(),
            format!("--description=Fleet scheduled reboot at={at_ms}"),
            SYSTEMCTL.into(),
            "reboot".into(),
        ]
    }

    fn as_strs(v: &[String]) -> Vec<&str> {
        v.iter().map(String::as_str).collect()
    }

    #[test]
    fn schedules_timer_and_emits() {
        let dir = tempfile::tempdir().unwrap();
        let r = Rc::new(FakeRunner::new());
        let args = run_args("300s", T0 + 300_000);
        r.expect(SYSTEMCTL, STOP, Ok(CommandOutput::exit(NOT_LOADED)))
            .expect(SYSTEMD_RUN, &as_strs(&args), Ok(CommandOutput::ok("")));
        let c = ctx_at(dir.path(), r.clone(), T0);
        let sink = Rc::new(Sink::default());
        let h = RebootHandler::new(sink.clone());
        let op = Op::SystemReboot { delay_s: 300 };
        h.validate(&c, &op, &meta(op.clone(), None)).unwrap();
        let out = block(h.handle(&c, &op, &meta(op.clone(), Some(9)))).unwrap();
        assert!(matches!(out, OpOutput::Payload(Payload::Empty)));
        assert_eq!(r.pending(), 0);
        assert_eq!(
            sink.0.borrow().as_slice(),
            [Event::RebootScheduled {
                at_ms: T0 + 300_000,
                audit_seq: 9
            }]
        );
    }

    #[test]
    fn minimum_delay_and_failures() {
        let dir = tempfile::tempdir().unwrap();
        let r = Rc::new(FakeRunner::new());
        let args = run_args("5s", T0 + 5_000);
        r.expect(SYSTEMCTL, STOP, Ok(CommandOutput::ok("")))
            .expect(SYSTEMD_RUN, &as_strs(&args), Ok(CommandOutput::exit(1)));
        let c = ctx_at(dir.path(), r.clone(), T0);
        let sink = Rc::new(Sink::default());
        let h = RebootHandler::new(sink.clone());
        let op = Op::SystemReboot { delay_s: 0 };
        let e = block(h.handle(&c, &op, &meta(op.clone(), Some(1)))).unwrap_err();
        assert_eq!(e.code(), ErrorCode::Internal);
        assert!(sink.0.borrow().is_empty());
        // A failing stop (not "not loaded") aborts before scheduling.
        let r = Rc::new(FakeRunner::new());
        r.expect(SYSTEMCTL, STOP, Ok(CommandOutput::exit(1)));
        let c = ctx_at(dir.path(), r.clone(), T0);
        assert!(block(h.handle(&c, &op, &meta(op.clone(), Some(2)))).is_err());
        assert_eq!(r.calls().len(), 1);
        let r = Rc::new(FakeRunner::new());
        r.expect(SYSTEMCTL, STOP, Err(RunError::Timeout));
        let c = ctx_at(dir.path(), r, T0);
        let e = block(h.handle(&c, &op, &meta(op.clone(), Some(3)))).unwrap_err();
        assert_eq!(e.code(), ErrorCode::Timeout);
    }

    #[test]
    fn local_time_parses_strictly() {
        assert_eq!(parse_local_seconds("00:00:00\n"), Some(0));
        assert_eq!(parse_local_seconds("03:30:15"), Some(3 * 3600 + 30 * 60 + 15));
        assert_eq!(parse_local_seconds("23:59:60"), Some(86_400));
        for bad in [
            "", "3:30:15", "03:30", "03:30:15:01", "24:00:00", "03:60:00", "03:30:61", "0a:00:00",
            "+0100", "03:30:-1", "03: 0:00",
        ] {
            assert_eq!(parse_local_seconds(bad), None, "{bad:?}");
        }
    }

    /// 2026-01-01 00:00:00 UTC.
    const MIDNIGHT: u64 = 1_767_225_600_000;

    #[test]
    fn window_plan_follows_the_local_clock() {
        let at = |h: u32, m: u32, s: u32| h * 3600 + m * 60 + s;
        let next = |wait_s| WindowPlan::Next { wait_s };
        // 01:00, window 03:00-05:00: two hours to the start.
        assert_eq!(plan_window(180, 300, at(1, 0, 0)), next(7200));
        // Inside: right away; the start is inclusive.
        assert_eq!(plan_window(180, 300, at(4, 0, 0)), WindowPlan::Now);
        assert_eq!(plan_window(180, 300, at(3, 0, 0)), WindowPlan::Now);
        // The end is exclusive: 05:00 waits for tomorrow's 03:00.
        assert_eq!(plan_window(180, 300, at(5, 0, 0)), next(22 * 3600));
        // Wrapping window 23:00-01:00.
        assert_eq!(plan_window(1380, 60, at(23, 30, 0)), WindowPlan::Now);
        assert_eq!(plan_window(1380, 60, at(0, 30, 0)), WindowPlan::Now);
        assert_eq!(plan_window(1380, 60, at(12, 0, 0)), next(11 * 3600));
    }

    /// The floor must not push the reboot past the window's end: with
    /// `MIN_DELAY_S` or less left, the next day's window is used.
    #[test]
    fn window_closing_within_the_floor_picks_tomorrow() {
        let end = 300 * 60;
        let day = 86_400;
        // Six seconds left: room for the 5 s floor.
        assert_eq!(plan_window(180, 300, end - 6), WindowPlan::Now);
        // Exactly the floor left, and less: too late.
        for left in [MIN_DELAY_S, 3, 1] {
            assert_eq!(
                plan_window(180, 300, end - left),
                WindowPlan::Next {
                    wait_s: 180 * 60 + day - (end - left)
                },
                "{left}"
            );
        }
        // Same across midnight (window 23:00-01:00, 2 s before 01:00).
        assert_eq!(
            plan_window(1380, 60, 3600 - 2),
            WindowPlan::Next {
                wait_s: 1380 * 60 - (3600 - 2)
            }
        );
    }

    #[test]
    fn calendar_timer_leaves_dst_to_systemd() {
        let c = calendar_command(3 * 60 + 5);
        let args: Vec<String> = c
            .args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args[0], "--on-calendar=*-*-* 03:05:00");
        assert!(args.contains(&"--unit=fleet-reboot".to_owned()));
        assert!(!args.iter().any(|a| a.starts_with("--on-active")));
    }

    #[test]
    fn at_and_in_bounds() {
        let now = MIDNIGHT;
        let at = |ms| RebootWhen::At { at_ms: ms };
        assert_eq!(lead_seconds(&at(now + 90_500), now), Ok(91));
        assert_eq!(lead_seconds(&at(now + 1000), now), Ok(MIN_DELAY_S));
        assert_eq!(lead_seconds(&at(now), now), Ok(MIN_DELAY_S));
        assert_eq!(
            lead_seconds(&at(now - 1), now),
            Err(ErrorCode::InvalidArgument)
        );
        let max = u64::from(REBOOT_MAX_LEAD_S) * 1000;
        assert!(lead_seconds(&at(now + max), now).is_ok());
        assert_eq!(
            lead_seconds(&at(now + max + 1), now),
            Err(ErrorCode::InvalidArgument)
        );
        assert_eq!(
            lead_seconds(&RebootWhen::In { delay_s: 0 }, now),
            Ok(MIN_DELAY_S)
        );
    }

    #[test]
    fn schedule_window_arms_now_or_a_calendar_timer() {
        let dir = tempfile::tempdir().unwrap();
        let sink = Rc::new(Sink::default());
        let h = RebootHandler::new(sink.clone());
        let op = Op::SystemRebootSchedule {
            when: RebootWhen::Window {
                start_min: 180,
                end_min: 300,
            },
        };
        // Open now (04:00 local): the floor, as a one-shot with `at=`.
        let r = Rc::new(FakeRunner::new());
        r.expect(DATE, &["+%H:%M:%S"], Ok(CommandOutput::ok("04:00:00\n")))
            .expect(SYSTEMCTL, STOP, Ok(CommandOutput::exit(NOT_LOADED)))
            .expect(
                SYSTEMD_RUN,
                &as_strs(&run_args("5s", T0 + 5_000)),
                Ok(CommandOutput::ok("")),
            );
        let c = ctx_at(dir.path(), r.clone(), T0);
        block(h.handle(&c, &op, &meta(op.clone(), Some(4)))).unwrap();
        assert_eq!(r.pending(), 0);
        // Closed (01:00 local): systemd's calendar, announced with the
        // local-clock estimate.
        let r = Rc::new(FakeRunner::new());
        r.expect(DATE, &["+%H:%M:%S"], Ok(CommandOutput::ok("01:00:00\n")))
            .expect(SYSTEMCTL, STOP, Ok(CommandOutput::exit(NOT_LOADED)))
            .expect(
                SYSTEMD_RUN,
                &[
                    "--on-calendar=*-*-* 03:00:00",
                    "--timer-property=AccuracySec=1s",
                    "--unit=fleet-reboot",
                    "--collect",
                    "--description=Fleet scheduled reboot window",
                    SYSTEMCTL,
                    "reboot",
                ],
                Ok(CommandOutput::ok("")),
            );
        let c = ctx_at(dir.path(), r.clone(), T0);
        block(h.handle(&c, &op, &meta(op.clone(), Some(5)))).unwrap();
        assert_eq!(r.pending(), 0);
        assert_eq!(
            sink.0.borrow().last(),
            Some(&Event::RebootScheduled {
                at_ms: T0 + 7_200_000,
                audit_seq: 5
            })
        );
        // An unparsable local time arms nothing.
        let r = Rc::new(FakeRunner::new());
        r.expect(DATE, &["+%H:%M:%S"], Ok(CommandOutput::ok("CEST")));
        let c = ctx_at(dir.path(), r.clone(), T0);
        let e = block(h.handle(&c, &op, &meta(op.clone(), Some(5)))).unwrap_err();
        assert_eq!(e.code(), ErrorCode::Internal);
        assert_eq!(r.calls().len(), 1);
        // A past `At` is refused before anything runs.
        let r = Rc::new(FakeRunner::new());
        let c = ctx_at(dir.path(), r.clone(), T0);
        let op = Op::SystemRebootSchedule {
            when: RebootWhen::At { at_ms: T0 - 1 },
        };
        let e = block(h.handle(&c, &op, &meta(op.clone(), Some(6)))).unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert!(r.calls().is_empty());
    }

    /// The committed fuzz seeds (malformed included) never panic.
    #[test]
    fn fuzz_seeds_parse_without_panic() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/reboot_parse");
        let mut n = 0;
        for e in std::fs::read_dir(dir).unwrap() {
            let bytes = std::fs::read(e.unwrap().path()).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            let _ = parse_status(&text);
            if let Some(s) = parse_local_seconds(&text) {
                assert!(s <= 86_400);
            }
            n += 1;
        }
        assert!(n >= 5);
    }

    #[test]
    fn cancel_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let sink = Rc::new(Sink::default());
        let h = RebootHandler::new(sink);
        let op = Op::SystemRebootCancel;
        for reply in [CommandOutput::ok(""), CommandOutput::exit(NOT_LOADED)] {
            let r = Rc::new(FakeRunner::new());
            r.expect(SYSTEMCTL, STOP, Ok(reply));
            let c = ctx_at(dir.path(), r.clone(), T0);
            let out = block(h.handle(&c, &op, &meta(op.clone(), Some(1)))).unwrap();
            assert!(matches!(out, OpOutput::Payload(Payload::Empty)));
            assert_eq!(r.pending(), 0);
        }
        let r = Rc::new(FakeRunner::new());
        r.expect(SYSTEMCTL, STOP, Ok(CommandOutput::exit(1)));
        let c = ctx_at(dir.path(), r, T0);
        assert!(block(h.handle(&c, &op, &meta(op.clone(), Some(2)))).is_err());
    }

    #[test]
    fn status_reads_the_timer_description() {
        assert_eq!(
            parse_status("ActiveState=active\nDescription=Fleet scheduled reboot at=1750000000123\n"),
            RebootStatus {
                at_ms: Some(1_750_000_000_123)
            }
        );
        // Not loaded / inactive: nothing scheduled.
        assert_eq!(
            parse_status("ActiveState=inactive\nDescription=fleet-reboot.timer\n"),
            RebootStatus { at_ms: None }
        );
        // Armed by something else: scheduled, time unknown.
        assert_eq!(
            parse_status("ActiveState=active\nDescription=Fleet scheduled reboot\n"),
            RebootStatus { at_ms: Some(0) }
        );
        // A calendar timer has no `at=`: systemd's own next elapse.
        assert_eq!(
            parse_status(
                "ActiveState=active\nDescription=Fleet scheduled reboot window\nNextElapseUSecRealtime=Tue 2026-09-29 04:43:00 UTC\n"
            ),
            RebootStatus {
                at_ms: Some(1_790_656_980_000)
            }
        );
        assert_eq!(parse_utc_timestamp("Thu 2024-02-29 23:59:59 UTC"), Some(1_709_251_199));
        assert_eq!(parse_utc_timestamp("Thu 1970-01-01 00:00:00 UTC"), Some(0));
        // The description wins when both are there; junk next elapses
        // are ignored.
        assert_eq!(
            parse_status("ActiveState=active\nDescription=Fleet scheduled reboot at=7\nNextElapseUSecRealtime=Tue 2026-09-29 04:43:00 UTC\n").at_ms,
            Some(7)
        );
        for n in [
            "",
            "n/a",
            "@1750000000",
            "Tue 2026-09-29 04:43:00 CEST",
            "Tue 2026-09-29 04:43:00",
            "Tue 2026-09-29 04:43:00 UTC extra",
            "Tue 2026-13-29 04:43:00 UTC",
            "Tue 2026-09-32 04:43:00 UTC",
            "Tue 2026-09-29 24:43:00 UTC",
            "Tue 1969-12-31 23:59:59 UTC",
            "Tue 99999999999-09-29 04:43:00 UTC",
            "Tue 2026-9-29 4:43:00 UTC",
            "Tue 2026-09-29-01 04:43:00 UTC",
            "Tuesday 2026-09-29 04:43:00 UTC",
        ] {
            let t = format!("ActiveState=active\nNextElapseUSecRealtime={n}\n");
            assert_eq!(parse_status(&t).at_ms, Some(0), "{n}");
        }
        // Hostile description text is not parsed as a time.
        for d in [
            "at=12x",
            "at=",
            "at=999999999999999999999999",
            "at=-5",
            "at= 5 ",
        ] {
            let t = format!("ActiveState=active\nDescription=Fleet scheduled reboot {d}\n");
            assert_eq!(parse_status(&t).at_ms, Some(0), "{d}");
        }
        let dir = tempfile::tempdir().unwrap();
        let r = Rc::new(FakeRunner::new());
        r.expect(
            SYSTEMCTL,
            SHOW,
            Ok(CommandOutput::ok(
                "ActiveState=active\nDescription=Fleet scheduled reboot at=42\n",
            )),
        );
        let c = ctx_at(dir.path(), r, T0);
        let h = RebootHandler::new(Rc::new(Sink::default()));
        let op = Op::SystemRebootStatus;
        match block(h.handle(&c, &op, &meta(op.clone(), Some(1)))).unwrap() {
            OpOutput::Payload(Payload::RebootStatus(s)) => assert_eq!(s.at_ms, Some(42)),
            _ => panic!(),
        }
    }
}
