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
//! **Windows** are daily and in the server's local time: one `date +%z`
//! call gives the UTC offset, and the lead time to the next window start
//! follows from that (right away, at the floor, when the local time is
//! inside a window). A DST switch between now and the window can shift the
//! reboot by the switch's size (one hour at most). No shell string is
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
        ])
        .timeout(COMMAND_TIMEOUT)
}

/// `date +%z`: the local UTC offset (`+0530`).
pub fn offset_command() -> CommandSpec {
    CommandSpec::new(DATE).arg("+%z").timeout(COMMAND_TIMEOUT)
}

/// Seconds east of UTC from `date +%z` output (`+hhmm` / `-hhmm`).
pub fn parse_offset(out: &str) -> Option<i64> {
    let s = out.trim();
    let (sign, rest) = match s.as_bytes().first()? {
        b'+' => (1, &s[1..]),
        b'-' => (-1, &s[1..]),
        _ => return None,
    };
    if rest.len() != 4 || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let hh: i64 = rest[..2].parse().ok()?;
    let mm: i64 = rest[2..].parse().ok()?;
    (hh <= 14 && mm < 60).then_some(sign * (hh * 3600 + mm * 60))
}

/// Lead time in seconds for `when`, from `now_ms` and the local UTC offset
/// (only windows need it). `InvalidArgument` for an `At` in the past or
/// beyond 30 days.
pub fn lead_seconds(when: &RebootWhen, now_ms: u64, offset_s: i64) -> Result<u32, ErrorCode> {
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
        RebootWhen::Window { start_min, end_min } => {
            let now_s = i64::try_from(now_ms / 1000).unwrap_or(i64::MAX);
            let local = now_s.saturating_add(offset_s).rem_euclid(86_400);
            let minute = i64::from(u16::try_from(local / 60).unwrap_or(0));
            let (start, end) = (i64::from(start_min), i64::from(end_min));
            let inside = if start < end {
                (start..end).contains(&minute)
            } else {
                minute >= start || minute < end
            };
            if inside {
                return Ok(MIN_DELAY_S);
            }
            let wait = (start * 60 - local).rem_euclid(i64::from(MINUTES_PER_DAY) * 60);
            Ok(floor(u64::try_from(wait).unwrap_or(0)))
        }
    }
}

/// `at=<ms>` out of `systemctl show` output; `None` when no active timer.
/// An active timer whose description has no parsable time (armed by
/// something else) answers `Some(0)`: scheduled, time unknown.
pub fn parse_status(text: &str) -> RebootStatus {
    let mut active = false;
    let mut at = None;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("ActiveState=") {
            active = v.trim() == "active";
        } else if let Some(v) = line.strip_prefix("Description=") {
            at = v
                .trim()
                .strip_prefix(DESCRIPTION_PREFIX)
                .filter(|d| !d.is_empty() && d.len() <= 20 && d.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|d| d.parse::<u64>().ok());
        }
    }
    RebootStatus {
        at_ms: active.then_some(at.unwrap_or(0)),
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
        let out = ctx.runner.run(cancel_command()).await?;
        if !out.success() && out.code != Some(NOT_LOADED) {
            return Err(OpError::internal(format!(
                "stop earlier reboot timer: exit {:?}",
                out.code
            )));
        }
        let at_ms = ctx.clock.now_ms() + u64::from(secs) * 1000;
        let out = ctx.runner.run(schedule_command(secs, at_ms)).await?;
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

    async fn utc_offset(&self, ctx: &SysCtx) -> Result<i64, OpError> {
        let out = ctx.runner.run(offset_command()).await?;
        if !out.success() {
            return Err(OpError::internal(format!("date: exit {:?}", out.code)));
        }
        parse_offset(&String::from_utf8_lossy(&out.stdout))
            .ok_or_else(|| OpError::internal("date: unexpected UTC offset"))
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
                    let offset = match when {
                        RebootWhen::Window { .. } => self.utc_offset(ctx).await?,
                        _ => 0,
                    };
                    let secs = lead_seconds(when, ctx.clock.now_ms(), offset)?;
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
    fn offsets_parse_strictly() {
        assert_eq!(parse_offset("+0000\n"), Some(0));
        assert_eq!(parse_offset("+0530"), Some(19_800));
        assert_eq!(parse_offset("-0800"), Some(-28_800));
        for bad in ["", "0530", "+530", "+05:30", "+1500", "+0560", "+05a0", "UTC"] {
            assert_eq!(parse_offset(bad), None, "{bad:?}");
        }
    }

    /// 2026-01-01 00:00:00 UTC.
    const MIDNIGHT: u64 = 1_767_225_600_000;

    #[test]
    fn window_lead_time_follows_local_time() {
        let win = |s, e| RebootWhen::Window {
            start_min: s,
            end_min: e,
        };
        let at = |h: u64, m: u64| MIDNIGHT + (h * 3600 + m * 60) * 1000;
        // UTC, 01:00, window 03:00-05:00: two hours to the start.
        assert_eq!(lead_seconds(&win(180, 300), at(1, 0), 0), Ok(7200));
        // Inside the window: right away.
        assert_eq!(lead_seconds(&win(180, 300), at(4, 0), 0), Ok(MIN_DELAY_S));
        // Window end is exclusive: 05:00 waits for tomorrow's 03:00.
        assert_eq!(lead_seconds(&win(180, 300), at(5, 0), 0), Ok(22 * 3600));
        // Window start inclusive.
        assert_eq!(lead_seconds(&win(180, 300), at(3, 0), 0), Ok(MIN_DELAY_S));
        // Local time east of UTC: 01:00 UTC is 03:30 at +02:30 = inside.
        assert_eq!(
            lead_seconds(&win(180, 300), at(1, 0), 9000),
            Ok(MIN_DELAY_S)
        );
        // West of UTC: 01:00 UTC is 20:00 the day before at -05:00.
        assert_eq!(
            lead_seconds(&win(180, 300), at(1, 0), -5 * 3600),
            Ok(7 * 3600)
        );
        // Wrapping window 23:00-01:00.
        assert_eq!(lead_seconds(&win(1380, 60), at(23, 30), 0), Ok(MIN_DELAY_S));
        assert_eq!(lead_seconds(&win(1380, 60), at(0, 30), 0), Ok(MIN_DELAY_S));
        assert_eq!(lead_seconds(&win(1380, 60), at(12, 0), 0), Ok(11 * 3600));
    }

    #[test]
    fn at_and_in_bounds() {
        let now = MIDNIGHT;
        let at = |ms| RebootWhen::At { at_ms: ms };
        assert_eq!(lead_seconds(&at(now + 90_500), now, 0), Ok(91));
        assert_eq!(lead_seconds(&at(now + 1000), now, 0), Ok(MIN_DELAY_S));
        assert_eq!(lead_seconds(&at(now), now, 0), Ok(MIN_DELAY_S));
        assert_eq!(
            lead_seconds(&at(now - 1), now, 0),
            Err(ErrorCode::InvalidArgument)
        );
        let max = u64::from(REBOOT_MAX_LEAD_S) * 1000;
        assert!(lead_seconds(&at(now + max), now, 0).is_ok());
        assert_eq!(
            lead_seconds(&at(now + max + 1), now, 0),
            Err(ErrorCode::InvalidArgument)
        );
        assert_eq!(
            lead_seconds(&RebootWhen::In { delay_s: 0 }, now, 0),
            Ok(MIN_DELAY_S)
        );
    }

    #[test]
    fn schedule_window_asks_for_the_offset_then_arms() {
        let dir = tempfile::tempdir().unwrap();
        let r = Rc::new(FakeRunner::new());
        // T0's local time at +01:00 decides the lead; whatever it is, the
        // timer is armed once with the description carrying the target.
        r.expect(DATE, &["+%z"], Ok(CommandOutput::ok("+0100\n")));
        let c = ctx_at(dir.path(), r.clone(), T0);
        let win = RebootWhen::Window {
            start_min: 0,
            end_min: 1439,
        };
        // 00:00-23:59 covers all but the last minute; pick T0's inside state.
        let lead = lead_seconds(&win, T0, 3600).unwrap();
        r.expect(SYSTEMCTL, STOP, Ok(CommandOutput::exit(NOT_LOADED)))
            .expect(
                SYSTEMD_RUN,
                &as_strs(&run_args(&format!("{lead}s"), T0 + u64::from(lead) * 1000)),
                Ok(CommandOutput::ok("")),
            );
        let sink = Rc::new(Sink::default());
        let h = RebootHandler::new(sink.clone());
        let op = Op::SystemRebootSchedule { when: win };
        block(h.handle(&c, &op, &meta(op.clone(), Some(4)))).unwrap();
        assert_eq!(r.pending(), 0);
        assert_eq!(sink.0.borrow().len(), 1);
        // An unparsable offset arms nothing.
        let r = Rc::new(FakeRunner::new());
        r.expect(DATE, &["+%z"], Ok(CommandOutput::ok("CEST")));
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
