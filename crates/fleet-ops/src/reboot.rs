//! `system.reboot` (design §4.2 `system` group, tier Change): schedules
//! `systemctl reboot` through a transient systemd timer, so the command's
//! receipt reaches the Mac before the machine goes down and the reboot
//! survives exec itself stopping.
//!
//! `systemd-run --on-active=<s>s --timer-property=AccuracySec=1s
//! --unit=fleet-reboot --collect /usr/bin/systemctl reboot`, after stopping
//! any earlier `fleet-reboot` timer (the newest schedule wins). The delay
//! is at least [`MIN_DELAY_S`]. Emits `reboot.scheduled`; the audit log
//! has the command like any other.

use crate::ctx::SysCtx;
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput};
use crate::runner::{CommandSpec, SYSTEMCTL};
use crate::scope::SYSTEMD_RUN;
use crate::security::EventSink;
use fleet_proto::{ErrorCode, Event, Op, Payload};
use std::rc::Rc;
use std::time::Duration;

pub const UNIT: &str = "fleet-reboot";
/// The receipt must leave first.
pub const MIN_DELAY_S: u32 = 5;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
/// `systemctl stop` of a unit that isn't loaded.
const NOT_LOADED: i32 = 5;

/// `systemctl stop fleet-reboot.timer fleet-reboot.service`.
pub fn cancel_command() -> CommandSpec {
    CommandSpec::new(SYSTEMCTL)
        .args(["stop", "fleet-reboot.timer", "fleet-reboot.service"])
        .timeout(COMMAND_TIMEOUT)
}

pub fn schedule_command(secs: u32) -> CommandSpec {
    CommandSpec::new(SYSTEMD_RUN)
        .args([
            format!("--on-active={secs}s"),
            "--timer-property=AccuracySec=1s".to_owned(),
            format!("--unit={UNIT}"),
            "--collect".to_owned(),
            "--description=Fleet scheduled reboot".to_owned(),
            SYSTEMCTL.to_owned(),
            "reboot".to_owned(),
        ])
        .timeout(COMMAND_TIMEOUT)
}

pub struct RebootHandler {
    sink: Rc<dyn EventSink>,
}

impl RebootHandler {
    pub fn new(sink: Rc<dyn EventSink>) -> Self {
        Self { sink }
    }
}

impl OpHandler for RebootHandler {
    fn validate(&self, _ctx: &SysCtx, op: &Op, _meta: &OpMeta) -> Result<(), OpError> {
        match op {
            Op::SystemReboot { .. } => Ok(()),
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
            let Op::SystemReboot { delay_s } = op else {
                return Err(ErrorCode::Unsupported.into());
            };
            let secs = (*delay_s).max(MIN_DELAY_S);
            let out = ctx.runner.run(cancel_command()).await?;
            if !out.success() && out.code != Some(NOT_LOADED) {
                return Err(OpError::internal(format!(
                    "stop earlier reboot timer: exit {:?}",
                    out.code
                )));
            }
            let out = ctx.runner.run(schedule_command(secs)).await?;
            if !out.success() {
                return Err(OpError::internal(format!(
                    "systemd-run reboot timer: exit {:?}",
                    out.code
                )));
            }
            self.sink.emit(Event::RebootScheduled {
                at_ms: ctx.clock.now_ms() + u64::from(secs) * 1000,
                audit_seq: meta.audit_seq.unwrap_or(0),
            });
            Ok(OpOutput::Payload(Payload::Empty))
        })
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

    fn run_args(secs: &str) -> Vec<String> {
        vec![
            format!("--on-active={secs}"),
            "--timer-property=AccuracySec=1s".into(),
            "--unit=fleet-reboot".into(),
            "--collect".into(),
            "--description=Fleet scheduled reboot".into(),
            SYSTEMCTL.into(),
            "reboot".into(),
        ]
    }

    #[test]
    fn schedules_timer_and_emits() {
        let dir = tempfile::tempdir().unwrap();
        let r = Rc::new(FakeRunner::new());
        let args = run_args("300s");
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        r.expect(SYSTEMCTL, STOP, Ok(CommandOutput::exit(NOT_LOADED)))
            .expect(SYSTEMD_RUN, &args, Ok(CommandOutput::ok("")));
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
        let args = run_args("5s");
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        r.expect(SYSTEMCTL, STOP, Ok(CommandOutput::ok("")))
            .expect(SYSTEMD_RUN, &args, Ok(CommandOutput::exit(1)));
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
}
