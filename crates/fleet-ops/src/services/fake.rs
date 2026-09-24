//! In-memory [`SystemdApi`] for tests (here and in exec).

use super::{JobKind, JobResult, RawUnit, SdError, SystemdApi, UnitProps, UnitSignal, UnitWatch};
use crate::handler::LocalBoxFuture;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;
use std::time::Duration;

/// Units, unit files and properties are plain data; every call is logged
/// as `"<verb> <unit>"` (see [`FakeSystemd::calls`]). Jobs answer queued
/// results, `Done` when none is queued, and move the unit's `ActiveState`
/// on success.
#[derive(Default)]
pub struct FakeSystemd {
    pub units: RefCell<Vec<RawUnit>>,
    pub files: RefCell<Vec<(String, String)>>,
    pub props: RefCell<HashMap<String, UnitProps>>,
    pub job_results: RefCell<VecDeque<Result<JobResult, SdError>>>,
    signals: Rc<RefCell<VecDeque<UnitSignal>>>,
    calls: RefCell<Vec<String>>,
}

impl FakeSystemd {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a loaded unit with its file (`/usr/lib/systemd/system/<name>`).
    pub fn with_unit(self, name: &str, active: &str, sub: &str, file_state: &str) -> Self {
        self.units.borrow_mut().push(RawUnit {
            name: name.into(),
            description: format!("{name} description"),
            load_state: "loaded".into(),
            active_state: active.into(),
            sub_state: sub.into(),
        });
        self.files
            .borrow_mut()
            .push((format!("/usr/lib/systemd/system/{name}"), file_state.into()));
        self.props.borrow_mut().insert(
            name.into(),
            UnitProps {
                description: format!("{name} description"),
                load_state: "loaded".into(),
                active_state: active.into(),
                sub_state: sub.into(),
                unit_file_state: file_state.into(),
                ..UnitProps::default()
            },
        );
        self
    }

    pub fn push_job_result(&self, r: Result<JobResult, SdError>) {
        self.job_results.borrow_mut().push_back(r);
    }

    /// Queues a signal for the current and future watches.
    pub fn push_signal(&self, unit: &str, active_state: &str) {
        self.signals.borrow_mut().push_back(UnitSignal {
            unit: unit.into(),
            active_state: active_state.into(),
        });
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }

    fn log(&self, s: String) {
        self.calls.borrow_mut().push(s);
    }
}

struct FakeWatch(Rc<RefCell<VecDeque<UnitSignal>>>);

impl UnitWatch for FakeWatch {
    fn next(&mut self) -> LocalBoxFuture<'_, Option<UnitSignal>> {
        let s = self.0.borrow_mut().pop_front();
        Box::pin(std::future::ready(s))
    }
}

impl SystemdApi for FakeSystemd {
    fn list_units(&self) -> LocalBoxFuture<'_, Result<Vec<RawUnit>, SdError>> {
        self.log("list_units".into());
        Box::pin(std::future::ready(Ok(self.units.borrow().clone())))
    }

    fn list_unit_files(&self) -> LocalBoxFuture<'_, Result<Vec<(String, String)>, SdError>> {
        self.log("list_unit_files".into());
        Box::pin(std::future::ready(Ok(self.files.borrow().clone())))
    }

    fn unit_props<'a>(&'a self, unit: &'a str) -> LocalBoxFuture<'a, Result<UnitProps, SdError>> {
        self.log(format!("props {unit}"));
        let r = self.props.borrow().get(unit).cloned().unwrap_or(UnitProps {
            load_state: "not-found".into(),
            active_state: "inactive".into(),
            ..UnitProps::default()
        });
        Box::pin(std::future::ready(Ok(r)))
    }

    fn run_job<'a>(
        &'a self,
        kind: JobKind,
        unit: &'a str,
        _timeout: Duration,
    ) -> LocalBoxFuture<'a, Result<JobResult, SdError>> {
        self.log(format!("{} {unit}", kind.method()));
        let r = self
            .job_results
            .borrow_mut()
            .pop_front()
            .unwrap_or(Ok(JobResult::Done));
        if r == Ok(JobResult::Done)
            && let Some(p) = self.props.borrow_mut().get_mut(unit)
        {
            p.active_state = match kind {
                JobKind::Stop => "inactive",
                _ => "active",
            }
            .into();
        }
        Box::pin(std::future::ready(r))
    }

    fn set_enabled<'a>(
        &'a self,
        unit: &'a str,
        enabled: bool,
    ) -> LocalBoxFuture<'a, Result<(), SdError>> {
        let verb = if enabled { "enable" } else { "disable" };
        self.log(format!("{verb} {unit}"));
        let r = match self.props.borrow_mut().get_mut(unit) {
            Some(p) => {
                p.unit_file_state = if enabled { "enabled" } else { "disabled" }.into();
                Ok(())
            }
            None => Err(SdError::NoSuchUnit),
        };
        Box::pin(std::future::ready(r))
    }

    fn watch(&self) -> LocalBoxFuture<'_, Result<Box<dyn UnitWatch>, SdError>> {
        self.log("watch".into());
        let w: Box<dyn UnitWatch> = Box::new(FakeWatch(self.signals.clone()));
        Box::pin(std::future::ready(Ok(w)))
    }
}
