//! `services` group (design §2.5, §4.2): systemd units over D-Bus.
//!
//! The bus is behind [`SystemdApi`] so handlers are tested against
//! [`FakeSystemd`]; [`ZbusSystemd`] is the real client (system bus,
//! `org.freedesktop.systemd1.Manager`). Exec connects once and registers
//! the handlers with [`register`].
//!
//! **Refusals** (checked in `validate`, before the nonce is consumed, and
//! again in `handle`):
//! - any mutating op on a `fleet-*` unit (also refused by the catalog's
//!   `check_args`): the agent is changed only through `agent.update`;
//! - `unit.stop` / `unit.disable` of `ssh.service`, `sshd.service` or
//!   `ssh.socket` (lockout: every Mac reaches the server only over SSH).
//!   `unit.restart`/`unit.reload` of sshd stay allowed (existing sessions
//!   survive an sshd restart);
//! - `unit.stop` / `unit.disable` of [`CRITICAL_UNITS`] (bus, logind,
//!   networking, journald, nftables);
//! - every job but `unit.enable` on `nftables.service` ([`NO_JOB_UNITS`]).
//!
//! Mutating ops wait for the job's `JobRemoved` signal (bounded by
//! [`DEFAULT_JOB_TIMEOUT`]) and answer the unit's fresh `UnitStatus`.
//!
//! [`ServiceEvents`] turns `PropertiesChanged` signals into
//! `Event::ServiceStateChanged`, the event source for the `ServiceDown`
//! alert rule (design §4.5).

mod fake;
mod zbus_impl;

#[cfg(test)]
mod tests;

pub use fake::FakeSystemd;
pub use zbus_impl::ZbusSystemd;

use crate::ctx::SysCtx;
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, Registry};
use fleet_proto::args::UnitName;
use fleet_proto::op::tag;
use fleet_proto::payload::{UnitActiveState, UnitInfo, UnitStatus, Units};
use fleet_proto::{ErrorCode, Event, Op, Payload};
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;
use std::time::Duration;

/// How long a start/stop/restart/reload waits for its job (systemd's own
/// default stop timeout is 90 s). The job keeps running in systemd after
/// this; the op answers `Timeout`.
pub const DEFAULT_JOB_TIMEOUT: Duration = Duration::from_secs(120);

/// Most units `unit.list` returns.
pub const MAX_UNITS: usize = 4096;

/// Longest description/sub-state sent (server strings are untrusted anyway).
const MAX_TEXT: usize = 256;

/// Units whose stop/disable would lock every Mac out.
pub const LOCKOUT_UNITS: &[&str] = &["ssh.service", "sshd.service", "ssh.socket"];

/// Unit base names (any type: `.service`, `.socket`) whose stop/disable
/// cuts the network, logging, the bus or logins. Plus every
/// `systemd-journald*` unit ([`critical_unit`]).
pub const CRITICAL_UNITS: &[&str] = &[
    "dbus",
    "dbus-broker",
    "systemd-networkd",
    "networking",
    "NetworkManager",
    "systemd-logind",
    "nftables",
];

/// Units that take no job at all but `enable`: starting, restarting or
/// reloading `nftables.service` runs `nft -f /etc/nftables.conf`, whose
/// `flush ruleset` wipes `table inet fleet` and Docker's rules
/// (cooperative firewall mode, design §4.8).
pub const NO_JOB_UNITS: &[&str] = &["nftables.service"];

/// See [`CRITICAL_UNITS`].
pub fn critical_unit(unit: &str) -> bool {
    let base = unit.rsplit_once('.').map_or(unit, |(b, _)| b);
    CRITICAL_UNITS.contains(&base) || base.starts_with("systemd-journald")
}

/// One row of `ListUnits`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawUnit {
    pub name: String,
    pub description: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
}

/// Properties of one unit (`org.freedesktop.systemd1.Unit` plus, for
/// services, `…Service`). `None` where systemd reports "unset".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnitProps {
    pub description: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub unit_file_state: String,
    pub main_pid: Option<u32>,
    /// `ActiveEnterTimestamp`, realtime µs.
    pub active_enter_us: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub cpu_ns: Option<u64>,
    pub tasks: Option<u64>,
    pub restarts: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobKind {
    Start,
    Stop,
    Restart,
    Reload,
}

impl JobKind {
    /// Manager method (called with mode `"replace"`).
    pub fn method(self) -> &'static str {
        match self {
            JobKind::Start => "StartUnit",
            JobKind::Stop => "StopUnit",
            JobKind::Restart => "RestartUnit",
            JobKind::Reload => "ReloadUnit",
        }
    }
}

/// `JobRemoved` result string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobResult {
    Done,
    Canceled,
    Timeout,
    Failed,
    Dependency,
    Skipped,
    Other(String),
}

impl JobResult {
    pub fn parse(s: &str) -> Self {
        match s {
            "done" => Self::Done,
            "canceled" => Self::Canceled,
            "timeout" => Self::Timeout,
            "failed" => Self::Failed,
            "dependency" => Self::Dependency,
            "skipped" => Self::Skipped,
            o => Self::Other(clip(o)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SdError {
    #[error("no such unit")]
    NoSuchUnit,
    #[error("job wait timed out")]
    Timeout,
    #[error("d-bus: {0}")]
    Bus(String),
}

impl From<SdError> for OpError {
    fn from(e: SdError) -> Self {
        let code = match e {
            SdError::NoSuchUnit => ErrorCode::NotFound,
            SdError::Timeout => ErrorCode::Timeout,
            SdError::Bus(_) => ErrorCode::Internal,
        };
        OpError::new(code).with_detail(e.to_string())
    }
}

/// A unit's `ActiveState` as reported by a `PropertiesChanged` signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitSignal {
    pub unit: String,
    pub active_state: String,
}

/// Stream of unit state signals. Dropping it unsubscribes.
pub trait UnitWatch {
    /// `None` when the bus connection ended.
    fn next(&mut self) -> LocalBoxFuture<'_, Option<UnitSignal>>;
}

/// The systemd calls the services group needs.
pub trait SystemdApi {
    fn list_units(&self) -> LocalBoxFuture<'_, Result<Vec<RawUnit>, SdError>>;
    /// `(unit file name, UnitFileState)`.
    fn list_unit_files(&self) -> LocalBoxFuture<'_, Result<Vec<(String, String)>, SdError>>;
    /// `NoSuchUnit` if the unit doesn't exist (load state `not-found`).
    fn unit_props<'a>(&'a self, unit: &'a str) -> LocalBoxFuture<'a, Result<UnitProps, SdError>>;
    /// Queues the job (mode `replace`) and waits for its `JobRemoved`.
    fn run_job<'a>(
        &'a self,
        kind: JobKind,
        unit: &'a str,
        timeout: Duration,
    ) -> LocalBoxFuture<'a, Result<JobResult, SdError>>;
    /// `EnableUnitFiles`/`DisableUnitFiles` (persistent, not forced), then
    /// `Reload`.
    fn set_enabled<'a>(
        &'a self,
        unit: &'a str,
        enabled: bool,
    ) -> LocalBoxFuture<'a, Result<(), SdError>>;
    fn watch(&self) -> LocalBoxFuture<'_, Result<Box<dyn UnitWatch>, SdError>>;
}

fn clip(s: &str) -> String {
    s.chars().take(MAX_TEXT).collect()
}

pub fn active_state(s: &str) -> UnitActiveState {
    match s {
        "active" => UnitActiveState::Active,
        "reloading" => UnitActiveState::Reloading,
        "inactive" => UnitActiveState::Inactive,
        "failed" => UnitActiveState::Failed,
        "activating" => UnitActiveState::Activating,
        "deactivating" => UnitActiveState::Deactivating,
        _ => UnitActiveState::Other,
    }
}

/// Units the services group shows: valid `UnitName`s (service, timer,
/// socket), not templates.
fn listable(name: &str) -> bool {
    UnitName::new(name).is_ok() && !name.contains("@.")
}

/// Refusal rules shared by `validate` and `handle`.
pub fn check_unit_op(op: &Op) -> Result<(), OpError> {
    let (unit, lockout_sensitive) = match op {
        Op::UnitStart { unit } | Op::UnitRestart { unit } | Op::UnitReload { unit } => {
            (unit, false)
        }
        Op::UnitEnable { unit } => (unit, false),
        Op::UnitStop { unit } | Op::UnitDisable { unit } => (unit, true),
        Op::UnitList | Op::UnitStatus { .. } => return Ok(()),
        _ => return Err(ErrorCode::Unsupported.into()),
    };
    let denied = |why: &'static str| Err(OpError::new(ErrorCode::PolicyDenied).with_detail(why));
    let name = unit.as_str();
    if unit.is_fleet() {
        return denied("fleet unit");
    }
    if lockout_sensitive && LOCKOUT_UNITS.contains(&name) {
        return denied("ssh lockout");
    }
    if lockout_sensitive && critical_unit(name) {
        return denied("critical unit");
    }
    if !matches!(op, Op::UnitEnable { .. }) && NO_JOB_UNITS.contains(&name) {
        return denied("flushes ruleset");
    }
    Ok(())
}

/// `ListUnits` ∪ `ListUnitFiles` (disabled units aren't loaded), sorted.
pub async fn list(api: &dyn SystemdApi) -> Result<Units, SdError> {
    let files: HashMap<String, String> = api
        .list_unit_files()
        .await?
        .into_iter()
        .map(|(path, state)| {
            let name = path.rsplit('/').next().unwrap_or_default().to_owned();
            (name, state)
        })
        .collect();
    let mut out: BTreeMap<String, UnitInfo> = BTreeMap::new();
    for u in api.list_units().await? {
        if !listable(&u.name) || u.load_state == "not-found" {
            continue;
        }
        let file_state = files.get(&u.name).map_or_else(String::new, |s| clip(s));
        out.insert(
            u.name.clone(),
            UnitInfo {
                description: clip(&u.description),
                active: active_state(&u.active_state),
                sub: clip(&u.sub_state),
                file_state,
                name: u.name,
            },
        );
    }
    for (name, state) in files {
        if listable(&name) && !out.contains_key(&name) {
            out.insert(
                name.clone(),
                UnitInfo {
                    name,
                    description: String::new(),
                    active: UnitActiveState::Inactive,
                    sub: "dead".into(),
                    file_state: clip(&state),
                },
            );
        }
    }
    Ok(Units {
        units: out.into_values().take(MAX_UNITS).collect(),
    })
}

pub fn status_from_props(name: &str, p: &UnitProps) -> UnitStatus {
    UnitStatus {
        info: UnitInfo {
            name: name.to_owned(),
            description: clip(&p.description),
            active: active_state(&p.active_state),
            sub: clip(&p.sub_state),
            file_state: clip(&p.unit_file_state),
        },
        main_pid: p.main_pid.filter(|&pid| pid != 0),
        since_ms: p.active_enter_us.filter(|&t| t != 0).map(|t| t / 1000),
        memory_bytes: p.memory_bytes,
        cpu_ns: p.cpu_ns,
        tasks: p.tasks.map(|t| u32::try_from(t).unwrap_or(u32::MAX)),
        restarts: p.restarts.unwrap_or(0),
    }
}

pub async fn status(api: &dyn SystemdApi, unit: &str) -> Result<UnitStatus, SdError> {
    let p = api.unit_props(unit).await?;
    if p.load_state == "not-found" {
        return Err(SdError::NoSuchUnit);
    }
    Ok(status_from_props(unit, &p))
}

/// Maps a finished job to the op result.
fn job_outcome(r: JobResult) -> Result<(), OpError> {
    match r {
        JobResult::Done | JobResult::Skipped => Ok(()),
        JobResult::Timeout => Err(OpError::new(ErrorCode::Timeout).with_detail("job timeout")),
        // Replaced by a newer job for the same unit.
        JobResult::Canceled => Err(OpError::new(ErrorCode::Busy).with_detail("job canceled")),
        other => Err(OpError::internal(format!("job result {other:?}"))),
    }
}

/// Handler for every `services` op (tags 300–399).
pub struct ServicesHandler {
    api: Rc<dyn SystemdApi>,
    job_timeout: Duration,
}

impl ServicesHandler {
    pub fn new(api: Rc<dyn SystemdApi>) -> Self {
        Self {
            api,
            job_timeout: DEFAULT_JOB_TIMEOUT,
        }
    }

    pub fn job_timeout(mut self, d: Duration) -> Self {
        self.job_timeout = d;
        self
    }

    async fn run(&self, op: &Op) -> Result<Payload, OpError> {
        check_unit_op(op)?;
        let api = &*self.api;
        let (unit, job) = match op {
            Op::UnitList => return Ok(Payload::Units(list(api).await?)),
            Op::UnitStatus { unit } => {
                return Ok(Payload::UnitStatus(status(api, unit.as_str()).await?));
            }
            Op::UnitStart { unit } => (unit, Some(JobKind::Start)),
            Op::UnitStop { unit } => (unit, Some(JobKind::Stop)),
            Op::UnitRestart { unit } => (unit, Some(JobKind::Restart)),
            Op::UnitReload { unit } => (unit, Some(JobKind::Reload)),
            Op::UnitEnable { unit } | Op::UnitDisable { unit } => (unit, None),
            _ => return Err(ErrorCode::Unsupported.into()),
        };
        match job {
            Some(kind) => {
                job_outcome(api.run_job(kind, unit.as_str(), self.job_timeout).await?)?;
            }
            None => {
                let enable = matches!(op, Op::UnitEnable { .. });
                api.set_enabled(unit.as_str(), enable).await?;
            }
        }
        Ok(Payload::UnitStatus(status(api, unit.as_str()).await?))
    }
}

impl OpHandler for ServicesHandler {
    fn validate(&self, _ctx: &SysCtx, op: &Op, _meta: &OpMeta) -> Result<(), OpError> {
        check_unit_op(op)
    }

    fn handle<'a>(
        &'a self,
        _ctx: &'a SysCtx,
        op: &'a Op,
        _meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move { self.run(op).await.map(OpOutput::Payload) })
    }
}

/// Registers [`ServicesHandler`] for every services tag.
pub fn register(r: &mut Registry, api: Rc<dyn SystemdApi>) {
    let h: Rc<dyn OpHandler> = Rc::new(ServicesHandler::new(api));
    for t in [
        tag::UNIT_LIST,
        tag::UNIT_STATUS,
        tag::UNIT_START,
        tag::UNIT_STOP,
        tag::UNIT_RESTART,
        tag::UNIT_RELOAD,
        tag::UNIT_ENABLE,
        tag::UNIT_DISABLE,
    ] {
        r.register(t, h.clone());
    }
}

/// Most units whose last state [`ServiceEvents`] remembers.
const MAX_TRACKED: usize = 8192;

/// Service state change event source (design §4.5): `PropertiesChanged`
/// signals → `Event::ServiceStateChanged` when `ActiveState` actually
/// changes. Feeds the `ServiceDown` alert rule.
pub struct ServiceEvents {
    watch: Box<dyn UnitWatch>,
    last: HashMap<String, UnitActiveState>,
}

impl ServiceEvents {
    /// Subscribes first, then seeds the known states, so no change between
    /// the two is lost (a duplicate is filtered as "no change").
    pub async fn start(api: &dyn SystemdApi) -> Result<Self, SdError> {
        let watch = api.watch().await?;
        let last = api
            .list_units()
            .await?
            .into_iter()
            .filter(|u| listable(&u.name))
            .take(MAX_TRACKED)
            .map(|u| (u.name, active_state(&u.active_state)))
            .collect();
        Ok(Self { watch, last })
    }

    /// Next actual change; `None` when the bus connection ended.
    pub async fn next(&mut self) -> Option<Event> {
        loop {
            let s = self.watch.next().await?;
            if !listable(&s.unit) {
                continue;
            }
            let to = active_state(&s.active_state);
            // A unit loaded for the first time was inactive before.
            let from = self
                .last
                .get(&s.unit)
                .copied()
                .unwrap_or(UnitActiveState::Inactive);
            if from == to {
                continue;
            }
            if self.last.len() >= MAX_TRACKED && !self.last.contains_key(&s.unit) {
                self.last.clear();
            }
            self.last.insert(s.unit.clone(), to);
            return Some(Event::ServiceStateChanged {
                unit: s.unit,
                from,
                to,
            });
        }
    }
}
