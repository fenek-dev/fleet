//! Bulk runs, snippets and runbooks for the app (design §7.3, §2.3).
//!
//! Operations cross as [`BulkOpRow`] (plain data) and are validated into
//! protocol types in Rust (`fleet_core::opspec`) before anything is
//! signed. Runs are spawned on the core runtime and report through a
//! [`BulkListener`]; [`BulkRunHandle::cancel`] stops them. Elevated runs ask
//! the root key once (Touch ID names the operation and server count).
//! Server-derived text in `detail` fields is escaped (`text`).

use crate::api::{FleetCore, id16, lock};
use crate::text;
use crate::types::FleetError;
use crate::validate;
use fleet_core::bulk::{
    self, AgentHealthProbe, Approver, BulkEvent, BulkExecutor, BulkOptions, BulkRequest,
    CancelToken, Outcome, Output, Plan, RootApprover, SkipReason, StopReason,
};
use fleet_core::confirm::ConfirmingExecutor;
use fleet_core::enroll::{SETTING_DEVICE_ID, SETTING_FLEET_ID};
use fleet_core::opspec;

/// Reconnect + `change.confirm` of an auto-revert answer (default policy
/// reverts after 60 s).
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(45);
use fleet_core::runbook::{
    self, Runbook, RunbookEvent, RunbookParam, RunbookStep, Schedule, Snippet, StepCondition,
};
use fleet_crypto::approval::MAX_APPROVAL_LIFETIME_MS;
use fleet_proto::{Actor, DeviceId, FleetId, Payload, ServerId};
use fleetctl_proto::OpSpec;
use fleetctl_proto::msg::{ContainerActionKind, ProfileLevelArg, ServiceActionKind};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

const DETAIL_MAX: usize = 4096;

fn invalid(field: &str) -> FleetError {
    FleetError::InvalidArgument {
        field: field.into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ServiceActionRow {
    Start,
    Stop,
    Restart,
    Reload,
    Enable,
    Disable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ContainerActionRow {
    Start,
    Stop,
    Restart,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ProfileLevelRow {
    Baseline,
    Strict,
}

/// Operations the bulk sheet, snippets and runbooks can run.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum BulkOpRow {
    AgentHealth,
    SystemInfo,
    Unit {
        unit: String,
        action: ServiceActionRow,
    },
    PkgRefresh,
    PkgUpgrade {
        security_only: bool,
    },
    Container {
        container: String,
        action: ContainerActionRow,
    },
    ComposePull {
        project: String,
    },
    ComposeRestart {
        project: String,
    },
    ComposeDeploy {
        project: String,
        compose_yaml: String,
        pull: bool,
    },
    ConfigRollback {
        path: String,
        version: u64,
    },
    ProfileCheck {
        level: ProfileLevelRow,
    },
    SystemReboot {
        delay_s: u32,
    },
    ShellExec {
        user: String,
        command: String,
        timeout_s: u32,
    },
}

impl BulkOpRow {
    fn spec(&self) -> OpSpec {
        match self.clone() {
            BulkOpRow::AgentHealth => OpSpec::AgentHealth,
            BulkOpRow::SystemInfo => OpSpec::SystemInfo,
            BulkOpRow::Unit { unit, action } => OpSpec::Unit {
                unit,
                action: match action {
                    ServiceActionRow::Start => ServiceActionKind::Start,
                    ServiceActionRow::Stop => ServiceActionKind::Stop,
                    ServiceActionRow::Restart => ServiceActionKind::Restart,
                    ServiceActionRow::Reload => ServiceActionKind::Reload,
                    ServiceActionRow::Enable => ServiceActionKind::Enable,
                    ServiceActionRow::Disable => ServiceActionKind::Disable,
                },
            },
            BulkOpRow::PkgRefresh => OpSpec::PkgRefresh,
            BulkOpRow::PkgUpgrade { security_only } => OpSpec::PkgUpgrade { security_only },
            BulkOpRow::Container { container, action } => OpSpec::Container {
                container,
                action: match action {
                    ContainerActionRow::Start => ContainerActionKind::Start,
                    ContainerActionRow::Stop => ContainerActionKind::Stop,
                    ContainerActionRow::Restart => ContainerActionKind::Restart,
                },
            },
            BulkOpRow::ComposePull { project } => OpSpec::ComposePull { project },
            BulkOpRow::ComposeRestart { project } => OpSpec::ComposeRestart { project },
            BulkOpRow::ComposeDeploy {
                project,
                compose_yaml,
                pull,
            } => OpSpec::ComposeDeploy {
                project,
                compose_yaml,
                pull,
            },
            BulkOpRow::ConfigRollback { path, version } => OpSpec::ConfigRollback { path, version },
            BulkOpRow::ProfileCheck { level } => OpSpec::ProfileCheck {
                level: match level {
                    ProfileLevelRow::Baseline => ProfileLevelArg::Baseline,
                    ProfileLevelRow::Strict => ProfileLevelArg::Strict,
                },
                roles: Vec::new(),
            },
            BulkOpRow::SystemReboot { delay_s } => OpSpec::SystemReboot { delay_s },
            BulkOpRow::ShellExec {
                user,
                command,
                timeout_s,
            } => OpSpec::ShellExec {
                user,
                command,
                timeout_s,
            },
        }
    }

    fn from_spec(s: &OpSpec) -> Self {
        match s.clone() {
            OpSpec::AgentHealth => BulkOpRow::AgentHealth,
            OpSpec::SystemInfo => BulkOpRow::SystemInfo,
            OpSpec::Unit { unit, action } => BulkOpRow::Unit {
                unit,
                action: match action {
                    ServiceActionKind::Start => ServiceActionRow::Start,
                    ServiceActionKind::Stop => ServiceActionRow::Stop,
                    ServiceActionKind::Restart => ServiceActionRow::Restart,
                    ServiceActionKind::Reload => ServiceActionRow::Reload,
                    ServiceActionKind::Enable => ServiceActionRow::Enable,
                    ServiceActionKind::Disable => ServiceActionRow::Disable,
                },
            },
            OpSpec::PkgRefresh => BulkOpRow::PkgRefresh,
            OpSpec::PkgUpgrade { security_only } => BulkOpRow::PkgUpgrade { security_only },
            OpSpec::Container { container, action } => BulkOpRow::Container {
                container,
                action: match action {
                    ContainerActionKind::Start => ContainerActionRow::Start,
                    ContainerActionKind::Stop => ContainerActionRow::Stop,
                    ContainerActionKind::Restart => ContainerActionRow::Restart,
                },
            },
            OpSpec::ComposePull { project } => BulkOpRow::ComposePull { project },
            OpSpec::ComposeRestart { project } => BulkOpRow::ComposeRestart { project },
            OpSpec::ComposeDeploy {
                project,
                compose_yaml,
                pull,
            } => BulkOpRow::ComposeDeploy {
                project,
                compose_yaml,
                pull,
            },
            OpSpec::ConfigRollback { path, version } => BulkOpRow::ConfigRollback { path, version },
            OpSpec::ProfileCheck { level, .. } => BulkOpRow::ProfileCheck {
                level: match level {
                    ProfileLevelArg::Baseline => ProfileLevelRow::Baseline,
                    ProfileLevelArg::Strict => ProfileLevelRow::Strict,
                },
            },
            OpSpec::SystemReboot { delay_s } => BulkOpRow::SystemReboot { delay_s },
            OpSpec::ShellExec {
                user,
                command,
                timeout_s,
            } => BulkOpRow::ShellExec {
                user,
                command,
                timeout_s,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BulkOptionsRow {
    /// 1–64; 0 means the default (16).
    pub concurrency: u32,
    pub canary: bool,
    /// After the canary: `agent.health` must answer.
    pub health_check: bool,
    pub stop_on_failure: bool,
    /// 0 = the manager's per-operation timeout.
    pub per_server_timeout_s: u32,
    pub dry_run: bool,
}

/// What the sheet shows before running.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BulkPreviewRow {
    pub op_name: String,
    pub elevated: bool,
    /// Has a `*.plan` counterpart for dry runs.
    pub has_plan: bool,
    pub command: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum BulkStatusRow {
    Running,
    Succeeded,
    Failed,
    Skipped,
    /// Cancelled while running: outcome unknown.
    Cancelled,
    Planned,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BulkSummaryRow {
    pub succeeded: u32,
    pub failed: u32,
    pub skipped: u32,
    pub cancelled: u32,
    pub planned: u32,
    /// Why the run stopped early, if it did.
    pub stop: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum BulkEventRow {
    Started {
        total: u32,
        needs_approval: bool,
    },
    Approved {
        servers: u32,
    },
    Server {
        server_id: String,
        status: BulkStatusRow,
        detail: String,
    },
    CanaryPassed {
        server_id: String,
    },
    Done {
        summary: BulkSummaryRow,
    },
    /// The run couldn't start (validation, not started…).
    Error {
        message: String,
    },
    /// Runbooks: step boundaries.
    StepStarted {
        index: u32,
        name: String,
    },
    StepSkipped {
        index: u32,
    },
    RunbookFinished {
        succeeded: bool,
    },
}

#[uniffi::export(callback_interface)]
pub trait BulkListener: Send + Sync {
    fn on_event(&self, event: BulkEventRow);
}

#[derive(uniffi::Object)]
pub struct BulkRunHandle {
    cancel: CancelToken,
}

#[uniffi::export]
impl BulkRunHandle {
    pub fn cancel(&self) {
        self.cancel.cancel();
    }
}

fn clip(s: String) -> String {
    let mut s = text::text(s);
    if s.len() > DETAIL_MAX {
        let mut end = DETAIL_MAX;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
        s.push('…');
    }
    s
}

fn stop_text(r: &StopReason) -> String {
    match r {
        StopReason::CanaryFailed => "canary failed".into(),
        StopReason::HealthCheckFailed(e) => {
            format!("canary health check failed: {}", text::line(e.clone()))
        }
        StopReason::Failure => "stopped after a failure".into(),
        StopReason::Cancelled => "cancelled".into(),
        StopReason::ApprovalDenied(e) => format!("approval not given: {e}"),
    }
}

fn outcome_row(o: &Outcome) -> (BulkStatusRow, String) {
    match o {
        Outcome::Succeeded(Output::Payload(Payload::Empty)) => {
            (BulkStatusRow::Succeeded, String::new())
        }
        Outcome::Succeeded(Output::Payload(p)) => {
            (BulkStatusRow::Succeeded, clip(format!("{p:#?}")))
        }
        Outcome::Succeeded(Output::Exec {
            status,
            stdout,
            stderr,
        }) => {
            let mut s = String::from_utf8_lossy(stdout).into_owned();
            if !stderr.is_empty() {
                s.push_str("\n--- stderr ---\n");
                s.push_str(&String::from_utf8_lossy(stderr));
            }
            let ok = *status == Some(0);
            (
                if ok {
                    BulkStatusRow::Succeeded
                } else {
                    BulkStatusRow::Failed
                },
                clip(format!(
                    "exit {}\n{s}",
                    status.map_or("?".into(), |c| c.to_string())
                )),
            )
        }
        Outcome::Succeeded(Output::Command(c)) | Outcome::Planned(Plan::Command(c)) => {
            (BulkStatusRow::Planned, clip(c.clone()))
        }
        Outcome::Planned(Plan::Fetched(p)) => (BulkStatusRow::Planned, clip(format!("{p:#?}"))),
        Outcome::Failed(bulk::Failure::ExitStatus { status, output }) => (
            BulkStatusRow::Failed,
            clip(format!(
                "exit {}\n{output}",
                status.map_or("?".into(), |c| c.to_string())
            )),
        ),
        Outcome::Failed(bulk::Failure::Transport(t)) => (BulkStatusRow::Failed, clip(t.clone())),
        Outcome::Failed(f) => (BulkStatusRow::Failed, format!("{f:?}")),
        Outcome::Skipped(r) => (
            BulkStatusRow::Skipped,
            match r {
                SkipReason::StoppedAfterFailure => "stopped after a failure",
                SkipReason::CanaryFailed => "canary failed",
                SkipReason::Cancelled => "cancelled",
                SkipReason::ApprovalDenied => "approval not given",
            }
            .into(),
        ),
        Outcome::Cancelled => (BulkStatusRow::Cancelled, "outcome unknown".into()),
    }
}

pub(crate) fn event_row(e: BulkEvent) -> BulkEventRow {
    match e {
        BulkEvent::Started {
            total,
            needs_approval,
        } => BulkEventRow::Started {
            total: total as u32,
            needs_approval,
        },
        BulkEvent::Approved { servers } => BulkEventRow::Approved {
            servers: servers as u32,
        },
        BulkEvent::Running { server } => BulkEventRow::Server {
            server_id: server.to_string(),
            status: BulkStatusRow::Running,
            detail: String::new(),
        },
        BulkEvent::Finished { server, outcome } => {
            let (status, detail) = outcome_row(&outcome);
            BulkEventRow::Server {
                server_id: server.to_string(),
                status,
                detail,
            }
        }
        BulkEvent::CanaryPassed { server } => BulkEventRow::CanaryPassed {
            server_id: server.to_string(),
        },
        BulkEvent::Done(s) => BulkEventRow::Done {
            summary: BulkSummaryRow {
                succeeded: s.succeeded as u32,
                failed: s.failed as u32,
                skipped: s.skipped as u32,
                cancelled: s.cancelled as u32,
                planned: s.planned as u32,
                stop: s.stop.as_ref().map(stop_text),
            },
        },
    }
}

fn options(o: &BulkOptionsRow) -> Result<BulkOptions, FleetError> {
    if o.concurrency as usize > bulk::MAX_CONCURRENCY {
        return Err(invalid("concurrency"));
    }
    if o.per_server_timeout_s > 24 * 3600 {
        return Err(invalid("per_server_timeout_s"));
    }
    Ok(BulkOptions {
        concurrency: if o.concurrency == 0 {
            bulk::DEFAULT_CONCURRENCY
        } else {
            o.concurrency as usize
        },
        canary: o.canary,
        health: None,
        stop_on_failure: o.stop_on_failure,
        per_server_timeout: (o.per_server_timeout_s > 0)
            .then(|| Duration::from_secs(u64::from(o.per_server_timeout_s))),
        dry_run: o.dry_run,
    })
}

fn targets(ids: &[String]) -> Result<Vec<ServerId>, FleetError> {
    ids.iter().map(|s| validate::server_id(s)).collect()
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SnippetRow {
    /// Empty for a new snippet.
    pub id: String,
    pub name: String,
    pub description: String,
    pub command: String,
    pub updated_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SnippetModeRow {
    /// `shell.exec` as `user` (policy-gated, Elevated: Touch ID once).
    ShellExec { user: String, timeout_s: u32 },
    /// SSH exec as the admin user (non-root).
    Ssh { timeout_s: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum StepConditionRow {
    Always,
    PreviousSucceeded,
    PreviousFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RunbookStepRow {
    pub name: String,
    pub op: BulkOpRow,
    pub when: StepConditionRow,
    pub canary: bool,
    pub stop_on_failure: bool,
    pub concurrency: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RunbookParamRow {
    pub name: String,
    pub default_value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RunbookRow {
    /// Empty for a new runbook.
    pub id: String,
    pub name: String,
    pub description: String,
    pub targets: Vec<String>,
    pub params: Vec<RunbookParamRow>,
    pub steps: Vec<RunbookStepRow>,
    /// Runs every N minutes while the app is open (5–10080).
    pub schedule_minutes: Option<u32>,
    pub last_run_ms: Option<u64>,
    pub updated_ms: u64,
}

fn snippet_row(s: Snippet) -> SnippetRow {
    SnippetRow {
        id: s.id,
        name: s.name,
        description: s.description,
        command: s.command,
        updated_ms: s.updated_ms,
    }
}

fn runbook_row(r: Runbook, last_run_ms: Option<u64>) -> RunbookRow {
    RunbookRow {
        id: r.id,
        name: r.name,
        description: r.description,
        targets: r.targets,
        params: r
            .params
            .into_iter()
            .map(|p| RunbookParamRow {
                name: p.name,
                default_value: p.default,
            })
            .collect(),
        steps: r
            .steps
            .into_iter()
            .map(|s| RunbookStepRow {
                name: s.name,
                op: BulkOpRow::from_spec(&s.op),
                when: match s.when {
                    StepCondition::Always => StepConditionRow::Always,
                    StepCondition::PreviousSucceeded => StepConditionRow::PreviousSucceeded,
                    StepCondition::PreviousFailed => StepConditionRow::PreviousFailed,
                },
                canary: s.canary,
                stop_on_failure: s.stop_on_failure,
                concurrency: s.concurrency,
            })
            .collect(),
        schedule_minutes: r.schedule.map(|s| s.every_minutes),
        last_run_ms,
        updated_ms: r.updated_ms,
    }
}

fn runbook_from_row(r: RunbookRow) -> Runbook {
    Runbook {
        id: if r.id.is_empty() {
            runbook::new_id()
        } else {
            r.id
        },
        name: r.name,
        description: r.description,
        targets: r.targets,
        params: r
            .params
            .into_iter()
            .map(|p| RunbookParam {
                name: p.name,
                default: p.default_value,
            })
            .collect(),
        steps: r
            .steps
            .into_iter()
            .map(|s| RunbookStep {
                name: s.name,
                op: s.op.spec(),
                when: match s.when {
                    StepConditionRow::Always => StepCondition::Always,
                    StepConditionRow::PreviousSucceeded => StepCondition::PreviousSucceeded,
                    StepConditionRow::PreviousFailed => StepCondition::PreviousFailed,
                },
                canary: s.canary,
                stop_on_failure: s.stop_on_failure,
                concurrency: s.concurrency,
            })
            .collect(),
        schedule: r.schedule_minutes.map(|m| Schedule { every_minutes: m }),
        updated_ms: fleet_core::now_ms(),
    }
}

impl FleetCore {
    /// The Secure Enclave root key as a bulk [`Approver`].
    pub(crate) fn root_approver(&self) -> Result<Arc<dyn Approver>, FleetError> {
        let (fleet_id, device_id) = {
            let c = lock(&self.cache);
            (id16(&c, SETTING_FLEET_ID)?, id16(&c, SETTING_DEVICE_ID)?)
        };
        Ok(Arc::new(RootApprover {
            keys: self.keys.clone(),
            fleet_id: FleetId(fleet_id),
            device_id: DeviceId(device_id),
            lifetime_ms: MAX_APPROVAL_LIFETIME_MS,
        }))
    }

    fn spawn_run<F>(&self, fut: F) -> Result<Arc<BulkRunHandle>, FleetError>
    where
        F: FnOnce(CancelToken) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
    {
        let (_, rt) = self.running()?;
        let cancel = CancelToken::new();
        rt.spawn(fut(cancel.clone()));
        Ok(Arc::new(BulkRunHandle { cancel }))
    }
}

#[uniffi::export]
impl FleetCore {
    /// Validates `op` and says what running it means.
    pub fn bulk_preview(&self, op: BulkOpRow) -> Result<BulkPreviewRow, FleetError> {
        let op = opspec::to_op(&op.spec()).map_err(|e| invalid(e.0))?;
        Ok(BulkPreviewRow {
            op_name: op.name().to_string(),
            elevated: opspec::needs_approval(&op),
            has_plan: bulk::plan_op(&op).is_some(),
            command: clip(bulk::describe(&op)),
        })
    }

    /// Runs `op` on `targets` (in order; the first is the canary).
    pub fn bulk_run(
        &self,
        targets: Vec<String>,
        op: BulkOpRow,
        options: BulkOptionsRow,
        listener: Box<dyn BulkListener>,
    ) -> Result<Arc<BulkRunHandle>, FleetError> {
        let ids = self::targets(&targets)?;
        let op = opspec::to_op(&op.spec()).map_err(|e| invalid(e.0))?;
        let health = options.health_check;
        let mut opts = self::options(&options)?;
        let (handle, _) = self.running()?;
        // Auto-revert answers are confirmed over a fresh connection.
        let exec: Arc<dyn BulkExecutor> = Arc::new(ConfirmingExecutor {
            handle,
            timeout: CONFIRM_TIMEOUT,
        });
        if health {
            opts.health = Some(Arc::new(AgentHealthProbe {
                exec: exec.clone(),
                actor: Actor::Human,
            }));
        }
        // May-escalate ops too: exec's `ApprovalRequired` gets one
        // gathered Touch ID and a retry (`fleet_core::escalate`).
        let approver = if (opspec::needs_approval(&op) || op.may_escalate()) && !opts.dry_run {
            Some(self.root_approver()?)
        } else {
            None
        };
        let req = BulkRequest::uniform(ids, op, Actor::Human, opts);
        self.spawn_run(move |cancel| {
            Box::pin(async move {
                let r = bulk::run(exec, approver, req, cancel, |e| {
                    listener.on_event(event_row(e))
                })
                .await;
                if let Err(e) = r {
                    listener.on_event(BulkEventRow::Error {
                        message: e.to_string(),
                    });
                }
            })
        })
    }

    // ---- snippets ----

    pub fn list_snippets(&self) -> Result<Vec<SnippetRow>, FleetError> {
        Ok(lock(&self.cache)
            .snippets()?
            .into_iter()
            .map(snippet_row)
            .collect())
    }

    pub fn save_snippet(&self, snippet: SnippetRow) -> Result<SnippetRow, FleetError> {
        let s = Snippet {
            id: if snippet.id.is_empty() {
                runbook::new_id()
            } else {
                snippet.id
            },
            name: snippet.name,
            description: snippet.description,
            command: snippet.command,
            updated_ms: fleet_core::now_ms(),
        };
        s.validate().map_err(|e| invalid(&e.to_string()))?;
        lock(&self.cache).put_snippet(&s)?;
        Ok(snippet_row(s))
    }

    pub fn delete_snippet(&self, id: String) -> Result<(), FleetError> {
        lock(&self.cache).delete_snippet(&id)?;
        Ok(())
    }

    /// Runs a saved snippet. The UI shows the exact text and targets first.
    pub fn run_snippet(
        &self,
        id: String,
        targets: Vec<String>,
        mode: SnippetModeRow,
        options: BulkOptionsRow,
        listener: Box<dyn BulkListener>,
    ) -> Result<Arc<BulkRunHandle>, FleetError> {
        let snippet = lock(&self.cache)
            .snippet(&id)?
            .ok_or_else(|| invalid("snippet"))?;
        let ids = self::targets(&targets)?;
        let opts = self::options(&options)?;
        let (handle, _) = self.running()?;
        match mode {
            SnippetModeRow::ShellExec { user, timeout_s } => {
                let op = runbook::snippet_op(&snippet, &user, timeout_s)
                    .map_err(|e| invalid(&e.to_string()))?;
                let approver = if opts.dry_run {
                    None
                } else {
                    Some(self.root_approver()?)
                };
                let mut req = BulkRequest::uniform(ids, op, Actor::Human, opts);
                req.label = format!("snippet \"{}\"", snippet.name);
                let exec: Arc<dyn BulkExecutor> = Arc::new(handle);
                self.spawn_run(move |cancel| {
                    Box::pin(async move {
                        let r = bulk::run(exec, approver, req, cancel, |e| {
                            listener.on_event(event_row(e))
                        })
                        .await;
                        if let Err(e) = r {
                            listener.on_event(BulkEventRow::Error {
                                message: e.to_string(),
                            });
                        }
                    })
                })
            }
            SnippetModeRow::Ssh { timeout_s } => {
                if !(1..=3600).contains(&timeout_s) {
                    return Err(invalid("timeout_s"));
                }
                let limit = Duration::from_secs(u64::from(timeout_s));
                self.spawn_run(move |cancel| {
                    Box::pin(async move {
                        let r = runbook::run_snippet_ssh(
                            handle,
                            &snippet,
                            ids,
                            opts,
                            limit,
                            cancel,
                            |e| listener.on_event(event_row(e)),
                        )
                        .await;
                        if let Err(e) = r {
                            listener.on_event(BulkEventRow::Error {
                                message: e.to_string(),
                            });
                        }
                    })
                })
            }
        }
    }

    // ---- runbooks ----

    pub fn list_runbooks(&self) -> Result<Vec<RunbookRow>, FleetError> {
        let c = lock(&self.cache);
        c.runbooks()?
            .into_iter()
            .map(|r| {
                let last = c.runbook_last_run(&r.id)?;
                Ok(runbook_row(r, last))
            })
            .collect()
    }

    pub fn save_runbook(&self, runbook: RunbookRow) -> Result<RunbookRow, FleetError> {
        let r = runbook_from_row(runbook);
        r.validate().map_err(|e| invalid(&e.to_string()))?;
        let c = lock(&self.cache);
        c.put_runbook(&r)?;
        let last = c.runbook_last_run(&r.id)?;
        Ok(runbook_row(r, last))
    }

    pub fn delete_runbook(&self, id: String) -> Result<(), FleetError> {
        lock(&self.cache).delete_runbook(&id)?;
        Ok(())
    }

    /// Ids of scheduled runbooks due at `now_ms` (the app's minute timer).
    pub fn due_runbooks(&self, now_ms: u64) -> Result<Vec<String>, FleetError> {
        Ok(lock(&self.cache)
            .due_runbooks(now_ms)?
            .into_iter()
            .map(|r| r.id)
            .collect())
    }

    pub fn run_runbook(
        &self,
        id: String,
        params: HashMap<String, String>,
        listener: Box<dyn BulkListener>,
    ) -> Result<Arc<BulkRunHandle>, FleetError> {
        let rb = {
            let c = lock(&self.cache);
            let rb = c.runbook(&id)?.ok_or_else(|| invalid("runbook"))?;
            c.set_runbook_last_run(&id, fleet_core::now_ms())?;
            rb
        };
        let given: BTreeMap<String, String> = params.into_iter().collect();
        // Fail fast on bad parameters, before anything is spawned.
        let values = rb
            .resolve_params(&given)
            .map_err(|e| invalid(&e.to_string()))?;
        let ops = rb.ops(&values).map_err(|e| invalid(&e.to_string()))?;
        let (handle, _) = self.running()?;
        let exec: Arc<dyn BulkExecutor> = Arc::new(ConfirmingExecutor {
            handle,
            timeout: CONFIRM_TIMEOUT,
        });
        let approver = if ops
            .iter()
            .any(|op| opspec::needs_approval(op) || op.may_escalate())
        {
            Some(self.root_approver()?)
        } else {
            None
        };
        let health: Arc<dyn bulk::HealthProbe> = Arc::new(AgentHealthProbe {
            exec: exec.clone(),
            actor: rb.actor(),
        });
        self.spawn_run(move |cancel| {
            Box::pin(async move {
                let r =
                    runbook::run_runbook(&rb, &given, exec, approver, Some(health), cancel, |e| {
                        let row = match e {
                            RunbookEvent::StepStarted { index, name } => {
                                BulkEventRow::StepStarted {
                                    index: index as u32,
                                    name,
                                }
                            }
                            RunbookEvent::StepSkipped { index } => BulkEventRow::StepSkipped {
                                index: index as u32,
                            },
                            RunbookEvent::Bulk { event, .. } => event_row(event),
                            RunbookEvent::Finished { succeeded } => {
                                BulkEventRow::RunbookFinished { succeeded }
                            }
                        };
                        listener.on_event(row)
                    })
                    .await;
                if let Err(e) = r {
                    listener.on_event(BulkEventRow::Error {
                        message: e.to_string(),
                    });
                }
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_rows_round_trip_through_specs() {
        let rows = [
            BulkOpRow::AgentHealth,
            BulkOpRow::Unit {
                unit: "nginx.service".into(),
                action: ServiceActionRow::Reload,
            },
            BulkOpRow::Container {
                container: "web".into(),
                action: ContainerActionRow::Stop,
            },
            BulkOpRow::ProfileCheck {
                level: ProfileLevelRow::Strict,
            },
            BulkOpRow::ShellExec {
                user: "deploy".into(),
                command: "uptime".into(),
                timeout_s: 5,
            },
        ];
        for r in rows {
            assert_eq!(BulkOpRow::from_spec(&r.spec()), r);
        }
    }

    #[test]
    fn outcome_detail_is_escaped() {
        let (s, d) = outcome_row(&Outcome::Succeeded(Output::Exec {
            status: Some(0),
            stdout: b"ok\x1b[2J".to_vec(),
            stderr: vec![],
        }));
        assert_eq!(s, BulkStatusRow::Succeeded);
        assert!(!d.contains('\u{1b}'));
        let (s, _) = outcome_row(&Outcome::Succeeded(Output::Exec {
            status: Some(2),
            stdout: vec![],
            stderr: b"no".to_vec(),
        }));
        assert_eq!(s, BulkStatusRow::Failed);
    }
}
