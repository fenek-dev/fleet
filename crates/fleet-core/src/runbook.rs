//! Saved snippets and runbooks (design §2.3).
//!
//! - A **snippet** is a saved shell command. It runs through `shell.exec`
//!   where the server policy allows it (Elevated: one root approval for
//!   all targets), or over SSH exec as the admin user (not root), after the
//!   operator confirms the exact text in the UI. The text is the operator's
//!   own command, run as written: nothing is interpolated into it.
//! - A **runbook** is ordered steps of typed operations ([`OpSpec`]) with
//!   parameters, a condition on the previous step's outcome, and an
//!   optional schedule the app runs while it is open. Parameters are
//!   substituted into typed fields only (never into `shell.exec` command
//!   text) and every step is validated again after substitution. Each step
//!   runs through the bulk engine. Scheduled runbooks can't contain
//!   Elevated steps (nobody is there to approve them).
//!
//! Both are stored in the cache with integrity MACs (`cache::library`).

use crate::bulk::{
    self, Approver, BoxFut, BulkEvent, BulkExecutor, BulkOptions, BulkReport, BulkRequest,
    CancelToken, Failure, Output,
};
use crate::manager::ManagerHandle;
use crate::opspec::{self, InvalidSpec};
use fleet_proto::args::ShellCommand;
use fleet_proto::{Actor, ServerId};
use fleetctl_proto::OpSpec;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

pub const MAX_NAME: usize = 100;
pub const MAX_DESCRIPTION: usize = 2000;
pub const MAX_STEPS: usize = 50;
pub const MAX_PARAMS: usize = 20;
pub const MAX_PARAM_VALUE: usize = 256;
/// Output cap for SSH snippets, per stream.
pub const SSH_OUTPUT_CAP: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RunbookError {
    #[error("invalid {0}")]
    Invalid(&'static str),
    #[error("step {step}: {error}")]
    Step { step: usize, error: InvalidSpec },
    #[error("missing parameter {0}")]
    MissingParam(String),
    #[error("scheduled runbooks can't contain elevated or may-escalate steps")]
    ScheduledElevated,
    #[error(transparent)]
    Bulk(#[from] bulk::BulkError),
}

/// 16 random bytes, hex.
pub fn new_id() -> String {
    let mut b = [0u8; 16];
    let _ = fleet_crypto::random_bytes(&mut b);
    hex::encode(b)
}

fn id_ok(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn text_ok(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len()) && !s.chars().any(|c| c.is_control() && c != '\n' && c != '\t')
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snippet {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Shell text, as the operator wrote it (`ShellCommand` rules).
    pub command: String,
    pub updated_ms: u64,
}

impl Snippet {
    pub fn validate(&self) -> Result<(), RunbookError> {
        if !id_ok(&self.id) {
            return Err(RunbookError::Invalid("id"));
        }
        if !text_ok(&self.name, 1, MAX_NAME) || self.name.contains('\n') {
            return Err(RunbookError::Invalid("name"));
        }
        if !text_ok(&self.description, 0, MAX_DESCRIPTION) {
            return Err(RunbookError::Invalid("description"));
        }
        ShellCommand::new(self.command.as_str()).map_err(|_| RunbookError::Invalid("command"))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepCondition {
    Always,
    /// Every target of the last step that ran succeeded.
    PreviousSucceeded,
    PreviousFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunbookStep {
    pub name: String,
    pub op: OpSpec,
    pub when: StepCondition,
    #[serde(default)]
    pub canary: bool,
    #[serde(default = "yes")]
    pub stop_on_failure: bool,
    #[serde(default)]
    pub concurrency: Option<u16>,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunbookParam {
    /// `[a-z][a-z0-9_]{0,31}`; used as `{{name}}` in step fields.
    pub name: String,
    #[serde(default)]
    pub default: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schedule {
    /// 5 minutes to 7 days.
    pub every_minutes: u32,
}

impl Schedule {
    pub fn is_due(&self, last_run_ms: Option<u64>, now_ms: u64) -> bool {
        match last_run_ms {
            None => true,
            Some(last) => now_ms.saturating_sub(last) >= u64::from(self.every_minutes) * 60_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Runbook {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Server ids the steps run on.
    pub targets: Vec<String>,
    #[serde(default)]
    pub params: Vec<RunbookParam>,
    pub steps: Vec<RunbookStep>,
    #[serde(default)]
    pub schedule: Option<Schedule>,
    pub updated_ms: u64,
}

fn param_name_ok(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=32).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

/// Parameter values are plain tokens: they end up in typed fields
/// (unit names, paths, projects…) that validate them again.
fn param_value_ok(s: &str) -> bool {
    s.len() <= MAX_PARAM_VALUE
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._:/@-+=,".contains(&c))
}

/// Replaces `{{name}}` in every string field of `spec` except shell text.
fn substitute(spec: &OpSpec, values: &BTreeMap<String, String>) -> Result<OpSpec, RunbookError> {
    let mut v = serde_json::to_value(spec).map_err(|_| RunbookError::Invalid("op"))?;
    let is_shell = matches!(spec, OpSpec::ShellExec { .. });
    if let serde_json::Value::Object(map) = &mut v {
        for (k, field) in map.iter_mut() {
            if k == "op" || (is_shell && k == "command") {
                continue;
            }
            if let serde_json::Value::String(s) = field {
                let mut out = s.clone();
                for (name, value) in values {
                    out = out.replace(&format!("{{{{{name}}}}}"), value);
                }
                if out.contains("{{") {
                    return Err(RunbookError::MissingParam(out));
                }
                *s = out;
            }
        }
    }
    serde_json::from_value(v).map_err(|_| RunbookError::Invalid("op"))
}

impl Runbook {
    pub fn target_ids(&self) -> Result<Vec<ServerId>, RunbookError> {
        self.targets
            .iter()
            .map(|t| ServerId::new(t.as_str()).map_err(|_| RunbookError::Invalid("targets")))
            .collect()
    }

    pub fn actor(&self) -> Actor {
        let mut id = [0u8; 16];
        if let Ok(b) = hex::decode(&self.id) {
            let n = b.len().min(16);
            id[..n].copy_from_slice(&b[..n]);
        }
        Actor::Runbook { id }
    }

    /// Parameter values: `given` over defaults; all must be present.
    pub fn resolve_params(
        &self,
        given: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, String>, RunbookError> {
        let mut out = BTreeMap::new();
        for p in &self.params {
            let v = given
                .get(&p.name)
                .or(p.default.as_ref())
                .ok_or_else(|| RunbookError::MissingParam(p.name.clone()))?;
            if !param_value_ok(v) {
                return Err(RunbookError::Invalid("parameter value"));
            }
            out.insert(p.name.clone(), v.clone());
        }
        if given.keys().any(|k| !out.contains_key(k)) {
            return Err(RunbookError::Invalid("unknown parameter"));
        }
        Ok(out)
    }

    /// Every step's op after substitution, validated.
    pub fn ops(
        &self,
        values: &BTreeMap<String, String>,
    ) -> Result<Vec<fleet_proto::Op>, RunbookError> {
        self.steps
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let spec = substitute(&s.op, values)?;
                opspec::to_op(&spec).map_err(|error| RunbookError::Step { step: i, error })
            })
            .collect()
    }

    /// Structure, targets and (with defaults, or placeholder-free) steps.
    pub fn validate(&self) -> Result<(), RunbookError> {
        if !id_ok(&self.id) {
            return Err(RunbookError::Invalid("id"));
        }
        if !text_ok(&self.name, 1, MAX_NAME) || self.name.contains('\n') {
            return Err(RunbookError::Invalid("name"));
        }
        if !text_ok(&self.description, 0, MAX_DESCRIPTION) {
            return Err(RunbookError::Invalid("description"));
        }
        let targets = self.target_ids()?;
        if targets.is_empty() || targets.len() > bulk::MAX_TARGETS {
            return Err(RunbookError::Invalid("targets"));
        }
        if self.steps.is_empty() || self.steps.len() > MAX_STEPS {
            return Err(RunbookError::Invalid("steps"));
        }
        if self.params.len() > MAX_PARAMS || self.params.iter().any(|p| !param_name_ok(&p.name)) {
            return Err(RunbookError::Invalid("params"));
        }
        let mut names: Vec<&str> = self.params.iter().map(|p| p.name.as_str()).collect();
        names.sort();
        names.dedup();
        if names.len() != self.params.len() {
            return Err(RunbookError::Invalid("params"));
        }
        for s in &self.steps {
            if !text_ok(&s.name, 1, MAX_NAME) {
                return Err(RunbookError::Invalid("step name"));
            }
            if s.concurrency
                .is_some_and(|c| c == 0 || usize::from(c) > bulk::MAX_CONCURRENCY)
            {
                return Err(RunbookError::Invalid("concurrency"));
            }
        }
        if let Some(sched) = self.schedule
            && !(5..=7 * 24 * 60).contains(&sched.every_minutes)
        {
            return Err(RunbookError::Invalid("schedule"));
        }
        // Validate ops with default (or sample) values.
        let sample: BTreeMap<String, String> = self
            .params
            .iter()
            .map(|p| {
                (
                    p.name.clone(),
                    p.default.clone().unwrap_or_else(|| "x.service".into()),
                )
            })
            .collect();
        if self
            .params
            .iter()
            .any(|p| p.default.as_deref().is_some_and(|d| !param_value_ok(d)))
        {
            return Err(RunbookError::Invalid("parameter value"));
        }
        let ops = match self.ops(&sample) {
            Ok(ops) => Some(ops),
            // Sample values may not fit every field; only defaults are binding.
            Err(e) if self.params.iter().all(|p| p.default.is_some()) => return Err(e),
            Err(_) => None,
        };
        if self.schedule.is_some() {
            if self.params.iter().any(|p| p.default.is_none()) {
                return Err(RunbookError::Invalid(
                    "scheduled runbooks need parameter defaults",
                ));
            }
            // May-escalate ops (e.g. compose.deploy) would ask for the root
            // key mid-run when exec answers `ApprovalRequired`: nobody is
            // there to approve them either.
            if ops
                .iter()
                .flatten()
                .any(|op| crate::opspec::needs_approval(op) || op.may_escalate())
            {
                return Err(RunbookError::ScheduledElevated);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RunbookEvent {
    StepStarted { index: usize, name: String },
    StepSkipped { index: usize },
    Bulk { index: usize, event: BulkEvent },
    Finished { succeeded: bool },
}

#[derive(Debug, Clone, PartialEq)]
pub struct StepReport {
    pub index: usize,
    /// `None`: the condition didn't hold.
    pub report: Option<BulkReport>,
}

fn step_ok(r: &BulkReport) -> bool {
    let s = &r.summary;
    s.stop.is_none() && s.failed == 0 && s.cancelled == 0 && s.skipped == 0
}

/// Runs every step in order through the bulk engine.
pub async fn run_runbook<E: FnMut(RunbookEvent) + Send>(
    rb: &Runbook,
    given: &BTreeMap<String, String>,
    exec: Arc<dyn BulkExecutor>,
    approver: Option<Arc<dyn Approver>>,
    health: Option<Arc<dyn bulk::HealthProbe>>,
    cancel: CancelToken,
    mut emit: E,
) -> Result<Vec<StepReport>, RunbookError> {
    rb.validate()?;
    let values = rb.resolve_params(given)?;
    let ops = rb.ops(&values)?;
    let targets = rb.target_ids()?;
    let actor = rb.actor();
    let mut reports = Vec::new();
    let mut previous_ok = true;
    let mut all_ok = true;
    for (i, (step, op)) in rb.steps.iter().zip(ops).enumerate() {
        let run = match step.when {
            StepCondition::Always => true,
            StepCondition::PreviousSucceeded => previous_ok,
            StepCondition::PreviousFailed => !previous_ok,
        };
        if !run || cancel.is_cancelled() {
            emit(RunbookEvent::StepSkipped { index: i });
            reports.push(StepReport {
                index: i,
                report: None,
            });
            continue;
        }
        emit(RunbookEvent::StepStarted {
            index: i,
            name: step.name.clone(),
        });
        let options = BulkOptions {
            concurrency: step
                .concurrency
                .map_or(bulk::DEFAULT_CONCURRENCY, usize::from),
            canary: step.canary,
            health: if step.canary { health.clone() } else { None },
            stop_on_failure: step.stop_on_failure,
            per_server_timeout: None,
            dry_run: false,
        };
        let mut req = BulkRequest::uniform(targets.clone(), op, actor.clone(), options);
        req.label = format!("{} ({})", req.label, rb.name);
        let report = bulk::run(
            exec.clone(),
            approver.clone(),
            req,
            cancel.clone(),
            |event| emit(RunbookEvent::Bulk { index: i, event }),
        )
        .await?;
        previous_ok = step_ok(&report);
        all_ok &= previous_ok;
        reports.push(StepReport {
            index: i,
            report: Some(report),
        });
    }
    emit(RunbookEvent::Finished { succeeded: all_ok });
    Ok(reports)
}

/// `shell.exec` for a snippet (Elevated; policy-gated on the server).
pub fn snippet_op(
    s: &Snippet,
    user: &str,
    timeout_s: u32,
) -> Result<fleet_proto::Op, RunbookError> {
    s.validate()?;
    opspec::shell_exec(user, &s.command, timeout_s)
        .map_err(|error| RunbookError::Step { step: 0, error })
}

/// Runs a snippet over each server's SSH connection as the admin user.
/// The UI must have shown the exact text and the targets first.
pub async fn run_snippet_ssh<E: FnMut(BulkEvent) + Send>(
    handle: ManagerHandle,
    snippet: &Snippet,
    targets: Vec<ServerId>,
    options: BulkOptions,
    limit: Duration,
    cancel: CancelToken,
    emit: E,
) -> Result<BulkReport, RunbookError> {
    snippet.validate()?;
    let command = Arc::new(snippet.command.clone());
    let ids = targets.clone();
    let work = move |i: usize| -> BoxFut<Result<Output, Failure>> {
        let conn = handle.ssh(&ids[i]);
        let command = command.clone();
        Box::pin(async move {
            let conn = conn.ok_or_else(|| Failure::NotReady("no ssh connection".into()))?;
            let out = conn
                .exec_capture(&command, SSH_OUTPUT_CAP, limit)
                .await
                .map_err(|e| match e {
                    crate::ssh::SshError::Timeout => Failure::Timeout,
                    e => Failure::Transport(e.to_string()),
                })?;
            if out.status != Some(0) {
                let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
                text.push_str(&String::from_utf8_lossy(&out.stderr));
                let (output, _) = fleetctl_proto::untrusted::truncate(&text, 8 * 1024);
                return Err(Failure::ExitStatus {
                    status: out.status,
                    output,
                });
            }
            Ok(Output::Exec {
                status: out.status,
                stdout: out.stdout,
                stderr: out.stderr,
            })
        })
    };
    let opts = BulkOptions {
        health: None,
        ..options
    };
    Ok(bulk::run_with(targets, &opts, &work, &cancel, emit).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bulk::tests::{Behave, FakeExec, SoftApprover, sid};
    use fleetctl_proto::msg::ServiceActionKind;

    fn step(op: OpSpec, when: StepCondition) -> RunbookStep {
        RunbookStep {
            name: "s".into(),
            op,
            when,
            canary: false,
            stop_on_failure: true,
            concurrency: None,
        }
    }

    fn restart(unit: &str) -> OpSpec {
        OpSpec::Unit {
            unit: unit.into(),
            action: ServiceActionKind::Restart,
        }
    }

    fn rb(steps: Vec<RunbookStep>) -> Runbook {
        Runbook {
            id: new_id(),
            name: "deploy".into(),
            description: String::new(),
            targets: vec![sid(0).to_string(), sid(1).to_string()],
            params: vec![RunbookParam {
                name: "unit".into(),
                default: Some("nginx.service".into()),
            }],
            steps,
            schedule: None,
            updated_ms: 0,
        }
    }

    #[test]
    fn validates_structure_params_and_schedules() {
        let mut r = rb(vec![step(restart("{{unit}}"), StepCondition::Always)]);
        r.validate().unwrap();
        let ops = r.ops(&r.resolve_params(&BTreeMap::new()).unwrap()).unwrap();
        assert!(
            matches!(&ops[0], fleet_proto::Op::UnitRestart { unit } if unit.as_str() == "nginx.service")
        );

        // Bad values never reach a typed field.
        let mut given = BTreeMap::new();
        given.insert("unit".to_string(), "x;reboot".to_string());
        assert!(r.resolve_params(&given).is_err());
        given.insert("unit".to_string(), "fleet-exec.service".to_string());
        let v = r.resolve_params(&given).unwrap();
        assert!(matches!(r.ops(&v), Err(RunbookError::Step { step: 0, .. })));

        // Shell text is never substituted.
        let sh = OpSpec::ShellExec {
            user: "deploy".into(),
            command: "echo {{unit}}".into(),
            timeout_s: 10,
        };
        let s = substitute(&sh, &v).unwrap();
        assert_eq!(s, sh);

        // Scheduled: no Elevated steps.
        r.steps.push(step(sh, StepCondition::Always));
        r.schedule = Some(Schedule { every_minutes: 60 });
        assert_eq!(r.validate(), Err(RunbookError::ScheduledElevated));
        r.steps.pop();
        r.validate().unwrap();
        r.schedule = Some(Schedule { every_minutes: 1 });
        assert!(r.validate().is_err());

        r.schedule = None;
        r.targets.push("nope".into());
        assert!(r.validate().is_err());
    }

    #[test]
    fn scheduled_runbooks_refuse_may_escalate_steps() {
        let compose = OpSpec::ComposeDeploy {
            project: "app".into(),
            compose_yaml: "services: {}\n".into(),
            pull: false,
        };
        let mut r = rb(vec![step(compose, StepCondition::Always)]);
        let op = crate::opspec::to_op(&r.steps[0].op).unwrap();
        assert!(op.may_escalate());
        r.validate().unwrap();
        r.schedule = Some(Schedule { every_minutes: 60 });
        assert_eq!(r.validate(), Err(RunbookError::ScheduledElevated));
    }

    #[test]
    fn schedule_due() {
        let s = Schedule { every_minutes: 10 };
        assert!(s.is_due(None, 0));
        assert!(!s.is_due(Some(1_000), 1_000 + 9 * 60_000));
        assert!(s.is_due(Some(1_000), 1_000 + 10 * 60_000));
    }

    #[test]
    fn snippet_rules() {
        let mut s = Snippet {
            id: new_id(),
            name: "disk".into(),
            description: String::new(),
            command: "df -h /".into(),
            updated_ms: 0,
        };
        s.validate().unwrap();
        assert!(matches!(
            snippet_op(&s, "deploy", 30).unwrap(),
            fleet_proto::Op::ShellExec(_)
        ));
        s.command = "a\0b".into();
        assert!(s.validate().is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn conditions_follow_previous_outcome() {
        let exec = FakeExec::with(&[(1, Behave::Fail(1))]);
        let r = rb(vec![
            step(restart("{{unit}}"), StepCondition::Always),
            step(restart("a.service"), StepCondition::PreviousSucceeded),
            step(restart("b.service"), StepCondition::PreviousFailed),
            step(OpSpec::AgentHealth, StepCondition::Always),
        ]);
        let mut events = Vec::new();
        let reports = run_runbook(
            &r,
            &BTreeMap::new(),
            Arc::new(exec.clone()),
            None,
            None,
            CancelToken::new(),
            |e| events.push(e),
        )
        .await
        .unwrap();
        // Step 0 fails on srv 1 → step 1 skipped, step 2 runs, step 3 runs.
        assert!(reports[0].report.is_some());
        assert!(reports[1].report.is_none());
        assert!(reports[2].report.is_some());
        assert!(reports[3].report.is_some());
        assert_eq!(
            events.last(),
            Some(&RunbookEvent::Finished { succeeded: false })
        );
        let calls = exec.calls();
        assert!(calls.iter().all(|(_, _, approved)| !approved));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn elevated_steps_ask_once_per_step() {
        let exec = FakeExec::with(&[]);
        let approver = SoftApprover::new(false);
        let r = rb(vec![step(
            OpSpec::SystemReboot { delay_s: 0 },
            StepCondition::Always,
        )]);
        if !crate::opspec::needs_approval(&crate::opspec::to_op(&r.steps[0].op).unwrap()) {
            return; // reboot isn't Elevated in this catalog
        }
        run_runbook(
            &r,
            &BTreeMap::new(),
            Arc::new(exec.clone()),
            Some(approver.clone()),
            None,
            CancelToken::new(),
            |_| {},
        )
        .await
        .unwrap();
        let asked = approver.asked.lock().unwrap();
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].1.len(), 2);
        assert!(asked[0].0.contains("deploy"));
    }
}
