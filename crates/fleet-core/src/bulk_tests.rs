//! Bulk engine tests with in-memory executors.

use super::*;
use fleet_crypto::merkle::{leaf_hash, verify_proof};
use fleet_crypto::sig::SoftwareP256Signer;
use fleet_proto::args::UnitName;
use std::collections::HashMap;
use std::sync::Mutex;

pub(crate) fn sid(i: usize) -> ServerId {
    ServerId::new(format!("srv_{i:08}")).unwrap()
}

#[derive(Clone, Copy)]
pub(crate) enum Behave {
    Ok(u64),
    Fail(u64),
    Hang,
}

#[derive(Default)]
pub(crate) struct FakeExec {
    pub behave: Mutex<HashMap<ServerId, Behave>>,
    pub calls: Mutex<Vec<(ServerId, String, bool)>>,
    pub in_flight: std::sync::atomic::AtomicUsize,
    pub max_in_flight: std::sync::atomic::AtomicUsize,
    pub approvals: Mutex<Vec<(ServerId, RootApproval)>>,
    pub health_fails: AtomicBool,
    /// Canned replies by op name (default `Payload::Empty`).
    pub replies: Mutex<HashMap<&'static str, Payload>>,
    pub actors: Mutex<Vec<Actor>>,
}

impl FakeExec {
    pub fn with(b: &[(usize, Behave)]) -> Arc<Self> {
        let e = Self::default();
        *e.behave.lock().unwrap() = b.iter().map(|(i, b)| (sid(*i), *b)).collect();
        Arc::new(e)
    }

    pub fn calls(&self) -> Vec<(ServerId, String, bool)> {
        self.calls.lock().unwrap().clone()
    }
}

struct Guard<'a>(&'a std::sync::atomic::AtomicUsize);
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl BulkExecutor for Arc<FakeExec> {
    fn execute(
        &self,
        server: ServerId,
        op: Op,
        actor: Actor,
        approval: Option<RootApproval>,
    ) -> BoxFut<Result<Payload, Failure>> {
        let me = self.clone();
        Box::pin(async move {
            me.actors.lock().unwrap().push(actor);
            let canned = me.replies.lock().unwrap().get(op.name()).cloned();
            me.calls.lock().unwrap().push((
                server.clone(),
                op.name().to_string(),
                approval.is_some(),
            ));
            if let Some(a) = approval {
                me.approvals.lock().unwrap().push((server.clone(), a));
            }
            if matches!(op, Op::AgentHealth) {
                return if me.health_fails.load(Ordering::SeqCst) {
                    Err(Failure::Agent(ErrorCode::Internal))
                } else {
                    Ok(canned.unwrap_or(Payload::Empty))
                };
            }
            let n = me.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            me.max_in_flight.fetch_max(n, Ordering::SeqCst);
            let _g = Guard(&me.in_flight);
            let b = me
                .behave
                .lock()
                .unwrap()
                .get(&server)
                .copied()
                .unwrap_or(Behave::Ok(1));
            match b {
                Behave::Ok(ms) => {
                    tokio::time::sleep(Duration::from_millis(ms)).await;
                    Ok(canned.unwrap_or(Payload::Empty))
                }
                Behave::Fail(ms) => {
                    tokio::time::sleep(Duration::from_millis(ms)).await;
                    Err(Failure::Agent(ErrorCode::Internal))
                }
                Behave::Hang => {
                    std::future::pending::<()>().await;
                    unreachable!()
                }
            }
        })
    }
}

/// Health probe backed by the fake's `health_fails` flag.
struct FakeHealth(Arc<FakeExec>);
impl HealthProbe for FakeHealth {
    fn check(&self, _server: ServerId) -> BoxFut<Result<(), String>> {
        let fails = self.0.health_fails.load(Ordering::SeqCst);
        Box::pin(async move {
            if fails {
                Err("cpu pegged".into())
            } else {
                Ok(())
            }
        })
    }
}

pub(crate) struct SoftApprover {
    pub root: SoftwareP256Signer,
    pub deny: bool,
    pub asked: Mutex<Vec<(String, Vec<ApprovalItem>)>>,
}

impl SoftApprover {
    pub fn new(deny: bool) -> Arc<Self> {
        Arc::new(Self {
            root: SoftwareP256Signer::generate().unwrap(),
            deny,
            asked: Mutex::new(Vec::new()),
        })
    }
}

impl Approver for SoftApprover {
    fn approve(
        &self,
        what: &str,
        items: &[ApprovalItem],
    ) -> Result<Vec<RootApproval>, ApproveError> {
        self.asked
            .lock()
            .unwrap()
            .push((what.to_string(), items.to_vec()));
        if self.deny {
            return Err(ApproveError::Cancelled);
        }
        let now = crate::now_ms();
        let params = ApprovalParams {
            fleet_id: FleetId([1; 16]),
            approval_id: [9; 16],
            issued_at_ms: now,
            expires_at_ms: now + 60_000,
        };
        Ok(build_approvals(&self.root, DeviceId([2; 16]), &params, items).unwrap())
    }
}

pub(crate) fn healthy() -> Payload {
    Payload::AgentHealth(fleet_proto::AgentHealth {
        agent_version: fleet_proto::AgentVersion {
            major: 0,
            minor: 1,
            patch: 0,
        },
        proto_version: 1,
        uptime_s: 1,
        gate_rss_bytes: 1,
        exec_rss_bytes: 1,
        audit_seq: 1,
        roster_epoch: 0,
        roster_version: 1,
        policy_version: 1,
        pending_recovery: None,
        run_id: [0; 16],
    })
}

fn restart() -> Op {
    Op::UnitRestart {
        unit: UnitName::new("nginx.service").unwrap(),
    }
}

fn targets(n: usize) -> Vec<ServerId> {
    (0..n).map(sid).collect()
}

async fn go(
    exec: Arc<FakeExec>,
    approver: Option<Arc<dyn Approver>>,
    req: BulkRequest,
    cancel: CancelToken,
) -> (BulkReport, Vec<BulkEvent>) {
    let mut events = Vec::new();
    let report = run(Arc::new(exec), approver, req, cancel, |e| events.push(e))
        .await
        .unwrap();
    (report, events)
}

#[tokio::test(flavor = "current_thread")]
async fn respects_concurrency_and_reports_every_server() {
    let exec = FakeExec::with(&[]);
    let opts = BulkOptions {
        concurrency: 3,
        ..Default::default()
    };
    let req = BulkRequest::uniform(targets(10), restart(), Actor::Human, opts);
    let (report, events) = go(exec.clone(), None, req, CancelToken::new()).await;
    assert_eq!(report.summary.succeeded, 10);
    assert_eq!(report.summary.stop, None);
    assert!(exec.max_in_flight.load(Ordering::SeqCst) <= 3);
    assert!(exec.max_in_flight.load(Ordering::SeqCst) >= 2);
    let finished = events
        .iter()
        .filter(|e| matches!(e, BulkEvent::Finished { .. }))
        .count();
    assert_eq!(finished, 10);
    assert!(matches!(
        events.first(),
        Some(BulkEvent::Started {
            total: 10,
            needs_approval: false
        })
    ));
    assert!(matches!(events.last(), Some(BulkEvent::Done(_))));
}

#[tokio::test(flavor = "current_thread")]
async fn canary_failure_stops_everything_else() {
    let exec = FakeExec::with(&[(0, Behave::Fail(1))]);
    let opts = BulkOptions {
        canary: true,
        stop_on_failure: false,
        ..Default::default()
    };
    let req = BulkRequest::uniform(targets(5), restart(), Actor::Human, opts);
    let (report, _) = go(exec.clone(), None, req, CancelToken::new()).await;
    assert_eq!(exec.calls().len(), 1);
    assert_eq!(report.summary.failed, 1);
    assert_eq!(report.summary.skipped, 4);
    assert_eq!(report.summary.stop, Some(StopReason::CanaryFailed));
    assert!(
        report.outcomes[1..]
            .iter()
            .all(|(_, o)| *o == Outcome::Skipped(SkipReason::CanaryFailed))
    );
}

#[tokio::test(flavor = "current_thread")]
async fn canary_health_check_gates_the_rest() {
    let exec = FakeExec::with(&[]);
    exec.health_fails.store(true, Ordering::SeqCst);
    let opts = BulkOptions {
        canary: true,
        health: Some(Arc::new(FakeHealth(exec.clone()))),
        ..Default::default()
    };
    let req = BulkRequest::uniform(targets(4), restart(), Actor::Human, opts.clone());
    let (report, events) = go(exec.clone(), None, req, CancelToken::new()).await;
    assert_eq!(report.summary.succeeded, 1);
    assert_eq!(report.summary.skipped, 3);
    assert!(matches!(
        report.summary.stop,
        Some(StopReason::HealthCheckFailed(_))
    ));
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, BulkEvent::CanaryPassed { .. }))
    );

    // Healthy: canary first and alone, then the rest.
    let exec = FakeExec::with(&[]);
    let opts = BulkOptions {
        canary: true,
        health: Some(Arc::new(FakeHealth(exec.clone()))),
        ..Default::default()
    };
    let req = BulkRequest::uniform(targets(4), restart(), Actor::Human, opts);
    let (report, events) = go(exec.clone(), None, req, CancelToken::new()).await;
    assert_eq!(report.summary.succeeded, 4);
    let pos = |pred: &dyn Fn(&BulkEvent) -> bool| events.iter().position(pred).unwrap();
    let passed = pos(&|e| matches!(e, BulkEvent::CanaryPassed { .. }));
    let second = pos(&|e| matches!(e, BulkEvent::Running { server } if *server == sid(1)));
    assert!(passed < second);
    assert_eq!(exec.calls()[0].0, sid(0));
}

#[tokio::test(flavor = "current_thread")]
async fn agent_health_probe_uses_the_executor() {
    let exec = FakeExec::with(&[]);
    let probe = AgentHealthProbe {
        exec: Arc::new(exec.clone()),
        actor: Actor::Human,
    };
    // The fake answers Payload::Empty, which isn't a health reply.
    assert!(probe.check(sid(0)).await.is_err());
    assert_eq!(exec.calls()[0].1, "agent.health");
    exec.replies
        .lock()
        .unwrap()
        .insert("agent.health", healthy());
    assert!(probe.check(sid(0)).await.is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn stop_on_failure_stops_dispatching() {
    let exec = FakeExec::with(&[(1, Behave::Fail(1))]);
    let opts = BulkOptions {
        concurrency: 1,
        ..Default::default()
    };
    let req = BulkRequest::uniform(targets(5), restart(), Actor::Human, opts);
    let (report, _) = go(exec.clone(), None, req, CancelToken::new()).await;
    assert_eq!(exec.calls().len(), 2);
    assert_eq!(report.summary.succeeded, 1);
    assert_eq!(report.summary.failed, 1);
    assert_eq!(report.summary.skipped, 3);
    assert_eq!(report.summary.stop, Some(StopReason::Failure));

    let exec = FakeExec::with(&[(1, Behave::Fail(1))]);
    let opts = BulkOptions {
        concurrency: 1,
        stop_on_failure: false,
        ..Default::default()
    };
    let req = BulkRequest::uniform(targets(5), restart(), Actor::Human, opts);
    let (report, _) = go(exec.clone(), None, req, CancelToken::new()).await;
    assert_eq!(report.summary.succeeded, 4);
    assert_eq!(report.summary.failed, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn cancel_marks_in_flight_unknown_and_skips_the_rest() {
    let b: Vec<(usize, Behave)> = (0..6).map(|i| (i, Behave::Hang)).collect();
    let exec = FakeExec::with(&b);
    let opts = BulkOptions {
        concurrency: 2,
        ..Default::default()
    };
    let req = BulkRequest::uniform(targets(6), restart(), Actor::Human, opts);
    let cancel = CancelToken::new();
    let c2 = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        c2.cancel();
    });
    let (report, _) = go(exec.clone(), None, req, cancel).await;
    assert_eq!(report.summary.cancelled, 2);
    assert_eq!(report.summary.skipped, 4);
    assert_eq!(report.summary.stop, Some(StopReason::Cancelled));
    assert_eq!(exec.calls().len(), 2);
    // Futures were dropped: nothing still counts as running.
    assert_eq!(exec.in_flight.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn per_server_timeout() {
    let exec = FakeExec::with(&[(0, Behave::Hang)]);
    let opts = BulkOptions {
        per_server_timeout: Some(Duration::from_millis(10)),
        stop_on_failure: false,
        ..Default::default()
    };
    let req = BulkRequest::uniform(targets(2), restart(), Actor::Human, opts);
    let (report, _) = go(exec, None, req, CancelToken::new()).await;
    assert_eq!(report.outcomes[0].1, Outcome::Failed(Failure::Timeout));
    assert!(matches!(report.outcomes[1].1, Outcome::Succeeded(_)));
}

#[tokio::test(flavor = "current_thread")]
async fn one_approval_covers_every_target() {
    let exec = FakeExec::with(&[]);
    let approver = SoftApprover::new(false);
    let op = crate::opspec::shell_exec("deploy", "uptime", 30).unwrap();
    let req = BulkRequest::uniform(targets(5), op.clone(), Actor::Human, BulkOptions::default());
    assert!(req.needs_approval());
    let (report, events) = go(
        exec.clone(),
        Some(approver.clone()),
        req,
        CancelToken::new(),
    )
    .await;
    assert_eq!(report.summary.succeeded, 5);
    let asked = approver.asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 1, "exactly one root approval");
    assert_eq!(asked[0].0, "shell.exec");
    assert_eq!(asked[0].1.len(), 5);
    assert!(events.contains(&BulkEvent::Approved { servers: 5 }));
    let approvals = exec.approvals.lock().unwrap().clone();
    assert_eq!(approvals.len(), 5);
    let body0 = approvals[0].1.decode_body().unwrap();
    for (server, a) in &approvals {
        let body = a.decode_body().unwrap();
        assert_eq!(body.items_root, body0.items_root, "same decision");
        let leaf = leaf_hash(&ApprovalItem {
            server_id: server.clone(),
            op_digest: op_digest(&op, None),
        });
        assert!(verify_proof(&leaf, &a.proof, &body.items_root));
    }
    assert!(exec.calls().iter().all(|(_, _, approved)| *approved));
}

#[tokio::test(flavor = "current_thread")]
async fn denied_approval_runs_nothing() {
    let exec = FakeExec::with(&[]);
    let op = crate::opspec::shell_exec("deploy", "uptime", 30).unwrap();
    let req = BulkRequest::uniform(targets(3), op, Actor::Human, BulkOptions::default());
    let (report, _) = go(
        exec.clone(),
        Some(SoftApprover::new(true)),
        req,
        CancelToken::new(),
    )
    .await;
    assert!(exec.calls().is_empty());
    assert_eq!(report.summary.skipped, 3);
    assert!(matches!(
        report.summary.stop,
        Some(StopReason::ApprovalDenied(_))
    ));

    // No approver at all: same.
    let op = crate::opspec::shell_exec("deploy", "uptime", 30).unwrap();
    let req = BulkRequest::uniform(targets(2), op, Actor::Human, BulkOptions::default());
    let (report, _) = go(exec.clone(), None, req, CancelToken::new()).await;
    assert!(exec.calls().is_empty());
    assert_eq!(report.summary.skipped, 2);
}

#[tokio::test(flavor = "current_thread")]
async fn dry_run_plans_without_changing_anything() {
    let exec = FakeExec::with(&[]);
    let apply = Op::ProfileApply {
        spec: crate::opspec::profile_spec(fleetctl_proto::msg::ProfileLevelArg::Baseline, &[]),
        plan_hash: [0; 32],
    };
    let opts = BulkOptions {
        dry_run: true,
        canary: true,
        ..Default::default()
    };
    let mut req = BulkRequest::uniform(targets(2), apply, Actor::Human, opts);
    req.targets[1].1 = crate::opspec::shell_exec("deploy", "uptime", 30).unwrap();
    assert!(!req.needs_approval(), "dry runs never need approval");
    let approver = SoftApprover::new(false);
    let (report, _) = go(
        exec.clone(),
        Some(approver.clone()),
        req,
        CancelToken::new(),
    )
    .await;
    assert!(approver.asked.lock().unwrap().is_empty());
    assert_eq!(exec.calls().len(), 1);
    assert_eq!(exec.calls()[0].1, "profile.plan");
    assert_eq!(report.summary.planned, 2);
    assert!(matches!(
        report.outcomes[0].1,
        Outcome::Planned(Plan::Fetched(_))
    ));
    match &report.outcomes[1].1 {
        Outcome::Planned(Plan::Command(c)) => assert!(c.starts_with("shell.exec")),
        o => panic!("{o:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_bad_requests() {
    let exec = FakeExec::with(&[]);
    let mut t = targets(2);
    t.push(sid(0));
    let req = BulkRequest::uniform(t, restart(), Actor::Human, BulkOptions::default());
    let r = run(
        Arc::new(exec.clone()),
        None,
        req,
        CancelToken::new(),
        |_| {},
    )
    .await;
    assert!(matches!(r, Err(BulkError::DuplicateTarget(_))));
    let req = BulkRequest::uniform(vec![], restart(), Actor::Human, BulkOptions::default());
    let r = run(Arc::new(exec), None, req, CancelToken::new(), |_| {}).await;
    assert_eq!(r.unwrap_err(), BulkError::NoTargets);
}
