//! Provisioning orchestration against a fake agent and app backend.

use super::*;
use crate::bulk::tests::{SoftApprover, healthy};
use crate::bulk::Approver;
use fleet_proto::op::Tier;
use fleet_proto::alert::Severity;
use fleet_proto::payload::{
    AuditFinding, AuditReport, ChangeKind, ModuleOutcome, PendingChange, PendingChanges,
    ProfileApplied,
};
use std::sync::{Arc, Mutex};

const ADMIN: &str = "ops";
const PROVIDER: &str = "root";

fn change(module: &str) -> PlannedChange {
    PlannedChange {
        module: module.into(),
        description: format!("configure {module}"),
        diff: String::new(),
        auto_revert: ProfilePhase::is_access_module(module),
    }
}

/// The agent: a plan of modules, applied phase by phase.
struct Fake {
    log: Mutex<Vec<String>>,
    remaining: Mutex<Vec<PlannedChange>>,
    /// Modules added to the next plan (drift since review).
    extra: Mutex<Vec<PlannedChange>>,
    /// `profile.apply` of this phase fails with the code, n times.
    fail: Mutex<Option<(ProfilePhase, ErrorCode, u32)>>,
    confirm: Mutex<Result<(), ConfirmFailure>>,
    ssh_user: Mutex<String>,
    confirmed_as: Mutex<Option<String>>,
    saved: Mutex<Vec<ProvisionState>>,
    approvals: Mutex<Vec<String>>,
    /// The Mac's root key (`None`: approvals fail).
    root: Mutex<Option<Arc<SoftApprover>>>,
    passwords: Mutex<Vec<bool>>,
    /// Unconfirmed changes (`changes.list`).
    pending: Mutex<Vec<PendingChange>>,
    findings: Mutex<Vec<AuditFinding>>,
}

fn pending_change() -> PendingChange {
    PendingChange {
        change_id: [4; 16],
        kind: ChangeKind::Profile,
        op_tag: 1102,
        created_ms: 1,
        deadline_ms: 60_001,
        new_version: None,
    }
}

impl Fake {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            log: Mutex::new(Vec::new()),
            remaining: Mutex::new(
                [
                    "admin.user",
                    "sudo.policy",
                    "ssh.hardening",
                    "firewall.baseline",
                    "sysctl",
                    "auditd",
                ]
                .into_iter()
                .map(change)
                .collect(),
            ),
            extra: Mutex::new(Vec::new()),
            fail: Mutex::new(None),
            confirm: Mutex::new(Ok(())),
            ssh_user: Mutex::new(PROVIDER.into()),
            confirmed_as: Mutex::new(None),
            saved: Mutex::new(Vec::new()),
            approvals: Mutex::new(Vec::new()),
            root: Mutex::new(Some(SoftApprover::new(false))),
            passwords: Mutex::new(Vec::new()),
            pending: Mutex::new(Vec::new()),
            findings: Mutex::new(Vec::new()),
        })
    }

    fn log(&self, s: impl Into<String>) {
        self.log.lock().unwrap().push(s.into());
    }

    fn logged(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    fn plan(&self) -> ProfilePlan {
        let mut changes = self.remaining.lock().unwrap().clone();
        changes.extend(self.extra.lock().unwrap().iter().cloned());
        let names: Vec<&str> = changes.iter().map(|c| c.module.as_str()).collect();
        ProfilePlan {
            plan_hash: *blake3::hash(names.join(",").as_bytes()).as_bytes(),
            changes,
        }
    }

    fn score(&self) -> u8 {
        100 - 10 * self.remaining.lock().unwrap().len() as u8
    }

    fn answer(&self, op: Op) -> Result<Payload, Failure> {
        match op {
            Op::AgentHealth => {
                self.log("agent.health");
                Ok(healthy())
            }
            Op::AuditRun { .. } => {
                self.log(format!("audit.run {}", self.score()));
                Ok(Payload::AuditReport(AuditReport {
                    score: self.score(),
                    findings: self.findings.lock().unwrap().clone(),
                }))
            }
            Op::ChangesList => {
                self.log("changes.list");
                Ok(Payload::PendingChanges(PendingChanges {
                    changes: self.pending.lock().unwrap().clone(),
                }))
            }
            Op::ProfilePlan(_) => {
                self.log("profile.plan");
                Ok(Payload::ProfilePlan(self.plan()))
            }
            Op::ProfileApply {
                plan_hash,
                phase,
                password_hash,
                ..
            } => {
                self.log(format!("profile.apply {phase:?}"));
                self.passwords.lock().unwrap().push(password_hash.is_some());
                if plan_hash != self.plan().plan_hash {
                    return Err(Failure::Agent(ErrorCode::VersionConflict { current: 0 }));
                }
                {
                    let mut f = self.fail.lock().unwrap();
                    if let Some((p, code, n)) = f.as_mut()
                        && *p == phase
                        && *n > 0
                    {
                        *n -= 1;
                        return Err(Failure::Agent(*code));
                    }
                }
                let before = self.score();
                let mut applied = Vec::new();
                self.remaining.lock().unwrap().retain(|c| {
                    let mine = in_phase(&c.module, phase);
                    if mine {
                        applied.push(ModuleResult {
                            id: c.module.clone(),
                            outcome: ModuleOutcome::Applied,
                            detail: String::new(),
                        });
                    }
                    !mine
                });
                let result = Payload::ProfileApplied(ProfileApplied {
                    modules: applied,
                    pending: None,
                    score_before: before,
                    score_after: self.score(),
                });
                if phase == ProfilePhase::Access {
                    self.pending.lock().unwrap().push(pending_change());
                    Ok(Payload::ChangePending {
                        change: pending_change(),
                        inner: Some(Box::new(result)),
                    })
                } else {
                    Ok(result)
                }
            }
            other => {
                self.log(other.name());
                Ok(Payload::Empty)
            }
        }
    }
}

impl ProvisionBackend for Arc<Fake> {
    fn request(&self, _: &ServerId, op: Op, opts: RequestOpts) -> BoxFut<Result<Payload, Failure>> {
        // Like exec: an Elevated op without a root approval is refused.
        let r = if op.tier() == Tier::Elevated && opts.approval.is_none() {
            Err(Failure::Agent(ErrorCode::ApprovalRequired))
        } else {
            self.answer(op)
        };
        Box::pin(async move { r })
    }

    fn approve(&self, what: String, item: ApprovalItem) -> BoxFut<Result<RootApproval, String>> {
        self.approvals.lock().unwrap().push(what.clone());
        let root = self.root.lock().unwrap().clone();
        let r = match root {
            Some(a) => a
                .approve(&what, &[item])
                .map_err(|e| format!("{e:?}"))
                .and_then(|mut l| l.pop().ok_or_else(|| "no approval".to_string())),
            None => Err("no root key".to_string()),
        };
        Box::pin(async move { r })
    }

    fn roster_chain(&self) -> Result<Vec<SignedRoster>, String> {
        Ok(Vec::new())
    }

    fn sudo_password_hash(&self, _: &ServerId) -> Result<SudoPasswordHash, String> {
        self.log("sudo.password");
        sudo_password_hash("A-test-password-24chars!").map_err(|e| e.to_string())
    }

    fn verify_admin_login(&self, _: &ServerId, admin: &str) -> BoxFut<Result<(), String>> {
        self.log(format!("verify {admin}"));
        Box::pin(async { Ok(()) })
    }

    fn set_ssh_user(&self, _: &ServerId, user: &str) -> Result<(), String> {
        self.log(format!("ssh as {user}"));
        *self.ssh_user.lock().unwrap() = user.to_string();
        Ok(())
    }

    fn confirm_change(
        &self,
        _: &ServerId,
        change: ChangeId,
        deadline_ms: u64,
    ) -> BoxFut<Result<(), ConfirmFailure>> {
        assert_eq!((change, deadline_ms), ([4; 16], 60_001));
        self.pending.lock().unwrap().clear();
        self.log("confirm (new connection)");
        *self.confirmed_as.lock().unwrap() = Some(self.ssh_user.lock().unwrap().clone());
        let r = self.confirm.lock().unwrap().clone();
        Box::pin(async move { r })
    }

    fn add_to_fleet(
        &self,
        _: &ServerId,
        name: &str,
        group: Option<&str>,
        tags: &[String],
    ) -> Result<(), String> {
        self.log(format!("add {name} {group:?} {tags:?}"));
        Ok(())
    }

    fn save(&self, state: &ProvisionState) -> Result<(), String> {
        self.saved.lock().unwrap().push(state.clone());
        Ok(())
    }
}

fn server() -> ServerId {
    ServerId::new("srv_prov00000001").unwrap()
}

fn choice() -> ProvisionChoice {
    ProvisionChoice {
        level: Level::Baseline,
        roles: vec![Role::Docker],
        admin_user: ADMIN.into(),
        allow_from: vec![],
        reboot_window: None,
        name: "web-05".into(),
        group: Some("g1".into()),
        tags: vec!["web".into()],
    }
}

fn cfg() -> ProvisionConfig {
    ProvisionConfig {
        busy_retries: 3,
        busy_delay: Duration::from_millis(1),
    }
}

async fn run(fake: &Arc<Fake>, st: &mut ProvisionState) -> Result<Step, ProvisionError> {
    advance(fake, st, &cfg(), |_| {}).await
}

/// Up to the review, then approve what was shown.
async fn reviewed(fake: &Arc<Fake>) -> ProvisionState {
    let mut st = ProvisionState::new(&server(), choice(), PROVIDER);
    assert_eq!(run(fake, &mut st).await, Ok(Step::Review));
    let hash = st.plan_hash.unwrap();
    st.approve_plan(&hash).unwrap();
    st
}

#[tokio::test(flavor = "current_thread")]
async fn phases_run_in_lockout_safe_order() {
    let fake = Fake::new();
    let mut st = ProvisionState::new(&server(), choice(), PROVIDER);
    assert_eq!(run(&fake, &mut st).await, Ok(Step::Review));
    assert_eq!(st.plan.len(), 6);
    assert_eq!(st.score_before, Some(40));
    // Nothing applied before the operator approves.
    assert!(!fake.logged().iter().any(|l| l.starts_with("profile.apply")));
    let hash = st.plan_hash.unwrap();
    assert!(st.approve_plan(&[0; 32]).is_err(), "only the plan shown");
    st.approve_plan(&hash).unwrap();
    assert_eq!(run(&fake, &mut st).await, Ok(Step::Done));
    assert_eq!(
        fake.logged(),
        vec![
            "agent.health",
            "audit.run 40",
            "profile.plan",
            "sudo.password",
            "profile.plan",
            "profile.apply Accounts",
            "verify ops",
            "profile.plan",
            "profile.apply Access",
            "ssh as ops",
            "confirm (new connection)",
            "profile.plan",
            "profile.apply System",
            "audit.run 100",
            "add web-05 Some(\"g1\") [\"web\"]",
        ]
    );
    // The confirm came over a connection as the admin (root login is off).
    assert_eq!(fake.confirmed_as.lock().unwrap().as_deref(), Some(ADMIN));
    // Only the Accounts phase carries the sudo password hash, which makes
    // it (alone, for a built-in profile) Elevated: one root approval.
    assert_eq!(*fake.passwords.lock().unwrap(), vec![true, false, false]);
    let asked = fake.approvals.lock().unwrap().clone();
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert!(asked[0].contains("Accounts"));
    assert_eq!((st.score_before, st.score_after), (Some(40), Some(100)));
    assert_eq!(st.modules.len(), 6);
    assert!(st.last_error.is_none());
    assert_eq!(fake.saved.lock().unwrap().last().unwrap().step, Step::Done);
}

#[tokio::test(flavor = "current_thread")]
async fn a_failed_step_resumes_where_it_stopped() {
    let fake = Fake::new();
    let mut st = reviewed(&fake).await;
    *fake.fail.lock().unwrap() = Some((ProfilePhase::System, ErrorCode::Internal, 1));
    let e = run(&fake, &mut st).await.unwrap_err();
    assert!(
        matches!(
            e,
            ProvisionError::Request {
                op: "profile.apply",
                ..
            }
        ),
        "{e}"
    );
    assert_eq!(st.step, Step::System);
    assert!(st.last_error.is_some());
    // What the app persisted says the same (resume after a restart).
    let saved = fake.saved.lock().unwrap().last().unwrap().clone();
    assert_eq!(saved.step, Step::System);
    let mut resumed = saved;
    fake.log.lock().unwrap().clear();
    assert_eq!(run(&fake, &mut resumed).await, Ok(Step::Done));
    let log = fake.logged();
    assert_eq!(log[0], "profile.plan");
    assert_eq!(log[1], "profile.apply System");
    assert!(
        !log.iter()
            .any(|l| l.contains("Accounts") || l.contains("Access"))
    );
    assert!(resumed.last_error.is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn busy_package_manager_is_waited_out() {
    let fake = Fake::new();
    let mut st = reviewed(&fake).await;
    *fake.fail.lock().unwrap() = Some((ProfilePhase::System, ErrorCode::Busy, 2));
    let mut waits = 0;
    let r = advance(&fake, &mut st, &cfg(), |e| {
        if matches!(e, ProvisionEvent::Waiting { .. }) {
            waits += 1;
        }
    })
    .await;
    assert_eq!(r, Ok(Step::Done));
    assert_eq!(waits, 2);
}

#[tokio::test(flavor = "current_thread")]
async fn unconfirmed_access_goes_back_to_the_provider_user() {
    let fake = Fake::new();
    let mut st = reviewed(&fake).await;
    *fake.confirm.lock().unwrap() = Err(ConfirmFailure::Other("connection refused".into()));
    let e = run(&fake, &mut st).await.unwrap_err();
    assert!(matches!(e, ProvisionError::Confirm(_)), "{e}");
    assert_eq!(st.step, Step::Access, "the change reverts: apply it again");
    assert_eq!(*fake.ssh_user.lock().unwrap(), PROVIDER);
    assert!(st.pending_change.is_none());
    // The agent reverted: the SSH/firewall modules are pending again.
    fake.remaining
        .lock()
        .unwrap()
        .insert(0, change("ssh.hardening"));
    *fake.confirm.lock().unwrap() = Ok(());
    assert_eq!(run(&fake, &mut st).await, Ok(Step::Done));
    assert_eq!(fake.confirmed_as.lock().unwrap().as_deref(), Some(ADMIN));

    // Reverted before the confirm arrived: also back to Access.
    let fake = Fake::new();
    let mut st = reviewed(&fake).await;
    *fake.confirm.lock().unwrap() = Err(ConfirmFailure::Reverted);
    assert_eq!(run(&fake, &mut st).await, Err(ProvisionError::Reverted));
    assert_eq!(st.step, Step::Access);
}

#[tokio::test(flavor = "current_thread")]
async fn resumed_access_confirms_a_change_still_pending() {
    let fake = Fake::new();
    let mut st = reviewed(&fake).await;
    // An earlier run applied Accounts and Access, then stopped before it
    // saved ConfirmAccess: the plan has nothing of Access left.
    fake.remaining.lock().unwrap().retain(|c| {
        !in_phase(&c.module, ProfilePhase::Access) && !in_phase(&c.module, ProfilePhase::Accounts)
    });
    fake.pending.lock().unwrap().push(pending_change());
    st.step = Step::Access;
    fake.log.lock().unwrap().clear();
    let mut armed = None;
    let r = advance(&fake, &mut st, &cfg(), |e| {
        if let ProvisionEvent::RevertArmed { deadline_ms } = e {
            armed = Some(deadline_ms);
        }
    })
    .await;
    assert_eq!(r, Ok(Step::Done));
    assert_eq!(armed, Some(60_001));
    let log = fake.logged();
    let at = |s: &str| log.iter().position(|l| l == s).unwrap();
    assert!(
        at("changes.list") < at("confirm (new connection)"),
        "{log:?}"
    );
    assert!(!log.iter().any(|l| l == "profile.apply Access"));
}

#[tokio::test(flavor = "current_thread")]
async fn access_not_compliant_after_audit_goes_back_to_access() {
    let fake = Fake::new();
    let mut st = reviewed(&fake).await;
    fake.findings.lock().unwrap().push(AuditFinding {
        module: "ssh.hardening".into(),
        status: fleet_proto::payload::ModuleStatus::Drifted,
        severity: Severity::Critical,
        title: "sshd".into(),
        fixable: true,
    });
    let e = run(&fake, &mut st).await.unwrap_err();
    assert!(matches!(e, ProvisionError::AccessNotCompliant(ref m) if m == "ssh.hardening"));
    assert_eq!(st.step, Step::Access);
    assert!(!fake.logged().iter().any(|l| l.starts_with("add ")));
}

#[tokio::test(flavor = "current_thread")]
async fn a_plan_that_grew_since_review_is_not_applied() {
    let fake = Fake::new();
    let mut st = reviewed(&fake).await;
    fake.extra.lock().unwrap().push(change("mounts.tmp"));
    assert_eq!(run(&fake, &mut st).await, Err(ProvisionError::PlanChanged));
    assert_eq!(st.step, Step::Review);
    assert!(st.plan.iter().any(|c| c.module == "mounts.tmp"));
    assert!(!fake.logged().iter().any(|l| l.starts_with("profile.apply")));
    // Approving the new plan continues.
    let hash = st.plan_hash.unwrap();
    st.approve_plan(&hash).unwrap();
    assert_eq!(run(&fake, &mut st).await, Ok(Step::Done));
}

#[tokio::test(flavor = "current_thread")]
async fn custom_profiles_need_a_root_approval_per_phase() {
    let fake = Fake::new();
    let mut c = choice();
    c.allow_from = vec!["203.0.113.0/24".into()];
    c.reboot_window = Some("Sun 04:00-05:00 UTC".into());
    assert!(c.is_custom());
    let toml = c.custom_toml(&server()).unwrap();
    let parsed: toml::Table = toml.parse().unwrap();
    assert_eq!(parsed["profile"]["extends"].as_str(), Some("baseline"));
    assert_eq!(
        parsed["ssh"]["allow_from"][0].as_str(),
        Some("203.0.113.0/24")
    );
    assert_eq!(parsed["admin"]["user"].as_str(), Some(ADMIN));
    let mut st = ProvisionState::new(&server(), c, PROVIDER);
    assert_eq!(run(&fake, &mut st).await, Ok(Step::Review));
    let hash = st.plan_hash.unwrap();
    st.approve_plan(&hash).unwrap();
    // Without the root key the first phase stops for approval.
    let root = fake.root.lock().unwrap().take();
    let e = run(&fake, &mut st).await.unwrap_err();
    assert!(matches!(e, ProvisionError::Approval(_)));
    assert_eq!(st.step, Step::Accounts);
    let asked = fake.approvals.lock().unwrap().clone();
    assert_eq!(asked.len(), 1);
    assert!(asked[0].contains("Accounts"));
    // With it, every phase asks for its own approval.
    *fake.root.lock().unwrap() = root;
    assert_eq!(run(&fake, &mut st).await, Ok(Step::Done));
    let asked = fake.approvals.lock().unwrap().clone();
    assert_eq!(asked.len(), 4, "{asked:?}");
    for (a, p) in asked[1..].iter().zip(["Accounts", "Access", "System"]) {
        assert!(a.contains(p), "{a}");
    }
}

#[test]
fn choices_are_validated() {
    let ok = choice();
    assert!(ok.validate().is_ok());
    let bad = |f: &dyn Fn(&mut ProvisionChoice)| {
        let mut c = choice();
        f(&mut c);
        c.validate().is_err()
    };
    assert!(bad(&|c| c.admin_user = "root".into()));
    assert!(bad(&|c| c.admin_user = "fleet-gate".into()));
    assert!(bad(&|c| c.admin_user = "Bad User".into()));
    assert!(bad(&|c| c.allow_from = vec!["10.0.0.0/33".into()]));
    assert!(bad(&|c| c.allow_from = vec!["example.com".into()]));
    assert!(bad(&|c| c.reboot_window = Some("Sun\n04:00".into())));
    assert!(bad(&|c| c.roles = vec![Role::Web, Role::Web]));
    assert!(bad(&|c| c.name = " ".into()));
    let mut v6 = choice();
    v6.allow_from = vec!["2001:db8::/32".into(), "198.51.100.7".into()];
    assert!(v6.validate().is_ok());
}

#[test]
fn sudo_hash_is_sha512_crypt() {
    use sha_crypt::{PasswordVerifier, ShaCrypt};
    // glibc's published vector: the crate computes crypt(3)'s `$6$`.
    let vector = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1";
    assert!(
        ShaCrypt::SHA512
            .verify_password(b"Hello world!", vector)
            .is_ok()
    );
    assert!(
        ShaCrypt::SHA512
            .verify_password(b"Hello world?", vector)
            .is_err()
    );
    // Ours: `$6$rounds=5000$<16 salt chars>$<86 chars>`, random salt,
    // accepted by the proto type and verifiable.
    let pw = "Abcdefghjkmnpqrstuvwxyz2";
    let a = sudo_password_hash(pw).unwrap();
    let b = sudo_password_hash(pw).unwrap();
    assert_ne!(a, b, "fresh salt each time");
    let s = serde_json::to_value(&a).unwrap();
    let s = s.as_str().unwrap();
    assert!(s.starts_with("$6$rounds=5000$"), "{s}");
    let parts: Vec<&str> = s.split('$').collect();
    assert_eq!((parts[3].len(), parts[4].len()), (16, 86));
    assert!(ShaCrypt::SHA512.verify_password(pw.as_bytes(), s).is_ok());
}
