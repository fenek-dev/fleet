use super::*;
use crate::engine;
use crate::handler::ProfileHandler;
use crate::module::{Action, Cmd, Status};
use crate::modules::ssh;
use crate::revert::{ProfileRevert, Snapshot};
use fleet_crypto::verify::VerifiedCommand;
use fleet_ops::Revertible;
use fleet_ops::handler::{Invocation, OpHandler, OpMeta, OpOutput};
use fleet_ops::runner::CommandOutput;
use fleet_proto::args::ModuleId;
use fleet_proto::args::SudoPasswordHash;
use fleet_proto::op::{ProfileLevel, ProfilePhase, ProfileSource, ProfileSpec};
use fleet_proto::payload::{ModuleOutcome, ModuleStatus};
use fleet_proto::{
    Actor, CommandBody, DeviceId, ErrorCode, FleetId, KeyKind, Op, Payload, ServerId,
};

fn meta(op: Op) -> OpMeta {
    OpMeta {
        command: VerifiedCommand {
            body: CommandBody {
                v: 1,
                fleet_id: FleetId([1; 16]),
                server_id: ServerId::new("srv_test01").unwrap(),
                issued_at_ms: 0,
                ttl_ms: 60_000,
                nonce: [0; 16],
                actor: Actor::Human,
                op,
                expected_version: None,
            },
            device_id: DeviceId([2; 16]),
            key: KeyKind::Device,
            approval: None,
            command_hash: [0; 32],
            nonce_expires_at_ms: 0,
        },
        approval: None,
        audit_seq: Some(7),
        now_ms: 0,
        invocation: Invocation::Request,
    }
}

fn run(env: &Env, op: Op) -> Result<Payload, fleet_ops::handler::OpError> {
    let h = ProfileHandler;
    let m = meta(op.clone());
    h.validate(&env.sys, &op, &m)?;
    match block(h.handle(&env.sys, &op, &m))? {
        OpOutput::Payload(p) => Ok(p),
        OpOutput::Stream(_) => panic!("stream"),
    }
}

fn apply(spec: ProfileSpec, plan_hash: [u8; 32], phase: ProfilePhase) -> Op {
    Op::ProfileApply {
        spec,
        plan_hash,
        phase,
        password_hash: None,
    }
}

fn plan_of(env: &Env, spec: ProfileSpec) -> fleet_proto::payload::ProfilePlan {
    let Payload::ProfilePlan(plan) = run(env, Op::ProfilePlan(spec)).unwrap() else {
        panic!()
    };
    plan
}

fn spec(only: &[&str]) -> ProfileSpec {
    ProfileSpec {
        source: ProfileSource::Builtin {
            level: ProfileLevel::Baseline,
            roles: vec![],
        },
        only: only.iter().map(|o| ModuleId::new(*o).unwrap()).collect(),
    }
}

fn fixed_plan() -> Vec<Change> {
    vec![Change {
        module: "sysctl",
        description: "update /etc/x".into(),
        diff: "+ a\n".into(),
        actions: vec![
            Action::Write {
                path: "/etc/x".into(),
                content: b"a\n".to_vec(),
                mode: 0o644,
            },
            Action::Run(Cmd::new("/usr/bin/true", ["a"])),
        ],
    }]
}

#[test]
fn plan_hash_is_stable_and_covers_actions() {
    let p = fixed_plan();
    let h = engine::plan_hash(&p);
    assert_eq!(h, engine::plan_hash(&fixed_plan()));
    let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
    // Pinned: a change here means every Mac's stored plan hash changes.
    assert_eq!(
        hex,
        "cb3e52a284bb5d430ed884fbea1180871eab2b5229ee0f5431258ff54edb2fe2"
    );
    let mut q = fixed_plan();
    let Action::Write { content, .. } = &mut q[0].actions[0] else {
        unreachable!()
    };
    content[0] = b'b';
    assert_ne!(engine::plan_hash(&q), h);
    let mut r = fixed_plan();
    r[0].actions[1] = Action::Run(Cmd::new("/usr/bin/true", ["a"]).stdin(b"x".to_vec()));
    assert_ne!(engine::plan_hash(&r), h);
}

#[test]
fn score_weights_and_exclusions() {
    let r = |id, weight, status: Result<Status, String>, skipped: Option<&str>| engine::Report {
        id,
        title: "",
        weight,
        severity: fleet_proto::alert::Severity::Warning,
        status,
        skipped: skipped.map(str::to_owned),
        fixable: false,
    };
    let reports = [
        r("a", 10, Ok(Status::Compliant), None),
        r("b", 10, Ok(Status::Drifted("x".into())), None),
        r("c", 20, Ok(Status::NotApplicable("n".into())), None),
        r("d", 20, Ok(Status::Compliant), Some("skipped")),
        r("e", 5, Ok(Status::PendingReboot("p".into())), None),
        r("f", 5, Err("boom".into()), None),
    ];
    // (10 + 5) / (10 + 10 + 5 + 5)
    assert_eq!(engine::score(&reports), 50);
    assert_eq!(engine::score(&[]), 100);
}

#[test]
fn plan_then_apply_through_the_handler() {
    let env = Env::new().with_admin();
    let Payload::ProfilePlan(plan) = run(&env, Op::ProfilePlan(spec(&["ssh.hardening"]))).unwrap()
    else {
        panic!()
    };
    assert_eq!(plan.changes.len(), 1);
    assert!(plan.changes[0].auto_revert);
    assert!(plan.changes[0].diff.contains("+ AllowUsers ops"));
    // A stale hash: refused before anything runs.
    let e = run(
        &env,
        apply(spec(&["ssh.hardening"]), [0; 32], ProfilePhase::Access),
    )
    .unwrap_err();
    assert!(matches!(e.code(), ErrorCode::VersionConflict { .. }));
    assert!(env.read(ssh::FLEET_CONF).is_none());
    env.ok(ssh::SSHD, &["-t"]);
    env.ok(
        "/usr/bin/systemctl",
        &["try-reload-or-restart", "--", "ssh.service"],
    );
    env.expect_sshd_t(&super::baseline());
    let op = apply(
        spec(&["ssh.hardening"]),
        plan.plan_hash,
        ProfilePhase::Access,
    );
    assert!(op.auto_revert());
    // The handler's real result (exec wraps it in `ChangePending`).
    let Payload::ProfileApplied(pa) = run(&env, op).unwrap() else {
        panic!()
    };
    assert_eq!(pa.modules.len(), 1);
    assert_eq!(pa.modules[0].id, "ssh.hardening");
    assert_eq!(pa.modules[0].outcome, ModuleOutcome::Applied);
    assert!(pa.pending.is_none());
    assert!(pa.score_after > pa.score_before, "{pa:?}");
    assert_eq!(pa.score_after, 100);
    assert_done(&env);
    assert!(
        env.read(ssh::FLEET_CONF)
            .unwrap()
            .contains("AllowUsers ops")
    );
    // Re-planning: nothing left.
    let Payload::ProfilePlan(again) = run(&env, Op::ProfilePlan(spec(&["ssh.hardening"]))).unwrap()
    else {
        panic!()
    };
    assert!(again.changes.is_empty());
}

#[test]
fn a_phase_applies_only_its_modules_of_the_hashed_plan() {
    let env = Env::new().with_admin();
    // A profile of two modules in different phases, `only` empty.
    let mut p = baseline();
    p.modules = vec!["ssh.hardening".into(), "sysctl".into()];
    let mut c = ctx(&env, p, facts());
    // One plan (both phases), hashed as the operator saw it.
    let plan = engine::plan(&c).unwrap();
    assert!(plan.iter().any(|ch| ch.module == "sysctl"));
    let hash = engine::plan_hash(&plan);
    env.ok(ssh::SSHD, &["-t"]);
    env.ok(
        "/usr/bin/systemctl",
        &["try-reload-or-restart", "--", "ssh.service"],
    );
    env.expect_sshd_t(&super::baseline());
    let res = block(engine::apply(&mut c, &hash, ProfilePhase::Access, None)).unwrap();
    assert_done(&env);
    let ids: Vec<&str> = res.iter().map(|m| m.id.as_str()).collect();
    assert_eq!(ids, ["ssh.hardening"]);
    assert!(env.read(ssh::FLEET_CONF).is_some());
    assert!(env.read(crate::modules::kernel::SYSCTL_CONF).is_none());
    // The System phase then runs sysctl, after re-planning: the plan
    // changed, so the old hash is stale.
    let stale = block(engine::apply(&mut c, &hash, ProfilePhase::System, None)).unwrap_err();
    assert!(matches!(stale.code(), ErrorCode::VersionConflict { .. }));
    let again = engine::plan_hash(&engine::plan(&c).unwrap());
    env.ok("/usr/sbin/sysctl", &["--ignore", "--system"]);
    let res = block(engine::apply(&mut c, &again, ProfilePhase::System, None)).unwrap();
    assert_done(&env);
    let ids: Vec<&str> = res.iter().map(|m| m.id.as_str()).collect();
    assert_eq!(ids, ["sysctl"]);
    assert!(env.read(crate::modules::kernel::SYSCTL_CONF).is_some());
}

#[test]
fn only_must_fit_the_phase() {
    let env = Env::new().with_admin();
    // sysctl isn't an Accounts module (the proto can't know that).
    let op = apply(spec(&["sysctl"]), [0; 32], ProfilePhase::Accounts);
    assert!(op.check_args().is_ok());
    let e = run(&env, op).unwrap_err();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    assert!(
        run(
            &env,
            apply(spec(&["admin.user"]), [0; 32], ProfilePhase::System)
        )
        .is_err()
    );
    assert!(env.runner.calls().is_empty());
}

#[test]
fn modules_phase_table_matches_the_wire_access_list() {
    let p = crate::profile::builtin(
        ProfileLevel::Strict,
        &[
            fleet_proto::op::ProfileRole::Docker,
            fleet_proto::op::ProfileRole::Web,
            fleet_proto::op::ProfileRole::Game,
        ],
    )
    .unwrap();
    let access: Vec<&str> = engine::modules_of(&p)
        .iter()
        .filter(|m| m.phase() == crate::Phase::Access)
        .map(|m| m.id())
        .collect();
    assert_eq!(access, ProfilePhase::ACCESS_MODULES);
    for m in engine::modules_of(&p) {
        assert_eq!(
            ProfilePhase::is_access_module(m.id()),
            m.phase().runs_in(ProfilePhase::Access),
            "{}",
            m.id()
        );
    }
}

#[test]
fn password_from_the_command_sets_the_sudo_password() {
    let env = Env::new().with_admin();
    let hash = "$y$j9T$abcdefghijklmnop$ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abc";
    let s = spec(&["admin.user"]);
    // The plan the operator saw has no password step (it isn't known yet).
    let plan = plan_of(&env, s.clone());
    assert!(plan.changes.is_empty(), "{:?}", plan.changes);
    let op = Op::ProfileApply {
        spec: s.clone(),
        plan_hash: plan.plan_hash,
        phase: ProfilePhase::Accounts,
        password_hash: Some(SudoPasswordHash::crypt(hash).unwrap()),
    };
    assert!(!op.auto_revert());
    env.ok(crate::modules::access::CHPASSWD, &["--encrypted"]);
    let Payload::ProfileApplied(pa) = run(&env, op).unwrap() else {
        panic!()
    };
    assert_done(&env);
    assert_eq!(pa.modules[0].outcome, ModuleOutcome::Applied);
    let calls = env.runner.calls();
    let chpasswd = calls
        .iter()
        .find(|c| c.program == crate::modules::access::CHPASSWD)
        .unwrap();
    assert_eq!(
        chpasswd.stdin.as_deref(),
        Some(format!("ops:{hash}\n").as_bytes())
    );
    assert!(
        calls
            .iter()
            .all(|c| c.args.iter().all(|a| !a.to_string_lossy().contains("j9T")))
    );
    // The redacted audit form is refused even past check_args.
    let redacted = Op::ProfileApply {
        spec: s,
        plan_hash: plan.plan_hash,
        phase: ProfilePhase::Accounts,
        password_hash: Some(SudoPasswordHash::crypt(hash).unwrap().redacted()),
    };
    assert_eq!(
        run(&env, redacted).unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
}

#[test]
fn pending_reboot_is_its_own_wire_status() {
    let r = engine::Report {
        id: "auditd",
        title: "audit rules",
        weight: 5,
        severity: fleet_proto::alert::Severity::Warning,
        status: Ok(Status::PendingReboot("immutable rules load at boot".into())),
        skipped: None,
        fixable: false,
    };
    assert_eq!(
        crate::handler::wire_status(&r),
        (
            ModuleStatus::PendingReboot,
            "immutable rules load at boot".to_owned()
        )
    );
}

#[test]
fn check_and_audit_report() {
    let env = Env::new().with_admin();
    let Payload::ProfileCheck(c) = run(&env, Op::ProfileCheck(spec(&[]))).unwrap() else {
        panic!()
    };
    let status = |id: &str| c.modules.iter().find(|m| m.id == id).unwrap().status;
    assert_eq!(status("ssh.hardening"), ModuleStatus::Drifted);
    // nft unavailable in the fake: the check errors, the rest still runs.
    assert_eq!(status("firewall.baseline"), ModuleStatus::Error);
    assert!(c.score < 100);
    let Payload::AuditReport(a) = run(
        &env,
        Op::AuditRun {
            level: ProfileLevel::Strict,
        },
    )
    .unwrap() else {
        panic!()
    };
    let ssh = a
        .findings
        .iter()
        .find(|f| f.module == "ssh.hardening")
        .unwrap();
    assert!(ssh.fixable);
    assert_eq!(ssh.severity, fleet_proto::alert::Severity::Critical);
    assert!(a.findings.iter().any(|f| f.module == "mounts.tmp"));
    assert!(a.findings.iter().all(|f| f.module != "role.docker"));
}

#[test]
fn custom_profile_exceptions_show_as_skipped() {
    let env = Env::new().with_admin();
    let toml =
        "[profile]\nextends = \"baseline\"\nroles = [\"docker\"]\n[skip]\nmodules = [\"swap\"]\n";
    let spec = ProfileSpec {
        source: ProfileSource::Custom(fleet_proto::args::ProfileToml::new(toml).unwrap()),
        only: vec![],
    };
    let Payload::ProfileCheck(c) = run(&env, Op::ProfileCheck(spec)).unwrap() else {
        panic!()
    };
    let find = |id: &str| c.modules.iter().find(|m| m.id == id).unwrap();
    assert_eq!(find("swap").status, ModuleStatus::Skipped);
    let fwd = find("sysctl.net.ipv4.ip_forward");
    assert_eq!(fwd.status, ModuleStatus::Skipped);
    assert_eq!(fwd.detail, "required by role: docker");
}

#[test]
fn revert_snapshot_restores_files_and_reloads() {
    let env = Env::new().with_admin();
    // Access alone: only sshd's files, only its reloads.
    let access = apply(spec(&[]), [0; 32], ProfilePhase::Access);
    let env2 = Env::new().with_admin();
    env2.runner.expect(
        fleet_ops::firewall::NFT,
        &["-j", "list", "table", "inet", "fleet"],
        Ok(CommandOutput {
            code: Some(1),
            stdout: Vec::new(),
            stderr: b"Error: No such file or directory".to_vec(),
            truncated: false,
        }),
    );
    let only_access =
        Snapshot::decode(&ProfileRevert.snapshot(&env2.sys, &access).unwrap()).unwrap();
    assert!(only_access.firewall.is_some());
    assert!(
        only_access
            .files
            .iter()
            .all(|f| [ssh::FLEET_CONF, ssh::OLD_FLEET_CONF, ssh::SSHD_CONFIG]
                .contains(&f.path.as_str())),
        "{:?}",
        only_access
            .files
            .iter()
            .map(|f| &f.path)
            .collect::<Vec<_>>()
    );
    // One group: `sshd -t` validates before the reload.
    assert_eq!(only_access.reload.len(), 1);
    assert_eq!(only_access.reload[0][0].0, ssh::SSHD);
    assert_eq!(only_access.reload[0][1].0, "/usr/bin/systemctl");
    let op = apply(spec(&["ssh.hardening"]), [0; 32], ProfilePhase::All);
    let bytes = ProfileRevert.snapshot(&env.sys, &op).unwrap();
    let snap = Snapshot::decode(&bytes).unwrap();
    assert!(snap.firewall.is_none());
    assert!(
        snap.files
            .iter()
            .any(|f| f.path == ssh::FLEET_CONF && f.prior.is_none())
    );
    // A phase-System module isn't part of an access snapshot.
    assert!(
        !snap
            .files
            .iter()
            .any(|f| f.path == crate::modules::kernel::SYSCTL_CONF)
    );
    env.put(ssh::FLEET_CONF, "AllowUsers nobody\n");
    env.put(ssh::SSHD_CONFIG, "broken\n");
    env.ok(ssh::SSHD, &["-t"]);
    env.ok(
        "/usr/bin/systemctl",
        &["try-reload-or-restart", "--", "ssh.service"],
    );
    ProfileRevert.restore(&env.sys, &bytes).unwrap();
    assert_done(&env);
    assert!(env.read(ssh::FLEET_CONF).is_none());
    assert_eq!(
        env.read(ssh::SSHD_CONFIG).unwrap(),
        "Include /etc/ssh/sshd_config.d/*.conf\nUsePAM yes\n"
    );
}

#[test]
fn revert_skips_reload_when_restored_sshd_config_is_invalid() {
    let env = Env::new().with_admin();
    let op = apply(spec(&["ssh.hardening"]), [0; 32], ProfilePhase::Access);
    let bytes = ProfileRevert.snapshot(&env.sys, &op).unwrap();
    env.put(ssh::FLEET_CONF, "AllowUsers ops\n");
    env.runner
        .expect(ssh::SSHD, &["-t"], Ok(CommandOutput::exit(255)));
    let e = ProfileRevert.restore(&env.sys, &bytes).unwrap_err();
    assert!(e.detail().unwrap().contains("reload skipped"), "{e:?}");
    // The files are back; no reload was attempted.
    assert!(env.read(ssh::FLEET_CONF).is_none());
    assert_done(&env);
    assert_eq!(env.runner.calls().len(), 1);
}

#[test]
fn revert_restores_the_firewall_only_while_unchanged() {
    use crate::revert::restore_firewall;
    let snap = Snapshot {
        files: vec![],
        firewall: Some(vec![]),
        firewall_version: Some(5),
        reload: vec![],
    };
    // Still what the apply left (7): restore.
    assert!(restore_firewall(&snap, Some(7), Some(7)));
    // Changed since (8): keep the newer table.
    assert!(!restore_firewall(&snap, Some(7), Some(8)));
    // Already the snapshotted table: nothing to do.
    assert!(!restore_firewall(&snap, Some(7), Some(5)));
    // Unknown current version or no recorded apply: restore.
    assert!(restore_firewall(&snap, Some(7), None));
    assert!(restore_firewall(&snap, None, Some(8)));
}

#[test]
fn v1_snapshots_still_decode() {
    #[derive(serde::Serialize)]
    struct V1 {
        files: Vec<crate::module::FileSnap>,
        firewall: Option<Vec<u8>>,
        reload: Vec<(String, Vec<String>)>,
    }
    let v1 = V1 {
        files: vec![],
        firewall: None,
        reload: vec![
            (ssh::SSHD.into(), vec!["-t".into()]),
            ("/usr/bin/systemctl".into(), vec!["x".into()]),
            ("/usr/sbin/sysctl".into(), vec!["--system".into()]),
        ],
    };
    let mut b = vec![1u8];
    b.extend(fleet_proto::encode(&v1));
    let s = Snapshot::decode(&b).unwrap();
    assert_eq!(s.reload.len(), 2);
    assert_eq!(s.reload[0].len(), 2);
}

#[test]
fn revert_covers_the_firewall() {
    let env = Env::new().with_admin();
    let absent = || {
        Ok(CommandOutput {
            code: Some(1),
            stdout: Vec::new(),
            stderr: b"Error: No such file or directory".to_vec(),
            truncated: false,
        })
    };
    env.runner.expect(
        fleet_ops::firewall::NFT,
        &["-j", "list", "table", "inet", "fleet"],
        absent(),
    );
    let op = apply(spec(&["firewall.baseline"]), [0; 32], ProfilePhase::Access);
    let bytes = ProfileRevert.snapshot(&env.sys, &op).unwrap();
    assert!(Snapshot::decode(&bytes).unwrap().firewall.is_some());
    env.ok(fleet_ops::firewall::NFT, &["-f", "-"]);
    ProfileRevert.restore(&env.sys, &bytes).unwrap();
    assert_done(&env);
    let calls = env.runner.calls();
    let apply = calls
        .iter()
        .find(|c| c.args.first().is_some_and(|a| a == "-f"))
        .unwrap();
    let script = String::from_utf8(apply.stdin.clone().unwrap()).unwrap();
    assert!(script.contains("delete table inet fleet"));
}

#[test]
fn restore_refuses_foreign_programs() {
    let env = Env::new();
    let snap = Snapshot {
        files: vec![],
        firewall: None,
        firewall_version: None,
        reload: vec![vec![("/bin/sh".into(), vec!["-c".into(), "x".into()])]],
    };
    assert!(crate::revert::restore(&env.sys, &snap, None).is_err());
    assert!(env.runner.calls().is_empty());
}
