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
use fleet_proto::op::{ProfileLevel, ProfileSource, ProfileSpec};
use fleet_proto::payload::{ChangeKind, ModuleStatus};
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
        Op::ProfileApply {
            spec: spec(&["ssh.hardening"]),
            plan_hash: [0; 32],
        },
    )
    .unwrap_err();
    assert!(matches!(e.code(), ErrorCode::VersionConflict { .. }));
    assert!(env.read(ssh::FLEET_CONF).is_none());
    env.ok(ssh::SSHD, &["-t"]);
    env.ok(
        "/usr/bin/systemctl",
        &["try-reload-or-restart", "--", "ssh.service"],
    );
    let p = run(
        &env,
        Op::ProfileApply {
            spec: spec(&["ssh.hardening"]),
            plan_hash: plan.plan_hash,
        },
    )
    .unwrap();
    let Payload::ChangePending(pc) = p else {
        panic!()
    };
    assert_eq!(pc.kind, ChangeKind::Profile);
    assert_eq!(pc.new_version, None);
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
    let op = Op::ProfileApply {
        spec: spec(&["ssh.hardening", "sysctl"]),
        plan_hash: [0; 32],
    };
    let bytes = ProfileRevert.snapshot(&env.sys, &op).unwrap();
    let snap = Snapshot::decode(&bytes).unwrap();
    assert!(snap.firewall.is_none());
    assert!(
        snap.files
            .iter()
            .any(|f| f.path == ssh::FLEET_CONF && f.prior.is_none())
    );
    env.put(ssh::FLEET_CONF, "AllowUsers nobody\n");
    env.put(ssh::SSHD_CONFIG, "broken\n");
    env.put(crate::modules::kernel::SYSCTL_CONF, "x = 1\n");
    env.ok(ssh::SSHD, &["-t"]);
    env.ok(
        "/usr/bin/systemctl",
        &["try-reload-or-restart", "--", "ssh.service"],
    );
    env.ok("/usr/sbin/sysctl", &["--ignore", "--system"]);
    ProfileRevert.restore(&env.sys, &bytes).unwrap();
    assert_done(&env);
    assert!(env.read(ssh::FLEET_CONF).is_none());
    assert!(env.read(crate::modules::kernel::SYSCTL_CONF).is_none());
    assert_eq!(
        env.read(ssh::SSHD_CONFIG).unwrap(),
        "Include /etc/ssh/sshd_config.d/*.conf\nUsePAM yes\n"
    );
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
    let op = Op::ProfileApply {
        spec: spec(&["firewall.baseline"]),
        plan_hash: [0; 32],
    };
    let bytes = ProfileRevert.snapshot(&env.sys, &op).unwrap();
    assert!(Snapshot::decode(&bytes).unwrap().firewall.is_some());
    env.ok(fleet_ops::firewall::NFT, &["-f", "-"]);
    ProfileRevert.restore(&env.sys, &bytes).unwrap();
    assert_done(&env);
    let script = String::from_utf8(env.runner.calls()[1].stdin.clone().unwrap()).unwrap();
    assert!(script.contains("delete table inet fleet"));
}

#[test]
fn restore_refuses_foreign_programs() {
    let env = Env::new();
    let snap = Snapshot {
        files: vec![],
        firewall: None,
        reload: vec![("/bin/sh".into(), vec!["-c".into(), "x".into()])],
    };
    assert!(crate::revert::restore(&env.sys, &snap).is_err());
    assert!(env.runner.calls().is_empty());
}
