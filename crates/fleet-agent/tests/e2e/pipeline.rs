//! Exec pipeline: `Op::check_args`, `expected_version`, undecodable signed
//! bodies, conditional escalation, and the auto-revert protocol with
//! `change.confirm` (design §4.2, §4.10, §5.6).

use super::*;
use fleet_ops::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, Revertible, SysCtx};
use fleet_proto::args::{ComposeFile, ComposeProject, FirewallMode, FirewallRuleSet};
use fleet_proto::op::tag;
use fleet_proto::payload::{self, ChangeKind as WireKind};
use std::rc::Rc;

fn fw() -> Op {
    Op::FirewallApply(FirewallRuleSet {
        mode: FirewallMode::Managed,
        rules: vec![],
    })
}

fn compose(yaml: &str) -> Op {
    Op::ComposeDeploy {
        project: ComposeProject::new("app").unwrap(),
        file: ComposeFile::new(yaml).unwrap(),
        pull: false,
    }
}

/// Test handler: `compose.deploy` escalates via the real validator;
/// auto-revert ops report `new_version: 8` after `delay`, or fail if
/// `fail` is set.
struct TestOps {
    fail: bool,
    delay: Duration,
}

impl OpHandler for TestOps {
    fn requires_elevated(&self, _: &SysCtx, op: &Op, _: &OpMeta) -> Result<bool, OpError> {
        fleet_ops::escalation::compose_deploy(op)
    }

    fn handle<'a>(
        &'a self,
        _: &'a SysCtx,
        op: &'a Op,
        _: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            tokio::time::sleep(self.delay).await;
            if self.fail {
                return Err(OpError::new(ErrorCode::Internal));
            }
            Ok(OpOutput::Payload(if op.auto_revert() {
                Payload::ChangePending(payload::PendingChange {
                    change_id: [0; 16],
                    kind: WireKind::Network,
                    op_tag: 0,
                    created_ms: 0,
                    deadline_ms: 0,
                    new_version: Some(8),
                })
            } else {
                Payload::Empty
            }))
        })
    }
}

/// Records snapshots taken and restores done.
#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<String>>>);

impl Log {
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut self.0.lock().unwrap())
    }
}

struct TestRevertible(Log);

impl Revertible for TestRevertible {
    fn snapshot(&self, _: &SysCtx, op: &Op) -> Result<Vec<u8>, OpError> {
        self.0
            .0
            .lock()
            .unwrap()
            .push(format!("snapshot {}", op.name()));
        Ok(op.name().as_bytes().to_vec())
    }

    fn restore(&self, _: &SysCtx, s: &[u8]) -> Result<(), OpError> {
        let s = String::from_utf8_lossy(s);
        self.0.0.lock().unwrap().push(format!("restore {s}"));
        Ok(())
    }
}

struct Env {
    fx: Fixture,
    log: Log,
    timers: Timers,
}

/// Exec with [`TestOps`] on compose/firewall/mesh tags and
/// [`TestRevertible`] for the firewall and mesh kinds.
fn env(groups: &'static str, fail: bool) -> Env {
    env_with(groups, fail, Duration::ZERO, Duration::from_secs(30))
}

fn env_with(groups: &'static str, fail: bool, delay: Duration, apply_timeout: Duration) -> Env {
    let mut fx = Fixture::with(
        2,
        0,
        Opts {
            pol: Pol {
                groups,
                ..Pol::default()
            },
            ..Opts::default()
        },
    );
    let log = Log::default();
    let timers = Arc::new(Mutex::new(Vec::new()));
    let (l, t) = (log.clone(), timers.clone());
    fx.exec = None;
    fx.start_exec_with(move |cfg| {
        let h: Rc<dyn OpHandler> = Rc::new(TestOps { fail, delay });
        cfg.apply_timeout = apply_timeout;
        for tag in [tag::COMPOSE_DEPLOY, tag::FIREWALL_APPLY, tag::MESH_LEAVE] {
            cfg.handlers.push((tag, h.clone()));
        }
        let r: Rc<dyn Revertible> = Rc::new(TestRevertible(l.clone()));
        // Only the test modules: authorized keys stays the "no module" kind.
        cfg.reverters = fleet_ops::Reverters::new();
        cfg.reverters.register(WireKind::Firewall, r.clone());
        cfg.reverters.register(WireKind::Mesh, r.clone());
        let mut restore = fleet_ops::Reverters::new();
        restore.register(WireKind::Firewall, r.clone());
        restore.register(WireKind::Mesh, r);
        cfg.reverter = Box::new(fleet_agent::revert::RegistryRevert::new(
            restore,
            fleet_ops::SysCtx::system(),
        ));
        cfg.timers = Rc::new(SharedRecorder(t));
    });
    Env { fx, log, timers }
}

fn with_ev(ev: Option<u64>) -> CommandOpts {
    CommandOpts {
        expected_version: ev,
        ..CommandOpts::default()
    }
}

#[test]
fn arg_checks_expected_version_and_undecodable_bodies() {
    let e = env(r#""system", "firewall""#, false);
    let fx = &e.fx;
    run(async {
        let m = &fx.macs[0];
        let mut s = fx.connect(m).await;
        // `Op::check_args`: reboot delay above an hour.
        let r = s
            .request(
                Op::SystemReboot { delay_s: 99_999 },
                &fx.server,
                Actor::Human,
                None,
            )
            .await
            .unwrap();
        assert_eq!(r.receipt.receipt.audit_seq, None);
        assert_eq!(err(r), ErrorCode::InvalidArgument);

        // `firewall.apply` replaces versioned state: `expected_version` is
        // mandatory.
        let cmd = s
            .build_command(fw(), &fx.server, Actor::Human, None, &with_ev(None))
            .unwrap();
        assert_eq!(err(s.send(&cmd).await.unwrap()), ErrorCode::InvalidArgument);

        // A body whose envelope signature verifies but that doesn't decode:
        // a signed `InvalidArgument` receipt, not an unsigned failure.
        let mut cmd = s
            .build_command(
                Op::SystemInfo,
                &fx.server,
                Actor::Human,
                None,
                &with_ev(None),
            )
            .unwrap();
        cmd.body.push(0);
        let msg = SignedCommand::signed_message(cmd.key, &cmd.device_id, &cmd.body);
        cmd.signature = m.device.sign(&msg).unwrap();
        let r = s.send(&cmd).await.unwrap();
        assert_eq!(r.receipt.receipt.audit_seq, None);
        assert_eq!(err(r), ErrorCode::InvalidArgument);
    });
}

#[test]
fn compose_deploy_escalates_on_deny_list() {
    let e = env(r#""system", "docker""#, false);
    let fx = &e.fx;
    run(async {
        let m = &fx.macs[0];
        let mut s = fx.connect(m).await;
        let clean = compose("services:\n  web:\n    image: nginx\n");
        let r = s
            .request(clean, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));

        let bad = compose("services:\n  web:\n    image: nginx\n    privileged: true\n");
        let r = s
            .request(bad.clone(), &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(err(r), ErrorCode::ApprovalRequired);
        // With a root approval covering exactly this op: runs.
        let approval = fx.approve(m, &bad);
        let r = s
            .request(bad, &fx.server, Actor::Human, Some(approval))
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));

        let broken = compose("a: &x 1\n");
        let r = s
            .request(broken, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(err(r), ErrorCode::InvalidArgument);
    });
}

fn pending_files(fx: &Fixture) -> usize {
    PendingDir::from_paths(&fx.paths).list().unwrap().len()
}

fn change_id(r: &Reply) -> [u8; 16] {
    match &r.result {
        Ok(Payload::ChangePending(p)) => p.change_id,
        other => panic!("{other:?}"),
    }
}

#[test]
fn auto_revert_then_confirm_over_a_new_session() {
    let e = env(r#""system", "firewall""#, false);
    let fx = &e.fx;
    run(async {
        let m = &fx.macs[0];
        let mut s = fx.connect(m).await;
        // Opened before the change was applied: can't prove anything.
        let mut early = fx.connect(m).await;
        let cmd = s
            .build_command(fw(), &fx.server, Actor::Human, None, &with_ev(Some(7)))
            .unwrap();
        let r = s.send(&cmd).await.unwrap();
        let Ok(Payload::ChangePending(p)) = &r.result else {
            panic!("{r:?}")
        };
        assert_eq!(
            (p.kind, p.op_tag, p.new_version),
            (WireKind::Firewall, tag::FIREWALL_APPLY, Some(8))
        );
        assert!(p.deadline_ms >= p.created_ms + 60_000);
        let id = p.change_id;
        assert_eq!(e.log.take(), ["snapshot firewall.apply"]);
        let hex_id = hex::encode(id);
        // Guard timer before the apply, the confirm timer (full window)
        // after it, then the guard stopped.
        let armed = e.timers.lock().unwrap().clone();
        assert_eq!(armed.len(), 3, "{armed:?}");
        assert!(armed[0].contains(&format!("--unit=fleet-revert-{hex_id}-guard")));
        assert!(armed[1].contains(&format!("--unit=fleet-revert-{hex_id}")));
        assert!(armed[1].contains(&"--on-active=60".to_owned()));
        assert!(armed[1].contains(&"--timer-property=AccuracySec=1s".to_owned()));
        assert_eq!(
            armed[2],
            [
                "/usr/bin/systemctl",
                "stop",
                &format!("fleet-revert-{hex_id}-guard.timer")
            ]
        );
        assert_eq!(pending_files(fx), 1);

        // One pending change per kind: a second firewall change is `Busy`
        // (refused before its nonce is consumed).
        let cmd2 = s
            .build_command(fw(), &fx.server, Actor::Human, None, &with_ev(Some(8)))
            .unwrap();
        let r2 = s.send(&cmd2).await.unwrap();
        assert_eq!(r2.receipt.receipt.audit_seq, None);
        assert_eq!(err(r2), ErrorCode::Busy);

        let r = s
            .request(Op::ChangesList, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        match r.result {
            Ok(Payload::PendingChanges(l)) => assert_eq!(l.changes[0].change_id, id),
            other => panic!("{other:?}"),
        }

        // Same session: refused, nothing burned but the nonce.
        let confirm = Op::ChangeConfirm { change_id: id };
        let r = s
            .request(confirm.clone(), &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(err(r), ErrorCode::PolicyDenied);
        // A session opened before the apply finished: refused too.
        let r = early
            .request(confirm.clone(), &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(err(r), ErrorCode::PolicyDenied);
        assert_eq!(pending_files(fx), 1);

        // A fresh session confirms; both timers are stopped.
        let mut s2 = fx.connect(m).await;
        let r = s2
            .request(confirm.clone(), &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));
        assert_eq!(pending_files(fx), 0);
        let stop = e.timers.lock().unwrap().last().cloned().unwrap();
        assert_eq!(
            stop,
            [
                "/usr/bin/systemctl",
                "stop",
                &format!("fleet-revert-{hex_id}.timer"),
                &format!("fleet-revert-{hex_id}-guard.timer")
            ]
        );
        let r = s2
            .request(confirm, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(err(r), ErrorCode::NotFound);
        assert!(e.log.take().is_empty(), "nothing restored");
    });
}

/// `change.confirm` is in the `firewall` group; the device that made a
/// mesh change may confirm it even where the policy doesn't allow
/// `firewall`, another device may not.
#[test]
fn confirm_allowed_for_the_device_that_made_the_change() {
    let e = env(r#""system", "mesh""#, false);
    let fx = &e.fx;
    run(async {
        let (m0, m1) = (&fx.macs[0], &fx.macs[1]);
        let mut s = fx.connect(m0).await;
        let r = s
            .request(Op::MeshLeave, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        let id = change_id(&r);
        let confirm = Op::ChangeConfirm { change_id: id };

        let mut other = fx.connect(m1).await;
        let r = other
            .request(confirm.clone(), &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(err(r), ErrorCode::PolicyDenied);

        let mut s2 = fx.connect(m0).await;
        let r = s2
            .request(confirm, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));
        assert_eq!(pending_files(fx), 0);
    });
}

/// An apply that fails is restored at once (and audited through the
/// marker); an auto-revert kind without a snapshot module is `Unsupported`.
#[test]
fn failed_apply_restores_and_missing_module_is_unsupported() {
    let e = env(r#""system", "firewall", "users""#, true);
    let fx = &e.fx;
    run(async {
        let m = &fx.macs[0];
        let mut s = fx.connect(m).await;
        let cmd = s
            .build_command(fw(), &fx.server, Actor::Human, None, &with_ev(Some(1)))
            .unwrap();
        assert_eq!(err(s.send(&cmd).await.unwrap()), ErrorCode::Internal);
        assert_eq!(
            e.log.take(),
            ["snapshot firewall.apply", "restore firewall.apply"]
        );
        assert_eq!(pending_files(fx), 0);
        let cmds = e.timers.lock().unwrap().clone();
        assert_eq!(cmds.len(), 2, "guard armed, then stopped: {cmds:?}");

        // No snapshot module for authorized keys (and no handler either).
        let op = Op::AuthorizedKeysSet {
            user: fleet_proto::args::UserName::new("ops").unwrap(),
            keys: vec![],
        };
        let approval = fx.approve_ev(m, &op, Some(1));
        let cmd = s
            .build_command(
                op,
                &fx.server,
                Actor::Human,
                Some(approval),
                &with_ev(Some(1)),
            )
            .unwrap();
        assert_eq!(err(s.send(&cmd).await.unwrap()), ErrorCode::Unsupported);
        assert_eq!(pending_files(fx), 0);
    });
}

/// An apply that outlives `apply_timeout` is abandoned and restored.
#[test]
fn apply_timeout_restores() {
    let e = env_with(
        r#""system", "firewall""#,
        false,
        Duration::from_secs(5),
        Duration::from_millis(200),
    );
    let fx = &e.fx;
    run(async {
        let mut s = fx.connect(&fx.macs[0]).await;
        let cmd = s
            .build_command(fw(), &fx.server, Actor::Human, None, &with_ev(Some(1)))
            .unwrap();
        assert_eq!(err(s.send(&cmd).await.unwrap()), ErrorCode::Timeout);
        assert_eq!(
            e.log.take(),
            ["snapshot firewall.apply", "restore firewall.apply"]
        );
        assert_eq!(pending_files(fx), 0);
    });
}

/// While a change is applying: confirming it is `Busy`, another change of
/// its kind is `Busy`, and an identical
/// re-forward of the command waits for the original answer instead of a
/// signed `Replay`.
#[test]
fn in_flight_change_is_protected() {
    let e = env_with(
        r#""system", "firewall""#,
        false,
        Duration::from_millis(1500),
        Duration::from_secs(30),
    );
    let fx = &e.fx;
    run(async {
        let m = &fx.macs[0];
        let (mut s, mut s2, mut s3) = (
            fx.connect(m).await,
            fx.connect(m).await,
            fx.connect(m).await,
        );
        let cmd = s
            .build_command(fw(), &fx.server, Actor::Human, None, &with_ev(Some(1)))
            .unwrap();
        let apply = s.send(&cmd);
        let again = async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            s3.send(&cmd).await.unwrap()
        };
        let other = async {
            tokio::time::sleep(Duration::from_millis(400)).await;
            let r = s2
                .request(Op::ChangesList, &fx.server, Actor::Human, None)
                .await
                .unwrap();
            let Ok(Payload::PendingChanges(l)) = r.result else {
                panic!("{r:?}")
            };
            let id = l.changes[0].change_id;
            let confirm = Op::ChangeConfirm { change_id: id };
            let r = s2
                .request(confirm, &fx.server, Actor::Human, None)
                .await
                .unwrap();
            assert_eq!(err(r), ErrorCode::Busy);
            let cmd2 = s2
                .build_command(fw(), &fx.server, Actor::Human, None, &with_ev(Some(2)))
                .unwrap();
            assert_eq!(err(s2.send(&cmd2).await.unwrap()), ErrorCode::Busy);
            id
        };
        let (first, second, id) = tokio::join!(apply, again, other);
        let first = first.unwrap();
        assert_eq!(change_id(&first), id);
        // The re-forward got the very same answer and receipt.
        assert_eq!(second.result, first.result);
        assert_eq!(second.receipt, first.receipt);
        assert_eq!(pending_files(fx), 1);
    });
}
