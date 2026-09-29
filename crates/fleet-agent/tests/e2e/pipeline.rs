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
            Ok(OpOutput::Payload(if matches!(op, Op::MeshLeave) {
                // A handler's own result: exec returns it inside the
                // `ChangePending` (like `ProfileApplied`).
                Payload::RconOutput {
                    text: "left".into(),
                }
            } else if op.auto_revert() {
                Payload::ChangePending {
                    change: payload::PendingChange {
                        change_id: [0; 16],
                        kind: WireKind::Network,
                        op_tag: 0,
                        created_ms: 0,
                        deadline_ms: 0,
                        new_version: Some(8),
                    },
                    inner: None,
                }
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
    env_full(
        groups,
        fail,
        delay,
        apply_timeout,
        Pol::default().security,
        None,
    )
}

/// Stands in for systemd where the reboot ops run: remembers the armed
/// `fleet-reboot` timer's description and answers `systemctl show` and
/// `date +%z` from it.
#[derive(Default)]
struct RebootSim {
    armed: Option<String>,
    calls: Vec<Vec<String>>,
}

type Sim = Arc<Mutex<RebootSim>>;

struct SimRunner(Sim);

impl CommandRunner for SimRunner {
    fn run(&self, spec: CommandSpec) -> LocalBoxFuture<'_, Result<CommandOutput, RunError>> {
        Box::pin(std::future::ready(self.run_blocking(spec)))
    }
    fn run_blocking(&self, spec: CommandSpec) -> Result<CommandOutput, RunError> {
        let mut argv = vec![spec.program.to_owned()];
        argv.extend(spec.args.iter().map(|a| a.to_string_lossy().into_owned()));
        let mut sim = self.0.lock().unwrap();
        sim.calls.push(argv.clone());
        let out = match (spec.program, argv.get(1).map(String::as_str)) {
            ("/usr/bin/systemd-run", _) => {
                sim.armed = argv
                    .iter()
                    .find_map(|a| a.strip_prefix("--description=").map(str::to_owned));
                String::new()
            }
            ("/usr/bin/systemctl", Some("stop")) => {
                sim.armed = None;
                String::new()
            }
            ("/usr/bin/systemctl", Some("show")) => match &sim.armed {
                Some(d) => format!("ActiveState=active\nDescription={d}\n"),
                None => "ActiveState=inactive\nDescription=fleet-reboot.timer\n".into(),
            },
            ("/usr/bin/date", _) => "+0100\n".into(),
            ("/usr/sbin/nft", _) => r#"{"nftables": []}"#.into(),
            _ => String::new(),
        };
        Ok(CommandOutput::ok(out))
    }
}

fn env_full(
    groups: &'static str,
    fail: bool,
    delay: Duration,
    apply_timeout: Duration,
    security: &'static str,
    sim: Option<Sim>,
) -> Env {
    let mut fx = Fixture::with(
        2,
        0,
        Opts {
            pol: Pol {
                groups,
                security,
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
        cfg.profile_apply_timeout = apply_timeout;
        for tag in [
            tag::COMPOSE_DEPLOY,
            tag::FIREWALL_APPLY,
            tag::MESH_LEAVE,
            tag::PROFILE_APPLY,
        ] {
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
        if let Some(sim) = sim {
            cfg.ctx.runner = Rc::new(SimRunner(sim));
        }
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
        Ok(Payload::ChangePending { change: p, .. }) => p.change_id,
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
        let Ok(Payload::ChangePending { change: p, inner }) = &r.result else {
            panic!("{r:?}")
        };
        assert_eq!(
            (p.kind, p.op_tag, p.new_version),
            (WireKind::Firewall, tag::FIREWALL_APPLY, Some(8))
        );
        assert_eq!(inner, &None);
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

/// Switching Managed → Agent-only (design §5.4) while a firewall change is
/// still pending confirmation is refused `Busy`, before the nonce is
/// consumed: it must not race an in-flight security-relevant change.
#[test]
fn policy_update_to_agent_only_refused_busy_while_security_change_pending() {
    let e = env(r#""system", "firewall""#, false);
    let fx = &e.fx;
    run(async {
        let m = &fx.macs[0];
        let mut s = fx.connect(m).await;
        let cmd = s
            .build_command(fw(), &fx.server, Actor::Human, None, &with_ev(Some(7)))
            .unwrap();
        let r = s.send(&cmd).await.unwrap();
        assert!(matches!(r.result, Ok(Payload::ChangePending { .. })), "{r:?}");
        assert_eq!(pending_files(fx), 1);

        let policy_op = Op::PolicyUpdate {
            policy_toml: policy_toml(
                fx.fleet,
                2,
                Pol {
                    groups: r#""system", "firewall""#,
                    security: "agent-only",
                    ..Pol::default()
                },
            ),
        };
        let approval = fx.approve(m, &policy_op);
        let cmd2 = s
            .build_command(
                policy_op,
                &fx.server,
                Actor::Human,
                Some(approval),
                &CommandOpts::default(),
            )
            .unwrap();
        assert_eq!(err(s.send(&cmd2).await.unwrap()), ErrorCode::Busy);
        // Not burned: the identical resend is still `Busy`, never `Replay`.
        assert_eq!(err(s.send(&cmd2).await.unwrap()), ErrorCode::Busy);
    });
}

/// The System profile phase claims no `ChangeKind` (it isn't auto-revert),
/// so `kind_busy` alone can't see it running — `Exec::security_ops` is
/// what makes a Managed → Agent-only switch refuse `Busy` while it's still
/// in flight (design §5.4).
#[test]
fn policy_update_to_agent_only_refused_busy_while_a_non_revertible_security_op_runs() {
    use fleet_proto::op::ProfilePhase;
    let e = env_with(
        r#""system", "profile""#,
        false,
        Duration::from_millis(1500),
        Duration::from_secs(30),
    );
    let fx = &e.fx;
    run(async {
        let m = &fx.macs[0];
        let (mut s, mut s2) = (fx.connect(m).await, fx.connect(m).await);
        let apply = s.request(
            profile_apply(ProfilePhase::System),
            &fx.server,
            Actor::Human,
            None,
        );
        let switch = async {
            tokio::time::sleep(Duration::from_millis(400)).await;
            let policy_op = Op::PolicyUpdate {
                policy_toml: policy_toml(
                    fx.fleet,
                    2,
                    Pol {
                        groups: r#""system", "profile""#,
                        security: "agent-only",
                        ..Pol::default()
                    },
                ),
            };
            let approval = fx.approve(m, &policy_op);
            let busy = s2
                .request(policy_op.clone(), &fx.server, Actor::Human, Some(approval.clone()))
                .await
                .unwrap();
            assert_eq!(err(busy), ErrorCode::Busy);
            (policy_op, approval)
        };
        let (apply_r, (policy_op, approval)) = tokio::join!(apply, switch);
        assert_eq!(apply_r.unwrap().result, Ok(Payload::Empty));

        // Finished now: the identical switch goes through.
        let r = s2
            .request(policy_op, &fx.server, Actor::Human, Some(approval))
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));
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
        // The handler's result comes back inside the pending change.
        let Ok(Payload::ChangePending { change, inner }) = &r.result else {
            panic!("{r:?}")
        };
        assert_eq!((change.kind, change.new_version), (WireKind::Mesh, None));
        assert_eq!(
            inner.as_deref(),
            Some(&Payload::RconOutput {
                text: "left".into()
            })
        );
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

fn profile_apply(phase: fleet_proto::op::ProfilePhase) -> Op {
    Op::ProfileApply {
        spec: fleet_proto::op::ProfileSpec {
            source: fleet_proto::op::ProfileSource::Builtin {
                level: fleet_proto::op::ProfileLevel::Baseline,
                roles: vec![],
            },
            only: vec![],
        },
        plan_hash: [0; 32],
        phase,
        password_hash: None,
    }
}

/// `profile.apply` phases: System runs without auto-revert (no snapshot,
/// no pending change, the handler's own answer) under its own timeout;
/// Access goes through auto-revert (here: no profile module, so
/// `Unsupported` before anything runs).
#[test]
fn profile_phases_and_their_timeouts() {
    use fleet_proto::op::ProfilePhase;
    let e = env(r#""system", "profile""#, false);
    let fx = &e.fx;
    run(async {
        let mut s = fx.connect(&fx.macs[0]).await;
        let r = s
            .request(
                profile_apply(ProfilePhase::System),
                &fx.server,
                Actor::Human,
                None,
            )
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));
        assert!(e.log.take().is_empty());
        assert_eq!(pending_files(fx), 0);
        let r = s
            .request(
                profile_apply(ProfilePhase::Access),
                &fx.server,
                Actor::Human,
                None,
            )
            .await
            .unwrap();
        assert_eq!(err(r), ErrorCode::Unsupported);
        assert!(e.log.take().is_empty());
    });
    // A System phase that outlives its timeout is abandoned: `Timeout`,
    // nothing to restore.
    let e = env_with(
        r#""system", "profile""#,
        false,
        Duration::from_secs(5),
        Duration::from_millis(200),
    );
    let fx = &e.fx;
    run(async {
        let mut s = fx.connect(&fx.macs[0]).await;
        let r = s
            .request(
                profile_apply(ProfilePhase::System),
                &fx.server,
                Actor::Human,
                None,
            )
            .await
            .unwrap();
        assert_eq!(err(r), ErrorCode::Timeout);
        assert!(e.log.take().is_empty());
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

/// `change.revert`: the timer's restore, now, over the very session that
/// made the change (a confirm may not). The pending file and both timers
/// are gone, the origin's audit entry closes as `Reverted`, and reverting
/// again is `NotFound`.
#[test]
fn change_revert_restores_now_disarms_timers_and_audits() {
    let e = env(r#""system", "firewall""#, false);
    let fx = &e.fx;
    run(async {
        let m = &fx.macs[0];
        let mut s = fx.connect(m).await;
        let cmd = s
            .build_command(fw(), &fx.server, Actor::Human, None, &with_ev(Some(7)))
            .unwrap();
        let r = s.send(&cmd).await.unwrap();
        let id = change_id(&r);
        let hex_id = hex::encode(id);
        e.log.take();

        let revert = Op::ChangeRevert { change_id: id };
        let r = s
            .request(revert.clone(), &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));
        assert!(r.receipt.receipt.audit_seq.is_some());
        assert_eq!(e.log.take(), ["restore firewall.apply"]);
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
        let r = s
            .request(
                Op::AuditQuery {
                    after_seq: 0,
                    limit: 1000,
                },
                &fx.server,
                Actor::Human,
                None,
            )
            .await
            .unwrap();
        let Ok(Payload::AuditPage(page)) = r.result else {
            panic!("{r:?}")
        };
        assert!(
            page.entries
                .iter()
                .any(|en| en.op.tag == tag::FIREWALL_APPLY
                    && en.result == fleet_proto::ResultSummary::Done(fleet_proto::Outcome::Reverted)),
            "the firewall.apply intent is closed as reverted"
        );

        // Once: the change is gone (a racing timer that got there first
        // leaves the same answer).
        let r = s
            .request(revert, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(err(r), ErrorCode::NotFound);
        assert!(e.log.take().is_empty(), "nothing restored twice");
        // The kind is free again.
        let cmd = s
            .build_command(fw(), &fx.server, Actor::Human, None, &with_ev(Some(8)))
            .unwrap();
        assert!(matches!(
            s.send(&cmd).await.unwrap().result,
            Ok(Payload::ChangePending { .. })
        ));
    });
}

/// `change.revert` is in the `firewall` group, which this policy doesn't
/// allow: only the device that made the change may revert it (like
/// `change.confirm`).
#[test]
fn change_revert_allowed_for_the_device_that_made_the_change() {
    let e = env(r#""system", "mesh""#, false);
    let fx = &e.fx;
    run(async {
        let (m0, m1) = (&fx.macs[0], &fx.macs[1]);
        let mut s = fx.connect(m0).await;
        let r = s
            .request(Op::MeshLeave, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        let revert = Op::ChangeRevert {
            change_id: change_id(&r),
        };
        let mut other = fx.connect(m1).await;
        let r = other
            .request(revert.clone(), &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(err(r), ErrorCode::PolicyDenied);
        assert_eq!(pending_files(fx), 1);
        let r = s
            .request(revert, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));
        assert_eq!(pending_files(fx), 0);
        assert_eq!(e.log.take(), ["snapshot mesh.leave", "restore mesh.leave"]);
    });
}

/// Agent-only mode (design §5.4): `firewall.apply` is refused, but
/// reverting a pending change, `firewall.counters` and the reboot ops are
/// not security takeovers.
#[test]
fn agent_only_allows_revert_counters_and_reboot_ops() {
    let sim: Sim = Arc::default();
    let e = env_full(
        r#""system", "mesh", "firewall""#,
        false,
        Duration::ZERO,
        Duration::from_secs(30),
        "agent-only",
        Some(sim.clone()),
    );
    let fx = &e.fx;
    run(async {
        let m0 = &fx.macs[0];
        let mut s = fx.connect(m0).await;
        let r = s
            .request(Op::MeshLeave, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        let revert = Op::ChangeRevert {
            change_id: change_id(&r),
        };
        let r = s
            .request(revert, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));
        assert_eq!(pending_files(fx), 0);

        // Read-only counters answer (no table: nothing counted).
        let r = s
            .request(Op::FirewallCounters, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert!(matches!(r.result, Ok(Payload::FirewallCounters(_))), "{r:?}");

        // Security takeover: refused before anything else.
        let cmd = s
            .build_command(fw(), &fx.server, Actor::Human, None, &with_ev(Some(7)))
            .unwrap();
        assert_eq!(err(s.send(&cmd).await.unwrap()), ErrorCode::PolicyDenied);

        // Reboot ops work in Agent-only mode.
        let sched = Op::SystemRebootSchedule {
            when: fleet_proto::op::RebootWhen::In { delay_s: 3600 },
        };
        let r = s
            .request(sched, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));
        let status = |r: Reply| match r.result {
            Ok(Payload::RebootStatus(s)) => s.at_ms,
            other => panic!("{other:?}"),
        };
        let r = s
            .request(Op::SystemRebootStatus, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        let at = status(r).expect("armed");
        assert!(at > now_ms() + 3_500_000 && at < now_ms() + 3_700_000, "{at}");
        let r = s
            .request(Op::SystemRebootCancel, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));
        let r = s
            .request(Op::SystemRebootStatus, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(status(r), None);
    });
}

/// Reboot windows in the server's local time (one `date +%z` call), a
/// replaced schedule, and the agent's bounds on `At`.
#[test]
fn reboot_window_and_at_schedule_status_cancel() {
    use fleet_proto::op::RebootWhen;
    let sim: Sim = Arc::default();
    let e = env_full(
        r#""system""#,
        false,
        Duration::ZERO,
        Duration::from_secs(30),
        "managed",
        Some(sim.clone()),
    );
    let fx = &e.fx;
    run(async {
        let mut s = fx.connect(&fx.macs[0]).await;
        let at_of = |r: Reply| match r.result {
            Ok(Payload::RebootStatus(s)) => s.at_ms,
            other => panic!("{other:?}"),
        };
        // A window covering all but the last minute of the local day is
        // (almost surely) open now: the reboot is due within seconds.
        let win = Op::SystemRebootSchedule {
            when: RebootWhen::Window {
                start_min: 0,
                end_min: 1439,
            },
        };
        let r = s
            .request(win, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));
        {
            let calls = sim.lock().unwrap().calls.clone();
            assert!(calls.iter().any(|c| c == &["/usr/bin/date", "+%z"]), "{calls:?}");
        }
        let r = s
            .request(Op::SystemRebootStatus, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        let first = at_of(r).expect("armed");
        assert!(first <= now_ms() + 24 * 3_600_000);

        // A later schedule replaces it.
        let target = now_ms() + 2 * 3_600_000;
        let at = Op::SystemRebootSchedule {
            when: RebootWhen::At { at_ms: target },
        };
        let r = s
            .request(at, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));
        let r = s
            .request(Op::SystemRebootStatus, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        let got = at_of(r).expect("armed");
        assert!(got.abs_diff(target) < 60_000, "{got} vs {target}");

        // In the past or past 30 days: refused, the schedule stays.
        for at_ms in [now_ms() - 60_000, now_ms() + 31 * 86_400_000] {
            let bad = Op::SystemRebootSchedule {
                when: RebootWhen::At { at_ms },
            };
            let r = s
                .request(bad, &fx.server, Actor::Human, None)
                .await
                .unwrap();
            assert_eq!(err(r), ErrorCode::InvalidArgument);
        }
        // Malformed arguments never reach the handler.
        let bad = Op::SystemRebootSchedule {
            when: RebootWhen::Window {
                start_min: 90,
                end_min: 90,
            },
        };
        let r = s
            .request(bad, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(r.receipt.receipt.audit_seq, None);
        assert_eq!(err(r), ErrorCode::InvalidArgument);
        let r = s
            .request(Op::SystemRebootStatus, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert!(at_of(r).is_some());

        // Cancel, twice (idempotent).
        for _ in 0..2 {
            let r = s
                .request(Op::SystemRebootCancel, &fx.server, Actor::Human, None)
                .await
                .unwrap();
            assert_eq!(r.result, Ok(Payload::Empty));
        }
        let r = s
            .request(Op::SystemRebootStatus, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(at_of(r), None);
    });
}
