//! Agent lifecycle over the real pipeline (design §10.2, §10.3): signed
//! update stage → commit (auto-revert, restart scheduled) → confirm from a
//! fresh session → manual rollback; an unconfirmed update restored by its
//! timer's `revert <id>`; uninstall prepare → confirm → uninstall.
//! Binaries are fake files under the test root; `systemctl`/`systemd-run`
//! are recorded, never run.

use super::*;
use fleet_agent::paths::{AGENT_PREV_BIN, SYSTEMCTL, SYSTEMD_RUN};
use fleet_agent::revert::{self, RegistryRevert, RevertOutcome};
use fleet_agent::userkeys::UserKeysMode;
use fleet_crypto::release::sign_release;
use fleet_proto::payload::ChangeKind as WireKind;
use fleet_proto::{AgentTarget, ReleaseManifest, SignedReleaseManifest};
use std::rc::Rc;

struct Env {
    fx: Fixture,
    /// Revert timers (`cfg.timers`).
    timers: Timers,
    /// Everything else exec runs (`cfg.ctx.runner`).
    cmds: Timers,
}

fn recorder_ctx(t: &Timers) -> fleet_ops::SysCtx {
    fleet_ops::SysCtx::new(
        "/",
        Rc::new(SharedRecorder(t.clone())),
        Rc::new(fleet_ops::SystemClock),
    )
}

fn env() -> Env {
    let mut fx = Fixture::new(1, 0);
    let (timers, cmds): (Timers, Timers) = Default::default();
    fx.exec = None;
    let (t, c, p) = (timers.clone(), cmds.clone(), fx.paths.clone());
    fx.start_exec_with(move |cfg| {
        cfg.timers = Rc::new(SharedRecorder(t));
        cfg.ctx = recorder_ctx(&c);
        cfg.user_keys = UserKeysMode::Direct;
        cfg.reverters = revert::agent_reverters(&p, UserKeysMode::Direct);
        cfg.reverter = Box::new(RegistryRevert::new(
            revert::agent_reverters(&p, UserKeysMode::Direct),
            recorder_ctx(&c),
        ));
    });
    std::fs::create_dir_all(fx.paths.agent_bin.parent().unwrap()).unwrap();
    std::fs::write(&fx.paths.agent_bin, b"build-A").unwrap();
    Env { fx, timers, cmds }
}

fn newer() -> AgentVersion {
    AgentVersion {
        major: 99,
        minor: 0,
        patch: 0,
    }
}

fn manifest(mac: &Mac, bytes: &[u8], version: AgentVersion) -> SignedReleaseManifest {
    sign_release(
        ReleaseManifest {
            version,
            blake3: fleet_crypto::blake3(bytes),
            min_proto: 1,
            target: AgentTarget::current().unwrap(),
        },
        mac.id,
        &mac.root,
    )
    .unwrap()
}

fn upload(fx: &Fixture, bytes: &[u8]) {
    let h = fleet_crypto::blake3(bytes);
    std::fs::write(fx.paths.incoming_dir.join(hex::encode(h)), bytes).unwrap();
}

fn stage_op(m: &SignedReleaseManifest) -> Op {
    Op::AgentUpdateStage {
        manifest: Box::new(m.clone()),
        staged_path_hash: m.manifest.blake3,
    }
}

fn has(cmds: &Timers, program: &str, needle: &str) -> bool {
    cmds.lock()
        .unwrap()
        .iter()
        .any(|c| c[0] == program && c.iter().any(|a| a == needle))
}

/// Stage + commit `bytes` as [`newer`]; returns the pending change id.
async fn stage_and_commit(fx: &Fixture, s: &mut Session<'_, UnixStream>, bytes: &[u8]) -> [u8; 16] {
    let m = &fx.macs[0];
    upload(fx, bytes);
    let man = manifest(m, bytes, newer());
    let r = s
        .request(stage_op(&man), &fx.server, Actor::Human, None)
        .await
        .unwrap();
    assert_eq!(r.result, Ok(Payload::Empty), "stage");
    let commit = Op::AgentUpdateCommit { version: newer() };
    let r = s
        .request(
            commit.clone(),
            &fx.server,
            Actor::Human,
            Some(fx.approve(m, &commit)),
        )
        .await
        .unwrap();
    let Ok(Payload::ChangePending { change, .. }) = &r.result else {
        panic!("{r:?}")
    };
    assert_eq!(change.kind, WireKind::AgentUpdate);
    change.change_id
}

#[test]
fn update_stage_commit_confirm_then_manual_rollback() {
    let e = env();
    let fx = &e.fx;
    run(async {
        let m = &fx.macs[0];
        let mut s = fx.connect(m).await;

        // Refused: a build signed by a key not in the roster.
        upload(fx, b"build-B");
        let mut forged = manifest(m, b"build-B", newer());
        forged.signature = sign_release(forged.manifest.clone(), m.id, &m.device)
            .unwrap()
            .signature;
        let r = s
            .request(stage_op(&forged), &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(err(r), ErrorCode::SignatureInvalid);
        // Refused: not above the running version.
        let old = manifest(m, b"build-B", fleet_agent::agent_version());
        let r = s
            .request(stage_op(&old), &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert!(matches!(err(r), ErrorCode::VersionConflict { .. }));
        // Commit needs a root approval (stage is self-signed).
        let commit = Op::AgentUpdateCommit { version: newer() };
        let r = s
            .request(commit, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(err(r), ErrorCode::ApprovalRequired);

        let id = stage_and_commit(fx, &mut s, b"build-B").await;
        assert_eq!(std::fs::read(&fx.paths.agent_bin).unwrap(), b"build-B");
        assert_eq!(std::fs::read(&fx.paths.agent_prev_bin).unwrap(), b"build-A");
        // Revert timers run the previous binary, confirm window 30 s after
        // the restart; the restart is scheduled in its own unit.
        let armed = e.timers.lock().unwrap().clone();
        let hex_id = hex::encode(id);
        let confirm_timer = armed
            .iter()
            .find(|a| a.contains(&format!("--unit=fleet-revert-{hex_id}")))
            .unwrap();
        assert!(confirm_timer.contains(&AGENT_PREV_BIN.to_owned()));
        assert!(confirm_timer.contains(&"--on-active=33".to_owned()));
        assert!(has(&e.cmds, SYSTEMD_RUN, SYSTEMCTL));
        assert!(has(&e.cmds, SYSTEMD_RUN, "fleet-exec.service"));

        // Rollback while the update is pending: its timer owns that.
        let rb = Op::AgentUpdateRollback;
        let r = s
            .request(
                rb.clone(),
                &fx.server,
                Actor::Human,
                Some(fx.approve(m, &rb)),
            )
            .await
            .unwrap();
        assert_eq!(err(r), ErrorCode::Busy);

        // Health, then confirm from a fresh session.
        let mut s2 = fx.connect(m).await;
        let r = s2
            .request(Op::AgentHealth, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert!(matches!(r.result, Ok(Payload::AgentHealth(_))));
        let r = s2
            .request(
                Op::ChangeConfirm { change_id: id },
                &fx.server,
                Actor::Human,
                None,
            )
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));

        // Manual rollback to the build the update replaced, once.
        let r = s2
            .request(
                rb.clone(),
                &fx.server,
                Actor::Human,
                Some(fx.approve(m, &rb)),
            )
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));
        assert_eq!(std::fs::read(&fx.paths.agent_bin).unwrap(), b"build-A");
        let r = s2
            .request(
                rb.clone(),
                &fx.server,
                Actor::Human,
                Some(fx.approve(m, &rb)),
            )
            .await
            .unwrap();
        assert_eq!(err(r), ErrorCode::NotFound);
    });
}

#[test]
fn unconfirmed_update_is_restored_by_its_timer() {
    let mut e = env();
    run(async {
        let fx = &e.fx;
        let mut s = fx.connect(&fx.macs[0]).await;
        stage_and_commit(fx, &mut s, b"build-C").await;
    });
    assert_eq!(std::fs::read(&e.fx.paths.agent_bin).unwrap(), b"build-C");
    // Exec restarts (the new build's first start): the confirm timer is
    // re-armed with the previous binary.
    e.fx.restart_exec();
    let dir = PendingDir::from_paths(&e.fx.paths);
    let (id, _) = dir.list().unwrap().remove(0);
    // What the timer's `fleet-agent.prev revert <id>` does.
    let cmds: Timers = Default::default();
    let reverter = RegistryRevert::new(
        revert::agent_reverters(&e.fx.paths, UserKeysMode::Direct),
        recorder_ctx(&cmds),
    );
    assert_eq!(
        revert::run_revert(&dir, id, &reverter, now_ms()).unwrap(),
        RevertOutcome::Reverted
    );
    assert_eq!(std::fs::read(&e.fx.paths.agent_bin).unwrap(), b"build-A");
    assert!(has(&cmds, SYSTEMCTL, "reset-failed"));
    assert!(has(&cmds, SYSTEMCTL, "--no-block"));
    assert!(dir.list().unwrap().is_empty());
}

#[test]
fn uninstall_prepare_confirm_then_schedule() {
    let e = env();
    let fx = &e.fx;
    let home = fx.paths.root.join("home/admin");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        &fx.paths.passwd,
        format!("admin:x:1000:1000::{}:/bin/bash\n", home.display()),
    )
    .unwrap();
    let conf = fleet_agent::uninstall::host(&fx.paths, fleet_agent::uninstall::FLEET_SSHD_CONFS[0]);
    std::fs::create_dir_all(conf.parent().unwrap()).unwrap();
    std::fs::write(
        &conf,
        "PasswordAuthentication no\nAuthorizedKeysFile /etc/fleet/authorized_keys/%u\n",
    )
    .unwrap();
    run(async {
        let m = &fx.macs[0];
        let mut s = fx.connect(m).await;
        let un = Op::AgentUninstall {
            keep_audit: true,
            remove_firewall: false,
        };
        // Not before SSH works without Fleet's key files.
        let r = s
            .request(
                un.clone(),
                &fx.server,
                Actor::Human,
                Some(fx.approve(m, &un)),
            )
            .await
            .unwrap();
        assert_eq!(err(r), ErrorCode::PolicyDenied);

        let prep = Op::AgentUninstallPrepare;
        let r = s
            .request(
                prep.clone(),
                &fx.server,
                Actor::Human,
                Some(fx.approve(m, &prep)),
            )
            .await
            .unwrap();
        let Ok(Payload::ChangePending { change, .. }) = &r.result else {
            panic!("{r:?}")
        };
        assert_eq!(change.kind, WireKind::Ssh);
        let keys = std::fs::read_to_string(home.join(".ssh/authorized_keys")).unwrap();
        assert!(keys.contains("fleet-device-"), "{keys}");
        assert!(!keys.contains("command="), "{keys}");
        assert!(
            !std::fs::read_to_string(&conf)
                .unwrap()
                .contains("AuthorizedKeysFile")
        );
        assert!(has(&e.cmds, "/usr/sbin/sshd", "-t"));

        // Pending: uninstall waits for the confirmation.
        let r = s
            .request(
                un.clone(),
                &fx.server,
                Actor::Human,
                Some(fx.approve(m, &un)),
            )
            .await
            .unwrap();
        assert_eq!(err(r), ErrorCode::Busy);
        let mut s2 = fx.connect(m).await;
        let r = s2
            .request(
                Op::ChangeConfirm {
                    change_id: change.change_id,
                },
                &fx.server,
                Actor::Human,
                None,
            )
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));
        let r = s2
            .request(
                un.clone(),
                &fx.server,
                Actor::Human,
                Some(fx.approve(m, &un)),
            )
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));
        assert!(has(&e.cmds, SYSTEMD_RUN, "--ssh-restored"));
        assert!(has(&e.cmds, SYSTEMD_RUN, "--keep-audit"));
    });
}
