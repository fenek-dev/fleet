//! App-side agent install (design §10.1) against a fresh container with no
//! agent: `probe` → pin host key → `install_agent`, exactly what the Mac
//! app's Add server sheet does, with per-step timing on stderr.
//!
//! ```sh
//! FLEET_IT_INSTALL_ARTIFACT=$(tests/vm/agent-artifact.sh --deb-only | tail -1) \
//!   cargo test -p fleet-it --test install --locked -- --ignored --nocapture
//! ```
//!
//! `FLEET_IT_INSTALL_ARTIFACT`: a `.deb` (package: users, units) or a bare
//! static binary (default `target/linux/<arch>/fleet-agent`). A bare binary
//! on a server without the package must fail fast with a clear error.
//! `FLEET_IT_IMAGE` picks the distro image.

use fleet_core::install::{self, InstallError, InstallRequest, InstallStage};
use fleet_core::signer::{KeyRole, RoleSigner};
use fleet_core::ssh::{HostKey, P256SshSigner, SshConnection, SshTarget};
use fleet_crypto::roster::sign_root;
use fleet_crypto::sig::Ed25519Signer;
use fleet_it::{ADMIN, Container, Mac, policy_toml};
use fleet_core::{CommandSigner, Session, SessionConfig, SessionMode};
use fleet_proto::{Actor, FleetId, KeyKind, Op, Payload, Roster, ServerId};
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn artifact() -> PathBuf {
    std::env::var_os("FLEET_IT_INSTALL_ARTIFACT").map_or_else(
        || {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("target/linux")
                .join(std::env::consts::ARCH)
                .join("fleet-agent")
        },
        PathBuf::from,
    )
}

#[test]
#[ignore = "needs Docker; see the module docs"]
fn app_install_on_fresh_server() {
    let t0 = Instant::now();
    let log = |s: &str| eprintln!("[{:>6.1}s] {s}", t0.elapsed().as_secs_f32());
    let image = std::env::var("FLEET_IT_IMAGE").unwrap_or_else(|_| "fleet-it:debian12".into());
    let c = Container::start(&image).expect("container");
    log("container up");
    let mac = Mac::generate().unwrap();
    let mac_b = Mac::generate().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ak = dir.path().join("authorized_keys");
    std::fs::write(&ak, format!("{} it\n", mac.ssh_public().unwrap())).unwrap();
    // /tmp is a tmpfs in the container: `docker cp` can't target it.
    c.cp_into(&ak, "/root/ak").unwrap();
    c.exec(&[
        "sh",
        "-c",
        "install -m 0600 -o ops -g ops /root/ak /home/ops/.ssh/authorized_keys",
    ])
    .unwrap();
    // As the app pool's servers: passwordless sudo for the admin user.
    c.exec(&[
        "sh",
        "-c",
        "echo 'ops ALL=(ALL) NOPASSWD:ALL' >/etc/sudoers.d/fleet-pool && chmod 0440 /etc/sudoers.d/fleet-pool",
    ])
    .unwrap();
    let pubs = c
        .exec(&["sh", "-c", "cat /etc/ssh/ssh_host_*_key.pub"])
        .unwrap();
    let known: Vec<HostKey> = pubs
        .lines()
        .filter_map(|l| HostKey::from_openssh(l).ok())
        .collect();

    let mut fid = [0u8; 16];
    fleet_crypto::random_bytes(&mut fid).unwrap();
    let fleet = FleetId(fid);
    let recovery = Ed25519Signer::generate().unwrap();
    let recovery_ssh = Ed25519Signer::generate().unwrap();
    let escrow = fleet_crypto::noise::StaticKeypair::generate().unwrap();
    let genesis = sign_root(
        Roster {
            fleet_id: fleet,
            epoch: 0,
            version: 1,
            prev_hash: [0; 32],
            issued_at_ms: fleet_core::now_ms(),
            devices: vec![
                mac.entry_with_monitor_ssh("Mac A"),
                mac_b.entry_with_monitor_ssh("Mac B"),
            ],
            recovery_key: recovery.public(),
            recovery_ssh_key: recovery_ssh.public(),
            recovery_escrow_key: escrow.public(),
            recovery_delay_s: 0,
            prev_recovery: None,
        },
        mac.id,
        &mac.keys.root,
    )
    .unwrap();
    let server = ServerId::new("srv_itest02").unwrap();
    let policy = policy_toml(fleet, 1).replace("srv_itest01", "srv_itest02");
    let target = SshTarget::new("127.0.0.1", c.ssh_port, ADMIN);
    let art = artifact();
    assert!(art.is_file(), "artifact {} missing", art.display());

    let rt = fleet_it::runtime();
    let attempt = || rt.block_on(async {
        let role = RoleSigner::new(&mac.keys, KeyRole::Ssh).unwrap();
        let ssh = P256SshSigner(role);
        let mut obs = None;
        for _ in 0..20 {
            match install::probe(&target, &ssh).await {
                Ok(o) => {
                    obs = Some(o);
                    break;
                }
                Err(e) => {
                    log(&format!("probe retry: {e}"));
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
        let obs = obs.expect("probe");
        assert!(known.contains(&obs.key), "unexpected host key");
        log("probe ok (host key matches the container's)");
        let mut progress = |s: InstallStage| match s {
            InstallStage::Uploading { done, total } if done != total => {}
            s => log(&format!("stage {s:?}")),
        };
        tokio::time::timeout(
            Duration::from_secs(240),
            install::install_agent(
                InstallRequest {
                    server_id: &server,
                    target: &target,
                    host_key: obs.key.clone(),
                    admin_user: ADMIN,
                    artifact: install::ArtifactSource::File(&art),
                    bundled_pins: &Default::default(),
                    genesis: &genesis,
                    policy_toml: &policy,
                },
                &ssh,
                &mut progress,
            ),
        )
        .await
    });
    let outcome = attempt().expect("install hung past 240 s");
    log(&format!("install finished: ok={}", outcome.is_ok()));
    let installed = match install::ArtifactKind::of(&art) {
        install::ArtifactKind::Deb => outcome.expect("deb install"),
        install::ArtifactKind::Binary => {
            // Fresh server without the package: refused before any upload.
            let e = outcome.expect_err("bare binary must be refused without the package");
            assert!(matches!(e, InstallError::NeedsPackage), "unexpected error: {e}");
            log(&format!("bare binary refused: {e}"));
            // What the package provides (users, units), plus a noexec /tmp
            // like CIS-hardened servers: the binary must run from
            // /usr/lib/fleet instead.
            let units = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packaging/systemd");
            for (f, to) in [
                ("fleet-exec.service", "/etc/systemd/system/fleet-exec.service"),
                ("fleet-gate.service", "/etc/systemd/system/fleet-gate.service"),
                ("tmpfiles.d/fleet.conf", "/usr/lib/tmpfiles.d/fleet.conf"),
            ] {
                c.cp_into(&units.join(f), "/root/unit.tmp").unwrap();
                c.exec(&["install", "-m", "0644", "/root/unit.tmp", to]).unwrap();
            }
            c.exec(&["sh", "-c", "getent group fleet >/dev/null || groupadd --system fleet"])
                .unwrap();
            c.exec(&[
                "sh",
                "-c",
                "getent passwd fleet-gate >/dev/null || useradd --system --user-group \
                 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin fleet-gate",
            ])
            .unwrap();
            c.exec(&["mount", "-o", "remount,noexec", "/tmp"]).unwrap();
            attempt()
                .expect("install hung past 240 s")
                .expect("bare binary install with the package's users and units")
        }
    };
    let st = c
        .exec(&["systemctl", "is-active", "fleet-exec", "fleet-gate"])
        .unwrap();
    assert_eq!(st.split_whitespace().collect::<Vec<_>>(), ["active", "active"]);

    // A fresh SSH connection (new login: carries group `fleet`), a Noise
    // session with the pinned agent keys and a signed `agent.health`, as
    // the app does after install.
    rt.block_on(async {
        let ssh = P256SshSigner(RoleSigner::new(&mac.keys, KeyRole::Ssh).unwrap());
        let obs = install::probe(&target, &ssh).await.expect("probe");
        let (conn, _) = fleet_core::ssh::SshConnection::connect(&target, &ssh, Some(obs.key.clone()))
            .await
            .expect("fresh ssh connection");
        let groups = conn
            .exec_capture("/usr/bin/id -nG", 4096, Duration::from_secs(15))
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&groups.stdout)
                .split_whitespace()
                .any(|g| g == "fleet"),
            "admin not in group fleet: {:?}",
            String::from_utf8_lossy(&groups.stdout)
        );
        // The units were just started: the gate may not have bound
        // agent.sock yet (the app's wait_ready retries the same way).
        let mut s = None;
        let mut last = String::new();
        for _ in 0..30 {
            let stream =
                tokio::time::timeout(Duration::from_secs(30), conn.open_agent_channel(false))
                    .await
                    .expect("agent channel timed out")
                    .expect("agent channel");
            let cfg = SessionConfig {
                mode: SessionMode::Normal,
                noise: &mac.noise,
                pinned_agent_noise: installed.noise_static,
                pinned_agent_signing: installed.signing_key,
                fleet_id: fleet,
                server_id: server.clone(),
                device_id: mac.id,
                key: KeyKind::Device,
                signer: CommandSigner::P256(&mac.keys.device),
            };
            match tokio::time::timeout(Duration::from_secs(30), Session::connect_bridged(stream, cfg))
                .await
                .expect("session setup timed out")
            {
                Ok(x) => {
                    s = Some(x);
                    break;
                }
                Err(e) => {
                    last = e.to_string();
                    log(&format!("session retry: {last}"));
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
        let mut s = s.unwrap_or_else(|| panic!("noise session: {last}"));
        let reply = tokio::time::timeout(
            Duration::from_secs(30),
            s.request(Op::AgentHealth, &server, Actor::Human, None),
        )
        .await
        .expect("agent.health timed out")
        .expect("agent.health");
        assert!(matches!(reply.result, Ok(Payload::AgentHealth(_))), "{:?}", reply.result);

        // Monitor sessions (locked app): sshd still reads ~/.ssh, so the
        // install put both Macs' forced-command monitor lines there.
        let home_keys = || c.exec(&["cat", "/home/ops/.ssh/authorized_keys"]).unwrap();
        let before = home_keys();
        let marker = |m: &Mac| format!("fleet-monitor-{}", m.id);
        for m in [&mac, &mac_b] {
            assert!(before.contains(&marker(m)), "no monitor line for {}:\n{before}", m.id);
        }
        assert!(
            before.lines().any(|l| l.contains(&marker(&mac))
                && l.starts_with("restrict,command=\"/usr/lib/fleet/fleet-agent bridge --monitor\"")),
            "{before}"
        );
        assert!(before.contains(&mac.ssh_public().unwrap()), "device key line kept");
        {
            let mon_ssh = P256SshSigner(RoleSigner::new(&mac.keys, KeyRole::MonitorSsh).unwrap());
            let (mconn, _) = SshConnection::connect(&target, &mon_ssh, Some(obs.key.clone()))
                .await
                .expect("monitor SSH key authenticates");
            let stream = mconn
                .open_agent_channel_mode(SessionMode::Monitor)
                .await
                .expect("monitor bridge");
            let cfg = SessionConfig {
                mode: SessionMode::Monitor,
                noise: &mac.noise,
                pinned_agent_noise: installed.noise_static,
                pinned_agent_signing: installed.signing_key,
                fleet_id: fleet,
                server_id: server.clone(),
                device_id: mac.id,
                key: KeyKind::Monitor,
                signer: CommandSigner::P256(&mac.keys.monitor),
            };
            let mut ms = tokio::time::timeout(
                Duration::from_secs(30),
                Session::connect_bridged(stream, cfg),
            )
            .await
            .expect("monitor session timed out")
            .expect("monitor session");
            let r = ms
                .request(Op::AgentHealth, &server, Actor::Human, None)
                .await
                .expect("monitor agent.health");
            assert!(matches!(r.result, Ok(Payload::AgentHealth(_))), "{:?}", r.result);
            mconn.disconnect().await;
        }

        // Revoking Mac B removes its monitor line (exec syncs on roster
        // changes) and keeps Mac A's.
        let mut next = genesis.roster.clone();
        next.version += 1;
        next.prev_hash = fleet_crypto::roster::roster_hash(&genesis);
        next.issued_at_ms = fleet_core::now_ms();
        next.devices.retain(|d| d.id != mac_b.id);
        let next = sign_root(next, mac.id, &mac.keys.root).unwrap();
        let r = s
            .request(
                Op::RosterUpdate { roster: Box::new(next) },
                &server,
                Actor::Human,
                None,
            )
            .await
            .expect("roster.update");
        assert_eq!(r.result, Ok(Payload::Empty));
        let deadline = Instant::now() + Duration::from_secs(40);
        loop {
            let now = home_keys();
            if !now.contains(&marker(&mac_b)) {
                assert!(now.contains(&marker(&mac)), "Mac A's monitor line kept:\n{now}");
                break;
            }
            assert!(Instant::now() < deadline, "monitor line of Mac B not removed:\n{now}");
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        conn.disconnect().await;
    });
    log("fresh ssh + noise session + signed agent.health ok");
}
