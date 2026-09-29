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
use fleet_core::ssh::{HostKey, P256SshSigner, SshTarget};
use fleet_crypto::roster::sign_root;
use fleet_crypto::sig::Ed25519Signer;
use fleet_it::{ADMIN, Container, Mac, policy_toml};
use fleet_proto::{FleetId, Roster, ServerId};
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
            devices: vec![mac.entry("Mac A")],
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
    let outcome = rt.block_on(async {
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
                    artifact: &art,
                    genesis: &genesis,
                    policy_toml: &policy,
                },
                &ssh,
                &mut progress,
            ),
        )
        .await
    });
    let outcome = outcome.expect("install hung past 240 s");
    log(&format!("install finished: ok={}", outcome.is_ok()));
    match install::ArtifactKind::of(&art) {
        install::ArtifactKind::Deb => {
            outcome.expect("deb install");
            let st = c
                .exec(&["systemctl", "is-active", "fleet-exec", "fleet-gate"])
                .unwrap();
            assert_eq!(st.split_whitespace().collect::<Vec<_>>(), ["active", "active"]);
        }
        install::ArtifactKind::Binary => match outcome {
            // Package already present in the image: works.
            Ok(_) => {}
            Err(e) => {
                // Bare binary without the package: a clear, fast error.
                assert!(
                    matches!(e, InstallError::Remote { .. }),
                    "unexpected error: {e}"
                );
                log(&format!("bare binary refused: {e}"));
            }
        },
    }
}
