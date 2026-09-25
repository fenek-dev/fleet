//! Linux integration harness (design §13): the real static `fleet-agent`
//! under systemd in a Docker container, reached from the test process over
//! real SSH → `fleet-agent bridge` → gate → exec, with fleet-core's
//! [`SshConnection`] and [`Session`].
//!
//! One container per test process ([`fixture`], shared through a
//! `OnceLock`). A reaper shell removes it once the test process exits
//! (set `FLEET_IT_KEEP=1` to keep it for debugging). Docker is driven with
//! the `docker` CLI and fixed argument lists; nothing is interpolated into a
//! shell.
//!
//! Inputs (environment, all optional):
//! - `FLEET_IT_IMAGE`: test image (default `fleet-it:debian12`).
//! - `FLEET_IT_AGENT`: agent binary (default
//!   `target/linux/<host arch>/fleet-agent`, see
//!   `scripts/build-agent-linux.sh`).
#![forbid(unsafe_code)]

use fleet_core::signer::{KeyRole, RoleSigner, SoftwareDeviceSigner};
use fleet_core::ssh::{
    AgentStream, HostKey, P256SshSigner, SshConnection, SshPublicKey, SshTarget,
};
use fleet_core::{ClientError, CommandSigner, Session, SessionConfig, SessionMode, now_ms};
use fleet_crypto::noise::{self, Handshake, StaticKeypair, Transport};
use fleet_crypto::roster::{roster_hash, sign_root};
use fleet_crypto::sig::{Ed25519Signer, Signer};
use fleet_proto::chunk::{NOISE_MAX_MSG, Reassembler, split_frame};
use fleet_proto::{
    Actor, BoundedString, CommandBody, Device, DeviceId, Ed25519Public, FleetId, KeyKind, Message,
    Op, PROTO_VERSION, Role, Roster, ServerId, SignedCommand, SignedRoster, X25519Public, decode,
    encode,
};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

pub const SERVER: &str = "srv_itest01";
pub const ADMIN: &str = "ops";
/// Per network step (SSH connect, channel, one request).
pub const STEP: Duration = Duration::from_secs(20);

pub type Res<T> = Result<T, String>;

fn err<E: std::fmt::Display>(ctx: &str) -> impl FnOnce(E) -> String + '_ {
    move |e| format!("{ctx}: {e}")
}

// ---------------------------------------------------------------- docker

/// Runs `docker <args>` with a timeout; returns stdout, or stderr on failure.
pub fn docker(args: &[&str], limit: Duration) -> Res<String> {
    let (ok, out, errs) = docker_raw(args, limit)?;
    if ok {
        Ok(out)
    } else {
        Err(format!("docker {args:?}: {}", errs.trim()))
    }
}

/// Runs `docker <args>` with a timeout: (exit success, stdout, stderr).
pub fn docker_raw(args: &[&str], limit: Duration) -> Res<(bool, String, String)> {
    let mut child = Command::new("docker")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn docker: {e}"))?;
    // Drain both pipes on threads so a chatty command can't block.
    let drain = |p: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut s = String::new();
            if let Some(mut p) = p {
                let _ = p.read_to_string(&mut s);
            }
            s
        })
    };
    let out = drain(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let errs = drain(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
            break s;
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("docker {args:?}: timed out after {limit:?}"));
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let out = out.join().unwrap_or_default();
    let errs = errs.join().unwrap_or_default();
    Ok((status.success(), out, errs))
}

pub struct Container {
    pub name: String,
    pub ssh_port: u16,
}

impl Container {
    /// Starts `image` with systemd as PID 1 and waits for boot to finish.
    pub fn start(image: &str) -> Res<Self> {
        let name = format!("fleet-it-{}-{}", std::process::id(), now_ms() % 1_000_000);
        docker(
            &[
                "run",
                "-d",
                // systemd as PID 1 plus the gate sandbox (namespaces,
                // seccomp, cgroup limits) need a privileged container; a
                // private cgroup namespace gives systemd its own writable
                // cgroup v2 tree on Docker Desktop.
                "--privileged",
                "--cgroupns=private",
                "--tmpfs",
                "/run",
                "--tmpfs",
                "/run/lock",
                "--tmpfs",
                "/tmp",
                "--label",
                "fleet-it=1",
                "-p",
                "127.0.0.1::22",
                "--name",
                &name,
                image,
            ],
            Duration::from_secs(60),
        )?;
        spawn_reaper(&name);
        let port = docker(&["port", &name, "22/tcp"], Duration::from_secs(10))?;
        let ssh_port = port
            .lines()
            .find_map(|l| l.rsplit(':').next()?.trim().parse().ok())
            .ok_or_else(|| format!("no SSH port mapping: {port:?}"))?;
        let c = Container { name, ssh_port };
        // `degraded` (some unit failed) still means boot finished.
        let state = c
            .exec_status(&["systemctl", "is-system-running", "--wait"], 120)
            .1;
        let state = state.trim();
        if state != "running" && state != "degraded" {
            return Err(format!("systemd did not boot: {state:?}"));
        }
        if state == "degraded" {
            let failed = c.exec(&["systemctl", "--failed", "--no-legend", "--plain"])?;
            eprintln!("fleet-it: systemd degraded; failed units:\n{failed}");
        }
        Ok(c)
    }

    /// `docker exec` as root; stdout on success.
    pub fn exec(&self, argv: &[&str]) -> Res<String> {
        let mut args = vec!["exec", self.name.as_str()];
        args.extend_from_slice(argv);
        docker(&args, Duration::from_secs(120))
    }

    /// `docker exec`, returning (exit success, stdout); stdout is kept on a
    /// non-zero exit. A timeout or spawn failure is (false, error text).
    pub fn exec_status(&self, argv: &[&str], secs: u64) -> (bool, String) {
        let mut args = vec!["exec", self.name.as_str()];
        args.extend_from_slice(argv);
        match docker_raw(&args, Duration::from_secs(secs)) {
            Ok((ok, out, _)) => (ok, out),
            Err(e) => (false, e),
        }
    }

    pub fn cp_into(&self, src: &Path, dst: &str) -> Res<()> {
        let src = src.to_str().ok_or("non-UTF-8 path")?;
        let dst = format!("{}:{dst}", self.name);
        docker(&["cp", src, &dst], Duration::from_secs(60)).map(|_| ())
    }

    /// Main PID of a unit (0 when not running).
    pub fn main_pid(&self, unit: &str) -> Res<u32> {
        let out = self.exec(&["systemctl", "show", "-p", "MainPID", "--value", unit])?;
        out.trim().parse().map_err(|_| format!("MainPID: {out:?}"))
    }

    /// `VmRSS` of a unit's main process, in bytes.
    pub fn rss_bytes(&self, unit: &str) -> Res<u64> {
        let pid = self.main_pid(unit)?;
        if pid == 0 {
            return Err(format!("{unit} is not running"));
        }
        let status = self.exec(&["cat", &format!("/proc/{pid}/status")])?;
        status
            .lines()
            .find_map(|l| l.strip_prefix("VmRSS:"))
            .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
            .map(|kb| kb * 1024)
            .ok_or_else(|| "no VmRSS".into())
    }
}

/// Removes the container once this process is gone, however it ends.
fn spawn_reaper(name: &str) {
    if std::env::var_os("FLEET_IT_KEEP").is_some() {
        eprintln!("fleet-it: FLEET_IT_KEEP set, container {name} is kept");
        return;
    }
    const SCRIPT: &str =
        r#"while kill -0 "$1" 2>/dev/null; do sleep 1; done; docker rm -f "$2" >/dev/null 2>&1"#;
    let pid = std::process::id().to_string();
    let _ = Command::new("/bin/sh")
        .args(["-c", SCRIPT, "fleet-it-reaper", &pid, name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

// ---------------------------------------------------------------- identities

/// A test Mac: software keys standing in for the Secure Enclave.
pub struct Mac {
    pub id: DeviceId,
    pub keys: SoftwareDeviceSigner,
    pub noise: StaticKeypair,
}

impl Mac {
    pub fn generate() -> Res<Self> {
        let mut id = [0u8; 16];
        fleet_crypto::random_bytes(&mut id).map_err(|e| e.to_string())?;
        Ok(Self {
            id: DeviceId(id),
            keys: SoftwareDeviceSigner::generate().map_err(|e| e.to_string())?,
            noise: StaticKeypair::generate().map_err(|e| e.to_string())?,
        })
    }

    pub fn entry(&self, name: &str) -> Device {
        Device {
            id: self.id,
            name: BoundedString::new(name).expect("short name"),
            role: Role::Admin,
            root_key: self.keys.root.public(),
            device_key: self.keys.device.public(),
            monitor_key: self.keys.monitor.public(),
            ssh_key: self.keys.ssh.public(),
            noise_static: self.noise.public(),
            added_at: 0,
            added_by: self.id,
        }
    }

    pub fn ssh_public(&self) -> Res<String> {
        SshPublicKey::EcdsaP256(self.keys.ssh.public())
            .to_openssh()
            .map_err(|e| e.to_string())
    }
}

pub fn policy_toml(fleet: FleetId, version: u64) -> String {
    format!(
        r#"version = {version}
fleet_id = "{fleet}"
server_id = "{SERVER}"
[capabilities]
allow = ["system", "logs", "security", "services", "packages"]
shell_exec = false
shell_exec_users = []
[elevated]
extra = []
[actors]
ai = "full"
ai_bulk_confirm_above = 5
ai_commands_per_minute = 60
[limits]
commands_per_minute = 240
max_stream_sessions = 32
[safety]
auto_revert_seconds = 60
"#
    )
}

// ---------------------------------------------------------------- fixture

pub struct Fixture {
    pub container: Container,
    /// `macs[0]` signs the genesis roster and drives most tests;
    /// `macs[1]` is revoked by the revocation test.
    pub macs: [Mac; 2],
    pub fleet: FleetId,
    pub server: ServerId,
    pub genesis: SignedRoster,
    pub agent_noise: X25519Public,
    pub agent_signing: Ed25519Public,
    pub host_key: HostKey,
    /// Main-process RSS right after install, before any session (bytes).
    pub idle_rss: (u64, u64),
    pub os: String,
}

static FIXTURE: OnceLock<Fixture> = OnceLock::new();

/// The shared container with the agent installed and running. Must be
/// called outside a tokio runtime (it runs its own for the host key probe).
pub fn fixture() -> &'static Fixture {
    FIXTURE.get_or_init(|| match Fixture::setup() {
        Ok(f) => f,
        Err(e) => panic!("fleet-it fixture setup failed: {e}"),
    })
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn agent_binary() -> PathBuf {
    std::env::var_os("FLEET_IT_AGENT").map_or_else(
        || {
            repo_root()
                .join("target/linux")
                .join(std::env::consts::ARCH)
                .join("fleet-agent")
        },
        PathBuf::from,
    )
}

impl Fixture {
    fn setup() -> Res<Self> {
        let image = std::env::var("FLEET_IT_IMAGE").unwrap_or_else(|_| "fleet-it:debian12".into());
        let bin = agent_binary();
        if !bin.is_file() {
            return Err(format!(
                "agent binary {} missing: run scripts/build-agent-linux.sh",
                bin.display()
            ));
        }
        let container = Container::start(&image)?;
        let os = container
            .exec(&["sh", "-c", ". /etc/os-release && echo \"$PRETTY_NAME\""])?
            .trim()
            .to_owned();

        let macs = [Mac::generate()?, Mac::generate()?];
        let mut fid = [0u8; 16];
        fleet_crypto::random_bytes(&mut fid).map_err(|e| e.to_string())?;
        let fleet = FleetId(fid);
        let recovery = Ed25519Signer::generate().map_err(|e| e.to_string())?;
        let recovery_ssh = Ed25519Signer::generate().map_err(|e| e.to_string())?;
        let escrow = StaticKeypair::generate().map_err(|e| e.to_string())?;
        let roster = Roster {
            fleet_id: fleet,
            epoch: 0,
            version: 1,
            prev_hash: [0; 32],
            issued_at_ms: now_ms(),
            devices: vec![macs[0].entry("Mac A"), macs[1].entry("Mac B")],
            recovery_key: recovery.public(),
            recovery_ssh_key: recovery_ssh.public(),
            recovery_escrow_key: escrow.public(),
            recovery_delay_s: 0,
            prev_recovery: None,
        };
        let genesis =
            sign_root(roster, macs[0].id, &macs[0].keys.root).map_err(|e| e.to_string())?;
        let server = ServerId::new(SERVER).map_err(|_| "server id")?;

        // Stage everything the install needs, copy it in, run it as root.
        let stage = tempfile::tempdir().map_err(err("tempdir"))?;
        let s = stage.path();
        let copy = |from: &Path, to: &str| {
            std::fs::copy(from, s.join(to)).map_err(|e| format!("{}: {e}", from.display()))
        };
        copy(&bin, "fleet-agent")?;
        let units = repo_root().join("packaging/systemd");
        std::fs::create_dir_all(s.join("systemd/tmpfiles.d")).map_err(err("mkdir"))?;
        copy(
            &units.join("fleet-exec.service"),
            "systemd/fleet-exec.service",
        )?;
        copy(
            &units.join("fleet-gate.service"),
            "systemd/fleet-gate.service",
        )?;
        copy(
            &units.join("tmpfiles.d/fleet.conf"),
            "systemd/tmpfiles.d/fleet.conf",
        )?;
        copy(
            &repo_root().join("tests/vm/docker/install-agent.sh"),
            "install-agent.sh",
        )?;
        let write = |to: &str, data: &[u8]| std::fs::write(s.join(to), data).map_err(err(to));
        write("genesis.hex", hex::encode(encode(&genesis)).as_bytes())?;
        write("policy.toml", policy_toml(fleet, 1).as_bytes())?;
        let mut ak = String::new();
        for (i, m) in macs.iter().enumerate() {
            ak.push_str(&format!("{} fleet-it-mac{i}\n", m.ssh_public()?));
        }
        write("authorized_keys", ak.as_bytes())?;
        container.cp_into(&s.join("."), "/root/fleet-it")?;
        let out = container.exec(&[
            "bash",
            "/root/fleet-it/install-agent.sh",
            "/root/fleet-it",
            SERVER,
            ADMIN,
        ])?;
        let key = |name: &str| -> Res<[u8; 32]> {
            let prefix = format!("{name}=");
            let hexs = out
                .lines()
                .find_map(|l| l.strip_prefix(prefix.as_str()))
                .ok_or_else(|| format!("install printed no {name}: {out:?}"))?;
            hex::decode(hexs.trim())
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| format!("bad {name}"))
        };
        let agent_noise = X25519Public(key("noise_static")?);
        let agent_signing = Ed25519Public(key("signing_key")?);

        // Idle footprint before anything connects; let startup settle.
        std::thread::sleep(Duration::from_secs(3));
        let idle_rss = (
            container.rss_bytes("fleet-gate.service")?,
            container.rss_bytes("fleet-exec.service")?,
        );

        let host_key = probe_host_key(&container, &macs[0])?;
        Ok(Fixture {
            container,
            macs,
            fleet,
            server,
            genesis,
            agent_noise,
            agent_signing,
            host_key,
            idle_rss,
            os,
        })
    }

    pub fn target(&self) -> SshTarget {
        SshTarget::new("127.0.0.1", self.container.ssh_port, ADMIN)
    }

    /// SSH as the admin user with `mac`'s SSH key, host key pinned.
    pub async fn ssh(&self, mac: &Mac) -> Res<SshConnection> {
        ssh_connect(&self.target(), mac, Some(self.host_key.clone())).await
    }

    pub fn cfg<'a>(&'a self, mac: &'a Mac) -> SessionConfig<'a> {
        SessionConfig {
            mode: SessionMode::Normal,
            noise: &mac.noise,
            pinned_agent_noise: self.agent_noise,
            pinned_agent_signing: self.agent_signing,
            fleet_id: self.fleet,
            server_id: self.server.clone(),
            device_id: mac.id,
            key: KeyKind::Device,
            signer: CommandSigner::P256(&mac.keys.device),
        }
    }

    /// Opens the agent channel on `conn` and runs the session setup.
    pub async fn session<'a>(
        &'a self,
        conn: &SshConnection,
        mac: &'a Mac,
    ) -> Res<Result<Session<'a, AgentStream>, ClientError>> {
        let stream = timeout(STEP, conn.open_agent_channel(false))
            .await
            .map_err(|_| "agent channel: timed out")?
            .map_err(err("agent channel"))?;
        timeout(STEP, Session::connect_bridged(stream, self.cfg(mac)))
            .await
            .map_err(|_| "session setup: timed out".into())
    }

    /// Next roster version (removing `drop`), signed by `by`'s root key.
    pub fn roster_without(&self, by: &Mac, drop: &Mac) -> Res<SignedRoster> {
        let mut r = self.genesis.roster.clone();
        r.version += 1;
        r.prev_hash = roster_hash(&self.genesis);
        r.issued_at_ms = now_ms();
        r.devices.retain(|d| d.id != drop.id);
        sign_root(r, by.id, &by.keys.root).map_err(|e| e.to_string())
    }

    /// A device-signed command envelope (for the raw stream client).
    pub fn signed(&self, mac: &Mac, op: Op) -> Res<SignedCommand> {
        let mut nonce = [0u8; 16];
        fleet_crypto::random_bytes(&mut nonce).map_err(|e| e.to_string())?;
        let body = encode(&CommandBody {
            v: PROTO_VERSION,
            fleet_id: self.fleet,
            server_id: self.server.clone(),
            issued_at_ms: now_ms(),
            ttl_ms: 60_000,
            nonce,
            actor: Actor::Human,
            op,
            expected_version: None,
        });
        let msg = SignedCommand::signed_message(KeyKind::Device, &mac.id, &body);
        Ok(SignedCommand {
            signature: fleet_crypto::sig::p256_sign(&mac.keys.device, &msg)
                .map_err(|e| e.to_string())?,
            body,
            device_id: mac.id,
            key: KeyKind::Device,
            approval: None,
        })
    }
}

async fn ssh_connect(target: &SshTarget, mac: &Mac, pin: Option<HostKey>) -> Res<SshConnection> {
    let role = RoleSigner::new(&mac.keys, KeyRole::Ssh).map_err(err("ssh signer"))?;
    let signer = P256SshSigner(role);
    let (conn, _obs) = timeout(STEP, SshConnection::connect(target, &signer, pin))
        .await
        .map_err(|_| "ssh connect: timed out")?
        .map_err(err("ssh connect"))?;
    Ok(conn)
}

/// First-use connect; the key sshd presents must be one of the container's
/// host keys (read out of band with `docker exec`). Then it is pinned.
fn probe_host_key(c: &Container, mac: &Mac) -> Res<HostKey> {
    let pubs = c.exec(&["sh", "-c", "cat /etc/ssh/ssh_host_*_key.pub"])?;
    let known: Vec<HostKey> = pubs
        .lines()
        .filter_map(|l| HostKey::from_openssh(l).ok())
        .collect();
    let target = SshTarget::new("127.0.0.1", c.ssh_port, ADMIN);
    let rt = runtime();
    rt.block_on(async {
        let role = RoleSigner::new(&mac.keys, KeyRole::Ssh).map_err(err("ssh signer"))?;
        let signer = P256SshSigner(role);
        // sshd may still be starting right after boot: retry briefly.
        let mut last = String::new();
        for _ in 0..20 {
            match timeout(STEP, SshConnection::connect(&target, &signer, None)).await {
                Ok(Ok((conn, obs))) => {
                    conn.disconnect().await;
                    return if known.contains(&obs.key) {
                        Ok(obs.key)
                    } else {
                        Err(format!("unknown host key {}", obs.key.fingerprint()))
                    };
                }
                Ok(Err(e)) => last = e.to_string(),
                Err(_) => last = "timed out".into(),
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Err(format!("ssh probe: {last}"))
    })
}

pub fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

/// Runs `f` on a fresh single-threaded runtime with an overall limit.
pub fn run<F: Future<Output = ()>>(limit: Duration, f: F) {
    runtime().block_on(async {
        timeout(limit, f).await.expect("test timed out");
    });
}

// ---------------------------------------------------------------- raw client

/// Minimal Noise client over the agent channel for stream ops, which
/// fleet-core's `Session` doesn't speak yet (same wire format: 4-byte
/// big-endian length + Noise message).
pub struct RawSession {
    s: AgentStream,
    t: Transport,
    reasm: Reassembler,
    next: u32,
}

impl RawSession {
    pub async fn open(fx: &Fixture, conn: &SshConnection, mac: &Mac) -> Res<Self> {
        let mut s = timeout(STEP, conn.open_agent_channel(false))
            .await
            .map_err(|_| "agent channel: timed out")?
            .map_err(err("agent channel"))?;
        let mut hs = Handshake::initiator(&mac.noise, &noise::prologue(SessionMode::Normal as u8))
            .map_err(err("noise"))?;
        write_raw(&mut s, &hs.write_message(&[]).map_err(err("noise"))?).await?;
        hs.read_message(&read_raw(&mut s).await?)
            .map_err(err("noise"))?;
        if hs.remote_static() != Some(fx.agent_noise) {
            return Err("agent Noise key is not the pinned one".into());
        }
        write_raw(&mut s, &hs.write_message(&[]).map_err(err("noise"))?).await?;
        let t = hs.into_transport(now_ms()).map_err(err("noise"))?;
        let auth_msg = Message::device_auth_message(KeyKind::Device, &mac.id, t.handshake_hash());
        let auth = Message::DeviceAuth {
            device_id: mac.id,
            key: KeyKind::Device,
            sig: fleet_crypto::sig::p256_sign(&mac.keys.device, &auth_msg).map_err(err("sign"))?,
        };
        let mut c = Self {
            s,
            t,
            reasm: Reassembler::for_exec(),
            next: 0,
        };
        c.send(&auth).await?;
        loop {
            match c.recv().await? {
                Message::Hello { .. } => return Ok(c),
                Message::Response { result: Err(e), .. } => {
                    return Err(format!("session refused: {e:?}"));
                }
                _ => {}
            }
        }
    }

    pub async fn send(&mut self, m: &Message) -> Res<()> {
        self.next += 1;
        for c in split_frame(self.next, &encode(m)) {
            let ct = self.t.encrypt(&c).map_err(err("encrypt"))?;
            write_raw(&mut self.s, &ct).await?;
        }
        Ok(())
    }

    pub async fn recv(&mut self) -> Res<Message> {
        loop {
            let ct = read_raw(&mut self.s).await?;
            let pt = self.t.decrypt(&ct).map_err(err("decrypt"))?;
            if let Some((_, f)) = self.reasm.push(&pt).map_err(|_| "reassembly")? {
                match decode(&f).map_err(|_| "decode")? {
                    Message::Rekey => self.t.rekey_incoming(),
                    m => return Ok(m),
                }
            }
        }
    }
}

async fn write_raw(s: &mut AgentStream, m: &[u8]) -> Res<()> {
    let mut b = Vec::with_capacity(4 + m.len());
    b.extend_from_slice(&(m.len() as u32).to_be_bytes());
    b.extend_from_slice(m);
    s.write_all(&b).await.map_err(err("write"))?;
    s.flush().await.map_err(err("flush"))
}

async fn read_raw(s: &mut AgentStream) -> Res<Vec<u8>> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await.map_err(err("read"))?;
    let len = u32::from_be_bytes(len) as usize;
    if len > NOISE_MAX_MSG {
        return Err("oversized Noise message".into());
    }
    let mut b = vec![0u8; len];
    s.read_exact(&mut b).await.map_err(err("read"))?;
    Ok(b)
}
