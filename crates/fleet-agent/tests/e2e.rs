//! End-to-end: Mac client (fleet-core) → gate → exec over real Unix sockets.
//! Each test gets its own root directory; gate and exec run in-process on
//! their own threads with single-threaded runtimes.

use fleet_agent::exec::{self, ExecConfig};
use fleet_agent::frame::{self, MAX_STREAM_FRAME};
use fleet_agent::gate::{self, GateConfig};
use fleet_agent::install::{self, InstallInput, InstallOutput};
use fleet_agent::ipc::{self, IpcMsg};
use fleet_agent::paths::Paths;
use fleet_agent::pending::{ChangeId, ChangeKind, PendingChange, PendingDir, RevertedMarker};
use fleet_agent::revert::{Revert, RevertError};
use fleet_agent::store::Store;
use fleet_agent::{fsutil, now_ms};
use fleet_core::{
    ClientError, CommandOpts, CommandSigner, Reply, Session, SessionConfig, SessionMode,
};
use fleet_crypto::Zeroizing;
use fleet_crypto::approval::{ApprovalParams, build_approvals, op_digest};
use fleet_crypto::noise::{self, Handshake, StaticKeypair, Transport};
use fleet_crypto::receipt::{receipt_for, sign_event, sign_receipt, verify_response};
use fleet_crypto::roster::{roster_hash, sign_recovery, sign_root};
use fleet_crypto::sig::{Ed25519Signer, Signer, SoftwareP256Signer};
use fleet_crypto::verify::command_hash;
use fleet_ops::{CommandOutput, CommandRunner, CommandSpec, LocalBoxFuture, RunError};
use fleet_proto::chunk::{Reassembler, split_frame};
use fleet_proto::{
    Actor, AgentHealth, AgentVersion, ApprovalItem, BoundedString, CommandBody, Device, DeviceId,
    ErrorCode, Event, FleetId, KeyKind, Message, Op, Outcome, PROTO_VERSION, Payload,
    ResultSummary, Role, RootApproval, Roster, ServerId, Signature, SignedCommand, SignedRoster,
    X25519Public, decode, encode,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;
use tokio::sync::oneshot;

const SERVER: &str = "srv_test01";

/// Stream sessions (`tests/e2e/streams.rs`), sharing this fixture.
#[path = "e2e/streams.rs"]
mod streams;

/// Pipeline checks, escalation, auto-revert and `change.confirm`
/// (`tests/e2e/pipeline.rs`).
#[path = "e2e/pipeline.rs"]
mod pipeline;

/// Event sources, bans, integrity, services wiring (`tests/e2e/sources.rs`).
#[path = "e2e/sources.rs"]
mod sources;

/// Agent updates and uninstall (`tests/e2e/lifecycle.rs`).
#[path = "e2e/lifecycle.rs"]
mod lifecycle;

/// Registry coverage, `audit.query` + mirror, policy re-verification
/// (`tests/e2e/audit.rs`).
#[path = "e2e/audit.rs"]
mod audit;

fn run(f: impl Future<Output = ()>) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), f)
            .await
            .expect("test timed out")
    });
}

fn p256(seed: u8) -> SoftwareP256Signer {
    SoftwareP256Signer::from_bytes(&[seed; 32]).unwrap()
}

struct Mac {
    id: DeviceId,
    root: SoftwareP256Signer,
    device: SoftwareP256Signer,
    monitor: SoftwareP256Signer,
    noise: StaticKeypair,
}

impl Mac {
    fn new(seed: u8) -> Self {
        Self {
            id: DeviceId([seed; 16]),
            root: p256(seed),
            device: p256(seed + 1),
            monitor: p256(seed + 2),
            noise: StaticKeypair::from_bytes(&Zeroizing::new([seed + 3; 32])),
        }
    }

    fn entry(&self) -> Device {
        Device {
            id: self.id,
            name: BoundedString::new("Mac").unwrap(),
            role: Role::Admin,
            root_key: self.root.public(),
            device_key: self.device.public(),
            monitor_key: self.monitor.public(),
            ssh_key: self.device.public(),
            monitor_ssh_key: self.monitor.public(),
            noise_static: self.noise.public(),
            added_at: 0,
            added_by: self.id,
        }
    }
}

type Task = Pin<Box<dyn Future<Output = ()>>>;

/// A gate or exec on its own thread; dropping it shuts it down and joins.
struct Running {
    stop: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Running {
    fn spawn(make: impl FnOnce(oneshot::Receiver<()>) -> Task + Send + 'static) -> Self {
        let (tx, rx) = oneshot::channel();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(make(rx));
        });
        Self {
            stop: Some(tx),
            thread: Some(thread),
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn wait_for(path: &std::path::Path) {
    for _ in 0..500 {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("{} never appeared", path.display());
}

/// Policy knobs the tests vary.
#[derive(Clone, Copy)]
struct Pol {
    commands_per_minute: u32,
    ai: &'static str,
    max_streams: u32,
    /// TOML list body of `capabilities.allow`.
    groups: &'static str,
    ai_per_minute: u32,
    /// `"managed"` or `"agent-only"` (design §5.4).
    security: &'static str,
}

impl Default for Pol {
    fn default() -> Self {
        Self {
            commands_per_minute: 240,
            ai: "full",
            max_streams: 32,
            groups: r#""system""#,
            ai_per_minute: 60,
            security: "managed",
        }
    }
}

fn policy_toml(fleet: FleetId, version: u64, pol: Pol) -> String {
    let Pol {
        commands_per_minute,
        ai,
        max_streams,
        groups,
        ai_per_minute,
        security,
    } = pol;
    format!(
        r#"version = {version}
fleet_id = "{fleet}"
server_id = "{SERVER}"
security = "{security}"
[capabilities]
allow = [{groups}]
shell_exec = false
shell_exec_users = []
[elevated]
extra = []
[actors]
ai = "{ai}"
ai_bulk_confirm_above = 5
ai_commands_per_minute = {ai_per_minute}
[limits]
commands_per_minute = {commands_per_minute}
max_stream_sessions = {max_streams}
[safety]
auto_revert_seconds = 60
"#
    )
}

/// Always restores successfully (tests only).
struct NoopRevert;
impl Revert for NoopRevert {
    fn revert(&self, _: ChangeKind, _: &[u8], _: Option<u64>) -> Result<(), RevertError> {
        Ok(())
    }
}

/// Records timer commands across threads (argv as strings); all succeed.
type Timers = Arc<Mutex<Vec<Vec<String>>>>;
struct SharedRecorder(Timers);
impl CommandRunner for SharedRecorder {
    fn run(&self, spec: CommandSpec) -> LocalBoxFuture<'_, Result<CommandOutput, RunError>> {
        Box::pin(std::future::ready(self.run_blocking(spec)))
    }
    fn run_blocking(&self, spec: CommandSpec) -> Result<CommandOutput, RunError> {
        let mut argv = vec![spec.program.to_owned()];
        argv.extend(spec.args.iter().map(|a| a.to_string_lossy().into_owned()));
        self.0.lock().unwrap().push(argv);
        Ok(CommandOutput::ok(""))
    }
}

#[derive(Default)]
struct Opts {
    pol: Pol,
    gate_rekey: Option<Duration>,
}

struct Fixture {
    gate: Option<Running>,
    exec: Option<Running>,
    paths: Paths,
    keys: InstallOutput,
    server: ServerId,
    fleet: FleetId,
    macs: Vec<Mac>,
    recovery: Ed25519Signer,
    genesis: SignedRoster,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// `n` Macs in the genesis roster (signed by mac 0), recovery delay `delay_s`.
    fn new(n: usize, delay_s: u32) -> Self {
        Self::with(n, delay_s, Opts::default())
    }

    fn with(n: usize, delay_s: u32, opts: Opts) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        let macs: Vec<Mac> = (0..n).map(|i| Mac::new(10 + 4 * i as u8)).collect();
        let recovery = Ed25519Signer::from_seed(&[200; 32]);
        let fleet = FleetId([1; 16]);
        let roster = Roster {
            fleet_id: fleet,
            epoch: 0,
            version: 1,
            prev_hash: [0; 32],
            issued_at_ms: now_ms(),
            devices: macs.iter().map(Mac::entry).collect(),
            recovery_key: recovery.public(),
            recovery_ssh_key: Ed25519Signer::from_seed(&[201; 32]).public(),
            recovery_escrow_key: StaticKeypair::from_bytes(&Zeroizing::new([202; 32])).public(),
            recovery_delay_s: delay_s,
            prev_recovery: None,
        };
        let genesis = sign_root(roster, macs[0].id, &macs[0].root).unwrap();
        let server = ServerId::new(SERVER).unwrap();
        let keys = install::install(
            &paths,
            &InstallInput {
                genesis: genesis.clone(),
                policy_toml: policy_toml(fleet, 1, opts.pol),
                server_id: server.clone(),
                admin_user: Some("admin".into()),
            },
        )
        .unwrap();
        let mut fx = Fixture {
            gate: None,
            exec: None,
            paths,
            keys,
            server,
            fleet,
            macs,
            recovery,
            genesis,
            _dir: dir,
        };
        fx.start_exec();
        let p = fx.paths.clone();
        let rekey = opts.gate_rekey;
        fx.gate = Some(Running::spawn(move |rx| {
            Box::pin(async move {
                let mut cfg = GateConfig::new(p);
                cfg.rekey_interval = rekey;
                gate::run(cfg, async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
            })
        }));
        wait_for(&fx.paths.agent_sock);
        fx
    }

    fn start_exec(&mut self) {
        self.start_exec_with(|_| {});
    }

    fn start_exec_with(&mut self, tweak: impl FnOnce(&mut ExecConfig) + Send + 'static) {
        let p = self.paths.clone();
        self.exec = Some(Running::spawn(move |rx| {
            Box::pin(async move {
                let uid = fsutil::current_uid().unwrap();
                let mut cfg = ExecConfig::new(p, uid);
                cfg.maintenance_interval = Duration::from_millis(100);
                // No journalctl/D-Bus/pollers against the host; tests that
                // want them use fakes (`tests/e2e/sources.rs`).
                cfg.sources.enabled = false;
                // No sshd journal to vouch for a new login; tests that
                // check it turn it back on.
                cfg.confirm_sshd_login = None;
                cfg.terminator = Some(Box::new(exec::NoopTerminator));
                // Snapshots/restores through the configured (fake) modules,
                // not the system reverter on the blocking pool.
                cfg.offload = None;
                tweak(&mut cfg);
                exec::run(cfg, async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
            })
        }));
        wait_for(&self.paths.exec_sock);
    }

    /// Stops exec (closing its database) and starts a fresh one.
    fn restart_exec(&mut self) {
        self.exec = None;
        self.start_exec();
    }

    fn cfg<'a>(&self, mac: &'a Mac, key: KeyKind) -> SessionConfig<'a> {
        let signer: &dyn Signer = match key {
            KeyKind::Monitor => &mac.monitor,
            _ => &mac.device,
        };
        SessionConfig {
            mode: SessionMode::Normal,
            noise: &mac.noise,
            pinned_agent_noise: self.keys.noise_static,
            pinned_agent_signing: self.keys.signing_key,
            fleet_id: self.fleet,
            server_id: self.server.clone(),
            device_id: mac.id,
            key,
            signer: CommandSigner::P256(signer),
        }
    }

    /// Recovery bridge session for a recovering Mac `mac` (fresh keys).
    fn recovery_cfg<'a>(&self, mac: &'a Mac, rec: &'a Ed25519Signer) -> SessionConfig<'a> {
        SessionConfig {
            mode: SessionMode::Recovery,
            key: KeyKind::Recovery,
            signer: CommandSigner::Recovery(rec),
            ..self.cfg(mac, KeyKind::Device)
        }
    }

    async fn connect_with<'a>(
        &self,
        cfg: SessionConfig<'a>,
    ) -> Result<Session<'a, UnixStream>, ClientError> {
        let s = UnixStream::connect(&self.paths.agent_sock).await?;
        Session::connect(s, cfg).await
    }

    async fn connect<'a>(&self, mac: &'a Mac) -> Session<'a, UnixStream> {
        self.connect_with(self.cfg(mac, KeyKind::Device))
            .await
            .unwrap()
    }

    fn approve(&self, mac: &Mac, op: &Op) -> RootApproval {
        self.approve_ev(mac, op, None)
    }

    /// Approval for `op` with `expected_version` (both are in the digest).
    fn approve_ev(&self, mac: &Mac, op: &Op, ev: Option<u64>) -> RootApproval {
        let mut approval_id = [0u8; 16];
        fleet_crypto::random_bytes(&mut approval_id).unwrap();
        let now = now_ms();
        let params = ApprovalParams {
            fleet_id: self.fleet,
            approval_id,
            issued_at_ms: now,
            expires_at_ms: now + 10 * 60_000,
        };
        let item = ApprovalItem {
            server_id: self.server.clone(),
            op_digest: op_digest(op, ev),
        };
        build_approvals(&mac.root, mac.id, &params, &[item])
            .unwrap()
            .remove(0)
    }

    fn next_roster(
        &self,
        cur: &SignedRoster,
        by: &Mac,
        edit: impl FnOnce(&mut Roster),
    ) -> SignedRoster {
        let mut r = cur.roster.clone();
        r.version += 1;
        r.prev_hash = roster_hash(cur);
        r.issued_at_ms = now_ms();
        edit(&mut r);
        sign_root(r, by.id, &by.root).unwrap()
    }

    /// Genesis plus `n` extra devices: well over one chunk when encoded.
    fn big_roster(&self, n: u16) -> SignedRoster {
        let m0 = &self.macs[0];
        self.next_roster(&self.genesis, m0, |r| {
            for i in 0..n {
                let mut d = m0.entry();
                let mut id = [0xd0; 16];
                id[..2].copy_from_slice(&i.to_be_bytes());
                d.id = DeviceId(id);
                r.devices.push(d);
            }
        })
    }

    /// Epoch 1: only `new_mac`, fresh recovery keys, signed by the recovery key.
    fn recovery_roster(&self, new_mac: &Mac) -> SignedRoster {
        self.recovery_roster_v(new_mac, 5)
    }

    fn recovery_roster_v(&self, new_mac: &Mac, version: u64) -> SignedRoster {
        let mut r = self.genesis.roster.clone();
        r.epoch = 1;
        r.version = version;
        r.prev_hash = roster_hash(&self.genesis);
        r.issued_at_ms = now_ms();
        r.devices = vec![new_mac.entry()];
        r.recovery_key = Ed25519Signer::from_seed(&[210; 32]).public();
        r.recovery_ssh_key = Ed25519Signer::from_seed(&[211; 32]).public();
        r.recovery_escrow_key = StaticKeypair::from_bytes(&Zeroizing::new([212; 32])).public();
        sign_recovery(r, &self.recovery)
    }

    fn policy_op(&self, version: u64) -> Op {
        Op::PolicyUpdate {
            policy_toml: policy_toml(self.fleet, version, Pol::default()),
        }
    }
}

fn err(r: Reply) -> ErrorCode {
    r.result.expect_err("expected an error")
}

fn roster_version(s: &Session<'_, UnixStream>) -> (u32, u64) {
    let h = s.status().health.as_ref().expect("health read at connect");
    (h.roster_epoch, h.roster_version)
}

#[test]
fn system_info_round_trip() {
    let fx = Fixture::new(1, 0);
    run(async {
        let mut s = fx.connect(&fx.macs[0]).await;
        assert_eq!(roster_version(&s), (0, 1));
        assert_eq!(s.hello().server_id, fx.server);
        let r = s
            .request(Op::SystemInfo, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert!(matches!(r.result, Ok(Payload::SystemInfo(_))), "{r:?}");
        // Reads are receipted too, with their audit entry.
        assert!(r.receipt.receipt.audit_seq.is_some());
    });
}

#[test]
fn policy_update_receipt_verifies() {
    let fx = Fixture::new(1, 0);
    run(async {
        let mut s = fx.connect(&fx.macs[0]).await;
        let op = fx.policy_op(2);
        let approval = fx.approve(&fx.macs[0], &op);
        let r = s
            .request(op, &fx.server, Actor::Human, Some(approval))
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));
        assert_eq!(r.receipt.receipt.outcome, Outcome::Ok);

        // Replaying an older version is refused.
        let op = fx.policy_op(2);
        let approval = fx.approve(&fx.macs[0], &op);
        let r = s
            .request(op, &fx.server, Actor::Human, Some(approval))
            .await
            .unwrap();
        assert_eq!(err(r), ErrorCode::VersionConflict { current: 2 });
    });
}

#[test]
fn policy_update_expected_version_enforced() {
    let fx = Fixture::new(1, 0);
    run(async {
        let m = &fx.macs[0];
        let mut s = fx.connect(m).await;
        for (ev, want) in [
            (Some(7), Err(ErrorCode::VersionConflict { current: 1 })),
            (Some(1), Ok(Payload::Empty)),
        ] {
            let op = fx.policy_op(2);
            let approval = fx.approve_ev(m, &op, ev);
            let opts = CommandOpts {
                expected_version: ev,
                ..CommandOpts::default()
            };
            let cmd = s
                .build_command(op, &fx.server, Actor::Human, Some(approval), &opts)
                .unwrap();
            assert_eq!(s.send(&cmd).await.unwrap().result, want);
        }
    });
}

#[test]
fn tampered_stale_and_wrong_server_rejected_with_receipts() {
    let fx = Fixture::new(1, 0);
    run(async {
        let mut s = fx.connect(&fx.macs[0]).await;
        let opts = CommandOpts::default();
        // Body changed after signing, still well-formed.
        let mut cmd = s
            .build_command(Op::SystemInfo, &fx.server, Actor::Human, None, &opts)
            .unwrap();
        let mut body: CommandBody = decode(&cmd.body).unwrap();
        body.issued_at_ms += 1;
        cmd.body = encode(&body);
        // Every rejection arrives receipted (verified by the client);
        // rejected before the audit intent, so without an audit seq.
        let r = s.send(&cmd).await.unwrap();
        assert_eq!(r.receipt.receipt.audit_seq, None);
        assert_eq!(err(r), ErrorCode::SignatureInvalid);

        let stale = CommandOpts {
            issued_at_ms: Some(now_ms() - 10 * 60_000),
            ..CommandOpts::default()
        };
        let cmd = s
            .build_command(Op::SystemInfo, &fx.server, Actor::Human, None, &stale)
            .unwrap();
        assert_eq!(err(s.send(&cmd).await.unwrap()), ErrorCode::Stale);

        let other = ServerId::new("srv_other1").unwrap();
        let r = s
            .request(Op::SystemInfo, &other, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(err(r), ErrorCode::Unauthorized);

        // Elevated op without a root approval: signed failure, not unknown.
        let r = s
            .request(fx.policy_op(2), &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(err(r), ErrorCode::ApprovalRequired);
    });
}

#[test]
fn policy_denied_command_does_not_burn_approval() {
    let fx = Fixture::with(
        1,
        0,
        Opts {
            pol: Pol {
                ai: "none",
                ..Pol::default()
            },
            ..Opts::default()
        },
    );
    run(async {
        let m = &fx.macs[0];
        let mut s = fx.connect(m).await;
        let op = fx.policy_op(2);
        let approval = fx.approve(m, &op);
        let ai = Actor::Ai {
            client: BoundedString::new("mcp").unwrap(),
            session: [1; 16],
        };
        let r = s
            .request(op.clone(), &fx.server, ai, Some(approval.clone()))
            .await
            .unwrap();
        assert_eq!(err(r), ErrorCode::PolicyDenied);
        // Same approval (same leaf), new command: still usable.
        let r = s
            .request(op, &fx.server, Actor::Human, Some(approval))
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));
    });
}

/// Agent-only (design §5.4): every op that would take over host security is
/// refused with `PolicyDenied` in `check_policy`, before the nonce is
/// consumed — resending the identical signed command gets the same refusal
/// again, never `Replay`.
#[test]
fn agent_only_refuses_security_takeover_ops_without_burning_nonce() {
    let fx = Fixture::with(
        1,
        0,
        Opts {
            pol: Pol {
                groups: r#""firewall", "security", "users", "profile""#,
                security: "agent-only",
                ..Pol::default()
            },
            ..Opts::default()
        },
    );
    run(async {
        let m = &fx.macs[0];
        let mut s = fx.connect(m).await;
        let ops = [
            Op::FirewallApply(fleet_proto::args::FirewallRuleSet {
                mode: fleet_proto::args::FirewallMode::Managed,
                rules: vec![],
            }),
            Op::AuthorizedKeysSet {
                user: fleet_proto::args::UserName::new("ops").unwrap(),
                keys: vec![],
            },
            Op::BansRemove {
                addr: "203.0.113.9".parse().unwrap(),
            },
            Op::BansConfigSet(fleet_ops::security::bans::default_config()),
            Op::ProfileApply {
                spec: fleet_proto::op::ProfileSpec {
                    source: fleet_proto::op::ProfileSource::Builtin {
                        level: fleet_proto::op::ProfileLevel::Baseline,
                        roles: vec![],
                    },
                    only: vec![],
                },
                plan_hash: [0; 32],
                phase: fleet_proto::op::ProfilePhase::System,
                password_hash: None,
            },
        ];
        for op in ops {
            // An approval, needed or not (`authorized_keys.set` is
            // Elevated: without one, `verify` itself would answer
            // `ApprovalRequired` before the policy check ever runs).
            let approval = fx.approve(m, &op);
            let cmd = s
                .build_command(
                    op.clone(),
                    &fx.server,
                    Actor::Human,
                    Some(approval),
                    &CommandOpts::default(),
                )
                .unwrap();
            assert_eq!(
                err(s.send(&cmd).await.unwrap()),
                ErrorCode::PolicyDenied,
                "{}",
                op.name()
            );
            // Resending the identical command: still refused, not `Replay`
            // (the nonce was never committed).
            assert_eq!(
                err(s.send(&cmd).await.unwrap()),
                ErrorCode::PolicyDenied,
                "{} (resend)",
                op.name()
            );
        }
        // Read-only ops in the same groups stay allowed: never refused by
        // the policy check (whatever else they answer — `firewall.get`
        // has no real `nft` in this sandbox).
        for op in [Op::FirewallGet, Op::BansList, Op::BansConfigGet] {
            let r = s
                .request(op.clone(), &fx.server, Actor::Human, None)
                .await
                .unwrap();
            assert!(
                !matches!(r.result, Err(ErrorCode::PolicyDenied)),
                "{}: {:?}",
                op.name(),
                r.result
            );
        }
    });
}

/// Switching `security` back to `managed` (a normal `policy.update`) takes
/// effect immediately, no agent restart: a takeover op that was refused
/// with `PolicyDenied` a moment ago now clears the policy check (it may
/// still need `ApprovalRequired`, which is a normal Elevated-tier check,
/// never `PolicyDenied`).
#[test]
fn agent_only_switch_to_managed_takes_effect_immediately() {
    let fx = Fixture::with(
        1,
        0,
        Opts {
            pol: Pol {
                groups: r#""users""#,
                security: "agent-only",
                ..Pol::default()
            },
            ..Opts::default()
        },
    );
    run(async {
        let m = &fx.macs[0];
        let mut s = fx.connect(m).await;
        let ak_op = || Op::AuthorizedKeysSet {
            user: fleet_proto::args::UserName::new("ops").unwrap(),
            keys: vec![],
        };
        // Elevated: an approval so `verify` doesn't answer
        // `ApprovalRequired` before the policy check even runs.
        let ak_approval = fx.approve(m, &ak_op());
        let r = s
            .request(ak_op(), &fx.server, Actor::Human, Some(ak_approval))
            .await
            .unwrap();
        assert_eq!(err(r), ErrorCode::PolicyDenied);

        let policy_op = Op::PolicyUpdate {
            policy_toml: policy_toml(
                fx.fleet,
                2,
                Pol {
                    groups: r#""users""#,
                    security: "managed",
                    ..Pol::default()
                },
            ),
        };
        let approval = fx.approve(m, &policy_op);
        let r = s
            .request(policy_op, &fx.server, Actor::Human, Some(approval))
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));

        // Same op again, no approval: now Elevated's normal
        // `ApprovalRequired`, not `PolicyDenied` — the policy check passed.
        let r = s
            .request(ak_op(), &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(err(r), ErrorCode::ApprovalRequired);
    });
}

/// `sync_authorized_keys` never runs under Agent-only (startup or
/// maintenance tick), and resumes as soon as the policy switches to
/// Managed — no agent restart.
#[test]
fn agent_only_never_syncs_authorized_keys_until_switched_to_managed() {
    let fx = Fixture::with(
        1,
        0,
        Opts {
            pol: Pol {
                security: "agent-only",
                ..Pol::default()
            },
            ..Opts::default()
        },
    );
    let ak_path = fx.paths.authorized_keys_dir.join("admin");
    run(async {
        // Startup sync plus a couple of 100ms maintenance ticks.
        tokio::time::sleep(Duration::from_millis(300)).await;
    });
    assert!(
        !ak_path.exists(),
        "agent-only must never write authorized_keys"
    );

    run(async {
        let m = &fx.macs[0];
        let mut s = fx.connect(m).await;
        let policy_op = Op::PolicyUpdate {
            policy_toml: policy_toml(
                fx.fleet,
                2,
                Pol {
                    security: "managed",
                    ..Pol::default()
                },
            ),
        };
        let approval = fx.approve(m, &policy_op);
        let r = s
            .request(policy_op, &fx.server, Actor::Human, Some(approval))
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));
        tokio::time::sleep(Duration::from_millis(300)).await;
    });
    assert!(
        ak_path.exists(),
        "managed must sync authorized_keys again, no restart needed"
    );
}

/// A gate that drops exec's reply and re-forwards the same command gets the
/// original result and receipt back, never a signed "failure" for a command
/// that ran; a different command reusing the nonce is a signed `Replay`,
/// which the client reports as outcome unknown for a state-changing op.
#[test]
fn replayed_command_gets_original_reply_also_after_exec_restart() {
    let mut fx = Fixture::new(1, 0);
    let (cmd, first) = {
        let fx = &fx;
        let mut out = None;
        run(async {
            let m = &fx.macs[0];
            let mut s = fx.connect(m).await;
            let op = fx.policy_op(2);
            let cmd = s
                .build_command(
                    op.clone(),
                    &fx.server,
                    Actor::Human,
                    Some(fx.approve(m, &op)),
                    &CommandOpts::default(),
                )
                .unwrap();
            let first = s.send(&cmd).await.unwrap();
            assert!(first.result.is_ok(), "{first:?}");
            assert!(first.receipt.receipt.audit_seq.is_some());
            assert_eq!(s.send(&cmd).await.unwrap(), first, "original reply");

            // Same nonce (and approval), different envelope.
            let mut body: CommandBody = decode(&cmd.body).unwrap();
            body.ttl_ms -= 1;
            let body = encode(&body);
            let msg = SignedCommand::signed_message(cmd.key, &cmd.device_id, &body);
            let other = SignedCommand {
                signature: fleet_crypto::sig::p256_sign(&m.device, &msg).unwrap(),
                body,
                ..cmd.clone()
            };
            let e = s.send(&other).await.unwrap_err();
            assert!(
                matches!(
                    e,
                    ClientError::OutcomeUnknown {
                        claimed: Some(ErrorCode::Replay)
                    }
                ),
                "{e}"
            );
            out = Some((cmd, first));
        });
        out.unwrap()
    };
    fx.restart_exec();
    run(async {
        let mut s = fx.connect(&fx.macs[0]).await;
        assert_eq!(s.send(&cmd).await.unwrap(), first);
    });
}

/// Unauthenticated connections can't lock anyone out: a full setup pool
/// evicts its oldest entry, recovery bridges have a pool of their own, and
/// only authenticated sessions count against the per-device cap.
#[test]
fn preauth_flood_does_not_block_sessions_or_recovery() {
    use tokio::io::AsyncWriteExt;
    let fx = Fixture::new(1, 0);
    run(async {
        let mut idle = Vec::new();
        for _ in 0..gate::MAX_PREAUTH_SESSIONS {
            idle.push(UnixStream::connect(&fx.paths.agent_sock).await.unwrap());
        }
        for _ in 0..gate::MAX_PREAUTH_RECOVERY {
            let mut s = UnixStream::connect(&fx.paths.agent_sock).await.unwrap();
            s.write_all(&[1]).await.unwrap(); // recovery mode byte
            idle.push(s);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;

        let m = &fx.macs[0];
        let mut s = fx.connect(m).await;
        let r = s
            .request(Op::SystemInfo, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert!(r.result.is_ok());
        let new_mac = Mac::new(50);
        let rec = fx
            .connect_with(fx.recovery_cfg(&new_mac, &fx.recovery))
            .await
            .unwrap();
        // The oldest idle connection was evicted (closed).
        let mut b = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(5), idle[0].read(&mut b))
            .await
            .expect("evicted connection closed")
            .unwrap_or(0);
        assert_eq!(n, 0);

        // Per-device cap, counted after DeviceAuth.
        let mut held = vec![s];
        for _ in 1..gate::MAX_SESSIONS_PER_DEVICE {
            held.push(fx.connect(m).await);
        }
        let e = fx
            .connect_with(fx.cfg(m, KeyKind::Device))
            .await
            .err()
            .unwrap();
        assert!(matches!(e, ClientError::Rejected(ErrorCode::Busy)), "{e}");
        drop((held, rec, idle));
    });
}

/// Records the SSH keys whose sessions exec asks to end.
struct RecTerm(Arc<Mutex<Vec<fleet_proto::P256Public>>>);
impl exec::SessionTerminator for RecTerm {
    fn end_sessions(&self, removed: &[fleet_proto::P256Public]) {
        self.0.lock().unwrap().extend_from_slice(removed);
    }
}

#[test]
fn revoked_device_rejected_and_authorized_keys_rewritten() {
    let mut fx = Fixture::new(2, 0);
    let ended = Arc::new(Mutex::new(Vec::new()));
    let e2 = ended.clone();
    // Stop exec before seeding: its maintenance tick (every 100 ms) does
    // read-merge-rename on this file, and a write landing between its read
    // and rename is lost.
    fx.exec = None;
    let ak_path = fx.paths.authorized_keys_dir.join("admin");
    // Hand edits: an extra key and a stale duplicate managed block.
    let seeded = format!(
        "ssh-ed25519 AAAA extra\n{}\nstale\n{}\n",
        fleet_agent::authorized_keys::BEGIN,
        fleet_agent::authorized_keys::END
    );
    std::fs::write(&ak_path, seeded).unwrap();
    fx.start_exec_with(move |cfg| cfg.terminator = Some(Box::new(RecTerm(e2))));
    run(async {
        let (m0, m1) = (&fx.macs[0], &fx.macs[1]);
        let mut old = fx.connect(m0).await;
        let mut s1 = fx.connect(m1).await;
        let v2 = fx.next_roster(&fx.genesis, m1, |r| r.devices.retain(|d| d.id != m0.id));
        let op = Op::RosterUpdate {
            roster: Box::new(v2),
        };
        let r = s1
            .request(op, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));

        // The open session is ended by the gate or refused by exec.
        match old
            .request(Op::SystemInfo, &fx.server, Actor::Human, None)
            .await
        {
            Ok(r) => assert_eq!(err(r), ErrorCode::Unauthorized),
            Err(e) => assert!(matches!(e, ClientError::Closed | ClientError::Io(_)), "{e}"),
        }
        let e = fx
            .connect_with(fx.cfg(m0, KeyKind::Device))
            .await
            .err()
            .unwrap();
        assert!(
            matches!(e, ClientError::Rejected(ErrorCode::Unauthorized)),
            "{e}"
        );

        // authorized_keys follows the roster; hand-added lines survive,
        // duplicate managed blocks don't.
        let ak = std::fs::read_to_string(&ak_path).unwrap();
        assert!(ak.contains(&format!("fleet-device-{}", m1.id)));
        assert!(!ak.contains(&format!("fleet-device-{}", m0.id)));
        assert!(ak.contains(
            "restrict,command=\"/usr/lib/fleet/fleet-agent bridge --recovery\" ssh-ed25519 "
        ));
        assert!(ak.contains("ssh-ed25519 AAAA extra\n"));
        assert!(!ak.contains("stale"));
        assert_eq!(ak.matches(fleet_agent::authorized_keys::BEGIN).count(), 1);
        // The remaining Mac's monitor key, pinned to the monitor bridge.
        let monitor_line = ak
            .lines()
            .find(|l| l.ends_with(&format!("fleet-monitor-{}", m1.id)))
            .unwrap();
        assert!(monitor_line.starts_with(
            "restrict,command=\"/usr/lib/fleet/fleet-agent bridge --monitor\" ecdsa-sha2-nistp256 "
        ));
        assert!(!ak.contains(&format!("fleet-monitor-{}", m0.id)));
        // The removed Mac's SSH sessions (device and monitor key) are ended.
        assert_eq!(
            *ended.lock().unwrap(),
            [m0.device.public(), m0.monitor.public()]
        );
    });
}

/// A monitor bridge (`bridge --monitor`, mode 2) takes only monitor-key
/// sessions; the normal bridge takes both.
#[test]
fn monitor_bridge_accepts_only_monitor_key() {
    let fx = Fixture::new(1, 0);
    let m = &fx.macs[0];
    // First message after `DeviceAuth` on a raw session.
    async fn first_after_auth(fx: &Fixture, mac: &Mac, mode: u8, key: KeyKind) -> Message {
        let mut s = UnixStream::connect(&fx.paths.agent_sock).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut s, &[mode])
            .await
            .unwrap();
        let mut hs = Handshake::initiator(&mac.noise, &noise::prologue(mode)).unwrap();
        let m1 = hs.write_message(&[]).unwrap();
        frame::write_frame(&mut s, &m1, MAX_STREAM_FRAME)
            .await
            .unwrap();
        let m2 = frame::read_frame(&mut s, MAX_STREAM_FRAME)
            .await
            .unwrap()
            .unwrap();
        hs.read_message(&m2).unwrap();
        let m3 = hs.write_message(&[]).unwrap();
        frame::write_frame(&mut s, &m3, MAX_STREAM_FRAME)
            .await
            .unwrap();
        let mut t = hs.into_transport(now_ms()).unwrap();
        let signer = if key == KeyKind::Monitor {
            &mac.monitor
        } else {
            &mac.device
        };
        let msg = Message::device_auth_message(key, &mac.id, t.handshake_hash());
        let auth = Message::DeviceAuth {
            device_id: mac.id,
            key,
            sig: signer.sign(&msg).unwrap(),
        };
        let ct = t.encrypt(&split_frame(1, &encode(&auth))[0]).unwrap();
        frame::write_frame(&mut s, &ct, MAX_STREAM_FRAME)
            .await
            .unwrap();
        let ct = frame::read_frame(&mut s, MAX_STREAM_FRAME)
            .await
            .unwrap()
            .unwrap();
        let pt = t.decrypt(&ct).unwrap();
        let mut r = Reassembler::for_exec();
        let (_, f) = r.push(&pt).unwrap().unwrap();
        decode(&f).unwrap()
    }
    run(async {
        let unauthorized = |msg: &Message| {
            matches!(
                msg,
                Message::Response {
                    id: 0,
                    result: Err(ErrorCode::Unauthorized),
                    ..
                }
            )
        };
        let hello = |msg: &Message| matches!(msg, Message::Hello { .. });
        assert!(hello(&first_after_auth(&fx, m, 2, KeyKind::Monitor).await));
        assert!(unauthorized(
            &first_after_auth(&fx, m, 2, KeyKind::Device).await
        ));
        assert!(hello(&first_after_auth(&fx, m, 0, KeyKind::Monitor).await));
        assert!(hello(&first_after_auth(&fx, m, 0, KeyKind::Device).await));
    });
}

/// Events are kept in the agent's log: `events.query` (allowed in monitor
/// sessions) pages through them, signed, also across an exec restart.
#[test]
fn events_persist_and_page() {
    let mut fx = Fixture::new(1, 0);
    let m = &fx.macs[0];
    let run_ids = |p: &fleet_proto::payload::SignedEventPage| -> Vec<([u8; 16], u64)> {
        p.events.iter().map(|e| (e.run_id, e.seq)).collect()
    };
    let (first_run, page1) = {
        let fx = &fx;
        let mut out = None;
        run(async {
            let mut s = fx.connect(m).await;
            for v in 2..=3 {
                let op = fx.policy_op(v);
                let approval = fx.approve(m, &op);
                let r = s
                    .request(op, &fx.server, Actor::Human, Some(approval))
                    .await
                    .unwrap();
                assert_eq!(r.result, Ok(Payload::Empty));
            }
            let run_id = s.status().health.as_ref().unwrap().run_id;
            let mut mon = fx.connect_with(fx.cfg(m, KeyKind::Monitor)).await.unwrap();
            let q = Op::EventsQuery {
                since_run_id: None,
                since_seq: 0,
                limit: 1,
            };
            let r = mon
                .request(q, &fx.server, Actor::Human, None)
                .await
                .unwrap();
            let Ok(Payload::SignedEvents(p)) = r.result else {
                panic!("{r:?}")
            };
            assert!(p.more);
            out = Some((run_id, p));
        });
        out.unwrap()
    };
    assert_eq!(run_ids(&page1), [(first_run, 1)]);
    for e in &page1.events {
        fleet_crypto::receipt::verify_event(e, &fx.keys.signing_key, &fx.server).unwrap();
    }
    assert!(matches!(
        page1.events[0].event,
        Event::PolicyChanged { version: 2 }
    ));
    fx.restart_exec();
    let m = &fx.macs[0];
    let fx = &fx;
    run(async {
        let mut s = fx.connect(m).await;
        let q = Op::EventsQuery {
            since_run_id: Some(first_run),
            since_seq: 1,
            limit: 100,
        };
        let r = s.request(q, &fx.server, Actor::Human, None).await.unwrap();
        let Ok(Payload::SignedEvents(p)) = r.result else {
            panic!("{r:?}")
        };
        assert!(!p.more);
        assert_eq!(run_ids(&p), [(first_run, 2)]);
        assert!(matches!(
            p.events[0].event,
            Event::PolicyChanged { version: 3 }
        ));
        // Bounds are checked.
        let q = Op::EventsQuery {
            since_run_id: None,
            since_seq: 0,
            limit: 0,
        };
        let r = s.request(q, &fx.server, Actor::Human, None).await.unwrap();
        assert_eq!(err(r), ErrorCode::InvalidArgument);
    });
}

/// `actors.ai_commands_per_minute`, per device and AI client.
#[test]
fn ai_command_rate_limited_per_actor() {
    let fx = Fixture::with(
        1,
        0,
        Opts {
            pol: Pol {
                ai_per_minute: 2,
                ..Pol::default()
            },
            ..Opts::default()
        },
    );
    let ai = |c: &str| Actor::Ai {
        client: BoundedString::new(c).unwrap(),
        session: [1; 16],
    };
    run(async {
        let mut s = fx.connect(&fx.macs[0]).await;
        for _ in 0..2 {
            let r = s
                .request(Op::SystemInfo, &fx.server, ai("claude"), None)
                .await
                .unwrap();
            assert!(r.result.is_ok());
        }
        let r = s
            .request(Op::SystemInfo, &fx.server, ai("claude"), None)
            .await
            .unwrap();
        assert_eq!(r.receipt.receipt.audit_seq, None);
        assert_eq!(err(r), ErrorCode::Busy);
        // Other actors aren't affected.
        for actor in [ai("other"), Actor::Human] {
            let r = s
                .request(Op::SystemInfo, &fx.server, actor, None)
                .await
                .unwrap();
            assert!(r.result.is_ok());
        }
    });
}

#[test]
fn monitor_session_is_read_only() {
    let fx = Fixture::new(1, 0);
    run(async {
        let m = &fx.macs[0];
        let mut s = fx.connect_with(fx.cfg(m, KeyKind::Monitor)).await.unwrap();
        let r = s
            .request(Op::AgentHealth, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert!(matches!(r.result, Ok(Payload::AgentHealth(_))), "{r:?}");
        // The roster is public: readable while the app is locked.
        let r = s
            .request(Op::RosterGet, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert!(matches!(r.result, Ok(Payload::RosterState(_))), "{r:?}");
        let op = fx.policy_op(2);
        let approval = fx.approve(m, &op);
        // Refused by the gate: unsigned, so only "outcome unknown".
        let e = s
            .request(op, &fx.server, Actor::Human, Some(approval))
            .await
            .unwrap_err();
        assert!(
            matches!(
                e,
                ClientError::OutcomeUnknown {
                    claimed: Some(ErrorCode::Unauthorized)
                }
            ),
            "{e}"
        );
    });
}

#[test]
fn client_refuses_wrong_agent_keys() {
    let fx = Fixture::new(1, 0);
    run(async {
        let m = &fx.macs[0];
        let cfg = SessionConfig {
            pinned_agent_noise: X25519Public([9; 32]),
            ..fx.cfg(m, KeyKind::Device)
        };
        let e = fx.connect_with(cfg).await.err().unwrap();
        assert!(matches!(e, ClientError::AgentKeyMismatch), "{e}");

        // Receipts not signed by the pinned agent key (what a compromised
        // gate would have to forge) fail the signed status read at connect.
        let cfg = SessionConfig {
            pinned_agent_signing: Ed25519Signer::from_seed(&[77; 32]).public(),
            ..fx.cfg(m, KeyKind::Device)
        };
        let e = fx.connect_with(cfg).await.err().unwrap();
        assert!(matches!(e, ClientError::BadReceipt), "{e}");
    });
}

async fn next_message(s: &mut UnixStream, reasm: &mut Reassembler) -> Message {
    loop {
        if let IpcMsg::Chunk(c) = ipc::read_msg(s).await.unwrap().unwrap()
            && let Some((_, f)) = reasm.push(&c).unwrap()
        {
            return decode(&f).unwrap();
        }
    }
}

#[test]
fn compromised_gate_cannot_forge_commands() {
    let fx = Fixture::new(1, 0);
    run(async {
        let m = &fx.macs[0];
        // Straight to exec, as the gate's uid, skipping Noise and DeviceAuth.
        let mut s = UnixStream::connect(&fx.paths.exec_sock).await.unwrap();
        for _ in 0..2 {
            let msg = ipc::read_msg(&mut s).await.unwrap().unwrap();
            assert!(matches!(
                msg,
                IpcMsg::RosterUpdate { .. } | IpcMsg::Limits { .. }
            ));
        }
        let open = IpcMsg::SessionOpen {
            mode: 0,
            device_id: m.id,
            key: KeyKind::Device,
            client_ip: None,
        };
        ipc::write_msg(&mut s, &open).await.unwrap();
        let mut reasm = Reassembler::for_exec();
        assert!(matches!(
            next_message(&mut s, &mut reasm).await,
            Message::Hello { .. }
        ));

        let mut nonce = [0u8; 16];
        fleet_crypto::random_bytes(&mut nonce).unwrap();
        let body = encode(&CommandBody {
            v: PROTO_VERSION,
            fleet_id: fx.fleet,
            server_id: fx.server.clone(),
            issued_at_ms: now_ms(),
            ttl_ms: 60_000,
            nonce,
            actor: Actor::Human,
            op: Op::SystemInfo,
            expected_version: None,
        });
        let stranger = p256(99);
        let msg = SignedCommand::signed_message(KeyKind::Device, &m.id, &body);
        let cases = [
            (Signature([0; 64]), m.id, ErrorCode::SignatureInvalid),
            (
                stranger.sign(&msg).unwrap(),
                m.id,
                ErrorCode::SignatureInvalid,
            ),
            (
                Signature([0; 64]),
                DeviceId([0x55; 16]),
                ErrorCode::Unauthorized,
            ),
        ];
        for (i, (signature, device_id, want)) in cases.into_iter().enumerate() {
            let id = i as u32 + 1;
            let cmd = SignedCommand {
                body: body.clone(),
                device_id,
                key: KeyKind::Device,
                signature,
                approval: None,
            };
            for c in split_frame(
                id,
                &encode(&Message::Request {
                    id,
                    cmd: cmd.clone(),
                }),
            ) {
                ipc::write_msg(&mut s, &IpcMsg::Chunk(c)).await.unwrap();
            }
            match next_message(&mut s, &mut reasm).await {
                Message::Response {
                    id: rid,
                    result,
                    receipt,
                } => {
                    assert_eq!((rid, &result), (id, &Err(want)));
                    let receipt = receipt.expect("rejections are receipted");
                    verify_response(
                        &receipt,
                        &fx.keys.signing_key,
                        &fx.server,
                        &command_hash(&cmd),
                        &result,
                    )
                    .unwrap();
                    assert_eq!(receipt.receipt.audit_seq, None);
                }
                other => panic!("{other:?}"),
            }
        }
    });
}

#[test]
fn recovery_session_immediate() {
    let fx = Fixture::new(1, 0);
    run(async {
        let new_mac = Mac::new(50);
        // Device key on a recovery bridge is refused.
        let cfg = SessionConfig {
            mode: SessionMode::Recovery,
            ..fx.cfg(&fx.macs[0], KeyKind::Device)
        };
        let e = fx.connect_with(cfg).await.err().unwrap();
        assert!(
            matches!(e, ClientError::Rejected(ErrorCode::Unauthorized)),
            "{e}"
        );

        let mut s = fx
            .connect_with(fx.recovery_cfg(&new_mac, &fx.recovery))
            .await
            .unwrap();
        assert!(s.status().health.is_none());
        assert_eq!(s.status().pending_recovery, None);
        let r = s
            .request(Op::SystemInfo, &fx.server, Actor::Recovery, None)
            .await
            .unwrap();
        assert!(r.result.is_ok(), "{r:?}");
        // The roster to chain a recovery roster to, without iCloud (receipted).
        let r = s
            .request(Op::RosterGet, &fx.server, Actor::Recovery, None)
            .await
            .unwrap();
        let Ok(Payload::RosterState(state)) = &r.result else {
            panic!("{r:?}")
        };
        assert_eq!(state.roster, fx.genesis);
        assert_eq!(state.epoch_hashes, [roster_hash(&fx.genesis)]);
        assert_eq!(
            fx.recovery_roster(&new_mac).roster.prev_hash,
            *state.epoch_hashes.last().unwrap()
        );
        // Refused by the gate (not a recovery op): an unsigned read error.
        let e = s
            .request(Op::AgentHealth, &fx.server, Actor::Recovery, None)
            .await
            .unwrap_err();
        assert!(
            matches!(
                e,
                ClientError::MissingReceipt {
                    claimed: Some(ErrorCode::Unauthorized)
                }
            ),
            "{e}"
        );

        let op = Op::RosterUpdate {
            roster: Box::new(fx.recovery_roster(&new_mac)),
        };
        let r = s
            .request(op, &fx.server, Actor::Recovery, None)
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));

        // The recovered Mac now works with its device key; the lost one doesn't.
        let mut n = fx.connect(&new_mac).await;
        assert_eq!(roster_version(&n).0, 1);
        let r = n
            .request(Op::SystemInfo, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert!(r.result.is_ok());
        let e = fx
            .connect_with(fx.cfg(&fx.macs[0], KeyKind::Device))
            .await
            .err()
            .unwrap();
        assert!(
            matches!(e, ClientError::Rejected(ErrorCode::Unauthorized)),
            "{e}"
        );
    });
}

#[test]
fn recovery_pending_then_vetoed() {
    let fx = Fixture::new(1, 72 * 3600);
    run(async {
        let new_mac = Mac::new(50);
        let mut s = fx
            .connect_with(fx.recovery_cfg(&new_mac, &fx.recovery))
            .await
            .unwrap();
        let op = Op::RosterUpdate {
            roster: Box::new(fx.recovery_roster(&new_mac)),
        };
        let r = s
            .request(op, &fx.server, Actor::Recovery, None)
            .await
            .unwrap();
        let Ok(Payload::RosterPending(Some(pending))) = r.result else {
            panic!("{r:?}");
        };
        assert!(pending.activates_at_ms > now_ms() + 71 * 3600 * 1000);

        // A second recovery can't replace or restart the pending one.
        let op = Op::RosterUpdate {
            roster: Box::new(fx.recovery_roster_v(&new_mac, 6)),
        };
        let r = s
            .request(op, &fx.server, Actor::Recovery, None)
            .await
            .unwrap();
        assert_eq!(err(r), ErrorCode::Busy);

        // Recovery sessions can't veto (not in their op set).
        let op = Op::RosterVeto {
            pending_hash: pending.hash,
        };
        let e = s
            .request(op.clone(), &fx.server, Actor::Recovery, None)
            .await
            .unwrap_err();
        assert!(matches!(e, ClientError::OutcomeUnknown { .. }), "{e}");

        let m = &fx.macs[0];
        let mut d = fx.connect(m).await;
        // Verified at connect (signed agent.health), not taken from Hello.
        assert_eq!(
            d.status().pending_recovery.map(|p| p.hash),
            Some(pending.hash)
        );
        let approval = fx.approve(m, &op);
        let r = d
            .request(op, &fx.server, Actor::Human, Some(approval))
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));
        let r = d
            .request(Op::RosterPending, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::RosterPending(None)));
    });
}

#[test]
fn pending_recovery_activates_after_delay() {
    let fx = Fixture::new(1, 1);
    run(async {
        let new_mac = Mac::new(50);
        let mut s = fx
            .connect_with(fx.recovery_cfg(&new_mac, &fx.recovery))
            .await
            .unwrap();
        let op = Op::RosterUpdate {
            roster: Box::new(fx.recovery_roster(&new_mac)),
        };
        let r = s
            .request(op, &fx.server, Actor::Recovery, None)
            .await
            .unwrap();
        assert!(
            matches!(r.result, Ok(Payload::RosterPending(Some(_)))),
            "{r:?}"
        );
        // Exec's maintenance tick (100 ms here) counts the delay down on the
        // monotonic clock and installs it after 1 s.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let mut n = fx.connect(&new_mac).await;
        assert_eq!(roster_version(&n).0, 1);
        assert_eq!(n.status().pending_recovery, None);
        let r = n
            .request(Op::SystemInfo, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert!(r.result.is_ok());
    });
}

#[test]
fn multi_chunk_roster_update_through_gate() {
    let fx = Fixture::new(1, 0);
    let big = fx.big_roster(800);
    assert!(encode(&big).len() > 2 * fleet_proto::chunk::MAX_CHUNK_DATA);
    run(async {
        let mut s = fx.connect(&fx.macs[0]).await;
        let op = Op::RosterUpdate {
            roster: Box::new(big),
        };
        let r = s.request(op, &fx.server, Actor::Human, None).await.unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));
        let n = fx.connect(&fx.macs[0]).await;
        assert_eq!(roster_version(&n), (0, 2));
    });
}

#[test]
fn gate_rate_limit_busy_then_close() {
    let fx = Fixture::with(
        1,
        0,
        Opts {
            pol: Pol {
                commands_per_minute: 3,
                ..Pol::default()
            },
            ..Opts::default()
        },
    );
    let big = fx.big_roster(800);
    run(async {
        // One token goes to the status read at connect.
        let mut s = fx.connect(&fx.macs[0]).await;
        for _ in 0..2 {
            let r = s
                .request(Op::SystemInfo, &fx.server, Actor::Human, None)
                .await
                .unwrap();
            assert!(r.result.is_ok());
        }
        // Single-chunk request over the limit: gate answers Busy (unsigned).
        let e = s
            .request(Op::SystemInfo, &fx.server, Actor::Human, None)
            .await
            .unwrap_err();
        assert!(
            matches!(
                e,
                ClientError::MissingReceipt {
                    claimed: Some(ErrorCode::Busy)
                }
            ),
            "{e}"
        );
        // Multi-chunk frame over the limit: the gate closes the session.
        let op = Op::RosterUpdate {
            roster: Box::new(big),
        };
        let e = s
            .request(op, &fx.server, Actor::Human, None)
            .await
            .unwrap_err();
        assert!(matches!(e, ClientError::Closed | ClientError::Io(_)), "{e}");
    });
}

#[test]
fn rekey_mid_session() {
    let fx = Fixture::with(
        1,
        0,
        Opts {
            gate_rekey: Some(Duration::from_millis(10)),
            ..Opts::default()
        },
    );
    run(async {
        let mut s = fx.connect(&fx.macs[0]).await;
        s.set_rekey_interval(Some(Duration::from_millis(10)));
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let r = s
                .request(Op::SystemInfo, &fx.server, Actor::Human, None)
                .await
                .unwrap();
            assert!(r.result.is_ok());
        }
        // Multi-chunk traffic across rekeys too.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let op = Op::RosterUpdate {
            roster: Box::new(fx.big_roster(800)),
        };
        let r = s.request(op, &fx.server, Actor::Human, None).await.unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));
    });
}

#[test]
fn exec_startup_recovers_pending_dir() {
    let mut fx = Fixture::new(1, 0);
    fx.exec = None;
    let dir = PendingDir::from_paths(&fx.paths);
    let now = now_ms();
    let change = |deadline_ms| PendingChange {
        kind: ChangeKind::Firewall,
        origin: Default::default(),
        snapshot: vec![],
        deadline_ms,
        audit_seq: 999,
        applying: false,
    };
    let marker = RevertedMarker {
        kind: ChangeKind::Firewall,
        origin_audit_seq: 999,
        restored: true,
        time_ms: now,
        conflict: None,
    };
    let [
        expired,
        future,
        corrupt,
        claimed,
        marked,
        stale_marker,
        bad_marker,
        interrupted,
    ] = [1u8, 2, 3, 4, 5, 6, 7, 8].map(|i| ChangeId([i; 16]));
    dir.insert(expired, &change(now - 1_000)).unwrap();
    dir.insert(future, &change(now + 3_600_000)).unwrap();
    // Exec crashed while applying it: reverted even though its (guard)
    // deadline is ahead.
    dir.insert(
        interrupted,
        &PendingChange {
            applying: true,
            ..change(now + 3_600_000)
        },
    )
    .unwrap();
    std::fs::write(fx.paths.pending_dir.join(format!("{corrupt}.bin")), b"junk").unwrap();
    std::fs::write(
        fx.paths.pending_dir.join(format!("{claimed}.claimed")),
        encode(&change(now - 1)),
    )
    .unwrap();
    // Expired, and its revert already wrote the marker before crashing.
    dir.insert(marked, &change(now - 1)).unwrap();
    dir.write_marker(marked, &marker).unwrap();
    dir.write_marker(stale_marker, &marker).unwrap();
    std::fs::write(
        fx.paths.reverted_dir.join(format!("{bad_marker}.bin")),
        b"junk",
    )
    .unwrap();

    let rec = Arc::new(Mutex::new(Vec::new()));
    let rec2 = rec.clone();
    fx.start_exec_with(move |cfg| {
        cfg.timers = std::rc::Rc::new(SharedRecorder(rec2));
        cfg.reverter = Box::new(NoopRevert);
    });
    fx.exec = None;

    let left = dir.scan().unwrap();
    assert_eq!(left.len(), 1, "{left:?}");
    assert_eq!((left[0].id, left[0].claimed), (future, false));
    assert!(dir.scan_markers().unwrap().is_empty());
    assert_eq!(
        std::fs::read_dir(&fx.paths.quarantine_dir).unwrap().count(),
        2
    );
    let cmds = rec.lock().unwrap().clone();
    assert_eq!(cmds.len(), 1);
    assert_eq!(cmds[0][0], "/usr/bin/systemd-run");
    assert!(cmds[0].contains(&future.to_hex()));

    let store = Store::open(&fx.paths.state_db).unwrap();
    let entries = store.audit().entries_since(0, 1000).unwrap();
    let count = |o: Outcome| {
        entries
            .iter()
            .filter(|e| e.actor == Actor::System && e.result == ResultSummary::Done(o))
            .count()
    };
    // expired, claimed, marked, stale_marker, interrupted (origin 999
    // missing).
    assert_eq!(count(Outcome::Reverted), 5);
    // The two quarantined files.
    assert_eq!(count(Outcome::Failed(ErrorCode::Internal)), 2);
    store.audit().verify_chain(1).unwrap();
}

/// A stand-in agent (compromised gate) speaking to the real client.
struct FakeAgent {
    s: UnixStream,
    t: Transport,
    reasm: Reassembler,
    next: u32,
    signer: Ed25519Signer,
    server: ServerId,
}

impl FakeAgent {
    async fn accept(mut s: UnixStream, fx: &Fixture) -> Self {
        let mode = s.read_u8().await.unwrap();
        let key = gate::load_noise_key(&fx.paths).unwrap();
        let mut hs = Handshake::responder(&key, &noise::prologue(mode)).unwrap();
        let m1 = frame::read_frame(&mut s, MAX_STREAM_FRAME)
            .await
            .unwrap()
            .unwrap();
        hs.read_message(&m1).unwrap();
        let m2 = hs.write_message(&[]).unwrap();
        frame::write_frame(&mut s, &m2, MAX_STREAM_FRAME)
            .await
            .unwrap();
        let m3 = frame::read_frame(&mut s, MAX_STREAM_FRAME)
            .await
            .unwrap()
            .unwrap();
        hs.read_message(&m3).unwrap();
        Self {
            s,
            t: hs.into_transport(now_ms()).unwrap(),
            reasm: Reassembler::for_exec(),
            next: 0,
            signer: exec::load_signing_key(&fx.paths).unwrap(),
            server: fx.server.clone(),
        }
    }

    async fn recv(&mut self) -> Message {
        loop {
            let ct = frame::read_frame(&mut self.s, MAX_STREAM_FRAME)
                .await
                .unwrap()
                .unwrap();
            let pt = self.t.decrypt(&ct).unwrap();
            if let Some((_, f)) = self.reasm.push(&pt).unwrap() {
                return decode(&f).unwrap();
            }
        }
    }

    async fn send(&mut self, msg: &Message) {
        self.next += 1;
        for c in split_frame(self.next, &encode(msg)) {
            let ct = self.t.encrypt(&c).unwrap();
            frame::write_frame(&mut self.s, &ct, MAX_STREAM_FRAME)
                .await
                .unwrap();
        }
    }

    /// Answers the next request with `result`, signed or not.
    async fn answer(&mut self, result: Result<Payload, ErrorCode>, signed: bool) {
        let Message::Request { id, cmd } = self.recv().await else {
            panic!("expected a request");
        };
        let receipt = signed.then(|| {
            sign_receipt(
                receipt_for(
                    self.server.clone(),
                    command_hash(&cmd),
                    None,
                    &result,
                    now_ms(),
                ),
                &self.signer,
            )
        });
        self.send(&Message::Response {
            id,
            result,
            receipt,
        })
        .await;
    }
}

#[test]
fn client_rejects_forged_events_and_unsigned_state_changes() {
    let fx = Fixture::new(1, 0);
    run(async {
        let (client_end, agent_end) = UnixStream::pair().unwrap();
        let m = &fx.macs[0];
        let op = fx.policy_op(2);
        let approval = fx.approve(m, &op);
        let client = async {
            let mut s = Session::connect(client_end, fx.cfg(m, KeyKind::Device))
                .await
                .unwrap();
            let e = s
                .request(op, &fx.server, Actor::Human, Some(approval))
                .await
                .unwrap_err();
            assert!(
                matches!(
                    e,
                    ClientError::OutcomeUnknown {
                        claimed: Some(ErrorCode::Internal)
                    }
                ),
                "{e}"
            );
            let e = s
                .request(Op::SystemInfo, &fx.server, Actor::Human, None)
                .await
                .unwrap_err();
            assert!(
                matches!(e, ClientError::MissingReceipt { claimed: None }),
                "{e}"
            );
            assert_eq!(
                s.take_events(),
                vec![
                    (1, Event::PolicyChanged { version: 9 }),
                    (4, Event::PolicyChanged { version: 9 })
                ]
            );
            // forged, repeat, other server, older run, stale time.
            assert_eq!(s.rejected_events(), 5);
            assert_eq!(s.event_gaps(), 1);
            // A signed Replay for a state-changing op: maybe it ran.
            let op = fx.policy_op(3);
            let approval = fx.approve(m, &op);
            let e = s
                .request(op, &fx.server, Actor::Human, Some(approval))
                .await
                .unwrap_err();
            assert!(
                matches!(
                    e,
                    ClientError::OutcomeUnknown {
                        claimed: Some(ErrorCode::Replay)
                    }
                ),
                "{e}"
            );
            // For a read it is just the (signed) error.
            let r = s
                .request(Op::SystemInfo, &fx.server, Actor::Human, None)
                .await
                .unwrap();
            assert_eq!(r.result, Err(ErrorCode::Replay));
        };
        let agent = async {
            let mut a = FakeAgent::accept(agent_end, &fx).await;
            assert!(matches!(a.recv().await, Message::DeviceAuth { .. }));
            a.send(&Message::Hello {
                proto_min: PROTO_VERSION,
                proto_max: PROTO_VERSION,
                agent_version: AgentVersion {
                    major: 0,
                    minor: 1,
                    patch: 0,
                },
                server_id: fx.server.clone(),
                time_ms: now_ms(),
                roster_epoch: 0,
                roster_version: 1,
                pending_recovery: None,
            })
            .await;
            let health = AgentHealth {
                agent_version: AgentVersion {
                    major: 0,
                    minor: 1,
                    patch: 0,
                },
                proto_version: PROTO_VERSION,
                uptime_s: 1,
                gate_rss_bytes: 0,
                exec_rss_bytes: 0,
                audit_seq: 1,
                roster_epoch: 0,
                roster_version: 1,
                policy_version: 1,
                pending_recovery: None,
                run_id: [9; 16],
            };
            a.answer(Ok(Payload::AgentHealth(health)), true).await;

            let ev = |run_id, seq, time_ms| {
                sign_event(
                    fx.server.clone(),
                    run_id,
                    seq,
                    time_ms,
                    Event::PolicyChanged { version: 9 },
                    &a.signer,
                )
            };
            let good = |seq| ev([9; 16], seq, now_ms());
            let forged = sign_event(
                fx.server.clone(),
                [9; 16],
                5,
                now_ms(),
                Event::PolicyChanged { version: 1 },
                &Ed25519Signer::from_seed(&[66; 32]),
            );
            let other_server = sign_event(
                ServerId::new("srv_other1").unwrap(),
                [9; 16],
                6,
                now_ms(),
                Event::PolicyChanged { version: 1 },
                &a.signer,
            );
            // Genuinely signed, but from an earlier exec run (huge seq).
            let old_run = ev([8; 16], 1_000_000, now_ms());
            // This run, but timed well before the session started.
            let stale = ev([9; 16], 2, now_ms() - 10 * 60_000);
            let (g1, g1_again, g4) = (good(1), good(1), good(4));
            let Message::Request { id, .. } = a.recv().await else {
                panic!()
            };
            for e in [forged, g1, g1_again, other_server, old_run, stale, g4] {
                a.send(&Message::Event(e)).await;
            }
            // An unsigned "failure" for a state-changing op.
            a.send(&Message::Response {
                id,
                result: Err(ErrorCode::Internal),
                receipt: None,
            })
            .await;
            a.answer(Ok(Payload::Empty), false).await;
            a.answer(Err(ErrorCode::Replay), true).await;
            a.answer(Err(ErrorCode::Replay), true).await;
        };
        tokio::join!(client, agent);
    });
}
