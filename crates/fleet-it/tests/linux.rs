//! Real agent in a systemd container, reached over SSH (see the crate docs).
//! Every test is `#[ignore]`: run `tests/vm/run.sh`, or build the agent and
//! image yourself and run `cargo test -p fleet-it -- --ignored
//! --test-threads=1 --nocapture`.

use fleet_core::ssh::{AgentStream, SshConnection};
use fleet_core::{ClientError, CommandOpts, Session};
use fleet_crypto::stream::{StreamItem, StreamVerifier};
use fleet_crypto::verify::command_hash;
use fleet_it::{AUTO_REVERT_SECONDS, Fixture, STEP, fixture, run};
use fleet_proto::args::{
    AbsPath, FirewallMode, FirewallRule, FirewallRuleSet, FwAction, FwChain, FwComment,
    GrepPattern, JournalQuery, ModuleId, Pid, Port, PortRange, Protocol, Signal, SudoPasswordHash,
    TimeRange, UnitName,
};
use fleet_proto::op::{ProfileLevel, ProfilePhase, ProfileSource, ProfileSpec, SampleInterval};
use fleet_proto::payload::{ConfigVersion, FirewallState, ModuleOutcome, ProfileApplied};
use fleet_proto::{Actor, ChangeId, ErrorCode, Message, Op, Payload, decode};
use std::net::IpAddr;
use std::time::{Duration, Instant};

const LIMIT: Duration = Duration::from_secs(90);

/// Connects `macs[0]`, sends `op`, returns the (receipt-verified) payload.
fn read(fx: &'static Fixture, op: Op) -> Payload {
    let mut out = None;
    run(LIMIT, async {
        let m = &fx.macs[0];
        let conn = fx.ssh(m).await.unwrap();
        let mut s = fx.session(&conn, m).await.unwrap().unwrap();
        let r = tokio::time::timeout(STEP, s.request(op, &fx.server, Actor::Human, None))
            .await
            .expect("request timed out")
            .expect("request failed");
        out = Some(r.result.expect("agent returned an error"));
        conn.disconnect().await;
    });
    out.unwrap()
}

#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn system_info_signed_round_trip() {
    let fx = fixture();
    let Payload::SystemInfo(i) = read(fx, Op::SystemInfo) else {
        panic!("wrong payload")
    };
    eprintln!(
        "system.info: host={} os={} {} kernel={} arch={} cpus={} (container: {})",
        i.hostname, i.os_id, i.os_version, i.kernel, i.arch, i.cpu_count, fx.os
    );
    assert!(
        matches!(i.os_id.as_str(), "debian" | "ubuntu"),
        "{}",
        i.os_id
    );
    assert!(i.cpu_count > 0 && i.mem_total_bytes > 0);
}

#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn agent_health_signed() {
    let fx = fixture();
    let Payload::AgentHealth(h) = read(fx, Op::AgentHealth) else {
        panic!("wrong payload")
    };
    eprintln!(
        "agent.health: v{}.{}.{} roster v{} policy v{} audit_seq {} gate_rss {} exec_rss {}",
        h.agent_version.major,
        h.agent_version.minor,
        h.agent_version.patch,
        h.roster_version,
        h.policy_version,
        h.audit_seq,
        h.gate_rss_bytes,
        h.exec_rss_bytes
    );
    assert_eq!(h.roster_epoch, 0);
    assert!(h.roster_version >= 1);
}

#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn journal_query_returns_entries() {
    let fx = fixture();
    let q = JournalQuery {
        units: vec![],
        priority: None,
        range: Default::default(),
        grep: None,
        after_cursor: None,
        limit: 50,
    };
    let Payload::JournalEntries(j) = read(fx, Op::JournalQuery(q)) else {
        panic!("wrong payload")
    };
    eprintln!("journal.query: {} entries", j.entries.len());
    assert!(!j.entries.is_empty());
}

#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn unit_list_over_dbus() {
    let fx = fixture();
    let Payload::Units(u) = read(fx, Op::UnitList) else {
        panic!("wrong payload")
    };
    let names: Vec<&str> = u.units.iter().map(|u| u.name.as_str()).collect();
    eprintln!("unit.list: {} units", names.len());
    for want in ["fleet-exec.service", "fleet-gate.service"] {
        assert!(names.contains(&want), "{want} missing");
    }
    assert!(
        names.iter().any(|n| n.starts_with("ssh")),
        "no ssh unit in {names:?}"
    );
}

#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn pkg_list_reads_dpkg() {
    let fx = fixture();
    let Payload::Packages(p) = read(fx, Op::PkgList { filter: None }) else {
        panic!("wrong payload")
    };
    eprintln!("pkg.list: {} packages", p.packages.len());
    assert!(p.packages.iter().any(|p| p.name == "openssh-server"));
}

#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn ports_list_shows_sshd() {
    let fx = fixture();
    let Payload::Ports(p) = read(fx, Op::PortsList) else {
        panic!("wrong payload")
    };
    let ssh: Vec<_> = p.ports.iter().filter(|p| p.port == 22).collect();
    eprintln!("ports.list: {} listening; :22 → {:?}", p.ports.len(), ssh);
    assert!(!ssh.is_empty(), "port 22 not listed");
    // Ubuntu 24.04 socket-activates sshd (ssh.socket): PID 1 holds :22.
    assert!(
        ssh.iter().any(|p| p
            .process
            .as_deref()
            .is_some_and(|n| n.contains("sshd") || n == "systemd")),
        "port 22 not attributed to sshd or ssh.socket"
    );
}

#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn metrics_subscribe_streams_samples() {
    let fx = fixture();
    run(LIMIT, async {
        let m = &fx.macs[0];
        let conn = fx.ssh(m).await.unwrap();
        let mut raw = fleet_it::RawSession::open(fx, &conn, m).await.unwrap();
        let cmd = fx
            .signed(
                m,
                Op::MetricsSubscribe {
                    interval: SampleInterval::OneSecond,
                },
            )
            .unwrap();
        let mut v = StreamVerifier::new(fx.agent_signing, fx.server.clone(), command_hash(&cmd));
        raw.send(&Message::StreamOpen { id: 1, cmd }).await.unwrap();
        let (mut samples, mut other) = (0, 0);
        tokio::time::timeout(Duration::from_secs(30), async {
            while samples < 2 {
                match raw.recv().await.unwrap() {
                    Message::StreamData { id: 1, seq, chunk } => {
                        match v.accept(seq, &chunk).expect("chunk verifies") {
                            StreamItem::Data(d) => match decode::<Payload>(&d).unwrap() {
                                Payload::MetricsSample(_) => samples += 1,
                                _ => other += 1,
                            },
                            StreamItem::Checkpoint { .. } => {}
                            StreamItem::Final { outcome, .. } => {
                                panic!("stream finished early: {outcome:?}")
                            }
                        }
                    }
                    Message::StreamEnd { id: 1, status } => {
                        panic!("stream ended: {status:?}")
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("fewer than 2 samples in 30 s");
        eprintln!("metrics.subscribe: {samples} verified samples ({other} other items)");
        raw.send(&Message::StreamCancel { id: 1 }).await.unwrap();
        conn.disconnect().await;
    });
}

/// Runs last-ish by name; changes the roster (removes `macs[1]`), which no
/// other test depends on.
#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn revoked_device_rejected_after_roster_update() {
    let fx = fixture();
    let (m0, m1) = (&fx.macs[0], &fx.macs[1]);
    run(LIMIT, async {
        let c0 = fx.ssh(m0).await.unwrap();
        let mut s0 = fx.session(&c0, m0).await.unwrap().unwrap();
        let c1 = fx.ssh(m1).await.unwrap();
        let mut s1 = fx.session(&c1, m1).await.unwrap().unwrap();
        let r = s1
            .request(Op::SystemInfo, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert!(r.result.is_ok(), "mac B works before revocation");

        let v2 = fx.roster_without(m0, m1).unwrap();
        let r = s0
            .request(
                Op::RosterUpdate {
                    roster: Box::new(v2),
                },
                &fx.server,
                Actor::Human,
                None,
            )
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty), "roster.update accepted");

        // Open session: ended by the gate, or refused by exec.
        match tokio::time::timeout(
            STEP,
            s1.request(Op::SystemInfo, &fx.server, Actor::Human, None),
        )
        .await
        .expect("timed out")
        {
            Ok(r) => assert_eq!(r.result, Err(ErrorCode::Unauthorized)),
            Err(e) => assert!(matches!(e, ClientError::Closed | ClientError::Io(_)), "{e}"),
        }
        // Before provisioning, SSH still works (keys in ~/.ssh) and the
        // agent refuses. Once `provision_*` has hardened sshd
        // (`AuthorizedKeysFile /etc/fleet/authorized_keys/%u`, rewritten
        // from the roster), sshd itself refuses the removed Mac's key.
        match fx.ssh(m1).await {
            Ok(c1b) => match fx.session(&c1b, m1).await.unwrap() {
                Err(ClientError::Rejected(ErrorCode::Unauthorized)) => {
                    eprintln!("revocation: open session cut, new session Unauthorized");
                }
                Err(e) => panic!("unexpected error: {e}"),
                Ok(_) => panic!("revoked device got a session"),
            },
            Err(e) => {
                assert!(e.contains("refused our key"), "{e}");
                eprintln!("revocation: open session cut, SSH key refused by sshd");
            }
        }
    });
}

#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn gate_sandbox_exposure() {
    let fx = fixture();
    let c = &fx.container;
    for unit in ["fleet-gate.service", "fleet-exec.service"] {
        // Non-zero exit when the score is above the (default 100) threshold;
        // the score line is what matters.
        let (_, out) = c.exec_status(&["systemd-analyze", "security", "--no-pager", unit], 60);
        let line = out
            .lines()
            .find(|l| l.contains("Overall exposure level"))
            .unwrap_or("no score line");
        eprintln!("systemd-analyze security {unit}: {}", line.trim());
        if unit == "fleet-gate.service" {
            assert!(line.contains("Overall exposure level"), "{out}");
        }
    }
    // The gate really runs unprivileged, in its own network namespace
    // (PrivateNetwork=yes) without the container's uplink.
    let pid = c.main_pid("fleet-gate.service").unwrap();
    let status = c.exec(&["cat", &format!("/proc/{pid}/status")]).unwrap();
    let uid = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned();
    assert_ne!(uid, "0", "gate runs as root");
    let dev = c.exec(&["cat", &format!("/proc/{pid}/net/dev")]).unwrap();
    let ifaces: Vec<&str> = dev
        .lines()
        .skip(2)
        .filter_map(|l| l.split(':').next().map(str::trim))
        .collect();
    let ns = |p: &str| {
        c.exec(&["readlink", &format!("/proc/{p}/ns/net")])
            .unwrap()
            .trim()
            .to_owned()
    };
    let (gate_ns, host_ns) = (ns(&pid.to_string()), ns("1"));
    eprintln!("gate uid {uid}, netns {gate_ns} (PID 1: {host_ns}), interfaces {ifaces:?}");
    assert_ne!(gate_ns, host_ns, "gate shares the host network namespace");
    // A fresh namespace also holds the kernel's fallback tunnel devices
    // (sit0, gre0, …: down, no addresses); only `eth*` would mean an uplink.
    assert!(
        !ifaces.iter().any(|i| i.starts_with("eth")),
        "gate sees an uplink: {ifaces:?}"
    );
}

/// Advisory (design §11 budgets): reports, never fails on the numbers.
#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn idle_memory_report() {
    let fx = fixture();
    let mib = |b: u64| b as f64 / (1024.0 * 1024.0);
    let (gate, exec) = fx.idle_rss;
    let verdict = |b: u64, budget: f64| if mib(b) <= budget { "ok" } else { "OVER" };
    eprintln!(
        "idle RSS (right after start): gate {:.2} MiB (budget 5, {}), exec {:.2} MiB (budget 20, {})",
        mib(gate),
        verdict(gate, 5.0),
        mib(exec),
        verdict(exec, 20.0)
    );
    let now = (
        fx.container.rss_bytes("fleet-gate.service").unwrap(),
        fx.container.rss_bytes("fleet-exec.service").unwrap(),
    );
    eprintln!(
        "RSS now (after other tests in this run): gate {:.2} MiB, exec {:.2} MiB",
        mib(now.0),
        mib(now.1)
    );
    assert!(gate > 0 && exec > 0);
}

/// `profile.check` + `profile.plan` of Baseline against the real system
/// (read-only; nothing is applied).
#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn profile_check_and_plan() {
    use fleet_proto::op::{ProfileLevel, ProfileSource, ProfileSpec};
    let fx = fixture();
    let spec = ProfileSpec {
        source: ProfileSource::Builtin {
            level: ProfileLevel::Baseline,
            roles: vec![],
        },
        only: vec![],
    };
    let Payload::ProfileCheck(c) = read(fx, Op::ProfileCheck(spec.clone())) else {
        panic!("wrong payload")
    };
    eprintln!("profile.check: score {} ({})", c.score, fx.os);
    for m in &c.modules {
        eprintln!(
            "  {:<18} {:?} {}",
            m.id,
            m.status,
            m.detail.lines().next().unwrap_or("")
        );
    }
    assert!(c.modules.iter().any(|m| m.id == "ssh.hardening"));
    assert!(c.score <= 100);
    let Payload::ProfilePlan(p) = read(fx, Op::ProfilePlan(spec)) else {
        panic!("wrong payload")
    };
    eprintln!("profile.plan: {} changes", p.changes.len());
    for ch in &p.changes {
        eprintln!("  {:<18} {}", ch.module, ch.description);
    }
    assert!(!p.changes.is_empty());
}

// ---------------------------------------------------------------- helpers
//
// Tests run in name order (`--test-threads=1`); the state-changing ones
// below are named so that `bans_*` creates `table inet fleet` before
// `firewall_*` switches it to Managed, and `provision_*` (which hardens
// sshd and the firewall) runs after the read-only profile test.

type Sess = Session<'static, AgentStream>;

async fn open(fx: &'static Fixture) -> (SshConnection, Sess) {
    let m = &fx.macs[0];
    let conn = fx.ssh(m).await.expect("ssh");
    let s = fx
        .session(&conn, m)
        .await
        .expect("agent channel")
        .expect("session");
    (conn, s)
}

async fn call_within(
    s: &mut Sess,
    fx: &Fixture,
    op: Op,
    limit: Duration,
) -> Result<Payload, ErrorCode> {
    // Elevated ops (e.g. `profile.apply` with a sudo password hash) carry
    // a root-key approval from the test Mac, as the app's Touch ID would.
    let approval = (op.authorization() == fleet_proto::Authorization::RootApproval)
        .then(|| approval_for(fx, &op));
    tokio::time::timeout(limit, s.request(op, &fx.server, Actor::Human, approval))
        .await
        .expect("request timed out")
        .expect("request failed")
        .result
}

/// A one-item root-key approval of `op` for the fixture's server, signed
/// by `macs[0]` (valid for five minutes).
fn approval_for(fx: &Fixture, op: &Op) -> fleet_proto::RootApproval {
    use fleet_crypto::approval::{ApprovalParams, build_approvals, op_digest};
    let m = &fx.macs[0];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let mut approval_id = [0u8; 16];
    fleet_crypto::random_bytes(&mut approval_id).unwrap();
    let params = ApprovalParams {
        fleet_id: fx.fleet,
        approval_id,
        issued_at_ms: now,
        expires_at_ms: now + 5 * 60_000,
    };
    let item = fleet_proto::ApprovalItem {
        server_id: fx.server.clone(),
        op_digest: op_digest(op, None),
    };
    build_approvals(&m.keys.root, m.id, &params, &[item])
        .unwrap()
        .remove(0)
}

async fn call(s: &mut Sess, fx: &Fixture, op: Op) -> Result<Payload, ErrorCode> {
    call_within(s, fx, op, STEP).await
}

/// `change.confirm` over a new SSH connection and session (exec requires
/// sshd to have logged that login).
async fn confirm(fx: &'static Fixture, id: ChangeId) -> Result<Payload, ErrorCode> {
    let (c, mut s) = open(fx).await;
    let r = call(&mut s, fx, Op::ChangeConfirm { change_id: id }).await;
    c.disconnect().await;
    r
}

async fn sleep(secs: u64) {
    tokio::time::sleep(Duration::from_secs(secs)).await;
}

/// Runs a blocking closure (docker CLI) off the runtime thread, so SSH
/// connections keep being serviced.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.expect("blocking task")
}

fn image() -> String {
    std::env::var("FLEET_IT_IMAGE").unwrap_or_else(|_| "fleet-it:debian12".into())
}

fn accept_tcp(port: u16, comment: &str) -> FirewallRule {
    FirewallRule {
        chain: FwChain::Input,
        action: FwAction::Accept,
        proto: Protocol::Tcp,
        ports: vec![PortRange::single(Port::new(port).unwrap())],
        source: None,
        rate_limit: None,
        comment: FwComment::new(comment).unwrap(),
    }
}

async fn fw_get(s: &mut Sess, fx: &Fixture) -> FirewallState {
    match call(s, fx, Op::FirewallGet).await {
        Ok(Payload::Firewall(f)) => f,
        other => panic!("firewall.get: {other:?}"),
    }
}

/// `firewall.apply` needs `expected_version` (the version the operator
/// saw), which `Session::request` doesn't set.
async fn fw_apply(
    s: &mut Sess,
    fx: &Fixture,
    set: FirewallRuleSet,
    version: u64,
) -> Result<Payload, ErrorCode> {
    let opts = CommandOpts {
        expected_version: Some(version),
        ..Default::default()
    };
    let cmd = s
        .build_command(
            Op::FirewallApply(set),
            &fx.server,
            Actor::Human,
            None,
            &opts,
        )
        .expect("sign");
    tokio::time::timeout(STEP, s.send(&cmd))
        .await
        .expect("firewall.apply timed out")
        .expect("firewall.apply failed")
        .result
}

fn nft(fx: &Fixture, args: &[&str]) -> String {
    let mut argv = vec!["nft"];
    argv.extend_from_slice(args);
    fx.container.exec_status(&argv, 30).1
}

/// Creates `table inet fleet` (bans need its sets) with a confirmed
/// bans-only apply, unless a Fleet firewall is already there.
async fn ensure_fleet_table(fx: &'static Fixture) {
    let (c, mut s) = open(fx).await;
    let st = fw_get(&mut s, fx).await;
    if st.version == 0 {
        let set = FirewallRuleSet {
            mode: FirewallMode::BansOnly,
            rules: vec![],
        };
        match fw_apply(&mut s, fx, set, 0).await {
            Ok(Payload::ChangePending { change, .. }) => {
                let r = confirm(fx, change.change_id).await;
                assert!(r.is_ok(), "confirm bans-only: {r:?}");
            }
            other => panic!("bans-only apply: {other:?}"),
        }
    }
    c.disconnect().await;
}

async fn bans_list(s: &mut Sess, fx: &Fixture) -> fleet_proto::payload::Bans {
    match call(s, fx, Op::BansList).await {
        Ok(Payload::Bans(b)) => b,
        other => panic!("bans.list: {other:?}"),
    }
}

fn container_ip(fx: &Fixture) -> String {
    fleet_it::docker(
        &[
            "inspect",
            "-f",
            // Newer Docker API versions dropped the top-level field.
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            &fx.container.name,
        ],
        Duration::from_secs(10),
    )
    .expect("docker inspect")
    .trim()
    .to_owned()
}

/// `n` failed logins (nonexistent user, no key offered) against
/// `target:22` from a throwaway sibling container on the Docker bridge.
/// Returns the sibling's address. Each attempt is capped: once the ban
/// lands mid-handshake, packets are dropped and ssh would wait for TCP.
fn sibling_failures(target: &str, n: u32) -> IpAddr {
    const SCRIPT: &str = r#"
        echo "sibling $(hostname -i)"
        i=0
        while [ "$i" -lt "$2" ]; do
            timeout 10 ssh -o BatchMode=yes -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
                -o LogLevel=ERROR "fleet-it-nosuchuser@$1" true >/dev/null 2>&1
            i=$((i + 1))
        done
    "#;
    let n = n.to_string();
    let img = image();
    let out = fleet_it::docker(
        &[
            "run",
            "--rm",
            "--label",
            "fleet-it=1",
            "--entrypoint",
            "/bin/sh",
            &img,
            "-c",
            SCRIPT,
            "sh",
            target,
            &n,
        ],
        Duration::from_secs(180),
    )
    .expect("sibling container");
    out.lines()
        .find_map(|l| l.strip_prefix("sibling "))
        .and_then(|l| l.split_whitespace().next())
        .and_then(|a| a.parse().ok())
        .unwrap_or_else(|| panic!("no sibling address in {out:?}"))
}

// ---------------------------------------------------------------- bans

/// Real sshd failures (journald → exec's sshd source) ban a sibling
/// container's address in `banned4`; the same failures from the Mac's
/// address (learned from its Fleet login) never ban it.
#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn bans_sshd_failures_ban_sibling_not_learned_mac() {
    let fx = fixture();
    run(Duration::from_secs(300), async {
        ensure_fleet_table(fx).await;
        // A fresh Fleet login: exec learns (and exempts) this address.
        let (c, mut s) = open(fx).await;
        match call(&mut s, fx, Op::BansConfigGet).await {
            Ok(p) => eprintln!("bans.config: {p:?}"),
            Err(e) => eprintln!("bans.config.get: {e:?}"),
        }
        let t0 = Instant::now();
        let mut b = bans_list(&mut s, fx).await;
        while b.learned_exempt.is_empty() && t0.elapsed() < Duration::from_secs(15) {
            sleep(1).await;
            b = bans_list(&mut s, fx).await;
        }
        eprintln!(
            "bans: learned_exempt {:?} after {:?}",
            b.learned_exempt,
            t0.elapsed()
        );
        assert!(!b.learned_exempt.is_empty(), "Mac address not learned");
        let mac_ip = b.learned_exempt[0];

        // Failures from the Mac's own address: an unknown user.
        for _ in 0..6 {
            let r = fx.ssh_as("fleet-it-nosuchuser", &fx.macs[0]).await;
            assert!(r.is_err(), "unknown user logged in");
        }

        // The same from a sibling container.
        let ip = container_ip(fx);
        let sib = blocking(move || sibling_failures(&ip, 7)).await;
        eprintln!("bans: sibling {sib} made 7 failed attempts (Mac address {mac_ip})");
        let t0 = Instant::now();
        let banned = loop {
            let b = bans_list(&mut s, fx).await;
            if let Some(e) = b.bans.iter().find(|e| e.addr == sib) {
                break Some((e.clone(), b));
            }
            if t0.elapsed() > Duration::from_secs(30) {
                eprintln!("bans: no ban after 30 s: {b:?}");
                break None;
            }
            sleep(1).await;
        };
        let (entry, b) = banned.expect("sibling not banned");
        eprintln!("bans: {entry:?} after {:?}", t0.elapsed());
        assert!(
            !b.bans.iter().any(|e| e.addr == mac_ip),
            "learned Mac address banned: {b:?}"
        );
        let set = nft(fx, &["list", "set", "inet", "fleet", "banned4"]);
        assert!(
            set.contains(&sib.to_string()),
            "{sib} not in banned4: {set}"
        );
        assert!(
            !set.contains(&format!(" {mac_ip}")),
            "Mac address in banned4"
        );

        let r = call(&mut s, fx, Op::BansRemove { addr: sib }).await;
        assert!(r.is_ok(), "bans.remove: {r:?}");
        let set = nft(fx, &["list", "set", "inet", "fleet", "banned4"]);
        assert!(!set.contains(&sib.to_string()), "still in banned4: {set}");
        c.disconnect().await;
    });
}

// ---------------------------------------------------------------- config history

async fn history(s: &mut Sess, fx: &Fixture, path: &str) -> Vec<ConfigVersion> {
    let op = Op::ConfigHistory {
        path: Some(AbsPath::new(path).unwrap()),
        range: TimeRange::default(),
        limit: 200,
    };
    match call(s, fx, op).await {
        Ok(Payload::ConfigHistory(h)) => {
            let mut v = h.versions;
            v.sort_by_key(|v| v.version);
            v
        }
        other => panic!("config.history {path}: {other:?}"),
    }
}

/// Polls until `path` has more than `before` versions (30 s).
async fn wait_versions(
    s: &mut Sess,
    fx: &Fixture,
    path: &str,
    before: usize,
) -> Vec<ConfigVersion> {
    let t0 = Instant::now();
    loop {
        let v = history(s, fx, path).await;
        if v.len() > before {
            eprintln!(
                "config.history {path}: {} → {} versions after {:?}",
                before,
                v.len(),
                t0.elapsed()
            );
            return v;
        }
        assert!(
            t0.elapsed() < Duration::from_secs(30),
            "no new version of {path} within 30 s"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn diff(s: &mut Sess, fx: &Fixture, path: &str, from: u64, to: Option<u64>) -> String {
    let op = Op::ConfigDiff {
        path: AbsPath::new(path).unwrap(),
        from,
        to,
    };
    match call(s, fx, op).await {
        Ok(Payload::ConfigDiff(d)) => d.unified,
        other => panic!("config.diff {path}: {other:?}"),
    }
}

/// inotify on `/etc`: an edit shows up in `config.history` and
/// `config.diff`; `/etc/shadow` is recorded as a hash only.
#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn config_history_inotify_and_secret_hash_only() {
    let fx = fixture();
    let c = &fx.container;
    run(Duration::from_secs(180), async {
        let (conn, mut s) = open(fx).await;
        // Not /etc/hosts: Docker bind-mounts it over /etc, and inotify on
        // the /etc directory sees no events for a mounted-over file (on a
        // real host it is a plain file). A regular file under /etc instead.
        let path = "/etc/fleet-it-confighist.conf";
        let mut v = history(&mut s, fx, path).await;
        // Create, then edit: two versions to diff.
        for n in 1..=2 {
            let line = format!("echo 'fleet-it-confighist {n}' >> {path}");
            c.exec(&["sh", "-c", &line]).unwrap();
            v = wait_versions(&mut s, fx, path, v.len()).await;
        }
        let (a, b) = (&v[v.len() - 2], &v[v.len() - 1]);
        eprintln!("config.history {path}: {a:?}\n  → {b:?}");
        assert!(!b.secret && !b.deleted);
        let d = diff(&mut s, fx, path, a.version, Some(b.version)).await;
        eprintln!("config.diff {path}:\n{d}");
        assert!(d.contains("+fleet-it-confighist 2"), "{d}");

        let shadow = "/etc/shadow";
        let before = history(&mut s, fx, shadow).await;
        c.exec(&["chage", "-W", "9", "ops"]).unwrap();
        let after = wait_versions(&mut s, fx, shadow, before.len()).await;
        let last = after.last().unwrap();
        eprintln!("config.history /etc/shadow: {last:?}");
        assert!(last.secret, "/etc/shadow not marked secret");
        let from = after
            .get(after.len().wrapping_sub(2))
            .unwrap_or(last)
            .version;
        let d = diff(&mut s, fx, shadow, from, Some(last.version)).await;
        eprintln!("config.diff /etc/shadow: {d}");
        assert!(
            !d.contains("ops:") && !d.contains("root:"),
            "secret content leaked: {d}"
        );
        conn.disconnect().await;
    });
}

// ---------------------------------------------------------------- firewall

/// Managed ruleset with SSH → pending → confirmed over a new session →
/// survives its deadline; a second apply left unconfirmed is reverted by
/// the deadline (checked in the kernel with `nft`).
#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn firewall_managed_confirm_then_auto_revert() {
    let fx = fixture();
    let secs = u64::from(AUTO_REVERT_SECONDS);
    run(Duration::from_secs(120 + 3 * secs), async {
        let (c, mut s) = open(fx).await;
        let st = fw_get(&mut s, fx).await;
        eprintln!(
            "firewall.get: {:?} v{} rules {} banned {} foreign {} bytes",
            st.mode,
            st.version,
            st.rules.len(),
            st.banned,
            st.foreign_ruleset.len()
        );
        let managed = FirewallRuleSet {
            mode: FirewallMode::Managed,
            rules: vec![accept_tcp(22, "ssh")],
        };
        let change = match fw_apply(&mut s, fx, managed.clone(), st.version).await {
            Ok(Payload::ChangePending { change, .. }) => change,
            other => panic!("firewall.apply: {other:?}"),
        };
        let window = change.deadline_ms.saturating_sub(change.created_ms);
        eprintln!("firewall.apply Managed: pending, window {window} ms, {change:?}");
        assert!(window <= (secs + 1) * 1000, "window {window} ms");
        let table = nft(fx, &["list", "table", "inet", "fleet"]);
        assert!(
            table.contains("dport 22"),
            "no ssh rule in the kernel:\n{table}"
        );

        let r = confirm(fx, change.change_id).await;
        assert!(r.is_ok(), "change.confirm: {r:?}");
        // The confirmed state outlives the deadline.
        sleep(secs + 5).await;
        let (c2, mut s2) = open(fx).await;
        let st1 = fw_get(&mut s2, fx).await;
        assert_eq!(st1.mode, FirewallMode::Managed);
        assert_eq!(st1.rules, managed.rules);
        let confirmed_version = st1.version;
        let changes = call(&mut s2, fx, Op::ChangesList).await;
        eprintln!("firewall: confirmed v{confirmed_version}; changes.list {changes:?}");
        let before = nft(fx, &["list", "table", "inet", "fleet"]);
        assert!(!before.contains("dport 8080"));

        // Second apply, never confirmed.
        let mut more = managed.clone();
        more.rules.push(accept_tcp(8080, "it-temp"));
        let change = match fw_apply(&mut s2, fx, more, confirmed_version).await {
            Ok(Payload::ChangePending { change, .. }) => change,
            other => panic!("second firewall.apply: {other:?}"),
        };
        let table = nft(fx, &["list", "table", "inet", "fleet"]);
        assert!(table.contains("dport 8080"), "second apply not in kernel");
        let t0 = Instant::now();
        loop {
            sleep(2).await;
            let table = nft(fx, &["list", "table", "inet", "fleet"]);
            if !table.contains("dport 8080") {
                eprintln!(
                    "firewall: reverted {:?} after apply (deadline {} ms after creation)",
                    t0.elapsed(),
                    change.deadline_ms - change.created_ms
                );
                assert!(table.contains("dport 22"), "ssh rule lost:\n{table}");
                break;
            }
            assert!(
                t0.elapsed() < Duration::from_secs(secs + 45),
                "not reverted {:?} after apply:\n{table}",
                t0.elapsed()
            );
        }
        let st2 = fw_get(&mut s2, fx).await;
        eprintln!("firewall.get after revert: {:?} v{}", st2.mode, st2.version);
        assert_eq!(st2.mode, FirewallMode::Managed);
        assert_eq!(st2.rules, managed.rules);
        c2.disconnect().await;
        c.disconnect().await;
    });
}

// ---------------------------------------------------------------- streams

/// Opens `op` as a verified stream; feeds items to `f` until it returns
/// true, the stream ends, or `limit` passes. Returns (items, ended).
async fn stream(
    fx: &'static Fixture,
    op: Op,
    limit: Duration,
    mut f: impl FnMut(&Payload) -> bool,
) -> (usize, bool) {
    let m = &fx.macs[0];
    let conn = fx.ssh(m).await.unwrap();
    let mut raw = fleet_it::RawSession::open(fx, &conn, m).await.unwrap();
    let cmd = fx.signed(m, op).unwrap();
    let mut v = StreamVerifier::new(fx.agent_signing, fx.server.clone(), command_hash(&cmd));
    raw.send(&Message::StreamOpen { id: 1, cmd }).await.unwrap();
    let (mut n, mut ended) = (0, false);
    let r = tokio::time::timeout(limit, async {
        loop {
            match raw.recv().await.unwrap() {
                Message::StreamData { id: 1, seq, chunk } => {
                    match v.accept(seq, &chunk).expect("chunk verifies") {
                        StreamItem::Data(d) => {
                            n += 1;
                            if f(&decode::<Payload>(&d).unwrap()) {
                                return;
                            }
                        }
                        StreamItem::Checkpoint { .. } => {}
                        StreamItem::Final { outcome, .. } => {
                            eprintln!("stream final: {outcome:?}");
                            ended = true;
                            return;
                        }
                    }
                }
                Message::StreamEnd { id: 1, status } => {
                    eprintln!("stream end: {status:?}");
                    ended = true;
                    return;
                }
                _ => {}
            }
        }
    })
    .await;
    if r.is_err() {
        eprintln!("stream: no end within {limit:?}");
    }
    let _ = raw.send(&Message::StreamCancel { id: 1 }).await;
    conn.disconnect().await;
    (n, ended)
}

#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn journal_follow_streams_new_entries() {
    let fx = fixture();
    let name = fx.container.name.clone();
    // Log a marker every second for a while (the stream opens meanwhile).
    let logger = std::thread::spawn(move || {
        for i in 0..15 {
            std::thread::sleep(Duration::from_secs(1));
            let msg = format!("fleet-it-follow {i}");
            let _ = fleet_it::docker(
                &["exec", &name, "logger", "-t", "fleet-it", &msg],
                Duration::from_secs(10),
            );
        }
    });
    let q = JournalQuery {
        units: vec![],
        priority: None,
        range: TimeRange::default(),
        grep: Some(GrepPattern::new("fleet-it-follow").unwrap()),
        after_cursor: None,
        limit: 100,
    };
    let mut seen = Vec::new();
    run(LIMIT, async {
        stream(fx, Op::JournalFollow(q), Duration::from_secs(30), |p| {
            if let Payload::JournalEntries(j) = p {
                seen.extend(j.entries.iter().map(|e| e.message.clone()));
            }
            seen.len() >= 2
        })
        .await;
    });
    let _ = logger.join();
    eprintln!("journal.follow: {} matching entries: {seen:?}", seen.len());
    assert!(
        seen.iter().any(|m| m.starts_with("fleet-it-follow")),
        "no followed entries"
    );
}

#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn logfile_tail_var_log_allowed_etc_refused() {
    let fx = fixture();
    let mut lines = Vec::new();
    run(LIMIT, async {
        let op = Op::LogfileTail {
            path: AbsPath::new("/var/log/dpkg.log").unwrap(),
            lines: 20,
            follow: false,
        };
        let (n, ended) = stream(fx, op, Duration::from_secs(20), |p| {
            if let Payload::LogLines(l) = p {
                lines.extend(l.lines.iter().cloned());
            }
            false
        })
        .await;
        eprintln!(
            "logfile.tail /var/log/dpkg.log: {n} items, {} lines, ended {ended}; last {:?}",
            lines.len(),
            lines.last()
        );
        let op = Op::LogfileTail {
            path: AbsPath::new("/etc/shadow").unwrap(),
            lines: 5,
            follow: false,
        };
        let (n, ended) = stream(fx, op, Duration::from_secs(20), |_| false).await;
        eprintln!("logfile.tail /etc/shadow: {n} items, ended {ended}");
        assert_eq!(n, 0, "/etc/shadow was tailed");
        assert!(ended);
    });
    assert!(
        !lines.is_empty() && lines.len() <= 20,
        "{} lines",
        lines.len()
    );
}

// ---------------------------------------------------------------- packages

#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn pkg_upgradable_simulates() {
    let fx = fixture();
    let Payload::Upgradable(u) = read(fx, Op::PkgUpgradable) else {
        panic!("wrong payload")
    };
    eprintln!(
        "pkg.upgradable: {} packages ({} security), reboot_required {}, lists {:?}",
        u.packages.len(),
        u.packages.iter().filter(|p| p.security).count(),
        u.reboot_required,
        u.lists_updated_ms
    );
}

// ---------------------------------------------------------------- processes

fn pgrep(fx: &Fixture, args: &[&str]) -> Option<u32> {
    let mut argv = vec!["pgrep"];
    argv.extend_from_slice(args);
    let (_, out) = fx.container.exec_status(&argv, 10);
    out.lines().next().and_then(|l| l.trim().parse().ok())
}

/// `process.signal` goes through pidfd on Linux: refused for sshd (a
/// protected unit's cgroup), delivered to an ordinary user's process.
#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn process_signal_refuses_sshd_allows_user_process() {
    let fx = fixture();
    let c = &fx.container;
    fleet_it::docker(
        &["exec", "-d", "-u", "ops", &c.name, "sleep", "6001"],
        Duration::from_secs(10),
    )
    .unwrap();
    let t0 = Instant::now();
    let sleeper = loop {
        if let Some(p) = pgrep(fx, &["-u", "ops", "-f", "sleep 6001"]) {
            break p;
        }
        assert!(t0.elapsed() < Duration::from_secs(10), "sleep not started");
        std::thread::sleep(Duration::from_millis(200));
    };
    let sshd = match c.main_pid("ssh.service").unwrap() {
        0 => pgrep(fx, &["-o", "-x", "sshd"]).expect("no sshd"),
        p => p,
    };
    let cg = c.exec(&["cat", &format!("/proc/{sshd}/cgroup")]).unwrap();
    eprintln!(
        "process.signal: sshd pid {sshd} ({}), sleep pid {sleeper}",
        cg.trim()
    );
    run(LIMIT, async {
        let (conn, mut s) = open(fx).await;
        for signal in [Signal::Term, Signal::Kill, Signal::Hup] {
            let op = Op::ProcessSignal {
                pid: Pid::new(sshd).unwrap(),
                signal,
            };
            let r = call(&mut s, fx, op).await;
            eprintln!("process.signal sshd {signal:?}: {r:?}");
            assert_eq!(r, Err(ErrorCode::PolicyDenied), "sshd {signal:?}");
        }
        let op = Op::ProcessSignal {
            pid: Pid::new(sleeper).unwrap(),
            signal: Signal::Term,
        };
        let r = call(&mut s, fx, op).await;
        eprintln!("process.signal sleep Term: {r:?}");
        assert_eq!(r, Ok(Payload::Empty));
        conn.disconnect().await;
    });
    let t0 = Instant::now();
    while c
        .exec_status(&["test", "-d", &format!("/proc/{sleeper}")], 10)
        .0
    {
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "sleep survived TERM"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(pgrep(fx, &["-x", "sshd"]).is_some(), "sshd gone");
}

// ---------------------------------------------------------------- provisioning

/// Baseline, applied phase by phase as the app does: Accounts (with a sudo
/// password hash), Access (auto-revert, confirmed over a new session),
/// System. The audit score must improve.
#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn provision_baseline_phases_apply_and_score() {
    let fx = fixture();
    let spec = ProfileSpec {
        source: ProfileSource::Builtin {
            level: ProfileLevel::Baseline,
            roles: vec![],
        },
        only: vec![],
    };
    let hash = fx
        .container
        .exec(&["openssl", "passwd", "-6", "fleet-it-sudo-password"])
        .ok()
        .and_then(|h| SudoPasswordHash::new(h.trim()).ok());
    eprintln!(
        "provision: sudo password hash {}",
        if hash.is_some() {
            "set"
        } else {
            "skipped (no openssl)"
        }
    );
    let score = async |s: &mut Sess| match call(s, fx, Op::ProfileCheck(spec.clone())).await {
        Ok(Payload::ProfileCheck(c)) => c,
        other => panic!("profile.check: {other:?}"),
    };
    run(Duration::from_secs(40 * 60), async {
        let (mut conn, mut s) = open(fx).await;
        let before = score(&mut s).await;
        eprintln!("provision: score before {}", before.score);
        let mut failed = Vec::new();
        for phase in [
            ProfilePhase::Accounts,
            ProfilePhase::Access,
            ProfilePhase::System,
        ] {
            // No kernel audit in a container (auditctl can't load rules
            // outside the initial PID namespace; `augenrules` fails and the
            // phase with it), so System runs without the auditd module.
            // An `only` list must also leave out the other phases' modules.
            const EARLIER: [&str; 5] = [
                "admin.user",
                "admin.shell",
                "sudo.policy",
                "ssh.hardening",
                "firewall.baseline",
            ];
            let spec = if phase == ProfilePhase::System {
                ProfileSpec {
                    only: before
                        .modules
                        .iter()
                        .filter(|m| m.id != "auditd" && !EARLIER.contains(&m.id.as_str()))
                        .map(|m| ModuleId::new(m.id.clone()).unwrap())
                        .collect(),
                    ..spec.clone()
                }
            } else {
                spec.clone()
            };
            let plan = match call(&mut s, fx, Op::ProfilePlan(spec.clone())).await {
                Ok(Payload::ProfilePlan(p)) => p,
                other => panic!("profile.plan: {other:?}"),
            };
            let op = Op::ProfileApply {
                spec: spec.clone(),
                plan_hash: plan.plan_hash,
                phase,
                password_hash: (phase == ProfilePhase::Accounts)
                    .then(|| hash.clone())
                    .flatten(),
            };
            let t0 = Instant::now();
            let r = call_within(&mut s, fx, op, Duration::from_secs(30 * 60)).await;
            let applied: ProfileApplied = match r {
                Ok(Payload::ProfileApplied(a)) => a,
                Ok(Payload::ChangePending { change, inner }) => {
                    eprintln!("provision {phase:?}: pending {change:?}");
                    let r = confirm(fx, change.change_id).await;
                    eprintln!("provision {phase:?}: confirm {r:?}");
                    assert!(r.is_ok(), "confirm {phase:?}: {r:?}");
                    match inner.map(|b| *b) {
                        Some(Payload::ProfileApplied(a)) => a,
                        other => panic!("{phase:?} pending without result: {other:?}"),
                    }
                }
                other => panic!("profile.apply {phase:?}: {other:?}"),
            };
            eprintln!(
                "provision {phase:?}: {:?}, score {} → {}, {} planned changes",
                t0.elapsed(),
                applied.score_before,
                applied.score_after,
                plan.changes.len()
            );
            for m in &applied.modules {
                if m.outcome != ModuleOutcome::Unchanged {
                    eprintln!(
                        "  {:<22} {:?} {}",
                        m.id,
                        m.outcome,
                        m.detail.lines().next().unwrap_or("")
                    );
                }
                if m.outcome == ModuleOutcome::Failed {
                    failed.push((phase, m.id.clone(), m.detail.clone()));
                }
            }
            // sshd may have been reloaded: continue on a fresh login.
            conn.disconnect().await;
            (conn, s) = open(fx).await;
        }
        let after = score(&mut s).await;
        eprintln!("provision: score {} → {}", before.score, after.score);
        for m in &after.modules {
            eprintln!("  {:<22} {:?}", m.id, m.status);
        }
        conn.disconnect().await;
        assert!(
            !failed.iter().any(|(p, ..)| *p != ProfilePhase::System),
            "failed modules: {failed:?}"
        );
        if !failed.is_empty() {
            eprintln!("provision: System modules failed: {failed:?}");
        }
        assert!(after.score > before.score, "score did not improve");
    });
}

// ---------------------------------------------------------------- services

#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn services_unit_status_and_protected_stop() {
    let fx = fixture();
    run(LIMIT, async {
        let (conn, mut s) = open(fx).await;
        for unit in ["ssh.service", "cron.service", "fleet-exec.service"] {
            let op = Op::UnitStatus {
                unit: UnitName::new(unit).unwrap(),
            };
            match call(&mut s, fx, op).await {
                Ok(Payload::UnitStatus(u)) => {
                    eprintln!(
                        "unit.status {unit}: {:?}/{} ({}) pid {:?} mem {:?} tasks {:?}",
                        u.info.active,
                        u.info.sub,
                        u.info.file_state,
                        u.main_pid,
                        u.memory_bytes,
                        u.tasks
                    );
                    assert_eq!(u.info.name, unit);
                }
                other => panic!("unit.status {unit}: {other:?}"),
            }
        }
        for unit in ["ssh.service", "fleet-exec.service"] {
            let op = Op::UnitStop {
                unit: UnitName::new(unit).unwrap(),
            };
            let r = call(&mut s, fx, op).await;
            eprintln!("unit.stop {unit}: {r:?}");
            assert!(r.is_err(), "unit.stop {unit} was allowed");
            if unit == "ssh.service" {
                assert_eq!(r, Err(ErrorCode::PolicyDenied));
            }
        }
        conn.disconnect().await;
    });
    // Still reachable.
    let Payload::SystemInfo(_) = read(fx, Op::SystemInfo) else {
        panic!("wrong payload")
    };
}

// ---------------------------------------------------------------- updates

/// `agent.health` over a new connection; `None` while the agent restarts.
async fn fresh_version(fx: &'static Fixture) -> Option<fleet_proto::AgentVersion> {
    let m = &fx.macs[0];
    let conn = fx.ssh(m).await.ok()?;
    let r = match fx.session(&conn, m).await {
        Ok(Ok(mut s)) => tokio::time::timeout(
            STEP,
            s.request(Op::AgentHealth, &fx.server, Actor::Human, None),
        )
        .await
        .ok()
        .and_then(Result::ok),
        _ => None,
    };
    conn.disconnect().await;
    match r?.result {
        Ok(Payload::AgentHealth(h)) => Some(h.agent_version),
        _ => None,
    }
}

/// Polls until the agent reports `want` (or `limit` passes).
async fn wait_version(
    fx: &'static Fixture,
    want: fleet_proto::AgentVersion,
    limit: Duration,
) -> bool {
    let t0 = Instant::now();
    while t0.elapsed() < limit {
        if fresh_version(fx).await == Some(want) {
            eprintln!("agent reports {want:?} after {:?}", t0.elapsed());
            return true;
        }
        sleep(1).await;
    }
    false
}

fn agent_hash(fx: &Fixture) -> String {
    fx.container
        .exec(&["sha256sum", "/usr/lib/fleet/fleet-agent"])
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned()
}

/// Build A (installed) → signed build B (`FLEET_IT_AGENT_NEXT`, a higher
/// `FLEET_AGENT_VERSION`): SFTP to the admin's drop directory, stage,
/// commit, B comes up and is confirmed from a fresh connection; manual
/// rollback to A; B committed again and never confirmed: the timer (run
/// by the previous binary) restores A and restarts the units.
#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn update_confirmed_then_manual_and_timer_rollback() {
    use fleet_crypto::release::sign_release;
    use fleet_proto::{AgentTarget, ReleaseManifest};
    let Some(next) = std::env::var_os("FLEET_IT_AGENT_NEXT") else {
        eprintln!("FLEET_IT_AGENT_NEXT unset (tests/vm/run.sh builds it): skipped");
        return;
    };
    let fx = fixture();
    let bin_b = std::fs::read(next).expect("build B");
    let hash_b = fleet_crypto::blake3(&bin_b);
    run(Duration::from_secs(360), async {
        let m = &fx.macs[0];
        let v_a = fresh_version(fx).await.expect("agent up");
        let (c, mut s) = open(fx).await;
        let sha_a = agent_hash(fx);
        // The container's architecture (the test process may run under
        // Rosetta, so not this process's).
        let target = AgentTarget::parse(fx.container.exec(&["uname", "-m"]).unwrap().trim())
            .expect("known architecture");
        let signed = sign_release(
            ReleaseManifest {
                version: fleet_proto::AgentVersion {
                    major: 0,
                    minor: 2,
                    patch: 0,
                },
                blake3: hash_b,
                min_proto: 1,
                target,
            },
            m.id,
            &m.keys.root,
        )
        .unwrap();
        let v_b = signed.manifest.version;
        assert!(v_b > v_a, "build B {v_b:?} must be above A {v_a:?}");
        // What the app does: SFTP as the admin into incoming/.
        let sftp = fleet_core::sftp::Sftp::open(&c).await.expect("sftp");
        sftp.upload_bytes(
            &bin_b,
            &format!("/var/lib/fleet/incoming/{}", hex::encode(hash_b)),
            Some(0o600),
            false,
            &mut |_, _| {},
        )
        .await
        .expect("upload");
        let stage = Op::AgentUpdateStage {
            manifest: Box::new(signed.clone()),
            staged_path_hash: hash_b,
        };
        assert_eq!(call(&mut s, fx, stage).await, Ok(Payload::Empty));
        let commit = Op::AgentUpdateCommit { version: v_b };
        let change = match call(&mut s, fx, commit.clone()).await {
            Ok(Payload::ChangePending { change, .. }) => change,
            other => panic!("commit: {other:?}"),
        };
        eprintln!(
            "update: committed, window {} ms",
            change.deadline_ms - change.created_ms
        );
        c.disconnect().await;
        assert!(
            wait_version(fx, v_b, Duration::from_secs(25)).await,
            "B never came up"
        );
        let r = confirm(fx, change.change_id).await;
        assert!(r.is_ok(), "confirm: {r:?}");
        sleep(40).await;
        assert_eq!(fresh_version(fx).await, Some(v_b), "confirmed update kept");

        // Manual rollback to A.
        let (c, mut s) = open(fx).await;
        assert_eq!(
            call(&mut s, fx, Op::AgentUpdateRollback).await,
            Ok(Payload::Empty)
        );
        c.disconnect().await;
        assert!(
            wait_version(fx, v_a, Duration::from_secs(30)).await,
            "manual rollback"
        );
        assert_eq!(agent_hash(fx), sha_a);

        // B again (still staged), never confirmed: the timer restores A.
        let (c, mut s) = open(fx).await;
        let change = match call(&mut s, fx, commit).await {
            Ok(Payload::ChangePending { change, .. }) => change,
            other => panic!("second commit: {other:?}"),
        };
        c.disconnect().await;
        assert!(
            wait_version(fx, v_b, Duration::from_secs(25)).await,
            "B second start"
        );
        let t0 = Instant::now();
        assert!(
            wait_version(fx, v_a, Duration::from_secs(90)).await,
            "timer did not roll back"
        );
        eprintln!(
            "update: unconfirmed B rolled back {:?} after it came up (window {} ms)",
            t0.elapsed(),
            change.deadline_ms - change.created_ms
        );
        assert_eq!(agent_hash(fx), sha_a);
        let (c, mut s) = open(fx).await;
        let r = call(&mut s, fx, Op::ChangesList).await;
        eprintln!("changes.list after rollback: {r:?}");
        c.disconnect().await;
    });
}

// ------------------------------------------- remaining handlers, audit (W6b)

#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn w6b_connections_list_shows_own_ssh_session() {
    let fx = fixture();
    let Payload::Connections(c) = read(fx, Op::ConnectionsList) else {
        panic!("wrong payload")
    };
    let ssh: Vec<_> = c
        .connections
        .iter()
        .filter(|c| c.local.port() == 22 && c.state == "ESTABLISHED")
        .collect();
    eprintln!(
        "connections.list: {} rows, {} established on :22, e.g. {:?}",
        c.connections.len(),
        ssh.len(),
        ssh.first()
    );
    assert!(!ssh.is_empty(), "our own SSH connection is missing");
    assert!(
        ssh.iter()
            .any(|c| c.process.as_deref().is_some_and(|p| p.starts_with("sshd"))),
        "sshd not mapped to the socket"
    );
}

#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn w6b_logfiles_list_and_weblog_query_fixture_log() {
    let fx = fixture();
    let c = &fx.container;
    let now_s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let line = |t: u64, ip: &str, uri: &str, status: u16| {
        format!(
            r#"{{"level":"info","ts":{t}.25,"logger":"http.log.access","request":{{"remote_ip":"10.0.0.1","client_ip":"{ip}","method":"GET","uri":"{uri}","headers":{{"User-Agent":["it"]}}}},"status":{status},"size":10}}"#
        )
    };
    let body = [
        line(now_s - 30, "198.51.100.4", "/index.html", 200),
        line(now_s - 20, "198.51.100.4", "/.env", 404),
        "garbage".to_owned(),
        line(now_s - 10, "203.0.113.9", "/api/v1/x", 500),
    ]
    .join("\n")
        + "\n";
    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("access.log");
    std::fs::write(&local, body).unwrap();
    c.exec(&["mkdir", "-p", "/var/log/caddy"]).unwrap();
    c.cp_into(&local, "/var/log/caddy/access.log").unwrap();
    c.exec(&["chown", "root:root", "/var/log/caddy/access.log"]).unwrap();

    let Payload::LogFiles(l) = read(fx, Op::LogfilesList) else {
        panic!("wrong payload")
    };
    let paths: Vec<&str> = l.files.iter().map(|f| f.path.as_str()).collect();
    eprintln!("logfiles.list: {} files, e.g. {:?}", paths.len(), &paths[..paths.len().min(5)]);
    assert!(paths.contains(&"/var/log/caddy/access.log"));
    assert!(!paths.iter().any(|p| p.starts_with("/var/log/journal")));

    let q = |status, client| Op::WeblogQuery {
        range: TimeRange::default(),
        limit: 100,
        status,
        path_prefix: None,
        client,
    };
    let Payload::WebLogSummary(all) = read(fx, q(None, None)) else {
        panic!("wrong payload")
    };
    eprintln!(
        "weblog.query: {} requests, by status {:?}, scanner hits {}",
        all.requests, all.by_status, all.scanner_hits
    );
    assert_eq!(all.requests, 3);
    assert_eq!(all.entries[0].path, "/api/v1/x", "newest first");
    assert_eq!(all.scanner_hits, 1);
    let Payload::WebLogSummary(errs) = read(
        fx,
        q(
            Some(fleet_proto::op::StatusRange { min: 400, max: 599 }),
            Some("198.51.100.4".parse().unwrap()),
        ),
    ) else {
        panic!("wrong payload")
    };
    assert_eq!(errs.requests, 1);
    assert_eq!(errs.entries[0].path, "/.env");
    c.exec(&["rm", "-f", "/var/log/caddy/access.log"]).unwrap();
}

#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn w6b_audit_query_verified_by_mirror() {
    use fleet_core::audit_mirror::{MirrorHead, verify_page};
    let fx = fixture();
    run(LIMIT, async {
        let (conn, mut s) = open(fx).await;
        let mut known = MirrorHead::default();
        let mut pages = 0;
        let mut entries = 0;
        loop {
            let op = Op::AuditQuery {
                after_seq: known.seq,
                limit: 200,
            };
            let Ok(Payload::AuditPage(p)) = call(&mut s, fx, op).await else {
                panic!("audit.query failed")
            };
            let v = verify_page(&fx.server, &fx.agent_signing, known, &p)
                .expect("chain or checkpoint doesn't verify");
            pages += 1;
            entries += v.entries.len();
            let more = v.more && !v.entries.is_empty();
            known = v.head;
            if !more {
                break;
            }
        }
        eprintln!("audit.query: {entries} entries in {pages} pages, head seq {}", known.seq);
        assert!(entries > 0 && known.seq as usize >= entries);
        // Continuing from the verified head: only new entries, still linked.
        let op = Op::AuditQuery {
            after_seq: known.seq,
            limit: 200,
        };
        let Ok(Payload::AuditPage(p)) = call(&mut s, fx, op).await else {
            panic!("audit.query failed")
        };
        verify_page(&fx.server, &fx.agent_signing, known, &p).unwrap();
        conn.disconnect().await;
    });
}

#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn w6b_system_reboot_schedules_timer_then_cancel() {
    let fx = fixture();
    let c = &fx.container;
    run(LIMIT, async {
        let (conn, mut s) = open(fx).await;
        let r = call(&mut s, fx, Op::SystemReboot { delay_s: 3600 }).await;
        conn.disconnect().await;
        assert_eq!(r, Ok(Payload::Empty));
    });
    let (_, timers) = c.exec_status(
        &["systemctl", "list-timers", "--all", "--no-pager", "fleet-reboot.timer"],
        30,
    );
    eprintln!("system.reboot timer: {}", timers.lines().nth(1).unwrap_or(""));
    // Never let it fire: stop it before asserting anything else.
    let (stopped, _) = c.exec_status(&["systemctl", "stop", "fleet-reboot.timer"], 30);
    assert!(stopped, "fleet-reboot.timer not loaded");
    assert!(timers.contains("fleet-reboot.timer"), "{timers}");
    let (active, _) = c.exec_status(&["systemctl", "is-active", "fleet-reboot.timer"], 30);
    assert!(!active);
}

/// Last by name: footprint after every other test in this run.
#[test]
#[ignore = "needs Docker; run tests/vm/run.sh"]
fn zz_resource_report() {
    let fx = fixture();
    let c = &fx.container;
    let mib = |b: u64| b as f64 / (1024.0 * 1024.0);
    let gate = c.rss_bytes("fleet-gate.service").unwrap();
    let exec = c.rss_bytes("fleet-exec.service").unwrap();
    let size: u64 = c
        .exec(&["stat", "-c", "%s", "/usr/lib/fleet/fleet-agent"])
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    eprintln!(
        "after all tests ({}): gate RSS {:.2} MiB (idle {:.2}), exec RSS {:.2} MiB (idle {:.2}), binary {} bytes ({:.2} MiB)",
        fx.os,
        mib(gate),
        mib(fx.idle_rss.0),
        mib(exec),
        mib(fx.idle_rss.1),
        size,
        mib(size)
    );
}
