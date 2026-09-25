//! Real agent in a systemd container, reached over SSH (see the crate docs).
//! Every test is `#[ignore]`: run `tests/vm/run.sh`, or build the agent and
//! image yourself and run `cargo test -p fleet-it -- --ignored
//! --test-threads=1 --nocapture`.

use fleet_core::ClientError;
use fleet_crypto::stream::{StreamItem, StreamVerifier};
use fleet_crypto::verify::command_hash;
use fleet_it::{Fixture, STEP, fixture, run};
use fleet_proto::args::JournalQuery;
use fleet_proto::op::SampleInterval;
use fleet_proto::{Actor, ErrorCode, Message, Op, Payload, decode};
use std::time::Duration;

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
        // SSH itself still works (keys in ~/.ssh), the agent refuses.
        let c1b = fx.ssh(m1).await.unwrap();
        match fx.session(&c1b, m1).await.unwrap() {
            Err(ClientError::Rejected(ErrorCode::Unauthorized)) => {}
            Err(e) => panic!("unexpected error: {e}"),
            Ok(_) => panic!("revoked device got a session"),
        }
        eprintln!("revocation: open session cut, new session Unauthorized");
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
