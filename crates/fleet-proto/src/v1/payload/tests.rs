use super::*;
use crate::tagged::Bytes;
use crate::v1::AgentVersion;
use crate::v1::args::Protocol;
use crate::v1::op::Resolution;
use crate::{decode, encode};
use proptest::prelude::*;
use std::collections::HashSet;

#[test]
fn tags_and_names_unique() {
    let tags: HashSet<_> = payload_tag::ALL.iter().collect();
    assert_eq!(tags.len(), payload_tag::ALL.len());
    let names: HashSet<_> = payload_tag::NAMES.iter().collect();
    assert_eq!(names.len(), payload_tag::NAMES.len());
    assert_eq!(payload_tag::ALL.len(), payload_tag::NAMES.len());
    // Phase 0 tags are frozen.
    assert_eq!(
        (
            payload_tag::EMPTY,
            payload_tag::SYSTEM_INFO,
            payload_tag::AGENT_HEALTH,
            payload_tag::ROSTER_PENDING
        ),
        (0, 1, 2, 3)
    );
}

fn pending() -> PendingChange {
    PendingChange {
        change_id: [1; 16],
        kind: ChangeKind::Firewall,
        op_tag: crate::v1::op::tag::FIREWALL_APPLY,
        created_ms: 1,
        deadline_ms: 60_001,
        new_version: Some(8),
    }
}

fn profile_applied() -> ProfileApplied {
    ProfileApplied {
        modules: vec![ModuleResult {
            id: "ssh.hardening".into(),
            outcome: ModuleOutcome::Applied,
            detail: String::new(),
        }],
        pending: None,
        score_before: 40,
        score_after: 70,
    }
}

#[test]
fn change_pending_result_and_nesting_bound() {
    let applied = Payload::ProfileApplied(profile_applied());
    let wrapped = Payload::ChangePending {
        change: pending(),
        inner: Some(Box::new(applied.clone())),
    };
    assert_eq!(wrapped.result(), &applied);
    assert_eq!(applied.result(), &applied);
    let bare = Payload::ChangePending {
        change: pending(),
        inner: None,
    };
    assert_eq!(bare.result(), &bare);
    // A hostile chain of nested payloads is refused, not recursed into
    // until the stack runs out.
    let mut p = Payload::Empty;
    for _ in 0..64 {
        p = Payload::ChangePending {
            change: pending(),
            inner: Some(Box::new(p)),
        };
    }
    assert!(decode::<Payload>(&encode(&p)).is_err());
    // The bound resets after a failure.
    assert_eq!(decode::<Payload>(&encode(&wrapped)).unwrap(), wrapped);
}

pub(crate) fn samples() -> Vec<Payload> {
    vec![
        Payload::Empty,
        Payload::SystemInfo(SystemInfo {
            hostname: "h".into(),
            os_id: "debian".into(),
            os_version: "12".into(),
            kernel: "6.1".into(),
            arch: "x86_64".into(),
            cpu_count: 4,
            mem_total_bytes: 1 << 30,
            uptime_s: 9,
        }),
        Payload::AgentHealth(AgentHealth {
            agent_version: AgentVersion {
                major: 1,
                minor: 2,
                patch: 3,
            },
            proto_version: 1,
            uptime_s: 1,
            gate_rss_bytes: 2,
            exec_rss_bytes: 3,
            audit_seq: 4,
            roster_epoch: 5,
            roster_version: 6,
            policy_version: 7,
            pending_recovery: Some(PendingRecovery {
                hash: [8; 32],
                activates_at_ms: 9,
            }),
            run_id: [10; 16],
        }),
        Payload::RosterPending(None),
        Payload::SignedEvents(SignedEventPage {
            events: vec![crate::v1::SignedEvent {
                server_id: crate::v1::ServerId::new("srv_test01").unwrap(),
                run_id: [3; 16],
                seq: 4,
                time_ms: 5,
                event: crate::v1::Event::PolicyChanged { version: 6 },
                sig: crate::v1::Signature([7; 64]),
            }],
            more: true,
        }),
        Payload::MetricsCatalog(MetricsCatalog {
            series: vec![MetricSeries {
                id: 1,
                name: "cpu.steal".into(),
                unit: MetricUnit::Percent,
            }],
        }),
        Payload::MetricsSample(MetricsSample {
            time_ms: 5,
            values: vec![(1, F32(0.5)), (2, F32(f32::NAN))],
        }),
        Payload::MetricsHistory(MetricsHistory {
            resolution: Resolution::Minute,
            start_ms: 0,
            step_ms: 60_000,
            catalog: vec![],
            series: vec![SeriesRollup {
                id: 1,
                min: vec![F32(1.0)],
                avg: vec![F32(2.0)],
                max: vec![F32(3.0)],
            }],
        }),
        Payload::Ports(Ports {
            ports: vec![ListeningPort {
                proto: Protocol::Tcp,
                addr: "0.0.0.0".parse().unwrap(),
                port: 22,
                pid: Some(1),
                process: Some("sshd".into()),
                user: Some("root".into()),
                reachable: Some(true),
            }],
        }),
        Payload::ChangePending {
            change: pending(),
            inner: None,
        },
        Payload::ChangePending {
            change: pending(),
            inner: Some(Box::new(Payload::ProfileApplied(profile_applied()))),
        },
        Payload::RosterState(Box::new(RosterState {
            roster: crate::v1::test_support::signed_roster(),
            epoch_hashes: vec![[1; 32], [2; 32]],
        })),
        Payload::ProfileCheck(ProfileCheck {
            score: 90,
            modules: vec![ModuleCheck {
                id: "auditd".into(),
                status: ModuleStatus::PendingReboot,
                detail: "immutable rules load at boot".into(),
            }],
        }),
        Payload::Packages(Packages {
            packages: vec![PackageInfo {
                name: "libssl3".into(),
                version: "3.0.11-1~deb12u2".into(),
                arch: "amd64".into(),
                held: false,
                auto_installed: true,
                source: Some("openssl".into()),
                source_version: Some("3.0.11-1~deb12u2".into()),
            }],
        }),
        Payload::Upgradable(Upgradable {
            packages: vec![UpgradablePackage {
                name: "openssl".into(),
                current: "3.0.1-1".into(),
                candidate: "3.0.1-2".into(),
                security: true,
                origin: "Debian-Security".into(),
            }],
            reboot_required: false,
            lists_updated_ms: Some(3),
        }),
        Payload::ConfigHistory(ConfigHistory {
            versions: vec![ConfigVersion {
                path: "/etc/hosts".into(),
                version: 2,
                time_ms: 3,
                hash: [4; 32],
                size: 5,
                source: ChangeSource::External {
                    process: Some("vim".into()),
                },
                secret: false,
                deleted: false,
            }],
            truncated: false,
        }),
        Payload::DockerStats(DockerStats {
            time_ms: 1,
            containers: vec![ContainerStats {
                id: "abc".into(),
                cpu_pct: F32(12.5),
                mem_bytes: 1,
                mem_limit: 2,
                net_rx_bps: 3,
                net_tx_bps: 4,
                blk_read_bps: 5,
                blk_write_bps: 6,
                pids: 7,
            }],
        }),
        Payload::AuditReport(AuditReport {
            score: 82,
            findings: vec![AuditFinding {
                module: "ssh.hardening".into(),
                status: ModuleStatus::Drifted,
                severity: crate::v1::alert::Severity::Warning,
                title: "PasswordAuthentication yes".into(),
                fixable: true,
            }],
        }),
        Payload::RconOutput {
            text: "saved".into(),
        },
        Payload::ShellResult(ShellResult {
            exit_code: Some(0),
            stdout: b"up 3 days".to_vec(),
            stderr: vec![],
            truncated: false,
            timed_out: false,
        }),
        Payload::WebLogSummary(WebLogSummary {
            requests: 3,
            by_status: vec![(404, 2)],
            top_clients: vec![("203.0.113.4".parse().unwrap(), 3)],
            top_paths: vec![("/.env".into(), 2)],
            scanner_hits: 2,
            entries: vec![WebLogEntry {
                time_ms: 1,
                client: "203.0.113.4".parse().unwrap(),
                method: "GET".into(),
                path: "/.env".into(),
                status: 404,
                bytes: 12,
                user_agent: Some("curl".into()),
                log: "/var/log/caddy/access.log".into(),
            }],
            truncated: false,
        }),
        Payload::AuditPage(Box::new(AuditPage {
            entries: vec![crate::v1::AuditEntry {
                seq: 5,
                time: 6,
                prev_hash: [1; 32],
                actor: crate::v1::Actor::System,
                device_id: crate::v1::DeviceId([2; 16]),
                command_hash: [3; 32],
                signature: crate::v1::Signature([4; 64]),
                op: crate::v1::OpSummary {
                    tag: 50,
                    args: vec![0],
                },
                phase: crate::v1::Phase::Result,
                result: crate::v1::ResultSummary::Done(crate::v1::Outcome::Ok),
            }],
            anchor: Some(AuditAnchor {
                seq: 4,
                entry_hash: [1; 32],
            }),
            checkpoint: crate::v1::SignedCheckpoint {
                checkpoint: crate::v1::Checkpoint {
                    server_id: crate::v1::ServerId::new("srv_test01").unwrap(),
                    seq: 5,
                    entry_hash: [5; 32],
                    time_ms: 7,
                },
                signature: crate::v1::Signature([6; 64]),
            },
            more: false,
        })),
    ]
}

#[test]
fn roundtrip_samples() {
    for p in samples() {
        assert!(Payload::is_known_tag(p.tag()), "{}", p.name());
        assert_eq!(decode::<Payload>(&encode(&p)).unwrap(), p, "{}", p.name());
    }
}

#[test]
fn f32_bitwise_eq() {
    assert_eq!(F32(f32::NAN), F32(f32::NAN));
    assert_ne!(F32(0.0), F32(-0.0));
    assert_eq!(encode(&F32(1.0)), 1.0f32.to_le_bytes());
}

#[test]
fn unknown_and_bad_payloads() {
    let bytes = encode(&(900u16, Bytes(&[1, 2, 3]), 42u8));
    let (p, rest): (Payload, u8) = decode(&bytes).unwrap();
    assert_eq!((p, rest), (Payload::Unknown { tag: 900 }, 42));
    let bytes = encode(&(payload_tag::EMPTY, Bytes(&[0])));
    assert!(decode::<Payload>(&bytes).is_err());
}

proptest! {
    #[test]
    fn metrics_sample_roundtrip(t in any::<u64>(), vals in prop::collection::vec((any::<u16>(), any::<f32>()), 0..64)) {
        let p = Payload::MetricsSample(MetricsSample {
            time_ms: t,
            values: vals.into_iter().map(|(id, v)| (id, F32(v))).collect(),
        });
        prop_assert_eq!(decode::<Payload>(&encode(&p)).unwrap(), p);
    }

    #[test]
    fn arbitrary_payload_never_panics(t in prop::sample::select(payload_tag::ALL.to_vec()), payload in prop::collection::vec(any::<u8>(), 0..64)) {
        if let Ok(p) = decode::<Payload>(&encode(&(t, Bytes(&payload)))) {
            prop_assert_eq!(p.tag(), t);
            prop_assert_eq!(decode::<Payload>(&encode(&p)).unwrap(), p);
        }
    }
}
