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
        Payload::ChangePending(PendingChange {
            change_id: [1; 16],
            kind: ChangeKind::Firewall,
            op_tag: crate::v1::op::tag::FIREWALL_APPLY,
            created_ms: 1,
            deadline_ms: 60_001,
            new_version: Some(8),
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
