use super::*;
use crate::bulk::ApproveError;
use crate::signer::SignerError;
use fleet_crypto::approval::{ApprovalParams, build_approvals};
use fleet_crypto::sig::{Signer, SoftwareP256Signer};
use fleet_proto::payload::ChangeKind;
use fleet_proto::{ErrorCode, FleetId, P256Public, Signature};
use std::collections::HashSet;
use std::sync::Mutex;

fn v(minor: u16) -> AgentVersion {
    AgentVersion {
        major: 1,
        minor,
        patch: 0,
    }
}

fn sid(i: usize) -> ServerId {
    ServerId::new(format!("srv_{i:08}")).unwrap()
}

// ---- artifacts ----

fn tar_entry(out: &mut Vec<u8>, name: &str, data: &[u8]) {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    let size = format!("{:011o}\0", data.len());
    h[124..136].copy_from_slice(size.as_bytes());
    h[156] = b'0';
    h[257..263].copy_from_slice(b"ustar\0");
    out.extend_from_slice(&h);
    out.extend_from_slice(data);
    out.resize(out.len().div_ceil(512) * 512, 0);
}

fn ar_member(out: &mut Vec<u8>, name: &str, data: &[u8]) {
    let h = format!(
        "{name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
        0,
        0,
        0,
        100644,
        data.len()
    );
    assert_eq!(h.len(), 60);
    out.extend_from_slice(h.as_bytes());
    out.extend_from_slice(data);
    if data.len() % 2 == 1 {
        out.push(b'\n');
    }
}

fn deb(data_name: &str, binary: &[u8]) -> Vec<u8> {
    let mut tar = Vec::new();
    tar_entry(&mut tar, "./usr/lib/fleet/", &[]);
    tar_entry(&mut tar, "./usr/lib/fleet/fleet-agent", binary);
    tar.extend_from_slice(&[0u8; 1024]);
    let mut d = b"!<arch>\n".to_vec();
    ar_member(&mut d, "debian-binary", b"2.0\n");
    ar_member(&mut d, "control.tar.gz", b"x");
    ar_member(&mut d, data_name, &tar);
    d
}

#[test]
fn reads_binary_out_of_uncompressed_deb_only() {
    assert_eq!(
        deb_binary(&deb("data.tar", b"ELF-agent")).unwrap(),
        b"ELF-agent"
    );
    assert!(matches!(
        deb_binary(&deb("data.tar.xz", b"x")),
        Err(ReleaseImportError::CompressedDeb)
    ));
    assert!(matches!(
        deb_binary(b"not a deb"),
        Err(ReleaseImportError::NotDeb)
    ));
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("fleet-agent_1.2.0_arm64.deb");
    std::fs::write(&p, deb("data.tar", b"bin")).unwrap();
    assert_eq!(
        artifact_hash(&p).unwrap(),
        hex::encode(fleet_crypto::blake3(b"bin"))
    );
}

#[test]
fn versions_attestations_and_phases() {
    assert_eq!(
        parse_version("1.2.3").unwrap(),
        AgentVersion {
            major: 1,
            minor: 2,
            patch: 3
        }
    );
    assert!(parse_version("1.2").is_err());
    assert!(parse_version("1.2.x").is_err());
    let h = fleet_crypto::blake3(b"b");
    assert_eq!(
        parse_attestation(&format!("{}  fleet-agent\n", hex::encode(h))).unwrap(),
        h
    );
    assert!(parse_attestation("abcd").is_err());
    assert_eq!(phases(1).len(), 1);
    assert_eq!(phases(1)[0], 0..1);
    assert_eq!(phases(2), [0..1, 1..2]);
    assert_eq!(phases(10), [0..1, 1..2, 2..10]);
    assert_eq!(phases(25), [0..1, 1..4, 4..25]);
}

// ---- import ----

struct SoftKeys(SoftwareP256Signer, Mutex<Vec<String>>);

impl DeviceSigner for SoftKeys {
    fn public_key(&self, _: KeyRole) -> Result<P256Public, SignerError> {
        Ok(self.0.public())
    }
    fn sign(&self, _: KeyRole, msg: &[u8], reason: &str) -> Result<Signature, SignerError> {
        self.1.lock().unwrap().push(reason.to_owned());
        self.0.sign(msg).map_err(|_| SignerError::Cancelled)
    }
}

#[test]
fn import_requires_matching_attestation_then_signs_and_stores() {
    let cache = Cache::open_in_memory().unwrap();
    let keys = SoftKeys(
        SoftwareP256Signer::from_bytes(&[7; 32]).unwrap(),
        Mutex::default(),
    );
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("fleet-agent");
    std::fs::write(&p, b"build").unwrap();
    let mut req = ImportRequest {
        artifact: p.clone(),
        version: v(2),
        target: AgentTarget::X86_64,
        attested: hex::encode(fleet_crypto::blake3(b"other build")),
    };
    assert!(matches!(
        import_release(&keys, DeviceId([2; 16]), &req),
        Err(ReleaseImportError::AttestationMismatch)
    ));
    assert!(keys.1.lock().unwrap().is_empty(), "nothing signed");
    req.attested = hex::encode(fleet_crypto::blake3(b"build"));
    let rec = import_release(&keys, DeviceId([2; 16]), &req).unwrap();
    remember(&cache, rec.clone()).unwrap();
    assert_eq!(
        *keys.1.lock().unwrap(),
        ["sign agent release v1.2.0 (x86_64)"]
    );
    fleet_crypto::release::verify_signature(&rec.signed, &roster_with(keys.0.public())).unwrap();
    assert_eq!(releases(&cache).unwrap(), std::slice::from_ref(&rec));
    assert_eq!(find(&cache, v(2), AgentTarget::X86_64).unwrap(), rec);
    assert_eq!(load_binary(&rec).unwrap(), b"build");
    std::fs::write(&p, b"changed").unwrap();
    assert!(matches!(
        load_binary(&rec),
        Err(ReleaseImportError::Changed)
    ));
}

fn roster_with(k: P256Public) -> fleet_proto::Roster {
    fleet_proto::Roster {
        fleet_id: FleetId([1; 16]),
        epoch: 0,
        version: 1,
        prev_hash: [0; 32],
        issued_at_ms: 0,
        devices: vec![fleet_proto::Device {
            id: DeviceId([2; 16]),
            name: fleet_proto::BoundedString::new("mac").unwrap(),
            role: fleet_proto::Role::Admin,
            root_key: k,
            device_key: k,
            monitor_key: k,
            ssh_key: k,
            monitor_ssh_key: k,
            noise_static: fleet_proto::X25519Public([6; 32]),
            added_at: 0,
            added_by: DeviceId([2; 16]),
        }],
        recovery_key: fleet_proto::Ed25519Public([3; 32]),
        recovery_ssh_key: fleet_proto::Ed25519Public([4; 32]),
        recovery_escrow_key: fleet_proto::X25519Public([5; 32]),
        recovery_delay_s: 60,
        prev_recovery: None,
    }
}

// ---- rollout ----

struct Approve(SoftwareP256Signer, Mutex<Vec<usize>>);

impl Approver for Approve {
    fn approve(&self, _: &str, items: &[ApprovalItem]) -> Result<Vec<RootApproval>, ApproveError> {
        self.1.lock().unwrap().push(items.len());
        let now = crate::now_ms();
        let params = ApprovalParams {
            fleet_id: FleetId([1; 16]),
            approval_id: [9; 16],
            issued_at_ms: now,
            expires_at_ms: now + 60_000,
        };
        Ok(build_approvals(&self.0, DeviceId([2; 16]), &params, items).unwrap())
    }
}

/// Servers in `bad` never come back with the new version; `refuse` answer
/// the stage with an agent error.
#[derive(Default)]
struct FakeSteps {
    bad: HashSet<ServerId>,
    refuse: HashSet<ServerId>,
    log: Mutex<Vec<String>>,
}

fn health(version: AgentVersion) -> AgentHealth {
    AgentHealth {
        agent_version: version,
        proto_version: 1,
        uptime_s: 1,
        gate_rss_bytes: 1,
        exec_rss_bytes: 1,
        audit_seq: 1,
        roster_epoch: 0,
        roster_version: 1,
        policy_version: 1,
        pending_recovery: None,
        run_id: [0; 16],
    }
}

impl UpdateSteps for FakeSteps {
    fn upload(&self, s: ServerId, b: Arc<Vec<u8>>, remote: String) -> BoxFut<Result<(), Failure>> {
        self.log
            .lock()
            .unwrap()
            .push(format!("{s} upload {} {remote}", b.len()));
        Box::pin(async { Ok(()) })
    }
    fn request(
        &self,
        s: ServerId,
        op: Op,
        approval: Option<RootApproval>,
    ) -> BoxFut<Result<Payload, Failure>> {
        self.log
            .lock()
            .unwrap()
            .push(format!("{s} {} approval={}", op.name(), approval.is_some()));
        let refuse = self.refuse.contains(&s);
        Box::pin(async move {
            match op {
                Op::AgentUpdateStage { .. } if refuse => {
                    Err(Failure::Agent(ErrorCode::SignatureInvalid))
                }
                Op::AgentUpdateStage { .. } => Ok(Payload::Empty),
                Op::AgentUpdateCommit { .. } => Ok(Payload::ChangePending {
                    change: PendingChange {
                        change_id: [1; 16],
                        kind: ChangeKind::AgentUpdate,
                        op_tag: op.tag(),
                        created_ms: 0,
                        deadline_ms: u64::MAX,
                        new_version: None,
                    },
                    inner: None,
                }),
                _ => Err(Failure::Agent(ErrorCode::Unsupported)),
            }
        })
    }
    fn fresh_health(&self, s: ServerId) -> BoxFut<Result<AgentHealth, Failure>> {
        let ver = if self.bad.contains(&s) { v(1) } else { v(2) };
        Box::pin(async move { Ok(health(ver)) })
    }
    fn confirm(&self, s: ServerId, _: PendingChange) -> BoxFut<Result<(), Failure>> {
        self.log.lock().unwrap().push(format!("{s} confirm"));
        Box::pin(async { Ok(()) })
    }
}

fn signed() -> SignedReleaseManifest {
    let k = SoftwareP256Signer::from_bytes(&[7; 32]).unwrap();
    fleet_crypto::release::sign_release(
        ReleaseManifest {
            version: v(2),
            blake3: fleet_crypto::blake3(b"bin"),
            min_proto: 1,
            target: AgentTarget::X86_64,
        },
        DeviceId([2; 16]),
        &k,
    )
    .unwrap()
}

fn fast() -> RolloutTiming {
    RolloutTiming {
        health_window: Duration::from_millis(60),
        retry: Duration::from_millis(5),
    }
}

async fn go(steps: Arc<FakeSteps>, n: usize) -> (BulkReport, Vec<BulkEvent>, Arc<Approve>) {
    let ap = Arc::new(Approve(
        SoftwareP256Signer::from_bytes(&[8; 32]).unwrap(),
        Mutex::default(),
    ));
    let mut evs = Vec::new();
    let rep = rollout(
        steps,
        ap.clone(),
        (0..n).map(sid).collect(),
        signed(),
        Arc::new(b"bin".to_vec()),
        4,
        fast(),
        CancelToken::new(),
        |e| evs.push(e),
    )
    .await;
    (rep, evs, ap)
}

#[tokio::test(flavor = "current_thread")]
async fn rollout_goes_through_canary_phases() {
    let steps = Arc::new(FakeSteps::default());
    let (rep, evs, ap) = go(steps.clone(), 12).await;
    assert_eq!(rep.summary.succeeded, 12, "{:?}", rep.summary);
    assert_eq!(*ap.1.lock().unwrap(), [12], "one approval for every commit");
    let passed = evs
        .iter()
        .filter(|e| matches!(e, BulkEvent::CanaryPassed { .. }))
        .count();
    assert_eq!(passed, 2, "after the canary and after the 10% phase");
    let log = steps.log.lock().unwrap().clone();
    let s0: Vec<&String> = log
        .iter()
        .filter(|l| l.starts_with("srv_00000000 "))
        .collect();
    assert_eq!(s0.len(), 4, "{s0:?}");
    assert!(s0[0].contains("/var/lib/fleet/incoming/"));
    assert!(s0[1].contains("agent.update.stage approval=false"));
    assert!(s0[2].contains("agent.update.commit approval=true"));
    assert!(s0[3].ends_with("confirm"));
}

#[tokio::test(flavor = "current_thread")]
async fn unhealthy_canary_stops_the_rollout_unconfirmed() {
    let steps = Arc::new(FakeSteps {
        bad: [sid(0)].into(),
        ..Default::default()
    });
    let (rep, _, _) = go(steps.clone(), 5).await;
    assert_eq!(rep.summary.stop, Some(StopReason::CanaryFailed));
    assert!(matches!(rep.outcomes[0].1, Outcome::Failed(_)));
    assert!(
        rep.outcomes[1..]
            .iter()
            .all(|(_, o)| *o == Outcome::Skipped(SkipReason::CanaryFailed))
    );
    let log = steps.log.lock().unwrap();
    assert!(
        !log.iter().any(|l| l.ends_with("confirm")),
        "never confirmed"
    );
    assert!(!log.iter().any(|l| l.starts_with("srv_00000001")));
}

#[tokio::test(flavor = "current_thread")]
async fn failure_in_second_phase_stops_before_the_rest() {
    let steps = Arc::new(FakeSteps {
        refuse: [sid(1)].into(),
        ..Default::default()
    });
    let (rep, _, _) = go(steps, 12).await;
    assert_eq!(rep.summary.stop, Some(StopReason::Failure));
    assert!(matches!(rep.outcomes[0].1, Outcome::Succeeded(_)));
    assert_eq!(
        rep.outcomes[1].1,
        Outcome::Failed(Failure::Agent(ErrorCode::SignatureInvalid))
    );
    assert!(
        rep.outcomes[3..]
            .iter()
            .all(|(_, o)| *o == Outcome::Skipped(SkipReason::StoppedAfterFailure))
    );
}
