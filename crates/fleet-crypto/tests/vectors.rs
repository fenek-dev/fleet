//! Golden test vectors (`tests/vectors/*.hex`), fixed seeds → fixed outputs.
//!
//! A missing file is written on first run; set `FLEET_REGEN_VECTORS=1` to
//! rewrite all. Any other mismatch fails: the change broke compatibility.

use fleet_crypto::approval::op_digest;
use fleet_crypto::merkle::MerkleTree;
use fleet_crypto::noise::sign_recovery_auth;
use fleet_crypto::receipt::{
    payload_hash, receipt_for, sign_checkpoint, sign_event, sign_receipt, verify_event,
    verify_receipt, verify_response,
};
use fleet_crypto::recovery::{KdfParams, RecoveryCode, RecoveryPublics};
use fleet_crypto::roster::{roster_hash, sign_recovery};
use fleet_crypto::sig::{self, Ed25519Signer, Signer, SoftwareP256Signer};
use fleet_proto::{
    Actor, ApprovalItem, BoundedString, Checkpoint, CommandBody, Device, DeviceId, Ed25519Public,
    ErrorCode, Event, FleetId, KeyKind, KeyRef, Op, Outcome, P256Public, Payload, Receipt, Role,
    Roster, ServerId, Signature, SignedCommand, X25519Public, encode,
};
use std::path::PathBuf;

const TINY: KdfParams = KdfParams {
    m_kib: 64,
    t: 1,
    p: 1,
};

fn path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(format!("{name}.hex"))
}

/// Compares `bytes` with the stored vector (writing it if absent).
fn check(name: &str, bytes: &[u8]) {
    let p = path(name);
    let hex = hex::encode(bytes);
    if std::env::var_os("FLEET_REGEN_VECTORS").is_some() || !p.exists() {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, format!("{hex}\n")).unwrap();
        return;
    }
    let stored = std::fs::read_to_string(&p).unwrap();
    assert_eq!(stored.trim(), hex, "vector {name} changed");
}

/// Reads a stored vector, creating it with `make` if absent.
fn stored(name: &str, make: impl FnOnce() -> Vec<u8>) -> Vec<u8> {
    let p = path(name);
    if !p.exists() {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, format!("{}\n", hex::encode(make()))).unwrap();
    }
    hex::decode(std::fs::read_to_string(&p).unwrap().trim()).unwrap()
}

fn h<const N: usize>(s: &str) -> [u8; N] {
    hex::decode(s).unwrap().try_into().unwrap()
}

#[test]
fn ed25519_rfc8032_test1() {
    let k = Ed25519Signer::from_seed(&h(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ));
    assert_eq!(
        k.public().0,
        h::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    );
    let sig = k.sign(b"");
    assert_eq!(
        sig.0,
        h::<64>(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
    );
    sig::ed25519_verify(&k.public(), b"", &sig).unwrap();
}

#[test]
fn p256_rfc6979_sample_low_s() {
    // RFC 6979 A.2.5, SHA-256, message "sample".
    let k = SoftwareP256Signer::from_bytes(&h(
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
    ))
    .unwrap();
    let pk = P256Public(h(
        "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
    ));
    assert_eq!(k.public(), pk);
    let rfc = Signature(h(
        "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
    ));
    // The RFC's s is high: rejected as-is, accepted once normalized.
    assert!(sig::p256_verify(&pk, b"sample", &rfc).is_err());
    let low = sig::p256_normalize(&rfc).unwrap();
    sig::p256_verify(&pk, b"sample", &low).unwrap();
    assert_eq!(k.sign(b"sample").unwrap(), low);
}

#[test]
fn p256_stored_signature_verifies() {
    let k = SoftwareP256Signer::from_bytes(&[0x21; 32]).unwrap();
    check("p256_pub_seed21", &k.public().0);
    let msg = b"fleet p256 vector";
    let s = stored("p256_sig_seed21", || k.sign(msg).unwrap().0.to_vec());
    sig::p256_verify_slice(&k.public(), msg, &s).unwrap();
}

#[test]
fn ed25519_receipt_and_checkpoint() {
    let k = Ed25519Signer::from_seed(&[0x01; 32]);
    check("ed25519_pub_seed01", &k.public().0);
    let srv = ServerId::new("srv_abc123").unwrap();
    let r = sign_receipt(
        Receipt {
            server_id: srv.clone(),
            command_hash: [0xaa; 32],
            audit_seq: Some(42),
            outcome: Outcome::Ok,
            payload_hash: payload_hash(&Payload::Empty),
            time_ms: 1_750_000_000_001,
        },
        &k,
    );
    verify_receipt(&r, &k.public()).unwrap();
    verify_response(&r, &k.public(), &srv, &[0xaa; 32], &Ok(Payload::Empty)).unwrap();
    check("signed_receipt", &encode(&r));
    let err = Err(ErrorCode::PolicyDenied);
    let r = sign_receipt(
        receipt_for(srv.clone(), [0xab; 32], None, &err, 1_750_000_000_002),
        &k,
    );
    verify_response(&r, &k.public(), &srv, &[0xab; 32], &err).unwrap();
    check("signed_receipt_error", &encode(&r));
    let e = sign_event(
        srv.clone(),
        [0x5a; 16],
        3,
        1_750_000_000_003,
        Event::PolicyChanged { version: 12 },
        &k,
    );
    verify_event(&e, &k.public(), &srv).unwrap();
    check("signed_event", &encode(&e));
    let c = sign_checkpoint(
        Checkpoint {
            server_id: ServerId::new("srv_abc123").unwrap(),
            seq: 1000,
            entry_hash: [0xbb; 32],
            time_ms: 1_750_000_000_000,
        },
        &k,
    );
    check("signed_checkpoint", &encode(&c));
}

#[test]
fn merkle_roots_and_proof() {
    let items: Vec<ApprovalItem> = (0..7)
        .map(|i| ApprovalItem {
            server_id: ServerId::new(format!("srv_{i:06}")).unwrap(),
            op_digest: op_digest(&Op::SystemInfo, Some(i)),
        })
        .collect();
    check(
        "op_digest_system_info_none",
        &op_digest(&Op::SystemInfo, None),
    );
    let mut roots = Vec::new();
    for n in 1..=7 {
        roots.extend_from_slice(&MerkleTree::from_items(&items[..n]).unwrap().root());
    }
    check("merkle_roots_1_to_7", &roots);
    let t = MerkleTree::from_items(&items[..5]).unwrap();
    check("merkle_proof_5_4", &encode(&t.proof(4).unwrap()));
    check("merkle_proof_5_1", &encode(&t.proof(1).unwrap()));
}

fn publics_bytes(p: &RecoveryPublics) -> Vec<u8> {
    [
        p.recovery_key.0,
        p.recovery_ssh_key.0,
        p.recovery_escrow_key.0,
    ]
    .concat()
}

#[test]
fn recovery_tiny_params() {
    let c = RecoveryCode::from_entropy(&[0x42; 32]);
    check("recovery_phrase_42", c.phrase().as_bytes());
    check(
        "recovery_tiny_42_nopass",
        &publics_bytes(&c.derive("", TINY).unwrap().publics()),
    );
    check(
        "recovery_tiny_42_pass",
        &publics_bytes(&c.derive("correct horse", TINY).unwrap().publics()),
    );
}

/// Production Argon2 (256 MiB, t=3). argon2 is built at opt-level 3 in dev.
#[test]
fn recovery_production_params() {
    let c = RecoveryCode::from_entropy(&[0x42; 32]);
    let keys = c.derive("", KdfParams::PRODUCTION).unwrap();
    check("recovery_prod_42_nopass", &publics_bytes(&keys.publics()));
}

#[test]
fn recovery_signed_roster_hash() {
    let rec = Ed25519Signer::from_seed(&[0x33; 32]);
    let key = P256Public(h(
        "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
    ));
    let roster = Roster {
        fleet_id: FleetId([1; 16]),
        epoch: 1,
        version: 9,
        prev_hash: [0x5a; 32],
        issued_at_ms: 1_750_000_000_000,
        devices: vec![Device {
            id: DeviceId([2; 16]),
            name: BoundedString::new("MacBook Pro 16").unwrap(),
            role: Role::Admin,
            root_key: key,
            device_key: key,
            monitor_key: key,
            ssh_key: key,
            monitor_ssh_key: key,
            noise_static: X25519Public([3; 32]),
            added_at: 1_700_000_000_000,
            added_by: DeviceId([2; 16]),
        }],
        recovery_key: Ed25519Public([4; 32]),
        recovery_ssh_key: Ed25519Public([5; 32]),
        recovery_escrow_key: X25519Public([6; 32]),
        recovery_delay_s: 0,
        prev_recovery: None,
    };
    let s = sign_recovery(roster, &rec);
    assert_eq!(s.signer, KeyRef::Recovery);
    check("signed_roster_recovery", &encode(&s));
    check("signed_roster_recovery_hash", &roster_hash(&s));
}

/// Recovery-key command and `DeviceAuth` over `key ‖ device_id ‖ …` (Ed25519
/// is deterministic, so the whole encoding is a stable vector).
#[test]
fn recovery_command_and_device_auth() {
    let rec = Ed25519Signer::from_seed(&[0x33; 32]);
    let id = DeviceId([0x77; 16]);
    let body = CommandBody {
        v: fleet_proto::PROTO_VERSION,
        fleet_id: FleetId([1; 16]),
        server_id: ServerId::new("srv_abc123").unwrap(),
        issued_at_ms: 1_750_000_000_000,
        ttl_ms: 60_000,
        nonce: [0x4e; 16],
        actor: Actor::Recovery,
        op: Op::RosterPending,
        expected_version: None,
    };
    let body = encode(&body);
    let msg = SignedCommand::signed_message(KeyKind::Recovery, &id, &body);
    check("recovery_command_signed_message", &msg);
    let cmd = SignedCommand {
        signature: rec.sign(&msg),
        body,
        device_id: id,
        key: KeyKind::Recovery,
        approval: None,
    };
    check("recovery_signed_command", &encode(&cmd));
    let auth = sign_recovery_auth(&rec, &id, &[0xee; 32]);
    check("recovery_device_auth_sig", &auth.0);
}
