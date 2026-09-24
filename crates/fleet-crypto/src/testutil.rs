//! Shared unit-test fixtures.

use crate::approval::{ApprovalParams, MAX_APPROVAL_LIFETIME_MS};
use crate::noise::StaticKeypair;
use crate::roster::sign_root;
use crate::sig::{Ed25519Signer, Signer, SoftwareP256Signer};
use fleet_proto::{
    Actor, BoundedString, CommandBody, Device, DeviceId, FleetId, KeyKind, Op, Role, Roster,
    ServerId, Signature, SignedCommand, SignedRoster, encode,
};
use zeroize::Zeroizing;

pub const NOW: u64 = 1_750_000_000_000;
pub const FLEET: FleetId = FleetId([1; 16]);

/// Order of the P-256 group, big-endian.
const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// `(r, n − s)`: the malleated (high-S) twin of a low-S signature.
pub fn malleate(sig: &Signature) -> Signature {
    let mut out = sig.0;
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = i16::from(N[i]) - i16::from(sig.0[32 + i]) - borrow;
        borrow = i16::from(d < 0);
        out[32 + i] = d.rem_euclid(256) as u8;
    }
    Signature(out)
}

pub fn p256_signer(seed: u8) -> SoftwareP256Signer {
    SoftwareP256Signer::from_bytes(&[seed; 32]).unwrap()
}

pub fn recovery_signer(seed: u8) -> Ed25519Signer {
    Ed25519Signer::from_seed(&[seed; 32])
}

pub fn server(i: usize) -> ServerId {
    ServerId::new(format!("srv_{i:06}")).unwrap()
}

pub fn body_for(server: &ServerId, op: Op, issued_at_ms: u64) -> CommandBody {
    let mut nonce = [0u8; 16];
    crate::random_bytes(&mut nonce).unwrap();
    CommandBody {
        v: fleet_proto::PROTO_VERSION,
        fleet_id: FLEET,
        server_id: server.clone(),
        issued_at_ms,
        ttl_ms: crate::verify::DEFAULT_TTL_MS,
        nonce,
        actor: Actor::Human,
        op,
        expected_version: None,
    }
}

pub struct Mac {
    pub id: DeviceId,
    pub root: SoftwareP256Signer,
    pub device: SoftwareP256Signer,
    pub monitor: SoftwareP256Signer,
    pub noise: StaticKeypair,
}

pub struct Fixture {
    pub macs: Vec<Mac>,
    pub recovery: Ed25519Signer,
    /// Epoch 0, version 1, signed by mac 0, 72 h recovery delay.
    pub genesis: SignedRoster,
}

impl Fixture {
    pub fn new(n: usize) -> Self {
        let macs: Vec<Mac> = (0..n)
            .map(|i| {
                let s = 10 + 4 * i as u8;
                Mac {
                    id: DeviceId([s; 16]),
                    root: p256_signer(s),
                    device: p256_signer(s + 1),
                    monitor: p256_signer(s + 2),
                    noise: StaticKeypair::from_bytes(&Zeroizing::new([s + 3; 32])),
                }
            })
            .collect();
        let recovery = recovery_signer(200);
        let roster = Roster {
            fleet_id: FLEET,
            epoch: 0,
            version: 1,
            prev_hash: [0; 32],
            issued_at_ms: NOW,
            devices: macs
                .iter()
                .map(|m| Device {
                    id: m.id,
                    name: BoundedString::new("Mac").unwrap(),
                    role: Role::Admin,
                    root_key: m.root.public(),
                    device_key: m.device.public(),
                    monitor_key: m.monitor.public(),
                    ssh_key: m.device.public(),
                    noise_static: m.noise.public(),
                    added_at: NOW,
                    added_by: macs_first_id(),
                })
                .collect(),
            recovery_key: recovery.public(),
            recovery_ssh_key: recovery_signer(201).public(),
            recovery_escrow_key: StaticKeypair::from_bytes(&Zeroizing::new([202; 32])).public(),
            recovery_delay_s: crate::recovery::DEFAULT_DELAY_S,
            prev_recovery: None,
        };
        let genesis = sign_root(roster, macs[0].id, &macs[0].root).unwrap();
        Self {
            macs,
            recovery,
            genesis,
        }
    }

    /// Genesis with `edit` applied, re-signed by mac 0.
    pub fn genesis_with(&self, edit: impl FnOnce(&mut Roster)) -> SignedRoster {
        let mut r = self.genesis.roster.clone();
        edit(&mut r);
        sign_root(r, self.macs[0].id, &self.macs[0].root).unwrap()
    }

    pub fn roster(&self) -> Roster {
        self.genesis.roster.clone()
    }

    /// Current roster with mac `i` removed.
    pub fn without(&self, i: usize) -> Roster {
        let mut r = self.roster();
        r.devices.retain(|d| d.id != self.macs[i].id);
        r
    }

    pub fn approval_params(&self, now: u64) -> ApprovalParams {
        ApprovalParams {
            fleet_id: FLEET,
            approval_id: [7; 16],
            issued_at_ms: now,
            expires_at_ms: now + MAX_APPROVAL_LIFETIME_MS,
        }
    }

    fn sign_p256(
        &self,
        id: DeviceId,
        key: KeyKind,
        s: &SoftwareP256Signer,
        body: &CommandBody,
    ) -> SignedCommand {
        let body = encode(body);
        SignedCommand {
            signature: s
                .sign(&SignedCommand::signed_message(key, &id, &body))
                .unwrap(),
            body,
            device_id: id,
            key,
            approval: None,
        }
    }

    pub fn sign_device(&self, i: usize, body: &CommandBody) -> SignedCommand {
        let m = &self.macs[i];
        self.sign_p256(m.id, KeyKind::Device, &m.device, body)
    }

    pub fn sign_monitor(&self, i: usize, body: &CommandBody) -> SignedCommand {
        let m = &self.macs[i];
        self.sign_p256(m.id, KeyKind::Monitor, &m.monitor, body)
    }

    /// Recovery-key command from the fixture's recovery code; sets
    /// `actor = Recovery` as required.
    pub fn sign_recovery_cmd(&self, body: &CommandBody) -> SignedCommand {
        let body = CommandBody {
            actor: Actor::Recovery,
            ..body.clone()
        };
        sign_recovery_raw(&self.recovery, RECOVERY_MAC, &body)
    }
}

/// Device id a recovering Mac claims in tests.
pub const RECOVERY_MAC: DeviceId = DeviceId([0x77; 16]);

/// Recovery-key command signed by `key`, body as given.
pub fn sign_recovery_raw(key: &Ed25519Signer, id: DeviceId, body: &CommandBody) -> SignedCommand {
    let body = encode(body);
    SignedCommand {
        signature: key.sign(&SignedCommand::signed_message(
            KeyKind::Recovery,
            &id,
            &body,
        )),
        body,
        device_id: id,
        key: KeyKind::Recovery,
        approval: None,
    }
}

fn macs_first_id() -> DeviceId {
    DeviceId([10; 16])
}
