//! Sync with an in-memory stand-in for the CloudKit zone.

use super::bridge::{PinsDoc, ServerDoc, apply_to_cache};
use super::engine::{Resolution, SyncEngine};
use super::keys::{SyncKey, keybox_record_name, open_keybox, seal_keybox};
use super::store::SyncStore;
use super::*;
use crate::cache::Cache;
use crate::signer::SoftwareDeviceSigner;
use fleet_crypto::hpke::{P256Recipient, SoftwareP256Recipient};
use fleet_crypto::roster::sign_root;
use fleet_crypto::sig::Signer;
use fleet_proto::{BoundedString, Device, Role, Roster, X25519Public, encode};
use std::collections::BTreeMap;

const NOW: u64 = 1_750_000_000_000;

/// CloudKit zone: records by name with a change counter (the change token).
#[derive(Default)]
struct MemoryCloud {
    records: BTreeMap<String, (Vec<u8>, u64)>,
    seq: u64,
}

impl MemoryCloud {
    fn push(&mut self, rs: &[CloudRecord]) -> Vec<String> {
        for r in rs {
            self.seq += 1;
            self.records
                .insert(r.name.clone(), (r.data.clone(), self.seq));
        }
        rs.iter().map(|r| r.name.clone()).collect()
    }
    fn delete(&mut self, names: &[String]) {
        for n in names {
            self.records.remove(n);
        }
    }
    fn fetch(&self, since: u64) -> (Vec<CloudRecord>, u64) {
        let rs = self
            .records
            .iter()
            .filter(|(_, (_, s))| *s > since)
            .map(|(n, (d, _))| CloudRecord {
                name: n.clone(),
                data: d.clone(),
            })
            .collect();
        (rs, self.seq)
    }
}

struct Mac {
    id: DeviceId,
    keys: SoftwareDeviceSigner,
    engine: SyncEngine,
    token: u64,
}

impl Mac {
    fn sync(
        &mut self,
        cloud: &mut MemoryCloud,
        chain: &[SignedRoster],
        now: u64,
    ) -> engine::ApplyReport {
        let (rs, tok) = cloud.fetch(self.token);
        self.token = tok;
        let rep = self.engine.apply_remote(&rs, chain, now).unwrap();
        let out = self.engine.outgoing().unwrap();
        let names = cloud.push(&out);
        self.engine.mark_pushed(&names).unwrap();
        rep
    }
}

fn device(id: DeviceId, k: &SoftwareDeviceSigner) -> Device {
    Device {
        id,
        name: BoundedString::new(format!("Mac {}", id.0[0])).unwrap(),
        role: Role::Admin,
        root_key: k.root.public(),
        device_key: k.device.public(),
        monitor_key: k.monitor.public(),
        ssh_key: k.ssh.public(),
        monitor_ssh_key: k.monitor_ssh.public(),
        noise_static: X25519Public([id.0[0]; 32]),
        added_at: NOW,
        added_by: id,
    }
}

fn setup() -> (Mac, Mac, Vec<SignedRoster>) {
    let key = SyncKey::generate().unwrap();
    let mk = |i: u8| {
        let id = DeviceId([i; 16]);
        Mac {
            id,
            keys: SoftwareDeviceSigner::generate().unwrap(),
            engine: SyncEngine::new(
                SyncStore::open_in_memory(&[i; 32]).unwrap(),
                SyncKey::from_bytes(&key.to_bytes()).unwrap(),
                id,
            )
            .unwrap(),
            token: 0,
        }
    };
    let (a, b) = (mk(1), mk(2));
    let r = Roster {
        fleet_id: fleet_proto::FleetId([7; 16]),
        epoch: 0,
        version: 1,
        prev_hash: [0; 32],
        issued_at_ms: NOW - 1000,
        devices: vec![device(a.id, &a.keys), device(b.id, &b.keys)],
        recovery_key: fleet_proto::Ed25519Public([1; 32]),
        recovery_ssh_key: fleet_proto::Ed25519Public([2; 32]),
        recovery_escrow_key: X25519Public([3; 32]),
        recovery_delay_s: 0,
        prev_recovery: None,
    };
    let g = sign_root(r, a.id, &a.keys.root).unwrap();
    (a, b, vec![g])
}

fn server_doc(name: &str) -> Vec<u8> {
    encode(&ServerDoc {
        name: name.into(),
        host: "web1.example.com".into(),
        port: 22,
        user: "admin".into(),
        jumps: vec![super::bridge::Hop {
            user: "jump".into(),
            host: "bastion".into(),
            port: 2222,
        }],
        group: None,
        tags: vec!["prod".into()],
    })
}

#[test]
fn hlc_orders_and_observes() {
    let mut c = HlcClock::new(DeviceId([1; 16]));
    let a = c.now(100);
    let b = c.now(100);
    let d = c.now(50);
    assert!(
        a < b && b < d,
        "monotonic under a stalled or backwards clock"
    );
    let remote = Hlc {
        wall_ms: 500,
        counter: 3,
        node: DeviceId([2; 16]),
    };
    c.observe(&remote, 100);
    assert!(c.now(100) > remote);
    let far = Hlc {
        wall_ms: 100 + MAX_HLC_DRIFT_MS + 1,
        counter: 0,
        node: DeviceId([2; 16]),
    };
    c.observe(&far, 100);
    assert!(c.now(100) < far, "implausible clocks are not adopted");
}

#[test]
fn servers_sync_and_bridge_into_the_cache() {
    let (mut a, mut b, chain) = setup();
    let mut cloud = MemoryCloud::default();
    a.engine
        .put(
            &a.keys.device,
            Collection::Servers,
            "srv_web001",
            server_doc("web1"),
            NOW,
        )
        .unwrap();
    a.sync(&mut cloud, &chain, NOW);
    assert!(
        cloud
            .records
            .keys()
            .all(|n| n.len() == 32 && !n.contains("web"))
    );
    let rep = b.sync(&mut cloud, &chain, NOW + 1);
    assert_eq!(rep.applied.len(), 1);
    let mut cache = Cache::open_in_memory().unwrap();
    for r in &rep.applied {
        apply_to_cache(&mut cache, r).unwrap();
    }
    let s = cache.servers().unwrap();
    assert_eq!(s[0].name, "web1");
    assert_eq!(s[0].target.proxy_jump.as_ref().unwrap().host, "bastion");
    // Round trip of the doc.
    assert_eq!(encode(&ServerDoc::from_record(&s[0])), server_doc("web1"));
    // Delete syncs as a tombstone.
    a.engine
        .delete(&a.keys.device, Collection::Servers, "srv_web001", NOW + 2)
        .unwrap();
    a.sync(&mut cloud, &chain, NOW + 2);
    let rep = b.sync(&mut cloud, &chain, NOW + 3);
    assert!(rep.applied[0].deleted);
    apply_to_cache(&mut cache, &rep.applied[0]).unwrap();
    assert!(cache.servers().unwrap().is_empty());
    assert!(
        b.engine
            .get(Collection::Servers, "srv_web001")
            .unwrap()
            .is_none()
    );
}

#[test]
fn last_writer_wins_for_non_text_records() {
    let (mut a, mut b, chain) = setup();
    let mut cloud = MemoryCloud::default();
    a.engine
        .put(
            &a.keys.device,
            Collection::Settings,
            "theme",
            b"dark".to_vec(),
            NOW,
        )
        .unwrap();
    b.engine
        .put(
            &b.keys.device,
            Collection::Settings,
            "theme",
            b"light".to_vec(),
            NOW + 5,
        )
        .unwrap();
    a.sync(&mut cloud, &chain, NOW + 6);
    b.sync(&mut cloud, &chain, NOW + 6);
    a.sync(&mut cloud, &chain, NOW + 7);
    for m in [&a, &b] {
        assert_eq!(
            m.engine
                .get(Collection::Settings, "theme")
                .unwrap()
                .unwrap()
                .body,
            b"light"
        );
    }
    assert!(a.engine.conflicts().unwrap().is_empty());
}

#[test]
fn concurrent_text_edits_conflict_once_and_resolve_cleanly() {
    let (mut a, mut b, chain) = setup();
    let mut cloud = MemoryCloud::default();
    a.engine
        .put(
            &a.keys.device,
            Collection::Snippets,
            "restart",
            b"v1".to_vec(),
            NOW,
        )
        .unwrap();
    a.sync(&mut cloud, &chain, NOW);
    b.sync(&mut cloud, &chain, NOW);
    // Offline edits on both, A several times (no self-conflict).
    a.engine
        .put(
            &a.keys.device,
            Collection::Snippets,
            "restart",
            b"a2".to_vec(),
            NOW + 10,
        )
        .unwrap();
    a.engine
        .put(
            &a.keys.device,
            Collection::Snippets,
            "restart",
            b"a3".to_vec(),
            NOW + 11,
        )
        .unwrap();
    b.engine
        .put(
            &b.keys.device,
            Collection::Snippets,
            "restart",
            b"b2".to_vec(),
            NOW + 20,
        )
        .unwrap();
    let ra = a.sync(&mut cloud, &chain, NOW + 30);
    let rb = b.sync(&mut cloud, &chain, NOW + 31);
    assert!(
        ra.conflicts.is_empty() && rb.conflicts.is_empty(),
        "b2 is newer: B keeps it"
    );
    let ra = a.sync(&mut cloud, &chain, NOW + 32);
    assert_eq!(
        ra.conflicts,
        vec![(Collection::Snippets, "restart".to_string())]
    );
    let c = &a.engine.conflicts().unwrap()[0];
    assert_eq!(
        (c.local.body.as_slice(), c.remote.body.as_slice()),
        (&b"a3"[..], &b"b2"[..])
    );
    // A merges; B takes the merge without a new conflict.
    a.engine
        .resolve(
            &a.keys.device,
            Collection::Snippets,
            "restart",
            Resolution::Merged(b"a3+b2".to_vec()),
            NOW + 40,
        )
        .unwrap();
    a.sync(&mut cloud, &chain, NOW + 41);
    let rb = b.sync(&mut cloud, &chain, NOW + 42);
    assert!(rb.conflicts.is_empty());
    for m in [&a, &b] {
        assert_eq!(
            m.engine
                .get(Collection::Snippets, "restart")
                .unwrap()
                .unwrap()
                .body,
            b"a3+b2"
        );
    }
    // Sequential edits never conflict.
    b.engine
        .put(
            &b.keys.device,
            Collection::Snippets,
            "restart",
            b"b4".to_vec(),
            NOW + 50,
        )
        .unwrap();
    b.sync(&mut cloud, &chain, NOW + 51);
    assert!(a.sync(&mut cloud, &chain, NOW + 52).conflicts.is_empty());
    assert_eq!(
        a.engine
            .get(Collection::Snippets, "restart")
            .unwrap()
            .unwrap()
            .body,
        b"b4"
    );
}

#[test]
fn changed_pins_need_local_confirmation() {
    let (mut a, mut b, chain) = setup();
    let mut cloud = MemoryCloud::default();
    let pins = |n: u8| {
        encode(&PinsDoc {
            host_key: None,
            agent_noise: Some([n; 32]),
            agent_signing: Some([n; 32]),
        })
    };
    a.engine
        .put(
            &a.keys.device,
            Collection::PinnedKeys,
            "srv_web001",
            pins(1),
            NOW,
        )
        .unwrap();
    a.sync(&mut cloud, &chain, NOW);
    let rep = b.sync(&mut cloud, &chain, NOW + 1);
    assert_eq!(rep.applied.len(), 1, "a new pin applies directly");
    a.engine
        .put(
            &a.keys.device,
            Collection::PinnedKeys,
            "srv_web001",
            pins(2),
            NOW + 5,
        )
        .unwrap();
    a.sync(&mut cloud, &chain, NOW + 5);
    let rep = b.sync(&mut cloud, &chain, NOW + 6);
    assert_eq!(rep.pin_changes, vec!["srv_web001".to_string()]);
    assert_eq!(
        b.engine
            .get(Collection::PinnedKeys, "srv_web001")
            .unwrap()
            .unwrap()
            .body,
        pins(1)
    );
    let applied = b.engine.confirm_pin_change("srv_web001").unwrap();
    assert_eq!(applied.body, pins(2));
    assert!(b.engine.pending_pin_changes().unwrap().is_empty());
    // A rejected change keeps ours and re-pushes it as newer.
    a.engine
        .put(
            &a.keys.device,
            Collection::PinnedKeys,
            "srv_web001",
            pins(3),
            NOW + 10,
        )
        .unwrap();
    a.sync(&mut cloud, &chain, NOW + 10);
    b.sync(&mut cloud, &chain, NOW + 11);
    b.engine
        .reject_pin_change(&b.keys.device, "srv_web001", NOW + 12)
        .unwrap();
    b.sync(&mut cloud, &chain, NOW + 12);
    let rep = a.sync(&mut cloud, &chain, NOW + 13);
    assert_eq!(rep.pin_changes.len(), 1, "A must confirm B's re-pin too");
}

#[test]
fn signatures_encryption_and_names_are_enforced() {
    let (mut a, mut b, chain) = setup();
    let mut cloud = MemoryCloud::default();
    // Signed by a Mac outside the roster.
    let stranger = SoftwareDeviceSigner::generate().unwrap();
    let mut rec = SyncRecord {
        collection: Collection::Settings,
        key: "x".into(),
        hlc: Hlc {
            wall_ms: NOW,
            counter: 0,
            node: DeviceId([9; 16]),
        },
        base: None,
        author: DeviceId([9; 16]),
        deleted: false,
        body: b"evil".to_vec(),
    };
    let forged = sign_record(rec.clone(), &stranger.device).unwrap();
    // Claiming to be A but signed by the stranger.
    rec.author = a.id;
    rec.hlc.node = a.id;
    rec.key = "x2".into();
    let spoofed = sign_record(rec, &stranger.device).unwrap();
    let key = SyncKey::from_bytes(&a.engine.key().to_bytes()).unwrap();
    let mut recs = vec![
        key.seal_record(&forged).unwrap(),
        key.seal_record(&spoofed).unwrap(),
    ];
    // A genuine record under another item's name.
    let good = sign_record(
        SyncRecord {
            collection: Collection::Settings,
            key: "y".into(),
            hlc: Hlc {
                wall_ms: NOW,
                counter: 0,
                node: a.id,
            },
            base: None,
            author: a.id,
            deleted: false,
            body: b"ok".to_vec(),
        },
        &a.keys.device,
    )
    .unwrap();
    let mut swapped = key.seal_record(&good).unwrap();
    swapped.name = key.record_name(Collection::Settings, "z");
    recs.push(swapped);
    let mut tampered = key.seal_record(&good).unwrap();
    let n = tampered.data.len();
    tampered.data[n - 1] ^= 1;
    recs.push(tampered);
    cloud.push(&recs);
    let rep = b.sync(&mut cloud, &chain, NOW);
    assert_eq!(rep.rejected, 4);
    assert!(rep.applied.is_empty());

    // A revoked Mac: what B held before the removal stays; anything new
    // from it is refused, even stamped (backdated) before the removal.
    let mut r2 = chain[0].roster.clone();
    r2.version = 2;
    r2.prev_hash = fleet_crypto::roster::roster_hash(&chain[0]);
    r2.issued_at_ms = NOW + 100;
    r2.devices.retain(|d| d.id != a.id);
    let s2 = sign_root(r2, b.id, &b.keys.root).unwrap();
    let chain2 = vec![chain[0].clone(), s2];
    let put = |a: &mut Mac, k: &str, at: u64| {
        a.engine
            .put(&a.keys.device, Collection::Settings, k, b"1".to_vec(), at)
            .unwrap();
    };
    put(&mut a, "before", NOW + 50);
    a.sync(&mut cloud, &chain, NOW + 50);
    b.sync(&mut cloud, &chain, NOW + 60);
    put(&mut a, "backdated", NOW + 50);
    put(&mut a, "after", NOW + 200);
    a.sync(&mut cloud, &chain, NOW + 200);
    b.token = 0; // re-fetch everything, "before" included
    let rep = b.sync(&mut cloud, &chain2, NOW + 201);
    // "after" fails the stamp rule, "backdated" the removed-author rule.
    assert_eq!(rep.removed_author, 1, "{rep:?}");
    let has = |b: &Mac, k: &str| b.engine.get(Collection::Settings, k).unwrap().is_some();
    assert!(has(&b, "before"));
    assert!(!has(&b, "backdated") && !has(&b, "after"));
    // Re-verifying stored rows after the roster change keeps "before"
    // (stamped before the removal) and drops nothing else of B's.
    assert!(b.engine.reverify(&chain2, NOW + 201).unwrap().is_empty());
}

#[test]
fn future_stamps_are_quarantined_and_reverify_drops_bad_rows() {
    let (mut a, mut b, chain) = setup();
    let mut cloud = MemoryCloud::default();
    let far = NOW + MAX_HLC_DRIFT_MS + 60_000;
    a.engine
        .put(
            &a.keys.device,
            Collection::Settings,
            "now",
            b"y".to_vec(),
            NOW,
        )
        .unwrap();
    a.engine
        .put(
            &a.keys.device,
            Collection::Settings,
            "future",
            b"x".to_vec(),
            far,
        )
        .unwrap();
    a.sync(&mut cloud, &chain, far);
    let rep = b.sync(&mut cloud, &chain, NOW);
    assert_eq!((rep.future, rep.rejected), (1, 1));
    assert!(
        b.engine
            .get(Collection::Settings, "future")
            .unwrap()
            .is_none()
    );
    // A's own store still has it: re-verifying at NOW drops it.
    let dropped = a.engine.reverify(&chain, NOW).unwrap();
    assert_eq!(dropped, vec![(Collection::Settings, "future".to_string())]);
    // A chain that doesn't list the author at all drops its rows.
    let mut stranger_roster = chain[0].roster.clone();
    stranger_roster.devices.retain(|d| d.id == b.id);
    let other = vec![sign_root(stranger_roster, b.id, &b.keys.root).unwrap()];
    assert_eq!(b.engine.reverify(&other, NOW).unwrap().len(), 1);
}

#[test]
fn readopted_rows_reach_macs_that_trust_only_current_members() {
    let (mut a, mut b, chain) = setup();
    let mut cloud = MemoryCloud::default();
    a.engine
        .put(
            &a.keys.device,
            Collection::Servers,
            "srv_1",
            server_doc("w"),
            NOW,
        )
        .unwrap();
    a.sync(&mut cloud, &chain, NOW);
    b.sync(&mut cloud, &chain, NOW);
    // B revokes A and re-signs A's rows as its own.
    let n = b
        .engine
        .readopt(&b.keys.device, |id| *id != a.id, NOW + 10)
        .unwrap();
    assert_eq!(n, 1);
    let r = b.engine.get(Collection::Servers, "srv_1").unwrap().unwrap();
    assert_eq!((r.author, r.body), (b.id, server_doc("w")));
}

#[test]
fn agreement_keys_are_self_signed() {
    let (a, b, _) = setup();
    let agree = SoftwareP256Recipient::generate().unwrap();
    let doc = keys::DeviceKeysDoc::sign(&a.id, agree.public().to_vec(), &a.keys.device).unwrap();
    assert_eq!(
        doc.verified(&device(a.id, &a.keys)).unwrap(),
        &agree.public()[..]
    );
    // Written by another Mac for A, or signed for another id: refused.
    let by_b = keys::DeviceKeysDoc::sign(&a.id, agree.public().to_vec(), &b.keys.device).unwrap();
    assert!(by_b.verified(&device(a.id, &a.keys)).is_err());
    assert!(doc.verified(&device(b.id, &a.keys)).is_err());
}

#[test]
fn rotation_with_key_boxes_and_escrow() {
    let (mut a, mut b, chain) = setup();
    let mut cloud = MemoryCloud::default();
    a.engine
        .put(
            &a.keys.device,
            Collection::SudoPasswords,
            "srv_web001",
            b"pw".to_vec(),
            NOW,
        )
        .unwrap();
    a.sync(&mut cloud, &chain, NOW);
    b.sync(&mut cloud, &chain, NOW);
    // A rotates (e.g. after revoking a third Mac): re-seal, delete old names,
    // key box for B's enclave key-agreement key.
    let b_agree = SoftwareP256Recipient::generate().unwrap();
    let fleet = fleet_proto::FleetId([7; 16]);
    let new = SyncKey::generate().unwrap();
    let boxed = seal_keybox(
        &new,
        fleet,
        b.id,
        &b_agree.public(),
        keybox_record_name(&b.id, &b_agree.public()),
        &keys::Sealer {
            id: a.id,
            device: &a.keys.device,
        },
    )
    .unwrap();
    let (uploads, old) = a.engine.rotate(new).unwrap();
    cloud.delete(&old);
    cloud.push(&uploads);
    cloud.push(std::slice::from_ref(&boxed));
    a.engine
        .put(
            &a.keys.device,
            Collection::Settings,
            "k",
            b"v".to_vec(),
            NOW + 5,
        )
        .unwrap();
    a.sync(&mut cloud, &chain, NOW + 5);
    // B still on the old key: sees records it can't open.
    let rep = b.sync(&mut cloud, &chain, NOW + 6);
    assert!(rep.other_key > 0);
    // B opens its key box with its enclave key and switches.
    let (fid, k, by) = open_keybox(&boxed, b.id, &b_agree).unwrap();
    assert_eq!(fid, fleet);
    // Only a roster member may hand out a (rotated) key.
    let latest = &chain.last().unwrap().roster;
    assert_eq!(by.verify(latest).unwrap(), a.id);
    let mut without_a = latest.clone();
    without_a.devices.retain(|d| d.id != a.id);
    assert!(matches!(by.verify(&without_a), Err(SyncError::Sealer)));
    // A key box signed by a Mac outside the roster is refused.
    let outsider = SoftwareDeviceSigner::generate().unwrap();
    let forged = seal_keybox(
        &SyncKey::generate().unwrap(),
        fleet,
        b.id,
        &b_agree.public(),
        keybox_record_name(&b.id, &b_agree.public()),
        &keys::Sealer {
            id: a.id,
            device: &outsider.device,
        },
    )
    .unwrap();
    let (_, _, fby) = open_keybox(&forged, b.id, &b_agree).unwrap();
    assert!(fby.verify(latest).is_err(), "right id, wrong key");
    assert!(
        open_keybox(&boxed, a.id, &b_agree).is_err(),
        "addressed to B only"
    );
    let store = SyncStore::open_in_memory(&[2; 32]).unwrap();
    b.engine = SyncEngine::new(store, k, b.id).unwrap();
    b.token = 0;
    let rep = b.sync(&mut cloud, &chain, NOW + 7);
    assert_eq!(rep.other_key, 0);
    assert_eq!(
        b.engine
            .get(Collection::SudoPasswords, "srv_web001")
            .unwrap()
            .unwrap()
            .body,
        b"pw"
    );
    assert_eq!(
        b.engine
            .get(Collection::Settings, "k")
            .unwrap()
            .unwrap()
            .body,
        b"v"
    );
}

#[test]
fn store_is_encrypted_at_rest_and_bound_to_its_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sync.sqlite");
    let k = SoftwareDeviceSigner::generate().unwrap();
    let key = SyncKey::generate().unwrap();
    {
        let mut e = SyncEngine::new(
            SyncStore::open(&path, &[4; 32]).unwrap(),
            key,
            DeviceId([1; 16]),
        )
        .unwrap();
        e.put(
            &k.device,
            Collection::SudoPasswords,
            "srv_x",
            b"hunter2-secret".to_vec(),
            NOW,
        )
        .unwrap();
    }
    let raw = std::fs::read(&path).unwrap();
    let wal = std::fs::read(dir.path().join("sync.sqlite-wal")).unwrap_or_default();
    let needle = b"hunter2-secret";
    assert!(!raw.windows(needle.len()).any(|w| w == needle));
    assert!(!wal.windows(needle.len()).any(|w| w == needle));
    let other = SyncStore::open(&path, &[5; 32]).unwrap();
    assert!(other.rows(None).is_err(), "another cache key can't read it");
}
