use fleet_agent::pending::{ChangeId, ChangeKind, PendingChange, PendingDir};
use fleet_agent::store::{ChainError, CheckpointSigner, Intent, MetaKey, Store};
use fleet_proto::{
    Actor, DeviceId, OpSummary, Outcome, Phase, ResultSummary, ServerId, Signature,
    SignedCheckpoint,
};

fn open(dir: &tempfile::TempDir) -> Store {
    Store::open(dir.path().join("state.redb")).unwrap()
}

fn intent(n: u8) -> Intent {
    Intent {
        time_ms: 1_000 + u64::from(n),
        actor: Actor::Human,
        device_id: DeviceId([n; 16]),
        command_hash: [n; 32],
        signature: Signature([n; 64]),
        op: OpSummary {
            tag: 0,
            args: vec![n],
        },
    }
}

#[test]
fn audit_chain_appends_and_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let s = open(&dir);
    let a = s.audit();
    assert_eq!(a.verify_chain(1).unwrap().seq, 0);
    let i1 = a.append_intent(intent(1)).unwrap();
    let r1 = a.append_result(i1, 2_000, Outcome::Ok).unwrap();
    let i2 = a.append_intent(intent(2)).unwrap();
    assert_eq!((i1, r1, i2), (1, 2, 3));

    let e1 = a.get(1).unwrap().unwrap();
    assert_eq!(e1.prev_hash, [0; 32]);
    let r = a.get(2).unwrap().unwrap();
    assert_eq!(r.phase, Phase::Result);
    assert_eq!(r.result, ResultSummary::Done(Outcome::Ok));
    assert_eq!(r.command_hash, [1; 32]);

    let head = a.verify_chain(1).unwrap();
    assert_eq!(head, a.head().unwrap());
    assert_eq!(head.seq, 3);
    assert_eq!(a.verify_chain(2).unwrap(), head);

    // Result for a closed or unknown intent is refused.
    assert!(a.append_result(i1, 3_000, Outcome::Ok).is_err());
    assert!(a.append_result(99, 3_000, Outcome::Ok).is_err());

    let since = a.entries_since(1, 10).unwrap();
    assert_eq!(since.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![2, 3]);
    assert_eq!(a.entries_since(0, 1).unwrap().len(), 1);
}

#[test]
fn audit_tamper_detected() {
    let dir = tempfile::tempdir().unwrap();
    let s = open(&dir);
    let a = s.audit();
    for n in 1..=3 {
        a.append_intent(intent(n)).unwrap();
    }
    // Rewrite a middle entry.
    let mut e = a.get(2).unwrap().unwrap();
    e.actor = Actor::Recovery;
    a.tamper_for_test(&e).unwrap();
    assert!(matches!(a.verify_chain(1), Err(ChainError::Broken(3))));

    // Rewrite the last entry: caught by the head.
    let dir2 = tempfile::tempdir().unwrap();
    let s2 = open(&dir2);
    let a2 = s2.audit();
    a2.append_intent(intent(1)).unwrap();
    let mut e = a2.get(1).unwrap().unwrap();
    e.time += 1;
    a2.tamper_for_test(&e).unwrap();
    assert!(matches!(a2.verify_chain(1), Err(ChainError::HeadMismatch)));
}

#[test]
fn audit_interrupted_marking_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    {
        let s = open(&dir);
        let a = s.audit();
        let i1 = a.append_intent(intent(1)).unwrap();
        a.append_intent(intent(2)).unwrap();
        a.append_result(i1, 5, Outcome::Ok).unwrap();
        a.append_intent(intent(3)).unwrap();
    }
    let s = open(&dir);
    let a = s.audit();
    assert_eq!(a.mark_interrupted_on_start(9).unwrap(), vec![2, 4]);
    let tail = a.entries_since(4, 10).unwrap();
    assert_eq!(tail.len(), 2);
    for (e, cmd) in tail.iter().zip([[2u8; 32], [3u8; 32]]) {
        assert_eq!(e.result, ResultSummary::Done(Outcome::Interrupted));
        assert_eq!(e.command_hash, cmd);
    }
    assert!(a.mark_interrupted_on_start(10).unwrap().is_empty());
    a.verify_chain(1).unwrap();
}

struct FixedSigner;
impl CheckpointSigner for FixedSigner {
    fn sign(&self, msg: &[u8]) -> Signature {
        let h = blake3::hash(msg);
        let mut s = [0u8; 64];
        s[..32].copy_from_slice(h.as_bytes());
        Signature(s)
    }
}

#[test]
fn audit_checkpoint_signs_head() {
    let dir = tempfile::tempdir().unwrap();
    let s = open(&dir);
    let a = s.audit();
    a.append_intent(intent(1)).unwrap();
    let head = a.head().unwrap();
    let srv = ServerId::new("srv_abcdef").unwrap();
    let cp = a.checkpoint(srv, 77, &FixedSigner).unwrap();
    assert_eq!(cp.checkpoint.seq, head.seq);
    assert_eq!(cp.checkpoint.entry_hash, head.entry_hash);
    let msg = SignedCheckpoint::signed_message(&cp.checkpoint);
    assert!(msg.starts_with(b"fleet/checkpoint/v1"));
    assert_eq!(cp.signature, FixedSigner.sign(&msg));
}

#[test]
fn replay_durable_across_reopen_and_prune() {
    let dir = tempfile::tempdir().unwrap();
    let dev = DeviceId([7; 16]);
    {
        let s = open(&dir);
        let r = s.replay();
        assert!(r.check_and_insert_nonce(&dev, &[1; 16], 100).unwrap());
        assert!(!r.check_and_insert_nonce(&dev, &[1; 16], 100).unwrap());
        assert!(
            r.check_and_insert_nonce(&DeviceId([8; 16]), &[1; 16], 100)
                .unwrap()
        );
        assert!(r.check_and_insert_leaf(&[3; 16], &[0; 32], 500).unwrap());
        assert!(r.check_and_insert_leaf(&[3; 16], &[1; 32], 500).unwrap());
        assert!(!r.check_and_insert_leaf(&[3; 16], &[0; 32], 500).unwrap());
    }
    let s = open(&dir);
    let r = s.replay();
    assert!(!r.check_and_insert_nonce(&dev, &[1; 16], 100).unwrap());
    assert!(!r.check_and_insert_leaf(&[3; 16], &[1; 32], 500).unwrap());
    assert_eq!(r.len().unwrap(), 4);
    assert_eq!(r.prune(100).unwrap(), 0); // expiry is inclusive
    assert_eq!(r.prune(101).unwrap(), 2);
    assert!(r.check_and_insert_nonce(&dev, &[1; 16], 200).unwrap());
    assert_eq!(r.prune(1_000).unwrap(), 3);
    assert!(r.is_empty().unwrap());
    assert_eq!(r.prune(2_000).unwrap(), 0); // nothing to remove: no commit
}

#[test]
fn replay_read_only_lookups() {
    use fleet_crypto::verify::ReplayStore;
    let dir = tempfile::tempdir().unwrap();
    let s = open(&dir);
    let mut r = s.replay();
    let dev = DeviceId([9; 16]);
    assert!(!r.contains_nonce(dev, [1; 16]));
    assert!(!r.contains_leaf([2; 16], [3; 32]));
    assert!(r.is_empty().unwrap(), "lookups write nothing");
    assert!(ReplayStore::check_and_insert_nonce(
        &mut r, dev, [1; 16], 10
    ));
    assert!(ReplayStore::check_and_insert_leaf(
        &mut r, [2; 16], [3; 32], 10
    ));
    assert!(r.contains_nonce(dev, [1; 16]));
    assert!(r.contains_leaf([2; 16], [3; 32]));
    assert!(!ReplayStore::check_and_insert_nonce(
        &mut r, dev, [1; 16], 10
    ));
}

#[test]
fn pending_changes_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let p = PendingDir::new(dir.path().join("pending"), dir.path().join("reverted"));
    p.create().unwrap();
    // Temp files and foreign names are ignored.
    std::fs::write(dir.path().join("pending/.x.tmp"), b"junk").unwrap();
    let mk = |deadline_ms| PendingChange {
        kind: ChangeKind::Firewall,
        origin: Default::default(),
        snapshot: vec![1, 2, 3],
        deadline_ms,
        audit_seq: 1,
        applying: false,
    };
    p.insert(ChangeId([1; 16]), &mk(100)).unwrap();
    p.insert(ChangeId([2; 16]), &mk(200)).unwrap();
    assert!(p.expired(99).unwrap().is_empty());
    let e = p.expired(150).unwrap();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].0, ChangeId([1; 16]));
    assert_eq!(p.get(ChangeId([1; 16])).unwrap(), Some(mk(100)));
    assert!(p.remove(ChangeId([1; 16])).unwrap());
    assert!(!p.remove(ChangeId([1; 16])).unwrap());
    assert_eq!(p.expired(1_000).unwrap().len(), 1);
    use std::os::unix::fs::MetadataExt;
    let f = dir
        .path()
        .join(format!("pending/{}.bin", ChangeId([2; 16])));
    assert_eq!(std::fs::metadata(f).unwrap().mode() & 0o777, 0o600);
}

#[test]
fn event_log_orders_runs_pages_and_prunes() {
    let dir = tempfile::tempdir().unwrap();
    let s = open(&dir);
    let ev = s.events();
    let (r0, r1) = ([1u8; 16], [0u8; 16]);
    // Run ordinals, not the random ids, order the log.
    let o0 = ev.begin_run(&r0).unwrap();
    let o1 = ev.begin_run(&r1).unwrap();
    assert!(o1 > o0);
    for seq in 1..=3 {
        ev.append(o0, seq, 100 + seq, &[seq as u8]).unwrap();
    }
    ev.append(o1, 1, 500, b"b1").unwrap();
    let keys = |v: Vec<fleet_agent::store::StoredEvent>| -> Vec<(u64, u64)> {
        v.into_iter().map(|e| (e.run, e.seq)).collect()
    };
    let (all, more) = ev.after(None, 0, 10, 1 << 20).unwrap();
    assert!(!more);
    assert_eq!(keys(all), [(o0, 1), (o0, 2), (o0, 3), (o1, 1)]);
    let (page, more) = ev.after(Some(&r0), 1, 2, 1 << 20).unwrap();
    assert!(more);
    assert_eq!(keys(page), [(o0, 2), (o0, 3)]);
    let (page, _) = ev.after(Some(&r0), 3, 10, 1 << 20).unwrap();
    assert_eq!(keys(page), [(o1, 1)]);
    // Unknown run: from the oldest kept.
    let (page, _) = ev.after(Some(&[9; 16]), 0, 1, 1 << 20).unwrap();
    assert_eq!(keys(page), [(o0, 1)]);
    assert_eq!(
        keys(ev.in_run_after(o0, 1, 10).unwrap()),
        [(o0, 2), (o0, 3)]
    );
    // Age: everything before 103 goes; count: at most 2 rows.
    assert_eq!(ev.prune(103, 100, o1).unwrap(), 2);
    assert_eq!(ev.prune(0, 1, o1).unwrap(), 1);
    assert_eq!(ev.len().unwrap(), 1);
    let (left, _) = ev.after(None, 0, 10, 1 << 20).unwrap();
    assert_eq!(keys(left), [(o1, 1)]);
    // Run r0 has no events left: a query for it starts at the oldest.
    let (page, _) = ev.after(Some(&r0), 0, 10, 1 << 20).unwrap();
    assert_eq!(keys(page), [(o1, 1)]);
}

#[test]
fn meta_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let s = open(&dir);
    assert_eq!(s.meta().get(MetaKey::Roster).unwrap(), None);
    s.meta().set(MetaKey::Roster, b"r1").unwrap();
    s.meta().set(MetaKey::Roster, b"r2").unwrap();
    assert_eq!(
        s.meta().get(MetaKey::Roster).unwrap().as_deref(),
        Some(&b"r2"[..])
    );
    assert_eq!(s.meta().get(MetaKey::Policy).unwrap(), None);
}
