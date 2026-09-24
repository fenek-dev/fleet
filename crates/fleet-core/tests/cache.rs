use fleet_core::cache::{
    AuditRow, Cache, CacheError, CheckpointRow, GroupRecord, METRICS_RETENTION_MS, PinnedKeys,
    RosterRow, ServerRecord,
};
use fleet_core::ssh::{HostKey, SshSigner, SshTarget};
use fleet_crypto::sig::Ed25519Signer;
use fleet_proto::{Ed25519Public, ServerId, X25519Public};

fn sid(i: usize) -> ServerId {
    ServerId::new(format!("srv_{i:06}")).unwrap()
}

fn host_key(seed: u8) -> HostKey {
    let k = Ed25519Signer::from_seed(&[seed; 32]);
    HostKey::from_blob(&SshSigner::public_key(&k).blob().unwrap()).unwrap()
}

fn record(i: usize) -> ServerRecord {
    let mut first = SshTarget::new("bastion1.example", 22, "ops");
    first.host_key = Some(host_key(1));
    let mut second = SshTarget::new("10.0.0.1", 2222, "ops").via(first);
    second.host_key = Some(host_key(2));
    ServerRecord {
        id: sid(i),
        name: format!("web-{i}"),
        target: SshTarget::new("10.0.1.5", 22, "admin").via(second),
        group: None,
        tags: vec!["prod".into(), "web".into()],
    }
}

#[test]
fn servers_groups_tags_and_jump_chain_roundtrip() {
    let mut c = Cache::open_in_memory().unwrap();
    assert_eq!(c.schema_version().unwrap(), 1);
    c.upsert_group(&GroupRecord {
        id: "g1".into(),
        name: "Web".into(),
        sort: 0,
    })
    .unwrap();
    let r = ServerRecord {
        group: Some("g1".into()),
        ..record(1)
    };
    c.upsert_server(&r).unwrap();
    assert_eq!(c.server(&sid(1)).unwrap().unwrap(), r);
    assert_eq!(c.server(&sid(2)).unwrap(), None);

    let mut r2 = record(2);
    r2.target = SshTarget::new("h", 22, "u");
    r2.tags = vec![];
    r2.group = None;
    c.upsert_server(&r2).unwrap();
    assert_eq!(c.servers().unwrap(), vec![r.clone(), r2]);

    // Deleting a group detaches its servers.
    c.delete_group("g1").unwrap();
    assert_eq!(c.server(&sid(1)).unwrap().unwrap().group, None);
    assert!(c.groups().unwrap().is_empty());

    c.delete_server(&sid(1)).unwrap();
    assert_eq!(c.servers().unwrap().len(), 1);
}

#[test]
fn pins() {
    let mut c = Cache::open_in_memory().unwrap();
    c.upsert_server(&record(1)).unwrap();
    assert_eq!(c.pins(&sid(1)).unwrap(), None);
    c.pin_host_key(&sid(1), &host_key(5)).unwrap();
    assert_eq!(
        c.pins(&sid(1)).unwrap().unwrap(),
        PinnedKeys {
            host_key: Some(host_key(5)),
            ..Default::default()
        }
    );
    let all = PinnedKeys {
        host_key: Some(host_key(6)),
        agent_noise: Some(X25519Public([3; 32])),
        agent_signing: Some(Ed25519Public([4; 32])),
    };
    c.set_pins(&sid(1), &all).unwrap();
    assert_eq!(c.pins(&sid(1)).unwrap().unwrap(), all);
    // Upserting the server keeps its pins.
    c.upsert_server(&record(1)).unwrap();
    assert_eq!(c.pins(&sid(1)).unwrap().unwrap(), all);
    // Pins can't exist for unknown servers.
    assert!(c.set_pins(&sid(9), &all).is_err());
}

#[test]
fn audit_mirror_and_checkpoints() {
    let mut c = Cache::open_in_memory().unwrap();
    c.upsert_server(&record(1)).unwrap();
    assert_eq!(c.last_audit_seq(&sid(1)).unwrap(), None);
    let rows: Vec<AuditRow> = (1..=5)
        .map(|s| AuditRow {
            seq: s,
            entry: vec![s as u8; 10],
            entry_hash: [s as u8; 32],
        })
        .collect();
    c.append_audit(&sid(1), &rows).unwrap();
    c.append_audit(&sid(1), &rows[3..]).unwrap(); // idempotent
    assert_eq!(c.last_audit_seq(&sid(1)).unwrap(), Some(5));
    assert_eq!(c.audit_range(&sid(1), 2, 2).unwrap(), rows[1..3].to_vec());
    let cp = CheckpointRow {
        seq: 5,
        checkpoint: vec![1, 2, 3],
        verified_at_ms: 42,
    };
    c.set_checkpoint(&sid(1), &cp).unwrap();
    assert_eq!(c.checkpoint(&sid(1)).unwrap(), Some(cp));
    c.delete_server(&sid(1)).unwrap();
    assert!(c.audit_range(&sid(1), 0, 100).unwrap().is_empty());
    assert_eq!(c.checkpoint(&sid(1)).unwrap(), None);
}

#[test]
fn metrics_rollups_and_pruning() {
    let mut c = Cache::open_in_memory().unwrap();
    c.upsert_server(&record(1)).unwrap();
    let now = 1_800_000_000_000u64;
    let old = now - METRICS_RETENTION_MS - 60_000;
    c.put_metric(&sid(1), "cpu", old, 1.0).unwrap();
    c.put_metric(&sid(1), "cpu", now - 61_000, 2.0).unwrap();
    c.put_metric(&sid(1), "cpu", now - 60_500, 3.0).unwrap(); // same minute: replaces
    c.put_metric(&sid(1), "mem", now, 9.0).unwrap();
    let minute = |t: u64| t - t % 60_000;
    assert_eq!(
        c.metrics(&sid(1), "cpu", 0).unwrap(),
        vec![(minute(old), 1.0), (minute(now - 61_000), 3.0)]
    );
    assert_eq!(c.prune_metrics(now).unwrap(), 1);
    assert_eq!(c.metrics(&sid(1), "cpu", 0).unwrap().len(), 1);
}

#[test]
fn settings_and_roster_chain() {
    let c = Cache::open_in_memory().unwrap();
    assert_eq!(c.setting("ai.paused").unwrap(), None);
    c.set_setting("ai.paused", b"1").unwrap();
    c.set_setting("ai.paused", b"0").unwrap();
    assert_eq!(c.setting("ai.paused").unwrap(), Some(b"0".to_vec()));
    let r = |e, v| RosterRow {
        epoch: e,
        version: v,
        hash: [v as u8; 32],
        signed: vec![e as u8, v as u8],
    };
    c.put_roster(&r(1, 2)).unwrap();
    c.put_roster(&r(1, 1)).unwrap();
    c.put_roster(&r(2, 3)).unwrap();
    c.put_roster(&r(1, 1)).unwrap();
    assert_eq!(c.roster_chain().unwrap(), vec![r(1, 1), r(1, 2), r(2, 3)]);
}

#[test]
fn file_database_migrates_once_and_refuses_newer_schema() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.sqlite");
    {
        let mut c = Cache::open(&path).unwrap();
        c.upsert_server(&record(1)).unwrap();
    }
    let c = Cache::open(&path).unwrap();
    assert_eq!(c.schema_version().unwrap(), 1);
    assert_eq!(c.servers().unwrap().len(), 1);
    drop(c);
    {
        let raw = rusqlite::Connection::open(&path).unwrap();
        let mode: String = raw
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        raw.execute(
            "INSERT INTO schema_migrations (version, applied_at_ms) VALUES (99, 0)",
            [],
        )
        .unwrap();
    }
    assert!(matches!(
        Cache::open(&path),
        Err(CacheError::TooNew {
            found: 99,
            supported: 1
        })
    ));
}
