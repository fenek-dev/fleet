use fleet_core::cache::{
    Cache, CacheError, CacheKey, GroupRecord, PinnedKeys, RosterRow, ServerRecord,
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

fn key(b: u8) -> CacheKey {
    CacheKey::from_bytes([b; 32])
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
    assert_eq!(c.schema_version().unwrap(), 4);
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
fn jump_pins_are_keyed_by_route() {
    let mut c = Cache::open_in_memory().unwrap();
    c.upsert_server(&record(1)).unwrap();
    // Same second hop (10.0.0.1:2222) behind a different bastion: its pin
    // does not carry over.
    let first = SshTarget::new("bastion2.example", 22, "ops");
    let second = SshTarget::new("10.0.0.1", 2222, "ops").via(first);
    let r = ServerRecord {
        target: SshTarget::new("10.0.1.6", 22, "admin").via(second),
        ..record(2)
    };
    c.upsert_server(&r).unwrap();
    let got = c.server(&sid(2)).unwrap().unwrap().target;
    let hop2 = got.proxy_jump.unwrap();
    assert_eq!(hop2.host, "10.0.0.1");
    assert_eq!(hop2.host_key, None);
    assert_eq!(hop2.proxy_jump.unwrap().host_key, None);
    // The original route still has both pins.
    assert_eq!(c.server(&sid(1)).unwrap().unwrap(), record(1));
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

fn raw(path: &std::path::Path, sql: &str) {
    rusqlite::Connection::open(path)
        .unwrap()
        .execute_batch(sql)
        .unwrap();
}

#[test]
fn tampered_rows_and_wrong_key_are_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.sqlite");
    {
        let mut c = Cache::open(&path, key(1)).unwrap();
        c.upsert_server(&record(1)).unwrap();
        c.set_pins(
            &sid(1),
            &PinnedKeys {
                host_key: Some(host_key(6)),
                agent_noise: Some(X25519Public([3; 32])),
                agent_signing: Some(Ed25519Public([4; 32])),
            },
        )
        .unwrap();
        c.set_setting("fleet_id", &[7; 16]).unwrap();
        c.put_roster(&RosterRow {
            epoch: 0,
            version: 1,
            hash: [1; 32],
            signed: vec![1, 2, 3],
        })
        .unwrap();
    }
    let integrity = |r: Result<_, CacheError>, what: &str| match r {
        Err(CacheError::Integrity(w)) => assert_eq!(w, what),
        Err(e) => panic!("{what}: {e}"),
        Ok(_) => panic!("{what}: tampering not detected"),
    };
    // Wrong key: every protected read fails.
    {
        let c = Cache::open(&path, key(2)).unwrap();
        integrity(c.server(&sid(1)).map(|_| ()), "server address");
        integrity(c.pins(&sid(1)).map(|_| ()), "pinned keys");
        integrity(c.setting("fleet_id").map(|_| ()), "setting");
        integrity(c.roster_chain().map(|_| ()), "roster chain");
    }
    // Right key, edited rows.
    raw(&path, "UPDATE servers SET host = 'evil.example'");
    raw(&path, "UPDATE pinned_keys SET agent_noise = zeroblob(32)");
    raw(&path, "UPDATE settings SET value = x'00'");
    raw(&path, "UPDATE roster_chain SET signed = x'09'");
    let c = Cache::open(&path, key(1)).unwrap();
    integrity(c.server(&sid(1)).map(|_| ()), "server address");
    integrity(c.pins(&sid(1)).map(|_| ()), "pinned keys");
    integrity(c.setting("fleet_id").map(|_| ()), "setting");
    integrity(c.roster_chain().map(|_| ()), "roster chain");
    drop(c);
    // Server row intact, jump pin swapped.
    raw(&path, "DELETE FROM servers");
    {
        let mut c = Cache::open(&path, key(1)).unwrap();
        c.upsert_server(&record(1)).unwrap();
    }
    raw(
        &path,
        "UPDATE jump_pins SET host_key = (SELECT host_key FROM jump_pins WHERE route != '')
         WHERE route = ''",
    );
    let c = Cache::open(&path, key(1)).unwrap();
    integrity(c.server(&sid(1)).map(|_| ()), "jump host pin");
}

#[test]
fn v1_database_is_upgraded_and_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.sqlite");
    {
        // A v1 database as the previous app version left it.
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at_ms INTEGER NOT NULL);
             CREATE TABLE groups (id TEXT PRIMARY KEY, name TEXT NOT NULL, sort INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE servers (id TEXT PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL,
               port INTEGER NOT NULL, user TEXT NOT NULL, proxy_jump TEXT,
               group_id TEXT REFERENCES groups(id) ON DELETE SET NULL);
             CREATE TABLE server_tags (server_id TEXT NOT NULL, tag TEXT NOT NULL, PRIMARY KEY (server_id, tag));
             CREATE TABLE pinned_keys (server_id TEXT PRIMARY KEY, host_key BLOB, agent_noise BLOB,
               agent_signing BLOB, updated_ms INTEGER NOT NULL);
             CREATE TABLE jump_host_keys (host TEXT NOT NULL, port INTEGER NOT NULL, host_key BLOB NOT NULL,
               PRIMARY KEY (host, port));
             CREATE TABLE settings (key TEXT PRIMARY KEY, value BLOB NOT NULL);
             CREATE TABLE roster_chain (epoch INTEGER NOT NULL, version INTEGER NOT NULL, hash BLOB NOT NULL,
               signed BLOB NOT NULL, PRIMARY KEY (epoch, version));
             CREATE TABLE audit_entries (server_id TEXT NOT NULL, seq INTEGER NOT NULL, entry BLOB NOT NULL,
               entry_hash BLOB NOT NULL, PRIMARY KEY (server_id, seq)) WITHOUT ROWID;
             CREATE TABLE audit_checkpoints (server_id TEXT PRIMARY KEY, seq INTEGER NOT NULL,
               checkpoint BLOB NOT NULL, verified_at_ms INTEGER NOT NULL);
             INSERT INTO schema_migrations VALUES (1, 0);
             INSERT INTO servers VALUES ('srv_000001', 'a', 'h', 22, 'u', NULL, NULL);
             INSERT INTO settings VALUES ('fleet_id', x'01');
             INSERT INTO pinned_keys VALUES ('srv_000001', NULL, zeroblob(32), NULL, 0);
             INSERT INTO roster_chain VALUES (0, 1, zeroblob(32), x'02');",
        )
        .unwrap();
    }
    let c = Cache::open(&path, key(3)).unwrap();
    assert!(c.upgraded());
    assert_eq!(c.schema_version().unwrap(), 4);
    assert_eq!(c.server(&sid(1)).unwrap().unwrap().target.host, "h");
    assert_eq!(c.setting("fleet_id").unwrap(), Some(vec![1]));
    assert!(c.pins(&sid(1)).unwrap().is_some());
    assert_eq!(c.roster_chain().unwrap().len(), 1);
    drop(c);
    let c = Cache::open(&path, key(3)).unwrap();
    assert!(!c.upgraded());
    assert!(c.server(&sid(1)).unwrap().is_some());
}

#[test]
fn file_database_migrates_once_and_refuses_newer_schema() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.sqlite");
    {
        let mut c = Cache::open(&path, key(1)).unwrap();
        assert!(!c.upgraded());
        c.upsert_server(&record(1)).unwrap();
    }
    let c = Cache::open(&path, key(1)).unwrap();
    assert_eq!(c.schema_version().unwrap(), 4);
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
        Cache::open(&path, key(1)),
        Err(CacheError::TooNew {
            found: 99,
            supported: 4
        })
    ));
}
