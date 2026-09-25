use super::*;
use crate::ManualClock;
use crate::handler::{OpHandler, OpOutput};
use crate::runner::FakeRunner;
use crate::security::VecSink;
use crate::testutil::{block, meta};
use fleet_proto::args::{AbsPath, TimeRange};
use fleet_proto::op::tag;
use fleet_proto::{Op, Payload};
use std::os::unix::fs::symlink;
use std::path::Path;

struct Rig {
    dir: tempfile::TempDir,
    ctx: SysCtx,
    clock: Rc<ManualClock>,
    store: Rc<MemStore>,
    sink: Rc<VecSink>,
    t: Rc<ConfigTracker>,
}

impl Rig {
    fn new() -> Self {
        Self::with(Retention::default())
    }

    fn with(ret: Retention) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        for d in [
            "etc/ssh",
            "etc/nginx",
            "etc/fleet",
            "srv/app",
            "etc/ssl/private",
        ] {
            std::fs::create_dir_all(r.join(d)).unwrap();
        }
        std::fs::write(r.join("etc/nginx/nginx.conf"), "worker_processes 1;\n").unwrap();
        std::fs::write(r.join("etc/shadow"), "root:$6$hash:19000::::::\n").unwrap();
        std::fs::write(r.join("etc/ssh/ssh_host_ed25519_key"), "KEYDATA\n").unwrap();
        std::fs::write(r.join("etc/fleet/policy.toml"), "x = 1\n").unwrap();
        std::fs::write(r.join("srv/app/compose.yaml"), "services: {}\n").unwrap();
        std::fs::write(r.join("srv/app/.env"), "DB_PASSWORD=hunter2\n").unwrap();
        let clock = Rc::new(ManualClock::new(1_700_000_000_000));
        let ctx = SysCtx::new(r, Rc::new(FakeRunner::new()), clock.clone());
        let store = Rc::new(MemStore::default());
        let sink = Rc::new(VecSink::default());
        let t =
            ConfigTracker::with_retention(store.clone(), sink.clone(), Rc::new(Unattributed), ret)
                .unwrap();
        Self {
            dir,
            ctx,
            clock,
            store,
            sink,
            t,
        }
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn write(&self, rel: &str, content: &str) {
        std::fs::write(self.root().join(rel), content).unwrap();
        // Distinct mtimes even on coarse filesystems: the scan fast path
        // compares size, mtime and inode.
        self.clock.advance(Duration::from_secs(1));
    }

    fn scan(&self) -> ScanReport {
        block(self.t.scan(&self.ctx)).unwrap()
    }

    fn versions(&self, p: &str) -> Vec<(u64, VersionRecord)> {
        self.store.versions(p).unwrap()
    }

    fn run(&self, op: Op, expected: Option<u64>) -> Result<Payload, OpError> {
        let h = ConfigOps(self.t.clone());
        let mut m = meta(op.clone(), None);
        m.command.body.expected_version = expected;
        h.validate(&self.ctx, &op, &m)?;
        m.audit_seq = Some(77);
        match block(h.handle(&self.ctx, &op, &m))? {
            OpOutput::Payload(p) => Ok(p),
            OpOutput::Stream(_) => panic!("stream"),
        }
    }
}

fn ap(s: &str) -> AbsPath {
    AbsPath::new(s).unwrap()
}

#[test]
fn baseline_then_scan_detects_changes() {
    let r = Rig::new();
    let rep = r.scan();
    assert!(!rep.truncated);
    // nginx.conf, shadow, host key, fleet policy, compose.yaml (not .env).
    assert_eq!(rep.files, 5, "{rep:?}");
    // Baseline: versions recorded, no events.
    assert!(r.sink.take().is_empty());
    assert_eq!(r.versions("/etc/nginx/nginx.conf").len(), 1);
    assert_eq!(r.versions("/srv/app/compose.yaml").len(), 1);
    // Nothing changed: nothing recorded.
    assert_eq!(r.scan().changed, 0);
    // Content change (same size, so hashing decides).
    r.write("etc/nginx/nginx.conf", "worker_processes 2;\n");
    let rep = r.scan();
    assert_eq!(rep.changed, 1);
    let v = r.versions("/etc/nginx/nginx.conf");
    assert_eq!(v.len(), 2);
    assert_eq!(v[1].1.source, ChangeSource::Unknown);
    let ev = r.sink.take();
    assert_eq!(
        ev,
        vec![Event::ConfigChanged {
            path: "/etc/nginx/nginx.conf".into(),
            version: 2,
            source: ChangeSource::Unknown,
            secret: false,
        }]
    );
    // New file, then deletion.
    r.write("etc/nginx/extra.conf", "a\n");
    assert_eq!(r.scan().changed, 1);
    std::fs::remove_file(r.root().join("etc/nginx/extra.conf")).unwrap();
    assert_eq!(r.scan().changed, 1);
    let v = r.versions("/etc/nginx/extra.conf");
    assert!(v[1].1.deleted);
    assert!(
        r.store
            .file("/etc/nginx/extra.conf")
            .unwrap()
            .unwrap()
            .deleted
    );
    // Mode change is a version too.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        r.root().join("etc/nginx/nginx.conf"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert_eq!(r.scan().changed, 1);
}

#[test]
fn symlinks_are_not_followed_or_tracked() {
    let r = Rig::new();
    std::fs::create_dir_all(r.root().join("outside")).unwrap();
    std::fs::write(r.root().join("outside/private"), "TOPSECRET\n").unwrap();
    symlink(r.root().join("outside/private"), r.root().join("etc/leak")).unwrap();
    symlink(r.root().join("outside"), r.root().join("etc/leakdir")).unwrap();
    r.scan();
    assert!(r.store.file("/etc/leak").unwrap().is_none());
    assert!(r.store.file("/etc/leakdir/private").unwrap().is_none());
    // Observing through the symlink directly records nothing either.
    let v =
        r.t.observe(&r.ctx, "/etc/leakdir/private", ChangeSource::Unknown, true)
            .unwrap();
    assert!(v.is_none());
}

#[test]
fn secrets_never_store_content() {
    let r = Rig::new();
    r.write(
        "etc/nginx/site.key",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n",
    );
    r.scan();
    for p in [
        "/etc/shadow",
        "/etc/ssh/ssh_host_ed25519_key",
        "/etc/nginx/site.key",
    ] {
        let v = r.versions(p);
        assert_eq!(v.len(), 1, "{p}");
        let rec = &v[0].1;
        assert!(rec.secret, "{p}");
        assert!(!rec.has_content(), "{p}");
        assert!(
            r.store.blob(&rec.hash).unwrap().is_none(),
            "{p}: blob stored"
        );
        assert_ne!(rec.hash, [0; 32]);
    }
    // /srv/**/.env: not tracked by default (no rule covers it), never stored.
    assert!(r.versions("/srv/app/.env").is_empty());
    // A change raises an event flagged secret, still no content.
    r.write("etc/shadow", "root:$6$other:19001::::::\n");
    r.scan();
    let ev = r.sink.take();
    assert!(matches!(
        &ev[..],
        [Event::ConfigChanged {
            secret: true,
            version: 2,
            ..
        }]
    ));
    let v = r.versions("/etc/shadow");
    assert!(r.store.blob(&v[1].1.hash).unwrap().is_none());
    // Diff is hash-only.
    let p = r
        .run(
            Op::ConfigDiff {
                path: ap("/etc/shadow"),
                from: 1,
                to: None,
            },
            None,
        )
        .unwrap();
    let Payload::ConfigDiff(d) = p else { panic!() };
    assert!(d.unified.starts_with("secret /etc/shadow"), "{}", d.unified);
    assert!(!d.unified.contains("$6$"));
    // Rollback of a secret is refused.
    let e = r
        .run(
            Op::ConfigRollback {
                path: ap("/etc/shadow"),
                version: 1,
            },
            None,
        )
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    // Every blob in the store is non-secret content.
    assert!(r.store.blob_bytes().unwrap() > 0);
}

#[test]
fn operator_secret_rule_strips_existing_content() {
    let r = Rig::new();
    r.scan();
    let v = r.versions("/etc/nginx/nginx.conf");
    assert!(v[0].1.has_content());
    let p = r
        .run(
            Op::ConfigPathsSet {
                tracked: vec![ap("/srv/app")],
                secret: vec![ap("/etc/nginx")],
            },
            Some(0),
        )
        .unwrap();
    let Payload::ConfigPaths(cp) = p else {
        panic!()
    };
    assert_eq!(cp.version, 1);
    assert_eq!(cp.secret, ["/etc/nginx"]);
    let v = r.versions("/etc/nginx/nginx.conf");
    assert!(!v[0].1.has_content());
    assert!(r.store.blob(&v[0].1.hash).unwrap().is_none());
    // Stale version: conflict.
    let e = r
        .run(
            Op::ConfigPathsSet {
                tracked: vec![],
                secret: vec![],
            },
            Some(0),
        )
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::VersionConflict { current: 1 });
    // Newly tracked /srv/app picks up .env as a secret (hash only).
    r.scan();
    let v = r.versions("/srv/app/.env");
    assert_eq!(v.len(), 1);
    assert!(v[0].1.secret && !v[0].1.has_content());
}

#[test]
fn diff_output() {
    let r = Rig::new();
    r.scan();
    r.write("etc/nginx/nginx.conf", "worker_processes 1;\nevents {}\n");
    r.scan();
    let p = r
        .run(
            Op::ConfigDiff {
                path: ap("/etc/nginx/nginx.conf"),
                from: 1,
                to: Some(2),
            },
            None,
        )
        .unwrap();
    let Payload::ConfigDiff(d) = p else { panic!() };
    assert!(!d.binary);
    assert_eq!(
        d.unified,
        "--- a/etc/nginx/nginx.conf@v1\n+++ b/etc/nginx/nginx.conf@v2\n@@ -1,1 +1,2 @@\n worker_processes 1;\n+events {}\n"
    );
    // Against the live file.
    r.write("etc/nginx/nginx.conf", "worker_processes 1;\n");
    let Payload::ConfigDiff(d) = r
        .run(
            Op::ConfigDiff {
                path: ap("/etc/nginx/nginx.conf"),
                from: 2,
                to: None,
            },
            None,
        )
        .unwrap()
    else {
        panic!()
    };
    assert!(d.unified.contains("-events {}\n"));
    assert!(d.unified.contains("@now"));
    // Binary content: summary only.
    std::fs::write(r.root().join("etc/bin.db"), [0u8, 1, 2]).unwrap();
    r.scan();
    std::fs::write(r.root().join("etc/bin.db"), [0u8, 1, 3]).unwrap();
    r.scan();
    let Payload::ConfigDiff(d) = r
        .run(
            Op::ConfigDiff {
                path: ap("/etc/bin.db"),
                from: 1,
                to: Some(2),
            },
            None,
        )
        .unwrap()
    else {
        panic!()
    };
    assert!(d.binary);
    assert!(d.unified.starts_with("binary /etc/bin.db"));
    // Unknown version.
    let e = r
        .run(
            Op::ConfigDiff {
                path: ap("/etc/bin.db"),
                from: 9,
                to: None,
            },
            None,
        )
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::NotFound);
}

#[test]
fn rollback_restores_and_records() {
    let r = Rig::new();
    r.scan();
    r.write("etc/nginx/nginx.conf", "broken\n");
    r.scan();
    r.sink.take();
    let p = r
        .run(
            Op::ConfigRollback {
                path: ap("/etc/nginx/nginx.conf"),
                version: 1,
            },
            None,
        )
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(r.root().join("etc/nginx/nginx.conf")).unwrap(),
        "worker_processes 1;\n"
    );
    let Payload::ConfigHistory(h) = p else {
        panic!()
    };
    assert_eq!(h.versions.len(), 1);
    assert_eq!(h.versions[0].version, 3);
    let src = ChangeSource::Fleet {
        op_tag: tag::CONFIG_ROLLBACK,
        audit_seq: 77,
    };
    assert_eq!(h.versions[0].source, src);
    assert_eq!(
        r.sink.take(),
        vec![Event::ConfigChanged {
            path: "/etc/nginx/nginx.conf".into(),
            version: 3,
            source: src,
            secret: false,
        }]
    );
    // Same content as version 1: the blob is shared, not duplicated.
    let v = r.versions("/etc/nginx/nginx.conf");
    assert_eq!(v[0].1.hash, v[2].1.hash);
    // A later scan sees no change.
    assert_eq!(r.scan().changed, 0);
}

#[test]
fn rollback_refusals() {
    let r = Rig::new();
    r.scan();
    let bad = |path: &str, version: u64| {
        r.run(
            Op::ConfigRollback {
                path: ap(path),
                version,
            },
            None,
        )
        .unwrap_err()
        .code()
    };
    // Fleet's own configuration and state.
    assert_eq!(bad("/etc/fleet/policy.toml", 1), ErrorCode::InvalidArgument);
    assert_eq!(
        bad("/var/lib/fleet/exec/state.redb", 1),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        bad("/etc/systemd/system/fleet-exec.service", 1),
        ErrorCode::InvalidArgument
    );
    // Untracked, unknown version, deletion.
    assert_eq!(bad("/opt/x.conf", 1), ErrorCode::InvalidArgument);
    assert_eq!(bad("/etc/nginx/nginx.conf", 5), ErrorCode::NotFound);
    std::fs::remove_file(r.root().join("etc/nginx/nginx.conf")).unwrap();
    r.scan();
    assert_eq!(bad("/etc/nginx/nginx.conf", 2), ErrorCode::InvalidArgument);
    // Target replaced by a symlink: refused, the link target untouched.
    std::fs::write(r.root().join("elsewhere"), "keep").unwrap();
    symlink(
        r.root().join("elsewhere"),
        r.root().join("etc/nginx/nginx.conf"),
    )
    .unwrap();
    assert_eq!(bad("/etc/nginx/nginx.conf", 1), ErrorCode::Internal);
    assert_eq!(std::fs::read(r.root().join("elsewhere")).unwrap(), b"keep");
    // The catalog makes protected paths Elevated.
    let op = Op::ConfigRollback {
        path: ap("/etc/ssh/sshd_config"),
        version: 1,
    };
    assert_eq!(op.tier(), fleet_proto::Tier::Elevated);
}

#[test]
fn history_queries() {
    let r = Rig::new();
    r.scan();
    for i in 0..5 {
        r.write("etc/nginx/nginx.conf", &format!("v{i}\n"));
        r.scan();
    }
    let Payload::ConfigHistory(h) = r
        .run(
            Op::ConfigHistory {
                path: Some(ap("/etc/nginx/nginx.conf")),
                range: TimeRange::default(),
                limit: 3,
            },
            None,
        )
        .unwrap()
    else {
        panic!()
    };
    let vs: Vec<u64> = h.versions.iter().map(|v| v.version).collect();
    assert_eq!(vs, [6, 5, 4]);
    assert!(h.truncated);
    let Payload::ConfigHistory(h) = r
        .run(
            Op::ConfigHistory {
                path: None,
                range: TimeRange {
                    since_ms: Some(1_700_000_000_000 + 1),
                    until_ms: None,
                },
                limit: 100,
            },
            None,
        )
        .unwrap()
    else {
        panic!()
    };
    // Only the five later nginx versions (the baseline is at t0).
    assert_eq!(h.versions.len(), 5);
    assert!(h.versions.iter().all(|v| v.path == "/etc/nginx/nginx.conf"));
    assert!(h.versions[0].time_ms >= h.versions[4].time_ms);
    assert!(!h.truncated);
}

#[test]
fn retention_pruning() {
    let r = Rig::with(Retention {
        max_age_ms: 10_000,
        max_versions: 3,
        disk_budget: 1 << 30,
    });
    r.scan();
    for i in 0..6 {
        r.write("etc/nginx/nginx.conf", &format!("content {i}\n"));
        r.scan();
    }
    assert_eq!(r.versions("/etc/nginx/nginx.conf").len(), 7);
    // Count cap: newest 3 kept (all within max age: 1 s apart).
    let now = r.ctx.clock.now_ms();
    r.t.prune(now).unwrap();
    let v: Vec<u64> = r
        .versions("/etc/nginx/nginx.conf")
        .iter()
        .map(|(v, _)| *v)
        .collect();
    assert_eq!(v, [5, 6, 7]);
    // Age: everything past 10 s goes except the latest version per file.
    r.t.prune(now + 60_000).unwrap();
    let v: Vec<u64> = r
        .versions("/etc/nginx/nginx.conf")
        .iter()
        .map(|(v, _)| *v)
        .collect();
    assert_eq!(v, [7]);
    assert_eq!(r.versions("/etc/fleet/policy.toml").len(), 1);
    // Blobs of dropped versions are gone.
    let bytes = r.store.blob_bytes().unwrap();
    let files = r.store.files().unwrap();
    let expected: u64 = files
        .iter()
        .filter_map(|(p, st)| r.store.record(p, st.version).unwrap())
        .filter(|rec| rec.has_content())
        .map(|rec| u64::from(rec.stored))
        .sum();
    assert_eq!(bytes, expected);
}

#[test]
fn disk_budget_drops_oldest_content() {
    let r = Rig::with(Retention {
        max_age_ms: u64::MAX,
        max_versions: 1000,
        disk_budget: 0,
    });
    r.scan();
    for i in 0..3 {
        r.write("etc/nginx/nginx.conf", &format!("c{i}\n"));
        r.scan();
    }
    r.t.prune(r.ctx.clock.now_ms()).unwrap();
    // Only latest versions survive a zero budget.
    assert_eq!(r.versions("/etc/nginx/nginx.conf").len(), 1);
}

#[cfg(target_os = "linux")]
#[test]
fn inotify_reports_changes() {
    let r = Rig::new();
    let mut w = watch::Watcher::new(&r.ctx, &["/etc".to_owned()]).expect("inotify");
    std::fs::write(r.root().join("etc/nginx/nginx.conf"), "changed\n").unwrap();
    std::fs::create_dir_all(r.root().join("etc/newdir")).unwrap();
    let b = block(async {
        tokio::time::timeout(Duration::from_secs(5), w.next())
            .await
            .unwrap()
    });
    let watch::Batch::Paths(p) = b else {
        panic!("{b:?}")
    };
    assert!(p.contains(&"/etc/nginx/nginx.conf".to_owned()), "{p:?}");
}
