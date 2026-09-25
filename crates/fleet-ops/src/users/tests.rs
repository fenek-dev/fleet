use super::authorized_keys::{
    self, AuthorizedKeysHandler, AuthorizedKeysReverter, BEGIN, END, MergeError,
};
use super::*;
use crate::revertible::Revertible;
use crate::runner::{CommandOutput, FakeRunner};
use crate::security::VecSink;
use crate::testutil::{block, ctx, meta};
use fleet_proto::args::{Label, SshKeyAlgo, SshPublicKey};
use fleet_proto::op::LoginShell;
use fleet_proto::{Tier, UserChangeKind};
use std::path::Path;

const DEV: &str = "d_02020202020202020202020202020202";

fn roster_block() -> String {
    format!("{BEGIN}\necdsa-sha2-nistp256 AAAA fleet-device-{DEV}\n{END}\n")
}

fn root() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    let p = d.path();
    std::fs::create_dir_all(p.join("etc/fleet/authorized_keys")).unwrap();
    std::fs::write(
        p.join("etc/passwd"),
        "root:x:0:0:root:/root:/bin/bash\nsshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n\
         admin:x:1000:1000::/home/admin:/bin/bash\nweb:x:1001:1001::/home/web:/bin/bash\n\
         ci:x:1002:1002::/home/ci:/bin/sh\ntoor:x:0:1003::/:/bin/sh\n",
    )
    .unwrap();
    std::fs::write(
        p.join("etc/group"),
        "root:x:0:\nsudo:x:27:admin,ci\ndocker:x:999:\nadmin:x:1000:\nweb:x:1001:\nci:x:1002:\n",
    )
    .unwrap();
    std::fs::write(
        p.join("etc/shadow"),
        "root:$6$r$hash:19000:0:99999:7:::\nadmin:!:19000:0:99999:7:::\n\
         web:!$6$w$hash:19000:0:99999:7:::\nci:!:19000:0:99999:7::1:\n",
    )
    .unwrap();
    std::fs::write(p.join("etc/login.defs"), "UID_MIN 1000\nUID_MAX 60000\n").unwrap();
    std::fs::write(
        p.join("etc/fleet/authorized_keys/admin"),
        format!("{}ssh-ed25519 AAAAold other\n", roster_block()),
    )
    .unwrap();
    d
}

fn users(p: &Path, runner: Rc<FakeRunner>) -> (SysCtx, Rc<VecSink>, UsersHandler) {
    let sink = Rc::new(VecSink::default());
    let h = UsersHandler { sink: sink.clone() };
    (ctx(p, runner), sink, h)
}

fn run_op(h: &dyn OpHandler, c: &SysCtx, op: Op) -> Result<Payload, ErrorCode> {
    let mut m = meta(op.clone(), Some(7));
    m.now_ms = 1_700_000_000_000;
    h.validate(c, &op, &m).map_err(|e| e.code())?;
    match block(h.handle(c, &op, &m)).map_err(|e| e.code())? {
        OpOutput::Payload(p) => Ok(p),
        OpOutput::Stream(_) => panic!("stream"),
    }
}

fn un(s: &str) -> UserName {
    UserName::new(s).unwrap()
}

fn gn(s: &str) -> GroupName {
    GroupName::new(s).unwrap()
}

fn argv(spec: &CommandSpec) -> Vec<String> {
    spec.args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
}

#[test]
fn list_flags_without_hashes() {
    let d = root();
    let (c, _, h) = users(d.path(), Rc::new(FakeRunner::new()));
    let Payload::Users(u) = run_op(&h, &c, Op::UsersList).unwrap() else {
        panic!()
    };
    let by = |n: &str| u.users.iter().find(|x| x.name == n).unwrap().clone();
    assert!(by("root").privileged && by("root").system);
    assert!(by("sshd").system && !by("sshd").privileged);
    assert!(by("admin").privileged && !by("admin").locked);
    assert_eq!(by("admin").groups, ["sudo", "admin"]);
    assert!(by("web").locked && !by("web").privileged);
    assert!(by("ci").locked, "expired account");
    assert!(by("toor").privileged);
    assert!(!format!("{u:?}").contains("$6$"));
    assert_eq!(u.groups[0].name, "root");
}

#[test]
fn create_argv_events_and_tiers() {
    let d = root();
    let r = Rc::new(FakeRunner::new());
    r.expect(
        USERADD,
        &[
            "--create-home",
            "--user-group",
            "--shell",
            "/bin/bash",
            "--comment",
            "Deploy bot",
            "--groups",
            "web,sudo",
            "--",
            "deploy",
        ],
        Ok(CommandOutput::ok("")),
    );
    let (c, sink, h) = users(d.path(), r.clone());
    let op = Op::UsersCreate {
        name: un("deploy"),
        groups: vec![gn("web"), gn("sudo")],
        shell: LoginShell::Bash,
        comment: Label::new("Deploy bot").unwrap(),
    };
    assert_eq!(op.tier(), Tier::Elevated, "privileged group");
    run_op(&h, &c, op).unwrap();
    assert_eq!(r.pending(), 0);
    let kinds: Vec<_> = sink
        .take()
        .into_iter()
        .map(|e| match e {
            Event::UserChanged { kind, .. } => kind,
            _ => panic!(),
        })
        .collect();
    assert_eq!(
        kinds,
        [UserChangeKind::UserAdded, UserChangeKind::SudoerAdded]
    );

    let plain = Op::UsersCreate {
        name: un("deploy2"),
        groups: vec![gn("web")],
        shell: LoginShell::Nologin,
        comment: Label::new("").unwrap(),
    };
    assert_eq!(plain.tier(), Tier::Change);

    // Exists already → InvalidArgument; missing group → NotFound.
    let r = Rc::new(FakeRunner::new());
    r.expect(
        USERADD,
        &[
            "--create-home",
            "--user-group",
            "--shell",
            "/usr/sbin/nologin",
            "--comment",
            "",
            "--groups",
            "web",
            "--",
            "deploy2",
        ],
        Ok(CommandOutput::exit(6)),
    );
    let (c, _, h) = users(d.path(), r);
    assert_eq!(run_op(&h, &c, plain), Err(ErrorCode::NotFound));

    for bad in [
        Op::UsersCreate {
            name: un("fleet-x"),
            groups: vec![],
            shell: LoginShell::Sh,
            comment: Label::new("").unwrap(),
        },
        Op::UsersCreate {
            name: un("x"),
            groups: vec![],
            shell: LoginShell::Sh,
            comment: Label::new("a:b").unwrap(),
        },
        Op::GroupsCreate { name: gn("fleet") },
    ] {
        let code = run_op(&h, &c, bad).unwrap_err();
        assert!(matches!(
            code,
            ErrorCode::PolicyDenied | ErrorCode::InvalidArgument
        ));
    }
}

#[test]
fn lock_unlock_argv() {
    let d = root();
    let r = Rc::new(FakeRunner::new());
    r.expect(
        USERMOD,
        &["--lock", "--expiredate", "1", "--", "web"],
        Ok(CommandOutput::ok("")),
    )
    .expect(
        USERMOD,
        &["--unlock", "--expiredate", "", "--", "web"],
        Ok(CommandOutput::ok("")),
    )
    .expect(
        USERMOD,
        &["--expiredate", "", "--", "ci"],
        Ok(CommandOutput::ok("")),
    );
    let (c, sink, h) = users(d.path(), r.clone());
    for (n, locked) in [("web", true), ("web", false)] {
        run_op(
            &h,
            &c,
            Op::UsersLock {
                name: un(n),
                locked,
            },
        )
        .unwrap();
    }
    // `ci` is expired only (no locked hash) and is in sudo but has no
    // roster keys: unlock clears the expiry only.
    run_op(
        &h,
        &c,
        Op::UsersLock {
            name: un("ci"),
            locked: false,
        },
    )
    .unwrap();
    assert_eq!(r.pending(), 0);
    assert_eq!(sink.take().len(), 3);
}

#[test]
fn protected_accounts_refused_before_running() {
    let d = root();
    let r = Rc::new(FakeRunner::new());
    let (c, _, h) = users(d.path(), r.clone());
    for (n, code) in [
        ("root", ErrorCode::PolicyDenied),
        ("toor", ErrorCode::PolicyDenied),
        ("sshd", ErrorCode::PolicyDenied),
        ("admin", ErrorCode::PolicyDenied),
        ("nobody2", ErrorCode::NotFound),
    ] {
        for op in [
            Op::UsersLock {
                name: un(n),
                locked: true,
            },
            Op::UsersDelete {
                name: un(n),
                remove_home: true,
            },
            Op::UsersGroupsSet {
                name: un(n),
                groups: vec![],
            },
        ] {
            let m = meta(op.clone(), Some(1));
            assert_eq!(h.validate(&c, &op, &m).unwrap_err().code(), code, "{n}");
        }
    }
    assert!(r.calls().is_empty());
}

#[test]
fn delete_removes_key_file_and_groups_set() {
    let d = root();
    std::fs::write(
        d.path().join("etc/fleet/authorized_keys/web"),
        "ssh-ed25519 AAAA x\n",
    )
    .unwrap();
    let r = Rc::new(FakeRunner::new());
    r.expect(
        USERDEL,
        &["--remove", "--", "web"],
        Ok(CommandOutput::ok("")),
    )
    .expect(
        USERMOD,
        &["--groups", "", "--", "ci"],
        Ok(CommandOutput::ok("")),
    );
    let (c, sink, h) = users(d.path(), r.clone());
    run_op(
        &h,
        &c,
        Op::UsersDelete {
            name: un("web"),
            remove_home: true,
        },
    )
    .unwrap();
    assert!(!d.path().join("etc/fleet/authorized_keys/web").exists());
    run_op(
        &h,
        &c,
        Op::UsersGroupsSet {
            name: un("ci"),
            groups: vec![],
        },
    )
    .unwrap();
    let ev = sink.take();
    assert!(ev.contains(&Event::UserChanged {
        kind: UserChangeKind::SudoerRemoved,
        name: "ci".into()
    }));
    assert_eq!(argv(&r.calls()[1]), ["--groups", "", "--", "ci"]);
    assert_eq!(
        Op::UsersGroupsSet {
            name: un("ci"),
            groups: vec![gn("docker")]
        }
        .tier(),
        Tier::Elevated
    );
}

// ---- authorized keys ----

fn key(n: u8, comment: &str) -> SshPublicKey {
    let mut blob = Vec::new();
    blob.extend_from_slice(&11u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32u32.to_be_bytes());
    blob.extend_from_slice(&[n; 32]);
    SshPublicKey::new(SshKeyAlgo::Ed25519, blob, comment.into()).unwrap()
}

fn keys_handler() -> (Rc<VecSink>, AuthorizedKeysHandler) {
    let sink = Rc::new(VecSink::default());
    (sink.clone(), AuthorizedKeysHandler { sink })
}

fn set_op(user: &str, keys: Vec<SshPublicKey>) -> Op {
    Op::AuthorizedKeysSet {
        user: un(user),
        keys,
    }
}

fn run_set(
    h: &AuthorizedKeysHandler,
    c: &SysCtx,
    op: Op,
    expected: Option<u64>,
) -> Result<Payload, ErrorCode> {
    let mut m = meta(op.clone(), Some(9));
    m.command.body.expected_version = expected;
    h.validate(c, &op, &m).map_err(|e| e.code())?;
    match block(h.handle(c, &op, &m)).map_err(|e| e.code())? {
        OpOutput::Payload(p) => Ok(p),
        OpOutput::Stream(_) => panic!(),
    }
}

#[test]
fn format_split_merge() {
    let f = format!("x1\n{}x2\n{END}\n{}", roster_block(), roster_block());
    let s = authorized_keys::split(&f).unwrap();
    assert_eq!(s.extra, ["x1", "x2"]);
    assert_eq!(s.roster.len(), 2);
    assert_eq!(
        authorized_keys::merge(&f, "NEW\n").unwrap(),
        "NEW\nx1\nx2\n"
    );
    assert_eq!(
        authorized_keys::split(&format!("{BEGIN}\nk\n")),
        Err(MergeError::Unterminated)
    );
}

#[test]
fn get_and_set_never_touch_roster_section() {
    let d = root();
    let c = ctx(d.path(), Rc::new(FakeRunner::new()));
    let (sink, h) = keys_handler();
    let Payload::AuthorizedKeys(before) =
        run_set(&h, &c, Op::AuthorizedKeysGet { user: un("admin") }, None).unwrap()
    else {
        panic!()
    };
    assert_eq!(before.extra, ["ssh-ed25519 AAAAold other"]);
    assert_eq!(before.roster_section.len(), 1);
    assert_eq!(
        before.roster_section[0].device_id,
        Some(DEV.parse().unwrap())
    );

    // Stale version → conflict, file untouched.
    let path = d.path().join("etc/fleet/authorized_keys/admin");
    let orig = std::fs::read_to_string(&path).unwrap();
    let op = set_op("admin", vec![key(1, "ci"), key(2, "")]);
    assert_eq!(
        run_set(&h, &c, op.clone(), Some(before.version ^ 1)),
        Err(ErrorCode::VersionConflict {
            current: before.version
        })
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), orig);

    let Payload::ChangePending { change: p, .. } =
        run_set(&h, &c, op, Some(before.version)).unwrap()
    else {
        panic!()
    };
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        text.starts_with(&roster_block()),
        "roster block byte-identical"
    );
    assert_eq!(text.matches(BEGIN).count(), 1);
    assert!(!text.contains("AAAAold"));
    assert!(text.ends_with(&format!(
        "{}\n{}\n",
        key(1, "ci").to_line(),
        key(2, "").to_line()
    )));
    let after = authorized_keys::get(&c, "admin").unwrap();
    assert_eq!(p.new_version, Some(after.version));
    assert_eq!(after.roster_section, before.roster_section);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert!(matches!(
        sink.take()[..],
        [Event::AuthorizedKeysChanged { .. }]
    ));
}

#[test]
fn set_refusals() {
    let d = root();
    let c = ctx(d.path(), Rc::new(FakeRunner::new()));
    let (_, h) = keys_handler();
    // Duplicate key, unknown user.
    assert_eq!(
        run_set(&h, &c, set_op("web", vec![key(1, "a"), key(1, "b")]), None),
        Err(ErrorCode::InvalidArgument)
    );
    assert_eq!(
        run_set(&h, &c, set_op("ghost", vec![]), None),
        Err(ErrorCode::NotFound)
    );
    // Unterminated roster block: refused, file kept.
    let p = d.path().join("etc/fleet/authorized_keys/web");
    std::fs::write(&p, format!("{BEGIN}\nk\n")).unwrap();
    assert_eq!(
        run_set(&h, &c, set_op("web", vec![key(3, "")]), None),
        Err(ErrorCode::Internal)
    );
    assert_eq!(
        std::fs::read_to_string(&p).unwrap(),
        format!("{BEGIN}\nk\n")
    );
    // Symlinked key file: refused, target untouched.
    std::fs::remove_file(&p).unwrap();
    let target = d.path().join("shadow-copy");
    std::fs::write(&target, "secret").unwrap();
    std::os::unix::fs::symlink(&target, &p).unwrap();
    assert_eq!(
        run_set(&h, &c, set_op("web", vec![key(3, "")]), None),
        Err(ErrorCode::PolicyDenied)
    );
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "secret");
    // Symlinked directory.
    let d2 = root();
    let c2 = ctx(d2.path(), Rc::new(FakeRunner::new()));
    std::fs::remove_dir_all(d2.path().join("etc/fleet/authorized_keys")).unwrap();
    std::os::unix::fs::symlink(
        d2.path().join("etc"),
        d2.path().join("etc/fleet/authorized_keys"),
    )
    .unwrap();
    assert_eq!(
        run_set(&h, &c2, set_op("web", vec![]), None),
        Err(ErrorCode::PolicyDenied)
    );
}

#[test]
fn set_target_account_and_version_required() {
    let d = root();
    let p = d.path();
    let mut pw = std::fs::read_to_string(p.join("etc/passwd")).unwrap();
    pw.push_str(
        "fleet-gate:x:1100:1100::/:/bin/sh\nsvc:x:1003:1003::/:/usr/sbin/nologin\n\
         f:x:1004:1004::/:/usr/bin/false\n",
    );
    std::fs::write(p.join("etc/passwd"), pw).unwrap();
    let c = ctx(p, Rc::new(FakeRunner::new()));
    let (_, h) = keys_handler();
    for (u, want) in [
        ("fleet-gate", ErrorCode::PolicyDenied),
        ("sshd", ErrorCode::PolicyDenied), // system uid, nologin
        ("toor", ErrorCode::PolicyDenied), // uid 0, not root
        ("svc", ErrorCode::PolicyDenied),  // nologin
        ("f", ErrorCode::PolicyDenied),    // false
    ] {
        assert_eq!(
            run_set(&h, &c, set_op(u, vec![]), Some(0)),
            Err(want),
            "{u}"
        );
    }
    // root is a valid target (Elevated by the catalog).
    let v = authorized_keys::get(&c, "root").unwrap().version;
    run_set(&h, &c, set_op("root", vec![key(4, "")]), Some(v)).unwrap();
    // No expected_version → conflict, file untouched.
    let v = authorized_keys::get(&c, "web").unwrap().version;
    assert_eq!(
        run_set(&h, &c, set_op("web", vec![key(4, "")]), None),
        Err(ErrorCode::VersionConflict { current: v })
    );
    assert!(!p.join("etc/fleet/authorized_keys/web").exists());
}

#[test]
fn sudoers_privilege_in_list_and_escalation() {
    let d = root();
    std::fs::write(
        d.path().join("etc/sudoers"),
        "web ALL=(ALL) ALL\n%ci ALL=ALL\n",
    )
    .unwrap();
    let (c, _, h) = users(d.path(), Rc::new(FakeRunner::new()));
    let Payload::Users(u) = run_op(&h, &c, Op::UsersList).unwrap() else {
        panic!()
    };
    assert!(u.users.iter().find(|x| x.name == "web").unwrap().privileged);
    let m = meta(Op::UsersList, None);
    for (op, want) in [
        (
            Op::UsersGroupsSet {
                name: un("web"),
                groups: vec![],
            },
            true,
        ),
        (
            Op::UsersCreate {
                name: un("x"),
                groups: vec![gn("ci")],
                shell: LoginShell::Bash,
                comment: Label::new("").unwrap(),
            },
            true,
        ),
        (
            Op::UsersCreate {
                name: un("x"),
                groups: vec![gn("web")],
                shell: LoginShell::Bash,
                comment: Label::new("").unwrap(),
            },
            false,
        ),
        (Op::UsersList, false),
    ] {
        assert_eq!(h.requires_elevated(&c, &op, &m).unwrap(), want, "{op:?}");
    }
}

#[test]
fn reverter_restores_extra_under_current_roster() {
    let d = root();
    let c = ctx(d.path(), Rc::new(FakeRunner::new()));
    let (_, h) = keys_handler();
    let op = set_op("admin", vec![key(5, "new")]);
    let snap = AuthorizedKeysReverter.snapshot(&c, &op).unwrap();
    let v = authorized_keys::get(&c, "admin").unwrap().version;
    run_set(&h, &c, op, Some(v)).unwrap();
    // A roster rewrite inside the confirm window.
    let path = d.path().join("etc/fleet/authorized_keys/admin");
    let cur = std::fs::read_to_string(&path).unwrap();
    let new_block = format!("{BEGIN}\necdsa-sha2-nistp256 BBBB fleet-device-{DEV}\n{END}\n");
    std::fs::write(&path, authorized_keys::merge(&cur, &new_block).unwrap()).unwrap();
    AuthorizedKeysReverter.restore(&c, &snap).unwrap();
    AuthorizedKeysReverter.restore(&c, &snap).unwrap();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        format!("{new_block}ssh-ed25519 AAAAold other\n")
    );
    assert!(AuthorizedKeysReverter.restore(&c, &[200, b'a']).is_err());
}
