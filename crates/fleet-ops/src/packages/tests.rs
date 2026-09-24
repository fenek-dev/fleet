use super::*;
use crate::FakeRunner;
use crate::handler::OpOutput;
use crate::runner::{CommandOutput, RunError};
use crate::testutil::{block, ctx, meta};
use fleet_proto::Event;
use fleet_proto::args::{DebVersion, SearchTerm, TimeRange};
use fleet_proto::payload::{PackageChange, PkgAction};
use proptest::prelude::*;
use std::cmp::Ordering;
use std::path::Path;

const SIM_DEBIAN: &str = include_str!("fixtures/apt-sim-debian.txt");
const SIM_UBUNTU_HELD: &str = include_str!("fixtures/apt-sim-ubuntu-held.txt");
const HISTORY_LOG: &str = include_str!("fixtures/history.log");
const DPKG_LOG_FIX: &str = include_str!("fixtures/dpkg.log");

const DPKG_QUERY_OUT: &str = "\
nginx\tamd64\t1.22.1-9\tinstall\tinstalled
nginx-common\tall\t1.22.1-9\tinstall\tinstalled
libssl3\tamd64\t3.0.11-1~deb12u2\tinstall\tinstalled
openssl\tamd64\t3.0.11-1~deb12u2\thold\tinstalled
telnet\tamd64\t0.17+2.4-2\tdeinstall\tconfig-files
libc6\ti386\t2.36-9\tinstall\tinstalled
broken line without tabs
a\tb\tc\td\tinstalled\textra
";

const EXTENDED: &str = "\
Package: nginx-common
Architecture: all
Auto-Installed: 1

Package: libssl3
Architecture: amd64
Auto-Installed: 1

Package: nginx
Architecture: amd64
Auto-Installed: 0
";

// ---- exact argv, spelled out ----

const SCOPE: [&str; 6] = [
    "--scope",
    "--quiet",
    "--collect",
    "--unit",
    "fleet-op-7",
    "--",
];
const APT: [&str; 9] = [
    "/usr/bin/apt-get",
    "-q",
    "-y",
    "-o",
    "Dpkg::Options::=--force-confdef",
    "-o",
    "Dpkg::Options::=--force-confold",
    "-o",
    "DPkg::Lock::Timeout=60",
];
const SIM: [&str; 4] = ["-s", "-q", "-o", "Debug::NoLocking=1"];
const QUERY: [&str; 2] = [
    "-W",
    "-f=${Package}\\t${Architecture}\\t${Version}\\t${db:Status-Want}\\t${db:Status-Status}\\n",
];
const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";

fn scoped_apt(verb: &[&str]) -> Vec<&'static str> {
    let mut v: Vec<&str> = SCOPE.to_vec();
    v.extend(APT);
    v.extend(verb.iter().map(|s| &*s.to_string().leak()));
    v
}

fn sim(verb: &[&str]) -> Vec<&'static str> {
    let mut v: Vec<&str> = SIM.to_vec();
    v.extend(verb.iter().map(|s| &*s.to_string().leak()));
    v
}

fn scoped_mark(verb: &[&str]) -> Vec<&'static str> {
    let mut v: Vec<&str> = SCOPE.to_vec();
    v.extend(["/usr/bin/apt-mark", "-o", "DPkg::Lock::Timeout=60"]);
    v.extend(verb.iter().map(|s| &*s.to_string().leak()));
    v
}

fn root_with(files: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (abs, text) in files {
        let p = dir.path().join(abs.trim_start_matches('/'));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }
    dir
}

fn run_op(
    root: &Path,
    runner: Rc<FakeRunner>,
    op: Op,
    seq: Option<u64>,
) -> Result<Payload, OpError> {
    let c = ctx(root, runner);
    let m = meta(op.clone(), seq);
    PackagesHandler.validate(&c, &op, &m)?;
    match block(PackagesHandler.handle(&c, &op, &m))? {
        OpOutput::Payload(p) => Ok(p),
        OpOutput::Stream(_) => panic!("stream"),
    }
}

fn ok(s: &str) -> Result<CommandOutput, RunError> {
    Ok(CommandOutput::ok(s.as_bytes().to_vec()))
}

fn pkg(s: &str) -> DebPackageName {
    DebPackageName::new(s).unwrap()
}

fn changes(p: Payload) -> PackageChanges {
    match p {
        Payload::PackageChanges(c) => c,
        other => panic!("{other:?}"),
    }
}

fn ch(name: &str, action: PkgAction, from: Option<&str>, to: Option<&str>) -> PackageChange {
    PackageChange {
        name: name.into(),
        action,
        from: from.map(Into::into),
        to: to.map(Into::into),
    }
}

// ---- reads ----

#[test]
fn list_filters_and_marks_auto() {
    let dir = root_with(&[(EXTENDED_STATES, EXTENDED)]);
    let r = Rc::new(FakeRunner::new());
    r.expect(DPKG_QUERY, &QUERY, ok(DPKG_QUERY_OUT));
    let op = Op::PkgList {
        filter: Some(SearchTerm::new("NGINX").unwrap()),
    };
    let Payload::Packages(p) = run_op(dir.path(), r.clone(), op, None).unwrap() else {
        panic!()
    };
    let got: Vec<(&str, bool, bool)> = p
        .packages
        .iter()
        .map(|p| (p.name.as_str(), p.auto_installed, p.held))
        .collect();
    assert_eq!(
        got,
        [("nginx", false, false), ("nginx-common", true, false)]
    );
    assert_eq!(r.pending(), 0);
}

#[test]
fn upgradable_from_simulation() {
    let dir = root_with(&[
        (REBOOT_REQUIRED, ""),
        ("/var/lib/apt/periodic/update-success-stamp", ""),
    ]);
    let r = Rc::new(FakeRunner::new());
    r.expect(APT_GET, &sim(&["dist-upgrade"]), ok(SIM_DEBIAN));
    let Payload::Upgradable(u) = run_op(dir.path(), r.clone(), Op::PkgUpgradable, None).unwrap()
    else {
        panic!()
    };
    let got: Vec<(&str, &str, &str, bool)> = u
        .packages
        .iter()
        .map(|p| {
            (
                p.name.as_str(),
                p.current.as_str(),
                p.candidate.as_str(),
                p.security,
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            ("libssl3", "3.0.11-1~deb12u2", "3.0.13-1~deb12u1", true),
            ("openssl", "3.0.11-1~deb12u2", "3.0.13-1~deb12u1", true),
            ("tzdata", "2024a-0+deb12u1", "2025b-0+deb12u1", false),
            ("curl", "7.88.1-10+deb12u5", "7.88.1-10+deb12u12", true),
            ("libcurl4", "7.88.1-10+deb12u5", "7.88.1-10+deb12u12", false),
        ]
    );
    assert_eq!(
        u.packages[3].origin,
        "Debian:12.11/stable, Debian-Security:12/stable-security"
    );
    assert!(u.reboot_required);
    assert!(u.lists_updated_ms.is_some());
    // Simulation runs with a cleared env plus noninteractive, no scope.
    let call = &r.calls()[0];
    assert!(
        call.env
            .contains(&("DEBIAN_FRONTEND", "noninteractive".into()))
    );
}

#[test]
fn history_merges_apt_and_dpkg_logs() {
    let dir = root_with(&[
        ("/var/log/apt/history.log", HISTORY_LOG),
        ("/var/log/dpkg.log", DPKG_LOG_FIX),
    ]);
    let r = Rc::new(FakeRunner::new());
    let op = Op::PkgHistory {
        range: TimeRange::default(),
        limit: 100,
    };
    let Payload::PackageHistory(h) = run_op(dir.path(), r.clone(), op, None).unwrap() else {
        panic!()
    };
    let got: Vec<(&str, PkgAction)> = h
        .entries
        .iter()
        .map(|e| (e.change.name.as_str(), e.change.action))
        .collect();
    use PkgAction::*;
    assert_eq!(
        got,
        [
            ("nginx-common", Install),
            ("nginx", Install),
            ("libssl3", Upgrade),
            ("openssl", Upgrade),
            ("telnet", Purge),
            ("inetutils-telnet", Remove),
            ("tzdata", Downgrade),
            ("htop", Install), // only in dpkg.log (plain dpkg -i)
        ]
    );
    // 2025-03-01 10:00:01 UTC
    assert_eq!(h.entries[0].time_ms, 1_740_823_201_000);
    assert!(r.calls().is_empty());

    // Range and limit keep the newest.
    let op = Op::PkgHistory {
        range: TimeRange {
            since_ms: Some(1_740_823_201_000),
            until_ms: Some(1_741_132_800_000), // 2025-03-05 00:00
        },
        limit: 2,
    };
    let Payload::PackageHistory(h) = run_op(dir.path(), r, op, None).unwrap() else {
        panic!()
    };
    let got: Vec<&str> = h.entries.iter().map(|e| e.change.name.as_str()).collect();
    assert_eq!(got, ["inetutils-telnet", "tzdata"]);
}

// ---- mutations: exact argv ----

#[test]
fn install_argv_and_changes() {
    let dir = root_with(&[]);
    let r = Rc::new(FakeRunner::new());
    let before = "nginx\tamd64\t1.22.1-9\tinstall\tinstalled\n";
    let after = "nginx\tamd64\t1.22.1-9\tinstall\tinstalled\n\
                 htop\tamd64\t3.2.2-2\tinstall\tinstalled\n";
    r.expect(DPKG_QUERY, &QUERY, ok(before))
        .expect(
            APT_GET,
            &sim(&["install", "htop=3.2.2-2", "curl"]),
            ok("Inst htop (3.2.2-2 Debian:12/stable [amd64])\n"),
        )
        .expect(
            SYSTEMD_RUN,
            &[
                "--scope",
                "--quiet",
                "--collect",
                "--unit",
                "fleet-op-7",
                "--",
                "/usr/bin/apt-get",
                "-q",
                "-y",
                "-o",
                "Dpkg::Options::=--force-confdef",
                "-o",
                "Dpkg::Options::=--force-confold",
                "-o",
                "DPkg::Lock::Timeout=60",
                "install",
                "htop=3.2.2-2",
                "curl",
            ],
            ok(""),
        )
        .expect(DPKG_QUERY, &QUERY, ok(after));
    let op = Op::PkgInstall {
        packages: vec![
            PkgSpec {
                name: pkg("htop"),
                version: Some(DebVersion::new("3.2.2-2").unwrap()),
            },
            PkgSpec {
                name: pkg("curl"),
                version: None,
            },
        ],
    };
    let c = changes(run_op(dir.path(), r.clone(), op, Some(7)).unwrap());
    assert_eq!(
        c.changes,
        [ch("htop", PkgAction::Install, None, Some("3.2.2-2"))]
    );
    assert!(!c.reboot_required);
    assert_eq!(r.pending(), 0);
    // The real run: noninteractive env, long timeout.
    let apt = &r.calls()[2];
    for (k, v) in [
        ("DEBIAN_FRONTEND", "noninteractive"),
        ("APT_LISTCHANGES_FRONTEND", "none"),
        ("UCF_FORCE_CONFFOLD", "1"),
    ] {
        assert!(apt.env.contains(&(k, v.into())), "{k}");
    }
    assert_eq!(apt.timeout, Duration::from_secs(1800));
}

#[test]
fn remove_and_purge_argv() {
    for (purge, verb, action) in [
        (false, "remove", PkgAction::Remove),
        (true, "purge", PkgAction::Purge),
    ] {
        let dir = root_with(&[]);
        let r = Rc::new(FakeRunner::new());
        let before = "nginx\tamd64\t1.22.1-9\tinstall\tinstalled\n";
        r.expect(DPKG_QUERY, &QUERY, ok(before))
            .expect(
                APT_GET,
                &sim(&[verb, "nginx"]),
                ok("Remv nginx [1.22.1-9]\n"),
            )
            .expect(SYSTEMD_RUN, &scoped_apt(&[verb, "nginx"]), ok(""))
            .expect(DPKG_QUERY, &QUERY, ok(""));
        let op = Op::PkgRemove {
            packages: vec![pkg("nginx")],
            purge,
        };
        let c = changes(run_op(dir.path(), r.clone(), op, Some(7)).unwrap());
        assert_eq!(c.changes, [ch("nginx", action, Some("1.22.1-9"), None)]);
        assert_eq!(r.pending(), 0);
    }
}

#[test]
fn protected_removal_refused_before_running() {
    // By name: refused in validate, nothing runs.
    for name in ["openssh-server", "sudo", "fleet-agent", "systemd"] {
        let dir = root_with(&[]);
        let r = Rc::new(FakeRunner::new());
        let op = Op::PkgRemove {
            packages: vec![pkg(name)],
            purge: false,
        };
        let e = run_op(dir.path(), r.clone(), op, Some(7)).unwrap_err();
        assert_eq!(e.code(), ErrorCode::PolicyDenied, "{name}");
        assert!(r.calls().is_empty());
    }
    // By consequence: the simulation would remove sshd.
    let dir = root_with(&[]);
    let r = Rc::new(FakeRunner::new());
    r.expect(DPKG_QUERY, &QUERY, ok("")).expect(
        APT_GET,
        &sim(&["remove", "openssh-client"]),
        ok("Remv openssh-server [1:9.2p1-2+deb12u2]\nRemv openssh-client [1:9.2p1-2+deb12u2]\n"),
    );
    let op = Op::PkgRemove {
        packages: vec![pkg("openssh-client")],
        purge: false,
    };
    let e = run_op(dir.path(), r.clone(), op, Some(7)).unwrap_err();
    assert_eq!(e.code(), ErrorCode::PolicyDenied);
    assert_eq!(r.calls().len(), 2, "apt never ran");
    // An install that conflicts with sshd is refused the same way.
    let r = Rc::new(FakeRunner::new());
    r.expect(DPKG_QUERY, &QUERY, ok("")).expect(
        APT_GET,
        &sim(&["install", "dropbear"]),
        ok("Remv openssh-server:amd64 [1:9.2p1]\nInst dropbear (1 x [amd64])\n"),
    );
    let op = Op::PkgInstall {
        packages: vec![PkgSpec {
            name: pkg("dropbear"),
            version: None,
        }],
    };
    let e = run_op(dir.path(), r.clone(), op, Some(7)).unwrap_err();
    assert_eq!(e.code(), ErrorCode::PolicyDenied);
    assert_eq!(r.calls().len(), 2);
}

#[test]
fn upgrade_all_argv() {
    let dir = root_with(&[(REBOOT_REQUIRED, "")]);
    let r = Rc::new(FakeRunner::new());
    let before = "libssl3\tamd64\t3.0.11-1~deb12u2\tinstall\tinstalled\n";
    let after = "libssl3\tamd64\t3.0.13-1~deb12u1\tinstall\tinstalled\n";
    r.expect(DPKG_QUERY, &QUERY, ok(before))
        .expect(
            APT_GET,
            &sim(&["upgrade", "--with-new-pkgs"]),
            ok(SIM_DEBIAN),
        )
        .expect(
            SYSTEMD_RUN,
            &scoped_apt(&["upgrade", "--with-new-pkgs"]),
            ok(""),
        )
        .expect(DPKG_QUERY, &QUERY, ok(after));
    let op = Op::PkgUpgrade {
        scope: UpgradeScope::All,
    };
    let c = changes(run_op(dir.path(), r.clone(), op, Some(7)).unwrap());
    assert_eq!(
        c.changes,
        [ch(
            "libssl3",
            PkgAction::Upgrade,
            Some("3.0.11-1~deb12u2"),
            Some("3.0.13-1~deb12u1")
        )]
    );
    assert!(c.reboot_required);
    assert_eq!(r.calls()[2].timeout, Duration::from_secs(3600));
    assert_eq!(r.pending(), 0);
}

#[test]
fn upgrade_security_pins_candidates_and_restores_auto() {
    let dir = root_with(&[(EXTENDED_STATES, EXTENDED)]);
    let r = Rc::new(FakeRunner::new());
    let set = [
        "install",
        "--only-upgrade",
        "curl=7.88.1-10+deb12u12",
        "libssl3=3.0.13-1~deb12u1",
        "openssl=3.0.13-1~deb12u1",
    ];
    r.expect(APT_GET, &sim(&["dist-upgrade"]), ok(SIM_DEBIAN))
        .expect(DPKG_QUERY, &QUERY, ok(DPKG_QUERY_OUT))
        .expect(APT_GET, &sim(&set), ok(SIM_DEBIAN))
        .expect(SYSTEMD_RUN, &scoped_apt(&set), ok(""))
        .expect(SYSTEMD_RUN, &scoped_mark(&["auto", "libssl3"]), ok(""))
        .expect(DPKG_QUERY, &QUERY, ok(DPKG_QUERY_OUT));
    let op = Op::PkgUpgrade {
        scope: UpgradeScope::SecurityOnly,
    };
    let c = changes(run_op(dir.path(), r.clone(), op, Some(7)).unwrap());
    assert!(c.changes.is_empty());
    assert_eq!(r.pending(), 0, "{:#?}", r.calls().last());

    // Nothing from a security origin: only the listing runs.
    let r = Rc::new(FakeRunner::new());
    r.expect(
        APT_GET,
        &sim(&["dist-upgrade"]),
        ok("Inst tzdata [1] (2 Debian:12/stable-updates [all])\n"),
    );
    let op = Op::PkgUpgrade {
        scope: UpgradeScope::SecurityOnly,
    };
    assert!(
        changes(run_op(dir.path(), r.clone(), op, Some(7)).unwrap())
            .changes
            .is_empty()
    );
    assert_eq!(r.calls().len(), 1);
}

#[test]
fn upgrade_named_packages_argv() {
    let dir = root_with(&[]);
    let r = Rc::new(FakeRunner::new());
    let verb = ["install", "--only-upgrade", "nginx", "curl"];
    r.expect(DPKG_QUERY, &QUERY, ok(""))
        .expect(APT_GET, &sim(&verb), ok(""))
        .expect(SYSTEMD_RUN, &scoped_apt(&verb), ok(""))
        .expect(DPKG_QUERY, &QUERY, ok(""));
    let op = Op::PkgUpgrade {
        scope: UpgradeScope::Packages(vec![pkg("nginx"), pkg("curl")]),
    };
    run_op(dir.path(), r.clone(), op, Some(7)).unwrap();
    assert_eq!(r.pending(), 0);
}

#[test]
fn hold_and_unhold_argv() {
    for (on, verb, action) in [
        (true, "hold", PkgAction::Hold),
        (false, "unhold", PkgAction::Unhold),
    ] {
        let dir = root_with(&[]);
        let r = Rc::new(FakeRunner::new());
        let (b, a) = if on {
            ("install", "hold")
        } else {
            ("hold", "install")
        };
        r.expect(
            DPKG_QUERY,
            &QUERY,
            ok(&format!("nginx\tamd64\t1\t{b}\tinstalled\n")),
        )
        .expect(SYSTEMD_RUN, &scoped_mark(&[verb, "nginx", "curl"]), ok(""))
        .expect(
            DPKG_QUERY,
            &QUERY,
            ok(&format!("nginx\tamd64\t1\t{a}\tinstalled\n")),
        );
        let op = Op::PkgHold {
            packages: vec![pkg("nginx"), pkg("curl")],
            hold: on,
        };
        let c = changes(run_op(dir.path(), r.clone(), op, Some(7)).unwrap());
        assert_eq!(c.changes, [ch("nginx", action, None, None)]);
        assert_eq!(r.pending(), 0);
    }
}

#[test]
fn refresh_argv_then_lists() {
    let dir = root_with(&[]);
    let r = Rc::new(FakeRunner::new());
    r.expect(SYSTEMD_RUN, &scoped_apt(&["update"]), ok(""))
        .expect(APT_GET, &sim(&["dist-upgrade"]), ok(SIM_UBUNTU_HELD));
    let Payload::Upgradable(u) = run_op(dir.path(), r.clone(), Op::PkgRefresh, Some(7)).unwrap()
    else {
        panic!()
    };
    assert_eq!(u.packages.len(), 3);
    assert_eq!(r.calls()[0].timeout, Duration::from_secs(600));
}

#[test]
fn lock_contention_is_busy() {
    let dir = root_with(&[]);
    let r = Rc::new(FakeRunner::new());
    let locked = CommandOutput {
        code: Some(100),
        stderr: b"E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 4242 (apt-get)\n\
                  E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), is another process using it?\n"
            .to_vec(),
        ..CommandOutput::default()
    };
    r.expect(SYSTEMD_RUN, &scoped_apt(&["update"]), Ok(locked));
    let e = run_op(dir.path(), r, Op::PkgRefresh, Some(7)).unwrap_err();
    assert_eq!(e.code(), ErrorCode::Busy);

    let r = Rc::new(FakeRunner::new());
    let missing = CommandOutput {
        code: Some(100),
        stderr: b"E: Unable to locate package nope\n".to_vec(),
        ..CommandOutput::default()
    };
    r.expect(DPKG_QUERY, &QUERY, ok(""))
        .expect(APT_GET, &sim(&["install", "nope"]), Ok(missing));
    let op = Op::PkgInstall {
        packages: vec![PkgSpec {
            name: pkg("nope"),
            version: None,
        }],
    };
    assert_eq!(
        run_op(dir.path(), r, op, Some(7)).unwrap_err().code(),
        ErrorCode::NotFound
    );

    let r = Rc::new(FakeRunner::new());
    r.expect(
        SYSTEMD_RUN,
        &scoped_apt(&["update"]),
        Err(RunError::Timeout),
    );
    assert_eq!(
        run_op(dir.path(), r, Op::PkgRefresh, Some(7))
            .unwrap_err()
            .code(),
        ErrorCode::Timeout
    );
}

#[test]
fn mutation_without_audit_seq_is_internal() {
    let dir = root_with(&[]);
    let r = Rc::new(FakeRunner::new());
    let e = run_op(dir.path(), r.clone(), Op::PkgRefresh, None).unwrap_err();
    assert_eq!(e.code(), ErrorCode::Internal);
    assert!(r.calls().is_empty());
}

#[test]
fn registry_routes_package_tags() {
    let r = Registry::with_generic();
    for op in [
        Op::PkgList { filter: None },
        Op::PkgUpgradable,
        Op::PkgHistory {
            range: TimeRange::default(),
            limit: 1,
        },
        Op::PkgRefresh,
        Op::PkgUpgrade {
            scope: UpgradeScope::All,
        },
        Op::PkgInstall { packages: vec![] },
        Op::PkgRemove {
            packages: vec![],
            purge: false,
        },
        Op::PkgHold {
            packages: vec![],
            hold: true,
        },
    ] {
        assert!(r.get(&op).is_some(), "{}", op.name());
    }
}

// ---- parsers ----

#[test]
fn dpkg_query_parse() {
    let p = parse_dpkg_query(DPKG_QUERY_OUT);
    let names: Vec<&str> = p.iter().map(|p| p.name.as_str()).collect();
    // config-files and malformed rows skipped.
    assert_eq!(
        names,
        ["nginx", "nginx-common", "libssl3", "openssl", "libc6"]
    );
    assert!(p[3].held);
    assert_eq!(p[4].arch, "i386");
}

#[test]
fn extended_states_parse() {
    let s = parse_extended_states(EXTENDED);
    assert!(s.contains(&("nginx-common".into(), "all".into())));
    assert!(s.contains(&("libssl3".into(), "amd64".into())));
    assert_eq!(s.len(), 2);
}

#[test]
fn apt_sim_ubuntu_and_held() {
    let s = parse_apt_sim(SIM_UBUNTU_HELD);
    let got: Vec<(&str, bool, &str)> = s
        .inst
        .iter()
        .map(|i| (i.name.as_str(), i.security, i.origins.as_str()))
        .collect();
    assert_eq!(
        got,
        [
            (
                "libc6",
                true,
                "Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security"
            ),
            (
                "libc6:i386",
                true,
                "Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security"
            ),
            ("libc-bin", false, "Ubuntu:22.04/jammy-updates"),
        ]
    );
    // Held/kept-back packages never appear as Inst lines.
    assert!(
        !s.inst
            .iter()
            .any(|i| i.name == "nginx" || i.name == "docker-ce")
    );
    assert_eq!(
        pinned_arg("libc6:i386", "2.35-0ubuntu3.7").as_deref(),
        Some("libc6:i386=2.35-0ubuntu3.7")
    );
    assert_eq!(pinned_arg("-x", "1"), None);
    assert_eq!(pinned_arg("a:B", "1"), None);

    let d = parse_apt_sim(SIM_DEBIAN);
    assert_eq!(d.inst.len(), 6);
    assert_eq!(d.inst[5].current, None);
    assert!(d.remove.is_empty());
    let r = parse_apt_sim("Remv openssh-server:amd64 [1]\nPurg sudo [1]\nRemv \n");
    assert_eq!(r.remove, ["openssh-server", "sudo"]);
}

#[test]
fn version_order() {
    use Ordering::*;
    for (a, b, o) in [
        ("1.0", "1.0", Equal),
        ("1.0", "1.1", Less),
        ("1.10", "1.9", Greater),
        ("1.0~rc1", "1.0", Less),
        ("1.0", "1.0+b1", Less),
        ("1:0.9", "2.0", Greater),
        ("1.0-1", "1.0-2", Less),
        ("3.0.11-1~deb12u2", "3.0.13-1~deb12u1", Less),
        ("7.88.1-10+deb12u5", "7.88.1-10+deb12u12", Less),
        ("2025b-0+deb12u1", "2024a-0+deb12u1", Greater),
        ("1.0a", "1.0.", Less),
        ("001", "1", Equal),
        ("1.0~~", "1.0~", Less),
    ] {
        assert_eq!(compare_versions(a, b), o, "{a} vs {b}");
        assert_eq!(compare_versions(b, a), o.reverse(), "{b} vs {a}");
    }
}

#[test]
fn datetime_parse() {
    assert_eq!(parse_datetime("1970-01-01", "00:00:00"), Some(0));
    assert_eq!(
        parse_datetime("2025-03-01", "10:00:01"),
        Some(1_740_823_201_000)
    );
    assert_eq!(
        parse_datetime("2024-02-29", "23:59:59"),
        Some(1_709_251_199_000)
    );
    assert_eq!(parse_datetime("2025-13-01", "00:00:00"), None);
    assert_eq!(parse_datetime("1969-12-31", "00:00:00"), None);
    assert_eq!(parse_datetime("2025-01-01", "24:00:00"), None);
}

#[test]
fn diff_detects_every_kind() {
    let i = |n: &str, v: &str, held: bool| Installed {
        name: n.into(),
        arch: "amd64".into(),
        version: v.into(),
        held,
    };
    let before = [
        i("a", "1", false),
        i("b", "2", false),
        i("c", "1", false),
        i("d", "1", false),
    ];
    let after = [
        i("a", "2", false),
        i("b", "1", false),
        i("d", "1", true),
        i("e", "1", false),
    ];
    use PkgAction::*;
    assert_eq!(
        diff_installed(&before, &after, false),
        [
            ch("a", Upgrade, Some("1"), Some("2")),
            ch("b", Downgrade, Some("2"), Some("1")),
            ch("c", Remove, Some("1"), None),
            ch("d", Hold, None, None),
            ch("e", Install, None, Some("1")),
        ]
    );
    assert_eq!(
        diff_installed(&before[2..3], &[], true),
        [ch("c", Purge, Some("1"), None)]
    );
}

// ---- dpkg.log watcher ----

#[test]
fn watcher_tails_and_follows_rotation() {
    let dir = root_with(&[(DPKG_LOG, "2025-03-01 10:00:04 install old:amd64 <none> 1\n")]);
    let c = ctx(dir.path(), Rc::new(FakeRunner::new()));
    let mut w = DpkgLogWatcher::new(&c);
    assert!(w.poll().is_empty(), "starts at the end");
    let log = dir.path().join("var/log/dpkg.log");
    let append = |s: &str| {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        f.write_all(s.as_bytes()).unwrap();
    };
    append(
        "2025-03-05 08:00:00 install htop:amd64 <none> 3.2.2-2\n2025-03-05 08:00:01 status installed htop:amd64 3.2.2-2\n2025-03-05 08:00:02 upgrade cu",
    );
    let ev = w.poll();
    assert_eq!(
        ev,
        [Event::PackagesChanged {
            changes: vec![ch("htop", PkgAction::Install, None, Some("3.2.2-2"))]
        }]
    );
    // The partial line completes on the next poll.
    append("rl:amd64 1 2\n");
    let Event::PackagesChanged { changes } = &w.poll()[0] else {
        panic!()
    };
    assert_eq!(
        changes[0],
        ch("curl", PkgAction::Upgrade, Some("1"), Some("2"))
    );
    // Rotation: new file (new inode), read from its start.
    std::fs::rename(&log, dir.path().join("var/log/dpkg.log.1")).unwrap();
    std::fs::write(
        &log,
        "2025-03-06 01:00:00 remove htop:amd64 3.2.2-2 <none>\n",
    )
    .unwrap();
    let Event::PackagesChanged { changes } = &w.poll()[0] else {
        panic!()
    };
    assert_eq!(changes[0].action, PkgAction::Remove);
    assert!(w.poll().is_empty());
}

// ---- no panics on any input ----

proptest! {
    #[test]
    fn parsers_never_panic(s in "(?s).{0,400}") {
        let _ = parse_dpkg_query(&s);
        let _ = parse_extended_states(&s);
        let _ = parse_apt_sim(&s);
        let _ = parse_dpkg_log(&s);
        let _ = parse_history_log(&s);
        let _ = is_lock_error(&s);
    }

    #[test]
    fn line_shaped_inputs_never_panic(
        a in "[A-Za-z0-9:~.+\\-\\[\\]() ,/]{0,80}",
        b in "[A-Za-z0-9:~.+\\-\\[\\]() ,/]{0,80}",
    ) {
        let _ = parse_apt_sim(&format!("Inst {a}\nRemv {b}\n"));
        let _ = parse_dpkg_log(&format!("2025-01-01 00:00:00 upgrade {a} {b}\n"));
        let _ = parse_history_log(&format!("Start-Date: 2025-01-01  00:00:00\nUpgrade: {a} ({b})\n"));
        let _ = parse_datetime(&a, &b);
        let _ = pinned_arg(&a, &b);
    }

    #[test]
    fn version_order_is_consistent(a in "[0-9a-z:~.+\\-]{0,24}", b in "[0-9a-z:~.+\\-]{0,24}") {
        prop_assert_eq!(compare_versions(&a, &a), Ordering::Equal);
        prop_assert_eq!(compare_versions(&a, &b), compare_versions(&b, &a).reverse());
    }
}
