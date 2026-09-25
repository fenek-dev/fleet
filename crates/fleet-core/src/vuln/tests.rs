use super::db::{FeedMeta, VulnDb};
use super::feed::{self, Compression, FeedError, Source, Stats};
use super::matcher::{Installed, match_packages, summarize};
use super::release::{Target, target};
use super::*;
use proptest::prelude::*;
use std::io::Write;

const DEBIAN: &str = include_str!("fixtures/debian-tracker.json");
const UBUNTU: &str = include_str!("fixtures/ubuntu-usn.json");

fn collect(source: Source, json: &str) -> (Stats, Vec<Advisory>) {
    let mut out = Vec::new();
    let stats = feed::parse(source, json.as_bytes(), &mut |a| {
        out.push(a);
        Ok(())
    })
    .unwrap();
    (stats, out)
}

fn loaded() -> VulnDb {
    let mut db = VulnDb::open_in_memory().unwrap();
    feed::ingest(&mut db, Source::DebianTracker, DEBIAN.as_bytes()).unwrap();
    feed::ingest(&mut db, Source::UbuntuUsn, UBUNTU.as_bytes()).unwrap();
    db
}

fn pkg(name: &str, version: &str, source: Option<&str>) -> Installed {
    Installed {
        name: name.into(),
        version: version.into(),
        source: source.map(Into::into),
    }
}

#[test]
fn debian_fixture() {
    let (stats, rows) = collect(Source::DebianTracker, DEBIAN);
    assert_eq!(
        stats,
        Stats {
            entries: 5,
            advisories: 6,
            invalid: 3
        }
    );
    let find = |p: &str, id: &str, rel: &str| {
        rows.iter()
            .find(|a| a.package == p && a.id == id && a.release == rel)
            .cloned()
    };
    let a = find("openssl", "CVE-2024-0001", "bookworm").unwrap();
    assert_eq!(a.fixed.as_deref(), Some("3.0.13-1~deb12u1"));
    assert_eq!(a.severity, Severity::Medium);
    assert!(find("openssl", "CVE-2024-0001", "trixie").is_some());
    // sid and bullseye are not supported releases.
    assert!(find("openssl", "CVE-2024-0001", "sid").is_none());
    assert!(find("openssl", "CVE-2024-0001", "bullseye").is_none());
    let open = find("openssl", "CVE-2024-0002", "bookworm").unwrap();
    assert_eq!((open.fixed, open.severity), (None, Severity::Unknown));
    // Unimportant open issues, `fixed_version: "0"` and undetermined are dropped.
    for id in ["CVE-2024-0003", "CVE-2012-0001", "CVE-2024-0004"] {
        assert!(find("openssl", id, "bookworm").is_none(), "{id}");
    }
    assert_eq!(
        find("curl", "TEMP-0000000-ABCDEF", "bookworm")
            .unwrap()
            .severity,
        Severity::Low
    );
    assert!(
        rows.iter()
            .all(|a| a.package != "bash" && a.aliases.is_empty())
    );
}

#[test]
fn ubuntu_fixture() {
    let (stats, rows) = collect(Source::UbuntuUsn, UBUNTU);
    assert_eq!(
        stats,
        Stats {
            entries: 3,
            advisories: 5,
            invalid: 2
        }
    );
    let jammy: Vec<_> = rows
        .iter()
        .filter(|a| a.id == "USN-6000-1" && a.release == "jammy")
        .map(|a| a.package.as_str())
        .collect();
    assert_eq!(jammy, ["libssl-dev", "libssl3", "openssl"]);
    let a = rows.iter().find(|a| a.package == "libssl3t64").unwrap();
    assert_eq!(a.release, "noble");
    assert_eq!(a.aliases, ["CVE-2023-0464", "CVE-2023-0465"]);
    assert!(rows.iter().all(|a| a.release != "focal"));
}

#[test]
fn db_lookup_with_aliases() {
    let db = loaded();
    let a = db.lookup(Distro::Ubuntu, "jammy", "libssl3").unwrap();
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].aliases, ["CVE-2023-0464", "CVE-2023-0465"]);
    assert_eq!(
        db.lookup(Distro::Debian, "bookworm", "openssl")
            .unwrap()
            .len(),
        2
    );
    assert!(
        db.lookup(Distro::Debian, "jammy", "openssl")
            .unwrap()
            .is_empty()
    );
    assert_eq!(db.count(Distro::Debian).unwrap(), 6);
    assert_eq!(db.count(Distro::Ubuntu).unwrap(), 5);
}

#[test]
fn failed_ingest_keeps_previous_rows() {
    let mut db = loaded();
    // Truncated document: parse error after some rows were inserted.
    let cut = &DEBIAN[..DEBIAN.len() / 2];
    assert!(matches!(
        feed::ingest(&mut db, Source::DebianTracker, cut.as_bytes()),
        Err(FeedError::Parse(_))
    ));
    assert!(matches!(
        feed::ingest(&mut db, Source::DebianTracker, &b"{}"[..]),
        Err(FeedError::Empty)
    ));
    assert!(feed::ingest(&mut db, Source::DebianTracker, &b"[1,2]"[..]).is_err());
    assert_eq!(db.count(Distro::Debian).unwrap(), 6);
    // The other feed was untouched throughout.
    assert_eq!(db.count(Distro::Ubuntu).unwrap(), 5);
}

#[test]
fn reingest_replaces() {
    let mut db = loaded();
    let one = r#"{"curl":{"CVE-2023-38545":{"releases":{"bookworm":{"status":"resolved","fixed_version":"7.88.1-10+deb12u4","urgency":"high"}}}}}"#;
    feed::ingest(&mut db, Source::DebianTracker, one.as_bytes()).unwrap();
    assert_eq!(db.count(Distro::Debian).unwrap(), 1);
    assert!(
        db.lookup(Distro::Debian, "bookworm", "openssl")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn compressed_files() {
    let dir = tempfile::tempdir().unwrap();
    let gz = dir.path().join("d.json.gz");
    let mut e = flate2::write::GzEncoder::new(
        std::fs::File::create(&gz).unwrap(),
        flate2::Compression::default(),
    );
    e.write_all(DEBIAN.as_bytes()).unwrap();
    e.finish().unwrap();
    let bz = dir.path().join("u.json.bz2");
    let mut e = bzip2::write::BzEncoder::new(
        std::fs::File::create(&bz).unwrap(),
        bzip2::Compression::default(),
    );
    e.write_all(UBUNTU.as_bytes()).unwrap();
    e.finish().unwrap();

    let mut db = VulnDb::open(&dir.path().join("vulns.sqlite")).unwrap();
    let c = Source::DebianTracker.compression(Some("gzip"));
    assert_eq!(c, Compression::Gzip);
    assert_eq!(
        feed::ingest_file(&mut db, Source::DebianTracker, &gz, c)
            .unwrap()
            .advisories,
        6
    );
    let c = Source::UbuntuUsn.compression(None);
    assert_eq!(
        feed::ingest_file(&mut db, Source::UbuntuUsn, &bz, c)
            .unwrap()
            .advisories,
        5
    );
    // Gzip bytes read as plain JSON: a parse error, not a panic.
    assert!(feed::ingest_file(&mut db, Source::DebianTracker, &gz, Compression::None).is_err());
    assert_eq!(Source::DebianTracker.compression(None), Compression::None);
}

#[test]
fn feed_meta_roundtrip_and_due() {
    let db = VulnDb::open_in_memory().unwrap();
    let m = db.meta(Source::UbuntuUsn).unwrap();
    assert_eq!(m, FeedMeta::default());
    let now = 1_000_000_000_000;
    assert!(feed::due(&m, now));
    let m = FeedMeta {
        etag: Some("\"abc\"".into()),
        last_modified: Some("Fri, 25 Sep 2026 00:36:33 GMT".into()),
        attempted_ms: Some(now),
        fetched_ms: Some(now),
        updated_ms: Some(now),
        rows: 42,
        last_error: None,
    };
    db.set_meta(Source::UbuntuUsn, &m).unwrap();
    assert_eq!(db.meta(Source::UbuntuUsn).unwrap(), m);
    let h = 3600 * 1000;
    assert!(!feed::due(&m, now + 23 * h));
    assert!(feed::due(&m, now + 24 * h));
    // A failed attempt an hour ago: retry; half an hour ago: wait.
    let failed = FeedMeta {
        attempted_ms: Some(now + 30 * h),
        last_error: Some("x".into()),
        ..m.clone()
    };
    assert!(!feed::due(&failed, now + 30 * h + h / 2));
    assert!(feed::due(&failed, now + 31 * h));
    // Clock went backwards.
    assert!(feed::due(&m, now - h));
}

#[test]
fn release_targets() {
    let t = |id, v| target(id, v).map(|t| (t.distro, t.codename));
    assert_eq!(t("debian", "12"), Some((Distro::Debian, "bookworm")));
    assert_eq!(t("debian", "\"13\""), Some((Distro::Debian, "trixie")));
    assert_eq!(t("ubuntu", "22.04"), Some((Distro::Ubuntu, "jammy")));
    assert_eq!(t("ubuntu", "24.04"), Some((Distro::Ubuntu, "noble")));
    assert_eq!(t("debian", "11"), None);
    assert_eq!(t("debian", ""), None);
    assert_eq!(t("fedora", "40"), None);
}

#[test]
fn match_debian() {
    let db = loaded();
    let target = Target {
        distro: Distro::Debian,
        codename: "bookworm",
    };
    let installed = [
        pkg("openssl", "3.0.11-1~deb12u2", None),
        // Binary of the openssl source: matched through its source name.
        pkg("libssl3", "3.0.11-1~deb12u2", Some("openssl")),
        pkg("curl", "7.88.1-10+deb12u3", Some("curl")),
        pkg("zlib1g", "1:1.2.13.dfsg-1", Some("zlib")),
        // Up to date.
        pkg("vim", "2:9.0.1378-2", None),
    ];
    let r = match_packages(&target, &installed, |p| {
        db.lookup(Distro::Debian, "bookworm", p)
    })
    .unwrap();
    let ids: Vec<_> = r
        .findings
        .iter()
        .map(|f| (f.package.as_str(), f.id.as_str()))
        .collect();
    assert_eq!(
        ids,
        [
            ("curl", "CVE-2023-38545"),
            ("libssl3", "CVE-2024-0001"),
            ("openssl", "CVE-2024-0001"),
            ("zlib1g", "CVE-2023-45853"),
            ("libssl3", "CVE-2024-0002"),
            ("openssl", "CVE-2024-0002"),
        ]
    );
    assert_eq!(r.vulnerable_packages, 3);
    assert_eq!(r.unfixed_packages, 1);
    assert_eq!(r.highest, Some(Severity::High));
    // At the fixed version: no longer affected.
    let fixed = [pkg("curl", "7.88.1-10+deb12u4", None)];
    let r = match_packages(&target, &fixed, |p| {
        db.lookup(Distro::Debian, "bookworm", p)
    })
    .unwrap();
    assert!(r.findings.is_empty());
    assert_eq!(r.highest, None);
}

#[test]
fn match_ubuntu() {
    let db = loaded();
    let target = Target {
        distro: Distro::Ubuntu,
        codename: "jammy",
    };
    let installed = [
        // Source name is ignored on Ubuntu (rows are per binary).
        pkg("libssl3", "3.0.2-0ubuntu1.8", Some("openssl")),
        pkg("openssl", "3.0.2-0ubuntu1.10", None),
        pkg("curl", "7.81.0-1ubuntu1.16", None),
    ];
    let r = match_packages(&target, &installed, |p| {
        db.lookup(Distro::Ubuntu, "jammy", p)
    })
    .unwrap();
    assert_eq!(r.findings.len(), 1);
    let f = &r.findings[0];
    assert_eq!(
        (f.package.as_str(), f.id.as_str()),
        ("libssl3", "USN-6000-1")
    );
    assert_eq!(f.fixed.as_deref(), Some("3.0.2-0ubuntu1.9"));
    assert_eq!(f.aliases, ["CVE-2023-0464", "CVE-2023-0465"]);
    assert_eq!((r.vulnerable_packages, r.unfixed_packages), (1, 0));
}

#[test]
fn match_ignores_other_releases() {
    let target = Target {
        distro: Distro::Debian,
        codename: "bookworm",
    };
    let wrong = Advisory {
        distro: Distro::Debian,
        release: "trixie".into(),
        package: "x".into(),
        id: "CVE-1".into(),
        aliases: vec![],
        fixed: Some("9".into()),
        severity: Severity::High,
    };
    let r = match_packages(&target, &[pkg("x", "1", None)], |_| {
        Ok::<_, ()>(vec![wrong.clone()])
    })
    .unwrap();
    assert!(r.findings.is_empty());
    assert_eq!(summarize(vec![]).vulnerable_packages, 0);
}

#[test]
fn severity_mapping() {
    for (s, v) in [
        ("unimportant", Severity::Negligible),
        ("low", Severity::Low),
        ("low**", Severity::Low),
        ("medium*", Severity::Medium),
        ("high", Severity::High),
        ("not yet assigned", Severity::Unknown),
        ("end-of-life", Severity::Unknown),
    ] {
        assert_eq!(Severity::from_urgency(s), v, "{s}");
    }
    for s in [
        Severity::Unknown,
        Severity::Negligible,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ] {
        assert_eq!(Severity::from_i64(s.as_i64()), s);
    }
}

proptest! {
    /// Feed bytes are untrusted: parsing never panics.
    #[test]
    fn parsers_never_panic(s in "[\\[\\]{}\":,a-z0-9. \\-~+]{0,200}") {
        let mut sink = |_: Advisory| Ok(());
        let _ = feed::parse(Source::DebianTracker, s.as_bytes(), &mut sink);
        let _ = feed::parse(Source::UbuntuUsn, s.as_bytes(), &mut sink);
    }

    /// A single advisory flags exactly the installed versions below the fix.
    #[test]
    fn flags_below_fix(a in "[0-9]{1,3}\\.[0-9]{1,3}(-[0-9a-z.+~]{1,6})?", b in "[0-9]{1,3}\\.[0-9]{1,3}(-[0-9a-z.+~]{1,6})?") {
        let t = Target { distro: Distro::Ubuntu, codename: "jammy" };
        let adv = Advisory {
            distro: Distro::Ubuntu, release: "jammy".into(), package: "p".into(),
            id: "USN-1-1".into(), aliases: vec![], fixed: Some(b.clone()), severity: Severity::Unknown,
        };
        let r = match_packages(&t, &[pkg("p", &a, None)], |_| Ok::<_, ()>(vec![adv.clone()])).unwrap();
        prop_assert_eq!(!r.findings.is_empty(), dpkgver::compare(&a, &b) == std::cmp::Ordering::Less);
    }
}
