use super::*;
use crate::logs::FakeLineSpawner;
use crate::packages::DPKG_QUERY;
use crate::runner::{CommandOutput, FakeRunner};
use crate::testutil::{block, ctx, meta};
use fleet_proto::args::{SearchTerm, TimeRange};
use std::os::unix::fs::symlink;

fn q(term: &str, limit: u32) -> SearchQuery {
    SearchQuery {
        term: SearchTerm::new(term).unwrap(),
        case_sensitive: false,
        roots: Vec::new(),
        range: TimeRange::default(),
        limit,
    }
}

const QUERY: [&str; 2] = [
    "-W",
    "-f=${Package}\\t${Architecture}\\t${Version}\\t${db:Status-Want}\\t${db:Status-Status}\\t${source:Package}\\t${source:Version}\\n",
];

#[test]
fn packages_by_name() {
    let d = tempfile::tempdir().unwrap();
    let r = Rc::new(FakeRunner::new());
    r.expect(
        DPKG_QUERY,
        &QUERY,
        Ok(CommandOutput::ok(
            "nginx\tamd64\t1.22.1-9\tinstall\tinstalled\tnginx\t1.22.1-9\n\
             nginx-common\tall\t1.22.1-9\tinstall\tinstalled\tnginx\t1.22.1-9\n\
             openssl\tamd64\t3.0.11\tinstall\tinstalled\topenssl\t3.0.11\n",
        )),
    );
    let c = ctx(d.path(), r);
    let res = block(packages(&c, &q("NGINX", 1))).unwrap();
    assert_eq!(res.hits.len(), 1);
    assert_eq!(res.hits[0].primary, "nginx");
    assert_eq!(res.hits[0].detail, "1.22.1-9 amd64");
    assert!(res.truncated);
}

#[test]
fn ports_and_processes_from_proc() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    std::fs::create_dir_all(root.join("proc/net")).unwrap();
    std::fs::create_dir_all(root.join("proc/812")).unwrap();
    std::fs::create_dir_all(root.join("etc")).unwrap();
    std::fs::write(
        root.join("proc/net/tcp"),
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0\n   1: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   105        0 1002 1 0000000000000000 100 0 0 10 0\n",
    )
    .unwrap();
    std::fs::write(
        root.join("proc/812/stat"),
        "812 (sshd) S 1 812 812 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 1000 1000000 200 18446744073709551615\n",
    )
    .unwrap();
    std::fs::write(
        root.join("proc/812/status"),
        "Uid:\t0\t0\t0\t0\nVmRSS:\t 4 kB\n",
    )
    .unwrap();
    std::fs::write(
        root.join("proc/812/cmdline"),
        "sshd: /usr/sbin/sshd -D\0[listener]\0",
    )
    .unwrap();
    std::fs::write(root.join("etc/passwd"), "root:x:0:0::/root:/bin/sh\n").unwrap();
    let c = ctx(root, Rc::new(FakeRunner::new()));
    let res = ports(&c, &q("22", 10));
    assert_eq!(res.hits.len(), 1, "{res:?}");
    assert_eq!(res.hits[0].primary, "tcp/22");
    let res = ports(&c, &q("127.0.0.1", 10));
    assert_eq!(res.hits[0].primary, "tcp/3306");
    let res = block(processes(&c, &q("listener", 10)));
    assert_eq!(res.hits.len(), 1);
    assert_eq!(res.hits[0].primary, "sshd");
    assert!(res.hits[0].detail.contains("pid 812"));
    assert!(block(processes(&c, &q("nomatch", 10))).hits.is_empty());
}

#[test]
fn files_by_glob_bounded_and_rooted() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    std::fs::create_dir_all(root.join("etc/nginx/sites")).unwrap();
    std::fs::create_dir_all(root.join("srv/app")).unwrap();
    std::fs::create_dir_all(root.join("secret")).unwrap();
    std::fs::write(root.join("etc/nginx/nginx.conf"), "x").unwrap();
    std::fs::write(root.join("etc/nginx/sites/a.conf"), "x").unwrap();
    std::fs::write(root.join("srv/app/app.CONF"), "x").unwrap();
    std::fs::write(root.join("secret/hidden.conf"), "x").unwrap();
    symlink(root.join("secret"), root.join("srv/app/link")).unwrap();
    let c = ctx(root, Rc::new(FakeRunner::new()));
    let res = block(files(&c, &q("*.conf", 100))).unwrap();
    let mut paths: Vec<&str> = res.hits.iter().map(|h| h.primary.as_str()).collect();
    paths.sort_unstable();
    assert_eq!(
        paths,
        [
            "/etc/nginx/nginx.conf",
            "/etc/nginx/sites/a.conf",
            "/srv/app/app.CONF"
        ]
    );
    let res = block(files(&c, &q("*.conf", 1))).unwrap();
    assert_eq!(res.hits.len(), 1);
    assert!(res.truncated);
    // Roots must be under the allowed set.
    let mut bad = q("x", 1);
    bad.roots = vec![AbsPath::new("/secret").unwrap()];
    let h = SearchHandler::new(Rc::new(FakeLineSpawner::new()));
    let op = Op::SearchFiles(bad);
    assert_eq!(
        h.validate(&c, &op, &meta(op.clone(), None))
            .unwrap_err()
            .code(),
        ErrorCode::InvalidArgument
    );
}

#[test]
fn journal_newest_first_matches() {
    let sp = Rc::new(FakeLineSpawner::new());
    sp.expect(
        JOURNALCTL,
        &[
            "-o",
            "json",
            "--no-pager",
            "--quiet",
            "--output-fields=MESSAGE,PRIORITY,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,_PID",
            "--reverse",
        ],
        &[
            r#"{"__CURSOR":"c3","__REALTIME_TIMESTAMP":"1700000003000000","PRIORITY":"3","_SYSTEMD_UNIT":"nginx.service","MESSAGE":"upstream timed OUT"}"#,
            r#"{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"1700000002000000","PRIORITY":"6","MESSAGE":"all good"}"#,
            "not json",
            r#"{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1700000001000000","PRIORITY":"6","_PID":"9","MESSAGE":"timed out again"}"#,
        ],
        false,
    );
    let res = block(journal(sp.as_ref(), &q("timed out", 10))).unwrap();
    let msgs: Vec<&str> = res.hits.iter().map(|h| h.primary.as_str()).collect();
    assert_eq!(msgs, ["upstream timed OUT", "timed out again"]);
    assert!(
        res.hits[0]
            .detail
            .starts_with("1700000003000 nginx.service")
    );
    assert!(!res.truncated);
}

#[test]
fn registry_has_search_tags() {
    let mut r = Registry::new();
    register(&mut r);
    for t in TAGS {
        assert!(r.tags().any(|x| x == t));
    }
    assert!(!r.tags().any(|x| x == tag::SEARCH_USERS));
}
