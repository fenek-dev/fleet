use super::model::{self, SshInfo, canonical, canonical_ports, check, parse_sshd_ports, version};
use super::parse::{parse_table, parse_ufw, summarize_ruleset};
use super::render::{delete_table_script, render};
use super::*;
use crate::Reverters;
use crate::handler::OpOutput;
use crate::runner::{CommandOutput, FakeRunner};
use crate::testutil::{block, ctx, meta};
use fleet_proto::args::{
    Cidr, FirewallRule, FwAction, FwChain, FwComment, Port, PortRange, Protocol, RateLimit,
};
use proptest::prelude::*;
use std::path::Path;

const MANAGED_JSON: &str = include_str!("testdata/managed.json");
const BANS_ONLY_JSON: &str = include_str!("testdata/bans_only.json");
const HAND_EDITED_JSON: &str = include_str!("testdata/hand_edited.json");
const RULESET_JSON: &str = include_str!("testdata/ruleset.json");
const NO_TABLE: &str =
    "Error: No such file or directory\nlist table inet fleet\n                 ^^^^^\n";
const UFW_ACTIVE: &str = "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\nNew profiles: skip\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW IN    Anywhere\n80,443/tcp                 ALLOW IN    Anywhere\n22/tcp (v6)                ALLOW IN    Anywhere (v6)\n";

fn nowhere() -> &'static Path {
    Path::new("/nonexistent-fleet-test-root")
}

fn p(n: u16) -> PortRange {
    PortRange::single(Port::new(n).unwrap())
}

fn pr(a: u16, b: u16) -> PortRange {
    PortRange::new(Port::new(a).unwrap(), Port::new(b).unwrap()).unwrap()
}

fn rule(chain: FwChain, action: FwAction, proto: Protocol, ports: Vec<PortRange>) -> FirewallRule {
    FirewallRule {
        chain,
        action,
        proto,
        ports,
        source: None,
        rate_limit: None,
        comment: FwComment::new("").unwrap(),
    }
}

fn named(mut r: FirewallRule, c: &str) -> FirewallRule {
    r.comment = FwComment::new(c).unwrap();
    r
}

fn from(mut r: FirewallRule, c: &str) -> FirewallRule {
    r.source = Some(c.parse::<Cidr>().unwrap());
    r
}

fn limited(mut r: FirewallRule, per_minute: u32, burst: u16) -> FirewallRule {
    r.rate_limit = Some(RateLimit { per_minute, burst });
    r
}

fn ssh() -> FirewallRule {
    limited(
        named(
            rule(FwChain::Input, FwAction::Accept, Protocol::Tcp, vec![p(22)]),
            "ssh",
        ),
        10,
        5,
    )
}

fn managed(rules: Vec<FirewallRule>) -> FirewallRuleSet {
    FirewallRuleSet {
        mode: FirewallMode::Managed,
        rules,
    }
}

#[test]
fn port_blocked_first_match() {
    use FwAction::*;
    use FwChain::*;
    use Protocol::*;
    let set = fixture_model();
    let b = |proto, port| model::port_blocked(&set, &[22], proto, port);
    assert!(!b(Tcp, 443), "accepted");
    assert!(!b(Tcp, 9050), "accepted from some sources");
    assert!(!b(Udp, 27015));
    assert!(!b(Tcp, 22), "sshd");
    assert!(b(Tcp, 8080), "forward rule doesn't open the host port");
    assert!(b(Udp, 443), "other protocol");
    assert!(b(Tcp, 5432), "Managed default drop");
    let mut dropped = managed(vec![
        rule(Input, Drop, Tcp, vec![p(25565)]),
        rule(Input, Accept, Tcp, vec![p(25565)]),
    ]);
    assert!(model::port_blocked(&dropped, &[], Tcp, 25565));
    dropped.rules[0] = from(dropped.rules[0].clone(), "198.51.100.0/24");
    assert!(!model::port_blocked(&dropped, &[], Tcp, 25565));
    let open = FirewallRuleSet {
        mode: FirewallMode::BansOnly,
        rules: Vec::new(),
    };
    assert!(!model::port_blocked(&open, &[], Tcp, 5432));
}

/// The model `testdata/managed.json` holds (ports deliberately
/// unsorted: canonical form sorts them).
fn fixture_model() -> FirewallRuleSet {
    use FwAction::*;
    use FwChain::*;
    use Protocol::*;
    managed(vec![
        ssh(),
        named(rule(Input, Accept, Tcp, vec![p(443), p(80)]), "web"),
        from(
            named(rule(Input, Accept, Tcp, vec![pr(9000, 9100)]), "office"),
            "203.0.113.0/24",
        ),
        named(rule(Forward, Accept, Tcp, vec![p(8080)]), "app"),
        limited(
            named(
                rule(Input, Accept, Udp, vec![pr(27015, 27016)]),
                "game: cs2",
            ),
            60,
            20,
        ),
        from(
            named(rule(Input, Reject, Tcp, vec![p(8080)]), "block"),
            "2001:db8::/32",
        ),
    ])
}

fn golden(name: &str, got: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/firewall/testdata")
        .join(format!("{name}.nft"));
    if std::env::var_os("FLEET_UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, got).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(want == got, "golden {name} differs; got:\n{got}");
}

// ---- rendering ----

#[test]
fn golden_managed() {
    golden("managed", &render(&fixture_model(), &[22]));
}

#[test]
fn golden_bans_only() {
    let set = FirewallRuleSet {
        mode: FirewallMode::BansOnly,
        rules: vec![],
    };
    golden("bans_only", &render(&set, &[22]));
}

#[test]
fn golden_docker_forward() {
    use FwAction::*;
    use FwChain::*;
    let set = managed(vec![
        ssh(),
        named(
            rule(Forward, Accept, Protocol::Tcp, vec![p(443), p(80)]),
            "caddy",
        ),
        from(
            named(
                rule(Forward, Accept, Protocol::Tcp, vec![p(5432)]),
                "db from lan",
            ),
            "10.0.0.0/8",
        ),
        named(rule(Forward, Drop, Protocol::Udp, vec![p(5353)]), "no mdns"),
    ]);
    golden("docker", &render(&set, &[22, 2222]));
}

#[test]
fn golden_game_meters() {
    use FwAction::*;
    use FwChain::*;
    let set = managed(vec![
        ssh(),
        limited(
            named(
                rule(Input, Accept, Protocol::Udp, vec![pr(27015, 27016)]),
                "cs2",
            ),
            60,
            20,
        ),
        limited(
            from(
                named(
                    rule(Input, Accept, Protocol::Tcp, vec![p(25565)]),
                    "minecraft",
                ),
                "198.51.100.0/24",
            ),
            30,
            0,
        ),
        limited(
            named(
                rule(Forward, Accept, Protocol::Udp, vec![p(7777)]),
                "container game",
            ),
            120,
            40,
        ),
    ]);
    golden("game", &render(&set, &[22]));
}

#[test]
fn render_only_touches_inet_fleet() {
    let s = render(&fixture_model(), &[22]);
    assert!(!s.contains("flush"));
    for line in s.lines() {
        if line.starts_with("add ") || line.starts_with("delete ") || line.starts_with("table ") {
            assert!(line.contains(" inet fleet"), "{line}");
        }
        assert!(!line.starts_with("delete table"), "{line}");
        assert!(!line.contains("delete set inet fleet banned"), "{line}");
        assert!(!line.contains("delete set inet fleet exempt"), "{line}");
    }
    assert_eq!(
        delete_table_script(),
        "add table inet fleet\ndelete table inet fleet\n"
    );
}

#[test]
fn canonical_ports_sort_and_merge() {
    let got = canonical_ports(&[p(443), pr(20, 30), p(25), p(31), p(80), p(79), p(443)]);
    assert_eq!(got, vec![pr(20, 31), pr(79, 80), p(443)]);
    let got = canonical_ports(&[pr(1, 65535), p(22)]);
    assert_eq!(got, vec![pr(1, 65535)]);
}

#[test]
fn version_is_canonical_and_nonzero() {
    let a = fixture_model();
    let b = canonical(&a);
    assert_ne!(a, b);
    assert_eq!(version(&a), version(&b));
    assert_ne!(version(&a), model::ABSENT_VERSION);
    let mut c = b.clone();
    c.rules.swap(1, 2);
    assert_ne!(version(&b), version(&c), "order matters");
}

// ---- safety checks ----

#[test]
fn lockout_checks() {
    use FwAction::*;
    use FwChain::*;
    let both = SshInfo::ports(&[22]);
    let v4_only = SshInfo {
        v6: false,
        ..both.clone()
    };
    let live_2222 = SshInfo {
        ports: vec![22, 2222],
        live: vec![2222],
        ..both.clone()
    };
    let (only_2222, two) = (SshInfo::ports(&[2222]), SshInfo::ports(&[22, 2222]));
    let web = named(rule(Input, Accept, Protocol::Tcp, vec![p(80)]), "web");
    let block = rule(Input, Drop, Protocol::Tcp, vec![pr(1, 1024)]);
    let ssh_on = |n: u16| rule(Input, Accept, Protocol::Tcp, vec![p(n)]);
    let bad = limited(rule(Input, Drop, Protocol::Tcp, vec![p(25)]), 5, 0);
    let cases: Vec<(&str, Vec<FirewallRule>, &SshInfo, bool)> = vec![
        ("fixture", fixture_model().rules, &both, true),
        ("no ssh rule", vec![web.clone()], &both, false),
        ("other port", vec![ssh()], &only_2222, false),
        ("one of the ports", vec![ssh()], &two, true),
        // Source-restricted SSH alone could lock out everyone else.
        (
            "restricted",
            vec![from(ssh(), "203.0.113.0/24")],
            &both,
            false,
        ),
        // Shorter than /8 counts as anywhere, but per family.
        ("v4 /4 only", vec![from(ssh(), "0.0.0.0/4")], &both, false),
        (
            "v4 /4, v4 host",
            vec![from(ssh(), "0.0.0.0/4")],
            &v4_only,
            true,
        ),
        ("v4 /7", vec![from(ssh(), "0.0.0.0/7")], &v4_only, true),
        ("v4 /8", vec![from(ssh(), "10.0.0.0/8")], &v4_only, false),
        (
            "v4 + v6 wide",
            vec![from(ssh(), "0.0.0.0/0"), from(ssh(), "::/15")],
            &both,
            true,
        ),
        (
            "v6 /16",
            vec![from(ssh(), "0.0.0.0/0"), from(ssh(), "2001::/16")],
            &both,
            false,
        ),
        ("drop before", vec![block.clone(), ssh()], &both, false),
        // Any earlier drop covering SSH, whatever its source.
        (
            "restricted drop before",
            vec![from(block.clone(), "192.0.2.0/24"), ssh()],
            &both,
            false,
        ),
        ("drop after", vec![ssh(), block.clone()], &both, true),
        // A v6-only drop can't block v4 SSH.
        (
            "v6 drop, v4 host",
            vec![from(block.clone(), "2001:db8::/32"), ssh()],
            &v4_only,
            true,
        ),
        (
            "v6 drop, both",
            vec![from(block, "2001:db8::/32"), ssh()],
            &both,
            false,
        ),
        (
            "udp",
            vec![rule(Input, Accept, Protocol::Udp, vec![p(22)])],
            &both,
            false,
        ),
        // sshd listens on 2222 only: an accept for config port 22 isn't enough.
        ("live port", vec![ssh_on(22)], &live_2222, false),
        ("live port ok", vec![ssh_on(2222)], &live_2222, true),
        // Rate limits only on accept rules.
        ("limited drop", vec![ssh(), bad], &both, false),
    ];
    for (name, rules, info, ok) in cases {
        assert_eq!(check(&managed(rules), info).is_ok(), ok, "{name}");
    }
    let both = &both;
    let many: Vec<_> = (0..=model::MAX_METERED)
        .map(|i| {
            limited(
                rule(Input, Accept, Protocol::Udp, vec![p(1000 + i as u16)]),
                5,
                0,
            )
        })
        .chain([ssh()])
        .collect();
    assert!(check(&managed(many), both).is_err());
    // Bans-only needs no SSH rule, but can't carry rules.
    let bo = FirewallRuleSet {
        mode: FirewallMode::BansOnly,
        rules: vec![],
    };
    assert_eq!(check(&bo, both), Ok(()));
    assert!(
        check(
            &FirewallRuleSet {
                rules: vec![web],
                ..bo
            },
            both
        )
        .is_err()
    );
}

#[test]
fn sshd_ports() {
    let text =
        "# Port 99\nPort 2222\nport=2200\nListenAddress 0.0.0.0\nMatch User git\nPort 3333\n";
    assert_eq!(parse_sshd_ports(text), vec![2222, 2200]);
    // A malformed Port is an error, not skipped.
    let mut cfg = model::SshdConfig::default();
    assert!(model::parse_sshd_config("Port x\n", &mut cfg, &mut |_| Ok(())).is_err());

    // (files under /etc/ssh, Ok(ports) or Err)
    let long = "Port 22\n".repeat(10_001);
    type Case<'a> = (&'a str, Vec<(&'a str, &'a str)>, Result<Vec<u16>, ()>);
    let cases: Vec<Case> = vec![
        ("no config", vec![], Ok(vec![22])),
        (
            "include glob, relative and absolute",
            vec![
                (
                    "sshd_config",
                    "Include sshd_config.d/*.conf /etc/ssh/extra\nPort 22\n",
                ),
                ("sshd_config.d/10-fleet.conf", "Port 2222\n"),
                ("sshd_config.d/x.disabled", "Port 1\n"),
                ("sshd_config.d/.hidden.conf", "Port 2\n"),
                ("extra", "Port 2200\n"),
            ],
            Ok(vec![22, 2200, 2222]),
        ),
        (
            "listen addresses",
            vec![(
                "sshd_config",
                "Port 2000\nListenAddress 10.0.0.1:2201\nListenAddress [2001:db8::1]:2202\nListenAddress 2001:db8::2\n",
            )],
            Ok(vec![2000, 2201, 2202]),
        ),
        (
            "listen ports only: Port unused",
            vec![("sshd_config", "ListenAddress 0.0.0.0:2201\n")],
            Ok(vec![2201]),
        ),
        (
            "include loop hits depth bound",
            vec![("sshd_config", "Include sshd_config\n")],
            Err(()),
        ),
        (
            "too many ports",
            vec![(
                "sshd_config",
                "Port 1\nPort 2\nPort 3\nPort 4\nPort 5\nPort 6\nPort 7\nPort 8\nPort 9\n",
            )],
            Err(()),
        ),
        ("too long", vec![("sshd_config", long.as_str())], Err(())),
        (
            "bad listen port",
            vec![("sshd_config", "ListenAddress [::1]:x\n")],
            Err(()),
        ),
    ];
    for (name, files, want) in cases {
        let dir = tempfile::tempdir().unwrap();
        for (f, text) in files {
            let p = dir.path().join("etc/ssh").join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        let c = ctx(dir.path(), Rc::new(FakeRunner::new()));
        let got = model::ssh_info(&c).map(|i| i.ports).map_err(|_| ());
        assert_eq!(got, want, "{name}");
    }
}

/// Live sshd sockets (from `/proc`) join the configured ports and decide
/// which one an accept rule must cover.
#[test]
fn sshd_live_ports_from_proc() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::create_dir_all(d.join("proc/net")).unwrap();
    std::fs::create_dir_all(d.join("proc/700/fd")).unwrap();
    std::fs::write(d.join("proc/700/comm"), "sshd\n").unwrap();
    // 0.0.0.0:2222 LISTEN, inode 4242.
    std::fs::write(
        d.join("proc/net/tcp"),
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000:08AE 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1 0 100 0 0 10 0\n",
    )
    .unwrap();
    std::os::unix::fs::symlink("socket:[4242]", d.join("proc/700/fd/3")).unwrap();
    let c = ctx(d, Rc::new(FakeRunner::new()));
    let info = model::ssh_info(&c).unwrap();
    assert_eq!(
        (info.ports.as_slice(), info.live.as_slice()),
        (&[22, 2222][..], &[2222][..])
    );
    assert!(check(&managed(vec![ssh()]), &info).is_err());
}

// ---- parsing ----

#[test]
fn parse_managed_fixture() {
    let got = parse_table(MANAGED_JSON.as_bytes()).unwrap();
    assert_eq!(got.unrecognized, None);
    assert_eq!(got.mode, FirewallMode::Managed);
    assert_eq!(got.banned, 3);
    assert_eq!(got.model, Some(canonical(&fixture_model())));
    assert_eq!(got.version, version(&fixture_model()));
}

#[test]
fn parse_bans_only_fixture() {
    let got = parse_table(BANS_ONLY_JSON.as_bytes()).unwrap();
    assert_eq!(got.unrecognized, None);
    assert_eq!(got.mode, FirewallMode::BansOnly);
    assert_eq!(got.banned, 3);
    let empty = FirewallRuleSet {
        mode: FirewallMode::BansOnly,
        rules: vec![],
    };
    assert_eq!(got.model, Some(empty.clone()));
    assert_eq!(got.version, version(&empty));
}

#[test]
fn parse_hand_edited_is_unrecognized_with_stable_version() {
    let got = parse_table(HAND_EDITED_JSON.as_bytes()).unwrap();
    assert_eq!(got.model, None);
    assert_eq!(got.unrecognized, Some("rule without comment"));
    assert_eq!(got.mode, FirewallMode::Managed);
    assert_eq!(got.banned, 1);
    // Bans (set elements) and handles don't move the version...
    let more_bans = HAND_EDITED_JSON
        .replace(
            r#"{"elem": {"val": "192.0.2.10", "timeout": 3600, "expires": 3412}}"#,
            r#"{"elem": {"val": "192.0.2.10", "timeout": 3600, "expires": 3000}}, "192.0.2.77""#,
        )
        .replace(r#""handle": 40"#, r#""handle": 41"#);
    let again = parse_table(more_bans.as_bytes()).unwrap();
    assert_eq!(again.banned, 2);
    assert_eq!(again.version, got.version);
    // ...rules do.
    let other = HAND_EDITED_JSON.replace("3306", "3307");
    assert_ne!(parse_table(other.as_bytes()).unwrap().version, got.version);
}

#[test]
fn parse_rejects_garbage() {
    assert!(parse_table(b"not json").is_err());
    let odd = MANAGED_JSON.replace(r#""comment": "r5 block""#, r#""comment": "r5 bl\"ock""#);
    let got = parse_table(odd.as_bytes()).unwrap();
    assert_eq!(got.model, None, "comment outside the FwComment charset");
    let gap = MANAGED_JSON.replace(r#""comment": "r5 block""#, r#""comment": "r7 block""#);
    assert_eq!(
        parse_table(gap.as_bytes()).unwrap().unrecognized,
        Some("rule numbering")
    );
    let jump = MANAGED_JSON.replace(r#"{"reject": null}"#, r#"{"jump": {"target": "x"}}"#);
    assert_eq!(
        parse_table(jump.as_bytes()).unwrap().unrecognized,
        Some("statement")
    );
}

/// Anything `render` wouldn't write, down to base rules and chain
/// definitions, makes the table unrecognized.
#[test]
fn parse_round_trip_checks() {
    let exprs65 = format!(
        r#"{}{{"reject": null}}]"#,
        r#"{"counter": null}, "#.repeat(64)
    );
    let cases: Vec<(&str, String, &str)> = vec![
        (
            "base rule changed",
            MANAGED_JSON.replace(r#""rate": 10, "burst": 20"#, r#""rate": 11, "burst": 20"#),
            "base rules",
        ),
        (
            "base rule missing",
            MANAGED_JSON.replace(
                r#"{"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": "invalid"}}, {"drop": null}"#,
                r#"{"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": "invalid"}}, {"accept": null}"#,
            ),
            "base rules",
        ),
        (
            "unknown base statement",
            MANAGED_JSON.replace(
                r#"{"match": {"op": "==", "left": {"meta": {"key": "iif"}}, "right": "lo"}}, {"accept": null}"#,
                r#"{"match": {"op": "==", "left": {"meta": {"key": "iif"}}, "right": "lo"}}, {"jump": {"target": "x"}}"#,
            ),
            "base rule",
        ),
        (
            "chain priority",
            MANAGED_JSON.replace(r#""hook": "input", "prio": 0"#, r#""hook": "input", "prio": 10"#),
            "chain definition",
        ),
        (
            "chain hook",
            MANAGED_JSON.replace(r#""hook": "forward""#, r#""hook": "output""#),
            "chain definition",
        ),
        (
            "forward policy",
            MANAGED_JSON.replace(
                r#""hook": "forward", "prio": 0, "policy": "accept""#,
                r#""hook": "forward", "prio": 0, "policy": "drop""#,
            ),
            "chain definition",
        ),
        (
            "rule over 64 expressions",
            MANAGED_JSON.replace(r#"{"reject": null}]"#, &exprs65),
            "rule too long",
        ),
        (
            "meter slot out of range",
            MANAGED_JSON.replace(r#""name": "m4_1""#, r#""name": "m4_16""#),
            "unknown set",
        ),
    ];
    for (name, json, why) in cases {
        assert_ne!(json, MANAGED_JSON, "{name}: fixture unchanged");
        let got = parse_table(json.as_bytes()).unwrap();
        assert_eq!(
            (got.model.is_none(), got.unrecognized),
            (true, Some(why)),
            "{name}"
        );
    }
    // The fixture itself round-trips, exempt ports masked.
    let exempt4 = r#""right": 22}}, {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "@exempt4""#;
    let other_ssh =
        MANAGED_JSON.replace(exempt4, &exempt4.replace("22}", "{\"set\": [22, 2222]}}"));
    assert_ne!(other_ssh, MANAGED_JSON);
    assert_eq!(
        parse_table(other_ssh.as_bytes()).unwrap().unrecognized,
        None
    );
}

#[test]
fn ruleset_summary() {
    let t = summarize_ruleset(RULESET_JSON.as_bytes()).unwrap();
    let names: Vec<_> = t
        .iter()
        .map(|t| format!("{} {}", t.family, t.name))
        .collect();
    assert_eq!(names, ["ip filter", "ip nat", "ip6 filterflushruleset"]);
    assert_eq!((t[0].chains, t[0].rules), (5, 3));
    assert_eq!(t[0].owners, ["ufw", "docker"]);
    assert_eq!(t[1].owners, ["docker"]);
    let text = parse::foreign_text(Ok(&t), Some(&parse_ufw(UFW_ACTIVE)), None);
    assert!(
        text.contains("ip filter: 5 chains, 3 rules (ufw, docker)"),
        "{text}"
    );
    assert!(text.contains("80,443/tcp"));
}

#[test]
fn ufw_status() {
    let u = parse_ufw(UFW_ACTIVE);
    assert!(u.active);
    assert_eq!(u.lines.len(), 10);
    assert!(!parse_ufw("Status: inactive\n").active);
    let hostile = format!("Status: active\n{}\x1b[2J\n", "x".repeat(1000));
    let u = parse_ufw(&hostile);
    assert!(
        u.lines
            .iter()
            .all(|l| l.len() <= parse::UFW_MAX_LINE && !l.contains('\x1b'))
    );
}

// ---- handlers ----

fn out(s: &str) -> Result<CommandOutput, RunError> {
    Ok(CommandOutput::ok(s.as_bytes().to_vec()))
}

fn absent() -> Result<CommandOutput, RunError> {
    Ok(CommandOutput {
        code: Some(1),
        stderr: NO_TABLE.as_bytes().to_vec(),
        ..CommandOutput::default()
    })
}

const LIST_TABLE: [&str; 5] = ["-j", "list", "table", "inet", "fleet"];
const APPLY: [&str; 2] = ["-f", "-"];

fn apply_meta(set: FirewallRuleSet, expected: Option<u64>) -> (Op, OpMeta) {
    let op = Op::FirewallApply(set);
    let mut m = meta(op.clone(), Some(7));
    m.command.body.expected_version = expected;
    (op, m)
}

fn run(h: &FirewallHandler, c: &SysCtx, op: &Op, m: &OpMeta) -> Result<Payload, OpError> {
    h.validate(c, op, m)?;
    match block(h.handle(c, op, m))? {
        OpOutput::Payload(p) => Ok(p),
        OpOutput::Stream(_) => panic!("stream"),
    }
}

#[test]
fn get_reports_model_bans_and_foreign_tables() {
    let f = Rc::new(FakeRunner::new());
    f.expect(NFT, &LIST_TABLE, out(MANAGED_JSON));
    f.expect(NFT, &["-j", "list", "ruleset"], out(RULESET_JSON));
    f.expect(UFW, &["status", "verbose"], out(UFW_ACTIVE));
    let c = ctx(nowhere(), f.clone());
    let op = Op::FirewallGet;
    let Payload::Firewall(st) = run(&FirewallHandler, &c, &op, &meta(op.clone(), None)).unwrap()
    else {
        panic!()
    };
    assert_eq!(st.mode, FirewallMode::Managed);
    assert_eq!(st.version, version(&fixture_model()));
    assert_eq!(st.rules, canonical(&fixture_model()).rules);
    assert_eq!(st.banned, 3);
    assert!(
        st.foreign_ruleset
            .contains("ip nat: 2 chains, 1 rules (docker)")
    );
    assert!(st.foreign_ruleset.contains("Status: active"));
    assert_eq!(f.pending(), 0);
}

#[test]
fn get_without_table_or_tools() {
    let f = Rc::new(FakeRunner::new());
    f.expect(NFT, &LIST_TABLE, absent());
    f.expect(NFT, &["-j", "list", "ruleset"], Err(RunError::Timeout));
    f.expect(
        UFW,
        &["status", "verbose"],
        Err(RunError::Spawn(std::io::ErrorKind::NotFound)),
    );
    let c = ctx(nowhere(), f);
    let op = Op::FirewallGet;
    let Payload::Firewall(st) = run(&FirewallHandler, &c, &op, &meta(op.clone(), None)).unwrap()
    else {
        panic!()
    };
    assert_eq!(
        (st.mode, st.version, st.banned),
        (FirewallMode::BansOnly, 0, 0)
    );
    assert!(st.rules.is_empty());
    assert!(st.foreign_ruleset.contains("unavailable"));
}

#[test]
fn apply_checks_version_then_applies_atomically() {
    let set = managed(vec![ssh()]);
    let current = version(&fixture_model());

    // Stale expected version: nothing applied.
    let f = Rc::new(FakeRunner::new());
    f.expect(NFT, &LIST_TABLE, out(MANAGED_JSON));
    let c = ctx(nowhere(), f.clone());
    let (op, m) = apply_meta(set.clone(), Some(current ^ 1));
    let e = run(&FirewallHandler, &c, &op, &m).unwrap_err();
    assert_eq!(e.code(), ErrorCode::VersionConflict { current });
    assert_eq!(f.calls().len(), 1);

    // Current: one `nft -f -` with the rendered script on stdin.
    let f = Rc::new(FakeRunner::new());
    f.expect(NFT, &LIST_TABLE, out(MANAGED_JSON));
    f.expect(NFT, &APPLY, out(""));
    let c = ctx(nowhere(), f.clone());
    let (op, m) = apply_meta(set.clone(), Some(current));
    let Payload::ChangePending { change: p, .. } = run(&FirewallHandler, &c, &op, &m).unwrap()
    else {
        panic!()
    };
    assert_eq!(p.new_version, Some(version(&set)));
    let calls = f.calls();
    assert_eq!(
        calls[1].stdin.as_deref(),
        Some(render(&set, &[22]).as_bytes())
    );
    assert!(calls[0].stdin.is_none());

    // First apply on a server without the table expects version 0.
    let f = Rc::new(FakeRunner::new());
    f.expect(NFT, &LIST_TABLE, absent());
    f.expect(NFT, &APPLY, out(""));
    let c = ctx(nowhere(), f.clone());
    let (op, m) = apply_meta(set.clone(), Some(0));
    assert!(run(&FirewallHandler, &c, &op, &m).is_ok());

    // nft refusing the script is an error (exec restores the snapshot).
    let f = Rc::new(FakeRunner::new());
    f.expect(NFT, &LIST_TABLE, absent());
    f.expect(
        NFT,
        &APPLY,
        Ok(CommandOutput {
            code: Some(1),
            stderr: b"Error: syntax error".to_vec(),
            ..CommandOutput::default()
        }),
    );
    let c = ctx(nowhere(), f);
    let (op, m) = apply_meta(set, Some(0));
    assert_eq!(
        run(&FirewallHandler, &c, &op, &m).unwrap_err().code(),
        ErrorCode::Internal
    );
}

/// An unrecognized table is replaced: every chain flushed and deleted,
/// foreign sets deleted, ban/exempt sets kept (or recreated with their
/// listed elements when declared differently).
#[test]
fn apply_replaces_unrecognized_table() {
    let set = managed(vec![ssh()]);
    let flush_io = "flush chain inet fleet input\nflush chain inet fleet forward\ndelete chain inet fleet input\ndelete chain inet fleet forward\n";
    // Objects listed ahead of the first chain.
    let insert = |objs: &str| {
        HAND_EDITED_JSON.replacen(r#"{"chain": {"#, &format!("{objs}\n{{\"chain\": {{"), 1)
    };
    let foreign_set = insert(
        r#"{"set": {"family": "inet", "name": "extra", "table": "fleet", "type": "ipv4_addr", "handle": 90}},
{"chain": {"family": "inet", "table": "fleet", "name": "x-1", "handle": 91}},"#,
    );
    let odd_ban = HAND_EDITED_JSON.replacen(
        r#""flags": ["interval", "timeout"]"#,
        r#""flags": ["timeout"]"#,
        1,
    );
    let bad_name = insert(
        r#"{"chain": {"family": "inet", "table": "fleet", "name": "x; flush ruleset", "handle": 91}},"#,
    );
    let flowtable = insert(
        r#"{"flowtable": {"family": "inet", "table": "fleet", "name": "ft", "handle": 91}},"#,
    );
    // (listing, Ok((pre, post)) or Err)
    type Case = (&'static str, String, Option<(String, String)>);
    let cases: Vec<Case> = vec![
        ("hand edited", HAND_EDITED_JSON.into(), Some((flush_io.into(), String::new()))),
        (
            "foreign set and chain",
            foreign_set,
            Some((
                "flush chain inet fleet x-1\nflush chain inet fleet input\nflush chain inet fleet forward\ndelete chain inet fleet x-1\ndelete chain inet fleet input\ndelete chain inet fleet forward\ndelete set inet fleet extra\n".into(),
                String::new(),
            )),
        ),
        (
            "ban set declared differently",
            odd_ban,
            Some((
                format!("{flush_io}delete set inet fleet banned4\n"),
                "add element inet fleet banned4 { 192.0.2.10 timeout 3412s }\n".into(),
            )),
        ),
        ("unsafe name", bad_name, None),
        ("unsupported object", flowtable, None),
    ];
    for (name, listing, want) in cases {
        let parsed = parse_table(listing.as_bytes()).unwrap();
        assert!(parsed.model.is_none(), "{name}");
        let f = Rc::new(FakeRunner::new());
        f.expect(NFT, &LIST_TABLE, out(&listing));
        if want.is_some() {
            f.expect(NFT, &APPLY, out(""));
        }
        let c = ctx(nowhere(), f.clone());
        let (op, m) = apply_meta(set.clone(), Some(parsed.version));
        let got = run(&FirewallHandler, &c, &op, &m);
        match want {
            Some((pre, post)) => {
                assert!(got.is_ok(), "{name}: {got:?}");
                let script = format!("{pre}{}{post}", render(&set, &[22]));
                assert_eq!(
                    f.calls()[1].stdin.as_deref(),
                    Some(script.as_bytes()),
                    "{name}"
                );
            }
            None => {
                assert_eq!(
                    got.unwrap_err().code(),
                    ErrorCode::InvalidArgument,
                    "{name}"
                );
                assert_eq!(f.calls().len(), 1, "{name}: nothing applied");
            }
        }
    }
}

/// `firewall.apply` holds the table lock across its nft calls and
/// releases it after.
#[test]
fn apply_holds_table_lock() {
    use std::task::{Context, Waker};
    let f = Rc::new(FakeRunner::new());
    f.expect(NFT, &LIST_TABLE, absent());
    f.expect(NFT, &APPLY, out(""));
    let c = ctx(nowhere(), f.clone());
    let (op, m) = apply_meta(managed(vec![ssh()]), Some(0));
    // Other tests may hold it briefly: wait for it.
    let held = block(crate::nftlock::lock());
    let mut fut = FirewallHandler.handle(&c, &op, &m);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(fut.as_mut().poll(&mut cx).is_pending());
    assert!(
        f.calls().is_empty(),
        "no nft call while another writer holds the table"
    );
    drop(held);
    assert!(block(fut).is_ok());
    assert_eq!(f.calls().len(), 2);
}

#[test]
fn raw_snapshot_must_be_one_fleet_table() {
    let ok = "table inet fleet {\n\tset s {\n\t\ttype ipv4_addr\n\t}\n\tchain input {\n\t\ttcp dport 3306 accept comment \"a } b\"\n\t}\n}\n";
    let cases: Vec<(&str, String, bool)> = vec![
        ("listing", ok.into(), true),
        (
            "trailing table",
            format!("{ok}table ip filter {{\n}}\n"),
            false,
        ),
        ("trailing command", format!("{ok}flush ruleset\n"), false),
        (
            "include inside",
            ok.replace("\tset s", "\tinclude \"/etc/x\"\n\tset s"),
            false,
        ),
        ("define", format!("define x = 1\n{ok}"), false),
        ("other table", ok.replace("inet fleet", "ip filter"), false),
        (
            "nested table",
            ok.replace("\tset s {", "\ttable ip x {"),
            false,
        ),
        (
            "unbalanced",
            ok.trim_end().trim_end_matches('}').into(),
            false,
        ),
        (
            "hash comment",
            ok.replace("accept comment", "accept # }\n comment"),
            false,
        ),
        ("variable", ok.replace("3306", "$p"), false),
        (
            "unterminated string",
            ok.replace("\"a } b\"", "\"a } b"),
            false,
        ),
    ];
    for (name, text, want) in cases {
        assert_eq!(check_raw(&text).is_ok(), want, "{name}");
        let script = Snapshot::Raw(text).script(&[22]);
        assert_eq!(script.is_ok(), want, "{name}");
    }
    // A listing that can't be restored refuses the op at snapshot time.
    let f = Rc::new(FakeRunner::new());
    let c = ctx(nowhere(), f.clone());
    f.expect(NFT, &LIST_TABLE, out(HAND_EDITED_JSON));
    f.expect(
        NFT,
        &["list", "table", "inet", "fleet"],
        out(&format!("{ok}flush ruleset\n")),
    );
    assert!(FirewallRevert.snapshot(&c, &Op::FirewallGet).is_err());
}

#[test]
fn apply_refuses_lockout_before_touching_anything() {
    let f = Rc::new(FakeRunner::new());
    let c = ctx(nowhere(), f.clone());
    let web = named(
        rule(FwChain::Input, FwAction::Accept, Protocol::Tcp, vec![p(80)]),
        "web",
    );
    let (op, m) = apply_meta(managed(vec![web]), Some(0));
    let e = FirewallHandler.validate(&c, &op, &m).unwrap_err();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    assert!(f.calls().is_empty());
}

/// Design §4.10 with the real module: snapshot → apply → no
/// `change.confirm` → the timer's restore puts back exactly the
/// snapshot's script.
#[test]
fn lockout_safety_restore_equals_snapshot() {
    let f = Rc::new(FakeRunner::new());
    let c = ctx(nowhere(), f.clone());
    let reverters = Reverters::with_generic();
    let module = reverters.get(ChangeKind::Firewall).unwrap();
    let new = managed(vec![ssh()]);
    let (op, m) = apply_meta(new, Some(version(&fixture_model())));

    // 1. Exec snapshots (blocking) before calling the handler.
    f.expect(NFT, &LIST_TABLE, out(MANAGED_JSON));
    let snap = module.snapshot(&c, &op).unwrap();
    assert_eq!(
        Snapshot::decode(&snap).unwrap(),
        Snapshot::Model(canonical(&fixture_model()))
    );
    // 2. The handler applies; the change is pending.
    f.expect(NFT, &LIST_TABLE, out(MANAGED_JSON));
    f.expect(NFT, &APPLY, out(""));
    assert!(matches!(
        run(&FirewallHandler, &c, &op, &m),
        Ok(Payload::ChangePending { .. })
    ));
    // 3. No confirmation: `fleet-agent revert <id>` restores by kind.
    f.expect(NFT, &APPLY, out(""));
    reverters.restore(&c, ChangeKind::Firewall, &snap).unwrap();
    let calls = f.calls();
    let last = calls.last().unwrap();
    assert_eq!(last.program, NFT);
    assert_eq!(last.args, ["-f", "-"]);
    let want = render(&fixture_model(), &[22]);
    assert_eq!(last.stdin.as_deref(), Some(want.as_bytes()));
    assert_eq!(
        Snapshot::decode(&snap).unwrap().script(&[22]).unwrap(),
        want,
        "restore = the snapshot's own script"
    );
    assert_ne!(calls[2].stdin, last.stdin, "the change differed");
    assert_eq!(f.pending(), 0);
}

#[test]
fn snapshot_absent_and_raw() {
    let f = Rc::new(FakeRunner::new());
    let c = ctx(nowhere(), f.clone());
    let r = FirewallRevert;
    let op = Op::FirewallGet;

    f.expect(NFT, &LIST_TABLE, absent());
    let snap = r.snapshot(&c, &op).unwrap();
    f.expect(NFT, &APPLY, out(""));
    r.restore(&c, &snap).unwrap();
    assert_eq!(
        f.calls().last().unwrap().stdin.as_deref(),
        Some(b"add table inet fleet\ndelete table inet fleet\n".as_slice())
    );

    let listing = "table inet fleet {\n\tchain input {\n\t\ttcp dport 3306 accept\n\t}\n}\n";
    f.expect(NFT, &LIST_TABLE, out(HAND_EDITED_JSON));
    f.expect(NFT, &["list", "table", "inet", "fleet"], out(listing));
    let snap = r.snapshot(&c, &op).unwrap();
    assert_eq!(
        Snapshot::decode(&snap).unwrap(),
        Snapshot::Raw(listing.into())
    );
    f.expect(NFT, &APPLY, out(""));
    r.restore(&c, &snap).unwrap();
    let want = format!("add table inet fleet\ndelete table inet fleet\n{listing}");
    assert_eq!(
        f.calls().last().unwrap().stdin.as_deref(),
        Some(want.as_bytes())
    );

    // A failed restore is reported (audited as a failed revert).
    f.expect(NFT, &APPLY, Ok(CommandOutput::exit(1)));
    assert!(r.restore(&c, &snap).is_err());
    assert!(r.restore(&c, b"\x09junk").is_err());
    // A failing listing aborts the op before anything is applied.
    f.expect(NFT, &LIST_TABLE, Err(RunError::Timeout));
    assert_eq!(r.snapshot(&c, &op).unwrap_err().code(), ErrorCode::Timeout);
}

#[test]
fn registered() {
    let r = crate::Registry::with_generic();
    assert!(r.get(&Op::FirewallGet).is_some());
    assert!(r.get(&Op::FirewallApply(managed(vec![]))).is_some());
}

// ---- properties ----

fn arb_comment() -> impl Strategy<Value = FwComment> {
    "[A-Za-z0-9 ._:/-]{0,64}".prop_map(|s| FwComment::new(s).unwrap())
}

fn arb_cidr() -> impl Strategy<Value = Cidr> {
    prop_oneof![
        (any::<u32>(), 0u8..=32).prop_map(|(a, l)| {
            let a = std::net::Ipv4Addr::from(if l == 0 {
                0
            } else {
                a & (u32::MAX << (32 - l))
            });
            Cidr::new(a.into(), l).unwrap()
        }),
        (any::<u128>(), 0u8..=128).prop_map(|(a, l)| {
            let a = std::net::Ipv6Addr::from(if l == 0 {
                0
            } else {
                a & (u128::MAX << (128 - l))
            });
            Cidr::new(a.into(), l).unwrap()
        }),
    ]
}

fn arb_rule() -> impl Strategy<Value = FirewallRule> {
    (
        prop_oneof![Just(FwChain::Input), Just(FwChain::Forward)],
        prop_oneof![
            Just(FwAction::Accept),
            Just(FwAction::Drop),
            Just(FwAction::Reject)
        ],
        prop_oneof![Just(Protocol::Tcp), Just(Protocol::Udp)],
        prop::collection::vec((1u16..=65535, 0u16..50), 1..=16),
        prop::option::of(arb_cidr()),
        prop::option::of((1u32..=100_000, any::<u16>())),
        arb_comment(),
    )
        .prop_map(
            |(chain, action, proto, ports, source, rl, comment)| FirewallRule {
                chain,
                action,
                proto,
                ports: ports
                    .into_iter()
                    .map(|(s, w)| pr(s, s.saturating_add(w)))
                    .collect(),
                source,
                rate_limit: rl
                    .filter(|_| action == FwAction::Accept)
                    .map(|(per_minute, burst)| RateLimit { per_minute, burst }),
                comment,
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Rendering never panics; the only quoted strings are `"lo"` and
    /// comments of the form `base` / `r<i>[ <FwComment>]`; nothing names
    /// another table or flushes.
    #[test]
    fn render_is_safe(
        managed_mode in any::<bool>(),
        rules in prop::collection::vec(arb_rule(), 0..24),
        ssh in prop::collection::vec(1u16..=65535, 0..4),
    ) {
        let set = FirewallRuleSet {
            mode: if managed_mode { FirewallMode::Managed } else { FirewallMode::BansOnly },
            rules: if managed_mode { rules } else { vec![] },
        };
        let s = render(&set, &ssh);
        prop_assert!(!s.contains("flush"));
        for line in s.lines() {
            prop_assert_eq!(line.matches('"').count() % 2, 0);
            let mut parts = line.split('"');
            parts.next();
            while let Some(quoted) = parts.next() {
                let ok = quoted == "lo"
                    || quoted == "base"
                    || super::parse::parse_comment(quoted)
                        .is_some_and(|(_, t)| FwComment::new(t).is_ok());
                prop_assert!(ok, "quoted {:?}", quoted);
                parts.next();
            }
            let unquoted: String = line.split('"').step_by(2).collect();
            prop_assert!(!unquoted.contains(';') || unquoted.contains("type ") || unquoted.contains("flags "), "{}", line);
            if line.starts_with("add ") || line.starts_with("delete ") || line.starts_with("table ") {
                prop_assert!(line.contains(" inet fleet"));
            }
        }
    }

    /// Canonical form is a fixed point and keeps the version.
    #[test]
    fn canonical_is_idempotent(rules in prop::collection::vec(arb_rule(), 0..8)) {
        let set = managed(rules);
        let c = canonical(&set);
        prop_assert_eq!(canonical(&c), c.clone());
        prop_assert_eq!(version(&c), version(&set));
    }

    /// Server output never panics the parsers.
    #[test]
    fn parsers_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..512), s in ".{0,300}") {
        let _ = parse_table(&bytes);
        let _ = summarize_ruleset(&bytes);
        let _ = parse_ufw(&s);
        let _ = parse_sshd_ports(&s);
    }
}
