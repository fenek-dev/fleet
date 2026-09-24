use super::model::{self, canonical, canonical_ports, check, parse_sshd_ports, version};
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
    assert_eq!(check(&fixture_model(), &[22]), Ok(()));
    // No SSH rule at all.
    let web = named(rule(Input, Accept, Protocol::Tcp, vec![p(80)]), "web");
    assert!(check(&managed(vec![web.clone()]), &[22]).is_err());
    // SSH on another port than sshd listens on.
    assert!(check(&managed(vec![ssh()]), &[2222]).is_err());
    assert_eq!(check(&managed(vec![ssh()]), &[22, 2222]), Ok(()));
    // Source-restricted SSH is fine (exempt sets and auto-revert cover it).
    let office = from(ssh(), "203.0.113.0/24");
    assert_eq!(check(&managed(vec![office]), &[22]), Ok(()));
    // Blanket drop of SSH.
    let block = rule(Input, Drop, Protocol::Tcp, vec![pr(1, 1024)]);
    assert!(check(&managed(vec![block.clone(), ssh()]), &[22]).is_err());
    assert_eq!(
        check(&managed(vec![from(block, "192.0.2.0/24"), ssh()]), &[22]),
        Ok(())
    );
    // UDP 22 is not SSH.
    let udp = rule(Input, Accept, Protocol::Udp, vec![p(22)]);
    assert!(check(&managed(vec![udp]), &[22]).is_err());
    // Rate limits only on accept rules; bounded meter count.
    let bad = limited(rule(Input, Drop, Protocol::Tcp, vec![p(25)]), 5, 0);
    assert!(check(&managed(vec![ssh(), bad]), &[22]).is_err());
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
    assert!(check(&managed(many), &[22]).is_err());
    // Bans-only needs no SSH rule, but can't carry rules.
    let bo = FirewallRuleSet {
        mode: FirewallMode::BansOnly,
        rules: vec![],
    };
    assert_eq!(check(&bo, &[22]), Ok(()));
    assert!(
        check(
            &FirewallRuleSet {
                rules: vec![web],
                ..bo
            },
            &[22]
        )
        .is_err()
    );
}

#[test]
fn sshd_ports() {
    let text = "# Port 99\nPort 2222\nport=2200\nListenAddress 0.0.0.0\nPort 0\nPort x\nMatch User git\nPort 3333\n";
    assert_eq!(parse_sshd_ports(text), vec![2222, 2200]);

    let dir = tempfile::tempdir().unwrap();
    let c = ctx(dir.path(), Rc::new(FakeRunner::new()));
    assert_eq!(model::ssh_ports(&c), vec![22]);
    std::fs::create_dir_all(dir.path().join("etc/ssh/sshd_config.d")).unwrap();
    std::fs::write(
        dir.path().join("etc/ssh/sshd_config"),
        "Include /etc/ssh/sshd_config.d/*.conf\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("etc/ssh/sshd_config.d/10-fleet.conf"),
        "Port 2222\nPort 22\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("etc/ssh/sshd_config.d/x.disabled"),
        "Port 1\n",
    )
    .unwrap();
    assert_eq!(model::ssh_ports(&c), vec![22, 2222]);
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
    let Payload::ChangePending(p) = run(&FirewallHandler, &c, &op, &m).unwrap() else {
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
    let new = managed(vec![from(ssh(), "192.0.2.0/24")]);
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
        Ok(Payload::ChangePending(_))
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
        Snapshot::decode(&snap).unwrap().script(&[22]),
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
