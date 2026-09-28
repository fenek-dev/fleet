use super::super::*;
use super::{a, ip, service, service_with_gate};
use std::cell::Cell;
use std::rc::Rc;
use crate::CommandOutput;
use crate::handler::{OpHandler, OpOutput, Registry};
use crate::security::authlog::parse_sshd;
use crate::testutil::{T0, block, meta_at};
use fleet_proto::args::Label;
use fleet_proto::payload::{BanEntry, BanReason};
use fleet_proto::{ErrorCode, Op, Payload};

#[test]
fn service_and_handlers() {
    let mut cfg = default_config();
    cfg.threshold = 2;
    let (svc, runner, sink, c, _dir) = service(cfg);
    let now = T0;

    // Detector path: two failures → nft add → event.
    let ev = parse_sshd("Failed password for root from 198.51.100.7 port 1 ssh2").unwrap();
    let d0 = Decision {
        key: ban_key(ip("198.51.100.7")),
        duration_s: 3_600,
        until_ms: 0,
        reason: BanReason::SshBruteForce,
        strikes: 1,
        replace: false,
    };
    runner.expect(NFT, &a(&ban_args(&d0)), Ok(CommandOutput::ok("")));
    assert!(block(svc.observe_auth(&c, &ev, now)).unwrap().is_none());
    let d = block(svc.observe_auth(&c, &ev, now)).unwrap().unwrap();
    assert_eq!(d.until_ms, now + 3_600_000);
    assert_eq!(sink.take().len(), 1);

    // nft failure rolls the ban back.
    let ev2 = parse_sshd("Invalid user x from 198.51.100.8 port 1").unwrap();
    let d1 = Decision {
        key: ban_key(ip("198.51.100.8")),
        ..d0
    };
    runner.expect(NFT, &a(&ban_args(&d1)), Ok(CommandOutput::exit(1)));
    assert!(block(svc.observe_auth(&c, &ev2, now)).unwrap().is_none());
    assert!(block(svc.observe_auth(&c, &ev2, now)).is_err());
    assert_eq!(svc.snapshot(now).bans.len(), 1);
    assert!(sink.take().is_empty());

    // Learned Mac via the trait.
    runner.expect(
        NFT,
        &a(&learned_args(ip("203.0.113.50"), false)),
        Ok(CommandOutput::ok("")),
    );
    block(svc.fleet_login(&c, ip("203.0.113.50"), now)).unwrap();

    let h = BansHandler(svc.clone());
    let m = meta_at(Op::SystemInfo, Some(1), T0);
    let add = Op::BansAdd {
        addr: ip("203.0.113.50"),
        duration_s: 600,
        comment: Label::new("").unwrap(),
    };
    assert_eq!(
        h.validate(&c, &add, &m).unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
    let add = Op::BansAdd {
        addr: ip("192.0.2.77"),
        duration_s: 600,
        comment: Label::new("by hand").unwrap(),
    };
    h.validate(&c, &add, &m).unwrap();
    let dm = Decision {
        key: ban_key(ip("192.0.2.77")),
        duration_s: 600,
        until_ms: 0,
        reason: BanReason::Manual,
        strikes: 0,
        replace: false,
    };
    runner.expect(NFT, &a(&ban_args(&dm)), Ok(CommandOutput::ok("")));
    let OpOutput::Payload(Payload::Bans(b)) = block(h.handle(&c, &add, &m)).unwrap() else {
        panic!()
    };
    assert_eq!(b.bans.len(), 2);
    assert_eq!(b.learned_exempt, [ip("203.0.113.50")]);

    let rm = Op::BansRemove {
        addr: ip("192.0.2.77"),
    };
    runner.expect(NFT, &a(&unban_args(&dm.key)), Ok(CommandOutput::ok("")));
    let OpOutput::Payload(Payload::Bans(b)) = block(h.handle(&c, &rm, &m)).unwrap() else {
        panic!()
    };
    assert_eq!(b.bans.len(), 1);
    // Unknown and not in the kernel either.
    runner.expect(NFT, &a(&unban_args(&dm.key)), Ok(CommandOutput::exit(1)));
    assert_eq!(
        block(h.handle(&c, &rm, &m)).unwrap_err().code(),
        ErrorCode::NotFound
    );

    // Config round trip with exempt-set sync.
    let mut cfg = default_config();
    cfg.exempt = vec![Cidr::new(ip("10.0.0.0"), 8).unwrap()];
    let set = Op::BansConfigSet(cfg.clone());
    h.validate(&c, &set, &m).unwrap();
    runner.expect(
        NFT,
        &a(&exempt_args(&cfg.exempt[0], true)),
        Ok(CommandOutput::ok("")),
    );
    block(h.handle(&c, &set, &m)).unwrap();
    let OpOutput::Payload(Payload::BanConfig(got)) =
        block(h.handle(&c, &Op::BansConfigGet, &m)).unwrap()
    else {
        panic!()
    };
    assert_eq!(got, cfg);
    let mut bad = cfg.clone();
    bad.threshold = 0;
    assert!(h.validate(&c, &Op::BansConfigSet(bad), &m).is_err());
    let mut dup = cfg;
    dup.exempt.push(super::cidr("10.2.0.0/16"));
    assert_eq!(
        h.validate(&c, &Op::BansConfigSet(dup), &m)
            .unwrap_err()
            .code(),
        ErrorCode::InvalidArgument
    );
    assert_eq!(runner.pending(), 0);
    let mut r = Registry::new();
    svc.register(&mut r);
    assert_eq!(r.tags().count(), 5);
}

#[test]
fn failed_first_learn_is_forgotten() {
    let (svc, runner, _sink, c, _dir) = service(default_config());
    let mac = ip("203.0.113.50");
    // Add fails → not remembered; the retry adds again (no delete of a
    // missing element); a later login replaces the element.
    for (replace, ok) in [(false, false), (false, true), (true, true)] {
        let reply = if ok {
            CommandOutput::ok("")
        } else {
            CommandOutput::exit(1)
        };
        runner.expect(NFT, &a(&learned_args(mac, replace)), Ok(reply));
        assert_eq!(block(svc.fleet_login(&c, mac, T0)).is_ok(), ok);
    }
    assert_eq!(runner.pending(), 0);
    assert_eq!(svc.snapshot(T0).learned_exempt, [mac]);
}

#[test]
fn restore_kernel_only_fills_empty_sets() {
    let (svc, runner, _sink, c, _dir) = service(default_config());
    let now = T0;
    let mut st = svc.export(now);
    st.bans.push(BanEntry {
        addr: ip("198.51.100.7"),
        prefix: 32,
        until_ms: now + 1_800_000,
        reason: BanReason::SshBruteForce,
        strikes: 1,
    });
    st.learned.push((ip("203.0.113.9"), now));
    st.learned.push((ip("2001:db8:1:2::"), now));
    svc.import(st, now);
    let list = |set: &'static str| ["-j", "list", "set", "inet", "fleet", set];
    let empty = r#"{"nftables":[{"set":{"name":"x"}}]}"#;
    let full = r#"{"nftables":[{"set":{"name":"x","elem":[1]}}]}"#;
    runner.expect(NFT, &list("banned4"), Ok(CommandOutput::ok(empty)));
    runner.expect(
        NFT,
        &a(&nft_add_args("banned4", "198.51.100.7", Some(1_800), false)),
        Ok(CommandOutput::ok("")),
    );
    // The kernel kept its exemptions: nothing re-added there.
    runner.expect(NFT, &list("exempt4"), Ok(CommandOutput::ok(full)));
    runner.expect(NFT, &list("banned6"), Ok(CommandOutput::exit(1)));
    runner.expect(NFT, &list("exempt6"), Ok(CommandOutput::ok(empty)));
    runner.expect(
        NFT,
        &a(&learned_args(ip("2001:db8:1:2::1"), false)),
        Ok(CommandOutput::ok("")),
    );
    assert_eq!(block(svc.restore_kernel(&c, now)), 2);
    assert_eq!(runner.pending(), 0);
}

/// Design §5.4: the gate is checked right before each kernel write, not
/// once for the whole call — the ban decision runs (the engine records the
/// offence), but a gate that goes false stops the actual nft write, and
/// the ban is forgotten again (as if nft itself had failed).
#[test]
fn gate_false_blocks_the_ban_write_after_the_decision() {
    let mut cfg = default_config();
    cfg.threshold = 1;
    let (svc, runner, sink, c, _dir) =
        service_with_gate(cfg, Rc::new(|| false) as Rc<dyn Fn() -> bool>);
    let ev = parse_sshd("Failed password for root from 198.51.100.7 port 1 ssh2").unwrap();
    let r = block(svc.observe_auth(&c, &ev, T0));
    assert!(r.is_err(), "{r:?}");
    assert!(runner.calls().is_empty(), "no nft call should be attempted");
    assert!(svc.snapshot(T0).bans.is_empty(), "the ban must be forgotten");
    assert!(sink.take().is_empty());
}

/// Same, for the learned-Mac-exemption write.
#[test]
fn gate_false_blocks_the_fleet_login_write() {
    let (svc, runner, _sink, c, _dir) =
        service_with_gate(default_config(), Rc::new(|| false) as Rc<dyn Fn() -> bool>);
    let r = block(svc.fleet_login(&c, ip("203.0.113.50"), T0));
    assert!(r.is_err(), "{r:?}");
    assert!(runner.calls().is_empty(), "no nft call should be attempted");
}

/// Design §5.4: `restore_kernel` rechecks the gate before *each* write, not
/// once for the whole restore — a gate that flips false after the first
/// write stops the second one, even mid-loop.
#[test]
fn gate_checked_before_each_restore_kernel_write() {
    let allowed = Rc::new(Cell::new(1u32));
    let g = allowed.clone();
    let gate: Rc<dyn Fn() -> bool> = Rc::new(move || {
        let n = g.get();
        let ok = n > 0;
        g.set(n.saturating_sub(1));
        ok
    });
    let (svc, runner, _sink, c, _dir) = service_with_gate(default_config(), gate);
    let now = T0;
    let mut st = svc.export(now);
    for addr in ["198.51.100.7", "198.51.100.8"] {
        st.bans.push(BanEntry {
            addr: ip(addr),
            prefix: 32,
            until_ms: now + 1_800_000,
            reason: BanReason::SshBruteForce,
            strikes: 1,
        });
    }
    svc.import(st, now);
    let list = |set: &'static str| ["-j", "list", "set", "inet", "fleet", set];
    let empty = r#"{"nftables":[{"set":{"name":"x"}}]}"#;
    runner.expect(NFT, &list("banned4"), Ok(CommandOutput::ok(empty)));
    runner.expect(
        NFT,
        &a(&nft_add_args("banned4", "198.51.100.7", Some(1_800), false)),
        Ok(CommandOutput::ok("")),
    );
    // No expectation for the second address's add: the gate must block it
    // before `run_nft` is ever called.
    runner.expect(NFT, &list("exempt4"), Ok(CommandOutput::ok(empty)));
    runner.expect(NFT, &list("banned6"), Ok(CommandOutput::ok(empty)));
    runner.expect(NFT, &list("exempt6"), Ok(CommandOutput::ok(empty)));
    let added = block(svc.restore_kernel(&c, now));
    assert_eq!(added, 1, "only the first write went through");
    assert_eq!(runner.pending(), 0);
    // Exactly the 5 expected calls: no unexpected second `add` landed.
    assert_eq!(runner.calls().len(), 5, "{:?}", runner.calls());
}
