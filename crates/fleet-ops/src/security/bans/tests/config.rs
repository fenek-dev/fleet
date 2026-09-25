//! `bans.config.set` against the kernel: learned elements move out of the
//! way of new ranges and come back when ranges go; failures roll back.

use super::super::*;
use super::{a, cidr, ip, service};
use crate::CommandOutput;
use crate::testutil::{T0, block};

const TTL_S: u64 = LEARNED_TTL_MS / 1000;

#[test]
fn config_set_moves_learned_elements_and_rolls_back() {
    let (svc, runner, _sink, c, _dir) = service(default_config());
    let mac4 = ip("203.0.113.50");
    let mac6 = ip("2001:db8:1:2::5");
    for m in [mac4, mac6] {
        runner.expect(NFT, &a(&learned_args(m, false)), Ok(CommandOutput::ok("")));
        block(svc.fleet_login(&c, m, T0)).unwrap();
    }
    let k4 = learned_key(mac4);
    let k6 = learned_key(mac6);
    let with = |ranges: &[&str]| {
        let mut cfg = default_config();
        cfg.exempt = ranges.iter().map(|s| cidr(s)).collect();
        cfg
    };
    let del_learned = |k: &BanKey| a(&nft::unlearn_args(k)).join(" ");
    let add_learned = |k: &BanKey| a(&nft::learned_key_args(k, TTL_S, false)).join(" ");
    let ok = || Ok(CommandOutput::ok(""));

    // (new ranges, expected argv in order with success, committed)
    type Case = (BanConfig, Vec<(String, bool)>, bool);
    let cases: Vec<Case> = vec![
        // A range covering the IPv4 Mac: its element goes first.
        (
            with(&["203.0.113.0/24"]),
            vec![
                (del_learned(&k4), true),
                (exempt_args(&cidr("203.0.113.0/24"), true).join(" "), true),
            ],
            true,
        ),
        // Range removed: the Mac's element comes back.
        (
            with(&[]),
            vec![
                (exempt_args(&cidr("203.0.113.0/24"), false).join(" "), true),
                (add_learned(&k4), true),
            ],
            true,
        ),
        // Second add fails: everything done is undone, in reverse.
        (
            with(&["203.0.113.0/24", "2001:db8::/32"]),
            vec![
                (del_learned(&k4), true),
                (del_learned(&k6), true),
                (exempt_args(&cidr("203.0.113.0/24"), true).join(" "), true),
                (exempt_args(&cidr("2001:db8::/32"), true).join(" "), false),
                (exempt_args(&cidr("203.0.113.0/24"), false).join(" "), true),
                (add_learned(&k6), true),
                (add_learned(&k4), true),
            ],
            false,
        ),
    ];
    for (cfg, steps, committed) in cases {
        for (argv, success) in &steps {
            let v: Vec<&str> = argv.split(' ').collect();
            let reply = if *success {
                ok()
            } else {
                Ok(CommandOutput::exit(1))
            };
            runner.expect(NFT, &v, reply);
        }
        let before = svc.engine.borrow().config().clone();
        let res = block(svc.set_config(&c, cfg.clone(), T0));
        assert_eq!(res.is_ok(), committed, "{cfg:?}");
        let now_cfg = svc.engine.borrow().config().clone();
        assert_eq!(now_cfg, if committed { cfg } else { before });
        assert_eq!(runner.pending(), 0);
        // The Macs stay learned throughout.
        assert_eq!(svc.snapshot(T0).learned_exempt, [k4.addr, k6.addr]);
    }
    // Overlapping ranges never reach the kernel.
    assert!(block(svc.set_config(&c, with(&["10.0.0.0/8", "10.0.0.0/8"]), T0)).is_err());
    assert_eq!(runner.calls().len(), 2 + 2 + 2 + 7);
}

#[test]
fn learning_inside_a_range_adds_no_element() {
    let mut cfg = default_config();
    cfg.exempt = vec![cidr("2001:db8:1:2::/80")];
    let (svc, runner, _sink, c, _dir) = service(cfg);
    // The /64 overlaps the configured /80: no element, still exempt.
    block(svc.fleet_login(&c, ip("2001:db8:1:2:ffff::1"), T0)).unwrap();
    assert!(runner.calls().is_empty());
    assert_eq!(svc.snapshot(T0).learned_exempt, [ip("2001:db8:1:2::")]);
}
