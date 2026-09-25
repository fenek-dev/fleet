use super::super::*;
use super::{MIN, ip};
use fleet_proto::payload::BanReason;

const DAY: u64 = 86_400_000;

#[test]
fn threshold_window_and_escalation() {
    let mut e = BanEngine::new(default_config());
    let a = ip("198.51.100.7");
    let mut t = 1_000_000_000;
    // 4 failures, then a gap longer than the window: no ban.
    for _ in 0..4 {
        assert!(e.observe(a, BanReason::SshBruteForce, t).is_none());
        t += MIN;
    }
    t += 11 * MIN;
    for i in 0..4 {
        assert!(e.observe(a, BanReason::SshBruteForce, t + i).is_none());
    }
    let d = e.observe(a, BanReason::SshBruteForce, t + 5).unwrap();
    assert_eq!((d.duration_s, d.strikes, d.replace), (3_600, 1, false));
    assert_eq!(
        d.key,
        BanKey {
            addr: a,
            prefix: 32
        }
    );
    // While banned, more failures change nothing.
    assert!(e.observe(a, BanReason::SshBruteForce, t + 6).is_none());
    let mut offence = |at: u64| {
        (0..5)
            .find_map(|i| e.observe(a, BanReason::SshBruteForce, at + i))
            .unwrap()
    };
    t += 2 * 3_600_000;
    assert_eq!(offence(t).duration_s, 86_400);
    t += 2 * DAY;
    assert_eq!(offence(t).duration_s, 7 * 86_400);
    t += 8 * DAY;
    assert_eq!(offence(t).duration_s, 7 * 86_400); // last step repeats
    t += 60 * DAY;
    let d = offence(t);
    assert_eq!((d.duration_s, d.strikes), (3_600, 1)); // forgiven after 30 days
}

#[test]
fn ipv6_slash64_and_exemptions() {
    let mut cfg = default_config();
    cfg.threshold = 2;
    cfg.exempt = vec![Cidr::new(ip("10.0.0.0"), 8).unwrap()];
    let mut e = BanEngine::new(cfg);
    let now = 5 * DAY;
    // Two different hosts in one /64 add up.
    assert!(
        e.observe(ip("2001:db8:1:2::1"), BanReason::SshBruteForce, now)
            .is_none()
    );
    let d = e
        .observe(ip("2001:db8:1:2:ffff::9"), BanReason::SshBruteForce, now)
        .unwrap();
    assert_eq!(
        d.key,
        BanKey {
            addr: ip("2001:db8:1:2::"),
            prefix: 64
        }
    );
    assert_eq!(
        ban_args(&d).join(" "),
        "add element inet fleet banned6 { 2001:db8:1:2::/64 timeout 3600s }"
    );
    for x in ["10.1.2.3", "127.0.0.1", "::1", "::ffff:10.9.9.9"] {
        for _ in 0..5 {
            assert!(
                e.observe(ip(x), BanReason::SshBruteForce, now).is_none(),
                "{x}"
            );
        }
    }
    // Learned Mac: exempt for 7 days after the last login.
    let mac = ip("203.0.113.50");
    assert_eq!(e.learn(mac, now), Some(false));
    assert_eq!(e.learn(mac, now + 1), Some(true));
    // Inside a configured range: no element, but remembered.
    assert_eq!(e.learn(ip("10.3.3.3"), now), None);
    assert!(e.is_exempt(mac, now + LEARNED_TTL_MS));
    assert!(!e.is_exempt(mac, now + 1 + LEARNED_TTL_MS));
    assert_eq!(e.snapshot(now).learned_exempt, [ip("10.3.3.3"), mac]);
    assert!(e.manual(mac, 3_600, now).is_err());
    assert!(e.manual(ip("192.0.2.1"), 59, now).is_err());
    // Web scanners can be turned off.
    let mut c = e.config().clone();
    c.web_scanners = false;
    e.set_config(c);
    for _ in 0..5 {
        assert!(
            e.observe(ip("192.0.2.9"), BanReason::WebScanner, now)
                .is_none()
        );
    }
}

#[test]
fn ipv6_mac_learned_as_slash64() {
    let mut cfg = default_config();
    cfg.threshold = 1;
    let mut e = BanEngine::new(cfg);
    let now = 5 * DAY;
    assert_eq!(e.learn(ip("2001:db8:1:2::5"), now), Some(false));
    // A rotated privacy address in the same /64 refreshes the same key.
    assert_eq!(e.learn(ip("2001:db8:1:2:aaaa::7"), now), Some(true));
    assert_eq!(e.snapshot(now).learned_exempt, [ip("2001:db8:1:2::")]);
    // Failures from the Mac's /64 are not even counted; other /64s are.
    for (src, banned) in [
        ("2001:db8:1:2::5", false),
        ("2001:db8:1:2:ffff::1", false),
        ("2001:db8:1:3::1", true),
    ] {
        let d = e.observe(ip(src), BanReason::SshBruteForce, now);
        assert_eq!(d.is_some(), banned, "{src}");
    }
    assert_eq!(
        learned_args(ip("2001:db8:1:2::5"), false).join(" "),
        "add element inet fleet exempt6 { 2001:db8:1:2::/64 timeout 604800s }"
    );
}

#[test]
fn exempt_ranges_must_not_overlap() {
    for (ranges, ok) in [
        (&["10.0.0.0/8", "192.168.0.0/16"][..], true),
        (&["10.0.0.0/8", "2001:db8::/32"], true),
        (&["10.0.0.0/8", "10.0.0.0/8"], false),
        (&["10.0.0.0/8", "10.1.0.0/16"], false),
        (&["10.1.0.0/16", "10.0.0.0/8"], false),
        (&["2001:db8::/32", "2001:db8:1::/48"], false),
        (&["203.0.113.5/32", "203.0.113.6/32"], true),
    ] {
        let v: Vec<Cidr> = ranges.iter().map(|s| super::cidr(s)).collect();
        assert_eq!(validate_exempt(&v).is_ok(), ok, "{ranges:?}");
    }
}

#[test]
fn nft_argv_shapes() {
    let d = Decision {
        key: ban_key(ip("192.0.2.1")),
        duration_s: 60,
        until_ms: 0,
        reason: BanReason::Manual,
        strikes: 0,
        replace: true,
    };
    assert_eq!(
        ban_args(&d).join(" "),
        "delete element inet fleet banned4 { 192.0.2.1 } ; add element inet fleet banned4 { 192.0.2.1 timeout 60s }"
    );
    assert_eq!(
        unban_args(&d.key).join(" "),
        "delete element inet fleet banned4 { 192.0.2.1 }"
    );
    assert_eq!(
        exempt_args(&Cidr::new(ip("10.0.0.0"), 8).unwrap(), true).join(" "),
        "add element inet fleet exempt4 { 10.0.0.0/8 }"
    );
    assert_eq!(
        learned_args(ip("::ffff:203.0.113.5"), false).join(" "),
        "add element inet fleet exempt4 { 203.0.113.5 timeout 604800s }"
    );
}

#[test]
fn export_import_round_trip_and_revalidation() {
    let t = 1_000_000_000;
    let mut e = BanEngine::new(default_config());
    let a = ip("198.51.100.7");
    let r0 = e.revision();
    let d = (0..5)
        .find_map(|i| e.observe(a, BanReason::SshBruteForce, t + i))
        .unwrap();
    assert!(e.revision() > r0);
    e.learn(ip("203.0.113.9"), t).unwrap();
    let st = e.export(t + 10);
    assert_eq!(st.bans.len(), 1);
    assert_eq!(st.strikes, vec![(a, 32, 1, d.until_ms - 3_600_000)]);
    let back: BanState = fleet_proto::decode(&fleet_proto::encode(&st)).unwrap();

    let mut f = BanEngine::new(default_config());
    f.import(back.clone(), t + 10);
    assert_eq!(f.export(t + 10), st);
    // The strike survived: the next offence escalates to 24 h.
    let later = t + 2 * 3_600_000;
    let d2 = (0..5)
        .find_map(|i| f.observe(a, BanReason::SshBruteForce, later + i))
        .unwrap();
    assert_eq!(d2.duration_s, 86_400);
    assert!(f.is_exempt(ip("203.0.113.9"), later));

    // Expired and non-canonical entries are dropped on import.
    let mut bad = back;
    bad.bans[0].prefix = 24;
    bad.strikes.push((ip("127.0.0.1"), 32, 3, t));
    bad.learned.push((ip("::ffff:192.0.2.1"), t));
    bad.learned.push((ip("2001:db8::5"), t)); // not a /64 key
    bad.config.threshold = 0;
    let mut g = BanEngine::new(default_config());
    g.import(bad, t + 10);
    let st = g.export(t + 10);
    assert!(st.bans.is_empty());
    assert_eq!(st.strikes.len(), 1);
    assert_eq!(st.learned, vec![(ip("203.0.113.9"), t)]);
    assert_eq!(st.config, default_config());
    let mut h = BanEngine::new(default_config());
    h.import(f.export(t), t + 8 * 86_400_000);
    assert!(h.export(t + 8 * 86_400_000).learned.is_empty());
    // Overlapping exempt ranges in a stored config are refused too.
    let mut ov = f.export(t);
    ov.config.exempt = vec![super::cidr("10.0.0.0/8"), super::cidr("10.1.0.0/16")];
    h.import(ov, t);
    assert!(h.config().exempt.is_empty());
}

#[test]
fn nft_set_listing() {
    let empty = r#"{"nftables":[{"metainfo":{"version":"1.0.6"}},{"set":{"family":"inet","name":"banned4","table":"fleet","type":"ipv4_addr","handle":3,"flags":["interval","timeout"]}}]}"#;
    let full = r#"{"nftables":[{"metainfo":{}},{"set":{"name":"banned4","elem":[{"elem":{"val":"198.51.100.7","timeout":3600,"expires":3500}}]}}]}"#;
    assert_eq!(nft_set_is_empty(empty), Some(true));
    assert_eq!(nft_set_is_empty(full), Some(false));
    assert_eq!(nft_set_is_empty("{}"), None);
    assert_eq!(nft_set_is_empty("garbage"), None);
}
