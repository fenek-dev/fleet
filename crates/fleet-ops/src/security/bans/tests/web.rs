use super::super::*;
use super::{a, ip, service};
use crate::CommandOutput;
use crate::security::webscan::AccessHit;
use crate::testutil::{T0, block};
use fleet_proto::payload::BanReason;
use std::path::Path;

const LOG: &str = "/var/log/caddy/access.log";

fn probe(src: &str) -> AccessHit {
    AccessHit {
        ip: ip(src),
        path: "/.env".into(),
        status: 404,
    }
}

#[test]
fn web_bans_config_only_tailed_paths() {
    let tailed = vec![LOG.to_owned(), "/var/log/nginx/access.log".to_owned()];
    let text = format!(
        "# opt in\n{LOG} 600\n/var/log/nginx/access.log\n/etc/shadow\n{LOG} 99\n\
         /var/log/nginx/access.log x\n/var/log/nginx/access.log 1 2\n"
    );
    let v = parse_web_bans(&text, &tailed);
    assert_eq!(
        v,
        vec![
            WebBanSource::new(LOG, 600),
            WebBanSource::new("/var/log/nginx/access.log", DEFAULT_WEB_MAX_STEP_S)
        ]
    );
    assert!(parse_web_bans("", &tailed).is_empty());
}

#[test]
fn internal_ranges() {
    for (s, internal) in [
        ("10.1.2.3", true),
        ("172.16.0.1", true),
        ("172.31.255.255", true),
        ("172.32.0.1", false),
        ("192.168.1.1", true),
        ("100.64.0.1", true),
        ("100.127.255.255", true),
        ("100.128.0.1", false),
        ("169.254.1.1", true),
        ("::ffff:10.0.0.1", true),
        ("fc00::1", true),
        ("fd12:3456::1", true),
        ("fe80::1", true),
        ("febf::1", true),
        ("fec0::1", false),
        ("198.51.100.4", false),
        ("2001:db8::1", false),
    ] {
        assert_eq!(is_internal(ip(s)), internal, "{s}");
    }
}

#[test]
fn web_bans_opt_in_capped_and_never_internal() {
    let mut cfg = default_config();
    cfg.threshold = 1;
    cfg.ban_steps_s = vec![7 * 86_400];
    let (svc, runner, _sink, c, _dir) = service(cfg);
    svc.set_web_sources(vec![WebBanSource::new(LOG, 3_600)]);
    svc.set_own_addrs([ip("203.0.113.1"), ip("2001:db8:5:6::1")]);
    let log = Path::new(LOG);
    // (log path, client, banned) — no nft call unless banned.
    for (path, src, banned) in [
        ("/var/log/nginx/access.log", "198.51.100.4", false),
        (LOG, "10.0.0.1", false),
        (LOG, "100.64.3.3", false),
        (LOG, "fd00::1", false),
        (LOG, "fe80::1", false),
        (LOG, "169.254.9.9", false),
        (LOG, "203.0.113.1", false),
        (LOG, "2001:db8:5:6::99", false), // the host's own /64
        (LOG, "198.51.100.4", true),
    ] {
        if banned {
            let d = Decision {
                key: ban_key(ip(src)),
                duration_s: 3_600, // capped from 7 days
                until_ms: 0,
                reason: BanReason::WebScanner,
                strikes: 1,
                replace: false,
            };
            runner.expect(NFT, &a(&ban_args(&d)), Ok(CommandOutput::ok("")));
        }
        let got = block(svc.observe_access_from(&c, Path::new(path), &probe(src), T0)).unwrap();
        assert_eq!(got.is_some(), banned, "{path} {src}");
    }
    assert_eq!(runner.pending(), 0);
    // The unnamed-log entry point never bans.
    let got = block(svc.observe_access(&c, &probe("198.51.100.5"), T0)).unwrap();
    assert!(got.is_none());
    assert_eq!(runner.calls().len(), 1);
    // Cap is clamped to the allowed step range.
    assert_eq!(WebBanSource::new(log, 1).max_step_s, 60);
}
