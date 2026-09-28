//! sshd journal messages (`parse_sshd`, per line) and sshd config /
//! `sshd -T` parsers used by the firewall and hardening.
#![no_main]

#[path = "common.rs"]
mod common;

use fleet_ops::firewall::model::{SshdConfig, parse_sshd_config, parse_sshd_ports};
use fleet_ops::security::authlog::parse_sshd;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let t = common::text(data);
    for line in t.lines() {
        let _ = parse_sshd(line);
    }
    let _ = parse_sshd(&t);
    let _ = parse_sshd_ports(&t);
    let mut cfg = SshdConfig::default();
    let _ = parse_sshd_config(&t, &mut cfg, &mut |_| Ok(()));
    let _ = fleet_hardening::facts::parse_sshd_t(&t);
});
