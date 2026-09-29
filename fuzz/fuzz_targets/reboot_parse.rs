//! `systemctl show fleet-reboot.timer` output and `date +%H:%M:%S`
//! (`system.reboot.status` / `.schedule`), both server output.
#![no_main]

#[path = "common.rs"]
mod common;

use fleet_ops::reboot::{parse_local_seconds, parse_status};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = common::text(data);
    let _ = parse_status(&text);
    if let Some(s) = parse_local_seconds(&text) {
        assert!(s <= 86_400);
    }
});
