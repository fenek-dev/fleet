//! crontab (user and system format) and systemd timer listings.
#![no_main]

#[path = "common.rs"]
mod common;

use fleet_ops::cron::parse::parse_crontab;
use fleet_ops::cron::timers::{parse_list_timers, parse_list_units, parse_show};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let t = common::text(data);
    let _ = parse_crontab(&t, false);
    let _ = parse_crontab(&t, true);
    let _ = parse_list_timers(data);
    let _ = parse_list_units(&t);
    let _ = parse_show(&t);
});
