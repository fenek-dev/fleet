//! Operator custom profile TOML (fleet-hardening `parse_custom`) and the
//! reboot-window syntax it embeds.
#![no_main]

#[path = "common.rs"]
mod common;

use fleet_hardening::profile::{RebootWindow, parse_custom};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let t = common::text(data);
    let _ = parse_custom(&t);
    let _ = RebootWindow::parse(&t);
});
