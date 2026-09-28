//! sudoers parser used by the escalation audit.
#![no_main]

#[path = "common.rs"]
mod common;

use fleet_ops::escalation::{SudoersGrants, parse_sudoers};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut g = SudoersGrants::default();
    let _ = parse_sudoers(&common::text(data), &mut g);
});
