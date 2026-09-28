//! `apt-get -s` simulation output.
#![no_main]

#[path = "common.rs"]
mod common;

use fleet_ops::packages::parse_apt_sim;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_apt_sim(&common::text(data));
});
