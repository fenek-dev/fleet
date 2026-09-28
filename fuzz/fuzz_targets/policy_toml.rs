//! Server policy TOML (`Policy::from_toml`).
#![no_main]

#[path = "common.rs"]
mod common;

use fleet_proto::policy::Policy;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Policy::from_toml(&common::text(data));
});
