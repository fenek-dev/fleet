//! `nft -j list table inet fleet` parser and `ufw status` text.
#![no_main]

#[path = "common.rs"]
mod common;

use fleet_ops::firewall::parse::{parse_table, parse_ufw};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_table(data);
    let _ = parse_ufw(&common::text(data));
});
