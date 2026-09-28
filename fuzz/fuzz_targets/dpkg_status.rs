//! dpkg outputs: `dpkg-query` listing, `/var/lib/dpkg/status`, apt
//! extended_states, dpkg.log and apt history.log.
#![no_main]

#[path = "common.rs"]
mod common;

use fleet_ops::packages::{
    diff_installed, parse_dpkg_log, parse_dpkg_query, parse_extended_states, parse_history_log,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let t = common::text(data);
    let installed = parse_dpkg_query(&t);
    let _ = diff_installed(&installed, &[], false);
    let _ = diff_installed(&[], &installed, true);
    let _ = parse_extended_states(&t);
    let _ = parse_dpkg_log(&t);
    let _ = parse_history_log(&t);
    let _ = fleet_hardening::facts::parse_dpkg_status(&t);
});
