//! `journalctl -o json` lines.
#![no_main]

use fleet_ops::logs::journal::parse_line;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_line(data);
});
