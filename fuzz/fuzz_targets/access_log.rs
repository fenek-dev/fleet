//! Caddy/nginx JSON access lines (web scan / web bans).
#![no_main]

use fleet_ops::security::webscan::{parse_access_line, parse_strict_json};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_strict_json(data);
    let _ = parse_access_line(data);
    for line in data.split(|&b| b == b'\n') {
        let _ = parse_access_line(line);
    }
});
