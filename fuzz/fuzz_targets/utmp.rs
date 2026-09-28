//! wtmp/utmp binary records (384 bytes each) and wtmpdb JSON.
#![no_main]

use fleet_ops::security::utmp::{parse_record, parse_wtmpdb_json};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_record(data);
    for rec in data.chunks(384) {
        let _ = parse_record(rec);
    }
    let _ = parse_wtmpdb_json(data);
});
