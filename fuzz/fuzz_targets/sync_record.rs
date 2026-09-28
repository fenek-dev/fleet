//! E2EE sync (Mac): `SignedRecord` decode + `verify_record` against the
//! golden roster chain; `CloudRecord` open under a fixed sync key; and
//! seal→open round trip for every decodable record.
#![no_main]

#[path = "common.rs"]
mod common;

use std::sync::LazyLock;

use fleet_core::sync::keys::SyncKey;
use fleet_core::sync::{CloudRecord, SignedRecord, verify_record};
use fleet_proto::{SignedRoster, decode};
use libfuzzer_sys::fuzz_target;

static CHAIN: LazyLock<[SignedRoster; 1]> = LazyLock::new(|| [common::roster()]);
static KEY: LazyLock<SyncKey> = LazyLock::new(|| SyncKey::from_bytes(&[7u8; 40]).unwrap());

fuzz_target!(|data: &[u8]| {
    if let Ok(sr) = decode::<SignedRecord>(data) {
        let _ = verify_record(&sr, &*CHAIN);
        if let Ok(cr) = KEY.seal_record(&sr) {
            let back = KEY.open_record(&cr).expect("own sealed record opens");
            assert!(back == sr, "seal/open round trip changed the record");
        }
    }
    let name = KEY.record_name(fleet_core::sync::Collection::Servers, "k");
    let _ = KEY.open_record(&CloudRecord { name, data: data.to_vec() });
});
