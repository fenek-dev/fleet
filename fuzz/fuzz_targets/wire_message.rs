//! Agent wire decoder: `Message` (and a bare `CommandBody`) from arbitrary
//! bytes. Successful decodes must re-encode to a stable form.
#![no_main]

use fleet_proto::{CommandBody, Message, SignedCommand, SignedRoster, decode, encode};
use libfuzzer_sys::fuzz_target;

fn roundtrip<T>(data: &[u8])
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    if let Ok(v) = decode::<T>(data) {
        let bytes = encode(&v);
        let again: T = decode(&bytes).expect("re-encoded value decodes");
        assert_eq!(v, again);
        assert_eq!(bytes, encode(&again), "encoding not stable");
    }
}

fuzz_target!(|data: &[u8]| {
    roundtrip::<Message>(data);
    roundtrip::<CommandBody>(data);
    roundtrip::<SignedCommand>(data);
    roundtrip::<SignedRoster>(data);
});
