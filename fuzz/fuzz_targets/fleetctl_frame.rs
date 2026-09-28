//! fleetctl <-> app socket frames: header length check and JSON bodies
//! (both directions). Decoded values must survive an encode/decode trip.
#![no_main]

use fleetctl_proto::{Request, Response, decode_body, encode_frame, frame_len};
use libfuzzer_sys::fuzz_target;

fn roundtrip<T>(body: &[u8])
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    if let Ok(v) = decode_body::<T>(body) {
        let frame = encode_frame(&v).expect("decoded value re-encodes");
        let again: T = decode_body(&frame[4..]).expect("re-encoded frame decodes");
        assert_eq!(v, again);
    }
}

fuzz_target!(|data: &[u8]| {
    if let Some(h) = data.get(..4) {
        let _ = frame_len([h[0], h[1], h[2], h[3]]);
    }
    roundtrip::<Request>(data);
    roundtrip::<Response>(data);
});
