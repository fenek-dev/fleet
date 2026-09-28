//! Chunk reassembly (design §6.1). Input: records `len: u8 ‖ chunk[len]`,
//! pushed in order into a small Reassembler. Frames returned must respect
//! the limits; `split_frame` of the whole input must reassemble exactly.
#![no_main]

use fleet_proto::chunk::{Reassembler, split_frame};
use libfuzzer_sys::fuzz_target;

const MAX_FRAME: usize = 1024;
const MAX_PARTIAL: usize = 4;

fuzz_target!(|data: &[u8]| {
    let mut r = Reassembler::new(MAX_FRAME, MAX_PARTIAL);
    let mut rest = data;
    while let Some((&len, tail)) = rest.split_first() {
        let n = (len as usize).min(tail.len());
        let (chunk, tail) = tail.split_at(n);
        rest = tail;
        match r.push(chunk) {
            Ok(Some((_, frame))) => assert!(frame.len() <= MAX_FRAME),
            Ok(None) | Err(_) => {}
        }
        assert!(r.buffered() <= MAX_FRAME * MAX_PARTIAL, "buffered {}", r.buffered());
    }

    // Round trip through the real splitter.
    let mut r = Reassembler::for_exec();
    let chunks = split_frame(7, data);
    let (last, init) = chunks.split_last().expect("at least one chunk");
    for c in init {
        assert_eq!(r.push(c).expect("split chunk accepted"), None);
    }
    let got = r.push(last).expect("last chunk accepted");
    assert_eq!(got, Some((7, data.to_vec())));
});
