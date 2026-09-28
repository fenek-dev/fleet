//! Vulnerability feeds (Mac): Debian security tracker JSON and Ubuntu USN
//! JSON, streamed into a sink.
#![no_main]

use fleet_core::vuln::feed::{Source, parse};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for source in [Source::DebianTracker, Source::UbuntuUsn] {
        let _ = parse(source, data, &mut |_| Ok(()));
    }
});
