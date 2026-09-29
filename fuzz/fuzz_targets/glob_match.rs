//! The shared path glob matcher (`fleet_proto::glob`): agent secret and
//! tracked-config rules and the Mac's MCP secret-file refusal. Input is
//! `pattern NUL text`.
#![no_main]

#[path = "common.rs"]
mod common;

use fleet_proto::glob::{
    allow_covers, allow_match, component_match, deny_covers, deny_match, is_glob, within_limits,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let t = common::text(data);
    let (pat, text) = t.split_once('\0').unwrap_or((t.as_str(), ""));
    let m = allow_match(pat, text);
    // A full match is also a cover; oversized input never matches an
    // allow-list and always matches a deny-list.
    if m {
        assert!(allow_covers(pat, text));
        assert!(within_limits(pat, text));
    }
    if within_limits(pat, text) {
        assert_eq!(m, deny_match(pat, text));
        assert_eq!(allow_covers(pat, text), deny_covers(pat, text));
    } else {
        assert!(!m && deny_match(pat, text) && deny_covers(pat, text));
    }
    // A pattern without wildcards matches itself (a literal `*` in the
    // text never hides anything).
    if !is_glob(pat) && within_limits(pat, pat) {
        assert!(allow_match(pat, pat));
    }
    let _ = component_match(pat, text);
    if within_limits("**", text) {
        assert!(allow_match("**", text));
    }
});
