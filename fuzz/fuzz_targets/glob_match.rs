//! The shared path glob matcher (`fleet_proto::glob`): agent secret and
//! tracked-config rules and the Mac's MCP secret-file refusal. Input is
//! `pattern NUL text`.
#![no_main]

#[path = "common.rs"]
mod common;

use fleet_proto::glob::{component_match, glob_covers, glob_match, is_glob, within_limits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let t = common::text(data);
    let (pat, text) = t.split_once('\0').unwrap_or((t.as_str(), ""));
    let m = glob_match(pat, text);
    // A full match is also a cover; oversized input never matches.
    if m {
        assert!(glob_covers(pat, text));
        assert!(within_limits(pat, text));
    }
    // A pattern without wildcards matches itself (a literal `*` in the
    // text never hides anything).
    if !is_glob(pat) && within_limits(pat, pat) {
        assert!(glob_match(pat, pat));
    }
    // `*` matches any one component, and the text as its own pattern
    // matches when it has no wildcard.
    let _ = component_match(pat, text);
    if within_limits("**", text) {
        assert!(glob_match("**", text));
    }
});
