//! Debian version ordering: panic-free, reflexive, antisymmetric.
//! Input: `a \0 b` (no NUL: `b` is empty).
#![no_main]

#[path = "common.rs"]
mod common;

use std::cmp::Ordering;

use fleet_debver::{Version, compare};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let t = common::text(data);
    let (a, b) = t.split_once('\0').unwrap_or((&t, ""));
    let ab = compare(a, b);
    assert_eq!(ab, compare(b, a).reverse(), "antisymmetry: {a:?} vs {b:?}");
    assert_eq!(compare(a, a), Ordering::Equal, "reflexive: {a:?}");
    if let (Ok(va), Ok(vb)) = (Version::parse(a), Version::parse(b)) {
        assert_eq!(va.cmp(&vb), vb.cmp(&va).reverse());
    }
    let _ = fleet_core::vuln::dpkgver::is_older(a, b);
});
