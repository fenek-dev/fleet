//! dpkg version order for matching. The implementation lives in the
//! `fleet-debver` crate so the agent (`fleet-ops` package diffs) and the
//! Mac use the same code; its tests hold the Policy table and the
//! property tests.

pub use fleet_debver::{Version, VersionError, compare};

/// `installed` is older than `fixed` (the fix is not installed).
pub fn is_older(installed: &str, fixed: &str) -> bool {
    compare(installed, fixed) == std::cmp::Ordering::Less
}
