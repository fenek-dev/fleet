//! Mac-side firewall ruleset history and accepted audit exceptions.
//!
//! The agent keeps no ruleset history: `firewall.get` reports only the
//! current table, whose `version` is a digest of it. This Mac therefore
//! remembers every distinct ruleset it has seen per server (newest first,
//! [`MAX_ENTRIES`] kept) so the Firewall tab can list versions and roll
//! back to one by applying it again as a normal `firewall.apply`. The
//! history is local to this Mac; another Mac builds its own.
//!
//! Accepted audit exceptions (hardening modules the operator decided to
//! leave as they are) live beside it, also per server and local.
//!
//! Both are stored in the cache's MAC-protected `settings` table.

use crate::cache::{Cache, CacheError};
use fleet_proto::ServerId;
use serde::{Deserialize, Serialize};

/// History depth per server.
pub const MAX_ENTRIES: usize = 50;

/// One remembered ruleset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FwHistoryEntry {
    /// Local sequence number, 1-based, never reused.
    pub n: u32,
    pub time_ms: u64,
    /// The agent's `firewall.get` version (digest) of this ruleset.
    pub version: u64,
    /// Where the change came from (`This Mac`, `Outside this Mac`, …).
    pub source: String,
    /// What changed relative to the previous entry.
    pub title: String,
    /// The ruleset, encoded by the caller (opaque here).
    pub ruleset: Vec<u8>,
}

fn history_key(id: &ServerId) -> String {
    format!("fw_history/{id}")
}

fn exceptions_key(id: &ServerId) -> String {
    format!("audit_exceptions/{id}")
}

/// Newest first. A missing or unreadable blob is an empty history (the
/// next observation starts it again); a MAC failure is an error.
pub fn history(cache: &Cache, id: &ServerId) -> Result<Vec<FwHistoryEntry>, CacheError> {
    Ok(cache
        .setting(&history_key(id))?
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default())
}

/// Adds `entry` (its `n` is assigned here) unless the newest entry already
/// has the same version. Returns whether one was added.
pub fn observe(
    cache: &Cache,
    id: &ServerId,
    mut entry: FwHistoryEntry,
) -> Result<bool, CacheError> {
    let mut all = history(cache, id)?;
    if all.first().is_some_and(|e| e.version == entry.version) {
        return Ok(false);
    }
    entry.n = all.first().map_or(1, |e| e.n + 1);
    all.insert(0, entry);
    all.truncate(MAX_ENTRIES);
    cache.set_setting(
        &history_key(id),
        &serde_json::to_vec(&all).expect("history serializes"),
    )?;
    Ok(true)
}

pub fn forget_history(cache: &Cache, id: &ServerId) -> Result<(), CacheError> {
    cache.set_setting(&history_key(id), b"[]")
}

/// Hardening modules the operator accepted on this server, sorted.
pub fn exceptions(cache: &Cache, id: &ServerId) -> Result<Vec<String>, CacheError> {
    Ok(cache
        .setting(&exceptions_key(id))?
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default())
}

pub fn set_exception(
    cache: &Cache,
    id: &ServerId,
    module: &str,
    accepted: bool,
) -> Result<(), CacheError> {
    let mut all = exceptions(cache, id)?;
    all.retain(|m| m != module);
    if accepted {
        all.push(module.to_string());
        all.sort();
    }
    cache.set_setting(
        &exceptions_key(id),
        &serde_json::to_vec(&all).expect("exceptions serialize"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid() -> ServerId {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        ServerId::new(format!("srv_testid{}", N.fetch_add(1, Ordering::Relaxed))).unwrap()
    }

    fn entry(version: u64) -> FwHistoryEntry {
        FwHistoryEntry {
            n: 0,
            time_ms: 1000 + version,
            version,
            source: "This Mac".into(),
            title: format!("v{version}"),
            ruleset: vec![version as u8],
        }
    }

    #[test]
    fn observe_numbers_dedupes_and_orders_newest_first() {
        let cache = Cache::open_in_memory().unwrap();
        let id = sid();
        assert!(history(&cache, &id).unwrap().is_empty());
        assert!(observe(&cache, &id, entry(7)).unwrap());
        assert!(!observe(&cache, &id, entry(7)).unwrap(), "same version again");
        assert!(observe(&cache, &id, entry(9)).unwrap());
        // An older ruleset coming back is a new entry.
        assert!(observe(&cache, &id, entry(7)).unwrap());
        let h = history(&cache, &id).unwrap();
        assert_eq!(h.iter().map(|e| e.n).collect::<Vec<_>>(), [3, 2, 1]);
        assert_eq!(h.iter().map(|e| e.version).collect::<Vec<_>>(), [7, 9, 7]);
    }

    #[test]
    fn history_is_capped_and_per_server() {
        let cache = Cache::open_in_memory().unwrap();
        let (a, b) = (sid(), sid());
        for v in 0..(MAX_ENTRIES as u64 + 5) {
            observe(&cache, &a, entry(v)).unwrap();
        }
        let h = history(&cache, &a).unwrap();
        assert_eq!(h.len(), MAX_ENTRIES);
        assert_eq!(h[0].n, MAX_ENTRIES as u32 + 5, "numbers keep counting");
        assert!(history(&cache, &b).unwrap().is_empty());
    }

    #[test]
    fn forget_clears_history() {
        let cache = Cache::open_in_memory().unwrap();
        let id = sid();
        observe(&cache, &id, entry(1)).unwrap();
        forget_history(&cache, &id).unwrap();
        assert!(history(&cache, &id).unwrap().is_empty());
    }

    #[test]
    fn exceptions_toggle_sorted_and_unique() {
        let cache = Cache::open_in_memory().unwrap();
        let id = sid();
        assert!(exceptions(&cache, &id).unwrap().is_empty());
        set_exception(&cache, &id, "sysctl", true).unwrap();
        set_exception(&cache, &id, "auditd", true).unwrap();
        set_exception(&cache, &id, "sysctl", true).unwrap();
        assert_eq!(exceptions(&cache, &id).unwrap(), ["auditd", "sysctl"]);
        set_exception(&cache, &id, "auditd", false).unwrap();
        assert_eq!(exceptions(&cache, &id).unwrap(), ["sysctl"]);
    }
}
