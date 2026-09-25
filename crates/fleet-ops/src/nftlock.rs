//! Serializes changes to `table inet fleet` (design §4.7).
//!
//! `firewall.apply` replaces the table while ban-set updates add and remove
//! elements in it; interleaving the two could drop elements or apply a
//! stale ruleset. Every writer holds [`lock`] across its nft calls.

use tokio::sync::{Mutex, MutexGuard};

static TABLE: Mutex<()> = Mutex::const_new(());

/// Waits for exclusive access to `table inet fleet`.
pub async fn lock() -> MutexGuard<'static, ()> {
    TABLE.lock().await
}

/// Exclusive access when nobody holds it (tests, non-async callers).
pub fn try_lock() -> Option<MutexGuard<'static, ()>> {
    TABLE.try_lock().ok()
}
