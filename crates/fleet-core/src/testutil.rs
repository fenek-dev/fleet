//! Shared helpers for this crate's unit tests.

use std::future::Future;

/// Runs `f` to completion on a fresh current-thread runtime (timers and
/// I/O enabled).
pub fn block_on<F: Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(f)
}
