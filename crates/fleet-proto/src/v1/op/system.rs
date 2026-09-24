//! `system` group argument types (tags 0–99).

use serde::{Deserialize, Serialize};

/// `metrics.subscribe` sampling (design §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SampleInterval {
    /// While the server is on screen.
    OneSecond,
    /// Background default.
    TenSeconds,
}

/// `metrics.query` resolution (design §4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Resolution {
    /// Native samples, last hour only.
    Raw,
    /// 1-minute min/avg/max rollups, 7 days.
    Minute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProcessSort {
    Cpu,
    Memory,
    Io,
    Pid,
}
