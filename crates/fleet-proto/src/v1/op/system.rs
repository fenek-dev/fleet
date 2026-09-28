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

/// `weblog.query` status filter: `min..=max`, both in 100..=599.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StatusRange {
    pub min: u16,
    pub max: u16,
}

impl StatusRange {
    pub fn contains(&self, status: u16) -> bool {
        (self.min..=self.max).contains(&status)
    }

    pub fn is_valid(&self) -> bool {
        (100..=599).contains(&self.min) && (100..=599).contains(&self.max) && self.min <= self.max
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProcessSort {
    Cpu,
    Memory,
    Io,
    Pid,
}
