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

/// Longest lead of a scheduled reboot: 30 days.
pub const REBOOT_MAX_LEAD_S: u32 = 30 * 86_400;
/// Minutes in a day (bound of [`RebootWhen::Window`] fields).
pub const MINUTES_PER_DAY: u16 = 1440;

/// When `system.reboot.schedule` reboots (design §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RebootWhen {
    /// After `delay_s` (at most 30 days; the agent enforces a floor).
    In { delay_s: u32 },
    /// At an absolute time (ms since the Unix epoch), between five seconds
    /// and 30 days from the agent's clock.
    At { at_ms: u64 },
    /// Inside a daily window in the server's **local** time, given as
    /// minutes since local midnight (`0..1440`, `start_min != end_min`;
    /// `end_min < start_min` wraps past midnight). Reboots at the start of
    /// the next window, or right away when the local time is inside one.
    Window { start_min: u16, end_min: u16 },
}

impl RebootWhen {
    pub fn is_valid(&self) -> bool {
        match *self {
            RebootWhen::In { delay_s } => delay_s <= REBOOT_MAX_LEAD_S,
            RebootWhen::At { at_ms } => at_ms > 0,
            RebootWhen::Window { start_min, end_min } => {
                start_min < MINUTES_PER_DAY && end_min < MINUTES_PER_DAY && start_min != end_min
            }
        }
    }
}
