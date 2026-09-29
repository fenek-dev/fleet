//! Results of `system` ops: metrics, processes, connections, timeline, health checks.

use super::F32;
use crate::v1::alert::HealthCheckSet;
use crate::v1::args::Protocol;
use crate::v1::event::Event;
use crate::v1::op::Resolution;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MetricUnit {
    Percent,
    Bytes,
    BytesPerSec,
    OpsPerSec,
    Count,
    Celsius,
    /// Load average and other plain ratios.
    Ratio,
}

/// One metric series (at most 256 per server, design §4.3). `id` is stable
/// for the agent run; values refer to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricSeries {
    pub id: u16,
    /// Dotted name plus optional instance, e.g. `cpu.steal`, `disk.used:/`,
    /// `net.rx:eth0`. Untrusted text (interface and mount names).
    pub name: String,
    pub unit: MetricUnit,
}

/// Sent first on `metrics.subscribe`, and again when the series set changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricsCatalog {
    pub series: Vec<MetricSeries>,
}

/// One sampling tick: only the series whose value changed (design §4.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricsSample {
    pub time_ms: u64,
    pub values: Vec<(u16, F32)>,
}

/// Rollups of one series: `min[i]`/`avg[i]`/`max[i]` cover
/// `start_ms + i * step_ms`; a gap is NaN. For `Resolution::Raw` the three
/// vectors are equal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeriesRollup {
    pub id: u16,
    pub min: Vec<F32>,
    pub avg: Vec<F32>,
    pub max: Vec<F32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricsHistory {
    pub resolution: Resolution,
    pub start_ms: u64,
    pub step_ms: u32,
    pub catalog: Vec<MetricSeries>,
    pub series: Vec<SeriesRollup>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub user: String,
    pub name: String,
    /// Truncated to 4 KiB.
    pub cmdline: String,
    /// `/proc/<pid>/stat` state letter.
    pub state: u8,
    pub nice: i8,
    pub threads: u32,
    pub cpu_pct: F32,
    pub rss_bytes: u64,
    pub read_bps: u64,
    pub write_bps: u64,
    pub start_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessList {
    pub total: u32,
    pub processes: Vec<ProcessInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopProcess {
    pub pid: u32,
    pub name: String,
    pub cpu_pct: F32,
    pub rss_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopProcessMinute {
    pub time_ms: u64,
    pub by_cpu: Vec<TopProcess>,
    pub by_memory: Vec<TopProcess>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessHistory {
    pub minutes: Vec<TopProcessMinute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connection {
    pub proto: Protocol,
    pub local: SocketAddr,
    pub remote: Option<SocketAddr>,
    /// TCP state name, e.g. `ESTABLISHED`.
    pub state: String,
    pub pid: Option<u32>,
    pub process: Option<String>,
    pub rx_bps: u64,
    pub tx_bps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connections {
    pub connections: Vec<Connection>,
}

/// A stored event (design §4.4 `events` table).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub seq: u64,
    pub time_ms: u64,
    pub event: Event,
}

/// `events.query` page: events exactly as they were pushed (each verified
/// by the Mac like a live `Event`, design §5.6), oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEventPage {
    pub events: Vec<crate::v1::SignedEvent>,
    /// More events follow the last one returned.
    pub more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timeline {
    pub events: Vec<TimelineEvent>,
    /// More events matched than `limit`.
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCheckResult {
    pub id: String,
    pub ok: bool,
    pub last_run_ms: u64,
    pub latency_ms: u32,
    pub status: Option<u16>,
    /// Short reason for a failure, e.g. `connection refused`.
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthChecks {
    pub config: HealthCheckSet,
    pub results: Vec<HealthCheckResult>,
}

/// `system.reboot.status`: the reboot timer, if one is armed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebootStatus {
    /// When the armed reboot fires (ms since the Unix epoch); `None` when
    /// nothing is scheduled.
    pub at_ms: Option<u64>,
}
