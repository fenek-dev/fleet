//! `docker.logs` and `docker.stats` streams.

use super::{DockerApi, DockerStream, LogFrame, RawStats, clip, parse_rfc3339_ms};
use crate::ctx::Clock;
use crate::handler::{LocalBoxFuture, OpError, OpStream};
use fleet_proto::payload::{ContainerStats, DockerLogChunk, DockerLogLine, DockerStats};
use fleet_proto::{F32, Payload};
use futures_util::{FutureExt, StreamExt};
use std::collections::HashMap;
use std::rc::Rc;
use std::time::{Duration, Instant};

pub const MAX_LINE: usize = 16 * 1024;
pub const MAX_CHUNK_LINES: usize = 256;

/// Splits a frame into lines; with Docker's `timestamps=true` each line
/// starts with an RFC 3339 time and a space.
pub fn frame_lines(f: &LogFrame) -> Vec<DockerLogLine> {
    let text = String::from_utf8_lossy(&f.bytes);
    text.split('\n')
        .filter(|l| !l.is_empty())
        .map(|l| {
            let l = l.strip_suffix('\r').unwrap_or(l);
            let (time_ms, text) = match l.split_once(' ') {
                Some((ts, rest)) => match parse_rfc3339_ms(ts) {
                    Some(ms) => (Some(ms), rest),
                    None => (None, l),
                },
                None => (
                    parse_rfc3339_ms(l),
                    if parse_rfc3339_ms(l).is_some() { "" } else { l },
                ),
            };
            DockerLogLine {
                time_ms,
                stream: f.stream,
                text: clip(text, MAX_LINE),
            }
        })
        .collect()
}

/// Batches whatever frames are ready into one `DockerLogChunk`; ends when
/// Docker ends the stream (bounded request, container removed).
pub struct LogsStream {
    inner: DockerStream<LogFrame>,
    done: bool,
    pending_err: Option<OpError>,
}

impl LogsStream {
    pub fn new(inner: DockerStream<LogFrame>) -> Self {
        Self {
            inner,
            done: false,
            pending_err: None,
        }
    }

    async fn next_chunk(&mut self) -> Option<Result<Payload, OpError>> {
        if let Some(e) = self.pending_err.take() {
            self.done = true;
            return Some(Err(e));
        }
        if self.done {
            return None;
        }
        let mut lines = match self.inner.next().await {
            None => {
                self.done = true;
                return None;
            }
            Some(Err(e)) => {
                self.done = true;
                return Some(Err(e.into()));
            }
            Some(Ok(f)) => frame_lines(&f),
        };
        while lines.len() < MAX_CHUNK_LINES {
            match self.inner.next().now_or_never() {
                Some(Some(Ok(f))) => lines.extend(frame_lines(&f)),
                Some(Some(Err(e))) => {
                    self.pending_err = Some(e.into());
                    break;
                }
                Some(None) => {
                    self.done = true;
                    break;
                }
                None => break,
            }
        }
        Some(Ok(Payload::DockerLogChunk(DockerLogChunk { lines })))
    }
}

impl OpStream for LogsStream {
    fn next(&mut self) -> LocalBoxFuture<'_, Option<Result<Payload, OpError>>> {
        Box::pin(self.next_chunk())
    }
}

/// Rates and CPU percent from two samples `dt` apart (the first sample of a
/// container has no previous one: zeros).
pub fn compute(id: &str, prev: Option<(&RawStats, Duration)>, cur: &RawStats) -> ContainerStats {
    let mut s = ContainerStats {
        id: clip(id, 128),
        cpu_pct: F32(0.0),
        mem_bytes: cur.mem_usage.saturating_sub(cur.mem_inactive_file),
        mem_limit: cur.mem_limit,
        net_rx_bps: 0,
        net_tx_bps: 0,
        blk_read_bps: 0,
        blk_write_bps: 0,
        pids: u32::try_from(cur.pids).unwrap_or(u32::MAX),
    };
    let Some((p, dt)) = prev else {
        return s;
    };
    let secs = dt.as_secs_f64();
    if secs <= 0.0 {
        return s;
    }
    let rate = |a: u64, b: u64| (a.saturating_sub(b) as f64 / secs) as u64;
    s.net_rx_bps = rate(cur.net_rx, p.net_rx);
    s.net_tx_bps = rate(cur.net_tx, p.net_tx);
    s.blk_read_bps = rate(cur.blk_read, p.blk_read);
    s.blk_write_bps = rate(cur.blk_write, p.blk_write);
    let dcpu = cur.cpu_total_ns.saturating_sub(p.cpu_total_ns) as f64;
    let dsys = cur.system_cpu_ns.saturating_sub(p.system_cpu_ns) as f64;
    if dsys > 0.0 {
        let cpus = f64::from(cur.online_cpus.max(1));
        s.cpu_pct = F32((dcpu / dsys * cpus * 100.0) as f32);
    }
    s
}

pub const STATS_INTERVAL: Duration = Duration::from_secs(2);
const MAX_STATS_CONTAINERS: usize = 256;

/// `docker.stats`: running containers (or the requested ones, by id prefix
/// or name) every [`STATS_INTERVAL`]. The first item comes after a one
/// second priming sample so it already has rates.
pub struct StatsStream {
    api: Rc<dyn DockerApi>,
    clock: Rc<dyn Clock>,
    filter: Vec<String>,
    prev: HashMap<String, (RawStats, Instant)>,
    primed: bool,
    interval: Duration,
}

impl StatsStream {
    pub fn new(api: Rc<dyn DockerApi>, clock: Rc<dyn Clock>, filter: Vec<String>) -> Self {
        Self {
            api,
            clock,
            filter,
            prev: HashMap::new(),
            primed: false,
            interval: STATS_INTERVAL,
        }
    }

    pub fn with_interval(mut self, d: Duration) -> Self {
        self.interval = d;
        self
    }

    async fn sample(&mut self) -> Result<Vec<ContainerStats>, OpError> {
        let list = self.api.list_containers(false).await?;
        let wanted = list
            .into_iter()
            .filter(|c| {
                self.filter.is_empty()
                    || self
                        .filter
                        .iter()
                        .any(|f| c.id.starts_with(f.as_str()) || c.name == *f)
            })
            .take(MAX_STATS_CONTAINERS);
        let mut out = Vec::new();
        let mut seen = HashMap::new();
        for c in wanted {
            // A container that stops between list and stats is skipped.
            let Ok(cur) = self.api.stats_once(&c.id).await else {
                continue;
            };
            let now = self.clock.monotonic();
            let prev = self
                .prev
                .get(&c.id)
                .map(|(p, t)| (p, now.saturating_duration_since(*t)));
            out.push(compute(&c.id, prev, &cur));
            seen.insert(c.id, (cur, now));
        }
        self.prev = seen;
        Ok(out)
    }

    async fn next_item(&mut self) -> Option<Result<Payload, OpError>> {
        if self.primed {
            tokio::time::sleep(self.interval).await;
        } else {
            self.primed = true;
            if let Err(e) = self.sample().await {
                return Some(Err(e));
            }
            tokio::time::sleep(self.interval.min(Duration::from_secs(1))).await;
        }
        Some(self.sample().await.map(|containers| {
            Payload::DockerStats(DockerStats {
                time_ms: self.clock.now_ms(),
                containers,
            })
        }))
    }
}

impl OpStream for StatsStream {
    fn next(&mut self) -> LocalBoxFuture<'_, Option<Result<Payload, OpError>>> {
        Box::pin(self.next_item())
    }

    fn latest_only(&self) -> bool {
        true
    }
}
