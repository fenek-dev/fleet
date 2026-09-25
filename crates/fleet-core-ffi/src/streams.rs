//! Live streams for the app (design §6.3): metrics subscriptions, journal
//! follow, and the fleet table's 10 s telemetry.
//!
//! Each stream runs as a task on the core runtime and reports to a Swift
//! sink on the core thread. Items are signature-checked by the session
//! (`fleet_core::session`); a verification failure ends the stream with
//! an error. [`StreamHandle::cancel`] (or dropping the handle) stops it
//! and cancels it on the agent. Metrics and journal streams reopen after a
//! reconnect (journal resumes after its last cursor).

use crate::api::{FleetCore, LiveMetrics, lock};
use crate::ops::journal_query;
use crate::rows::*;
use crate::signer::CoreListener;
use crate::types::FleetError;
use crate::validate;
use fleet_core::StreamEvent;
use fleet_core::manager::{ManagerEvent, ManagerHandle, RequestError};
use fleet_proto::args::JournalCursor;
use fleet_proto::op::SampleInterval;
use fleet_proto::{Actor, Op, Payload, ServerId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{broadcast, oneshot};

/// How long a reconnecting stream waits for the server to be Ready again.
const REOPEN_WAIT: Duration = Duration::from_secs(60);

#[uniffi::export(callback_interface)]
pub trait MetricsSink: Send + Sync {
    /// Sent first, and again when the series set changes.
    fn on_catalog(&self, series: Vec<MetricSeriesRow>);
    fn on_sample(&self, sample: MetricsSampleRow);
    fn on_status(&self, status: StreamStatus);
}

#[uniffi::export(callback_interface)]
pub trait JournalSink: Send + Sync {
    fn on_entries(&self, page: JournalPageRow);
    fn on_status(&self, status: StreamStatus);
}

/// A running stream; `cancel` (or dropping it) stops it.
#[derive(uniffi::Object)]
pub struct StreamHandle {
    cancel: Mutex<Option<oneshot::Sender<()>>>,
}

#[uniffi::export]
impl StreamHandle {
    pub fn cancel(&self) {
        lock(&self.cancel).take();
    }
}

impl StreamHandle {
    fn new() -> (Arc<Self>, oneshot::Receiver<()>) {
        let (tx, rx) = oneshot::channel();
        (
            Arc::new(Self {
                cancel: Mutex::new(Some(tx)),
            }),
            rx,
        )
    }
}

/// Opens `op()` on `id`, forwards items, reopens after a lost link.
async fn run_stream(
    handle: ManagerHandle,
    id: ServerId,
    op: impl Fn() -> Op + Send,
    on_item: impl Fn(Payload) + Send,
    on_status: impl Fn(StreamStatus) + Send,
    mut cancel: oneshot::Receiver<()>,
) {
    loop {
        let opened = tokio::select! {
            _ = &mut cancel => return,
            r = handle.open_stream(&id, op(), Actor::Human) => r,
        };
        match opened {
            Ok(mut s) => {
                on_status(StreamStatus::Live);
                loop {
                    let ev = tokio::select! {
                        _ = &mut cancel => return,
                        ev = s.events.recv() => ev,
                    };
                    match ev {
                        Some(StreamEvent::Item(p)) => on_item(p),
                        Some(StreamEvent::Verified { .. }) => {}
                        Some(StreamEvent::End(end)) => {
                            on_status(StreamStatus::Ended {
                                error: end.err().map(|f| f.to_string()),
                            });
                            return;
                        }
                        // The session went away: reconnect below.
                        None => break,
                    }
                }
            }
            Err(RequestError::NotReady(_) | RequestError::Timeout) => {}
            Err(e) => {
                on_status(StreamStatus::Ended {
                    error: Some(FleetError::from(e).to_string()),
                });
                return;
            }
        }
        on_status(StreamStatus::Reconnecting);
        tokio::select! {
            _ = &mut cancel => return,
            _ = async {
                // Let the worker notice the drop, then wait for Ready.
                tokio::time::sleep(Duration::from_secs(1)).await;
                handle.wait_ready(&id, REOPEN_WAIT).await
            } => {}
        }
    }
}

#[uniffi::export]
impl FleetCore {
    /// Live metrics: 1 s while the server is on screen, 10 s otherwise.
    /// Allowed on monitor sessions (locked app).
    pub fn subscribe_metrics(
        &self,
        server_id: String,
        one_second: bool,
        sink: Box<dyn MetricsSink>,
    ) -> Result<Arc<StreamHandle>, FleetError> {
        let id = validate::server_id(&server_id)?;
        let (handle, rt) = self.running()?;
        let (h, cancel) = StreamHandle::new();
        let sink: Arc<dyn MetricsSink> = Arc::from(sink);
        let interval = if one_second {
            SampleInterval::OneSecond
        } else {
            SampleInterval::TenSeconds
        };
        let s1 = sink.clone();
        rt.spawn(run_stream(
            handle,
            id,
            move || Op::MetricsSubscribe { interval },
            move |p| match p {
                Payload::MetricsCatalog(c) => {
                    s1.on_catalog(c.series.into_iter().map(Into::into).collect())
                }
                Payload::MetricsSample(s) => s1.on_sample(s.into()),
                _ => {}
            },
            move |st| sink.on_status(st),
            cancel,
        ));
        Ok(h)
    }

    /// `journal.follow`: new entries as they are written. After a
    /// reconnect it resumes after the last cursor seen.
    pub fn follow_journal(
        &self,
        server_id: String,
        query: JournalQueryArgs,
        sink: Box<dyn JournalSink>,
    ) -> Result<Arc<StreamHandle>, FleetError> {
        let id = validate::server_id(&server_id)?;
        let base = journal_query(&query)?;
        let (handle, rt) = self.running()?;
        let (h, cancel) = StreamHandle::new();
        let sink: Arc<dyn JournalSink> = Arc::from(sink);
        let cursor: Arc<Mutex<Option<JournalCursor>>> = Arc::default();
        let c1 = cursor.clone();
        let s1 = sink.clone();
        rt.spawn(run_stream(
            handle,
            id,
            move || {
                let mut q = base.clone();
                if let Some(c) = lock(&c1).clone() {
                    q.after_cursor = Some(c);
                }
                Op::JournalFollow(q)
            },
            move |p| {
                if let Payload::JournalEntries(j) = p {
                    if let Some(c) = j.cursor.as_deref().and_then(|c| JournalCursor::new(c).ok()) {
                        *lock(&cursor) = Some(c);
                    }
                    s1.on_entries(j.into());
                }
            },
            move |st| sink.on_status(st),
            cancel,
        ));
        Ok(h)
    }
}

/// Fleet-table figures from the latest values of a metrics stream.
#[derive(Default)]
pub(crate) struct Rollup {
    names: HashMap<u16, String>,
    values: HashMap<String, f32>,
}

impl Rollup {
    pub(crate) fn catalog(&mut self, c: &[fleet_proto::payload::MetricSeries]) {
        self.names = c.iter().map(|s| (s.id, s.name.clone())).collect();
        self.values
            .retain(|k, _| self.names.values().any(|n| n == k));
    }

    pub(crate) fn sample(
        &mut self,
        server: &ServerId,
        s: &fleet_proto::payload::MetricsSample,
    ) -> ServerMetricsRow {
        for (id, v) in &s.values {
            if let Some(n) = self.names.get(id) {
                self.values.insert(n.clone(), v.0);
            }
        }
        let get = |k: &str| self.values.get(k).copied().filter(|v| v.is_finite());
        let mem = match (get("mem.used"), get("mem.total")) {
            (Some(u), Some(t)) if t > 0.0 => Some(u / t * 100.0),
            _ => None,
        };
        ServerMetricsRow {
            server_id: server.to_string(),
            cpu_percent: get("cpu.busy"),
            mem_percent: mem,
            disk_percent: get("disk.used:/"),
            time_ms: s.time_ms,
        }
    }
}

/// For every server that becomes Ready, a 10 s metrics stream whose
/// latest CPU/memory/disk go to the fleet table (`on_metrics`) and into
/// `live` (read by `list_servers`). One stream per Ready period; a newer
/// period supersedes an older task.
pub(crate) async fn fleet_telemetry(
    handle: ManagerHandle,
    live: LiveMetrics,
    listener: Arc<dyn CoreListener>,
) {
    let mut events = handle.subscribe();
    let generations: Arc<Mutex<HashMap<ServerId, u64>>> = Arc::default();
    loop {
        match events.recv().await {
            Ok(ManagerEvent::State {
                server,
                state: fleet_core::manager::ConnState::Ready,
                ..
            }) => {
                let generation = {
                    let mut g = lock(&generations);
                    let e = g.entry(server.clone()).or_default();
                    *e += 1;
                    *e
                };
                tokio::spawn(server_telemetry(
                    handle.clone(),
                    server,
                    generation,
                    generations.clone(),
                    live.clone(),
                    listener.clone(),
                ));
            }
            Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}

async fn server_telemetry(
    handle: ManagerHandle,
    id: ServerId,
    generation: u64,
    generations: Arc<Mutex<HashMap<ServerId, u64>>>,
    live: LiveMetrics,
    listener: Arc<dyn CoreListener>,
) {
    let current = || lock(&generations).get(&id) == Some(&generation);
    let op = Op::MetricsSubscribe {
        interval: SampleInterval::TenSeconds,
    };
    let Ok(mut s) = handle.open_stream(&id, op, Actor::Human).await else {
        return;
    };
    let mut roll = Rollup::default();
    while let Some(ev) = s.events.recv().await {
        if !current() {
            return;
        }
        match ev {
            StreamEvent::Item(Payload::MetricsCatalog(c)) => roll.catalog(&c.series),
            StreamEvent::Item(Payload::MetricsSample(smp)) => {
                let row = roll.sample(&id, &smp);
                lock(&live).insert(id.clone(), row.clone());
                listener.on_metrics(row);
            }
            StreamEvent::End(_) => return,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_proto::F32;
    use fleet_proto::payload::{MetricSeries, MetricUnit, MetricsSample};

    #[test]
    fn rollup_computes_table_figures() {
        let id = ServerId::new("srv_abc123").unwrap();
        let mut r = Rollup::default();
        let s = |id: u16, name: &str, unit| MetricSeries {
            id,
            name: name.into(),
            unit,
        };
        r.catalog(&[
            s(1, "cpu.busy", MetricUnit::Percent),
            s(2, "mem.used", MetricUnit::Bytes),
            s(3, "mem.total", MetricUnit::Bytes),
            s(4, "disk.used:/", MetricUnit::Percent),
        ]);
        let row = r.sample(
            &id,
            &MetricsSample {
                time_ms: 5,
                values: vec![(1, F32(12.5)), (2, F32(1.0)), (3, F32(4.0)), (4, F32(40.0))],
            },
        );
        assert_eq!(row.cpu_percent, Some(12.5));
        assert_eq!(row.mem_percent, Some(25.0));
        assert_eq!(row.disk_percent, Some(40.0));
        // Only changed values arrive; the rest carry over.
        let row = r.sample(
            &id,
            &MetricsSample {
                time_ms: 6,
                values: vec![(1, F32(50.0))],
            },
        );
        assert_eq!(
            (row.cpu_percent, row.mem_percent, row.time_ms),
            (Some(50.0), Some(25.0), 6)
        );
        // Unknown ids are ignored.
        let row = r.sample(
            &id,
            &MetricsSample {
                time_ms: 7,
                values: vec![(99, F32(1.0))],
            },
        );
        assert_eq!(row.cpu_percent, Some(50.0));
    }
}
