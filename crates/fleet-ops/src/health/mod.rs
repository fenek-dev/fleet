//! Health checks (design §2.2): HTTP and TCP probes the agent runs against
//! **local** services.
//!
//! Loopback only, by construction: a [`Probe`] carries a port and an
//! address family, never a host, and [`target`] maps it to `127.0.0.1` or
//! `::1`; [`connect`] refuses any non-loopback address anyway, so a check
//! can't be turned into a network scanner. Textual hosts (from templates)
//! go through [`loopback_host`] (`127.0.0.1`, `::1`, `localhost` only).
//!
//! [`HealthService`] keeps the `health_checks.update` set (persisted by a
//! [`HealthStore`]), runs each check at its interval ([`HealthService::run`]
//! on exec's `LocalSet`) and reports every result three ways:
//!
//! - gauges `health.ok:<id>` (1/0) and `health.latency:<id>` (ms) in the
//!   metric series;
//! - a `health_check.changed` event when a check flips (and when its first
//!   result is a failure);
//! - a `HealthCheckFailed { check }` level for the alert engine.
//!
//! `https` probes (`tls: true`) report a failure (`tls unsupported`): the
//! agent carries no TLS stack.
//!
//! **Accepted risk:** probes run inside `fleet-exec` (root), not as an
//! unprivileged user. They are kept inert instead: a fixed `GET <path>`
//! with no body, no cookies, no `Authorization` or other credential
//! headers (the request is exactly [`http_request`]), to loopback only, and
//! only the status line is read. A local service can't be made to act on
//! root's behalf beyond what an anonymous local GET already can.

use crate::ctx::SysCtx;
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, Registry};
use crate::security::EventSink;
use crate::telemetry::{AlertInput, GaugeSink, Observation};
use fleet_proto::alert::{AlertKind, HealthCheck, HealthCheckSet, Probe};
use fleet_proto::args::CheckId;
use fleet_proto::payload::{HealthCheckResult, HealthChecks, MetricUnit};
use fleet_proto::{ErrorCode, Event, Op, Payload};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Bytes of an HTTP response read to find the status line.
pub const MAX_HTTP_HEAD: usize = 4096;
/// Stored set file size cap.
const MAX_STORED: u64 = 64 * 1024;
/// Scheduler resolution.
pub const TICK: Duration = Duration::from_secs(1);

/// The loopback address a probe connects to.
/// The only request an HTTP probe sends: `GET`, no body, no credentials.
pub fn http_request(path: &fleet_proto::args::HttpPath) -> String {
    format!(
        "GET {} HTTP/1.1\r\nHost: localhost\r\nUser-Agent: fleet-health\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        path.as_str()
    )
}

pub fn target(p: &Probe) -> SocketAddr {
    let (port, ipv6) = match p {
        Probe::Tcp { port, ipv6 } | Probe::Http { port, ipv6, .. } => (port.get(), *ipv6),
    };
    let ip = if ipv6 {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    } else {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    };
    SocketAddr::new(ip, port)
}

/// `127.0.0.1`, `::1` or `localhost` → the loopback address; anything else
/// (other loopback aliases included) → `None`.
pub fn loopback_host(host: &str) -> Option<IpAddr> {
    match host {
        "localhost" | "127.0.0.1" => Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        "::1" | "[::1]" => Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        _ => None,
    }
}

/// Connects within `timeout`; refuses every non-loopback address.
pub async fn connect(addr: SocketAddr, timeout: Duration) -> Result<TcpStream, &'static str> {
    if !addr.ip().is_loopback() {
        return Err("not loopback");
    }
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Err(_) => Err("timeout"),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            Err("connection refused")
        }
        Ok(Err(_)) => Err("connect failed"),
        Ok(Ok(s)) => Ok(s),
    }
}

/// `HTTP/1.x NNN …` → `NNN`.
pub fn parse_status_line(head: &[u8]) -> Option<u16> {
    let line = head.split(|&b| b == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?.trim_end_matches('\r');
    let mut parts = line.splitn(3, ' ');
    let proto = parts.next()?;
    if !proto.starts_with("HTTP/1.") {
        return None;
    }
    let code = parts.next()?;
    if code.len() != 3 {
        return None;
    }
    code.parse().ok().filter(|c| (100..=599).contains(c))
}

/// One probe's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub ok: bool,
    pub latency_ms: u32,
    pub status: Option<u16>,
    pub error: Option<&'static str>,
}

fn millis(d: Duration) -> u32 {
    u32::try_from(d.as_millis()).unwrap_or(u32::MAX)
}

/// Runs `p` once with `timeout` for the whole exchange.
pub async fn probe(p: &Probe, timeout: Duration) -> Outcome {
    let start = Instant::now();
    let fail = |e, status| Outcome {
        ok: false,
        latency_ms: millis(start.elapsed()),
        status,
        error: Some(e),
    };
    if let Probe::Http { tls: true, .. } = p {
        return fail("tls unsupported", None);
    }
    let r = tokio::time::timeout(timeout, async {
        let mut s = connect(target(p), timeout).await?;
        let Probe::Http {
            path,
            expect_status,
            ..
        } = p
        else {
            return Ok((None, true));
        };
        let req = http_request(path);
        s.write_all(req.as_bytes())
            .await
            .map_err(|_| "write failed")?;
        let mut head = Vec::with_capacity(256);
        let mut buf = [0u8; 512];
        while head.len() < MAX_HTTP_HEAD && !head.contains(&b'\n') {
            let n = s.read(&mut buf).await.map_err(|_| "read failed")?;
            if n == 0 {
                break;
            }
            head.extend_from_slice(&buf[..n]);
        }
        let status = parse_status_line(&head).ok_or("bad response")?;
        Ok((Some(status), status == *expect_status))
    })
    .await;
    match r {
        Err(_) => fail("timeout", None),
        Ok(Err(e)) => fail(e, None),
        Ok(Ok((status, true))) => Outcome {
            ok: true,
            latency_ms: millis(start.elapsed()),
            status,
            error: None,
        },
        Ok(Ok((status, false))) => fail("unexpected status", status),
    }
}

// ---- storage ----

/// Where the check set survives restarts.
pub trait HealthStore {
    fn load(&self) -> Result<Option<HealthCheckSet>, OpError>;
    fn save(&self, set: &HealthCheckSet) -> Result<(), OpError>;
}

/// Postcard file (exec: `/var/lib/fleet/exec/health-checks.bin`), 0600,
/// replaced by temp file + rename.
pub struct FileStore(pub PathBuf);

impl HealthStore for FileStore {
    fn load(&self) -> Result<Option<HealthCheckSet>, OpError> {
        use std::io::Read;
        let f = match std::fs::File::open(&self.0) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(OpError::internal(e)),
        };
        let mut b = Vec::new();
        f.take(MAX_STORED)
            .read_to_end(&mut b)
            .map_err(OpError::internal)?;
        fleet_proto::decode(&b)
            .map(Some)
            .map_err(|e| OpError::internal(format!("health checks: {e}")))
    }

    fn save(&self, set: &HealthCheckSet) -> Result<(), OpError> {
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = self.0.with_extension("tmp");
        let _ = std::fs::remove_file(&tmp);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(OpError::internal)?;
        f.write_all(&fleet_proto::encode(set))
            .and_then(|()| f.sync_all())
            .map_err(OpError::internal)?;
        std::fs::rename(&tmp, &self.0).map_err(OpError::internal)
    }
}

/// In memory (tests).
#[derive(Default)]
pub struct MemStore(pub RefCell<Option<HealthCheckSet>>);

impl HealthStore for MemStore {
    fn load(&self) -> Result<Option<HealthCheckSet>, OpError> {
        Ok(self.0.borrow().clone())
    }

    fn save(&self, set: &HealthCheckSet) -> Result<(), OpError> {
        *self.0.borrow_mut() = Some(set.clone());
        Ok(())
    }
}

// ---- the service ----

struct CheckState {
    next_ms: u64,
    result: Option<HealthCheckResult>,
}

pub struct HealthService {
    store: Rc<dyn HealthStore>,
    set: RefCell<HealthCheckSet>,
    state: RefCell<BTreeMap<String, CheckState>>,
    sink: Rc<dyn EventSink>,
    alerts: Option<Rc<dyn AlertInput>>,
    gauges: Rc<dyn GaugeSink>,
}

fn ok_gauge(id: &str) -> String {
    format!("health.ok:{id}")
}

fn latency_gauge(id: &str) -> String {
    format!("health.latency:{id}")
}

fn failed_kind(id: &str) -> Option<AlertKind> {
    Some(AlertKind::HealthCheckFailed {
        check: CheckId::new(id).ok()?,
    })
}

impl HealthService {
    /// Loads the stored set (a corrupt one starts empty, logged by the
    /// caller through the returned error being ignored here).
    pub fn new(
        store: Rc<dyn HealthStore>,
        sink: Rc<dyn EventSink>,
        alerts: Option<Rc<dyn AlertInput>>,
        gauges: Rc<dyn GaugeSink>,
    ) -> Rc<Self> {
        let set = store.load().ok().flatten().unwrap_or(HealthCheckSet {
            version: 0,
            checks: Vec::new(),
        });
        let state = set
            .checks
            .iter()
            .map(|c| {
                (
                    c.id.as_str().to_owned(),
                    CheckState {
                        next_ms: 0,
                        result: None,
                    },
                )
            })
            .collect();
        Rc::new(Self {
            store,
            set: RefCell::new(set),
            state: RefCell::new(state),
            sink,
            alerts,
            gauges,
        })
    }

    pub fn config(&self) -> HealthCheckSet {
        self.set.borrow().clone()
    }

    pub fn results(&self) -> Vec<HealthCheckResult> {
        self.state
            .borrow()
            .values()
            .filter_map(|s| s.result.clone())
            .collect()
    }

    /// Persists and applies `set` (version checks are the handler's).
    /// Removed checks lose their gauges and clear their alert; new and
    /// changed ones run at the next tick.
    pub fn update(&self, set: HealthCheckSet, now_ms: u64) -> Result<(), OpError> {
        self.store.save(&set)?;
        let old = std::mem::replace(&mut *self.set.borrow_mut(), set.clone());
        let mut st = self.state.borrow_mut();
        for c in &old.checks {
            let id = c.id.as_str();
            let kept = set.checks.iter().find(|n| n.id == c.id);
            if kept == Some(c) {
                continue;
            }
            st.remove(id);
            if kept.is_none() {
                self.gauges.clear_gauge(&ok_gauge(id));
                self.gauges.clear_gauge(&latency_gauge(id));
            }
            if let (Some(a), Some(kind)) = (&self.alerts, failed_kind(id)) {
                a.observe(
                    Observation::Level {
                        kind,
                        subject: id.to_owned(),
                        value: 0,
                    },
                    now_ms,
                );
            }
        }
        for c in &set.checks {
            st.entry(c.id.as_str().to_owned()).or_insert(CheckState {
                next_ms: 0,
                result: None,
            });
        }
        Ok(())
    }

    /// Runs every check that is due at `ctx.clock.now_ms()`, one after
    /// another (each bounded by its own timeout).
    pub async fn run_due(&self, ctx: &SysCtx) {
        let now = ctx.clock.now_ms();
        let due: Vec<HealthCheck> = {
            let st = self.state.borrow();
            self.set
                .borrow()
                .checks
                .iter()
                .filter(|c| st.get(c.id.as_str()).is_some_and(|s| s.next_ms <= now))
                .cloned()
                .collect()
        };
        for c in due {
            let out = probe(&c.probe, Duration::from_millis(u64::from(c.timeout_ms))).await;
            self.record(&c, &out, ctx.clock.now_ms());
        }
    }

    fn record(&self, c: &HealthCheck, out: &Outcome, now_ms: u64) {
        let id = c.id.as_str();
        let mut st = self.state.borrow_mut();
        // Removed or replaced while the probe ran: drop the result.
        let current = self.set.borrow().checks.iter().any(|n| n == c);
        let Some(s) = st.get_mut(id).filter(|_| current) else {
            return;
        };
        let was = s.result.as_ref().map(|r| r.ok);
        s.next_ms = now_ms + u64::from(c.interval_s) * 1000;
        s.result = Some(HealthCheckResult {
            id: id.to_owned(),
            ok: out.ok,
            last_run_ms: now_ms,
            latency_ms: out.latency_ms,
            status: out.status,
            error: out.error.map(str::to_owned),
        });
        drop(st);
        self.gauges.set_gauge(
            &ok_gauge(id),
            MetricUnit::Ratio,
            f32::from(u8::from(out.ok)),
        );
        self.gauges
            .set_gauge(&latency_gauge(id), MetricUnit::Count, out.latency_ms as f32);
        if was != Some(out.ok) && (was.is_some() || !out.ok) {
            self.sink.emit(Event::HealthCheckChanged {
                check_id: id.to_owned(),
                ok: out.ok,
            });
        }
        if let (Some(a), Some(kind)) = (&self.alerts, failed_kind(id)) {
            a.observe(
                Observation::Level {
                    kind,
                    subject: id.to_owned(),
                    value: u64::from(!out.ok),
                },
                now_ms,
            );
        }
    }

    /// Forever: every [`TICK`], the due checks. Spawn on exec's LocalSet.
    pub async fn run(self: Rc<Self>, ctx: SysCtx) {
        let mut t = tokio::time::interval(TICK);
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            t.tick().await;
            self.run_due(&ctx).await;
        }
    }
}

/// `health_checks.list` and `health_checks.update`.
pub struct HealthOps(pub Rc<HealthService>);

impl HealthOps {
    fn check_update(&self, set: &HealthCheckSet, meta: &OpMeta) -> Result<(), OpError> {
        set.validate()
            .map_err(|_| OpError::new(ErrorCode::InvalidArgument))?;
        let current = self.0.set.borrow().version;
        // Versioned state (design §2.6), like alert rules.
        if meta.command.body.expected_version != Some(current) || set.version <= current {
            return Err(ErrorCode::VersionConflict { current }.into());
        }
        Ok(())
    }
}

impl OpHandler for HealthOps {
    fn validate(&self, _: &SysCtx, op: &Op, meta: &OpMeta) -> Result<(), OpError> {
        match op {
            Op::HealthChecksList => Ok(()),
            Op::HealthChecksUpdate(set) => self.check_update(set, meta),
            _ => Err(ErrorCode::Unsupported.into()),
        }
    }

    fn handle<'a>(
        &'a self,
        _: &'a SysCtx,
        op: &'a Op,
        meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            let p = match op {
                Op::HealthChecksList => Payload::HealthChecks(HealthChecks {
                    config: self.0.config(),
                    results: self.0.results(),
                }),
                Op::HealthChecksUpdate(set) => {
                    self.check_update(set, meta)?;
                    self.0.update(set.clone(), meta.now_ms)?;
                    Payload::Empty
                }
                _ => return Err(ErrorCode::Unsupported.into()),
            };
            Ok(OpOutput::Payload(p))
        })
    }
}

pub fn register(r: &mut Registry, svc: Rc<HealthService>) {
    let h: Rc<dyn OpHandler> = Rc::new(HealthOps(svc));
    r.register(fleet_proto::op::tag::HEALTH_CHECKS_LIST, h.clone());
    r.register(fleet_proto::op::tag::HEALTH_CHECKS_UPDATE, h);
}

#[cfg(test)]
mod tests;
