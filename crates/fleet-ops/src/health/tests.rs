use super::*;
use crate::runner::FakeRunner;
use crate::testutil::{block, ctx_at, meta};
use crate::{Clock, ManualClock};
use fleet_proto::args::{HttpPath, Port};
use std::cell::Cell;
use tokio::net::TcpListener;

#[derive(Default)]
struct Events(RefCell<Vec<Event>>);
impl EventSink for Events {
    fn emit(&self, e: Event) {
        self.0.borrow_mut().push(e);
    }
}

#[derive(Default)]
struct Levels(RefCell<Vec<(String, u64)>>);
impl AlertInput for Levels {
    fn observe(&self, obs: Observation, _: u64) {
        if let Observation::Level {
            kind: AlertKind::HealthCheckFailed { check },
            value,
            ..
        } = obs
        {
            self.0.borrow_mut().push((check.as_str().to_owned(), value));
        }
    }
}

#[derive(Default)]
struct Gauges(RefCell<BTreeMap<String, f32>>);
impl GaugeSink for Gauges {
    fn set_gauge(&self, name: &str, _: MetricUnit, v: f32) {
        self.0.borrow_mut().insert(name.to_owned(), v);
    }
    fn clear_gauge(&self, name: &str) {
        self.0.borrow_mut().remove(name);
    }
}

fn port(p: u16) -> Port {
    Port::new(p).unwrap()
}

fn check(id: &str, probe: Probe) -> HealthCheck {
    HealthCheck {
        id: CheckId::new(id).unwrap(),
        probe,
        interval_s: 5,
        timeout_ms: 1000,
    }
}

fn http(p: u16, status: u16) -> Probe {
    Probe::Http {
        port: port(p),
        ipv6: false,
        tls: false,
        path: HttpPath::new("/healthz").unwrap(),
        expect_status: status,
    }
}

/// Answers every connection with `reply` after reading the request head.
async fn server(reply: &'static str) -> (u16, Rc<Cell<u32>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let hits = Rc::new(Cell::new(0));
    let h = hits.clone();
    tokio::task::spawn_local(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            h.set(h.get() + 1);
            let mut buf = [0u8; 1024];
            let n = s.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                continue; // a TCP probe: connect only
            }
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            assert!(req.starts_with("GET /healthz HTTP/1.1\r\nHost: localhost\r\n"));
            let _ = s.write_all(reply.as_bytes()).await;
        }
    });
    (port, hits)
}

fn local<F: std::future::Future>(f: F) -> F::Output {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    tokio::task::LocalSet::new().block_on(&rt, f)
}

#[test]
fn targets_are_loopback_only() {
    let t = target(&http(8080, 200));
    assert_eq!(t, "127.0.0.1:8080".parse().unwrap());
    let t6 = target(&Probe::Tcp {
        port: port(5432),
        ipv6: true,
    });
    assert_eq!(t6, "[::1]:5432".parse().unwrap());
    assert!(t.ip().is_loopback() && t6.ip().is_loopback());
    for ok in ["127.0.0.1", "::1", "[::1]", "localhost"] {
        assert!(loopback_host(ok).is_some_and(|ip| ip.is_loopback()), "{ok}");
    }
    for bad in [
        "10.0.0.1",
        "127.0.0.2",
        "0.0.0.0",
        "example.com",
        "localhost.evil",
        "::ffff:127.0.0.1",
        "",
    ] {
        assert_eq!(loopback_host(bad), None, "{bad}");
    }
    let r = block(connect(
        "192.0.2.1:80".parse().unwrap(),
        Duration::from_millis(50),
    ));
    assert_eq!(r.unwrap_err(), "not loopback");
}

#[test]
fn status_line_parsing() {
    assert_eq!(parse_status_line(b"HTTP/1.1 204 No Content\r\n"), Some(204));
    assert_eq!(parse_status_line(b"HTTP/1.0 500\r\n"), Some(500));
    assert_eq!(parse_status_line(b"HTTP/2 200\r\n"), None);
    assert_eq!(parse_status_line(b"HTTP/1.1 99 x\r\n"), None);
    assert_eq!(parse_status_line(b"HTTP/1.1 2000 x\r\n"), None);
    assert_eq!(parse_status_line(b"garbage"), None);
}

#[test]
fn probes_http_tcp_and_failures() {
    local(async {
        let (p, hits) = server("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
        let o = probe(&http(p, 200), Duration::from_secs(2)).await;
        assert!(o.ok, "{o:?}");
        assert_eq!(o.status, Some(200));
        let o = probe(&http(p, 204), Duration::from_secs(2)).await;
        assert_eq!(
            (o.ok, o.status, o.error),
            (false, Some(200), Some("unexpected status"))
        );
        assert_eq!(hits.get(), 2);
        let o = probe(
            &Probe::Tcp {
                port: port(p),
                ipv6: false,
            },
            Duration::from_secs(2),
        )
        .await;
        assert!(o.ok);

        // Nothing listening.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed = l.local_addr().unwrap().port();
        drop(l);
        let o = probe(&http(closed, 200), Duration::from_secs(2)).await;
        assert_eq!(o.error, Some("connection refused"));

        let mut tls = http(p, 200);
        if let Probe::Http { tls: t, .. } = &mut tls {
            *t = true;
        }
        assert_eq!(
            probe(&tls, Duration::from_secs(1)).await.error,
            Some("tls unsupported")
        );
    });
}

struct Rig {
    svc: Rc<HealthService>,
    events: Rc<Events>,
    levels: Rc<Levels>,
    gauges: Rc<Gauges>,
    store: Rc<MemStore>,
}

fn rig() -> Rig {
    let (events, levels, gauges, store) = (
        Rc::new(Events::default()),
        Rc::new(Levels::default()),
        Rc::new(Gauges::default()),
        Rc::new(MemStore::default()),
    );
    let svc = HealthService::new(
        store.clone(),
        events.clone(),
        Some(levels.clone()),
        gauges.clone(),
    );
    Rig {
        svc,
        events,
        levels,
        gauges,
        store,
    }
}

#[test]
fn runner_reports_gauges_events_and_levels() {
    local(async {
        let r = rig();
        let (p, hits) = server("HTTP/1.1 200 OK\r\n\r\n").await;
        let clock = Rc::new(ManualClock::new(1_000_000));
        let dir = tempfile::tempdir().unwrap();
        let mut c = ctx_at(dir.path(), Rc::new(FakeRunner::new()), 0);
        c.clock = clock.clone();
        let set = HealthCheckSet {
            version: 1,
            checks: vec![check("api", http(p, 200)), check("db", http(p, 503))],
        };
        r.svc.update(set.clone(), clock.now_ms()).unwrap();
        assert_eq!(r.store.0.borrow().as_ref(), Some(&set));
        r.svc.run_due(&c).await;
        assert_eq!(hits.get(), 2);
        // First result: only the failure is an event.
        assert_eq!(
            *r.events.0.borrow(),
            vec![Event::HealthCheckChanged {
                check_id: "db".into(),
                ok: false
            }]
        );
        assert_eq!(
            *r.levels.0.borrow(),
            vec![("api".into(), 0), ("db".into(), 1)]
        );
        assert_eq!(r.gauges.0.borrow().get("health.ok:api"), Some(&1.0));
        assert_eq!(r.gauges.0.borrow().get("health.ok:db"), Some(&0.0));
        assert!(r.gauges.0.borrow().contains_key("health.latency:api"));

        // Not due again before the interval.
        clock.advance(Duration::from_secs(4));
        r.svc.run_due(&c).await;
        assert_eq!(hits.get(), 2);
        clock.advance(Duration::from_secs(1));
        r.svc.run_due(&c).await;
        assert_eq!(hits.get(), 4);
        assert_eq!(r.events.0.borrow().len(), 1, "no flip, no event");

        // `db` removed: gauges gone, alert level cleared.
        let set2 = HealthCheckSet {
            version: 2,
            checks: vec![check("api", http(p, 200))],
        };
        r.svc.update(set2, clock.now_ms()).unwrap();
        assert!(!r.gauges.0.borrow().contains_key("health.ok:db"));
        assert_eq!(r.levels.0.borrow().last(), Some(&("db".into(), 0)));
        let res = r.svc.results();
        assert_eq!(res.len(), 1);
        assert_eq!((res[0].id.as_str(), res[0].ok), ("api", true));
    });
}

#[test]
fn handler_versions_and_list() {
    let r = rig();
    let h = HealthOps(r.svc.clone());
    let c = crate::testutil::ctx_empty();
    let set = HealthCheckSet {
        version: 1,
        checks: vec![check("api", http(8080, 200))],
    };
    let op = Op::HealthChecksUpdate(set.clone());
    let mut m = meta(op.clone(), None);
    // Missing / wrong expected version.
    assert_eq!(
        h.validate(&c, &op, &m).unwrap_err().code(),
        ErrorCode::VersionConflict { current: 0 }
    );
    m.command.body.expected_version = Some(0);
    h.validate(&c, &op, &m).unwrap();
    m.audit_seq = Some(1);
    block(h.handle(&c, &op, &m)).unwrap();
    // Replaying the same version conflicts.
    assert_eq!(
        h.validate(&c, &op, &m).unwrap_err().code(),
        ErrorCode::VersionConflict { current: 1 }
    );
    let list = Op::HealthChecksList;
    let out = block(h.handle(&c, &list, &meta(list.clone(), Some(2)))).unwrap();
    let OpOutput::Payload(Payload::HealthChecks(hc)) = out else {
        panic!()
    };
    assert_eq!(hc.config, set);
    assert!(hc.results.is_empty());
}

#[test]
fn file_store_roundtrip() {
    let d = tempfile::tempdir().unwrap();
    let s = FileStore(d.path().join("hc.bin"));
    assert_eq!(s.load().unwrap(), None);
    let set = HealthCheckSet {
        version: 7,
        checks: vec![check("api", http(80, 200))],
    };
    s.save(&set).unwrap();
    assert_eq!(s.load().unwrap(), Some(set));
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(d.path().join("hc.bin"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}
