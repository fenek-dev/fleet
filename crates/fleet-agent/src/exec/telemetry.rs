//! Wires `fleet_ops::telemetry` into exec: the hub persists to exec's redb
//! ([`crate::store::MetricsDb`]), its handlers join the registry, and alert
//! events go out through [`State::emit`] (signed, broadcast to gates).
//!
//! Other event sources (services, logins, certificates, docker) feed alert
//! rules through the returned hub's `fleet_ops::telemetry::AlertInput`.

use super::{State, log};
use fleet_ops::telemetry::{AlertSink, RealSys, Telemetry, TelemetryOps};
use fleet_ops::{OpHandler, Registry, SysCtx};
use fleet_proto::Event;
use std::cell::RefCell;
use std::rc::Rc;

/// Most alert events held while exec's state is borrowed elsewhere.
const MAX_QUEUED: usize = 1024;

/// Emits through exec's state. An event raised while the state is
/// borrowed (a source reporting from inside a state operation) is queued
/// and sent with the next one.
struct ExecSink {
    st: Rc<RefCell<State>>,
    queue: RefCell<Vec<Event>>,
}

impl AlertSink for ExecSink {
    fn emit(&self, event: Event) {
        let mut q = self.queue.borrow_mut();
        if q.len() >= MAX_QUEUED {
            log("alert queue", "full, event dropped");
        } else {
            q.push(event);
        }
        if let Ok(mut st) = self.st.try_borrow_mut() {
            for e in q.drain(..) {
                st.emit(e);
            }
        }
    }
}

/// Builds the hub on exec's database and registers its handlers. The
/// caller spawns [`Telemetry::run`] on the exec `LocalSet`.
pub(super) fn start(
    st: &Rc<RefCell<State>>,
    ctx: &SysCtx,
    registry: &mut Registry,
) -> Rc<Telemetry> {
    let store = Rc::new(st.borrow().store.metrics());
    let sink = Rc::new(ExecSink {
        st: st.clone(),
        queue: RefCell::default(),
    });
    let tel = Telemetry::new(Rc::new(RealSys::new(ctx.root())), store, sink);
    let ops: Rc<dyn OpHandler> = Rc::new(TelemetryOps(tel.clone()));
    for tag in fleet_ops::telemetry::TAGS {
        registry.register(tag, ops.clone());
    }
    tel
}
