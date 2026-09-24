//! Wires `fleet_ops::telemetry` into exec: the hub persists to exec's redb
//! ([`crate::store::MetricsDb`]), its handlers join the registry, and alert
//! events go out through the [`EventBus`] (signed, broadcast to gates).
//!
//! Other event sources (services, logins, certificates, ports, integrity)
//! feed alert rules through the same bus ([`super::sources`]).

use super::State;
use super::events::EventBus;
use fleet_ops::telemetry::{RealSys, Telemetry, TelemetryOps};
use fleet_ops::{OpHandler, Registry, SysCtx};
use std::cell::RefCell;
use std::rc::Rc;

/// Builds the hub on exec's database, connects it to `bus` and registers
/// its handlers. The caller spawns [`Telemetry::run`] on the exec
/// `LocalSet`.
pub(super) fn start(
    st: &Rc<RefCell<State>>,
    ctx: &SysCtx,
    registry: &mut Registry,
    bus: &Rc<EventBus>,
) -> Rc<Telemetry> {
    let store = Rc::new(st.borrow().store.metrics());
    let tel = Telemetry::new(Rc::new(RealSys::new(ctx.root())), store, bus.clone());
    bus.set_alerts(&tel);
    let ops: Rc<dyn OpHandler> = Rc::new(TelemetryOps(tel.clone()));
    for tag in fleet_ops::telemetry::TAGS {
        registry.register(tag, ops.clone());
    }
    tel
}
