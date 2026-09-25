//! Wires `fleet_ops::confighist` into exec: the tracker persists to exec's
//! redb ([`crate::store::ConfigDb`]), its ops join the registry, and
//! `config.changed` events go out through the shared [`EventBus`] (signed,
//! logged, broadcast; queued while the state is busy, oldest dropped
//! first).
//!
//! Attribution uses `Unattributed` until exec tracks the operation in
//! flight (`fleet_ops::confighist::AttributionContext`): pid-less watch
//! events are then `Unknown`, never guessed. Handlers that write tracked
//! files record their own writes with `ConfigTracker::note_write`.

use super::events::EventBus;
use super::log;
use super::state::State;
use fleet_ops::confighist::{ConfigOps, ConfigTracker, Unattributed};
use fleet_ops::{Registry, SysCtx};
use std::cell::RefCell;
use std::rc::Rc;

/// Builds the tracker on exec's database and registers `config.*`. The
/// caller spawns [`ConfigTracker::run`] on the exec `LocalSet`.
pub(super) fn start(
    st: &Rc<RefCell<State>>,
    registry: &mut Registry,
    bus: &Rc<EventBus>,
) -> Option<Rc<ConfigTracker>> {
    let store = Rc::new(st.borrow().store.config());
    match ConfigTracker::new(store, bus.clone(), Rc::new(Unattributed)) {
        Ok(t) => {
            ConfigOps::register(t.clone(), registry);
            Some(t)
        }
        Err(e) => {
            log("config history", e);
            None
        }
    }
}

/// The background task (scan, watch, prune).
pub(super) async fn run(t: Rc<ConfigTracker>, ctx: SysCtx) {
    t.run(ctx, |what, e| log(what, e)).await;
}
