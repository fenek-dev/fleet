//! Wires `fleet_ops::confighist` into exec: the tracker persists to exec's
//! redb ([`crate::store::ConfigDb`]), its ops join the registry, and
//! `config.changed` events go out through the shared [`EventBus`] (signed,
//! logged, broadcast; queued while the state is busy, oldest dropped
//! first).
//!
//! Attribution is exec's [`ExecAttribution`]: pid-less watch events on a
//! path announced by a running (or just finished) exec operation are
//! `Fleet { op, seq }`; everything else is `Unknown`, never guessed.
//! Handlers that write tracked files may also record their own writes with
//! `ConfigTracker::note_write`.

use super::attribution::ExecAttribution;
use super::events::EventBus;
use super::log;
use super::state::State;
use fleet_ops::confighist::{ConfigOps, ConfigTracker};
use fleet_ops::{Registry, SysCtx};
use std::cell::RefCell;
use std::rc::Rc;

/// Builds the tracker on exec's database and registers `config.*`. The
/// caller spawns [`ConfigTracker::run`] on the exec `LocalSet`.
pub(super) fn start(
    st: &Rc<RefCell<State>>,
    registry: &mut Registry,
    bus: &Rc<EventBus>,
    attribution: Rc<ExecAttribution>,
) -> Option<Rc<ConfigTracker>> {
    let store = Rc::new(st.borrow().store.config());
    match ConfigTracker::new(store, bus.clone(), attribution) {
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
