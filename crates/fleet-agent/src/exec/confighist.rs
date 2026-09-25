//! Wires `fleet_ops::confighist` into exec: the tracker persists to exec's
//! redb ([`crate::store::ConfigDb`]), its ops join the registry, and
//! `config.changed` events go out through [`State::emit`].
//!
//! Attribution uses `Unattributed` until exec tracks the operation in
//! flight (`fleet_ops::confighist::AttributionContext`): pid-less watch
//! events are then `Unknown`, never guessed. Handlers that write tracked
//! files record their own writes with `ConfigTracker::note_write`.

use super::{State, log};
use fleet_ops::confighist::{ConfigOps, ConfigTracker, Unattributed};
use fleet_ops::security::EventSink;
use fleet_ops::{Registry, SysCtx};
use fleet_proto::Event;
use std::cell::RefCell;
use std::rc::Rc;

/// Most events held while exec's state is borrowed elsewhere.
const MAX_QUEUED: usize = 1024;

struct StateSink {
    st: Rc<RefCell<State>>,
    queue: RefCell<Vec<Event>>,
}

impl EventSink for StateSink {
    fn emit(&self, event: Event) {
        let mut q = self.queue.borrow_mut();
        if q.len() >= MAX_QUEUED {
            log("config event queue", "full, event dropped");
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

/// Builds the tracker on exec's database and registers `config.*`. The
/// caller spawns [`ConfigTracker::run`] on the exec `LocalSet`.
pub(super) fn start(st: &Rc<RefCell<State>>, registry: &mut Registry) -> Option<Rc<ConfigTracker>> {
    let store = Rc::new(st.borrow().store.config());
    let sink = Rc::new(StateSink {
        st: st.clone(),
        queue: RefCell::default(),
    });
    match ConfigTracker::new(store, sink, Rc::new(Unattributed)) {
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
