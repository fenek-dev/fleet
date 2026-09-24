//! Exec's one event bus (design §4.5).
//!
//! Every event source reports here: `fleet_ops` detectors through
//! [`EventSink`], the telemetry hub's alert engine through [`AlertSink`].
//! Each event is signed and broadcast to connected gates ([`State::emit`]);
//! events that are also alert inputs ([`observations`]) are then fed to the
//! hub as [`Observation`]s, so a `ServiceDown`/`NewListeningPort`/… rule
//! fires right after the event that caused it. Alert events coming back
//! from the hub are only emitted (never re-observed).
//!
//! The bus holds the hub weakly (the hub holds the bus as its sink), so
//! dropping exec's tasks frees both, and with them the database.

use super::{State, log};
use fleet_ops::Clock;
use fleet_ops::security::EventSink;
use fleet_ops::telemetry::{AlertInput, AlertSink, Observation, Telemetry};
use fleet_proto::Event;
use fleet_proto::alert::AlertKind;
use fleet_proto::args::UnitName;
use fleet_proto::payload::UnitActiveState;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::{Rc, Weak};

/// Most events held while exec's state is borrowed elsewhere.
const MAX_QUEUED: usize = 1024;

pub(super) struct EventBus {
    st: Rc<RefCell<State>>,
    clock: Rc<dyn Clock>,
    queue: RefCell<VecDeque<Event>>,
    alerts: RefCell<Weak<Telemetry>>,
}

impl EventBus {
    pub(super) fn new(st: Rc<RefCell<State>>, clock: Rc<dyn Clock>) -> Rc<Self> {
        Rc::new(Self {
            st,
            clock,
            queue: RefCell::default(),
            alerts: RefCell::new(Weak::new()),
        })
    }

    /// Connects the alert engine (created with this bus as its sink).
    pub(super) fn set_alerts(&self, tel: &Rc<Telemetry>) {
        *self.alerts.borrow_mut() = Rc::downgrade(tel);
    }

    /// An alert input that isn't an event of its own (a failed SSH login,
    /// a certificate's days left, a unit's current state).
    pub(super) fn observe(&self, obs: Observation) {
        let tel = self.alerts.borrow().upgrade();
        if let Some(t) = tel {
            t.observe(obs, self.clock.now_ms());
        }
    }

    /// Units named by enabled `ServiceDown` rules.
    pub(super) fn service_down_units(&self) -> Vec<UnitName> {
        let tel = self.alerts.borrow().upgrade();
        let Some(t) = tel else {
            return Vec::new();
        };
        t.rules()
            .rules
            .into_iter()
            .filter(|r| r.enabled)
            .filter_map(|r| match r.kind {
                AlertKind::ServiceDown { unit } => Some(unit),
                _ => None,
            })
            .collect()
    }

    /// Signs and broadcasts. An event raised while the state is borrowed
    /// (a source reporting from inside a state operation) is queued and
    /// sent with the next one or at [`EventBus::flush`].
    fn publish(&self, event: Event) {
        {
            let mut q = self.queue.borrow_mut();
            if q.len() >= MAX_QUEUED {
                log("event queue", "full, oldest event dropped");
                q.pop_front();
            }
            q.push_back(event);
        }
        self.flush();
    }

    pub(super) fn flush(&self) {
        let Ok(mut st) = self.st.try_borrow_mut() else {
            return;
        };
        loop {
            let next = self.queue.borrow_mut().pop_front();
            match next {
                Some(e) => st.emit(e),
                None => break,
            }
        }
    }
}

impl AlertSink for EventBus {
    fn emit(&self, event: Event) {
        self.publish(event);
    }
}

impl EventSink for EventBus {
    fn emit(&self, event: Event) {
        let obs = observations(&event);
        self.publish(event);
        for o in obs {
            self.observe(o);
        }
    }
}

/// Alert-rule inputs carried by an event (design §4.5). Failed logins and
/// certificate levels are observed by their sources directly.
pub(super) fn observations(e: &Event) -> Vec<Observation> {
    let occ = |kind, subject: String| vec![Observation::Occurrence { kind, subject }];
    match e {
        Event::ServiceStateChanged { unit, to, .. } => {
            let Ok(name) = UnitName::new(unit.clone()) else {
                return Vec::new();
            };
            vec![Observation::Level {
                kind: AlertKind::ServiceDown { unit: name },
                subject: unit.clone(),
                value: u64::from(unit_down(*to)),
            }]
        }
        Event::NewListeningPort {
            proto, addr, port, ..
        } => occ(
            AlertKind::NewListeningPort,
            format!("{proto:?}/{addr}:{port}").to_lowercase(),
        ),
        Event::UserChanged { name, .. } => occ(AlertKind::UserChange, name.clone()),
        Event::AuthorizedKeysChanged { user, .. } => {
            occ(AlertKind::AuthorizedKeysChange, user.clone())
        }
        Event::IntegrityViolation { path, .. } => occ(AlertKind::IntegrityViolation, path.clone()),
        Event::Login {
            success: true,
            new_source: true,
            source: Some(ip),
            ..
        } => occ(AlertKind::LoginNewSource, ip.to_string()),
        _ => Vec::new(),
    }
}

/// `ServiceDown` holds for failed and inactive units (design §4.5).
pub(super) fn unit_down(s: UnitActiveState) -> bool {
    matches!(s, UnitActiveState::Failed | UnitActiveState::Inactive)
}
