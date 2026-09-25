//! `security` group (design §2.4, §4.6, §4.7): login history, intrusion
//! blocking, listening ports, TLS certificates, file integrity.
//!
//! Detectors are pure (`observe(...) -> Vec<Event>` or a [`BanService`]
//! call per parsed event); exec owns the timers and followers that feed
//! them and forwards events through an [`EventSink`].
//!
//! `audit.run` is not registered here: it runs the hardening modules'
//! `check` (later phase), so exec answers `Unsupported` until then.

pub mod authlog;
pub mod bans;
pub mod certs;
pub mod integrity;
pub mod logins;
pub mod ownaddrs;
pub mod ports;
pub mod utmp;
pub mod webscan;

pub use authlog::{AuthEvent, AuthKind, parse_sshd};
pub use bans::{BanEngine, BanService, BanState, BansHandler, LearnedMacIps};
pub use certs::{CertWatcher, CertsHandler};
pub use integrity::{BaselineStore, IntegrityHandler, IntegrityWatcher, MemoryBaselineStore};
pub use logins::{FingerprintResolver, LoginsHandler, NoResolver, ssh_fingerprint};
pub use ports::{PortWatcher, PortsHandler};

use crate::handler::Registry;
use crate::logs::SystemLineSpawner;
use fleet_proto::Event;
use fleet_proto::op::tag;
use std::cell::RefCell;
use std::rc::Rc;

/// Where detectors send events (exec's event log; the alert lane's sink
/// adapts to this).
pub trait EventSink {
    fn emit(&self, event: Event);
}

/// Drops events.
pub struct NullSink;

impl EventSink for NullSink {
    fn emit(&self, _event: Event) {}
}

/// Collects events (tests, batching).
#[derive(Default)]
pub struct VecSink(RefCell<Vec<Event>>);

impl VecSink {
    pub fn take(&self) -> Vec<Event> {
        std::mem::take(&mut self.0.borrow_mut())
    }
}

impl EventSink for VecSink {
    fn emit(&self, event: Event) {
        self.0.borrow_mut().push(event);
    }
}

/// Registers the stateless `security` handlers (`logins.query`,
/// `ports.list`, `certs.list`). Stateful ones are registered by exec with
/// its state: [`BanService::register`] and an [`IntegrityHandler`] on
/// `tag::INTEGRITY_STATUS` with exec's [`BaselineStore`].
pub fn register(r: &mut Registry, resolver: Rc<dyn FingerprintResolver>) {
    r.register(
        tag::LOGINS_QUERY,
        Rc::new(LoginsHandler::new(Rc::new(SystemLineSpawner), resolver)),
    );
    r.register(tag::PORTS_LIST, Rc::new(PortsHandler));
    r.register(tag::CERTS_LIST, Rc::new(CertsHandler::default()));
}
