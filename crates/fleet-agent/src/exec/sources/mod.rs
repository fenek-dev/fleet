//! Exec's background event sources and the stateful security handlers
//! (design §4.5–§4.7).
//!
//! Everything runs on exec's `LocalSet` and reports through the
//! [`EventBus`]:
//!
//! - **sshd follower**: `journalctl --follow -o json _UID=0
//!   SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sshd-session` (resuming after
//!   the persisted cursor, saved at most every second) → `parse_sshd` →
//!   [`BanService`], `login` events, `BruteForce` observations, the
//!   accepted-publickey side of the learned-address correlation
//!   ([`Correlator`]) and the pid ↔ key table ([`sshd::Logins`]) used by
//!   `change.confirm` and session termination. Each line must also pass
//!   [`sshd::trusted_entry`]: `_UID=0`, `_COMM` sshd/sshd-session or unit
//!   ssh(d).service, and no `CONTAINER_ID`. These are trusted journal
//!   fields: a local user can log with `SYSLOG_IDENTIFIER=sshd` (`logger -t
//!   sshd`) but not as uid 0 or as sshd, and dockerd (root) forwarding a
//!   container's `sshd` output adds `CONTAINER_ID`, so forged lines can
//!   neither ban an address nor vouch for a Mac's.
//! - **systemd signals**: [`ServiceEvents`] over the lazily connected bus
//!   ([`LazySystemd`]); `ServiceDown` rules are seeded with each watched
//!   unit's current state on every (re)subscribe.
//! - **pollers**: listening ports (`blocked` from Fleet's firewall model),
//!   certificates, file integrity, the dpkg log, web access logs (only
//!   files that exist; scanner hits ban only from logs opted in through
//!   `web_bans_conf`), the host's own addresses (never banned from a web
//!   log) and a persist tick.
//!
//! Followers restart with exponential backoff. Memory is bounded (line
//! length, correlation tables, known login sources, failed-login event
//! rate). Every state change is synchronous, so dropping any task at an
//! await point loses nothing but the work in flight.

use super::events::{EventBus, unit_down};
use super::sshd::{self, KeyRole, Login, Logins};
use super::{State, log};
use crate::authorized_keys::ecdsa_blob;
use crate::store::{SecurityDb, SecurityKey};
use fleet_ops::handler::{LocalBoxFuture, OpError};
use fleet_ops::logs::journal::{JOURNALCTL, parse_line};
use fleet_ops::logs::lines::LineSpawner;
use fleet_ops::logs::logfile::open_nofollow;
use fleet_ops::packages::DpkgLogWatcher;
use fleet_ops::security::authlog::{AuthEvent, AuthKind};
use fleet_ops::security::bans::{
    BanState, WEB_BANS_CONF, canonical, default_config, parse_web_bans,
};
use fleet_ops::security::integrity::{Baseline, package_paths};
use fleet_ops::security::webscan::parse_access_line;
use fleet_ops::security::{
    BanService, BaselineStore, CertWatcher, EventSink, FingerprintResolver, IntegrityHandler,
    IntegrityWatcher, LearnedMacIps, LoginsHandler, PortWatcher, certs, parse_sshd, ports,
    ssh_fingerprint,
};
use fleet_ops::services::{
    self, JobKind, JobResult, RawUnit, SdError, ServiceEvents, SystemdApi, UnitProps, UnitWatch,
    ZbusSystemd,
};
use fleet_ops::telemetry::Observation;
use fleet_ops::{CommandSpec, Registry, SysCtx, firewall};
use fleet_proto::alert::AlertKind;
use fleet_proto::op::tag;
use fleet_proto::payload::LoginMethod;
use fleet_proto::{DeviceId, Event, decode, encode};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::ffi::OsString;
use std::io::{Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::rc::{Rc, Weak};
use std::time::{Duration, Instant};

const MINUTE_MS: u64 = 60_000;
/// Failed-login `login` events per minute (brute force is thousands).
const FAILED_LOGIN_EVENTS_PER_MIN: u32 = 30;
/// Failures older than this (journal backlog after a restart) neither ban
/// nor count toward `BruteForce`.
const FRESH_FAILURE_MS: u64 = 10 * MINUTE_MS;
/// Known successful-login sources kept (for `new_source`).
const MAX_LOGIN_SOURCES: usize = 1024;
/// Web access-log bytes read per poll, and the longest partial line kept.
const WEB_MAX_READ: u64 = 1 << 20;
const WEB_MAX_PARTIAL: usize = 64 * 1024;
/// A follower that ran this long restarts with the minimum backoff.
const HEALTHY_RUN: Duration = Duration::from_secs(60);
/// The sshd journal cursor is saved at most this often.
const CURSOR_SAVE_EVERY: Duration = Duration::from_secs(1);

/// Background sources and their inputs (production defaults from
/// [`SourcesConfig::system`]).
pub struct SourcesConfig {
    /// Run the background tasks. The handlers (`bans.*`, `integrity.status`,
    /// `logins.query`, `unit.*`) are registered either way.
    pub enabled: bool,
    pub spawner: Rc<dyn LineSpawner>,
    /// `None`: the real system bus through [`LazySystemd`].
    pub systemd: Option<Rc<dyn SystemdApi>>,
    pub ports_every: Duration,
    pub certs_every: Duration,
    pub integrity_every: Duration,
    pub dpkg_every: Duration,
    pub web_every: Duration,
    /// Ban expiry and persistence of ban state, login sources, cursor.
    pub persist_every: Duration,
    pub backoff_min: Duration,
    pub backoff_max: Duration,
    /// JSON access logs tailed when they exist (web role).
    pub web_logs: Vec<String>,
    /// Opt-in file naming which of `web_logs` may ban
    /// (`fleet_ops::security::bans::WEB_BANS_CONF`, under the context
    /// root); absent means web bans are off.
    pub web_bans_conf: String,
    /// Re-read of that file and of the host's own addresses (never banned
    /// from a web log).
    pub own_addrs_every: Duration,
    pub integrity_paths: Vec<String>,
    pub cert_patterns: Vec<String>,
    /// Journal accept ↔ session hint distance for learning (design §4.7).
    pub correlation_window: Duration,
}

impl SourcesConfig {
    pub fn system() -> Self {
        Self {
            enabled: true,
            spawner: Rc::new(fleet_ops::logs::SystemLineSpawner),
            systemd: None,
            ports_every: Duration::from_secs(60),
            certs_every: Duration::from_secs(6 * 3600),
            integrity_every: Duration::from_secs(15 * 60),
            dpkg_every: Duration::from_secs(5),
            web_every: Duration::from_secs(2),
            persist_every: Duration::from_secs(30),
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(300),
            web_logs: vec![
                "/var/log/caddy/access.log".into(),
                "/var/log/nginx/access.log".into(),
            ],
            web_bans_conf: WEB_BANS_CONF.into(),
            own_addrs_every: Duration::from_secs(300),
            integrity_paths: fleet_ops::security::integrity::DEFAULT_CRITICAL
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            cert_patterns: certs::DEFAULT_PATTERNS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            correlation_window: Duration::from_secs(60),
        }
    }
}

mod pollers;
mod ssh;
mod systemd;

use pollers::{LogTail, RedbBaseline};
pub(super) use ssh::RosterResolver;
use ssh::{Correlator, KnownSources};
pub use systemd::LazySystemd;

// ---- the sources ----

pub(super) struct Sources {
    cfg: SourcesConfig,
    ctx: SysCtx,
    bus: Rc<EventBus>,
    pub(super) bans: Rc<BanService>,
    db: SecurityDb,
    integrity: Rc<IntegrityHandler>,
    integrity_watch: RefCell<IntegrityWatcher>,
    ports: RefCell<PortWatcher>,
    certs: RefCell<CertWatcher>,
    dpkg: RefCell<DpkgLogWatcher>,
    web: RefCell<Vec<LogTail>>,
    /// Fleet package ops running now (their dpkg changes re-baseline).
    fleet_pkg: Cell<u32>,
    correlator: RefCell<Correlator>,
    resolver: Rc<RosterResolver>,
    logins: RefCell<KnownSources>,
    /// (minute, failed-login events sent in it).
    failed_events: Cell<(u64, u32)>,
    saved_ban_rev: Cell<u64>,
    /// (cursor, not yet saved).
    cursor: RefCell<(Option<String>, bool)>,
    cursor_saved: Cell<Option<Instant>>,
    /// Public-key logins by sshd pid (shared with the session terminator
    /// and `change.confirm`).
    pub(super) ssh_logins: Rc<RefCell<Logins>>,
    systemd: Rc<dyn SystemdApi>,
    lazy: Option<Rc<LazySystemd>>,
}

/// Marks a Fleet package op; on drop, reads the dpkg log right away and
/// re-baselines the integrity entries of the packages it changed.
pub(super) struct FleetPkgOp(Rc<Sources>);

impl Drop for FleetPkgOp {
    fn drop(&mut self) {
        let s = &self.0;
        s.fleet_pkg.set(s.fleet_pkg.get().saturating_sub(1));
        let evs = s.dpkg.borrow_mut().poll();
        s.dpkg_events(evs, true);
    }
}

impl Sources {
    /// Loads persisted state (bans, known login sources, journal cursor).
    pub(super) fn new(
        st: &Rc<RefCell<State>>,
        ctx: &SysCtx,
        bus: Rc<EventBus>,
        cfg: SourcesConfig,
        ssh_logins: Rc<RefCell<Logins>>,
    ) -> Rc<Self> {
        let db = st.borrow().store.security();
        let now = ctx.clock.now_ms();
        let bans = BanService::new(default_config(), bus.clone());
        match db.get(SecurityKey::Bans) {
            Ok(Some(b)) => match decode::<BanState>(&b) {
                Ok(s) => bans.import(s, now),
                Err(_) => log("load bans", "corrupt record, starting empty"),
            },
            Ok(None) => {}
            Err(e) => log("load bans", e),
        }
        let cursor = db
            .get(SecurityKey::SshdCursor)
            .ok()
            .flatten()
            .and_then(|b| String::from_utf8(b).ok())
            .filter(|c| c.len() <= 512 && c.bytes().all(|b| b.is_ascii_graphic()));
        let (systemd, lazy): (Rc<dyn SystemdApi>, _) = match &cfg.systemd {
            Some(s) => (s.clone(), None),
            None => {
                let l = Rc::new(LazySystemd::default());
                (l.clone(), Some(l))
            }
        };
        let integrity = Rc::new(IntegrityHandler::new(
            Rc::new(RedbBaseline(db.clone())),
            cfg.integrity_paths.clone(),
        ));
        Rc::new(Self {
            web: RefCell::new(cfg.web_logs.iter().cloned().map(LogTail::new).collect()),
            correlator: RefCell::new(Correlator::new(cfg.correlation_window)),
            cfg,
            ctx: ctx.clone(),
            bus,
            saved_ban_rev: Cell::new(bans.revision()),
            bans,
            integrity,
            integrity_watch: RefCell::default(),
            ports: RefCell::default(),
            certs: RefCell::default(),
            dpkg: RefCell::new(DpkgLogWatcher::new(ctx)),
            fleet_pkg: Cell::new(0),
            resolver: Rc::new(RosterResolver::new(st)),
            logins: RefCell::new(KnownSources::load(&db)),
            failed_events: Cell::new((0, 0)),
            cursor: RefCell::new((cursor, false)),
            cursor_saved: Cell::new(None),
            ssh_logins,
            db,
            systemd,
            lazy,
        })
    }

    /// `bans.*`, `integrity.status`, `logins.query` (roster resolver),
    /// `unit.*` (systemd).
    pub(super) fn register(&self, r: &mut Registry) {
        self.bans.register(r);
        r.register(tag::INTEGRITY_STATUS, self.integrity.clone());
        r.register(
            tag::LOGINS_QUERY,
            Rc::new(LoginsHandler::new(
                self.cfg.spawner.clone(),
                self.resolver.clone(),
            )),
        );
        services::register(r, self.systemd.clone());
    }

    /// Spawns every background task on the current `LocalSet`.
    pub(super) fn spawn(self: &Rc<Self>) {
        if !self.cfg.enabled {
            return;
        }
        let s = self.clone();
        tokio::task::spawn_local(async move {
            let n = s.bans.restore_kernel(&s.ctx, s.ctx.clock.now_ms()).await;
            if n > 0 {
                log("bans", format!("restored {n} kernel set elements"));
            }
        });
        self.refresh_web_config();
        tokio::task::spawn_local(self.clone().sshd_follower());
        tokio::task::spawn_local(self.clone().service_events());
        tokio::task::spawn_local(self.clone().pollers());
    }

    fn emit(&self, e: Event) {
        EventSink::emit(&*self.bus, e);
    }

    fn now(&self) -> u64 {
        self.ctx.clock.now_ms()
    }

    fn backoff(&self, d: Duration) -> Duration {
        (d * 2).clamp(self.cfg.backoff_min, self.cfg.backoff_max)
    }

    // -- package ops --

    pub(super) fn fleet_pkg_op(self: &Rc<Self>) -> FleetPkgOp {
        self.fleet_pkg.set(self.fleet_pkg.get() + 1);
        FleetPkgOp(self.clone())
    }

    fn dpkg_events(&self, evs: Vec<Event>, by_fleet: bool) {
        if by_fleet {
            let names: Vec<String> = evs
                .iter()
                .filter_map(|e| match e {
                    Event::PackagesChanged { changes } => Some(changes),
                    _ => None,
                })
                .flatten()
                .map(|c| c.name.clone())
                .collect();
            let paths = package_paths(&self.ctx, &names, self.integrity.paths());
            if let Err(e) = self.integrity.rebaseline(&self.ctx, &paths) {
                log("integrity re-baseline", e);
            }
        }
        for e in evs {
            self.emit(e);
        }
    }

    /// Expires bans; saves what changed (ban state, login sources, journal
    /// cursor); sends events queued while the state was busy. Also runs
    /// once more at shutdown.
    pub(super) fn persist(&self) {
        self.bans.expire(self.now());
        let rev = self.bans.revision();
        if rev != self.saved_ban_rev.get() {
            match self
                .db
                .set(SecurityKey::Bans, &encode(&self.bans.export(self.now())))
            {
                Ok(()) => self.saved_ban_rev.set(rev),
                Err(e) => log("persist bans", e),
            }
        }
        let mut l = self.logins.borrow_mut();
        if l.dirty {
            let v: Vec<(IpAddr, u64)> = l.seen.iter().map(|(k, v)| (*k, *v)).collect();
            match self.db.set(SecurityKey::LoginSources, &encode(&v)) {
                Ok(()) => l.dirty = false,
                Err(e) => log("persist login sources", e),
            }
        }
        drop(l);
        self.save_cursor(true);
        self.bus.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::ssh::MAX_SEEN;
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn correlation_needs_both_sides_in_window() {
        let (a, b) = (DeviceId([1; 16]), DeviceId([2; 16]));
        let mut c = Correlator::new(Duration::from_secs(60));
        let t = 1_000_000;
        // Hint alone, accept alone, or a mismatch learns nothing.
        assert_eq!(c.hint(ip("203.0.113.5"), a, t), None);
        assert_eq!(c.accepted(ip("203.0.113.6"), a, t), None);
        assert_eq!(c.accepted(ip("203.0.113.5"), b, t), None);
        // Too far apart.
        assert_eq!(c.accepted(ip("203.0.113.5"), a, t + 61_000), None);
        // Accept first, hint within the window (mapped IPv6 is the same).
        let mut c = Correlator::new(Duration::from_secs(60));
        assert_eq!(c.accepted(ip("198.51.100.1"), a, t), None);
        assert_eq!(
            c.hint(ip("::ffff:198.51.100.1"), a, t + 59_000),
            Some(ip("198.51.100.1"))
        );
        // Consumed: a second hint needs a new accept.
        assert_eq!(c.hint(ip("198.51.100.1"), a, t + 59_500), None);
        assert_eq!(
            c.accepted(ip("198.51.100.1"), a, t + 60_000),
            Some(ip("198.51.100.1"))
        );
        // Bounded.
        let mut c = Correlator::new(Duration::from_secs(60));
        for i in 0..1000u32 {
            c.hint(IpAddr::from(i.to_be_bytes()), a, t);
        }
        assert_eq!(c.hints.len(), MAX_SEEN);
    }

    #[test]
    fn known_sources_prime_and_bound() {
        let mut k = KnownSources {
            seen: HashMap::new(),
            primed: false,
            dirty: false,
        };
        assert!(!k.record(ip("203.0.113.5"), 1));
        assert!(!k.record(ip("203.0.113.5"), 2));
        assert!(k.record(ip("203.0.113.6"), 3));
        for i in 0..2000u32 {
            k.record(IpAddr::from(i.to_be_bytes()), 10 + u64::from(i));
        }
        assert_eq!(k.seen.len(), MAX_LOGIN_SOURCES);
    }

    #[test]
    fn follow_args_filter_on_uid_0() {
        let a = Sources::follow_args(Some("s=abc;i=1"));
        let a: Vec<String> = a.iter().map(|s| s.to_string_lossy().into()).collect();
        assert!(a.contains(&"--after-cursor=s=abc;i=1".to_owned()));
        assert!(a.contains(&"_UID=0".to_owned()));
        assert!(a.contains(&"--follow".to_owned()));
        // The fields `sshd::trusted_entry` checks are requested.
        let fields = a
            .iter()
            .find(|s| s.starts_with("--output-fields="))
            .unwrap();
        for f in ["_UID", "_COMM", "_SYSTEMD_UNIT", "CONTAINER_ID", "_PID"] {
            assert!(fields.contains(f), "{f}");
        }
        let a = Sources::follow_args(None);
        assert!(a.iter().any(|s| s == "--lines=0"));
    }
}
