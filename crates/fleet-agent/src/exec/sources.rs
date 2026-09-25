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
//! - **pollers**: listening ports, certificates, file integrity, the dpkg
//!   log, web access logs (only files that exist), and a persist tick.
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
use fleet_ops::security::bans::{BanState, canonical, default_config};
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
use fleet_ops::{CommandSpec, Registry, SysCtx};
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

// ---- systemd, connected on first use ----

/// The system bus, connected on first use and again after it went away,
/// so exec starts (and serves everything else) without D-Bus. While the
/// bus is unreachable, calls fail with `SdError::Bus` (→ `Internal`) and a
/// new connection is tried at most every [`LazySystemd::COOLDOWN`].
#[derive(Default)]
pub struct LazySystemd {
    conn: RefCell<Option<Rc<ZbusSystemd>>>,
    retry_at: Cell<Option<Instant>>,
}

impl LazySystemd {
    pub const COOLDOWN: Duration = Duration::from_secs(5);

    async fn get(&self) -> Result<Rc<ZbusSystemd>, SdError> {
        if let Some(c) = self.conn.borrow().clone() {
            return Ok(c);
        }
        if self.retry_at.get().is_some_and(|t| Instant::now() < t) {
            return Err(SdError::Bus("system bus unavailable".into()));
        }
        match ZbusSystemd::connect().await {
            Ok(c) => {
                let c = Rc::new(c);
                *self.conn.borrow_mut() = Some(c.clone());
                Ok(c)
            }
            Err(e) => {
                self.retry_at.set(Some(Instant::now() + Self::COOLDOWN));
                Err(e)
            }
        }
    }

    /// Drops the connection (its signal stream ended).
    pub fn reset(&self) {
        self.conn.borrow_mut().take();
    }
}

impl SystemdApi for LazySystemd {
    fn list_units(&self) -> LocalBoxFuture<'_, Result<Vec<RawUnit>, SdError>> {
        Box::pin(async move { self.get().await?.list_units().await })
    }

    fn list_unit_files(&self) -> LocalBoxFuture<'_, Result<Vec<(String, String)>, SdError>> {
        Box::pin(async move { self.get().await?.list_unit_files().await })
    }

    fn unit_props<'a>(&'a self, unit: &'a str) -> LocalBoxFuture<'a, Result<UnitProps, SdError>> {
        Box::pin(async move { self.get().await?.unit_props(unit).await })
    }

    fn run_job<'a>(
        &'a self,
        kind: JobKind,
        unit: &'a str,
        timeout: Duration,
    ) -> LocalBoxFuture<'a, Result<JobResult, SdError>> {
        Box::pin(async move { self.get().await?.run_job(kind, unit, timeout).await })
    }

    fn set_enabled<'a>(
        &'a self,
        unit: &'a str,
        enabled: bool,
    ) -> LocalBoxFuture<'a, Result<(), SdError>> {
        Box::pin(async move { self.get().await?.set_enabled(unit, enabled).await })
    }

    fn watch(&self) -> LocalBoxFuture<'_, Result<Box<dyn UnitWatch>, SdError>> {
        Box::pin(async move { self.get().await?.watch().await })
    }
}

// ---- roster fingerprints ----

/// `SHA256:` fingerprints of the roster's device and monitor SSH keys →
/// device and key (`logins.query`, correlation, `change.confirm`). Rebuilt
/// when the roster changes. The recovery SSH key has no device id and
/// resolves to nothing.
pub(super) struct RosterResolver {
    st: Weak<RefCell<State>>,
    cache: RefCell<RosterFps>,
}

type RosterFps = ((u32, u64), HashMap<String, (DeviceId, KeyRole)>);

impl RosterResolver {
    pub(super) fn role_for(&self, fingerprint: &str) -> Option<(DeviceId, KeyRole)> {
        let st = self.st.upgrade()?;
        let st = st.try_borrow().ok()?;
        let r = &st.roster.roster;
        let mut c = self.cache.borrow_mut();
        if c.0 != (r.epoch, r.version) {
            let fp = |k| Some(ssh_fingerprint(&ecdsa_blob(k)?));
            let mut m = HashMap::new();
            for d in &r.devices {
                // The device key wins if both are the same key.
                if let Some(f) = fp(&d.monitor_ssh_key) {
                    m.insert(f, (d.id, KeyRole::Monitor));
                }
                if let Some(f) = fp(&d.ssh_key) {
                    m.insert(f, (d.id, KeyRole::Device));
                }
            }
            *c = ((r.epoch, r.version), m);
        }
        c.1.get(fingerprint).copied()
    }
}

impl RosterResolver {
    fn new(st: &Rc<RefCell<State>>) -> Self {
        Self {
            st: Rc::downgrade(st),
            cache: RefCell::new(((u32::MAX, u64::MAX), HashMap::new())),
        }
    }
}

impl FingerprintResolver for RosterResolver {
    fn device_for(&self, fingerprint: &str) -> Option<DeviceId> {
        self.role_for(fingerprint).map(|(d, _)| d)
    }
}

// ---- learned Mac addresses: hint ↔ journal correlation ----

#[derive(Debug, Clone, Copy)]
struct Seen {
    ip: IpAddr,
    device: DeviceId,
    t: u64,
}

/// Learns a Mac's address only from two independent sources that agree
/// (design §4.7): exec verified a command from `device` on a session whose
/// bridge reported `ip` (untrusted hint), **and** sshd (uid 0 in the
/// journal) logged `Accepted publickey` from `ip` with that device's roster
/// SSH key, within `window` of each other. Either side alone learns
/// nothing, so a forged hint (anyone can run `fleet-agent bridge` with any
/// `SSH_CONNECTION`) can't exempt an attacker's address.
pub(super) struct Correlator {
    window_ms: u64,
    hints: VecDeque<Seen>,
    accepts: VecDeque<Seen>,
}

/// Entries per side.
const MAX_SEEN: usize = 256;

impl Correlator {
    pub(super) fn new(window: Duration) -> Self {
        Self {
            window_ms: window.as_millis() as u64,
            hints: VecDeque::new(),
            accepts: VecDeque::new(),
        }
    }

    /// A verified command on a session with a hint. `Some(ip)` = learn.
    pub(super) fn hint(&mut self, ip: IpAddr, device: DeviceId, t: u64) -> Option<IpAddr> {
        self.add(false, ip, device, t)
    }

    /// sshd accepted `device`'s roster key from `ip` at journal time `t`.
    pub(super) fn accepted(&mut self, ip: IpAddr, device: DeviceId, t: u64) -> Option<IpAddr> {
        self.add(true, ip, device, t)
    }

    fn add(&mut self, accept: bool, ip: IpAddr, device: DeviceId, t: u64) -> Option<IpAddr> {
        let ip = canonical(ip);
        let w = self.window_ms;
        for q in [&mut self.hints, &mut self.accepts] {
            q.retain(|s| s.t.abs_diff(t) <= 2 * w);
        }
        let (mine, other) = if accept {
            (&mut self.accepts, &mut self.hints)
        } else {
            (&mut self.hints, &mut self.accepts)
        };
        if let Some(i) = other
            .iter()
            .position(|s| s.ip == ip && s.device == device && s.t.abs_diff(t) <= w)
        {
            other.remove(i);
            mine.retain(|s| !(s.ip == ip && s.device == device));
            return Some(ip);
        }
        mine.retain(|s| !(s.ip == ip && s.device == device));
        if mine.len() >= MAX_SEEN {
            mine.pop_front();
        }
        mine.push_back(Seen { ip, device, t });
        None
    }
}

// ---- persistence ----

/// Integrity baseline in exec's `security` table.
struct RedbBaseline(SecurityDb);

impl BaselineStore for RedbBaseline {
    fn load(&self) -> Option<Baseline> {
        let bytes = self
            .0
            .get(SecurityKey::IntegrityBaseline)
            .map_err(|e| log("load integrity baseline", e))
            .ok()??;
        decode(&bytes)
            .map_err(|_| log("load integrity baseline", "corrupt, re-baselining"))
            .ok()
    }

    fn save(&self, b: &Baseline) -> Result<(), OpError> {
        self.0
            .set(SecurityKey::IntegrityBaseline, &encode(b))
            .map_err(OpError::internal)
    }
}

/// Sources of successful logins, for `login.new_source`.
struct KnownSources {
    seen: HashMap<IpAddr, u64>,
    /// False until the first login ever recorded: that one isn't "new".
    primed: bool,
    dirty: bool,
}

impl KnownSources {
    fn load(db: &SecurityDb) -> Self {
        let stored: Option<Vec<(IpAddr, u64)>> = db
            .get(SecurityKey::LoginSources)
            .ok()
            .flatten()
            .and_then(|b| decode(&b).ok());
        Self {
            primed: stored.is_some(),
            seen: stored
                .unwrap_or_default()
                .into_iter()
                .take(MAX_LOGIN_SOURCES)
                .collect(),
            dirty: false,
        }
    }

    /// Records a successful login; whether its source is new.
    fn record(&mut self, ip: IpAddr, t: u64) -> bool {
        let ip = canonical(ip);
        let new = self.primed && !self.seen.contains_key(&ip);
        if self.seen.len() >= MAX_LOGIN_SOURCES
            && !self.seen.contains_key(&ip)
            && let Some(oldest) = self.seen.iter().min_by_key(|(_, t)| **t).map(|(k, _)| *k)
        {
            self.seen.remove(&oldest);
        }
        self.seen.insert(ip, t);
        self.primed = true;
        self.dirty = true;
        new
    }
}

// ---- web access logs ----

/// Poll-based tail of one access log: starts at the end, follows rotation
/// (new inode) and truncation, opens `O_NOFOLLOW` below `/var/log`.
struct LogTail {
    path: String,
    pos: Option<(u64, u64)>,
    partial: Vec<u8>,
}

impl LogTail {
    fn new(path: String) -> Self {
        Self {
            path,
            pos: None,
            partial: Vec::new(),
        }
    }

    fn poll(&mut self, ctx: &SysCtx) -> Vec<Vec<u8>> {
        let Ok((mut f, _)) = open_nofollow(ctx, &self.path) else {
            return Vec::new();
        };
        let Ok(m) = f.metadata() else {
            return Vec::new();
        };
        let offset = match self.pos {
            // First sight: history isn't replayed.
            None => m.len(),
            Some((ino, off)) if ino == m.ino() && m.len() >= off => off,
            Some(_) => {
                self.partial.clear();
                0
            }
        };
        self.pos = Some((m.ino(), offset));
        if m.len() == offset || f.seek(SeekFrom::Start(offset)).is_err() {
            return Vec::new();
        }
        let mut buf = Vec::new();
        let Ok(n) = f.take(WEB_MAX_READ).read_to_end(&mut buf) else {
            return Vec::new();
        };
        self.pos = Some((m.ino(), offset + n as u64));
        self.partial.extend_from_slice(&buf);
        let Some(i) = self.partial.iter().rposition(|&b| b == b'\n') else {
            if self.partial.len() > WEB_MAX_PARTIAL {
                self.partial.clear();
            }
            return Vec::new();
        };
        let done: Vec<u8> = self.partial.drain(..=i).collect();
        if self.partial.len() > WEB_MAX_PARTIAL {
            self.partial.clear();
        }
        done.split(|&b| b == b'\n')
            .filter(|l| !l.is_empty())
            .map(<[u8]>::to_vec)
            .collect()
    }
}

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

    // -- learned addresses --

    /// Exec verified a command from `device` on a normal session whose
    /// bridge sent the hint `ip`.
    pub(super) fn session_verified(self: &Rc<Self>, ip: IpAddr, device: DeviceId) {
        let hit = self.correlator.borrow_mut().hint(ip, device, self.now());
        if let Some(ip) = hit {
            let s = self.clone();
            tokio::task::spawn_local(async move { s.learn(ip).await });
        }
    }

    async fn learn(&self, ip: IpAddr) {
        if let Err(e) = self.bans.fleet_login(&self.ctx, ip, self.now()).await {
            log("learn Mac address", e);
        }
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

    // -- sshd --

    fn follow_args(cursor: Option<&str>) -> Vec<OsString> {
        let mut a: Vec<OsString> = ["-o", "json", "--no-pager", "--quiet", "--follow"]
            .into_iter()
            .map(Into::into)
            .collect();
        a.push(
            format!(
                "--output-fields=MESSAGE,SYSLOG_IDENTIFIER,_PID,{}",
                sshd::TRUST_FIELDS
            )
            .into(),
        );
        a.push(match cursor {
            Some(c) => format!("--after-cursor={c}").into(),
            None => "--lines=0".into(),
        });
        for m in [
            "_UID=0",
            "SYSLOG_IDENTIFIER=sshd",
            "SYSLOG_IDENTIFIER=sshd-session",
        ] {
            a.push(m.into());
        }
        a
    }

    async fn sshd_follower(self: Rc<Self>) {
        let mut delay = self.cfg.backoff_min;
        loop {
            let cursor = self.cursor.borrow().0.clone();
            let spec = CommandSpec::new(JOURNALCTL).args(Self::follow_args(cursor.as_deref()));
            let started = Instant::now();
            match self.cfg.spawner.spawn(spec) {
                Ok(mut src) => {
                    while let Some(Ok(line)) = src.next_line().await {
                        let Some(p) = parse_line(&line) else {
                            continue;
                        };
                        if let Some(c) = p.cursor {
                            *self.cursor.borrow_mut() = (Some(c), true);
                        }
                        if !sshd::trusted_entry(&line) {
                            continue;
                        }
                        let pid = p.entry.pid;
                        if let Some(ev) = parse_sshd(&p.entry.message) {
                            self.on_auth(&ev, pid, p.entry.time_us / 1000).await;
                            self.save_cursor(false);
                        } else if let Some(pid) = pid
                            && sshd::is_disconnect(&p.entry.message)
                        {
                            self.ssh_logins.borrow_mut().closed(pid);
                        }
                    }
                    log("sshd journal follow", "ended; restarting");
                }
                Err(e) => log("sshd journal follow", e),
            }
            if started.elapsed() >= HEALTHY_RUN {
                delay = self.cfg.backoff_min;
            }
            tokio::time::sleep(delay).await;
            delay = self.backoff(delay);
        }
    }

    /// One sshd auth event logged at `t` (journal time) by process `pid`.
    pub(super) async fn on_auth(&self, ev: &AuthEvent, pid: Option<u32>, t: u64) {
        let now = self.now();
        match &ev.kind {
            AuthKind::Accepted {
                method,
                fingerprint,
            } => {
                let role = fingerprint
                    .as_deref()
                    .and_then(|f| self.resolver.role_for(f));
                let device = role.map(|(d, _)| d);
                if *method == LoginMethod::PublicKey
                    && let (Some(pid), Some(fp)) = (pid, fingerprint)
                {
                    self.ssh_logins.borrow_mut().accepted(Login {
                        pid,
                        fingerprint: fp.clone(),
                        device: role,
                        t,
                    });
                }
                let new_source = self.logins.borrow_mut().record(ev.addr, t);
                self.emit(Event::Login {
                    user: ev.user.clone().unwrap_or_default(),
                    source: Some(ev.addr),
                    success: true,
                    new_source,
                    device_id: device,
                });
                // Only the device key vouches for an address: the monitor
                // key opens nothing but read-only sessions.
                if *method == LoginMethod::PublicKey
                    && let Some((d, KeyRole::Device)) = role
                {
                    let hit = self.correlator.borrow_mut().accepted(ev.addr, d, t);
                    if let Some(ip) = hit {
                        self.learn(ip).await;
                    }
                }
            }
            _ if ev.is_failure() => {
                let minute = now / MINUTE_MS;
                let (m, n) = self.failed_events.get();
                let n = if m == minute { n } else { 0 };
                if n < FAILED_LOGIN_EVENTS_PER_MIN {
                    self.failed_events.set((minute, n + 1));
                    self.emit(Event::Login {
                        user: ev.user.clone().unwrap_or_default(),
                        source: Some(ev.addr),
                        success: false,
                        new_source: false,
                        device_id: None,
                    });
                }
                if now.saturating_sub(t) > FRESH_FAILURE_MS {
                    return;
                }
                self.bus.observe(Observation::Occurrence {
                    kind: AlertKind::BruteForce,
                    subject: ev.addr.to_string(),
                });
                if let Err(e) = self.bans.observe_auth(&self.ctx, ev, now).await {
                    log("ban", e);
                }
            }
            _ => {}
        }
    }

    // -- systemd --

    async fn service_events(self: Rc<Self>) {
        let mut delay = self.cfg.backoff_min;
        loop {
            let started = Instant::now();
            match ServiceEvents::start(&*self.systemd).await {
                Ok(mut evs) => {
                    self.seed_service_levels().await;
                    while let Some(e) = evs.next().await {
                        self.emit(e);
                    }
                    log("systemd signals", "ended; resubscribing");
                }
                Err(e) => log("systemd signals", e),
            }
            if let Some(l) = &self.lazy {
                l.reset();
            }
            if started.elapsed() >= HEALTHY_RUN {
                delay = self.cfg.backoff_min;
            }
            tokio::time::sleep(delay).await;
            delay = self.backoff(delay);
        }
    }

    /// Current state of every unit a `ServiceDown` rule watches: a unit
    /// that was already down when exec started never sends a signal.
    async fn seed_service_levels(&self) {
        for unit in self.bus.service_down_units() {
            let down = match self.systemd.unit_props(unit.as_str()).await {
                Ok(p) => unit_down(services::active_state(&p.active_state)),
                Err(SdError::NoSuchUnit) => true,
                Err(_) => continue,
            };
            self.bus.observe(Observation::Level {
                kind: AlertKind::ServiceDown { unit: unit.clone() },
                subject: unit.as_str().to_owned(),
                value: u64::from(down),
            });
        }
    }

    // -- pollers --

    async fn pollers(self: Rc<Self>) {
        use tokio::time::{MissedTickBehavior, interval};
        let tick = |d: Duration| {
            let mut i = interval(d);
            i.set_missed_tick_behavior(MissedTickBehavior::Delay);
            i
        };
        let c = &self.cfg;
        let (mut ports, mut certs, mut integ) = (
            tick(c.ports_every),
            tick(c.certs_every),
            tick(c.integrity_every),
        );
        let (mut dpkg, mut web, mut persist) =
            (tick(c.dpkg_every), tick(c.web_every), tick(c.persist_every));
        loop {
            tokio::select! {
                _ = ports.tick() => self.poll_ports(),
                _ = certs.tick() => self.poll_certs(),
                _ = integ.tick() => self.poll_integrity(),
                _ = dpkg.tick() => {
                    let evs = self.dpkg.borrow_mut().poll();
                    self.dpkg_events(evs, self.fleet_pkg.get() > 0);
                }
                _ = web.tick() => self.poll_web().await,
                _ = persist.tick() => self.persist(),
            }
        }
    }

    fn poll_ports(&self) {
        let p = ports::collect(&self.ctx);
        let eph = ports::ephemeral_range(&self.ctx);
        let evs = self.ports.borrow_mut().observe(&p, eph);
        for e in evs {
            self.emit(e);
        }
    }

    fn poll_certs(&self) {
        let now = self.now();
        let found = certs::collect(&self.ctx, &self.cfg.cert_patterns);
        for c in &found.certs {
            self.bus.observe(Observation::Level {
                kind: AlertKind::CertExpiry,
                subject: c.source.clone(),
                value: c.not_after_ms.saturating_sub(now) / 86_400_000,
            });
        }
        let evs = self.certs.borrow_mut().observe(&found, now);
        for e in evs {
            self.emit(e);
        }
    }

    /// Skipped while a Fleet package op runs (its files are mid-change and
    /// get re-baselined when it ends).
    pub(super) fn poll_integrity(&self) {
        if self.fleet_pkg.get() > 0 {
            return;
        }
        match self.integrity.status(&self.ctx, self.now()) {
            Ok(s) => {
                let evs = self.integrity_watch.borrow_mut().observe(&s.violations);
                for e in evs {
                    self.emit(e);
                }
            }
            Err(e) => log("integrity check", e),
        }
    }

    async fn poll_web(&self) {
        let lines: Vec<Vec<u8>> = self
            .web
            .borrow_mut()
            .iter_mut()
            .flat_map(|t| t.poll(&self.ctx))
            .collect();
        for l in lines {
            let Some(hit) = parse_access_line(&l) else {
                continue;
            };
            if let Err(e) = self.bans.observe_access(&self.ctx, &hit, self.now()).await {
                log("ban", e);
            }
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

    /// Saves the sshd journal cursor if it moved: after each auth event at
    /// most every [`CURSOR_SAVE_EVERY`] (so a restart doesn't replay much
    /// and can't count a failure twice), and on every persist tick.
    fn save_cursor(&self, force: bool) {
        if !force
            && self
                .cursor_saved
                .get()
                .is_some_and(|t| t.elapsed() < CURSOR_SAVE_EVERY)
        {
            return;
        }
        let mut c = self.cursor.borrow_mut();
        if let (Some(cur), true) = (&c.0, c.1) {
            match self.db.set(SecurityKey::SshdCursor, cur.as_bytes()) {
                Ok(()) => {
                    c.1 = false;
                    self.cursor_saved.set(Some(Instant::now()));
                }
                Err(e) => log("persist sshd cursor", e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
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
