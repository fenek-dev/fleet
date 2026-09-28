//! The sshd follower, learned Mac addresses and login sources.

use super::*;

// ---- roster fingerprints ----

/// `SHA256:` fingerprints of the roster's device and monitor SSH keys →
/// device and key (`logins.query`, correlation, `change.confirm`). Rebuilt
/// when the roster changes. The recovery SSH key has no device id and
/// resolves to nothing.
pub(in crate::exec) struct RosterResolver {
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
    pub(super) fn new(st: &Rc<RefCell<State>>) -> Self {
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
pub(super) struct Seen {
    pub(super) ip: IpAddr,
    pub(super) device: DeviceId,
    pub(super) t: u64,
}

/// Learns a Mac's address only from two independent sources that agree
/// (design §4.7): exec verified a command from `device` on a session whose
/// bridge reported `ip` (untrusted hint), **and** sshd (uid 0 in the
/// journal) logged `Accepted publickey` from `ip` with that device's roster
/// SSH key, within `window` of each other. Either side alone learns
/// nothing, so a forged hint (anyone can run `fleet-agent bridge` with any
/// `SSH_CONNECTION`) can't exempt an attacker's address.
pub(super) struct Correlator {
    pub(super) window_ms: u64,
    pub(super) hints: VecDeque<Seen>,
    pub(super) accepts: VecDeque<Seen>,
}

/// Entries per side.
pub(super) const MAX_SEEN: usize = 256;

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

    pub(super) fn add(
        &mut self,
        accept: bool,
        ip: IpAddr,
        device: DeviceId,
        t: u64,
    ) -> Option<IpAddr> {
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

/// Sources of successful logins, for `login.new_source`.
pub(super) struct KnownSources {
    pub(super) seen: HashMap<IpAddr, u64>,
    /// False until the first login ever recorded: that one isn't "new".
    pub(super) primed: bool,
    pub(super) dirty: bool,
}

impl KnownSources {
    pub(super) fn load(db: &SecurityDb) -> Self {
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
    pub(super) fn record(&mut self, ip: IpAddr, t: u64) -> bool {
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

impl Sources {
    // -- learned addresses --

    /// Exec verified a command from `device` on a normal session whose
    /// bridge sent the hint `ip`.
    pub(in crate::exec) fn session_verified(self: &Rc<Self>, ip: IpAddr, device: DeviceId) {
        let hit = self.correlator.borrow_mut().hint(ip, device, self.now());
        if let Some(ip) = hit {
            let s = self.clone();
            tokio::task::spawn_local(async move { s.learn(ip).await });
        }
    }

    pub(in crate::exec) async fn learn(&self, ip: IpAddr) {
        // Agent-only (design §5.4): never write a learned exemption into
        // the kernel's nft sets.
        if !self.bans_may_apply() {
            return;
        }
        if let Err(e) = self.bans.fleet_login(&self.ctx, ip, self.now()).await {
            log("learn Mac address", e);
        }
    }

    // -- sshd --

    pub(in crate::exec) fn follow_args(cursor: Option<&str>) -> Vec<OsString> {
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

    pub(in crate::exec) async fn sshd_follower(self: Rc<Self>) {
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
    pub(in crate::exec) async fn on_auth(&self, ev: &AuthEvent, pid: Option<u32>, t: u64) {
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
                // Agent-only (design §5.4): the failed-login event above
                // still fires (detection-only), but the engine never
                // decides or applies a ban.
                if self.bans_may_apply()
                    && let Err(e) = self.bans.observe_auth(&self.ctx, ev, now).await
                {
                    log("ban", e);
                }
            }
            _ => {}
        }
    }

    /// Saves the sshd journal cursor if it moved: after each auth event at
    /// most every [`CURSOR_SAVE_EVERY`] (so a restart doesn't replay much
    /// and can't count a failure twice), and on every persist tick.
    pub(in crate::exec) fn save_cursor(&self, force: bool) {
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
