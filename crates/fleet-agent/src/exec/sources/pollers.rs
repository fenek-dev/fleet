//! Pollers: ports, certificates, integrity, dpkg log, web access logs.

use super::*;

// ---- persistence ----

/// Integrity baseline in exec's `security` table.
pub(super) struct RedbBaseline(pub(super) SecurityDb);

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

// ---- web access logs ----

/// Poll-based tail of one access log: starts at the end, follows rotation
/// (new inode) and truncation, opens `O_NOFOLLOW` below `/var/log`.
pub(super) struct LogTail {
    pub(super) path: String,
    pub(super) pos: Option<(u64, u64)>,
    pub(super) partial: Vec<u8>,
}

impl LogTail {
    pub(super) fn new(path: String) -> Self {
        Self {
            path,
            pos: None,
            partial: Vec::new(),
        }
    }

    pub(super) fn poll(&mut self, ctx: &SysCtx) -> Vec<Vec<u8>> {
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

impl Sources {
    // -- pollers --

    pub(in crate::exec) async fn pollers(self: Rc<Self>) {
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
        let mut addrs = tick(c.own_addrs_every);
        loop {
            tokio::select! {
                _ = addrs.tick() => self.refresh_web_config(),
                _ = ports.tick() => self.poll_ports().await,
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

    /// New listening ports, with `blocked` from Fleet's firewall model
    /// when the table is Fleet-rendered (unknown → `false`). Loopback
    /// listeners are never blocked by it.
    pub(in crate::exec) async fn poll_ports(&self) {
        let p = ports::collect(&self.ctx);
        let eph = ports::ephemeral_range(&self.ctx);
        let mut evs = self.ports.borrow_mut().observe(&p, eph);
        if !evs.is_empty() {
            let model = match firewall::table_from(
                self.ctx.runner.run(firewall::list_table_spec()).await,
            ) {
                Ok(firewall::Table::Present(t)) => t.model,
                _ => None,
            };
            if let Some(m) = model {
                let ssh = firewall::model::ssh_ports_lenient(&self.ctx);
                for e in &mut evs {
                    if let Event::NewListeningPort {
                        proto,
                        addr,
                        port,
                        blocked,
                        ..
                    } = e
                    {
                        *blocked = !addr.is_loopback()
                            && firewall::model::port_blocked(&m, &ssh, *proto, *port);
                    }
                }
            }
        }
        for e in evs {
            self.emit(e);
        }
    }

    /// Re-reads the web-ban opt-in file and the host's own addresses.
    pub(in crate::exec) fn refresh_web_config(&self) {
        let sources =
            match fleet_ops::fswrite::read_regular(&self.ctx, &self.cfg.web_bans_conf, 64 * 1024) {
                Ok(Some(b)) => parse_web_bans(&String::from_utf8_lossy(&b), &self.cfg.web_logs),
                Ok(None) => Vec::new(),
                Err(e) => {
                    log("web bans config", e);
                    Vec::new()
                }
            };
        self.bans.set_web_sources(sources);
        self.bans
            .set_own_addrs(fleet_ops::security::ownaddrs::collect(&self.ctx));
    }

    pub(in crate::exec) fn poll_certs(&self) {
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
    pub(in crate::exec) fn poll_integrity(&self) {
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

    /// Scanner hits ban only from logs opted in by `web_bans_conf`
    /// (`BanService::observe_access_from` checks the path).
    pub(in crate::exec) async fn poll_web(&self) {
        let lines: Vec<(String, Vec<u8>)> = self
            .web
            .borrow_mut()
            .iter_mut()
            .flat_map(|t| {
                let path = t.path.clone();
                t.poll(&self.ctx)
                    .into_iter()
                    .map(move |l| (path.clone(), l))
            })
            .collect();
        for (path, l) in lines {
            let Some(hit) = parse_access_line(&l) else {
                continue;
            };
            // Agent-only (design §5.4): web-log scanning never bans.
            // Rechecked per line, not once for the whole batch — the
            // policy can switch mid-poll on a long queue.
            if !self.bans_may_apply() {
                continue;
            }
            let r = self
                .bans
                .observe_access_from(&self.ctx, std::path::Path::new(&path), &hit, self.now())
                .await;
            if let Err(e) = r {
                log("ban", e);
            }
        }
    }
}
