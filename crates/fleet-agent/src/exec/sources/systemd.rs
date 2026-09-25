//! systemd over the system bus: the lazy connection and service events.

use super::*;

// ---- systemd, connected on first use ----

/// The system bus, connected on first use and again after it went away,
/// so exec starts (and serves everything else) without D-Bus. While the
/// bus is unreachable, calls fail with `SdError::Bus` (→ `Internal`) and a
/// new connection is tried at most every [`LazySystemd::COOLDOWN`].
#[derive(Default)]
pub struct LazySystemd {
    conn: RefCell<Option<Rc<ZbusSystemd>>>,
    retry_at: Cell<Option<Instant>>,
    /// Single flight: concurrent first users wait for one connect instead
    /// of each opening a bus connection.
    connecting: tokio::sync::Mutex<()>,
}

impl LazySystemd {
    pub const COOLDOWN: Duration = Duration::from_secs(5);

    async fn get(&self) -> Result<Rc<ZbusSystemd>, SdError> {
        if let Some(c) = self.conn.borrow().clone() {
            return Ok(c);
        }
        let _one = self.connecting.lock().await;
        // Someone else may have connected (or failed) while we waited.
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

impl Sources {
    // -- systemd --

    pub(in crate::exec) async fn service_events(self: Rc<Self>) {
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
    pub(in crate::exec) async fn seed_service_levels(&self) {
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
}
