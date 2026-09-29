//! Op families whose handlers need exec's state, event bus or telemetry
//! hub, and their background tasks:
//!
//! - `users.*` with the real event sink (`user.changed`,
//!   `authorized_keys.changed` events);
//! - `docker.*` / `compose.*` on one shared [`DockerApi`], which also
//!   feeds `docker::events::watch` (container events, `ContainerDown`);
//! - `shell.exec` gated by the current policy (`shell_exec`,
//!   `shell_exec_users`);
//! - `health_checks.*` and the probe runner (store in exec's directory,
//!   results as gauges, events and alert levels);
//! - `game.*` and the game scheduler (player gauges, scheduled restarts).
//!
//! `mesh.*` is generic (`Registry::with_generic`, `MeshRevert` in
//! `Reverters::with_generic`).

use super::State;
use super::events::EventBus;
use crate::paths::Paths;
use fleet_ops::docker::{BollardDocker, DockerApi};
use fleet_ops::game::GameService;
use fleet_ops::health::{FileStore, HealthService};
use fleet_ops::security::EventSink;
use fleet_ops::shell::ShellPolicy;
use fleet_ops::telemetry::{AlertInput, Telemetry};
use fleet_ops::{Registry, SysCtx};
use std::cell::RefCell;
use std::rc::Rc;

/// `shell.exec` targets from the policy in force (re-read per command).
pub(super) struct PolicyShell(pub Rc<RefCell<State>>);

impl ShellPolicy for PolicyShell {
    fn may_run_as(&self, user: &str) -> bool {
        let st = self.0.borrow();
        let caps = &st.policy.capabilities;
        caps.shell_exec && caps.shell_exec_users.iter().any(|u| u == user)
    }
}

/// Background parts, spawned by [`Wired::spawn`].
pub(super) struct Wired {
    docker: Rc<dyn DockerApi>,
    sink: Rc<dyn EventSink>,
    alerts: Rc<dyn AlertInput>,
    health: Rc<HealthService>,
    games: Rc<GameService>,
}

pub(super) fn start(
    st: &Rc<RefCell<State>>,
    paths: &Paths,
    registry: &mut Registry,
    bus: &Rc<EventBus>,
    tel: &Rc<Telemetry>,
) -> Wired {
    let sink: Rc<dyn EventSink> = bus.clone();
    let alerts: Rc<dyn AlertInput> = tel.clone();
    fleet_ops::users::register(registry, sink.clone());
    // `reboot.scheduled` through the event bus.
    fleet_ops::reboot::register(registry, sink.clone());
    let docker: Rc<dyn DockerApi> = Rc::new(BollardDocker::new());
    fleet_ops::docker::register(registry, docker.clone());
    fleet_ops::shell::register(registry, Rc::new(PolicyShell(st.clone())));
    let health = HealthService::new(
        Rc::new(FileStore(paths.exec_dir.join("health-checks.bin"))),
        sink.clone(),
        Some(alerts.clone()),
        tel.clone(),
    );
    fleet_ops::health::register(registry, health.clone());
    let games = GameService::builtin(tel.clone());
    fleet_ops::game::register(registry, games.clone());
    Wired {
        docker,
        sink,
        alerts,
        health,
        games,
    }
}

impl Wired {
    /// Spawns the docker event watch, the health runner and the game
    /// scheduler on the current `LocalSet`.
    pub(super) fn spawn(&self, ctx: &SysCtx) {
        tokio::task::spawn_local(fleet_ops::docker::events::watch(
            self.docker.clone(),
            self.sink.clone(),
            Some(self.alerts.clone()),
            ctx.clock.clone(),
        ));
        tokio::task::spawn_local(self.health.clone().run(ctx.clone()));
        tokio::task::spawn_local(self.games.clone().run(ctx.clone()));
    }
}
