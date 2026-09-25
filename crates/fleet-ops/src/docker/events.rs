//! Docker container events → `Event::Container` and the `ContainerDown`
//! alert level. Health-check `exec_*` events and other noise are dropped.

use super::{ContainerEvent, DockerApi, DockerStream, clip};
use crate::ctx::Clock;
use crate::security::EventSink;
use crate::telemetry::{AlertInput, Observation};
use fleet_proto::alert::AlertKind;
use fleet_proto::args::ContainerName;
use fleet_proto::{ContainerAction, Event};
use futures_util::StreamExt;
use std::rc::Rc;
use std::time::Duration;

/// Known actions only; everything else (exec_*, attach, rename, …) is
/// `None` and not reported.
pub fn action(a: &str) -> Option<ContainerAction> {
    Some(match a {
        "create" => ContainerAction::Create,
        "start" => ContainerAction::Start,
        "stop" => ContainerAction::Stop,
        "die" => ContainerAction::Die,
        "oom" => ContainerAction::Oom,
        "restart" => ContainerAction::Restart,
        "destroy" => ContainerAction::Destroy,
        "health_status: unhealthy" => ContainerAction::Unhealthy,
        "health_status: healthy" => ContainerAction::Healthy,
        _ => return None,
    })
}

pub fn to_event(e: &ContainerEvent) -> Option<Event> {
    Some(Event::Container {
        id: clip(&e.id, 128),
        name: clip(&e.name, 256),
        action: action(&e.action)?,
        exit_code: e.exit_code,
    })
}

/// `ContainerDown` level: 1 when it stopped, died, OOMed or turned
/// unhealthy; 0 when it (re)started or turned healthy. Removal clears it.
pub fn observation(e: &ContainerEvent) -> Option<Observation> {
    let value = match action(&e.action)? {
        ContainerAction::Die
        | ContainerAction::Stop
        | ContainerAction::Oom
        | ContainerAction::Unhealthy => 1,
        ContainerAction::Start
        | ContainerAction::Restart
        | ContainerAction::Healthy
        | ContainerAction::Destroy => 0,
        _ => return None,
    };
    let name = ContainerName::new(e.name.clone()).ok()?;
    Some(Observation::Level {
        kind: AlertKind::ContainerDown { name },
        subject: clip(&e.name, 256),
        value,
    })
}

/// Consumes `events` until it ends or fails; returns how many events were
/// forwarded.
pub async fn pump(
    mut events: DockerStream<ContainerEvent>,
    sink: &dyn EventSink,
    alerts: Option<&dyn AlertInput>,
    clock: &dyn Clock,
) -> usize {
    let mut n = 0;
    while let Some(Ok(e)) = events.next().await {
        if let Some(ev) = to_event(&e) {
            sink.emit(ev);
            n += 1;
        }
        if let (Some(a), Some(o)) = (alerts, observation(&e)) {
            a.observe(o, clock.now_ms());
        }
    }
    n
}

/// Runs forever: subscribes to container events and re-subscribes with
/// backoff (5 s doubling to 5 min) when Docker is absent or restarts.
/// Exec spawns this on its `LocalSet` next to the docker handlers.
pub async fn watch(
    api: Rc<dyn DockerApi>,
    sink: Rc<dyn EventSink>,
    alerts: Option<Rc<dyn AlertInput>>,
    clock: Rc<dyn Clock>,
) {
    let mut backoff = Duration::from_secs(5);
    loop {
        let n = pump(api.events(), &*sink, alerts.as_deref(), &*clock).await;
        if n > 0 {
            backoff = Duration::from_secs(5);
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(300));
    }
}
