//! `docker` group (design §2.5, §4.2, §9.6).
//!
//! - Engine operations go through [`DockerApi`]: the Docker Engine API over
//!   `/var/run/docker.sock` ([`BollardDocker`], `bollard` with the Unix
//!   socket transport only; no TCP, no TLS). The admin user is not in the
//!   `docker` group; only exec talks to the socket. Tests use
//!   [`FakeDocker`].
//! - Streams: `docker.logs` ([`streams::LogsStream`]: `tail` ≤ 10000,
//!   optional `since`, follow or bounded; lines ≤ 16 KiB, chunks ≤ 256
//!   lines) and `docker.stats` ([`streams::StatsStream`], `latest_only`,
//!   one item every 2 s, CPU and rates from exec's own deltas of one-shot
//!   samples).
//! - `docker.containers.get` returns the inspect JSON with every
//!   `Config.Env` value redacted (secrets live there).
//! - Container events feed `Event::Container` and the `ContainerDown` rule
//!   ([`events::watch`], spawned by exec).
//! - Compose projects (`compose.*`) run the `docker compose` CLI through the
//!   runner: see [`project`].
//! - Image update checks are Mac-side: the Mac compares registry digests
//!   with `docker.images.list` `digests` and fills
//!   `ComposeService::update_available`; the agent never talks to
//!   registries except through `docker pull`.
//!
//! All text from Docker is untrusted and clipped.

mod bollard_api;
pub mod events;
mod fake;
pub mod project;
pub mod streams;
#[cfg(test)]
mod tests;

pub use bollard_api::BollardDocker;
pub use fake::FakeDocker;

use crate::ctx::SysCtx;
use crate::handler::{Invocation, LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, Registry};
use fleet_proto::args::{ContainerRef, Protocol};
use fleet_proto::op::tag;
use fleet_proto::payload::{
    ContainerDetail, ContainerInfo, ContainerState, Containers, ImageInfo, Images, LogStream,
    NetworkInfo, Networks, Pruned, PublishedPort, VolumeInfo, Volumes,
};
use fleet_proto::{ErrorCode, Op, Payload};
use futures_util::stream::LocalBoxStream;
use std::rc::Rc;
use std::time::Duration;

pub type DockerResult<T> = Result<T, DockerError>;
pub type DockerStream<T> = LocalBoxStream<'static, DockerResult<T>>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DockerError {
    #[error("not found: {0}")]
    NotFound(String),
    /// 409: e.g. removing a running container without `force`, an image in
    /// use.
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("docker unavailable: {0}")]
    Unavailable(String),
    #[error("timed out")]
    Timeout,
    #[error("{0}")]
    Other(String),
}

impl From<DockerError> for OpError {
    fn from(e: DockerError) -> Self {
        let code = match e {
            DockerError::NotFound(_) => ErrorCode::NotFound,
            DockerError::Conflict(_) => ErrorCode::Busy,
            DockerError::Timeout => ErrorCode::Timeout,
            DockerError::Unavailable(_) | DockerError::Other(_) => ErrorCode::Internal,
        };
        OpError::new(code).with_detail(clip(&e.to_string(), 300))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogOptions {
    pub tail: u32,
    /// Unix seconds.
    pub since_s: Option<i64>,
    pub follow: bool,
}

/// One multiplexed log frame (usually one line, with its timestamp prefix).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogFrame {
    pub stream: LogStream,
    pub bytes: Vec<u8>,
}

/// Cumulative counters of one stats sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RawStats {
    pub cpu_total_ns: u64,
    pub system_cpu_ns: u64,
    pub online_cpus: u32,
    pub mem_usage: u64,
    /// `inactive_file` (page cache the kernel can drop), subtracted like
    /// `docker stats` does.
    pub mem_inactive_file: u64,
    pub mem_limit: u64,
    pub net_rx: u64,
    pub net_tx: u64,
    pub blk_read: u64,
    pub blk_write: u64,
    pub pids: u64,
}

/// A container event from `/events`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerEvent {
    pub id: String,
    pub name: String,
    /// Docker's action text (`die`, `health_status: unhealthy`, …).
    pub action: String,
    pub exit_code: Option<i32>,
}

/// The Docker Engine API surface exec uses. Implementations must not
/// follow redirects to other hosts or talk TCP.
pub trait DockerApi {
    fn list_containers(&self, all: bool) -> LocalBoxFuture<'_, DockerResult<Vec<ContainerInfo>>>;
    /// Raw inspect JSON.
    fn inspect_container<'a>(
        &'a self,
        id: &'a str,
    ) -> LocalBoxFuture<'a, DockerResult<serde_json::Value>>;
    fn start<'a>(&'a self, id: &'a str) -> LocalBoxFuture<'a, DockerResult<()>>;
    fn stop<'a>(&'a self, id: &'a str, timeout_s: u16) -> LocalBoxFuture<'a, DockerResult<()>>;
    fn restart<'a>(&'a self, id: &'a str, timeout_s: u16) -> LocalBoxFuture<'a, DockerResult<()>>;
    fn remove<'a>(&'a self, id: &'a str, force: bool) -> LocalBoxFuture<'a, DockerResult<()>>;
    fn logs(&self, id: &str, opts: LogOptions) -> DockerStream<LogFrame>;
    /// One sample without waiting for a second one (`one-shot`).
    fn stats_once<'a>(&'a self, id: &'a str) -> LocalBoxFuture<'a, DockerResult<RawStats>>;
    fn list_images(&self) -> LocalBoxFuture<'_, DockerResult<Vec<ImageInfo>>>;
    fn pull_image<'a>(&'a self, image: &'a str) -> LocalBoxFuture<'a, DockerResult<()>>;
    fn remove_image<'a>(
        &'a self,
        image: &'a str,
        force: bool,
    ) -> LocalBoxFuture<'a, DockerResult<()>>;
    fn prune_images(&self, all_unused: bool) -> LocalBoxFuture<'_, DockerResult<Pruned>>;
    fn list_volumes(&self) -> LocalBoxFuture<'_, DockerResult<Vec<VolumeInfo>>>;
    fn remove_volume<'a>(&'a self, name: &'a str) -> LocalBoxFuture<'a, DockerResult<()>>;
    fn list_networks(&self) -> LocalBoxFuture<'_, DockerResult<Vec<NetworkInfo>>>;
    /// Container events from now on (never ends unless the daemon goes).
    fn events(&self) -> DockerStream<ContainerEvent>;
}

// ---- conversions shared by the real and fake APIs ----

pub(crate) fn clip(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

pub fn container_state(s: &str) -> ContainerState {
    match s.to_ascii_lowercase().as_str() {
        "created" => ContainerState::Created,
        "running" => ContainerState::Running,
        "paused" => ContainerState::Paused,
        "restarting" => ContainerState::Restarting,
        "removing" => ContainerState::Removing,
        "exited" => ContainerState::Exited,
        "dead" => ContainerState::Dead,
        _ => ContainerState::Other,
    }
}

pub fn protocol(s: &str) -> Option<Protocol> {
    match s {
        "tcp" => Some(Protocol::Tcp),
        "udp" => Some(Protocol::Udp),
        _ => None,
    }
}

/// Days since 1970-01-01 (H. Hinnant).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// RFC 3339 (`2024-01-02T03:04:05.123456789Z` or `…+02:00`) → Unix ms.
/// Docker's zero time (`0001-01-01T00:00:00Z`) and garbage → `None`.
pub fn parse_rfc3339_ms(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u32> { s.get(r)?.parse().ok() };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut rest = &s[19..];
    let mut ms = 0u64;
    if let Some(frac) = rest.strip_prefix('.') {
        let n = frac.bytes().take_while(u8::is_ascii_digit).count();
        let digits = &frac[..n];
        let first3: String = digits.chars().chain("000".chars()).take(3).collect();
        ms = first3.parse().ok()?;
        rest = &frac[n..];
    }
    let offset_s: i64 = match rest {
        "Z" | "z" => 0,
        _ => {
            let sign = match rest.as_bytes().first()? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let (oh, om) = rest[1..].split_once(':')?;
            sign * (oh.parse::<i64>().ok()? * 3600 + om.parse::<i64>().ok()? * 60)
        }
    };
    let days = days_from_civil(i64::from(y), mo, d);
    let secs = days * 86_400 + i64::from(h) * 3600 + i64::from(mi) * 60 + i64::from(sec) - offset_s;
    let secs = u64::try_from(secs).ok().filter(|&s| s > 0)?;
    Some(secs * 1000 + ms)
}

const MAX_INSPECT: usize = 256 * 1024;

/// `docker.containers.get`: redacts `Config.Env` values (keeps names),
/// builds [`ContainerInfo`] from inspect fields, clips the JSON.
pub fn detail_from_inspect(mut v: serde_json::Value) -> ContainerDetail {
    if let Some(env) = v
        .pointer_mut("/Config/Env")
        .and_then(serde_json::Value::as_array_mut)
    {
        for e in env.iter_mut() {
            let name = e
                .as_str()
                .map(|s| s.split_once('=').map_or(s, |(n, _)| n).to_owned())
                .unwrap_or_default();
            *e = serde_json::Value::String(format!("{name}=<redacted>"));
        }
    }
    let s = |p: &str| {
        v.pointer(p)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
    };
    let mut ports = Vec::new();
    if let Some(map) = v
        .pointer("/NetworkSettings/Ports")
        .and_then(serde_json::Value::as_object)
    {
        for (k, binds) in map {
            let Some((port, proto)) = k.split_once('/') else {
                continue;
            };
            let (Ok(container_port), Some(proto)) = (port.parse::<u16>(), protocol(proto)) else {
                continue;
            };
            for b in binds.as_array().into_iter().flatten() {
                let host_port = b
                    .get("HostPort")
                    .and_then(|p| p.as_str())
                    .and_then(|p| p.parse().ok());
                let Some(host_port) = host_port else {
                    continue;
                };
                ports.push(PublishedPort {
                    host_ip: b
                        .get("HostIp")
                        .and_then(|p| p.as_str())
                        .and_then(|p| p.parse().ok()),
                    host_port,
                    container_port,
                    proto,
                });
            }
        }
    }
    let info = ContainerInfo {
        id: clip(s("/Id"), 128),
        name: clip(s("/Name").trim_start_matches('/'), 256),
        image: clip(s("/Config/Image"), 512),
        state: container_state(s("/State/Status")),
        status: clip(s("/State/Status"), 256),
        created_ms: parse_rfc3339_ms(s("/Created")).unwrap_or(0),
        ports,
        compose_project: v
            .pointer("/Config/Labels/com.docker.compose.project")
            .and_then(|p| p.as_str())
            .map(|p| clip(p, 256)),
    };
    let mut inspect_json = v.to_string();
    if inspect_json.len() > MAX_INSPECT {
        let mut cut = MAX_INSPECT;
        while !inspect_json.is_char_boundary(cut) {
            cut -= 1;
        }
        inspect_json.truncate(cut);
    }
    ContainerDetail { info, inspect_json }
}

pub fn container_ref(r: &ContainerRef) -> &str {
    match r {
        ContainerRef::Id(id) => id.as_str(),
        ContainerRef::Name(n) => n.as_str(),
    }
}

const T_PULL: Duration = Duration::from_secs(30 * 60);

/// Engine operations of the `docker` group (not `compose.*`).
pub struct DockerHandler {
    pub api: Rc<dyn DockerApi>,
}

impl DockerHandler {
    async fn request(&self, op: &Op) -> Result<Payload, OpError> {
        let api = &self.api;
        Ok(match op {
            Op::DockerContainersList { all } => Payload::Containers(Containers {
                containers: api.list_containers(*all).await?,
            }),
            Op::DockerContainersGet { container } => Payload::ContainerDetail(detail_from_inspect(
                api.inspect_container(container_ref(container)).await?,
            )),
            Op::DockerContainersStart { container } => {
                api.start(container_ref(container)).await?;
                Payload::Empty
            }
            Op::DockerContainersStop {
                container,
                timeout_s,
            } => {
                api.stop(container_ref(container), *timeout_s).await?;
                Payload::Empty
            }
            Op::DockerContainersRestart {
                container,
                timeout_s,
            } => {
                api.restart(container_ref(container), *timeout_s).await?;
                Payload::Empty
            }
            Op::DockerContainersRemove { container, force } => {
                api.remove(container_ref(container), *force).await?;
                Payload::Empty
            }
            Op::DockerImagesList => Payload::Images(Images {
                images: api.list_images().await?,
            }),
            Op::DockerImagesPull { image } => {
                tokio::time::timeout(T_PULL, api.pull_image(image.as_str()))
                    .await
                    .map_err(|_| OpError::new(ErrorCode::Timeout))??;
                Payload::Empty
            }
            Op::DockerImagesRemove { image, force } => {
                api.remove_image(image.as_str(), *force).await?;
                Payload::Empty
            }
            Op::DockerImagesPrune { all_unused } => {
                Payload::Pruned(api.prune_images(*all_unused).await?)
            }
            Op::DockerVolumesList => Payload::Volumes(Volumes {
                volumes: api.list_volumes().await?,
            }),
            Op::DockerVolumesRemove { volume } => {
                api.remove_volume(volume.as_str()).await?;
                Payload::Empty
            }
            Op::DockerNetworksList => Payload::Networks(Networks {
                networks: api.list_networks().await?,
            }),
            _ => return Err(ErrorCode::Unsupported.into()),
        })
    }
}

impl OpHandler for DockerHandler {
    fn supports(&self, op: &Op, invocation: Invocation) -> bool {
        let stream = matches!(op, Op::DockerLogs { .. } | Op::DockerStats { .. });
        stream == (invocation == Invocation::Stream)
    }

    fn validate(&self, _ctx: &SysCtx, op: &Op, _meta: &OpMeta) -> Result<(), OpError> {
        match op {
            Op::DockerLogs { tail, .. } if *tail > 10_000 => {
                Err(OpError::new(ErrorCode::InvalidArgument).with_detail("tail"))
            }
            Op::DockerStats { containers } if containers.len() > 256 => {
                Err(OpError::new(ErrorCode::InvalidArgument).with_detail("containers"))
            }
            _ => Ok(()),
        }
    }

    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        op: &'a Op,
        _meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            match op {
                Op::DockerLogs {
                    container,
                    tail,
                    since_ms,
                    follow,
                } => {
                    let opts = LogOptions {
                        tail: *tail,
                        since_s: since_ms.map(|ms| i64::try_from(ms / 1000).unwrap_or(i64::MAX)),
                        follow: *follow,
                    };
                    let inner = self.api.logs(container_ref(container), opts);
                    Ok(OpOutput::Stream(Box::new(streams::LogsStream::new(inner))))
                }
                Op::DockerStats { containers } => {
                    let filter = containers
                        .iter()
                        .map(|c| container_ref(c).to_owned())
                        .collect();
                    Ok(OpOutput::Stream(Box::new(streams::StatsStream::new(
                        self.api.clone(),
                        ctx.clock.clone(),
                        filter,
                    ))))
                }
                _ => self.request(op).await.map(OpOutput::Payload),
            }
        })
    }
}

/// Registers the engine handler for every `docker.*` tag. Exec also spawns
/// [`events::watch`] with the same `api`.
pub fn register(r: &mut Registry, api: Rc<dyn DockerApi>) {
    let h: Rc<dyn OpHandler> = Rc::new(DockerHandler { api });
    for t in [
        tag::DOCKER_CONTAINERS_LIST,
        tag::DOCKER_CONTAINERS_GET,
        tag::DOCKER_CONTAINERS_START,
        tag::DOCKER_CONTAINERS_STOP,
        tag::DOCKER_CONTAINERS_RESTART,
        tag::DOCKER_CONTAINERS_REMOVE,
        tag::DOCKER_LOGS,
        tag::DOCKER_STATS,
        tag::DOCKER_IMAGES_LIST,
        tag::DOCKER_IMAGES_PULL,
        tag::DOCKER_IMAGES_REMOVE,
        tag::DOCKER_IMAGES_PRUNE,
        tag::DOCKER_VOLUMES_LIST,
        tag::DOCKER_VOLUMES_REMOVE,
        tag::DOCKER_NETWORKS_LIST,
    ] {
        r.register(t, h.clone());
    }
    project::register(r);
}
