//! [`DockerApi`] over `/var/run/docker.sock` with `bollard` (Unix socket
//! transport only). Connects lazily, so exec starts on servers without
//! Docker and every call answers `Internal` ("docker unavailable") there.

use super::{
    ContainerEvent, DockerApi, DockerError, DockerResult, DockerStream, LogFrame, LogOptions,
    RawStats, clip, container_state, protocol,
};
use crate::handler::LocalBoxFuture;
use bollard::Docker;
use bollard::container::LogOutput;
use bollard::errors::Error as BError;
use bollard::models::{ContainerStatsResponse, ContainerSummary, EventMessageTypeEnum};
use bollard::query_parameters::{
    CreateImageOptions, EventsOptions, ListContainersOptions, LogsOptions, PruneImagesOptions,
    RemoveContainerOptions, RemoveImageOptions, RestartContainerOptions, StatsOptions,
    StopContainerOptions,
};
use fleet_proto::payload::{
    ContainerInfo, ImageInfo, LogStream, NetworkInfo, Pruned, PublishedPort, VolumeInfo,
};
use futures_util::{StreamExt, TryStreamExt};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

pub const DOCKER_SOCKET: &str = "/var/run/docker.sock";
/// Request timeout (response headers; streamed bodies aren't limited).
const TIMEOUT_S: u64 = 120;

pub struct BollardDocker {
    socket: String,
    conn: RefCell<Option<Docker>>,
}

impl Default for BollardDocker {
    fn default() -> Self {
        Self::new()
    }
}

impl BollardDocker {
    pub fn new() -> Self {
        Self::with_socket(DOCKER_SOCKET)
    }

    pub fn with_socket(path: &str) -> Self {
        Self {
            socket: path.to_owned(),
            conn: RefCell::new(None),
        }
    }

    fn docker(&self) -> DockerResult<Docker> {
        if let Some(d) = self.conn.borrow().as_ref() {
            return Ok(d.clone());
        }
        let d = Docker::connect_with_unix(&self.socket, TIMEOUT_S, bollard::API_DEFAULT_VERSION)
            .map_err(|e| DockerError::Unavailable(e.to_string()))?;
        *self.conn.borrow_mut() = Some(d.clone());
        Ok(d)
    }
}

fn map_err(e: BError) -> DockerError {
    match e {
        BError::DockerResponseServerError {
            status_code,
            message,
        } => match status_code {
            404 => DockerError::NotFound(clip(&message, 300)),
            409 => DockerError::Conflict(clip(&message, 300)),
            _ => DockerError::Other(format!("{status_code}: {}", clip(&message, 300))),
        },
        BError::RequestTimeoutError => DockerError::Timeout,
        BError::SocketNotFoundError(s) => DockerError::Unavailable(s),
        BError::HyperResponseError { .. } | BError::IOError { .. } => {
            DockerError::Unavailable(clip(&e.to_string(), 300))
        }
        other => DockerError::Other(clip(&other.to_string(), 300)),
    }
}

/// 304 "already started/stopped" is success.
fn not_modified_ok(r: Result<(), BError>) -> DockerResult<()> {
    match r {
        Err(BError::DockerResponseServerError {
            status_code: 304, ..
        }) => Ok(()),
        r => r.map_err(map_err),
    }
}

fn i64_u64(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

pub(super) fn container_info(c: &ContainerSummary) -> ContainerInfo {
    let ports = c
        .ports
        .iter()
        .flatten()
        .filter_map(|p| {
            Some(PublishedPort {
                host_ip: p.ip.as_deref().and_then(|ip| ip.parse().ok()),
                host_port: p.public_port?,
                container_port: p.private_port,
                proto: protocol(p.typ.as_ref()?.as_ref())?,
            })
        })
        .collect();
    let name = c
        .names
        .as_ref()
        .and_then(|n| n.first())
        .map(|n| n.trim_start_matches('/'))
        .unwrap_or_default();
    ContainerInfo {
        id: clip(c.id.as_deref().unwrap_or_default(), 128),
        name: clip(name, 256),
        image: clip(c.image.as_deref().unwrap_or_default(), 512),
        state: c
            .state
            .as_ref()
            .map_or(fleet_proto::payload::ContainerState::Other, |s| {
                container_state(s.as_ref())
            }),
        status: clip(c.status.as_deref().unwrap_or_default(), 256),
        created_ms: i64_u64(c.created.unwrap_or(0)).saturating_mul(1000),
        ports,
        compose_project: c
            .labels
            .as_ref()
            .and_then(|l| l.get("com.docker.compose.project"))
            .map(|p| clip(p, 256)),
    }
}

pub(super) fn raw_stats(s: &ContainerStatsResponse) -> RawStats {
    let cpu = s.cpu_stats.as_ref();
    let mem = s.memory_stats.as_ref();
    let inactive = mem
        .and_then(|m| m.stats.as_ref())
        .and_then(|m| {
            m.get("inactive_file")
                .or_else(|| m.get("total_inactive_file"))
        })
        .copied()
        .unwrap_or(0);
    let (mut rx, mut tx) = (0u64, 0u64);
    for n in s.networks.iter().flat_map(|m| m.values()) {
        rx = rx.saturating_add(n.rx_bytes.unwrap_or(0));
        tx = tx.saturating_add(n.tx_bytes.unwrap_or(0));
    }
    let (mut rd, mut wr) = (0u64, 0u64);
    for e in s
        .blkio_stats
        .as_ref()
        .and_then(|b| b.io_service_bytes_recursive.as_ref())
        .into_iter()
        .flatten()
    {
        let v = e.value.unwrap_or(0);
        match e.op.as_deref().map(str::to_ascii_lowercase).as_deref() {
            Some("read") => rd = rd.saturating_add(v),
            Some("write") => wr = wr.saturating_add(v),
            _ => {}
        }
    }
    RawStats {
        cpu_total_ns: cpu
            .and_then(|c| c.cpu_usage.as_ref())
            .and_then(|u| u.total_usage)
            .unwrap_or(0),
        system_cpu_ns: cpu.and_then(|c| c.system_cpu_usage).unwrap_or(0),
        online_cpus: cpu.and_then(|c| c.online_cpus).unwrap_or(1),
        mem_usage: mem.and_then(|m| m.usage).unwrap_or(0),
        mem_inactive_file: inactive,
        mem_limit: mem.and_then(|m| m.limit).unwrap_or(0),
        net_rx: rx,
        net_tx: tx,
        blk_read: rd,
        blk_write: wr,
        pids: s.pids_stats.as_ref().and_then(|p| p.current).unwrap_or(0),
    }
}

/// `fromImage` without a tag pulls every tag: default to `latest`.
pub(super) fn pull_parts(image: &str) -> (String, Option<String>) {
    let last = image.rsplit('/').next().unwrap_or(image);
    if image.contains('@') || last.contains(':') {
        (image.to_owned(), None)
    } else {
        (image.to_owned(), Some("latest".to_owned()))
    }
}

impl DockerApi for BollardDocker {
    fn list_containers(&self, all: bool) -> LocalBoxFuture<'_, DockerResult<Vec<ContainerInfo>>> {
        Box::pin(async move {
            let d = self.docker()?;
            let opts = ListContainersOptions {
                all,
                ..Default::default()
            };
            let v = d.list_containers(Some(opts)).await.map_err(map_err)?;
            Ok(v.iter().map(container_info).collect())
        })
    }

    fn inspect_container<'a>(
        &'a self,
        id: &'a str,
    ) -> LocalBoxFuture<'a, DockerResult<serde_json::Value>> {
        Box::pin(async move {
            let d = self.docker()?;
            let r = d.inspect_container(id, None).await.map_err(map_err)?;
            serde_json::to_value(r).map_err(|e| DockerError::Other(e.to_string()))
        })
    }

    fn start<'a>(&'a self, id: &'a str) -> LocalBoxFuture<'a, DockerResult<()>> {
        Box::pin(async move { not_modified_ok(self.docker()?.start_container(id, None).await) })
    }

    fn stop<'a>(&'a self, id: &'a str, timeout_s: u16) -> LocalBoxFuture<'a, DockerResult<()>> {
        Box::pin(async move {
            // The daemon answers after the container stopped: allow for it.
            let d = self
                .docker()?
                .with_timeout(Duration::from_secs(u64::from(timeout_s) + TIMEOUT_S));
            let opts = StopContainerOptions {
                t: Some(i32::from(timeout_s)),
                ..Default::default()
            };
            not_modified_ok(d.stop_container(id, Some(opts)).await)
        })
    }

    fn restart<'a>(&'a self, id: &'a str, timeout_s: u16) -> LocalBoxFuture<'a, DockerResult<()>> {
        Box::pin(async move {
            let d = self
                .docker()?
                .with_timeout(Duration::from_secs(u64::from(timeout_s) + TIMEOUT_S));
            let opts = RestartContainerOptions {
                t: Some(i32::from(timeout_s)),
                ..Default::default()
            };
            d.restart_container(id, Some(opts)).await.map_err(map_err)
        })
    }

    fn remove<'a>(&'a self, id: &'a str, force: bool) -> LocalBoxFuture<'a, DockerResult<()>> {
        Box::pin(async move {
            let opts = RemoveContainerOptions {
                force,
                ..Default::default()
            };
            self.docker()?
                .remove_container(id, Some(opts))
                .await
                .map_err(map_err)
        })
    }

    fn logs(&self, id: &str, opts: LogOptions) -> DockerStream<LogFrame> {
        let d = match self.docker() {
            Ok(d) => d,
            Err(e) => return Box::pin(futures_util::stream::once(async move { Err(e) })),
        };
        let o = LogsOptions {
            follow: opts.follow,
            stdout: true,
            stderr: true,
            since: opts
                .since_s
                .map_or(0, |s| i32::try_from(s).unwrap_or(i32::MAX)),
            timestamps: true,
            tail: opts.tail.to_string(),
            ..Default::default()
        };
        Box::pin(d.logs(id, Some(o)).map(|r| {
            r.map_err(map_err).map(|o| match o {
                LogOutput::StdErr { message } => LogFrame {
                    stream: LogStream::Stderr,
                    bytes: message.to_vec(),
                },
                LogOutput::StdOut { message }
                | LogOutput::Console { message }
                | LogOutput::StdIn { message } => LogFrame {
                    stream: LogStream::Stdout,
                    bytes: message.to_vec(),
                },
            })
        }))
    }

    fn stats_once<'a>(&'a self, id: &'a str) -> LocalBoxFuture<'a, DockerResult<RawStats>> {
        Box::pin(async move {
            let d = self.docker()?;
            let o = StatsOptions {
                stream: false,
                one_shot: true,
            };
            let mut s = d.stats(id, Some(o));
            match s.next().await {
                Some(Ok(r)) => Ok(raw_stats(&r)),
                Some(Err(e)) => Err(map_err(e)),
                None => Err(DockerError::NotFound(id.to_owned())),
            }
        })
    }

    fn list_images(&self) -> LocalBoxFuture<'_, DockerResult<Vec<ImageInfo>>> {
        Box::pin(async move {
            let d = self.docker()?;
            let used: HashSet<String> = d
                .list_containers(Some(ListContainersOptions {
                    all: true,
                    ..Default::default()
                }))
                .await
                .map_err(map_err)?
                .into_iter()
                .filter_map(|c| c.image_id)
                .collect();
            let v = d
                .list_images(None::<bollard::query_parameters::ListImagesOptions>)
                .await
                .map_err(map_err)?;
            Ok(v.into_iter()
                .map(|i| ImageInfo {
                    in_use: used.contains(&i.id),
                    id: clip(&i.id, 128),
                    tags: i.repo_tags.iter().take(64).map(|t| clip(t, 512)).collect(),
                    digests: i
                        .repo_digests
                        .iter()
                        .take(64)
                        .map(|t| clip(t, 512))
                        .collect(),
                    size_bytes: i64_u64(i.size),
                    created_ms: i64_u64(i.created).saturating_mul(1000),
                })
                .collect())
        })
    }

    fn pull_image<'a>(&'a self, image: &'a str) -> LocalBoxFuture<'a, DockerResult<()>> {
        Box::pin(async move {
            let d = self.docker()?;
            let (from_image, tag) = pull_parts(image);
            let o = CreateImageOptions {
                from_image: Some(from_image),
                tag,
                ..Default::default()
            };
            let mut s = d.create_image(Some(o), None, None);
            while let Some(item) = s.next().await {
                let item = item.map_err(map_err)?;
                if let Some(e) = item.error_detail.and_then(|e| e.message) {
                    return Err(DockerError::Other(clip(&e, 300)));
                }
            }
            Ok(())
        })
    }

    fn remove_image<'a>(
        &'a self,
        image: &'a str,
        force: bool,
    ) -> LocalBoxFuture<'a, DockerResult<()>> {
        Box::pin(async move {
            let o = RemoveImageOptions {
                force,
                ..Default::default()
            };
            self.docker()?
                .remove_image(image, Some(o), None)
                .await
                .map(|_| ())
                .map_err(map_err)
        })
    }

    fn prune_images(&self, all_unused: bool) -> LocalBoxFuture<'_, DockerResult<Pruned>> {
        Box::pin(async move {
            let filters = all_unused
                .then(|| HashMap::from([("dangling".to_owned(), vec!["false".to_owned()])]));
            let r = self
                .docker()?
                .prune_images(Some(PruneImagesOptions { filters }))
                .await
                .map_err(map_err)?;
            Ok(Pruned {
                removed: u32::try_from(r.images_deleted.map_or(0, |v| v.len())).unwrap_or(u32::MAX),
                reclaimed_bytes: i64_u64(r.space_reclaimed.unwrap_or(0)),
            })
        })
    }

    fn list_volumes(&self) -> LocalBoxFuture<'_, DockerResult<Vec<VolumeInfo>>> {
        Box::pin(async move {
            let d = self.docker()?;
            let used: HashSet<String> = d
                .list_containers(Some(ListContainersOptions {
                    all: true,
                    ..Default::default()
                }))
                .await
                .map_err(map_err)?
                .into_iter()
                .flat_map(|c| c.mounts.unwrap_or_default())
                .filter_map(|m| m.name)
                .collect();
            let r = d
                .list_volumes(None::<bollard::query_parameters::ListVolumesOptions>)
                .await
                .map_err(map_err)?;
            Ok(r.volumes
                .unwrap_or_default()
                .into_iter()
                .map(|v| VolumeInfo {
                    in_use: used.contains(&v.name),
                    size_bytes: v
                        .usage_data
                        .as_ref()
                        .and_then(|u| u64::try_from(u.size).ok()),
                    name: clip(&v.name, 256),
                    driver: clip(&v.driver, 128),
                    mountpoint: clip(&v.mountpoint, 1024),
                })
                .collect())
        })
    }

    fn remove_volume<'a>(&'a self, name: &'a str) -> LocalBoxFuture<'a, DockerResult<()>> {
        Box::pin(async move {
            self.docker()?
                .remove_volume(name, None::<bollard::query_parameters::RemoveVolumeOptions>)
                .await
                .map_err(map_err)
        })
    }

    fn list_networks(&self) -> LocalBoxFuture<'_, DockerResult<Vec<NetworkInfo>>> {
        Box::pin(async move {
            let v = self.docker()?.list_networks(None).await.map_err(map_err)?;
            Ok(v.into_iter()
                .map(|n| NetworkInfo {
                    id: clip(n.id.as_deref().unwrap_or_default(), 128),
                    name: clip(n.name.as_deref().unwrap_or_default(), 256),
                    driver: clip(n.driver.as_deref().unwrap_or_default(), 128),
                    subnets: n
                        .ipam
                        .and_then(|i| i.config)
                        .unwrap_or_default()
                        .into_iter()
                        .filter_map(|c| c.subnet)
                        .take(16)
                        .map(|s| clip(&s, 64))
                        .collect(),
                })
                .collect())
        })
    }

    fn events(&self) -> DockerStream<ContainerEvent> {
        let d = match self.docker() {
            Ok(d) => d,
            Err(e) => return Box::pin(futures_util::stream::once(async move { Err(e) })),
        };
        let o = EventsOptions {
            filters: Some(HashMap::from([(
                "type".to_owned(),
                vec!["container".to_owned()],
            )])),
            ..Default::default()
        };
        Box::pin(
            d.events(Some(o))
                .map_err(map_err)
                .try_filter_map(|m| async move {
                    if m.typ != Some(EventMessageTypeEnum::CONTAINER) {
                        return Ok(None);
                    }
                    let actor = m.actor.unwrap_or_default();
                    let attrs = actor.attributes.unwrap_or_default();
                    Ok(Some(ContainerEvent {
                        id: actor.id.unwrap_or_default(),
                        name: attrs.get("name").cloned().unwrap_or_default(),
                        action: m.action.unwrap_or_default(),
                        exit_code: attrs.get("exitCode").and_then(|c| c.parse().ok()),
                    }))
                }),
        )
    }
}
