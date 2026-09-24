//! Results of `docker` ops. All text is untrusted server data.

use super::F32;
use crate::v1::Hash32;
use crate::v1::args::Protocol;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Docker container state; unknown states map to `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ContainerState {
    Created,
    Running,
    Paused,
    Restarting,
    Removing,
    Exited,
    Dead,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedPort {
    pub host_ip: Option<IpAddr>,
    pub host_port: u16,
    pub container_port: u16,
    pub proto: Protocol,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: ContainerState,
    /// Docker's status text, e.g. `Up 3 hours (healthy)`.
    pub status: String,
    pub created_ms: u64,
    pub ports: Vec<PublishedPort>,
    pub compose_project: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Containers {
    pub containers: Vec<ContainerInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerDetail {
    pub info: ContainerInfo,
    /// `docker inspect` JSON, with `Env` values redacted.
    pub inspect_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageInfo {
    pub id: String,
    pub tags: Vec<String>,
    pub digests: Vec<String>,
    pub size_bytes: u64,
    pub created_ms: u64,
    pub in_use: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Images {
    pub images: Vec<ImageInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeInfo {
    pub name: String,
    pub driver: String,
    pub mountpoint: String,
    pub size_bytes: Option<u64>,
    pub in_use: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Volumes {
    pub volumes: Vec<VolumeInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub id: String,
    pub name: String,
    pub driver: String,
    pub subnets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Networks {
    pub networks: Vec<NetworkInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerStats {
    pub id: String,
    pub cpu_pct: F32,
    pub mem_bytes: u64,
    pub mem_limit: u64,
    pub net_rx_bps: u64,
    pub net_tx_bps: u64,
    pub blk_read_bps: u64,
    pub blk_write_bps: u64,
    pub pids: u32,
}

/// One `docker.stats` stream item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DockerStats {
    pub time_ms: u64,
    pub containers: Vec<ContainerStats>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LogStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DockerLogLine {
    pub time_ms: Option<u64>,
    pub stream: LogStream,
    pub text: String,
}

/// One `docker.logs` stream item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DockerLogChunk {
    pub lines: Vec<DockerLogLine>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComposeService {
    pub name: String,
    pub container: Option<String>,
    pub state: ContainerState,
    pub image: String,
    /// The registry has a newer digest for the image's tag (Mac-filled).
    pub update_available: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComposeStatus {
    pub project: String,
    pub path: String,
    /// BLAKE3 of the deployed `compose.yaml`.
    pub file_hash: Option<Hash32>,
    pub services: Vec<ComposeService>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComposeProjects {
    pub projects: Vec<ComposeStatus>,
}

/// Result of a prune.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pruned {
    pub removed: u32,
    pub reclaimed_bytes: u64,
}
