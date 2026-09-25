//! Docker tab (design §2.5): containers, images, volumes, networks,
//! Compose projects, and the log/stats streams. Compose files are checked
//! on the Mac with the agent's own validator (`fleet_core::compose_check`)
//! so the editor shows errors and Touch ID findings before signing.

use crate::admin_ops::{invalid, unexpected};
use crate::admin_rows::*;
use crate::api::FleetCore;
use crate::rows::StreamStatus;
use crate::streams::{StreamHandle, run_stream};
use crate::types::FleetError;
use crate::validate;
use fleet_core::compose_check::{self, ComposeError};
use fleet_proto::args::{
    ComposeFile, ComposeProject, ContainerId, ContainerName, ContainerRef, ImageRef, VolumeName,
};
use fleet_proto::{Op, Payload};
use std::sync::Arc;

#[uniffi::export(callback_interface)]
pub trait DockerLogSink: Send + Sync {
    fn on_lines(&self, lines: Vec<DockerLogLineRow>);
    fn on_status(&self, status: StreamStatus);
}

#[uniffi::export(callback_interface)]
pub trait DockerStatsSink: Send + Sync {
    fn on_stats(&self, time_ms: u64, stats: Vec<ContainerStatsRow>);
    fn on_status(&self, status: StreamStatus);
}

/// A container by id (hex) or name.
pub(crate) fn container(s: &str) -> Result<ContainerRef, FleetError> {
    if let Ok(id) = ContainerId::new(s) {
        return Ok(ContainerRef::Id(id));
    }
    ContainerName::new(s.trim_start_matches('/'))
        .map(ContainerRef::Name)
        .map_err(|_| invalid("container"))
}

fn project(s: &str) -> Result<ComposeProject, FleetError> {
    ComposeProject::new(s).map_err(|_| invalid("project"))
}

fn image(s: &str) -> Result<ImageRef, FleetError> {
    ImageRef::new(s.trim()).map_err(|_| invalid("image"))
}

fn compose_error(e: &ComposeError) -> String {
    match e {
        ComposeError::TooLarge => "File too large.".into(),
        ComposeError::Syntax { line, col } => {
            format!("YAML syntax error at line {line}, column {col}.")
        }
        ComposeError::TooDeep => "Nested too deeply.".into(),
        ComposeError::TooManyNodes => "Too many YAML nodes.".into(),
        ComposeError::Empty => "The file is empty.".into(),
        ComposeError::MultipleDocuments => "More than one YAML document.".into(),
        ComposeError::Anchor | ComposeError::Alias => {
            "YAML anchors and aliases are not allowed.".into()
        }
        ComposeError::Tag => "YAML tags are not allowed.".into(),
        ComposeError::MergeKey => "Merge keys (<<) are not allowed.".into(),
        ComposeError::NonScalarKey => "Keys must be plain strings.".into(),
        ComposeError::DuplicateKey(k) => format!("Duplicate key: {k}."),
        ComposeError::Shape(s) => format!("Unexpected structure: {s}."),
    }
}

/// Client-side Compose check for `project` (pure; same rules as exec).
#[uniffi::export]
pub fn compose_validate(project: String, yaml: String) -> Result<ComposeCheckRow, FleetError> {
    let p = self::project(&project)?;
    let v = compose_check::validate(&p, &yaml);
    Ok(ComposeCheckRow {
        ok: v.ok,
        errors: v.errors.iter().map(compose_error).collect(),
        findings: v
            .requires_elevated
            .iter()
            .map(|f| match &f.service {
                Some(s) => format!("{s}: {:?} — {}", f.kind, f.detail),
                None => format!("{:?} — {}", f.kind, f.detail),
            })
            .collect(),
    })
}

#[uniffi::export]
impl FleetCore {
    pub async fn docker_containers(
        &self,
        server_id: String,
        all: bool,
    ) -> Result<Vec<ContainerRow>, FleetError> {
        match self
            .send_op(&server_id, Op::DockerContainersList { all }, None)
            .await?
        {
            Payload::Containers(c) => Ok(c.containers.into_iter().map(Into::into).collect()),
            p => unexpected(p),
        }
    }

    pub async fn docker_container_action(
        &self,
        server_id: String,
        container: String,
        action: DockerContainerAction,
    ) -> Result<(), FleetError> {
        let c = self::container(&container)?;
        let op = match action {
            DockerContainerAction::Start => Op::DockerContainersStart { container: c },
            DockerContainerAction::Stop => Op::DockerContainersStop {
                container: c,
                timeout_s: 10,
            },
            DockerContainerAction::Restart => Op::DockerContainersRestart {
                container: c,
                timeout_s: 10,
            },
            DockerContainerAction::Remove => Op::DockerContainersRemove {
                container: c,
                force: false,
            },
            DockerContainerAction::ForceRemove => Op::DockerContainersRemove {
                container: c,
                force: true,
            },
        };
        self.send_op(&server_id, op, None).await.map(|_| ())
    }

    pub async fn docker_images(&self, server_id: String) -> Result<Vec<ImageRow>, FleetError> {
        match self.send_op(&server_id, Op::DockerImagesList, None).await? {
            Payload::Images(i) => Ok(i.images.into_iter().map(Into::into).collect()),
            p => unexpected(p),
        }
    }

    pub async fn docker_image_pull(
        &self,
        server_id: String,
        image: String,
    ) -> Result<(), FleetError> {
        let op = Op::DockerImagesPull {
            image: self::image(&image)?,
        };
        self.send_op(&server_id, op, None).await.map(|_| ())
    }

    /// `image`: a tag (`nginx:1.27`) or digest reference.
    pub async fn docker_image_remove(
        &self,
        server_id: String,
        image: String,
        force: bool,
    ) -> Result<(), FleetError> {
        let op = Op::DockerImagesRemove {
            image: self::image(&image)?,
            force,
        };
        self.send_op(&server_id, op, None).await.map(|_| ())
    }

    pub async fn docker_images_prune(
        &self,
        server_id: String,
        all_unused: bool,
    ) -> Result<PrunedRow, FleetError> {
        match self
            .send_op(&server_id, Op::DockerImagesPrune { all_unused }, None)
            .await?
        {
            Payload::Pruned(p) => Ok(PrunedRow {
                removed: p.removed,
                reclaimed_bytes: p.reclaimed_bytes,
            }),
            p => unexpected(p),
        }
    }

    pub async fn docker_volumes(&self, server_id: String) -> Result<Vec<VolumeRow>, FleetError> {
        match self
            .send_op(&server_id, Op::DockerVolumesList, None)
            .await?
        {
            Payload::Volumes(v) => Ok(v.volumes.into_iter().map(Into::into).collect()),
            p => unexpected(p),
        }
    }

    pub async fn docker_volume_remove(
        &self,
        server_id: String,
        name: String,
    ) -> Result<(), FleetError> {
        let op = Op::DockerVolumesRemove {
            volume: VolumeName::new(name).map_err(|_| invalid("volume"))?,
        };
        self.send_op(&server_id, op, None).await.map(|_| ())
    }

    pub async fn docker_networks(&self, server_id: String) -> Result<Vec<NetworkRow>, FleetError> {
        match self
            .send_op(&server_id, Op::DockerNetworksList, None)
            .await?
        {
            Payload::Networks(n) => Ok(n.networks.into_iter().map(Into::into).collect()),
            p => unexpected(p),
        }
    }

    pub async fn compose_list(
        &self,
        server_id: String,
    ) -> Result<Vec<ComposeProjectRow>, FleetError> {
        match self.send_op(&server_id, Op::ComposeList, None).await? {
            Payload::ComposeProjects(c) => Ok(c.projects.into_iter().map(Into::into).collect()),
            p => unexpected(p),
        }
    }

    pub async fn compose_action(
        &self,
        server_id: String,
        project: String,
        action: ComposeAction,
    ) -> Result<(), FleetError> {
        let project = self::project(&project)?;
        let op = match action {
            ComposeAction::Pull => Op::ComposePull { project },
            ComposeAction::Restart => Op::ComposeRestart { project },
            ComposeAction::Down => Op::ComposeDown {
                project,
                remove_volumes: false,
            },
            ComposeAction::DownRemoveVolumes => Op::ComposeDown {
                project,
                remove_volumes: true,
            },
        };
        self.send_op(&server_id, op, None).await.map(|_| ())
    }

    /// Writes `/srv/<project>/compose.yaml` and brings the project up. A
    /// file with deny-listed features needs Touch ID (asked when exec
    /// answers `ApprovalRequired`).
    pub async fn compose_deploy(
        &self,
        server_id: String,
        project: String,
        yaml: String,
        pull: bool,
    ) -> Result<(), FleetError> {
        let p = self::project(&project)?;
        if !compose_check::validate(&p, &yaml).ok {
            return Err(invalid("compose file"));
        }
        let op = Op::ComposeDeploy {
            project: p,
            file: ComposeFile::new(yaml).map_err(|_| invalid("compose file"))?,
            pull,
        };
        self.send_op(&server_id, op, None).await.map(|_| ())
    }

    /// `docker.logs`: the last `tail` lines, then new ones as written.
    pub fn follow_docker_logs(
        &self,
        server_id: String,
        container: String,
        tail: u32,
        sink: Box<dyn DockerLogSink>,
    ) -> Result<Arc<StreamHandle>, FleetError> {
        let id = validate::server_id(&server_id)?;
        let c = self::container(&container)?;
        if tail > 10_000 {
            return Err(invalid("tail"));
        }
        let (handle, rt) = self.running()?;
        let (h, cancel) = StreamHandle::new();
        let sink: Arc<dyn DockerLogSink> = Arc::from(sink);
        let s1 = sink.clone();
        // After a reconnect: no replay, only lines written since.
        let first = std::sync::atomic::AtomicBool::new(true);
        rt.spawn(run_stream(
            handle,
            id,
            move || Op::DockerLogs {
                container: c.clone(),
                tail: if first.swap(false, std::sync::atomic::Ordering::Relaxed) {
                    tail
                } else {
                    0
                },
                since_ms: None,
                follow: true,
            },
            move |p| {
                if let Payload::DockerLogChunk(c) = p {
                    s1.on_lines(c.lines.into_iter().map(Into::into).collect());
                }
            },
            move |st| sink.on_status(st),
            cancel,
        ));
        Ok(h)
    }

    /// `docker.stats` for `containers` (empty: all running).
    pub fn stream_docker_stats(
        &self,
        server_id: String,
        containers: Vec<String>,
        sink: Box<dyn DockerStatsSink>,
    ) -> Result<Arc<StreamHandle>, FleetError> {
        let id = validate::server_id(&server_id)?;
        let cs = containers
            .iter()
            .map(|c| self::container(c))
            .collect::<Result<Vec<_>, _>>()?;
        let op = Op::DockerStats { containers: cs };
        op.check_args().map_err(|_| invalid("containers"))?;
        let (handle, rt) = self.running()?;
        let (h, cancel) = StreamHandle::new();
        let sink: Arc<dyn DockerStatsSink> = Arc::from(sink);
        let s1 = sink.clone();
        rt.spawn(run_stream(
            handle,
            id,
            move || op.clone(),
            move |p| {
                if let Payload::DockerStats(s) = p {
                    s1.on_stats(
                        s.time_ms,
                        s.containers.into_iter().map(Into::into).collect(),
                    );
                }
            },
            move |st| sink.on_status(st),
            cancel,
        ));
        Ok(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_refs() {
        assert!(matches!(
            container("0123456789ab").unwrap(),
            ContainerRef::Id(_)
        ));
        assert!(matches!(
            container("/app-web-1").unwrap(),
            ContainerRef::Name(_)
        ));
        assert!(container("a b").is_err());
    }

    #[test]
    fn compose_check_reports() {
        let ok =
            compose_validate("app".into(), "services:\n  web:\n    image: nginx\n".into()).unwrap();
        assert!(ok.ok && ok.errors.is_empty() && ok.findings.is_empty());
        let priv_ = compose_validate(
            "app".into(),
            "services:\n  web:\n    image: nginx\n    privileged: true\n".into(),
        )
        .unwrap();
        assert!(!priv_.findings.is_empty());
        let bad = compose_validate("app".into(), "a: &x 1\nb: *x\n".into()).unwrap();
        assert!(!bad.ok && !bad.errors.is_empty());
        assert!(compose_validate("Bad Name".into(), String::new()).is_err());
    }
}
