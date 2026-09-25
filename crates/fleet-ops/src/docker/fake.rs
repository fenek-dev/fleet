//! In-memory [`DockerApi`] for tests (here and in exec).

use super::{
    ContainerEvent, DockerApi, DockerError, DockerResult, DockerStream, LogFrame, LogOptions,
    RawStats,
};
use crate::handler::LocalBoxFuture;
use fleet_proto::payload::{ContainerInfo, ImageInfo, NetworkInfo, Pruned, VolumeInfo};
use std::cell::RefCell;
use std::collections::HashMap;

/// Canned state; every mutating call is recorded in `calls` as text
/// (`"stop web 10"`). Unknown containers/images/volumes are `NotFound`.
#[derive(Default)]
pub struct FakeDocker {
    pub containers: RefCell<Vec<ContainerInfo>>,
    pub inspect: RefCell<HashMap<String, serde_json::Value>>,
    pub images: RefCell<Vec<ImageInfo>>,
    pub volumes: RefCell<Vec<VolumeInfo>>,
    pub networks: RefCell<Vec<NetworkInfo>>,
    pub logs: RefCell<Vec<DockerResult<LogFrame>>>,
    pub stats: RefCell<HashMap<String, Vec<RawStats>>>,
    pub events: RefCell<Vec<DockerResult<ContainerEvent>>>,
    pub calls: RefCell<Vec<String>>,
    pub log_opts: RefCell<Vec<LogOptions>>,
}

impl FakeDocker {
    pub fn new() -> Self {
        Self::default()
    }

    fn record(&self, s: String) {
        self.calls.borrow_mut().push(s);
    }

    fn has_container(&self, id: &str) -> bool {
        self.containers
            .borrow()
            .iter()
            .any(|c| c.id.starts_with(id) || c.name == id)
    }

    fn container_op(&self, what: String, id: &str) -> DockerResult<()> {
        self.record(what);
        if self.has_container(id) {
            Ok(())
        } else {
            Err(DockerError::NotFound(id.to_owned()))
        }
    }
}

fn ready<'a, T: 'a>(v: T) -> LocalBoxFuture<'a, T> {
    Box::pin(std::future::ready(v))
}

impl DockerApi for FakeDocker {
    fn list_containers(&self, all: bool) -> LocalBoxFuture<'_, DockerResult<Vec<ContainerInfo>>> {
        let v = self
            .containers
            .borrow()
            .iter()
            .filter(|c| all || c.state == fleet_proto::payload::ContainerState::Running)
            .cloned()
            .collect();
        ready(Ok(v))
    }

    fn inspect_container<'a>(
        &'a self,
        id: &'a str,
    ) -> LocalBoxFuture<'a, DockerResult<serde_json::Value>> {
        ready(
            self.inspect
                .borrow()
                .get(id)
                .cloned()
                .ok_or_else(|| DockerError::NotFound(id.to_owned())),
        )
    }

    fn start<'a>(&'a self, id: &'a str) -> LocalBoxFuture<'a, DockerResult<()>> {
        ready(self.container_op(format!("start {id}"), id))
    }

    fn stop<'a>(&'a self, id: &'a str, timeout_s: u16) -> LocalBoxFuture<'a, DockerResult<()>> {
        ready(self.container_op(format!("stop {id} {timeout_s}"), id))
    }

    fn restart<'a>(&'a self, id: &'a str, timeout_s: u16) -> LocalBoxFuture<'a, DockerResult<()>> {
        ready(self.container_op(format!("restart {id} {timeout_s}"), id))
    }

    fn remove<'a>(&'a self, id: &'a str, force: bool) -> LocalBoxFuture<'a, DockerResult<()>> {
        ready(self.container_op(format!("remove {id} {force}"), id))
    }

    fn logs(&self, id: &str, opts: LogOptions) -> DockerStream<LogFrame> {
        self.record(format!("logs {id}"));
        self.log_opts.borrow_mut().push(opts);
        let items: Vec<_> = self.logs.borrow_mut().drain(..).collect();
        Box::pin(futures_util::stream::iter(items))
    }

    fn stats_once<'a>(&'a self, id: &'a str) -> LocalBoxFuture<'a, DockerResult<RawStats>> {
        let mut m = self.stats.borrow_mut();
        let r = match m.get_mut(id) {
            Some(v) if v.len() > 1 => Ok(v.remove(0)),
            Some(v) if !v.is_empty() => Ok(v[0]),
            _ => Err(DockerError::NotFound(id.to_owned())),
        };
        ready(r)
    }

    fn list_images(&self) -> LocalBoxFuture<'_, DockerResult<Vec<ImageInfo>>> {
        ready(Ok(self.images.borrow().clone()))
    }

    fn pull_image<'a>(&'a self, image: &'a str) -> LocalBoxFuture<'a, DockerResult<()>> {
        self.record(format!("pull {image}"));
        ready(Ok(()))
    }

    fn remove_image<'a>(
        &'a self,
        image: &'a str,
        force: bool,
    ) -> LocalBoxFuture<'a, DockerResult<()>> {
        self.record(format!("rmi {image} {force}"));
        let found = self
            .images
            .borrow()
            .iter()
            .any(|i| i.id == image || i.tags.iter().any(|t| t == image));
        ready(if found {
            Ok(())
        } else {
            Err(DockerError::NotFound(image.to_owned()))
        })
    }

    fn prune_images(&self, all_unused: bool) -> LocalBoxFuture<'_, DockerResult<Pruned>> {
        self.record(format!("prune images {all_unused}"));
        ready(Ok(Pruned {
            removed: 2,
            reclaimed_bytes: 1024,
        }))
    }

    fn list_volumes(&self) -> LocalBoxFuture<'_, DockerResult<Vec<VolumeInfo>>> {
        ready(Ok(self.volumes.borrow().clone()))
    }

    fn remove_volume<'a>(&'a self, name: &'a str) -> LocalBoxFuture<'a, DockerResult<()>> {
        self.record(format!("rmv {name}"));
        let v = self.volumes.borrow();
        ready(match v.iter().find(|v| v.name == name) {
            Some(v) if v.in_use => Err(DockerError::Conflict(name.to_owned())),
            Some(_) => Ok(()),
            None => Err(DockerError::NotFound(name.to_owned())),
        })
    }

    fn list_networks(&self) -> LocalBoxFuture<'_, DockerResult<Vec<NetworkInfo>>> {
        ready(Ok(self.networks.borrow().clone()))
    }

    fn events(&self) -> DockerStream<ContainerEvent> {
        let items: Vec<_> = self.events.borrow_mut().drain(..).collect();
        Box::pin(futures_util::stream::iter(items))
    }
}
