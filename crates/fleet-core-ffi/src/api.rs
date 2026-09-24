//! [`FleetCore`]: the object Swift holds.
//!
//! Threading: [`FleetCore::start`] spawns one `fleet-core` thread running a
//! current-thread tokio runtime with a `LocalSet` (the manager's sessions
//! aren't `Send`, see `fleet_core::manager`). Requests are spawned onto that
//! runtime and awaited from Swift's executor; listener callbacks run on the
//! core thread. The thread ends when the `FleetCore` is dropped (the last
//! `ManagerHandle` goes with it).

use crate::signer::{CoreListener, DeviceSigner, KeyStore, SignerAdapter};
use crate::types::*;
use crate::validate;
use fleet_core::cache::{Cache, GroupRecord, ServerRecord};
use fleet_core::manager::{
    ConnectionManager, ManagerConfig, ManagerEvent, ManagerHandle, ServerSpec, SshConnector,
};
use fleet_core::ssh::{HostKey, HostKeyStatus, SshOptions, SshTarget};
use fleet_crypto::Zeroizing;
use fleet_crypto::noise::StaticKeypair;
use fleet_proto::{Actor, DeviceId, FleetId, Op, Payload, ServerId};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::sync::broadcast;

/// Cache `settings` keys written by enrollment (16 raw bytes each).
pub const SETTING_FLEET_ID: &str = "fleet_id";
pub const SETTING_DEVICE_ID: &str = "device_id";

const SESSION_TIMEOUT: Duration = Duration::from_secs(20);

type PendingKeys = Arc<Mutex<HashMap<ServerId, HostKey>>>;

struct Running {
    handle: ManagerHandle,
    rt: tokio::runtime::Handle,
}

#[derive(uniffi::Object)]
pub struct FleetCore {
    cache: Mutex<Cache>,
    keys: Arc<SignerAdapter>,
    key_store: Box<dyn KeyStore>,
    kind: Mutex<SessionKind>,
    running: Mutex<Option<Running>>,
    pending_host_keys: PendingKeys,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn id16(cache: &Cache, key: &str) -> Result<[u8; 16], FleetError> {
    cache
        .setting(key)?
        .and_then(|v| <[u8; 16]>::try_from(v.as_slice()).ok())
        .ok_or(FleetError::NotEnrolled)
}

/// What the manager needs for `rec`, if the agent keys are pinned.
fn spec_for(cache: &Cache, rec: &ServerRecord) -> Result<Option<ServerSpec>, FleetError> {
    let Some(pins) = cache.pins(&rec.id)? else {
        return Ok(None);
    };
    let (Some(agent_noise), Some(agent_signing)) = (pins.agent_noise, pins.agent_signing) else {
        return Ok(None);
    };
    Ok(Some(ServerSpec {
        id: rec.id.clone(),
        target: rec.target.clone(),
        host_key: pins.host_key,
        agent_noise,
        agent_signing,
    }))
}

impl FleetCore {
    fn running(&self) -> Result<(ManagerHandle, tokio::runtime::Handle), FleetError> {
        lock(&self.running)
            .as_ref()
            .map(|r| (r.handle.clone(), r.rt.clone()))
            .ok_or(FleetError::NotStarted)
    }

    fn noise_key(&self) -> Result<StaticKeypair, FleetError> {
        let keys = |e| FleetError::Keys { error: e };
        if let Some(raw) = self.key_store.load_noise_key().map_err(keys)? {
            let raw = Zeroizing::new(raw);
            let secret: Zeroizing<[u8; 32]> = Zeroizing::new(
                raw.as_slice()
                    .try_into()
                    .map_err(|_| keys(SignerError::Failed))?,
            );
            return Ok(StaticKeypair::from_bytes(&secret));
        }
        let kp = StaticKeypair::generate().map_err(|_| FleetError::Internal {
            message: "noise keygen".into(),
        })?;
        self.key_store
            .store_noise_key(kp.secret_bytes().to_vec())
            .map_err(keys)?;
        Ok(kp)
    }

    async fn request(&self, server_id: String, op: Op) -> Result<Payload, FleetError> {
        let id = validate::server_id(&server_id)?;
        let (handle, rt) = self.running()?;
        let task = rt.spawn(async move { handle.request(&id, op, Actor::Human, None).await });
        let reply = task.await.map_err(|_| FleetError::Stopped)??;
        reply.result.map_err(|code| FleetError::Agent {
            code: format!("{code:?}"),
        })
    }

    fn row(&self, rec: ServerRecord, cache: &Cache, handle: Option<&ManagerHandle>) -> ServerRow {
        let pinned = cache
            .pins(&rec.id)
            .ok()
            .flatten()
            .is_some_and(|p| p.agent_noise.is_some() && p.agent_signing.is_some());
        let state = handle
            .and_then(|h| h.state(&rec.id))
            .map(ConnState::from)
            .unwrap_or(ConnState::Disconnected);
        ServerRow {
            id: rec.id.to_string(),
            name: rec.name,
            host: rec.target.host,
            port: rec.target.port,
            user: rec.target.user,
            group_id: rec.group,
            tags: rec.tags,
            state,
            agent_pinned: pinned,
            cpu_percent: None,
            mem_percent: None,
            disk_percent: None,
            uptime_s: None,
            kernel: None,
            agent_version: None,
            pending_updates: None,
            last_seen_ms: None,
        }
    }
}

#[uniffi::export]
impl FleetCore {
    /// Opens (or creates) the cache at `cache_path`. Starts locked
    /// (monitor sessions) per design §5.10.
    #[uniffi::constructor]
    pub fn open(
        cache_path: String,
        signer: Box<dyn DeviceSigner>,
        key_store: Box<dyn KeyStore>,
    ) -> Result<Arc<Self>, FleetError> {
        let cache = Cache::open(Path::new(&cache_path))?;
        Ok(Arc::new(Self {
            cache: Mutex::new(cache),
            keys: Arc::new(SignerAdapter(signer)),
            key_store,
            kind: Mutex::new(SessionKind::Monitor),
            running: Mutex::new(None),
            pending_host_keys: Arc::default(),
        }))
    }

    /// `fleet_id` and `device_id` are in the cache.
    pub fn is_enrolled(&self) -> bool {
        let c = lock(&self.cache);
        id16(&c, SETTING_FLEET_ID).is_ok() && id16(&c, SETTING_DEVICE_ID).is_ok()
    }

    // ---- groups ----

    pub fn list_groups(&self) -> Result<Vec<GroupRow>, FleetError> {
        Ok(lock(&self.cache)
            .groups()?
            .into_iter()
            .map(|g| GroupRow {
                id: g.id,
                name: g.name,
                sort: g.sort,
            })
            .collect())
    }

    pub fn add_group(&self, name: String) -> Result<GroupRow, FleetError> {
        let name = validate::name(&name, "name")?;
        let cache = lock(&self.cache);
        let sort = cache
            .groups()?
            .iter()
            .map(|g| g.sort + 1)
            .max()
            .unwrap_or(0);
        let g = GroupRecord {
            id: validate::random_id("grp_")?,
            name,
            sort,
        };
        cache.upsert_group(&g)?;
        Ok(GroupRow {
            id: g.id,
            name: g.name,
            sort: g.sort,
        })
    }

    /// Servers in the group become ungrouped.
    pub fn remove_group(&self, group_id: String) -> Result<(), FleetError> {
        let id = validate::group_id(&group_id)?;
        lock(&self.cache).delete_group(&id)?;
        Ok(())
    }

    // ---- servers ----

    pub fn list_servers(&self) -> Result<Vec<ServerRow>, FleetError> {
        let handle = lock(&self.running).as_ref().map(|r| r.handle.clone());
        let cache = lock(&self.cache);
        let recs = cache.servers()?;
        Ok(recs
            .into_iter()
            .map(|r| self.row(r, &cache, handle.as_ref()))
            .collect())
    }

    /// Adds a server to the cache. It connects once the agent is installed
    /// and its keys pinned (agent install flow, later phase).
    pub fn add_server(&self, server: NewServer) -> Result<ServerRow, FleetError> {
        let group = server
            .group_id
            .as_deref()
            .map(validate::group_id)
            .transpose()?;
        let rec = ServerRecord {
            id: validate::server_id(&validate::random_id("srv_")?)?,
            name: validate::name(&server.name, "name")?,
            target: SshTarget::new(
                validate::host(&server.host)?,
                validate::port(server.port)?,
                validate::user(&server.user)?,
            ),
            group,
            tags: validate::tags(&server.tags)?,
        };
        let mut cache = lock(&self.cache);
        cache.upsert_server(&rec)?;
        Ok(self.row(rec, &cache, None))
    }

    pub fn remove_server(&self, server_id: String) -> Result<(), FleetError> {
        let id = validate::server_id(&server_id)?;
        if let Some(r) = lock(&self.running).as_ref() {
            r.handle.remove_server(&id);
        }
        lock(&self.pending_host_keys).remove(&id);
        lock(&self.cache).delete_server(&id)?;
        Ok(())
    }

    // ---- connection manager ----

    /// Starts the connection manager and connects every server with pinned
    /// agent keys. `listener` receives state changes and events.
    pub fn start(&self, listener: Box<dyn CoreListener>) -> Result<(), FleetError> {
        let mut running = lock(&self.running);
        if running.is_some() {
            return Err(FleetError::AlreadyStarted);
        }
        let (fleet_id, device_id, specs) = {
            let cache = lock(&self.cache);
            let fleet_id = FleetId(id16(&cache, SETTING_FLEET_ID)?);
            let device_id = DeviceId(id16(&cache, SETTING_DEVICE_ID)?);
            let mut specs = Vec::new();
            for rec in cache.servers()? {
                if let Some(s) = spec_for(&cache, &rec)? {
                    specs.push(s);
                }
            }
            (fleet_id, device_id, specs)
        };
        let connector = SshConnector {
            keys: self.keys.clone(),
            noise: Arc::new(self.noise_key()?),
            fleet_id,
            device_id,
            ssh: SshOptions::default(),
            session_timeout: SESSION_TIMEOUT,
        };
        let kind = *lock(&self.kind);
        let pending = self.pending_host_keys.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("fleet-core".into())
            .spawn(move || core_thread(connector, kind.into(), listener, pending, tx))
            .map_err(|e| FleetError::Internal {
                message: e.to_string(),
            })?;
        let (handle, rt) = rx
            .recv()
            .map_err(|_| FleetError::Internal {
                message: "core thread failed to start".into(),
            })?
            .map_err(|message| FleetError::Internal { message })?;
        for s in specs {
            handle.add_server(s);
        }
        *running = Some(Running { handle, rt });
        Ok(())
    }

    /// Lock → monitor sessions; unlock → device sessions. Every Ready
    /// server reconnects with the new key (design §7.2).
    pub fn set_session_kind(&self, kind: SessionKind) {
        *lock(&self.kind) = kind;
        if let Some(r) = lock(&self.running).as_ref() {
            r.handle.set_session_kind(kind.into());
        }
    }

    pub fn session_kind(&self) -> SessionKind {
        *lock(&self.kind)
    }

    /// Reconnects now, clearing backoff and a fatal block.
    pub fn reconnect(&self, server_id: String) -> Result<(), FleetError> {
        let id = validate::server_id(&server_id)?;
        let (handle, _) = self.running()?;
        handle.reconnect(&id);
        Ok(())
    }

    /// Pins the first-use host key last reported for `server_id` (after the
    /// operator compared fingerprints) and reconnects with it.
    pub fn accept_host_key(&self, server_id: String) -> Result<(), FleetError> {
        let id = validate::server_id(&server_id)?;
        let key = lock(&self.pending_host_keys)
            .remove(&id)
            .ok_or(FleetError::UnknownServer)?;
        let spec = {
            let cache = lock(&self.cache);
            cache.pin_host_key(&id, &key)?;
            let rec = cache.server(&id)?.ok_or(FleetError::UnknownServer)?;
            spec_for(&cache, &rec)?
        };
        if let (Some(spec), Some(r)) = (spec, lock(&self.running).as_ref()) {
            r.handle.add_server(spec);
        }
        Ok(())
    }

    /// Forgets a first-use host key without pinning it.
    pub fn reject_host_key(&self, server_id: String) -> Result<(), FleetError> {
        let id = validate::server_id(&server_id)?;
        lock(&self.pending_host_keys).remove(&id);
        if let Some(r) = lock(&self.running).as_ref() {
            r.handle.remove_server(&id);
        }
        Ok(())
    }

    // ---- requests ----

    pub async fn system_info(&self, server_id: String) -> Result<SystemInfoRow, FleetError> {
        match self.request(server_id, Op::SystemInfo).await? {
            Payload::SystemInfo(v) => Ok(v.into()),
            _ => Err(FleetError::UnexpectedReply),
        }
    }

    /// Works on monitor sessions too (design §5.5).
    pub async fn agent_health(&self, server_id: String) -> Result<AgentHealthRow, FleetError> {
        match self.request(server_id, Op::AgentHealth).await? {
            Payload::AgentHealth(v) => Ok(v.into()),
            _ => Err(FleetError::UnexpectedReply),
        }
    }
}

type Started = Result<(ManagerHandle, tokio::runtime::Handle), String>;

fn core_thread(
    connector: SshConnector,
    kind: fleet_core::manager::SessionKind,
    listener: Box<dyn CoreListener>,
    pending: PendingKeys,
    started: std::sync::mpsc::Sender<Started>,
) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = started.send(Err(e.to_string()));
            return;
        }
    };
    let (mgr, handle) = ConnectionManager::new(connector, ManagerConfig::default(), kind);
    let events = handle.subscribe();
    if started.send(Ok((handle, rt.handle().clone()))).is_err() {
        return;
    }
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async move {
        // Ends with the runtime when `run` returns (every handle dropped).
        tokio::task::spawn_local(forward(events, listener, pending));
        mgr.run().await;
    });
}

async fn forward(
    mut events: broadcast::Receiver<ManagerEvent>,
    listener: Box<dyn CoreListener>,
    pending: PendingKeys,
) {
    loop {
        match events.recv().await {
            Ok(ev) => dispatch(ev, &*listener, &pending),
            Err(broadcast::error::RecvError::Lagged(_)) => listener.on_resync(),
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}

fn dispatch(ev: ManagerEvent, listener: &dyn CoreListener, pending: &PendingKeys) {
    match ev {
        ManagerEvent::State {
            server,
            state,
            kind,
            failure,
        } => listener.on_state(StateChange {
            server_id: server.to_string(),
            state: state.into(),
            kind: kind.map(Into::into),
            fatal: failure.as_ref().is_some_and(|f| f.fatal),
            failure: failure.map(|f| f.message),
        }),
        ManagerEvent::Event { server, seq, event } => {
            listener.on_event(AgentEventRow::new(server.to_string(), seq, &event));
        }
        ManagerEvent::HostKeyFirstUse {
            server,
            observation,
        } => {
            let via_jump_unpinned = observation
                .via
                .as_ref()
                .is_some_and(|v| v.needs_confirmation());
            let target_first_use = observation.status == HostKeyStatus::FirstUse;
            let prompt = HostKeyPrompt {
                server_id: server.to_string(),
                algorithm: observation.key.algorithm(),
                fingerprint: observation.key.fingerprint(),
                via_jump_unpinned,
            };
            if target_first_use {
                lock(pending).insert(server, observation.key);
            }
            listener.on_host_key(prompt);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoKeys;
    impl DeviceSigner for NoKeys {
        fn public_key(&self, _: KeyRole) -> Result<Vec<u8>, SignerError> {
            Err(SignerError::Unavailable)
        }
        fn sign(&self, _: KeyRole, _: Vec<u8>) -> Result<Vec<u8>, SignerError> {
            Err(SignerError::Unavailable)
        }
    }
    impl KeyStore for NoKeys {
        fn load_noise_key(&self) -> Result<Option<Vec<u8>>, SignerError> {
            Ok(None)
        }
        fn store_noise_key(&self, _: Vec<u8>) -> Result<(), SignerError> {
            Ok(())
        }
    }
    struct Quiet;
    impl CoreListener for Quiet {
        fn on_state(&self, _: StateChange) {}
        fn on_host_key(&self, _: HostKeyPrompt) {}
        fn on_event(&self, _: AgentEventRow) {}
        fn on_resync(&self) {}
    }

    fn core(dir: &tempfile::TempDir) -> Arc<FleetCore> {
        let path = dir.path().join("cache.sqlite");
        FleetCore::open(
            path.to_string_lossy().into_owned(),
            Box::new(NoKeys),
            Box::new(NoKeys),
        )
        .unwrap()
    }

    fn web(group_id: Option<String>) -> NewServer {
        NewServer {
            name: "web-04".into(),
            host: "203.0.113.14".into(),
            port: 22,
            user: "deploy".into(),
            group_id,
            tags: vec!["web".into()],
        }
    }

    #[test]
    fn servers_and_groups_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let c = core(&dir);
        let g = c.add_group("Production".into()).unwrap();
        let row = c.add_server(web(Some(g.id.clone()))).unwrap();
        assert_eq!(row.state, ConnState::Disconnected);
        assert!(!row.agent_pinned);
        let rows = c.list_servers().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].group_id.as_deref(), Some(g.id.as_str()));
        assert_eq!(rows[0].tags, vec!["web".to_string()]);

        c.remove_group(g.id).unwrap();
        assert_eq!(c.list_servers().unwrap()[0].group_id, None);
        c.remove_server(row.id).unwrap();
        assert!(c.list_servers().unwrap().is_empty());
    }

    #[test]
    fn rejects_bad_input() {
        let dir = tempfile::tempdir().unwrap();
        let c = core(&dir);
        let mut s = web(None);
        s.host = "-oProxyCommand=sh".into();
        assert!(matches!(
            c.add_server(s),
            Err(FleetError::InvalidArgument { .. })
        ));
        assert!(matches!(
            c.remove_server("nope".into()),
            Err(FleetError::InvalidArgument { .. })
        ));
    }

    #[test]
    fn start_needs_enrollment() {
        let dir = tempfile::tempdir().unwrap();
        let c = core(&dir);
        assert!(!c.is_enrolled());
        assert_eq!(c.start(Box::new(Quiet)), Err(FleetError::NotEnrolled));
        assert_eq!(
            c.reconnect("srv_abcdef".into()),
            Err(FleetError::NotStarted)
        );
    }

    #[test]
    fn starts_when_enrolled_and_switches_kind() {
        let dir = tempfile::tempdir().unwrap();
        let c = core(&dir);
        {
            let cache = lock(&c.cache);
            cache.set_setting(SETTING_FLEET_ID, &[1; 16]).unwrap();
            cache.set_setting(SETTING_DEVICE_ID, &[2; 16]).unwrap();
        }
        c.add_server(web(None)).unwrap();
        c.start(Box::new(Quiet)).unwrap();
        assert_eq!(c.start(Box::new(Quiet)), Err(FleetError::AlreadyStarted));
        assert_eq!(c.session_kind(), SessionKind::Monitor);
        c.set_session_kind(SessionKind::Device);
        assert_eq!(c.session_kind(), SessionKind::Device);
        // Unpinned servers aren't connected.
        assert_eq!(c.list_servers().unwrap()[0].state, ConnState::Disconnected);
    }
}
