//! [`SshConnector`], the manager's production [`Connector`].

use super::*;

/// The app's connector: SSH, the agent exec channel, then a Noise session
/// signed by the device or monitor key (design §5.5, §5.10).
///
/// - **Device** sessions authenticate SSH with the enclave SSH key (needs
///   the unlock context), open `bridge` and publish the SSH connection for
///   terminals and SFTP.
/// - **Monitor** sessions (app locked) authenticate SSH with the monitor
///   SSH key, which works while locked and which `authorized_keys` forces
///   to `bridge --monitor` (Noise prologue mode 2). That connection is
///   **never published**: it can't run anything but the monitor bridge,
///   and nothing may use it for terminals or files.
/// - **Lock/unlock:** a connection authenticated with the device SSH key is
///   kept across a session-kind change and reused (locking: a monitor
///   session on the normal bridge, unpublished; unlocking again: a device
///   session on the same connection). A monitor-SSH connection can't be
///   upgraded (every channel is forced to the monitor bridge, and SSH has
///   no re-authentication), so unlocking reconnects with the device SSH
///   key, without backoff.
pub struct SshConnector {
    pub keys: Arc<dyn DeviceSigner>,
    pub noise: Arc<StaticKeypair>,
    pub fleet_id: FleetId,
    pub device_id: DeviceId,
    pub ssh: SshOptions,
    /// Noise handshake + `DeviceAuth` + signed status read.
    pub session_timeout: Duration,
    /// Device-key SSH connections kept across a session-kind change.
    kept: std::cell::RefCell<HashMap<ServerId, KeptConn>>,
}

struct KeptConn {
    spec: ServerSpec,
    conn: Arc<SshConnection>,
    at: std::time::Instant,
}

/// A kept connection not picked up again within this time is closed.
const KEEP_FOR: Duration = Duration::from_secs(60);

impl SshConnector {
    pub fn new(
        keys: Arc<dyn DeviceSigner>,
        noise: Arc<StaticKeypair>,
        fleet_id: FleetId,
        device_id: DeviceId,
        ssh: SshOptions,
        session_timeout: Duration,
    ) -> Self {
        Self {
            keys,
            noise,
            fleet_id,
            device_id,
            ssh,
            session_timeout,
            kept: Default::default(),
        }
    }

    /// SSH key and bridge for a fresh connection of `kind`.
    pub fn plan(kind: SessionKind) -> (KeyRole, SessionMode) {
        match kind {
            SessionKind::Device => (KeyRole::Ssh, SessionMode::Normal),
            SessionKind::Monitor => (KeyRole::MonitorSsh, SessionMode::Monitor),
        }
    }

    /// A kept device-key connection for `server`, if still usable.
    fn take_kept(&self, server: &ServerSpec) -> Option<Arc<SshConnection>> {
        let mut kept = self.kept.borrow_mut();
        let stale: Vec<ServerId> = kept
            .iter()
            .filter(|(_, k)| k.at.elapsed() > KEEP_FOR || k.conn.is_closed())
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            if let Some(k) = kept.remove(&id) {
                tokio::task::spawn_local(async move { k.conn.disconnect().await });
            }
        }
        let k = kept.remove(&server.id)?;
        if k.spec == *server {
            Some(k.conn)
        } else {
            tokio::task::spawn_local(async move { k.conn.disconnect().await });
            None
        }
    }
}

impl Connector for SshConnector {
    async fn run(
        &self,
        server: &ServerSpec,
        kind: SessionKind,
        mut ctx: LinkCtx<'_>,
    ) -> Result<ServeEnd, LinkError> {
        let (conn, ssh_role) = match self.take_kept(server) {
            Some(conn) => (conn, KeyRole::Ssh),
            None => {
                let (ssh_role, _) = Self::plan(kind);
                let ssh_key = P256SshSigner(RoleSigner::new(&*self.keys, ssh_role)?);
                let (conn, observation) = SshConnection::connect_with(
                    &server.target,
                    &ssh_key,
                    server.host_key.clone(),
                    &self.ssh,
                )
                .await?;
                // A first-use key (any hop) blocks the connection: nothing
                // but the fingerprint prompt happens until the operator
                // pins it. Only an all-Matched connection is used or
                // published.
                if !observation.all_matched() {
                    conn.disconnect().await;
                    ctx.host_key_first_use(observation);
                    return Err(LinkError::Ssh(SshError::HostKeyUnconfirmed));
                }
                (Arc::new(conn), ssh_role)
            }
        };
        // A device-key connection runs the normal bridge for either kind;
        // a monitor-key connection only the monitor bridge.
        let mode = if ssh_role == KeyRole::MonitorSsh {
            SessionMode::Monitor
        } else {
            SessionMode::Normal
        };
        ctx.authenticating();
        let role = match kind {
            SessionKind::Monitor => KeyRole::Monitor,
            SessionKind::Device => KeyRole::Device,
        };
        // Enclave signatures block (Swift callback): signed on the
        // blocking pool, never on this runtime thread.
        let signer: Arc<dyn fleet_crypto::sig::Signer + Send + Sync> =
            Arc::new(SharedRoleSigner::new(self.keys.clone(), role)?);
        let result = async {
            let stream = conn.open_agent_channel_mode(mode).await?;
            let cfg = SessionConfig {
                mode,
                noise: &self.noise,
                pinned_agent_noise: server.agent_noise,
                pinned_agent_signing: server.agent_signing,
                fleet_id: self.fleet_id,
                server_id: server.id.clone(),
                device_id: self.device_id,
                key: kind.key_kind(),
                signer: CommandSigner::Blocking(signer.clone()),
            };
            let mut session =
                tokio::time::timeout(self.session_timeout, Session::connect_bridged(stream, cfg))
                    .await
                    .map_err(|_| LinkError::Timeout)??;
            // Terminals and SFTP only over a device-key connection while
            // unlocked (design §5.10: terminals are hidden while locked).
            if kind == SessionKind::Device && ssh_role == KeyRole::Ssh {
                ctx.publish_ssh(conn.clone());
            }
            ctx.serve(&mut session).await
        }
        .await;
        if matches!(result, Ok(ServeEnd::KindChanged))
            && ssh_role == KeyRole::Ssh
            && !conn.is_closed()
        {
            self.kept.borrow_mut().insert(
                server.id.clone(),
                KeptConn {
                    spec: server.clone(),
                    conn,
                    at: std::time::Instant::now(),
                },
            );
        } else {
            conn.disconnect().await;
        }
        result
    }
}
