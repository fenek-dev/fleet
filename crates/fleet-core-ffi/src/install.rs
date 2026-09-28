//! Agent install from the app (design §10.1); the steps are in
//! `fleet_core::install`. After the install prints the agent's keys they
//! are pinned together with the confirmed host key, the server joins the
//! connection manager, and a signed `agent.health` read confirms the
//! session end to end.

use crate::api::{FleetCore, id16, lock};
use crate::rows::{InstallProgress, InstallStep};
use crate::types::{
    AgentHealthRow, ConnState, FleetError, HostKeyPrompt, SecurityModeArg, SecurityModeStatus,
};
use crate::validate;
use fleet_core::cache::PinnedKeys;
use fleet_core::install::{self, InstallRequest, InstallStage};
use fleet_core::manager::ConnState as CoreState;
use fleet_core::signer::{KeyRole, RoleSigner};
use fleet_core::ssh::P256SshSigner;
use fleet_proto::{Actor, DeviceId, FleetId, Op, Payload};
use std::sync::Arc;
use std::time::Duration;

/// How long a fresh install may take to reach a Ready session.
const READY_TIMEOUT: Duration = Duration::from_secs(60);

/// Install progress; called on the core thread.
#[uniffi::export(callback_interface)]
pub trait InstallListener: Send + Sync {
    fn on_progress(&self, progress: InstallProgress);
}

fn ssh_signer(core: &FleetCore) -> Result<P256SshSigner<RoleSigner<'_>>, FleetError> {
    RoleSigner::new(&*core.keys, KeyRole::Ssh)
        .map(P256SshSigner)
        .map_err(|e| match e {
            fleet_core::signer::SignerError::Cancelled => FleetError::Cancelled,
            s @ (fleet_core::signer::SignerError::Missing
            | fleet_core::signer::SignerError::Invalidated) => FleetError::Keys { error: s.into() },
            _ => FleetError::Locked,
        })
}

#[uniffi::export]
impl FleetCore {
    /// Connects to `server_id` without a host key pin, authenticating with
    /// this Mac's SSH key (so a missing `authorized_keys` entry shows up
    /// now as `SshKeyRefused`), and returns the host key for the operator
    /// to compare. `accept_host_key` pins it.
    pub async fn probe_host_key(
        self: Arc<Self>,
        server_id: String,
    ) -> Result<HostKeyPrompt, FleetError> {
        let id = validate::server_id(&server_id)?;
        let rec = self.server_record(&id)?;
        let core = self.clone();
        self.on_core(async move {
            let ssh = ssh_signer(&core)?;
            let obs = install::probe(&rec.target, &ssh).await?;
            let prompt = crate::api::host_key_prompt(&id, &obs);
            core.remember_host_key(id, obs);
            Ok(prompt)
        })
        .await
    }

    /// Installs the agent (a `.deb` package or a bare `fleet-agent`
    /// binary at `artifact_path`) with the genesis roster and a default
    /// policy, pins the printed agent keys and connects. `admin_user`
    /// defaults to the SSH user. `security_mode` picks the pushed policy's
    /// starting mode (design §5.4): `Managed` lets Fleet take over host
    /// security as before; `AgentOnly` leaves an already-configured server
    /// alone (no bans, no `authorized_keys` rewriting) until the operator
    /// switches it later. Needs a confirmed host key, an unlocked app (SSH
    /// key) and passwordless sudo (or root).
    pub async fn install_agent(
        self: Arc<Self>,
        server_id: String,
        admin_user: Option<String>,
        artifact_path: String,
        security_mode: SecurityModeArg,
        listener: Box<dyn InstallListener>,
    ) -> Result<AgentHealthRow, FleetError> {
        let id = validate::server_id(&server_id)?;
        let rec = self.server_record(&id)?;
        let artifact = validate::local_path(&artifact_path)?;
        let admin = validate::user(admin_user.as_deref().unwrap_or(&rec.target.user))?;
        let (host_key, genesis, policy_toml, device_id) = {
            let cache = lock(&self.cache);
            let host_key = cache
                .pins(&id)?
                .and_then(|p| p.host_key)
                .ok_or(FleetError::HostKeyNotConfirmed)?;
            let genesis = fleet_core::enroll::genesis(&cache)?;
            let fleet_id = FleetId(id16(&cache, crate::api::SETTING_FLEET_ID)?);
            let device_id = DeviceId(id16(&cache, crate::api::SETTING_DEVICE_ID)?);
            let policy =
                fleet_core::policy::default_policy(fleet_id, id.clone(), security_mode.into());
            let toml = fleet_core::policy::to_toml(&policy)
                .map_err(|message| FleetError::Internal { message })?;
            (host_key, genesis, toml, device_id)
        };
        // The genesis a server will trust forever must be ours: every key
        // this Mac's, self-signed by our root key (cache tampering guard).
        // A Mac that joined later isn't in the genesis: then the genesis
        // must anchor the verified chain that lists this Mac.
        if let Err(e) = fleet_core::enroll::check_genesis_is_ours(
            &genesis,
            &*self.keys,
            self.noise_key()?.public(),
            device_id,
            fleet_core::now_ms(),
        ) {
            self.genesis_is_anchor(&genesis, device_id)
                .map_err(|_| FleetError::from(e))?;
        }
        let listener: Arc<dyn InstallListener> = Arc::from(listener);
        let core = self.clone();
        self.on_core(async move {
            let ssh = ssh_signer(&core)?;
            let l = listener.clone();
            let mut progress = move |s: InstallStage| l.on_progress(s.into());
            let installed = install::install_agent(
                InstallRequest {
                    server_id: &id,
                    target: &rec.target,
                    host_key: host_key.clone(),
                    admin_user: &admin,
                    artifact: &artifact,
                    genesis: &genesis,
                    policy_toml: &policy_toml,
                },
                &ssh,
                &mut progress,
            )
            .await?;

            listener.on_progress(InstallProgress::step(InstallStep::Pinning));
            {
                let cache = lock(&core.cache);
                cache.set_pins(
                    &id,
                    &PinnedKeys {
                        host_key: Some(host_key),
                        agent_noise: Some(installed.noise_static),
                        agent_signing: Some(installed.signing_key),
                    },
                )?;
                // The Mac's copy of what the agent enforces (MCP limits).
                fleet_core::policy::remember_pushed(&cache, &id, &policy_toml)?;
            }
            core.connect_pinned(&id)?;
            // Per-server sudo password (design §5.9): Keychain + sync.
            // Best effort: sync may not be set up yet.
            let _ = core.ensure_sudo_password(id.to_string());

            listener.on_progress(InstallProgress::step(InstallStep::WaitingForAgent));
            let (handle, _) = core.running()?;
            let state = handle.wait_ready(&id, READY_TIMEOUT).await;
            if state != Some(CoreState::Ready) {
                return Err(FleetError::NotReady {
                    state: state
                        .map(ConnState::from)
                        .unwrap_or(ConnState::Disconnected),
                });
            }
            listener.on_progress(InstallProgress::step(InstallStep::CheckingHealth));
            let reply = handle
                .request(&id, Op::AgentHealth, Actor::Human, None)
                .await?;
            match reply.result {
                Ok(Payload::AgentHealth(h)) => Ok(h.into()),
                Ok(_) => Err(FleetError::UnexpectedReply),
                Err(code) => Err(FleetError::Agent {
                    code: format!("{code:?}"),
                }),
            }
        })
        .await
    }

    /// The security mode last pushed to `server_id` (design §5.4):
    /// `Unknown` when this Mac's cached copy of the pushed policy is
    /// missing or its version doesn't match the agent's live
    /// `agent.health.policy_version` — another Mac may have pushed a
    /// newer policy this cache never saw, so guessing Managed or
    /// Agent-only here would be misleading.
    pub async fn security_mode(
        self: Arc<Self>,
        server_id: String,
    ) -> Result<SecurityModeStatus, FleetError> {
        let id = validate::server_id(&server_id)?;
        let health = match self.send_op(&server_id, Op::AgentHealth, None).await? {
            Payload::AgentHealth(h) => h,
            _ => return Err(FleetError::UnexpectedReply),
        };
        let cache = lock(&self.cache);
        let pushed = fleet_core::policy::pushed(&cache, &id);
        Ok(match fresh_pushed(pushed.as_ref(), health.policy_version) {
            Some(p) => SecurityModeArg::from(p.security).into(),
            None => SecurityModeStatus::Unknown,
        })
    }

    /// Switches `server_id` between Managed and Agent-only: a normal
    /// `policy.update` (Elevated, Touch-ID-approved) that keeps every
    /// other setting from the last pushed policy, changing only
    /// `security`. Refuses `PolicyOutOfDate` when this Mac's cached copy
    /// is missing or its version doesn't match the agent's live
    /// `agent.health.policy_version`, rather than silently overwrite
    /// settings pushed by another Mac this cache never saw (design §5.4)
    /// — the operator refreshes (reconnects) and tries again. Switching to
    /// Managed re-enables bans and `authorized_keys` sync immediately, no
    /// agent restart; switching to Agent-only stops them but does **not**
    /// undo firewall or sshd state a prior Managed period already applied.
    pub async fn set_security_mode(
        self: Arc<Self>,
        server_id: String,
        mode: SecurityModeArg,
    ) -> Result<(), FleetError> {
        let id = validate::server_id(&server_id)?;
        let health = match self.send_op(&server_id, Op::AgentHealth, None).await? {
            Payload::AgentHealth(h) => h,
            _ => return Err(FleetError::UnexpectedReply),
        };
        let current = health.policy_version;
        let mut policy = {
            let cache = lock(&self.cache);
            let pushed = fleet_core::policy::pushed(&cache, &id);
            fresh_pushed(pushed.as_ref(), current)
                .cloned()
                .ok_or(FleetError::PolicyOutOfDate)?
        };
        policy.security = mode.into();
        policy.version = current.saturating_add(1);
        let toml = fleet_core::policy::to_toml(&policy)
            .map_err(|message| FleetError::Internal { message })?;
        self.send_op(
            &server_id,
            Op::PolicyUpdate {
                policy_toml: toml.clone(),
            },
            Some(current),
        )
        .await?;
        let cache = lock(&self.cache);
        fleet_core::policy::remember_pushed(&cache, &id, &toml)?;
        Ok(())
    }
}

/// `pushed` if its version equals `live_version` (the agent's own
/// `agent.health.policy_version`), else `None` — the cache is missing or
/// stale relative to what the agent actually enforces (design §5.4).
/// Pulled out of `security_mode`/`set_security_mode` so the "is this cache
/// usable" decision is tested without a live connection.
fn fresh_pushed(pushed: Option<&fleet_proto::Policy>, live_version: u64) -> Option<&fleet_proto::Policy> {
    pushed.filter(|p| p.version == live_version)
}

#[cfg(test)]
mod fresh_pushed_tests {
    use super::fresh_pushed;
    use fleet_proto::policy::SecurityMode;
    use fleet_proto::{FleetId, ServerId};

    fn policy(version: u64) -> fleet_proto::Policy {
        let mut p = fleet_core::policy::default_policy(
            FleetId([1; 16]),
            ServerId::new("srv_abc123def456").unwrap(),
            SecurityMode::Managed,
        );
        p.version = version;
        p
    }

    #[test]
    fn none_when_cache_missing() {
        assert!(fresh_pushed(None, 3).is_none());
    }

    #[test]
    fn none_when_cache_version_differs_from_live() {
        let p = policy(2);
        assert!(fresh_pushed(Some(&p), 3).is_none());
    }

    #[test]
    fn some_when_versions_match() {
        let p = policy(3);
        assert_eq!(fresh_pushed(Some(&p), 3).map(|p| p.version), Some(3));
    }
}
