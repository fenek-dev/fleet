//! Agent releases, rollout and uninstall (design §5.7, §10.2, §10.3):
//! Settings → Agent releases.

use crate::api::{FleetCore, id16, lock};
use crate::bulk::{BulkListener, BulkRunHandle, event_row, targets};
use crate::fleet_mgmt::blocking;
use crate::types::FleetError;
use crate::validate;
use fleet_core::autorevert;
use fleet_core::enroll::SETTING_DEVICE_ID;
use fleet_core::release::{
    self, ImportRequest, ManagerSteps, ReleaseImportError, ReleaseRecord, RolloutTiming,
};
use fleet_proto::{Actor, AgentTarget, DeviceId, Op, Payload};
use std::path::PathBuf;
use std::sync::Arc;

/// Servers updated at once within a phase.
const ROLLOUT_CONCURRENCY: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AgentReleaseRow {
    /// `major.minor.patch`.
    pub version: String,
    /// `x86_64` | `aarch64`.
    pub target: String,
    /// BLAKE3 of the binary (hex), as signed.
    pub blake3: String,
    /// The independent build's attested hash (hex); equal to `blake3`.
    pub attested: String,
    pub artifact_path: String,
    /// Mac whose root key signed (hex device id).
    pub signed_by: String,
    pub imported_ms: u64,
}

fn row(r: &ReleaseRecord) -> AgentReleaseRow {
    let m = &r.signed.manifest;
    AgentReleaseRow {
        version: release::version_string(m.version),
        target: m.target.as_str().to_owned(),
        blake3: hex::encode(m.blake3),
        attested: hex::encode(r.attested),
        artifact_path: r.artifact.clone(),
        signed_by: hex::encode(r.signed.device_id.0),
        imported_ms: r.imported_ms,
    }
}

fn release_err(e: ReleaseImportError) -> FleetError {
    match e {
        ReleaseImportError::Sign(m) if m.contains("cancel") => FleetError::Cancelled,
        ReleaseImportError::Cache(c) => c.into(),
        ReleaseImportError::BadVersion => FleetError::InvalidArgument {
            field: "version".into(),
        },
        ReleaseImportError::BadTarget(_) => FleetError::InvalidArgument {
            field: "target".into(),
        },
        ReleaseImportError::BadAttestation => FleetError::InvalidArgument {
            field: "attested_blake3".into(),
        },
        e => FleetError::Internal {
            message: e.to_string(),
        },
    }
}

fn target(s: &str) -> Result<AgentTarget, FleetError> {
    AgentTarget::parse(s.trim()).ok_or(FleetError::InvalidArgument {
        field: "target".into(),
    })
}

#[uniffi::export]
impl FleetCore {
    /// BLAKE3 (hex) of the agent binary in `artifact_path` (a binary or a
    /// `.deb` from `scripts/build-deb.sh`), to compare with an independent
    /// reproducible build before signing.
    pub async fn agent_artifact_hash(&self, artifact_path: String) -> Result<String, FleetError> {
        blocking("fleet-release-hash", move || {
            release::artifact_hash(&PathBuf::from(artifact_path)).map_err(release_err)
        })
        .await
    }

    /// Imports and root-signs an agent release (Touch ID: "sign agent
    /// release vX"). Refused unless `attested_blake3` (the hash of a
    /// second, independent reproducible build) equals the build's own.
    pub async fn import_agent_release(
        &self,
        artifact_path: String,
        version: String,
        target: String,
        attested_blake3: String,
    ) -> Result<AgentReleaseRow, FleetError> {
        let req = ImportRequest {
            artifact: PathBuf::from(artifact_path),
            version: release::parse_version(&version).map_err(release_err)?,
            target: self::target(&target)?,
            attested: attested_blake3,
        };
        let device = DeviceId(id16(&lock(&self.cache), SETTING_DEVICE_ID)?);
        let keys = self.keys.clone();
        let rec = blocking("fleet-release-sign", move || {
            release::import_release(&*keys, device, &req).map_err(release_err)
        })
        .await?;
        release::remember(&lock(&self.cache), rec.clone())?;
        Ok(row(&rec))
    }

    /// Imported releases, newest first.
    pub fn list_agent_releases(&self) -> Result<Vec<AgentReleaseRow>, FleetError> {
        Ok(release::releases(&lock(&self.cache))?
            .iter()
            .map(row)
            .collect())
    }

    /// Rolls a signed release out to `targets` (first server, then 10%,
    /// then the rest; stops at the first failure). One Touch ID approves
    /// every `agent.update.commit`.
    pub fn rollout_agent_release(
        &self,
        version: String,
        target: String,
        targets: Vec<String>,
        listener: Box<dyn BulkListener>,
    ) -> Result<Arc<BulkRunHandle>, FleetError> {
        let ids = self::targets(&targets)?;
        let v = release::parse_version(&version).map_err(release_err)?;
        let rec =
            release::find(&lock(&self.cache), v, self::target(&target)?).map_err(release_err)?;
        let bin = release::load_binary(&rec).map_err(release_err)?;
        let (handle, _) = self.running()?;
        let approver = self.root_approver()?;
        let steps: Arc<dyn release::UpdateSteps> = Arc::new(ManagerSteps { handle });
        self.spawn_run(move |cancel| {
            Box::pin(async move {
                release::rollout(
                    steps,
                    approver,
                    ids,
                    rec.signed,
                    Arc::new(bin),
                    ROLLOUT_CONCURRENCY,
                    RolloutTiming::default(),
                    cancel,
                    |e| listener.on_event(event_row(e)),
                )
                .await;
            })
        })
    }

    /// Removes the agent from a server without locking the operator out
    /// (design §10.3): `agent.uninstall.prepare` (keys back to
    /// `~/.ssh/authorized_keys`), confirmed over a fresh SSH connection,
    /// then `agent.uninstall`. Two Touch ID approvals.
    pub async fn uninstall_agent(
        &self,
        server_id: String,
        keep_audit: bool,
        remove_firewall: bool,
    ) -> Result<(), FleetError> {
        let id = validate::server_id(&server_id)?;
        let change = match self
            .send_op(&server_id, Op::AgentUninstallPrepare, None)
            .await?
        {
            Payload::ChangePending { change, .. } => change,
            _ => return Err(FleetError::UnexpectedReply),
        };
        let (handle, _) = self.running()?;
        self.on_core(async move {
            autorevert::confirm_pending(&handle, &id, &change, Actor::Human)
                .await
                .map_err(|e| FleetError::Internal {
                    message: format!("SSH without Fleet's key files not confirmed ({e}); reverted"),
                })
        })
        .await?;
        self.send_op(
            &server_id,
            Op::AgentUninstall {
                keep_audit,
                remove_firewall,
            },
            None,
        )
        .await?;
        Ok(())
    }
}
