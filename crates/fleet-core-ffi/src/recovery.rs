//! Recovery over FFI (design §5.11): "Recover fleet" on a fresh install,
//! vetoing a pending recovery, the recovery drill and replacing the code.
//! Core logic: `fleet_core::recovery_flow`.
//!
//! ```text
//! let r = await core.begin_recovery(words, passphrase)   // Argon2id
//! fetch r.escrow_record_name() from iCloud → r.open_escrow(record)
//! fetch the zone → r.restore(records)                     // servers, pins, chain
//! keys.creationAllowed = true                             // new enclave keys
//! let out = await r.recover(device_name, new_passphrase)  // per-server results,
//!                                                         // new words (once), uploads
//! ```

use crate::api::{FleetCore, lock, spec_for};
use crate::fleet_mgmt::{CloudRecordRow, RosterChangeResult, blocking, roster_err, sync_err};
use crate::types::FleetError;
use fleet_core::enroll::{
    SETTING_DEVICE_ID, SETTING_DEVICE_NAME, SETTING_FLEET_ID, SETTING_FLEET_NAME,
};
use fleet_core::manager::ServerSpec;
use fleet_core::recovery_flow::{self as rf, DrillResult, NewCode, ServerRecovery, SshRecovery};
use fleet_core::roster_mgmt as rm;
use fleet_core::signer::{DeviceSigner as _, KeyRole};
use fleet_core::ssh::SshOptions;
use fleet_core::sync::engine::SyncEngine;
use fleet_core::sync::keys::{self, SyncKey};
use fleet_core::sync::{CloudRecord, Collection};
use fleet_crypto::Zeroizing;
use fleet_crypto::recovery::{KdfParams, RecoveryKeys};
use fleet_crypto::roster::verify_genesis;
use fleet_proto::{
    Actor, BoundedString, Device, DeviceId, FleetId, Role, ServerId, SignedRoster, decode,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const SERVER_TIMEOUT: Duration = Duration::from_secs(30);

fn rec_err(e: impl std::fmt::Display) -> FleetError {
    FleetError::Recovery {
        reason: e.to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RestoreRow {
    pub servers: u32,
    pub roster_epoch: u32,
    pub roster_version: u64,
    pub devices_lost: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ServerRecoveryStatus {
    Installed,
    /// Waiting out the recovery delay; a remaining Mac can veto it.
    Pending,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ServerRecoveryRow {
    pub server_id: String,
    pub name: String,
    pub status: ServerRecoveryStatus,
    pub activates_at_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RecoveryResultRow {
    /// The replacement code. Shown once; the used one is dead.
    pub new_words: Vec<String>,
    pub new_delay_s: u32,
    pub servers: Vec<ServerRecoveryRow>,
    pub upload: Vec<CloudRecordRow>,
    pub delete: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DrillRow {
    pub server_id: String,
    pub name: String,
    /// `match`, `mismatch`, `unknown roster`, or why it was unreachable.
    pub result: String,
    pub ok: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CodeRotationRow {
    pub new_words: Vec<String>,
    pub new_delay_s: u32,
    pub change: RosterChangeResult,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PendingRecoveryRow {
    pub server_id: String,
    pub name: String,
    pub pending_hash: String,
    pub activates_at_ms: u64,
}

struct RecState {
    keys: Option<RecoveryKeys>,
    fleet_id: Option<FleetId>,
    key: Option<SyncKey>,
    me: DeviceId,
    fleet_name: String,
}

#[derive(uniffi::Object)]
pub struct RecoverySession {
    core: Arc<FleetCore>,
    st: Mutex<RecState>,
}

fn words(code: &fleet_crypto::recovery::RecoveryCode) -> Vec<String> {
    code.phrase()
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

#[uniffi::export]
impl FleetCore {
    /// Fresh install, "Recover fleet": derives the recovery keys from the
    /// 24 words and passphrase (Argon2id, 256 MiB; slow).
    pub async fn begin_recovery(
        self: Arc<Self>,
        words: String,
        passphrase: String,
    ) -> Result<Arc<RecoverySession>, FleetError> {
        if self.is_enrolled() {
            return Err(rec_err("this Mac is already enrolled"));
        }
        let (words, pass) = (Zeroizing::new(words), Zeroizing::new(passphrase));
        let keys = blocking("fleet-recovery-kdf", move || {
            rf::derive(&words, &pass, KdfParams::PRODUCTION).map_err(rec_err)
        })
        .await?;
        let me = DeviceId(fleet_core::enroll::random_id16().map_err(rec_err)?);
        Ok(Arc::new(RecoverySession {
            core: self,
            st: Mutex::new(RecState {
                keys: Some(keys),
                fleet_id: None,
                key: None,
                me,
                fleet_name: String::new(),
            }),
        }))
    }

    /// Vetoes a pending recovery on one server (root key, Touch ID).
    pub async fn veto_recovery(
        self: Arc<Self>,
        server_id: String,
        pending_hash: String,
    ) -> Result<(), FleetError> {
        let id = crate::validate::server_id(&server_id)?;
        let hash: [u8; 32] = hex::decode(&pending_hash)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(FleetError::InvalidArgument {
                field: "pending_hash".into(),
            })?;
        let core = self.clone();
        let sid = id.clone();
        let (op, approval) = blocking("fleet-veto", move || {
            let (fleet_id, me) = (core.fleet_id()?, core.me()?);
            rm::veto_command(&*core.keys, fleet_id, me, &sid, hash, fleet_core::now_ms())
                .map_err(Into::into)
        })
        .await?;
        let (handle, _) = self.running()?;
        let reply = self
            .on_core(async move {
                handle
                    .request(&id, op, Actor::Human, Some(approval))
                    .await
                    .map_err(FleetError::from)
            })
            .await?;
        reply.result.map(|_| ()).map_err(|code| FleetError::Agent {
            code: format!("{code:?}"),
        })?;
        lock(&self.fleet.pending_recoveries).remove(&crate::validate::server_id(&server_id)?);
        Ok(())
    }

    /// Recoveries reported pending by servers (signed events).
    pub fn pending_recoveries(&self) -> Vec<PendingRecoveryRow> {
        let cache = lock(&self.cache);
        lock(&self.fleet.pending_recoveries)
            .iter()
            .map(|(s, p)| PendingRecoveryRow {
                name: cache
                    .server(s)
                    .ok()
                    .flatten()
                    .map(|r| r.name)
                    .unwrap_or_default(),
                server_id: s.to_string(),
                pending_hash: hex::encode(p.hash),
                activates_at_ms: p.activates_at_ms,
            })
            .collect()
    }

    /// Recovery drill (P1): checks the code against every server's roster;
    /// nothing changes on servers.
    pub async fn recovery_drill(
        self: Arc<Self>,
        words: String,
        passphrase: String,
    ) -> Result<Vec<DrillRow>, FleetError> {
        let (words, pass) = (Zeroizing::new(words), Zeroizing::new(passphrase));
        let publics = blocking("fleet-drill-kdf", move || {
            rf::derive(&words, &pass, KdfParams::PRODUCTION)
                .map(|k| k.publics())
                .map_err(rec_err)
        })
        .await?;
        let (servers, chain, names) = {
            let cache = lock(&self.cache);
            let recs = cache.servers()?;
            let ids: Vec<ServerId> = recs.iter().map(|r| r.id.clone()).collect();
            let names: Vec<(ServerId, String)> = recs.into_iter().map(|r| (r.id, r.name)).collect();
            (ids, rm::chain(&cache)?, names)
        };
        let (handle, _) = self.running()?;
        let results = self
            .on_core(async move {
                Ok(rf::drill(&handle, &servers, &chain, &publics, fleet_core::now_ms()).await)
            })
            .await?;
        Ok(results
            .into_iter()
            .map(|(s, r)| DrillRow {
                name: names
                    .iter()
                    .find(|(i, _)| *i == s)
                    .map(|(_, n)| n.clone())
                    .unwrap_or_default(),
                server_id: s.to_string(),
                ok: r == DrillResult::Match,
                result: match r {
                    DrillResult::Match => "match".into(),
                    DrillResult::Mismatch => "mismatch".into(),
                    DrillResult::UnknownRoster { epoch, version } => {
                        format!("unknown roster e{epoch} v{version}")
                    }
                    DrillResult::Unreachable(m) => crate::text::line(m),
                },
            })
            .collect())
    }

    /// Replaces the recovery code (after a drill, or any time): a
    /// root-signed roster with the new keys and a 72 h grace for the old
    /// ones (rule 6), pushed to every server; the sync key re-escrowed.
    pub async fn rotate_recovery_code(
        self: Arc<Self>,
        passphrase: String,
    ) -> Result<CodeRotationRow, FleetError> {
        let pass = Zeroizing::new(passphrase);
        let servers: Vec<ServerId> = {
            let cache = lock(&self.cache);
            cache.servers()?.into_iter().map(|r| r.id).collect()
        };
        let core = self.clone();
        let n = servers.len();
        let (new_words, delay, signed) = blocking("fleet-rotate-code", move || {
            let next = NewCode::generate(&pass, KdfParams::PRODUCTION).map_err(rec_err)?;
            let me = core.me()?;
            let latest = rm::latest(&lock(&core.cache))?;
            let now = fleet_core::now_ms();
            let r = rf::rotation_roster(&latest, &next.keys.publics(), next.delay_s, now)
                .map_err(rec_err)?;
            let signed = rm::sign_next(
                &*core.keys,
                me,
                &latest,
                r,
                "replace the recovery code",
                n,
                now,
            )?;
            rm::store_own(&lock(&core.cache), &signed)?;
            Ok((words(&next.code), next.delay_s, signed))
        })
        .await?;
        let mut upload = Vec::new();
        if let Some(e) = lock(&self.fleet.sync).as_ref() {
            let fid = self.fleet_id()?;
            upload.push(
                keys::seal_escrow(e.key(), fid, &signed.roster.recovery_escrow_key)
                    .map_err(sync_err)?,
            );
        }
        let mut change = self.clone().push_pending_rosters().await?;
        change.upload.extend(upload.into_iter().map(Into::into));
        Ok(CodeRotationRow {
            new_words,
            new_delay_s: delay,
            change,
        })
    }
}

#[uniffi::export]
impl RecoverySession {
    /// iCloud record holding the escrowed sync key for this code.
    pub fn escrow_record_name(&self) -> Result<String, FleetError> {
        let st = lock(&self.st);
        let k = st
            .keys
            .as_ref()
            .ok_or_else(|| rec_err("session finished"))?;
        Ok(rf::escrow_name(k))
    }

    /// Opens the escrow; returns the fleet id (hex).
    pub fn open_escrow(&self, escrow: CloudRecordRow) -> Result<String, FleetError> {
        let mut st = lock(&self.st);
        let k = st
            .keys
            .as_ref()
            .ok_or_else(|| rec_err("session finished"))?;
        let (fid, key) = keys::open_escrow(&escrow.into(), &k.escrow.secret_bytes())
            .map_err(|_| rec_err("the escrow doesn't open with this code"))?;
        st.fleet_id = Some(fid);
        st.key = Some(key);
        Ok(hex::encode(fid.0))
    }

    /// Restores synced records: roster copies first (verified from
    /// genesis; the latest must hold this code's recovery key), then
    /// servers, pins and the rest.
    pub fn restore(&self, records: Vec<CloudRecordRow>) -> Result<RestoreRow, FleetError> {
        let records: Vec<CloudRecord> = records.into_iter().map(Into::into).collect();
        let mut st = lock(&self.st);
        let key_bytes = st
            .key
            .as_ref()
            .ok_or_else(|| rec_err("open the escrow first"))?
            .to_bytes();
        let key = SyncKey::from_bytes(&key_bytes).map_err(sync_err)?;
        let recovery = st
            .keys
            .as_ref()
            .ok_or_else(|| rec_err("session finished"))?
            .publics();
        let fleet_id = st
            .fleet_id
            .ok_or_else(|| rec_err("open the escrow first"))?;
        let chain = chain_from(&key, &records, fleet_id)?;
        let latest = chain.last().ok_or_else(|| rec_err("no roster copies"))?;
        let r = &latest.roster;
        let ours = r.recovery_key == recovery.recovery_key
            || r.prev_recovery
                .is_some_and(|p| p.recovery_key == recovery.recovery_key);
        if !ours {
            return Err(rec_err("the code doesn't match the fleet's roster"));
        }
        {
            let cache = lock(&self.core.cache);
            for s in &chain {
                rm::store_own(&cache, s)?;
            }
        }
        let store = self.core.fleet.open_store()?;
        let engine = SyncEngine::new(store, key, st.me).map_err(sync_err)?;
        *lock(&self.core.fleet.sync) = Some(engine);
        self.core.ingest(&records)?;
        st.fleet_name = lock(&self.core.fleet.sync)
            .as_ref()
            .and_then(|e| {
                e.get(Collection::Settings, SETTING_FLEET_NAME)
                    .ok()
                    .flatten()
            })
            .and_then(|r| String::from_utf8(r.body).ok())
            .unwrap_or_else(|| "Recovered fleet".into());
        let servers = lock(&self.core.cache).servers()?.len() as u32;
        Ok(RestoreRow {
            servers,
            roster_epoch: r.epoch,
            roster_version: r.version,
            devices_lost: r
                .devices
                .iter()
                .map(|d| crate::text::line(d.name.as_str().to_string()))
                .collect(),
        })
    }

    /// Creates this Mac's roster entry (its new enclave keys), a new
    /// recovery code, the epoch + 1 recovery roster, submits it to every
    /// restored server over the recovery SSH key, then enrolls this Mac,
    /// rotates the sync key (the lost Macs had it) and escrows it to the
    /// new code.
    pub async fn recover(
        &self,
        device_name: String,
        new_passphrase: String,
    ) -> Result<RecoveryResultRow, FleetError> {
        let name = crate::validate::name(&device_name, "device_name")?;
        let pass = Zeroizing::new(new_passphrase);
        let (old, me, fleet_id, fleet_name) = {
            let mut st = lock(&self.st);
            let k = st.keys.take().ok_or_else(|| rec_err("session finished"))?;
            let fid = st
                .fleet_id
                .ok_or_else(|| rec_err("open the escrow first"))?;
            (k, st.me, fid, st.fleet_name.clone())
        };
        let core = self.core.clone();
        blocking("fleet-recover", move || {
            run_recovery(&core, old, me, fleet_id, &name, &fleet_name, &pass)
        })
        .await
    }

    /// Abandons recovery; the derived keys are wiped.
    pub fn cancel(&self) {
        lock(&self.st).keys.take();
    }
}

/// Roster copies from the records, verified as a chain from genesis.
fn chain_from(
    key: &SyncKey,
    records: &[CloudRecord],
    fleet_id: FleetId,
) -> Result<Vec<SignedRoster>, FleetError> {
    let mut rosters: Vec<SignedRoster> = records
        .iter()
        .filter_map(|r| key.open_record(r).ok())
        .filter(|s| s.record.collection == Collection::RosterChain && !s.record.deleted)
        .filter_map(|s| decode::<SignedRoster>(&s.record.body).ok())
        .filter(|r| r.roster.fleet_id == fleet_id)
        .collect();
    rosters.sort_by_key(|r| (r.roster.epoch, r.roster.version));
    rosters.dedup_by_key(|r| (r.roster.epoch, r.roster.version));
    let g = rosters
        .first()
        .ok_or_else(|| rec_err("no roster copies in iCloud"))?;
    verify_genesis(g, g.roster.issued_at_ms).map_err(roster_err)?;
    let tmp = fleet_core::cache::Cache::open_in_memory()?;
    rm::store_own(&tmp, g)?;
    for r in &rosters[1..] {
        // A link that doesn't verify (or whose predecessor is missing)
        // ends the trusted part of the chain.
        if !rm::store_chain_link(&tmp, r).unwrap_or(false) {
            continue;
        }
    }
    Ok(rm::chain(&tmp)?)
}

fn run_recovery(
    core: &Arc<FleetCore>,
    old: RecoveryKeys,
    me: DeviceId,
    fleet_id: FleetId,
    name: &str,
    fleet_name: &str,
    pass: &str,
) -> Result<RecoveryResultRow, FleetError> {
    let keys = |e: fleet_core::signer::SignerError| FleetError::Keys { error: e.into() };
    let noise = core.noise_key()?;
    let device = Device {
        id: me,
        name: BoundedString::new(name).map_err(|_| FleetError::InvalidArgument {
            field: "device_name".into(),
        })?,
        role: Role::Admin,
        root_key: core.keys.public_key(KeyRole::Root).map_err(keys)?,
        device_key: core.keys.public_key(KeyRole::Device).map_err(keys)?,
        monitor_key: core.keys.public_key(KeyRole::Monitor).map_err(keys)?,
        ssh_key: core.keys.public_key(KeyRole::Ssh).map_err(keys)?,
        monitor_ssh_key: core.keys.public_key(KeyRole::MonitorSsh).map_err(keys)?,
        noise_static: noise.public(),
        added_at: fleet_core::now_ms(),
        added_by: me,
    };
    let next = NewCode::generate(pass, KdfParams::PRODUCTION).map_err(rec_err)?;
    let (latest, specs, names) = {
        let cache = lock(&core.cache);
        let mut specs: Vec<ServerSpec> = Vec::new();
        let mut names = Vec::new();
        for rec in cache.servers()? {
            names.push((rec.id.clone(), rec.name.clone()));
            if let Some(s) = spec_for(&cache, &rec)? {
                specs.push(s);
            }
        }
        (rm::latest(&cache)?, specs, names)
    };
    let roster = rf::build_recovery_roster(
        &latest,
        device,
        &old,
        &next.keys.publics(),
        next.delay_s,
        fleet_core::now_ms(),
    )
    .map_err(rec_err)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(rec_err)?;
    let results = {
        let transport = SshRecovery {
            keys: &old,
            noise: &noise,
            fleet_id,
            device_id: me,
            ssh: SshOptions::default(),
            timeout: SERVER_TIMEOUT,
        };
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, rf::recover_all(&transport, &specs, &roster))
    };
    drop(old);
    let any = results.iter().any(|(_, r)| r.is_ok());
    let rows: Vec<ServerRecoveryRow> = names
        .iter()
        .map(|(id, n)| {
            let r = results.iter().find(|(s, _)| s == id).map(|(_, r)| r);
            let (status, at, err) = match r {
                Some(Ok(ServerRecovery::Installed)) => {
                    (ServerRecoveryStatus::Installed, None, None)
                }
                Some(Ok(ServerRecovery::Pending {
                    activates_at_ms, ..
                })) => (ServerRecoveryStatus::Pending, Some(*activates_at_ms), None),
                Some(Err(e)) => (ServerRecoveryStatus::Failed, None, Some(e.to_string())),
                None => (
                    ServerRecoveryStatus::Failed,
                    None,
                    Some("agent keys not restored".into()),
                ),
            };
            ServerRecoveryRow {
                server_id: id.to_string(),
                name: n.clone(),
                status,
                activates_at_ms: at,
                error: err,
            }
        })
        .collect();
    if !any {
        return Err(rec_err(format!(
            "no server accepted the recovery roster ({})",
            rows.iter()
                .filter_map(|r| r.error.clone())
                .collect::<Vec<_>>()
                .join("; ")
        )));
    }
    // Enroll this Mac with the recovery roster as its latest.
    {
        let cache = lock(&core.cache);
        rm::store_own(&cache, &roster)?;
        cache.set_setting(SETTING_FLEET_NAME, fleet_name.as_bytes())?;
        cache.set_setting(SETTING_DEVICE_NAME, name.as_bytes())?;
        cache.set_setting(SETTING_DEVICE_ID, &me.0)?;
        cache.set_setting(SETTING_FLEET_ID, &fleet_id.0)?;
    }
    // Lost Macs had the sync key: rotate it and escrow to the new code.
    let mut upload = Vec::new();
    let mut delete = Vec::new();
    if let Some(e) = lock(&core.fleet.sync).as_mut() {
        let new = SyncKey::generate().map_err(sync_err)?;
        let secrets = core.secrets()?;
        secrets
            .store_sync_key(new.to_bytes().to_vec())
            .map_err(|e| FleetError::Keys { error: e })?;
        let (u, d) = e.rotate(new).map_err(sync_err)?;
        upload = u;
        delete = d;
        upload.push(
            keys::seal_escrow(e.key(), fleet_id, &next.keys.publics().recovery_escrow_key)
                .map_err(sync_err)?,
        );
    }
    lock(&core.fleet.deletions).extend(delete.iter().cloned());
    Ok(RecoveryResultRow {
        new_words: words(&next.code),
        new_delay_s: next.delay_s,
        servers: rows,
        upload: upload.into_iter().map(Into::into).collect(),
        delete,
    })
}
