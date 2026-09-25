//! Multi-Mac features over FFI: roster management and pairing (design
//! §5.12), end-to-end encrypted sync (§7.6), event catch-up and roster
//! alerts (§5.10), sudo passwords (§5.9). Core logic lives in
//! `fleet_core::{roster_mgmt, sync, catchup, sudo}`; this module wires it to
//! the cache, the manager and two new Swift callback interfaces:
//!
//! - [`SyncSecrets`]: the Keychain-held sync key, the Secure Enclave
//!   P-256 key-agreement key (ECDH only; the private key never leaves the
//!   enclave) and the per-server sudo passwords.
//! - [`FleetListener`]: fleet-level alerts (Mac added/revoked, recovery
//!   pending, removed from the fleet, pin changes, sync conflicts).
//!
//! Sync transport is Swift's (CloudKit): it calls [`FleetCore::sync_outgoing`]
//! / [`FleetCore::sync_mark_pushed`] / [`FleetCore::sync_deletions`] and
//! feeds fetched records to [`FleetCore::sync_ingest`]. Local edits are
//! picked up by reconciling the cache with the sync store on every
//! `sync_outgoing` (no hooks in the edit paths).

use crate::api::{FleetCore, id16, lock, spec_for};
use crate::signer::CoreListener;
use crate::types::{AgentEventRow, FleetError, SignerError};
use fleet_core::cache::Cache;
use fleet_core::catchup::{self, EventTracker};
use fleet_core::enroll::{
    SETTING_DEVICE_ID, SETTING_DEVICE_NAME, SETTING_FLEET_ID, SETTING_FLEET_NAME,
};
use fleet_core::manager::{ConnState, ManagerEvent, ManagerHandle, SessionKind};
use fleet_core::roster_mgmt::{self as rm, PairingOffer, PairingResponse, PushOutcome};
use fleet_core::signer::{DeviceSigner as _, KeyRole, RoleSigner};
use fleet_core::sync::bridge::{self, Bridged, GroupDoc, PinsDoc, ServerDoc};
use fleet_core::sync::engine::{Resolution, SyncEngine};
use fleet_core::sync::keys::{self, SyncKey};
use fleet_core::sync::store::SyncStore;
use fleet_core::sync::{Blob, CloudRecord, Collection};
use fleet_crypto::Zeroizing;
use fleet_crypto::hpke::P256Recipient;
use fleet_crypto::roster::verify_genesis;
use fleet_proto::{
    DeviceId, Event, FleetId, KeyRef, PendingRecovery, ServerId, SignedRoster, decode, encode,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};

// ---- callback interfaces ----

/// Keychain and Secure Enclave pieces of sync (design §5.2).
#[uniffi::export(callback_interface)]
pub trait SyncSecrets: Send + Sync {
    /// The 40-byte sync key (`id ‖ key`), or `None` before first use.
    fn load_sync_key(&self) -> Result<Option<Vec<u8>>, SignerError>;
    fn store_sync_key(&self, key: Vec<u8>) -> Result<(), SignerError>;
    /// Uncompressed SEC1 (65 bytes) public key of the enclave P-256
    /// key-agreement key; created on first call.
    fn agreement_public_key(&self) -> Result<Vec<u8>, SignerError>;
    /// ECDH with `peer` (uncompressed SEC1): the 32-byte shared x-coordinate.
    fn agree(&self, peer: Vec<u8>) -> Result<Vec<u8>, SignerError>;
    /// Keeps a server's sudo password in the Keychain (revealed only
    /// behind Touch ID by the app, never typed automatically).
    fn store_sudo_password(&self, server_id: String, password: String) -> Result<(), SignerError>;
    fn delete_sudo_password(&self, server_id: String) -> Result<(), SignerError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FleetAlertKind {
    MacAdded,
    MacRevoked,
    /// A roster change this Mac didn't make and can't describe (yet).
    RosterChanged,
    RecoveryPending,
    RecoveryVetoed,
    /// Signed or unsigned refusal of this Mac (see `signed`).
    RemovedFromFleet,
    /// A server doesn't hold the roster listing this Mac yet.
    WaitingForRoster,
    RosterPushFailed,
    PinChange,
    SyncConflict,
    SyncRejected,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FleetAlertRow {
    pub kind: FleetAlertKind,
    pub server_id: Option<String>,
    /// The Mac a roster alert is about, hex (one-click revoke).
    pub device_id: Option<String>,
    pub title: String,
    pub detail: String,
    /// Recovery pending: hash to veto (hex) and activation time.
    pub pending_hash: Option<String>,
    pub activates_at_ms: Option<u64>,
    /// `RemovedFromFleet`: the refusal carried a receipt.
    pub signed: bool,
}

#[uniffi::export(callback_interface)]
pub trait FleetListener: Send + Sync {
    fn on_fleet_alert(&self, alert: FleetAlertRow);
    /// Synced data changed (reload servers, groups, devices).
    fn on_sync_changed(&self);
}

// ---- rows ----

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CloudRecordRow {
    pub name: String,
    pub data: Vec<u8>,
}

impl From<CloudRecord> for CloudRecordRow {
    fn from(r: CloudRecord) -> Self {
        Self {
            name: r.name,
            data: r.data,
        }
    }
}

impl From<CloudRecordRow> for CloudRecord {
    fn from(r: CloudRecordRow) -> Self {
        Self {
            name: r.name,
            data: r.data,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeviceRow {
    pub id: String,
    pub name: String,
    pub added_at_ms: u64,
    pub added_by: String,
    pub this_mac: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PendingServerRow {
    pub server_id: String,
    pub name: String,
    /// Roster version the server last confirmed, if any.
    pub seen_version: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RosterStatusRow {
    pub epoch: u32,
    pub version: u64,
    pub devices: Vec<DeviceRow>,
    /// Servers still on an older roster (they trust a revoked Mac until
    /// they get the new one).
    pub pending: Vec<PendingServerRow>,
    pub recovery_delay_s: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PairingOfferRow {
    /// `FLEETPAIR1-…`, for the QR code and for pasting.
    pub code: String,
    pub device_id: String,
    /// iCloud record names to watch for the answer and the key box.
    pub response_record: String,
    pub keybox_record: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AddMacPrompt {
    pub name: String,
    pub device_id: String,
    /// Six digits; the new Mac must show the same.
    pub verification_code: String,
    /// Upload before asking the operator to compare codes.
    pub response: CloudRecordRow,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RosterChangeResult {
    pub version: u64,
    /// Servers now on the new roster.
    pub current: u32,
    /// Offline or locked: they catch up on their next connect.
    pub queued: u32,
    /// `server: reason` for refusals.
    pub failed: Vec<String>,
    /// Records to upload / delete now (key boxes, escrow, re-sealed data).
    pub upload: Vec<CloudRecordRow>,
    pub delete: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SyncReportRow {
    pub applied: u32,
    pub conflicts: u32,
    pub pin_changes: u32,
    pub rejected: u32,
    /// Records under a newer sync key: fetch this Mac's key box
    /// (`sync_keybox_record_name`) and call `sync_accept_keybox`.
    pub needs_key: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SyncConflictRow {
    pub collection: String,
    pub key: String,
    pub local: String,
    pub remote: String,
    pub remote_author: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PinChangeRow {
    pub server_id: String,
    pub server_name: String,
    pub changed_by: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ConflictChoice {
    KeepLocal,
    TakeRemote,
    Merged,
}

// ---- state ----

struct OfferDraft {
    offer: PairingOffer,
    response: Option<PairingResponse>,
}

/// Per-`FleetCore` multi-Mac state.
pub(crate) struct FleetState {
    cache_key: Zeroizing<[u8; 32]>,
    sync_path: Option<PathBuf>,
    pub(crate) secrets: Mutex<Option<Arc<dyn SyncSecrets>>>,
    listener: Mutex<Option<Arc<dyn FleetListener>>>,
    pub(crate) sync: Mutex<Option<SyncEngine>>,
    tracker: Mutex<EventTracker>,
    offer: Mutex<Option<OfferDraft>>,
    requests: Mutex<HashMap<DeviceId, (PairingOffer, PairingResponse)>>,
    pub(crate) pending_recoveries: Mutex<HashMap<ServerId, PendingRecovery>>,
    /// Records outside the engine to upload (key boxes, escrow, pairing).
    pub(crate) extra_uploads: Mutex<Vec<CloudRecord>>,
    pub(crate) deletions: Mutex<Vec<String>>,
}

impl FleetState {
    pub(crate) fn new(cache_key: [u8; 32], cache_path: &str) -> Self {
        let sync_path =
            (cache_path != ":memory:").then(|| PathBuf::from(format!("{cache_path}.sync")));
        Self {
            cache_key: Zeroizing::new(cache_key),
            sync_path,
            secrets: Mutex::default(),
            listener: Mutex::default(),
            sync: Mutex::default(),
            tracker: Mutex::default(),
            offer: Mutex::default(),
            requests: Mutex::default(),
            pending_recoveries: Mutex::default(),
            extra_uploads: Mutex::default(),
            deletions: Mutex::default(),
        }
    }

    pub(crate) fn open_store(&self) -> Result<SyncStore, FleetError> {
        match &self.sync_path {
            Some(p) => SyncStore::open(p, &self.cache_key),
            None => SyncStore::open_in_memory(&self.cache_key),
        }
        .map_err(sync_err)
    }
}

pub(crate) fn sync_err(e: impl std::fmt::Display) -> FleetError {
    FleetError::Sync {
        reason: e.to_string(),
    }
}

pub(crate) fn roster_err(e: impl std::fmt::Display) -> FleetError {
    FleetError::Roster {
        reason: e.to_string(),
    }
}

fn keys_err(e: SignerError) -> FleetError {
    FleetError::Keys { error: e }
}

impl From<rm::RosterMgmtError> for FleetError {
    fn from(e: rm::RosterMgmtError) -> Self {
        match e {
            rm::RosterMgmtError::Signer(fleet_core::signer::SignerError::Cancelled) => {
                Self::Cancelled
            }
            rm::RosterMgmtError::Signer(s) => Self::Keys { error: s.into() },
            rm::RosterMgmtError::Cache(c) => c.into(),
            other => roster_err(other),
        }
    }
}

/// The enclave key-agreement key as an HPKE recipient.
pub(crate) struct EnclaveAgreement<'a> {
    secrets: &'a dyn SyncSecrets,
    public: [u8; 65],
}

impl<'a> EnclaveAgreement<'a> {
    pub(crate) fn new(secrets: &'a dyn SyncSecrets) -> Result<Self, FleetError> {
        let pk = secrets.agreement_public_key().map_err(keys_err)?;
        let public = fleet_crypto::hpke::p256_check_public(&pk)
            .map_err(|_| keys_err(SignerError::Failed))?;
        Ok(Self { secrets, public })
    }
}

impl P256Recipient for EnclaveAgreement<'_> {
    fn public(&self) -> [u8; 65] {
        self.public
    }

    fn agree(&self, peer: &[u8; 65]) -> Result<Zeroizing<[u8; 32]>, fleet_crypto::Error> {
        let raw = Zeroizing::new(
            self.secrets
                .agree(peer.to_vec())
                .map_err(|_| fleet_crypto::Error::Signer)?,
        );
        let mut out = Zeroizing::new([0u8; 32]);
        if raw.len() != 32 {
            return Err(fleet_crypto::Error::Signer);
        }
        out.copy_from_slice(&raw);
        Ok(out)
    }
}

pub(crate) fn device_hex(id: &DeviceId) -> String {
    hex::encode(id.0)
}

pub(crate) fn parse_device(s: &str) -> Result<DeviceId, FleetError> {
    let b = hex::decode(s).map_err(|_| FleetError::InvalidArgument {
        field: "device_id".into(),
    })?;
    <[u8; 16]>::try_from(b.as_slice())
        .map(DeviceId)
        .map_err(|_| FleetError::InvalidArgument {
            field: "device_id".into(),
        })
}

/// Runs a blocking closure (Touch ID, Argon2) off the caller's executor.
pub(crate) async fn blocking<T: Send + 'static>(
    name: &str,
    f: impl FnOnce() -> Result<T, FleetError> + Send + 'static,
) -> Result<T, FleetError> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            let _ = tx.send(f());
        })
        .map_err(|e| FleetError::Internal {
            message: e.to_string(),
        })?;
    rx.await.map_err(|_| FleetError::Stopped)?
}

fn setting_str(cache: &Cache, key: &str) -> String {
    cache
        .setting(key)
        .ok()
        .flatten()
        .and_then(|v| String::from_utf8(v).ok())
        .unwrap_or_default()
}

// ---- internals ----

impl FleetCore {
    pub(crate) fn me(&self) -> Result<DeviceId, FleetError> {
        Ok(DeviceId(id16(&lock(&self.cache), SETTING_DEVICE_ID)?))
    }

    pub(crate) fn fleet_id(&self) -> Result<FleetId, FleetError> {
        Ok(FleetId(id16(&lock(&self.cache), SETTING_FLEET_ID)?))
    }

    pub(crate) fn secrets(&self) -> Result<Arc<dyn SyncSecrets>, FleetError> {
        lock(&self.fleet.secrets)
            .clone()
            .ok_or_else(|| sync_err("sync secrets not set"))
    }

    pub(crate) fn alert(&self, a: FleetAlertRow) {
        if let Some(l) = lock(&self.fleet.listener).clone() {
            l.on_fleet_alert(a);
        }
    }

    fn sync_changed(&self) {
        if let Some(l) = lock(&self.fleet.listener).clone() {
            l.on_sync_changed();
        }
    }

    /// Device name in the latest roster, or the hex id.
    fn device_name(&self, id: &DeviceId) -> String {
        let cache = lock(&self.cache);
        rm::chain(&cache)
            .ok()
            .and_then(|c| {
                c.iter()
                    .rev()
                    .find_map(|r| r.roster.device(id).map(|d| d.name.as_str().to_string()))
            })
            .map(crate::text::line)
            .unwrap_or_else(|| device_hex(id))
    }

    /// Opens the engine with `key` over the local store.
    pub(crate) fn install_engine(&self, key: SyncKey) -> Result<(), FleetError> {
        let me = self.me()?;
        let store = self.fleet.open_store()?;
        let engine = SyncEngine::new(store, key, me).map_err(sync_err)?;
        *lock(&self.fleet.sync) = Some(engine);
        Ok(())
    }

    /// Writes local cache state the sync store doesn't have yet (and
    /// tombstones for items deleted locally). Needs the device key
    /// (unlocked); silently does nothing while locked.
    fn reconcile(&self) -> Result<(), FleetError> {
        let Ok(signer) = RoleSigner::new(&*self.keys, KeyRole::Device) else {
            return Ok(());
        };
        let me = self.me()?;
        let agreement = lock(&self.fleet.secrets)
            .clone()
            .and_then(|s| s.agreement_public_key().ok());
        let now = fleet_core::now_ms();
        let mut sync = lock(&self.fleet.sync);
        let Some(engine) = sync.as_mut() else {
            return Ok(());
        };
        let cache = lock(&self.cache);
        let mut wants: Vec<(Collection, String, Option<Vec<u8>>)> = Vec::new();
        let servers = cache.servers()?;
        for s in &servers {
            wants.push((
                Collection::Servers,
                s.id.to_string(),
                Some(encode(&ServerDoc::from_record(s))),
            ));
            if let Some(p) = cache.pins(&s.id)? {
                wants.push((
                    Collection::PinnedKeys,
                    s.id.to_string(),
                    Some(encode(&PinsDoc::from_pins(&p))),
                ));
            }
        }
        for g in cache.groups()? {
            wants.push((
                Collection::Groups,
                g.id.clone(),
                Some(encode(&GroupDoc {
                    name: g.name,
                    sort: g.sort,
                })),
            ));
        }
        for r in rm::chain(&cache)? {
            wants.push((
                Collection::RosterChain,
                bridge::roster_key(&r),
                Some(bridge::roster_body(&r)),
            ));
        }
        if let Some(a) = agreement {
            wants.push((Collection::DeviceKeys, device_hex(&me), Some(a)));
        }
        // Local deletions (servers and groups only; pins go with servers).
        for c in [Collection::Servers, Collection::Groups] {
            for r in engine.list(c).map_err(sync_err)? {
                if !wants.iter().any(|(wc, k, _)| *wc == c && *k == r.key) {
                    wants.push((c, r.key, None));
                }
            }
        }
        let pending_pins: Vec<String> = engine
            .pending_pin_changes()
            .map_err(sync_err)?
            .into_iter()
            .map(|r| r.key)
            .collect();
        drop(cache);
        for (c, k, body) in wants {
            let have = engine.get(c, &k).map_err(sync_err)?;
            match body {
                Some(b) => {
                    // Roster copies never change; pins under review wait.
                    let same = have.as_ref().is_some_and(|h| h.body == b);
                    let skip = (c == Collection::RosterChain && have.is_some())
                        || (c == Collection::PinnedKeys && pending_pins.contains(&k));
                    if !same && !skip {
                        engine.put(&signer, c, &k, b, now).map_err(sync_err)?;
                    }
                }
                None => {
                    if have.is_some() {
                        engine.delete(&signer, c, &k, now).map_err(sync_err)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Applies merged records to the cache, the manager and the Keychain.
    fn bridge_applied(&self, applied: &[fleet_core::sync::SyncRecord]) -> Result<bool, FleetError> {
        let mut order: Vec<&fleet_core::sync::SyncRecord> = applied.iter().collect();
        let rank = |c: Collection| match c {
            Collection::RosterChain => 0,
            Collection::Groups => 1,
            Collection::Servers => 2,
            Collection::PinnedKeys => 3,
            _ => 4,
        };
        order.sort_by_key(|r| rank(r.collection));
        let mut roster_added = false;
        let handle = self.running().ok().map(|(h, _)| h);
        for r in order {
            if r.collection == Collection::SudoPasswords {
                if let Ok(s) = self.secrets() {
                    if r.deleted {
                        let _ = s.delete_sudo_password(r.key.clone());
                    } else if let Ok(pw) = std::str::from_utf8(&r.body)
                        && fleet_core::sudo::is_valid(pw)
                    {
                        let _ = s.store_sudo_password(r.key.clone(), pw.to_string());
                    }
                }
                continue;
            }
            let res = bridge::apply_to_cache(&mut lock(&self.cache), r);
            match res {
                Ok(Bridged::Server(id) | Bridged::Pins(id)) => {
                    let _ = self.connect_pinned(&id);
                }
                Ok(Bridged::ServerRemoved(id)) => {
                    if let Some(h) = &handle {
                        h.remove_server(&id);
                    }
                }
                Ok(Bridged::Roster { .. }) => roster_added = true,
                Ok(_) => {}
                Err(_) => self.alert(FleetAlertRow {
                    kind: FleetAlertKind::SyncRejected,
                    server_id: None,
                    device_id: Some(device_hex(&r.author)),
                    title: "A synced record was refused".into(),
                    detail: format!(
                        "{:?} {} from {}",
                        r.collection,
                        crate::text::line(r.key.clone()),
                        self.device_name(&r.author)
                    ),
                    pending_hash: None,
                    activates_at_ms: None,
                    signed: false,
                }),
            }
        }
        Ok(roster_added)
    }

    /// Pushes the local chain to `servers`; records what each confirmed.
    async fn push_to(
        handle: &ManagerHandle,
        core: &Weak<FleetCore>,
        servers: Vec<ServerId>,
    ) -> RosterChangeResult {
        let mut res = RosterChangeResult {
            version: 0,
            current: 0,
            queued: 0,
            failed: Vec::new(),
            upload: Vec::new(),
            delete: Vec::new(),
        };
        let Some(chain) = core.upgrade().and_then(|c| rm::chain(&lock(&c.cache)).ok()) else {
            return res;
        };
        res.version = chain.last().map_or(0, |r| r.roster.version);
        for s in servers {
            match rm::push_chain(handle, &s, &chain).await {
                PushOutcome::Current { epoch, version } => {
                    res.current += 1;
                    if let Some(c) = core.upgrade() {
                        let _ = rm::set_seen(&lock(&c.cache), &s, (epoch, version));
                    }
                }
                PushOutcome::Queued => res.queued += 1,
                PushOutcome::Rejected { at_version, code } => res
                    .failed
                    .push(format!("{s}: v{at_version} refused ({code:?})")),
                PushOutcome::Unknown(m) => res.failed.push(format!("{s}: {m}")),
            }
        }
        res
    }

    fn managed_servers(&self) -> Result<Vec<ServerId>, FleetError> {
        let cache = lock(&self.cache);
        let mut out = Vec::new();
        for rec in cache.servers()? {
            if spec_for(&cache, &rec)?.is_some() {
                out.push(rec.id);
            }
        }
        Ok(out)
    }

    /// Accepts the cached genesis for an agent install when it isn't this
    /// Mac's own (a Mac that joined later): it must be the first link of
    /// the verified local chain, and the latest roster must list this Mac
    /// with its current keys. The new server then learns the rest of the
    /// chain from any connected Mac already in its roster.
    pub(crate) fn genesis_is_anchor(
        &self,
        genesis: &SignedRoster,
        device_id: DeviceId,
    ) -> Result<(), FleetError> {
        let chain = rm::chain(&lock(&self.cache))?;
        let first_ok = chain.first() == Some(genesis);
        let noise = self.noise_key()?.public();
        let me_ok = chain
            .last()
            .and_then(|l| l.roster.device(&device_id))
            .is_some_and(|d| {
                d.noise_static == noise
                    && self
                        .keys
                        .public_key(KeyRole::Device)
                        .is_ok_and(|k| k == d.device_key)
                    && self
                        .keys
                        .public_key(KeyRole::Ssh)
                        .is_ok_and(|k| k == d.ssh_key)
            });
        if first_ok && me_ok {
            Ok(())
        } else {
            Err(roster_err("genesis roster is not part of this Mac's fleet"))
        }
    }

    /// Delivers one verified agent event: the existing listener plus the
    /// roster/recovery alerts (design §5.10).
    fn deliver(&self, listener: &dyn CoreListener, server: &ServerId, seq: u64, event: &Event) {
        listener.on_event(AgentEventRow::new(server.to_string(), seq, event));
        match event {
            Event::RosterChanged { epoch, version } => {
                let (chain, me) = {
                    let cache = lock(&self.cache);
                    let _ = rm::set_seen(&cache, server, (*epoch, *version));
                    (
                        rm::chain(&cache).unwrap_or_default(),
                        id16(&cache, SETTING_DEVICE_ID).ok(),
                    )
                };
                match rm::describe_version(&chain, *epoch, *version) {
                    Some(ch) if ch.by.as_ref().map(|b| b.0 .0) == me => {}
                    Some(ch) => {
                        let by = ch.by.as_ref().map_or("the recovery key".to_string(), |b| crate::text::line(b.1.clone()));
                        for (id, name) in &ch.added {
                            self.alert(FleetAlertRow {
                                kind: FleetAlertKind::MacAdded,
                                server_id: Some(server.to_string()),
                                device_id: Some(device_hex(id)),
                                title: format!("Mac added by {by}"),
                                detail: format!("{} joined the fleet (roster v{version}).", crate::text::line(name.clone())),
                                pending_hash: None,
                                activates_at_ms: None,
                                signed: true,
                            });
                        }
                        for (id, name) in &ch.removed {
                            self.alert(FleetAlertRow {
                                kind: FleetAlertKind::MacRevoked,
                                server_id: Some(server.to_string()),
                                device_id: Some(device_hex(id)),
                                title: format!("Mac revoked by {by}"),
                                detail: format!("{} was removed (roster v{version}).", crate::text::line(name.clone())),
                                pending_hash: None,
                                activates_at_ms: None,
                                signed: true,
                            });
                        }
                        if ch.added.is_empty() && ch.removed.is_empty() {
                            self.alert(FleetAlertRow {
                                kind: FleetAlertKind::RosterChanged,
                                server_id: Some(server.to_string()),
                                device_id: ch.by.as_ref().map(|b| device_hex(&b.0)),
                                title: format!("Roster changed by {by}"),
                                detail: if ch.recovery_changed {
                                    format!("The recovery code was replaced (roster v{version}).")
                                } else {
                                    format!("Roster v{version}.")
                                },
                                pending_hash: None,
                                activates_at_ms: None,
                                signed: true,
                            });
                        }
                    }
                    None => self.alert(FleetAlertRow {
                        kind: FleetAlertKind::RosterChanged,
                        server_id: Some(server.to_string()),
                        device_id: None,
                        title: "Roster changed on a server".into(),
                        detail: format!(
                            "{server} now holds roster epoch {epoch} v{version}, which this Mac hasn't seen. Details follow once it syncs."
                        ),
                        pending_hash: None,
                        activates_at_ms: None,
                        signed: true,
                    }),
                }
            }
            Event::RecoveryPending(p) => {
                lock(&self.fleet.pending_recoveries).insert(server.clone(), *p);
                self.alert(FleetAlertRow {
                    kind: FleetAlertKind::RecoveryPending,
                    server_id: Some(server.to_string()),
                    device_id: None,
                    title: "Fleet recovery pending".into(),
                    detail: format!(
                        "Someone used the recovery code on {server}. Veto it unless it was you."
                    ),
                    pending_hash: Some(hex::encode(p.hash)),
                    activates_at_ms: Some(p.activates_at_ms),
                    signed: true,
                });
            }
            Event::RecoveryVetoed { hash } => {
                lock(&self.fleet.pending_recoveries).remove(server);
                self.alert(FleetAlertRow {
                    kind: FleetAlertKind::RecoveryVetoed,
                    server_id: Some(server.to_string()),
                    device_id: None,
                    title: "Recovery vetoed".into(),
                    detail: format!(
                        "The pending recovery {} on {server} was vetoed.",
                        &hex::encode(hash)[..12]
                    ),
                    pending_hash: Some(hex::encode(hash)),
                    activates_at_ms: None,
                    signed: true,
                });
            }
            _ => {}
        }
    }

    fn removed_alert(&self, server: &ServerId, signed: bool) {
        // A server installed or added before its roster listed this Mac
        // refuses it until another Mac pushes the chain: not an attack.
        let waiting = {
            let cache = lock(&self.cache);
            let me = id16(&cache, SETTING_DEVICE_ID).ok().map(DeviceId);
            let chain = rm::chain(&cache).unwrap_or_default();
            let added = me.and_then(|me| {
                chain
                    .iter()
                    .find(|r| r.roster.device(&me).is_some())
                    .map(|r| (r.roster.epoch, r.roster.version))
            });
            let seen = rm::seen(&cache, server).ok().flatten();
            added.is_some_and(|a| seen.is_none_or(|s| s < a))
        };
        let (kind, title, detail) = if waiting {
            (
                FleetAlertKind::WaitingForRoster,
                "Waiting for a roster update".to_string(),
                format!(
                    "{server} doesn't list this Mac yet. It will once another Mac in the fleet connects to it."
                ),
            )
        } else {
            (
                FleetAlertKind::RemovedFromFleet,
                "This Mac may have been removed from the fleet".to_string(),
                format!(
                    "{server} refused this Mac{}. If no one revoked it, another Mac or the recovery code may have been used against you.",
                    if signed { " (signed by the agent)" } else { "" }
                ),
            )
        };
        self.alert(FleetAlertRow {
            kind,
            server_id: Some(server.to_string()),
            device_id: None,
            title,
            detail,
            pending_hash: None,
            activates_at_ms: None,
            signed,
        });
    }
}

/// Fleet-level handling of manager output: catch-up on Ready, deduped
/// live events, roster pushes to servers that are behind, alerts.
pub(crate) async fn fleet_events(
    core: Weak<FleetCore>,
    handle: ManagerHandle,
    listener: Arc<dyn CoreListener>,
) {
    let mut rx = handle.subscribe();
    loop {
        let ev = match rx.recv().await {
            Ok(ev) => ev,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
        };
        let Some(c) = core.upgrade() else { return };
        match ev {
            ManagerEvent::State {
                server,
                state,
                kind,
                ..
            } => {
                if state == ConnState::Ready {
                    let (core, handle, listener) = (core.clone(), handle.clone(), listener.clone());
                    tokio::spawn(on_ready(core, handle, listener, server, kind));
                } else {
                    lock(&c.fleet.tracker).forget(&server);
                }
            }
            ManagerEvent::Event { server, seq, event } => {
                let deliver = lock(&c.fleet.tracker).live(&server, seq);
                if let Some(cursor) = deliver {
                    if let Some(cur) = cursor {
                        let _ = catchup::store_cursor(&lock(&c.cache), &server, &cur);
                    }
                    c.deliver(&*listener, &server, seq, &event);
                }
            }
            ManagerEvent::RemovedFromFleet { server, signed } => c.removed_alert(&server, signed),
            ManagerEvent::HostKeyFirstUse { .. } => {}
        }
    }
}

async fn on_ready(
    core: Weak<FleetCore>,
    handle: ManagerHandle,
    listener: Arc<dyn CoreListener>,
    server: ServerId,
    kind: Option<SessionKind>,
) {
    let Some((pin, from)) = core.upgrade().and_then(|c| {
        let cache = lock(&c.cache);
        let pin = cache.pins(&server).ok().flatten()?.agent_signing?;
        Some((pin, catchup::load_cursor(&cache, &server).ok().flatten()))
    }) else {
        return;
    };
    if let Ok(up) = catchup::catch_up(&handle, &server, &pin, from).await
        && let Some(c) = core.upgrade()
    {
        for e in &up.events {
            c.deliver(&*listener, &server, e.seq, &e.event);
        }
        if let Some(cur) = up.cursor {
            let _ = catchup::store_cursor(&lock(&c.cache), &server, &cur);
        }
        lock(&c.fleet.tracker).caught_up(&server, &up);
    }
    // Servers behind on the roster catch up (rule 2) — needs a device
    // session; while locked they stay queued.
    if kind == Some(SessionKind::Device) {
        let behind = core.upgrade().is_some_and(|c| {
            rm::pending_servers(&lock(&c.cache), std::slice::from_ref(&server))
                .is_ok_and(|p| !p.is_empty())
        });
        if behind {
            let r = FleetCore::push_to(&handle, &core, vec![server.clone()]).await;
            if let (Some(c), Some(f)) = (core.upgrade(), r.failed.first()) {
                c.alert(FleetAlertRow {
                    kind: FleetAlertKind::RosterPushFailed,
                    server_id: Some(server.to_string()),
                    device_id: None,
                    title: "Roster update refused".into(),
                    detail: f.clone(),
                    pending_hash: None,
                    activates_at_ms: None,
                    signed: true,
                });
            }
        }
    }
}

// ---- exported API ----

#[uniffi::export]
impl FleetCore {
    pub fn set_sync_secrets(&self, secrets: Box<dyn SyncSecrets>) {
        *lock(&self.fleet.secrets) = Some(Arc::from(secrets));
    }

    pub fn set_fleet_listener(&self, listener: Box<dyn FleetListener>) {
        *lock(&self.fleet.listener) = Some(Arc::from(listener));
    }

    // ---- devices ----

    pub fn roster_status(&self) -> Result<RosterStatusRow, FleetError> {
        let servers = self.managed_servers()?;
        let cache = lock(&self.cache);
        let me = id16(&cache, SETTING_DEVICE_ID).ok().map(DeviceId);
        let latest = rm::latest(&cache)?;
        let name_of = |id: &DeviceId| {
            rm::chain(&cache)
                .ok()
                .and_then(|c| {
                    c.iter()
                        .rev()
                        .find_map(|r| r.roster.device(id).map(|d| d.name.as_str().to_string()))
                })
                .unwrap_or_else(|| device_hex(id))
        };
        let devices = latest
            .roster
            .devices
            .iter()
            .map(|d| DeviceRow {
                id: device_hex(&d.id),
                name: crate::text::line(d.name.as_str().to_string()),
                added_at_ms: d.added_at,
                added_by: crate::text::line(name_of(&d.added_by)),
                this_mac: Some(d.id) == me,
            })
            .collect();
        let pending = rm::pending_servers(&cache, &servers)?
            .into_iter()
            .map(|(id, seen)| PendingServerRow {
                name: cache
                    .server(&id)
                    .ok()
                    .flatten()
                    .map(|s| s.name)
                    .unwrap_or_default(),
                server_id: id.to_string(),
                seen_version: seen.map(|s| s.1),
            })
            .collect();
        Ok(RosterStatusRow {
            epoch: latest.roster.epoch,
            version: latest.roster.version,
            devices,
            pending,
            recovery_delay_s: latest.roster.recovery_delay_s,
        })
    }

    /// Enrolled Mac, step 2: parse a scanned or pasted pairing code, create
    /// the answer (upload `response`) and the verification code to compare.
    pub fn begin_add_mac(&self, code: String) -> Result<AddMacPrompt, FleetError> {
        let offer = PairingOffer::parse(&code, fleet_core::now_ms())?;
        let me = self.me()?;
        let (fleet_id, fleet_name, my_name, latest) = {
            let cache = lock(&self.cache);
            (
                FleetId(id16(&cache, SETTING_FLEET_ID)?),
                setting_str(&cache, SETTING_FLEET_NAME),
                setting_str(&cache, SETTING_DEVICE_NAME),
                rm::latest(&cache)?,
            )
        };
        if latest.roster.device(&offer.device_id).is_some() {
            return Err(roster_err("that Mac is already in the roster"));
        }
        let root = self
            .keys
            .public_key(KeyRole::Root)
            .map_err(|e| keys_err(e.into()))?;
        let resp = PairingResponse::new(&offer, fleet_id, &fleet_name, me, &my_name, root)?;
        let sas = rm::sas(&offer, &resp);
        let response = CloudRecord {
            name: rm::pairing_record_name(&offer.nonce, "response"),
            data: encode(&Blob::Pairing(resp.clone())),
        };
        let prompt = AddMacPrompt {
            name: crate::text::line(offer.name.clone()),
            device_id: device_hex(&offer.device_id),
            verification_code: sas,
            response: response.into(),
        };
        lock(&self.fleet.requests).insert(offer.device_id, (offer, resp));
        Ok(prompt)
    }

    /// Enrolled Mac, step 3–4 after the codes matched: roster v+1 (Touch
    /// ID: "add Mac <name>"), pushed to every server (offline ones are
    /// queued), the sync key sealed to the new Mac (upload `upload`).
    pub async fn approve_add_mac(
        self: Arc<Self>,
        device_id: String,
    ) -> Result<RosterChangeResult, FleetError> {
        let id = parse_device(&device_id)?;
        let (offer, _) = lock(&self.fleet.requests)
            .remove(&id)
            .ok_or_else(|| roster_err("no pairing request for that Mac"))?;
        let servers = self.managed_servers()?;
        let core = self.clone();
        let offer2 = offer.clone();
        let n = servers.len();
        blocking("fleet-add-mac", move || {
            let me = core.me()?;
            let latest = rm::latest(&lock(&core.cache))?;
            let now = fleet_core::now_ms();
            let roster = rm::add_mac_roster(&latest, &offer2, me, now)?;
            let what = format!("add Mac {}", offer2.name);
            let signed = rm::sign_next(&*core.keys, me, &latest, roster, &what, n, now)?;
            rm::store_own(&lock(&core.cache), &signed)?;
            Ok(())
        })
        .await?;
        // The key box: the sync key sealed to the new Mac's enclave key.
        let mut upload = Vec::new();
        {
            let fleet_id = self.fleet_id()?;
            let mut sync = lock(&self.fleet.sync);
            if let Some(engine) = sync.as_mut() {
                let name = keys::keybox_record_name(&offer.device_id, &offer.agreement_key);
                let kb = keys::seal_keybox(
                    engine.key(),
                    fleet_id,
                    offer.device_id,
                    &offer.agreement_key,
                    name,
                )
                .map_err(sync_err)?;
                upload.push(kb.into());
                // Its key-agreement key, for key boxes after a rotation.
                if let Ok(signer) = RoleSigner::new(&*self.keys, KeyRole::Device) {
                    engine
                        .put(
                            &signer,
                            Collection::DeviceKeys,
                            &device_hex(&offer.device_id),
                            offer.agreement_key.clone(),
                            fleet_core::now_ms(),
                        )
                        .map_err(sync_err)?;
                }
            }
        }
        let _ = self.reconcile();
        let (handle, _) = self.running()?;
        let weak = Arc::downgrade(&self);
        let mut res = self
            .on_core(async move { Ok(FleetCore::push_to(&handle, &weak, servers).await) })
            .await?;
        res.upload.extend(upload);
        self.sync_changed();
        Ok(res)
    }

    /// Revokes another Mac (Touch ID: "revoke Mac <name>"): roster v+1
    /// without it, pushed to every server; then the sync key is rotated,
    /// sealed to the remaining Macs and re-escrowed (upload/delete).
    pub async fn revoke_mac(
        self: Arc<Self>,
        device_id: String,
    ) -> Result<RosterChangeResult, FleetError> {
        let target = parse_device(&device_id)?;
        let name = self.device_name(&target);
        let servers = self.managed_servers()?;
        let core = self.clone();
        let signed = blocking("fleet-revoke-mac", move || {
            let me = core.me()?;
            let latest = rm::latest(&lock(&core.cache))?;
            let now = fleet_core::now_ms();
            let roster = rm::revoke_mac_roster(&latest, target, me, now)?;
            let what = format!("revoke Mac {name}");
            let signed =
                rm::sign_next(&*core.keys, me, &latest, roster, &what, servers.len(), now)?;
            rm::store_own(&lock(&core.cache), &signed)?;
            Ok(signed)
        })
        .await?;
        let (upload, delete) = self.rotate_sync_key(&signed)?;
        let _ = self.reconcile();
        let (handle, _) = self.running()?;
        let weak = Arc::downgrade(&self);
        let servers = self.managed_servers()?;
        let mut res = self
            .on_core(async move { Ok(FleetCore::push_to(&handle, &weak, servers).await) })
            .await?;
        res.upload.extend(upload.into_iter().map(Into::into));
        res.delete.extend(delete);
        self.sync_changed();
        Ok(res)
    }

    /// Retries roster pushes to every server still behind.
    pub async fn push_pending_rosters(self: Arc<Self>) -> Result<RosterChangeResult, FleetError> {
        let servers = self.managed_servers()?;
        let pending: Vec<ServerId> = rm::pending_servers(&lock(&self.cache), &servers)?
            .into_iter()
            .map(|(s, _)| s)
            .collect();
        let (handle, _) = self.running()?;
        let weak = Arc::downgrade(&self);
        self.on_core(async move { Ok(FleetCore::push_to(&handle, &weak, pending).await) })
            .await
    }

    // ---- joining a fleet (the new Mac) ----

    /// New Mac, step 1: its keys (the app must allow key creation) and the
    /// pairing code to show as a QR code or copy.
    pub fn create_pairing_offer(&self, device_name: String) -> Result<PairingOfferRow, FleetError> {
        if self.is_enrolled() {
            return Err(roster_err("already enrolled"));
        }
        let name = crate::validate::name(&device_name, "device_name")?;
        let secrets = self.secrets()?;
        let agreement = secrets.agreement_public_key().map_err(keys_err)?;
        let id = DeviceId(
            fleet_core::enroll::random_id16().map_err(|_| FleetError::Internal {
                message: "rng".into(),
            })?,
        );
        let noise = self.noise_key()?.public();
        let offer = PairingOffer::build(
            &*self.keys,
            agreement.clone(),
            noise,
            id,
            &name,
            fleet_core::now_ms(),
        )?;
        let row = PairingOfferRow {
            code: offer.to_code(),
            device_id: device_hex(&id),
            response_record: rm::pairing_record_name(&offer.nonce, "response"),
            keybox_record: keys::keybox_record_name(&id, &agreement),
        };
        *lock(&self.fleet.offer) = Some(OfferDraft {
            offer,
            response: None,
        });
        Ok(row)
    }

    /// New Mac, step 2: the enrolled Mac's answer (fetched by
    /// `response_record`); the verification code to compare.
    pub fn pairing_verification_code(
        &self,
        response: CloudRecordRow,
    ) -> Result<String, FleetError> {
        let mut g = lock(&self.fleet.offer);
        let d = g
            .as_mut()
            .ok_or_else(|| roster_err("no pairing in progress"))?;
        if response.name != rm::pairing_record_name(&d.offer.nonce, "response") {
            return Err(roster_err("not the answer to this pairing"));
        }
        let Ok(Blob::Pairing(resp)) = decode::<Blob>(&response.data) else {
            return Err(roster_err("malformed pairing answer"));
        };
        if resp.offer_nonce != d.offer.nonce {
            return Err(roster_err("not the answer to this pairing"));
        }
        let sas = rm::sas(&d.offer, &resp);
        d.response = Some(resp);
        Ok(sas)
    }

    /// New Mac, final step after the operator confirmed the codes and the
    /// enrolled Mac approved: opens the key box with the enclave key,
    /// verifies the synced roster chain (the roster adding this Mac must be
    /// signed by the root key the verified answer named), stores it, and
    /// becomes enrolled. `records`: the whole zone.
    pub fn complete_pairing(
        &self,
        keybox: CloudRecordRow,
        records: Vec<CloudRecordRow>,
    ) -> Result<(), FleetError> {
        let (offer, resp) = {
            let g = lock(&self.fleet.offer);
            let d = g
                .as_ref()
                .ok_or_else(|| roster_err("no pairing in progress"))?;
            let r = d
                .response
                .clone()
                .ok_or_else(|| roster_err("codes not compared yet"))?;
            (d.offer.clone(), r)
        };
        let secrets = self.secrets()?;
        let agreement = EnclaveAgreement::new(&*secrets)?;
        let (fleet_id, key) =
            keys::open_keybox(&keybox.into(), offer.device_id, &agreement).map_err(sync_err)?;
        if fleet_id != resp.fleet_id {
            return Err(roster_err("key box is for another fleet"));
        }
        let records: Vec<CloudRecord> = records.into_iter().map(Into::into).collect();
        let chain = verified_chain(&key, &records, &resp, &offer)?;
        {
            let cache = lock(&self.cache);
            for r in &chain {
                rm::store_own(&cache, r)?;
            }
            cache.set_setting(SETTING_FLEET_NAME, resp.fleet_name.as_bytes())?;
            cache.set_setting(SETTING_DEVICE_NAME, offer.name.as_bytes())?;
            cache.set_setting(SETTING_DEVICE_ID, &offer.device_id.0)?;
            cache.set_setting(SETTING_FLEET_ID, &fleet_id.0)?;
        }
        secrets
            .store_sync_key(key.to_bytes().to_vec())
            .map_err(keys_err)?;
        self.install_engine(key)?;
        lock(&self.fleet.offer).take();
        self.ingest(&records)?;
        Ok(())
    }

    // ---- sync ----

    /// Opens sync after enrollment. With no sync key in the Keychain, a
    /// single-Mac fleet creates one and escrows it to the recovery escrow
    /// key; a Mac in a multi-Mac fleet waits for its key box instead.
    /// Returns whether a new key was created.
    pub fn sync_setup(&self) -> Result<bool, FleetError> {
        if lock(&self.fleet.sync).is_some() {
            return Ok(false);
        }
        let secrets = self.secrets()?;
        if let Some(raw) = secrets.load_sync_key().map_err(keys_err)? {
            let raw = Zeroizing::new(raw);
            self.install_engine(SyncKey::from_bytes(&raw).map_err(sync_err)?)?;
            return Ok(false);
        }
        let (latest, fleet_id, me) = {
            let cache = lock(&self.cache);
            (
                rm::latest(&cache)?,
                FleetId(id16(&cache, SETTING_FLEET_ID)?),
                DeviceId(id16(&cache, SETTING_DEVICE_ID)?),
            )
        };
        if latest.roster.devices.len() != 1 || latest.roster.device(&me).is_none() {
            return Err(sync_err("waiting for the sync key from another Mac"));
        }
        let key = SyncKey::generate().map_err(sync_err)?;
        let escrow = keys::seal_escrow(&key, fleet_id, &latest.roster.recovery_escrow_key)
            .map_err(sync_err)?;
        secrets
            .store_sync_key(key.to_bytes().to_vec())
            .map_err(keys_err)?;
        self.install_engine(key)?;
        lock(&self.fleet.extra_uploads).push(escrow);
        Ok(true)
    }

    pub fn sync_ready(&self) -> bool {
        lock(&self.fleet.sync).is_some()
    }

    /// Records to upload: local changes (reconciled from the cache) plus
    /// key boxes and escrow.
    pub fn sync_outgoing(&self) -> Result<Vec<CloudRecordRow>, FleetError> {
        self.reconcile()?;
        let mut out: Vec<CloudRecordRow> = match lock(&self.fleet.sync).as_ref() {
            Some(e) => e
                .outgoing()
                .map_err(sync_err)?
                .into_iter()
                .map(Into::into)
                .collect(),
            None => Vec::new(),
        };
        out.extend(
            lock(&self.fleet.extra_uploads)
                .iter()
                .cloned()
                .map(Into::into),
        );
        Ok(out)
    }

    pub fn sync_mark_pushed(&self, names: Vec<String>) -> Result<(), FleetError> {
        lock(&self.fleet.extra_uploads).retain(|r| !names.contains(&r.name));
        if let Some(e) = lock(&self.fleet.sync).as_mut() {
            e.mark_pushed(&names).map_err(sync_err)?;
        }
        Ok(())
    }

    /// Record names to delete from the zone (old names after a rotation).
    pub fn sync_deletions(&self) -> Vec<String> {
        lock(&self.fleet.deletions).clone()
    }

    pub fn sync_mark_deleted(&self, names: Vec<String>) {
        lock(&self.fleet.deletions).retain(|n| !names.contains(n));
    }

    /// Merges fetched records and applies them to the cache.
    pub fn sync_ingest(&self, records: Vec<CloudRecordRow>) -> Result<SyncReportRow, FleetError> {
        let records: Vec<CloudRecord> = records.into_iter().map(Into::into).collect();
        self.ingest(&records)
    }

    /// This Mac's key-box record name (fetch it when `needs_key`).
    pub fn sync_keybox_record_name(&self) -> Result<String, FleetError> {
        let a = self.secrets()?.agreement_public_key().map_err(keys_err)?;
        Ok(keys::keybox_record_name(&self.me()?, &a))
    }

    /// Switches to the sync key in this Mac's key box (after a rotation).
    pub fn sync_accept_keybox(&self, keybox: CloudRecordRow) -> Result<(), FleetError> {
        let secrets = self.secrets()?;
        let agreement = EnclaveAgreement::new(&*secrets)?;
        let (fid, key) =
            keys::open_keybox(&keybox.into(), self.me()?, &agreement).map_err(sync_err)?;
        if fid != self.fleet_id()? {
            return Err(sync_err("key box is for another fleet"));
        }
        secrets
            .store_sync_key(key.to_bytes().to_vec())
            .map_err(keys_err)?;
        lock(&self.fleet.sync).take();
        self.install_engine(key)
    }

    pub fn sync_conflicts(&self) -> Result<Vec<SyncConflictRow>, FleetError> {
        let sync = lock(&self.fleet.sync);
        let Some(e) = sync.as_ref() else {
            return Ok(Vec::new());
        };
        let cs = e.conflicts().map_err(sync_err)?;
        drop(sync);
        Ok(cs
            .into_iter()
            .map(|c| SyncConflictRow {
                collection: format!("{:?}", c.local.collection),
                key: crate::text::line(c.local.key.clone()),
                local: crate::text::text(String::from_utf8_lossy(&c.local.body).into_owned()),
                remote: crate::text::text(String::from_utf8_lossy(&c.remote.body).into_owned()),
                remote_author: self.device_name(&c.remote.author),
            })
            .collect())
    }

    pub fn sync_resolve(
        &self,
        collection: String,
        key: String,
        choice: ConflictChoice,
        merged: Option<String>,
    ) -> Result<(), FleetError> {
        let c = Collection::ALL
            .into_iter()
            .find(|c| format!("{c:?}") == collection)
            .ok_or(FleetError::InvalidArgument {
                field: "collection".into(),
            })?;
        let res = match choice {
            ConflictChoice::KeepLocal => Resolution::KeepLocal,
            ConflictChoice::TakeRemote => Resolution::TakeRemote,
            ConflictChoice::Merged => Resolution::Merged(merged.unwrap_or_default().into_bytes()),
        };
        let signer =
            RoleSigner::new(&*self.keys, KeyRole::Device).map_err(|e| keys_err(e.into()))?;
        let mut sync = lock(&self.fleet.sync);
        let e = sync.as_mut().ok_or_else(|| sync_err("sync not set up"))?;
        e.resolve(&signer, c, &key, res, fleet_core::now_ms())
            .map_err(sync_err)?;
        Ok(())
    }

    pub fn pin_changes(&self) -> Result<Vec<PinChangeRow>, FleetError> {
        let changes = match lock(&self.fleet.sync).as_ref() {
            Some(e) => e.pending_pin_changes().map_err(sync_err)?,
            None => return Ok(Vec::new()),
        };
        Ok(changes
            .into_iter()
            .map(|r| PinChangeRow {
                server_name: ServerId::new(r.key.clone())
                    .ok()
                    .and_then(|id| lock(&self.cache).server(&id).ok().flatten())
                    .map(|s| s.name)
                    .unwrap_or_default(),
                server_id: r.key,
                changed_by: self.device_name(&r.author),
            })
            .collect())
    }

    /// The operator confirmed another Mac's change to a server's pins.
    pub fn confirm_pin_change(&self, server_id: String) -> Result<(), FleetError> {
        let rec = {
            let mut sync = lock(&self.fleet.sync);
            let e = sync.as_mut().ok_or_else(|| sync_err("sync not set up"))?;
            e.confirm_pin_change(&server_id).map_err(sync_err)?
        };
        self.bridge_applied(&[rec])?;
        let id = crate::validate::server_id(&server_id)?;
        if let Ok((h, _)) = self.running() {
            h.reconnect(&id);
        }
        Ok(())
    }

    pub fn reject_pin_change(&self, server_id: String) -> Result<(), FleetError> {
        let signer =
            RoleSigner::new(&*self.keys, KeyRole::Device).map_err(|e| keys_err(e.into()))?;
        let mut sync = lock(&self.fleet.sync);
        let e = sync.as_mut().ok_or_else(|| sync_err("sync not set up"))?;
        e.reject_pin_change(&signer, &server_id, fleet_core::now_ms())
            .map_err(sync_err)
    }

    /// A synced app setting (not a security setting: those never sync).
    pub fn synced_setting(&self, key: String) -> Option<Vec<u8>> {
        lock(&self.fleet.sync)
            .as_ref()
            .and_then(|e| e.get(Collection::Settings, &key).ok().flatten())
            .map(|r| r.body)
    }

    pub fn set_synced_setting(&self, key: String, value: Vec<u8>) -> Result<(), FleetError> {
        let signer =
            RoleSigner::new(&*self.keys, KeyRole::Device).map_err(|e| keys_err(e.into()))?;
        let mut sync = lock(&self.fleet.sync);
        let e = sync.as_mut().ok_or_else(|| sync_err("sync not set up"))?;
        e.put(
            &signer,
            Collection::Settings,
            &key,
            value,
            fleet_core::now_ms(),
        )
        .map_err(sync_err)?;
        Ok(())
    }

    // ---- sudo passwords ----

    /// Generates `server_id`'s sudo password if it has none (design §5.9):
    /// stored in the Keychain (via `SyncSecrets`) and synced. Returns
    /// whether one was created. The password is never returned here.
    pub fn ensure_sudo_password(&self, server_id: String) -> Result<bool, FleetError> {
        let id = crate::validate::server_id(&server_id)?;
        let signer =
            RoleSigner::new(&*self.keys, KeyRole::Device).map_err(|e| keys_err(e.into()))?;
        let secrets = self.secrets()?;
        let mut sync = lock(&self.fleet.sync);
        let e = sync.as_mut().ok_or_else(|| sync_err("sync not set up"))?;
        if e.get(Collection::SudoPasswords, id.as_str())
            .map_err(sync_err)?
            .is_some()
        {
            return Ok(false);
        }
        let pw = fleet_core::sudo::generate().map_err(|_| FleetError::Internal {
            message: "rng".into(),
        })?;
        e.put(
            &signer,
            Collection::SudoPasswords,
            id.as_str(),
            pw.as_bytes().to_vec(),
            fleet_core::now_ms(),
        )
        .map_err(sync_err)?;
        secrets
            .store_sudo_password(id.to_string(), pw.to_string())
            .map_err(keys_err)?;
        Ok(true)
    }

    /// Puts a synced sudo password back into the Keychain (e.g. the item
    /// was removed). Does not reveal it; the app reads the Keychain item
    /// behind Touch ID.
    pub fn restore_sudo_password(&self, server_id: String) -> Result<bool, FleetError> {
        let id = crate::validate::server_id(&server_id)?;
        let pw = lock(&self.fleet.sync)
            .as_ref()
            .and_then(|e| e.get(Collection::SudoPasswords, id.as_str()).ok().flatten())
            .map(|r| Zeroizing::new(r.body));
        let Some(pw) = pw else { return Ok(false) };
        let s = std::str::from_utf8(&pw).map_err(|_| sync_err("bad sudo password record"))?;
        self.secrets()?
            .store_sudo_password(id.to_string(), s.to_string())
            .map_err(keys_err)?;
        Ok(true)
    }
}

impl FleetCore {
    pub(crate) fn ingest(&self, records: &[CloudRecord]) -> Result<SyncReportRow, FleetError> {
        let now = fleet_core::now_ms();
        let mut total = SyncReportRow {
            applied: 0,
            conflicts: 0,
            pin_changes: 0,
            rejected: 0,
            needs_key: false,
        };
        // Two passes: records signed by a Mac whose roster arrives in the
        // same batch verify once that roster is in the chain.
        for pass in 0..2 {
            let chain = rm::chain(&lock(&self.cache))?;
            let rep = {
                let mut sync = lock(&self.fleet.sync);
                let e = sync.as_mut().ok_or_else(|| sync_err("sync not set up"))?;
                e.apply_remote(records, &chain, now).map_err(sync_err)?
            };
            let roster_added = self.bridge_applied(&rep.applied)?;
            total.applied += rep.applied.len() as u32;
            total.conflicts += rep.conflicts.len() as u32;
            total.pin_changes += rep.pin_changes.len() as u32;
            total.needs_key |= rep.other_key > 0;
            for (c, k) in &rep.conflicts {
                self.alert(FleetAlertRow {
                    kind: FleetAlertKind::SyncConflict,
                    server_id: None,
                    device_id: None,
                    title: "Edited on two Macs".into(),
                    detail: format!(
                        "{c:?} “{}” changed on another Mac too. Choose a version.",
                        crate::text::line(k.clone())
                    ),
                    pending_hash: None,
                    activates_at_ms: None,
                    signed: false,
                });
            }
            for k in &rep.pin_changes {
                self.alert(FleetAlertRow {
                    kind: FleetAlertKind::PinChange,
                    server_id: Some(k.clone()),
                    device_id: None,
                    title: "Another Mac changed pinned keys".into(),
                    detail: format!(
                        "Confirm the new host/agent keys for {} on this Mac before they are used.",
                        crate::text::line(k.clone())
                    ),
                    pending_hash: None,
                    activates_at_ms: None,
                    signed: false,
                });
            }
            if !roster_added || pass == 1 {
                total.rejected = rep.rejected;
                break;
            }
        }
        if total.applied > 0 {
            self.sync_changed();
        }
        Ok(total)
    }

    /// New sync key after a revocation: re-seals every record, key boxes
    /// for the remaining Macs (their enclave keys from the `DeviceKeys`
    /// records), escrow to the roster's recovery escrow key(s).
    fn rotate_sync_key(
        &self,
        roster: &SignedRoster,
    ) -> Result<(Vec<CloudRecord>, Vec<String>), FleetError> {
        let fleet_id = self.fleet_id()?;
        let me = self.me()?;
        let secrets = self.secrets()?;
        let mut sync = lock(&self.fleet.sync);
        let Some(engine) = sync.as_mut() else {
            return Ok((Vec::new(), Vec::new()));
        };
        let new = SyncKey::generate().map_err(sync_err)?;
        secrets
            .store_sync_key(new.to_bytes().to_vec())
            .map_err(keys_err)?;
        let dev_keys = engine.list(Collection::DeviceKeys).map_err(sync_err)?;
        let (mut upload, delete) = engine.rotate(new).map_err(sync_err)?;
        for d in &roster.roster.devices {
            if d.id == me {
                continue;
            }
            if let Some(k) = dev_keys.iter().find(|r| r.key == device_hex(&d.id)) {
                let name = keys::keybox_record_name(&d.id, &k.body);
                upload.push(
                    keys::seal_keybox(engine.key(), fleet_id, d.id, &k.body, name)
                        .map_err(sync_err)?,
                );
            }
        }
        let r = &roster.roster;
        upload.push(
            keys::seal_escrow(engine.key(), fleet_id, &r.recovery_escrow_key).map_err(sync_err)?,
        );
        if let Some(p) = r
            .prev_recovery
            .filter(|p| p.active_at(fleet_core::now_ms()))
        {
            upload.push(
                keys::seal_escrow(engine.key(), fleet_id, &p.recovery_escrow_key)
                    .map_err(sync_err)?,
            );
        }
        lock(&self.fleet.deletions).extend(delete.iter().cloned());
        Ok((upload, delete))
    }
}

/// The roster chain from synced copies, checked for a joining Mac: a valid
/// genesis, every link valid, this Mac in the latest roster with the keys
/// it offered, and the roster that added it signed by the root key the
/// SAS-verified answer named.
fn verified_chain(
    key: &SyncKey,
    records: &[CloudRecord],
    resp: &PairingResponse,
    offer: &PairingOffer,
) -> Result<Vec<SignedRoster>, FleetError> {
    let mut rosters: Vec<SignedRoster> = records
        .iter()
        .filter_map(|r| key.open_record(r).ok())
        .filter(|s| s.record.collection == Collection::RosterChain && !s.record.deleted)
        .filter_map(|s| decode::<SignedRoster>(&s.record.body).ok())
        .collect();
    rosters.sort_by_key(|r| (r.roster.epoch, r.roster.version));
    rosters.dedup_by_key(|r| (r.roster.epoch, r.roster.version));
    let genesis = rosters
        .first()
        .ok_or_else(|| roster_err("no roster copies in iCloud yet"))?;
    verify_genesis(genesis, genesis.roster.issued_at_ms).map_err(roster_err)?;
    if genesis.roster.fleet_id != resp.fleet_id {
        return Err(roster_err("roster copies are for another fleet"));
    }
    let tmp = Cache::open_in_memory()?;
    rm::store_own(&tmp, genesis)?;
    for r in &rosters[1..] {
        rm::store_chain_link(&tmp, r)?;
    }
    let chain = rm::chain(&tmp)?;
    let latest = chain.last().ok_or_else(|| roster_err("empty chain"))?;
    let mine = latest.roster.device(&offer.device_id).is_some_and(|d| {
        d.device_key == offer.device_key
            && d.noise_static == offer.noise_static
            && d.ssh_key == offer.ssh_key
    });
    let added_by_them = chain.iter().any(|r| {
        r.roster.device(&offer.device_id).is_some()
            && r.signer == KeyRef::Root(resp.by)
            && chain.iter().any(|p| {
                p.roster
                    .device(&resp.by)
                    .is_some_and(|d| d.root_key == resp.by_root_key)
            })
    });
    if !mine || !added_by_them {
        return Err(roster_err(
            "the roster doesn't list this Mac as approved by the Mac you paired with",
        ));
    }
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::{DeviceSigner, KeyStore};
    use crate::types::{HostKeyPrompt, KeyRole as FfiRole, StateChange};
    use fleet_core::signer::SoftwareDeviceSigner;
    use fleet_crypto::hpke::SoftwareP256Recipient;

    struct Soft(SoftwareDeviceSigner);
    fn role(r: FfiRole) -> KeyRole {
        match r {
            FfiRole::Root => KeyRole::Root,
            FfiRole::Device => KeyRole::Device,
            FfiRole::Monitor => KeyRole::Monitor,
            FfiRole::Ssh => KeyRole::Ssh,
            FfiRole::MonitorSsh => KeyRole::MonitorSsh,
        }
    }
    impl DeviceSigner for Soft {
        fn public_key(&self, r: FfiRole) -> Result<Vec<u8>, SignerError> {
            Ok(self.0.public_key(role(r)).unwrap().0.to_vec())
        }
        fn sign(&self, r: FfiRole, msg: Vec<u8>, _: String) -> Result<Vec<u8>, SignerError> {
            Ok(
                fleet_core::signer::DeviceSigner::sign(&self.0, role(r), &msg, "")
                    .unwrap()
                    .0
                    .to_vec(),
            )
        }
    }

    #[derive(Default)]
    struct Store {
        noise: Mutex<Option<Vec<u8>>>,
        cache: Mutex<Option<Vec<u8>>>,
    }
    impl KeyStore for Store {
        fn load_noise_key(&self) -> Result<Option<Vec<u8>>, SignerError> {
            Ok(lock(&self.noise).clone())
        }
        fn store_noise_key(&self, s: Vec<u8>) -> Result<(), SignerError> {
            *lock(&self.noise) = Some(s);
            Ok(())
        }
        fn load_cache_key(&self) -> Result<Option<Vec<u8>>, SignerError> {
            Ok(lock(&self.cache).clone())
        }
        fn store_cache_key(&self, s: Vec<u8>) -> Result<(), SignerError> {
            *lock(&self.cache) = Some(s);
            Ok(())
        }
    }

    struct Secrets {
        key: Mutex<Option<Vec<u8>>>,
        agree: SoftwareP256Recipient,
        sudo: Arc<Mutex<HashMap<String, String>>>,
    }
    impl SyncSecrets for Secrets {
        fn load_sync_key(&self) -> Result<Option<Vec<u8>>, SignerError> {
            Ok(lock(&self.key).clone())
        }
        fn store_sync_key(&self, k: Vec<u8>) -> Result<(), SignerError> {
            *lock(&self.key) = Some(k);
            Ok(())
        }
        fn agreement_public_key(&self) -> Result<Vec<u8>, SignerError> {
            Ok(self.agree.public().to_vec())
        }
        fn agree(&self, peer: Vec<u8>) -> Result<Vec<u8>, SignerError> {
            let p: [u8; 65] = peer.try_into().map_err(|_| SignerError::Failed)?;
            Ok(self.agree.agree(&p).unwrap().to_vec())
        }
        fn store_sudo_password(&self, s: String, p: String) -> Result<(), SignerError> {
            lock(&self.sudo).insert(s, p);
            Ok(())
        }
        fn delete_sudo_password(&self, s: String) -> Result<(), SignerError> {
            lock(&self.sudo).remove(&s);
            Ok(())
        }
    }

    struct Quiet;
    impl CoreListener for Quiet {
        fn on_state(&self, _: StateChange) {}
        fn on_host_key(&self, _: HostKeyPrompt) {}
        fn on_event(&self, _: AgentEventRow) {}
        fn on_resync(&self) {}
        fn on_metrics(&self, _: crate::rows::ServerMetricsRow) {}
    }

    fn mac(
        dir: &tempfile::TempDir,
        name: &str,
    ) -> (Arc<FleetCore>, Arc<Mutex<HashMap<String, String>>>) {
        let path = dir.path().join(format!("{name}.sqlite"));
        let c = FleetCore::open(
            path.to_string_lossy().into_owned(),
            Box::new(Soft(SoftwareDeviceSigner::generate().unwrap())),
            Box::new(Store::default()),
        )
        .unwrap();
        let sudo = Arc::new(Mutex::new(HashMap::new()));
        c.set_sync_secrets(Box::new(Secrets {
            key: Mutex::default(),
            agree: SoftwareP256Recipient::generate().unwrap(),
            sudo: sudo.clone(),
        }));
        (c, sudo)
    }

    fn enroll(c: &FleetCore) {
        use fleet_crypto::recovery::{KdfParams, RecoveryCode};
        let tiny = KdfParams {
            m_kib: 64,
            t: 1,
            p: 1,
        };
        let rk = RecoveryCode::generate().unwrap().derive("", tiny).unwrap();
        let g = fleet_core::enroll::build_genesis(
            &*c.keys,
            fleet_core::enroll::GenesisInput {
                fleet_id: FleetId([4; 16]),
                device_id: DeviceId([1; 16]),
                device_name: "Studio".into(),
                noise_static: c.noise_key().unwrap().public(),
                recovery: rk.publics(),
                recovery_delay_s: 0,
                now_ms: fleet_core::now_ms(),
            },
        )
        .unwrap();
        fleet_core::enroll::persist(&lock(&c.cache), "Prod", "Studio", &g).unwrap();
    }

    fn by_name(rs: &[CloudRecordRow], name: &str) -> CloudRecordRow {
        rs.iter().find(|r| r.name == name).cloned().unwrap()
    }

    #[test]
    fn pairing_sync_sudo_and_revocation_between_two_cores() {
        let dir = tempfile::tempdir().unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (a, _) = mac(&dir, "a");
        enroll(&a);
        assert!(a.sync_setup().unwrap(), "single Mac creates the sync key");
        a.clone().start(Box::new(Quiet)).unwrap();
        let mut cloud: Vec<CloudRecordRow> = a.sync_outgoing().unwrap();
        a.sync_mark_pushed(cloud.iter().map(|r| r.name.clone()).collect())
            .unwrap();

        // New Mac B shows its code; A scans it; both show the same digits.
        let (b, b_sudo) = mac(&dir, "b");
        let offer = b.create_pairing_offer("Laptop".into()).unwrap();
        let prompt = a.begin_add_mac(offer.code.clone()).unwrap();
        assert_eq!(prompt.name, "Laptop");
        assert_eq!(prompt.response.name, offer.response_record);
        let sas = b
            .pairing_verification_code(prompt.response.clone())
            .unwrap();
        assert_eq!(sas, prompt.verification_code);

        let res = rt
            .block_on(a.clone().approve_add_mac(prompt.device_id.clone()))
            .unwrap();
        assert_eq!(res.version, 2);
        cloud.extend(res.upload.clone());
        cloud.extend(a.sync_outgoing().unwrap());
        let keybox = by_name(&cloud, &offer.keybox_record);
        b.complete_pairing(keybox, cloud.clone()).unwrap();
        assert!(b.is_enrolled());
        let st = b.roster_status().unwrap();
        assert_eq!(st.version, 2);
        assert_eq!(st.devices.len(), 2);
        assert!(st.devices.iter().any(|d| d.this_mac && d.name == "Laptop"));

        // A adds a group and a sudo password; B receives both.
        a.add_group("Web".into()).unwrap();
        let sid = "srv_abcdef1";
        {
            let rec = fleet_core::cache::ServerRecord {
                id: ServerId::new(sid).unwrap(),
                name: "web".into(),
                target: fleet_core::ssh::SshTarget::new("web.example.com", 22, "admin"),
                group: None,
                tags: vec![],
            };
            lock(&a.cache).upsert_server(&rec).unwrap();
        }
        assert!(a.ensure_sudo_password(sid.into()).unwrap());
        assert!(!a.ensure_sudo_password(sid.into()).unwrap(), "only once");
        let out = a.sync_outgoing().unwrap();
        a.sync_mark_pushed(out.iter().map(|r| r.name.clone()).collect())
            .unwrap();
        let rep = b.sync_ingest(out).unwrap();
        assert_eq!(rep.rejected, 0);
        assert!(b.list_groups().unwrap().iter().any(|g| g.name == "Web"));
        assert_eq!(b.list_servers().unwrap().len(), 1);
        let pw = lock(&b_sudo).get(sid).cloned().unwrap();
        assert!(fleet_core::sudo::is_valid(&pw));

        // A revokes B: v3, new sync key sealed to nobody else, escrowed.
        let res = rt
            .block_on(a.clone().revoke_mac(prompt.device_id.clone()))
            .unwrap();
        assert_eq!(res.version, 3);
        assert!(!res.delete.is_empty(), "old record names go");
        assert_eq!(a.roster_status().unwrap().devices.len(), 1);
        // B can't read what A writes now.
        a.add_group("Db".into()).unwrap();
        let rep = b.sync_ingest(a.sync_outgoing().unwrap()).unwrap();
        assert!(rep.needs_key);
    }
}
