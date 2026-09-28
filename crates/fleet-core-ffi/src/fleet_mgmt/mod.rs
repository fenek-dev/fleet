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
//!
//! Split by concern: [`roster`] (devices, adding and revoking Macs, roster
//! pushes), [`pairing`] (the joining Mac), [`sync`] (sync engine, key
//! boxes, escrow, sudo passwords), [`events`] (agent events and fleet
//! alerts). Shared rows, state and helpers live here.

mod events;
mod pairing;
mod roster;
mod sync;

pub(crate) use events::fleet_events;

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
    DeviceId, Event, FleetId, KeyRef, PendingRecovery, ServerId, SignedRoster, X25519Public,
    decode, encode,
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
    /// Two different signed rosters at the same epoch and version.
    RosterFork,
    /// A server's audit chain was truncated or rewritten after this Mac
    /// verified it (design §5.8). Critical.
    AuditTampered,
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
    /// Genesis roster fingerprint: note it with the recovery code; a
    /// recovery shows it for comparison.
    pub fleet_fingerprint: String,
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
    /// Upload now; the new Mac answers with its revealed secret.
    pub response: CloudRecordRow,
    /// Record to fetch for that reveal; then `add_mac_verification_code`.
    pub reveal_record: String,
}

/// The joining Mac's code and its reveal (commit-reveal pairing).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PairingCodeRow {
    /// Six digits; the enrolled Mac must show the same.
    pub verification_code: String,
    /// Upload now: the enrolled Mac computes its code from it.
    pub reveal: CloudRecordRow,
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

/// Cache setting: `(old escrow public key, grace end)` to retire after a
/// recovery-code rotation.
const ESCROW_RETIRE: &str = "escrow_retire";

// ---- state ----

struct OfferDraft {
    offer: PairingOffer,
    /// Committed in the offer; disclosed only after the answer arrived.
    reveal: [u8; 16],
    response: Option<PairingResponse>,
    /// The operator pressed "codes match" on this (new) Mac.
    confirmed: bool,
}

/// An enrolled Mac's pairing in progress: the offer, its answer and, once
/// the new Mac revealed it, the checked secret.
struct AddRequest {
    offer: PairingOffer,
    response: PairingResponse,
    reveal: Option<[u8; 16]>,
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
    requests: Mutex<HashMap<DeviceId, AddRequest>>,
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
}
