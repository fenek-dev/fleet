//! End-to-end encrypted sync between Macs (design §7.6).
//!
//! Rust owns formats, encryption and merging; Swift only moves opaque
//! [`CloudRecord`]s to and from a CloudKit private-database zone.
//!
//! - **Records:** one [`SyncRecord`] per logical item (a server, a pin set,
//!   a snippet…), stamped with a hybrid logical clock ([`Hlc`]) and signed
//!   by the author Mac's device key ([`SignedRecord`]); receivers check the
//!   signature against the roster chain ([`verify_record`]), so a record
//!   can't be attributed to a Mac that didn't write it, and a revoked Mac's
//!   records written after its removal are refused.
//! - **Encryption:** AES-256-GCM under the sync key ([`keys::SyncKey`]);
//!   CloudKit record names are keyed hashes of `(collection, key)`, so they
//!   look random and reveal nothing about servers, yet every Mac derives the
//!   same name for the same item. Apple sees ciphertext, sizes and timing.
//! - **Merging** ([`engine`]): newest HLC wins; text documents (snippets,
//!   runbooks, profiles) edited concurrently become a conflict prompt; a
//!   *changed* pin set coming from another Mac waits for local confirmation.
//! - **Escrow and key boxes** ([`keys`]): the sync key sealed to the
//!   recovery escrow key (X25519 HPKE) and to each Mac's Secure Enclave
//!   key-agreement key (P-256 HPKE).
//! - **Local store** ([`store`]): its own SQLite file, rows AES-GCM
//!   encrypted at rest under a key derived from the Keychain-held cache key.
//! - [`bridge`]: synced servers, groups, pins and roster copies ↔ the cache.

pub mod bridge;
pub mod engine;
pub mod keys;
pub mod store;
#[cfg(test)]
mod tests;

use crate::roster_mgmt::PairingResponse;
use fleet_crypto::hpke::Sealed;
use fleet_crypto::sig::{self, Signer};
use fleet_proto::{DeviceId, FleetId, KeyRef, Signature, SignedRoster, encode};
use serde::{Deserialize, Serialize};

const RECORD_DOMAIN: &[u8] = b"fleet/sync-record/v1";
/// A remote clock this far ahead of ours is not adopted (a Mac with a
/// broken clock can't push every later edit into the future).
pub const MAX_HLC_DRIFT_MS: u64 = 24 * 3600 * 1000;
/// Largest record body.
pub const MAX_BODY: usize = 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("crypto: {0}")]
    Crypto(#[from] fleet_crypto::Error),
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("malformed record")]
    Malformed,
    #[error("record sealed with another sync key")]
    OtherKey,
    #[error("record signature invalid or author not in the roster")]
    Signature,
    #[error("record too large")]
    TooLarge,
    #[error("no such conflict or pin change")]
    NotFound,
    /// Key box or escrow not signed by a Mac in the current roster.
    #[error("sealed sync key not signed by a Mac in the roster")]
    Sealer,
    /// Two different rosters with the same epoch and version.
    #[error("roster fork at epoch {epoch} version {version}")]
    RosterFork { epoch: u32, version: u64 },
    /// Stamped implausibly far in the future (quarantined, not merged).
    #[error("record stamped in the future")]
    FutureStamp,
    #[error(transparent)]
    Cache(#[from] crate::cache::CacheError),
}

/// What a record holds (design §7.6 "What syncs"). Tags ride in server
/// records. Metrics and logs never sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Collection {
    Servers,
    Groups,
    Snippets,
    Runbooks,
    Profiles,
    AlertRules,
    PinnedKeys,
    RosterChain,
    AuditMirror,
    SudoPasswords,
    Settings,
    /// Each Mac's sync key-agreement public key (for key boxes).
    DeviceKeys,
}

impl Collection {
    pub const ALL: [Collection; 12] = [
        Collection::Servers,
        Collection::Groups,
        Collection::Snippets,
        Collection::Runbooks,
        Collection::Profiles,
        Collection::AlertRules,
        Collection::PinnedKeys,
        Collection::RosterChain,
        Collection::AuditMirror,
        Collection::SudoPasswords,
        Collection::Settings,
        Collection::DeviceKeys,
    ];

    /// Concurrent edits produce a conflict prompt instead of last-writer-wins.
    pub fn is_text_doc(self) -> bool {
        matches!(
            self,
            Collection::Snippets | Collection::Runbooks | Collection::Profiles
        )
    }

    pub fn tag(self) -> u8 {
        self as u8
    }

    pub fn from_tag(t: u8) -> Option<Self> {
        Self::ALL.get(usize::from(t)).copied()
    }
}

/// Hybrid logical clock stamp. Ordered by wall time, then counter, then
/// author (a total order, so every Mac picks the same winner).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hlc {
    pub wall_ms: u64,
    pub counter: u32,
    pub node: DeviceId,
}

#[derive(Debug, Clone, Copy)]
pub struct HlcClock {
    last: Hlc,
}

impl HlcClock {
    pub fn new(node: DeviceId) -> Self {
        Self {
            last: Hlc {
                wall_ms: 0,
                counter: 0,
                node,
            },
        }
    }

    pub fn restore(last: Hlc) -> Self {
        Self { last }
    }

    pub fn last(&self) -> Hlc {
        self.last
    }

    /// A stamp later than every stamp issued or observed so far.
    pub fn now(&mut self, wall_ms: u64) -> Hlc {
        if wall_ms > self.last.wall_ms {
            self.last.wall_ms = wall_ms;
            self.last.counter = 0;
        } else {
            self.last.counter = self.last.counter.saturating_add(1);
        }
        self.last
    }

    /// Folds in a remote stamp (unless it is implausibly far ahead).
    pub fn observe(&mut self, remote: &Hlc, wall_ms: u64) {
        if remote.wall_ms > wall_ms.saturating_add(MAX_HLC_DRIFT_MS) {
            return;
        }
        if (remote.wall_ms, remote.counter) > (self.last.wall_ms, self.last.counter) {
            self.last.wall_ms = remote.wall_ms;
            self.last.counter = remote.counter;
        }
    }
}

/// One synced item. `Debug` never prints the body (sudo passwords ride in
/// records).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncRecord {
    pub collection: Collection,
    pub key: String,
    pub hlc: Hlc,
    /// Stamp of the synced version this edit started from (conflict
    /// detection for text documents).
    pub base: Option<Hlc>,
    pub author: DeviceId,
    pub deleted: bool,
    pub body: Vec<u8>,
}

impl std::fmt::Debug for SyncRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncRecord")
            .field("collection", &self.collection)
            .field("key", &self.key)
            .field("hlc", &self.hlc)
            .field("base", &self.base)
            .field("author", &self.author)
            .field("deleted", &self.deleted)
            .field("body", &format_args!("<{} bytes>", self.body.len()))
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRecord {
    pub record: SyncRecord,
    /// Author's device key over `RECORD_DOMAIN ‖ postcard(record)`.
    pub sig: Signature,
}

fn signed_message(r: &SyncRecord) -> Vec<u8> {
    let mut m = RECORD_DOMAIN.to_vec();
    m.extend_from_slice(&encode(r));
    m
}

pub fn sign_record(record: SyncRecord, device: &dyn Signer) -> Result<SignedRecord, SyncError> {
    if record.body.len() > MAX_BODY {
        return Err(SyncError::TooLarge);
    }
    let sig = sig::p256_sign(device, &signed_message(&record))?;
    Ok(SignedRecord { record, sig })
}

/// Whether `author` is listed in the latest roster of `chain`.
pub fn author_current(author: &DeviceId, chain: &[SignedRoster]) -> bool {
    chain
        .last()
        .is_some_and(|l| l.roster.device(author).is_some())
}

/// Checks the author's device-key signature against the roster chain
/// (oldest first). The author must be listed in some roster; if it was
/// later removed, only records stamped before the removing roster was
/// issued are accepted. (A removed author's *new* records are refused
/// by the engine regardless of their stamp; this rule governs rows kept
/// from before the removal.)
pub fn verify_record(sr: &SignedRecord, chain: &[SignedRoster]) -> Result<(), SyncError> {
    let r = &sr.record;
    if r.hlc.node != r.author || r.body.len() > MAX_BODY {
        return Err(SyncError::Signature);
    }
    let last_with = chain
        .iter()
        .rposition(|s| s.roster.device(&r.author).is_some())
        .ok_or(SyncError::Signature)?;
    if let Some(removal) = chain.get(last_with + 1)
        && r.hlc.wall_ms >= removal.roster.issued_at_ms
    {
        return Err(SyncError::Signature);
    }
    let dev = chain[last_with]
        .roster
        .device(&r.author)
        .ok_or(SyncError::Signature)?;
    sig::p256_verify(&dev.device_key, &signed_message(r), &sr.sig).map_err(|_| SyncError::Signature)
}

/// What CloudKit stores: an opaque name and bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudRecord {
    pub name: String,
    pub data: Vec<u8>,
}

/// Plain envelope inside [`CloudRecord::data`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Blob {
    /// A [`SignedRecord`] sealed with the sync key `key_id`.
    Record { key_id: [u8; 8], sealed: Vec<u8> },
    /// The sync key sealed to the recovery escrow key (design §5.11),
    /// signed by the sealing Mac's device key ([`keys::SealedBy`]).
    Escrow {
        fleet_id: FleetId,
        key_id: [u8; 8],
        sealed: Sealed,
        signer: DeviceId,
        sig: Signature,
    },
    /// The sync key sealed to one Mac's key-agreement key, signed by the
    /// sealing Mac's device key.
    KeyBox {
        fleet_id: FleetId,
        device_id: DeviceId,
        key_id: [u8; 8],
        sealed: Sealed,
        signer: DeviceId,
        sig: Signature,
    },
    /// Pairing answer (public data, checked by the SAS; design §5.12).
    Pairing(PairingResponse),
    /// The joining Mac's revealed pairing secret (commit-reveal: the offer
    /// carried only its hash; revealed after the answer was fixed).
    PairingReveal {
        offer_nonce: [u8; 16],
        reveal: [u8; 16],
    },
}

/// Signer of a roster: the device that made a change (for alerts).
pub fn roster_author(s: &SignedRoster) -> Option<DeviceId> {
    match s.signer {
        KeyRef::Root(id) => Some(id),
        KeyRef::Recovery => None,
    }
}
