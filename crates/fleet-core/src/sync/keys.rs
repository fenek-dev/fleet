//! The sync key and the records that carry it (design §5.11, §5.12, §7.6).
//!
//! - Data records: `Blob::Record`, AES-256-GCM under the sync key, AAD
//!   binding the CloudKit record name and key id; the name is a keyed
//!   BLAKE3 of `(collection, key)` (keyed by a key derived from the sync
//!   key), checked again on open so blobs can't be swapped between names.
//! - Escrow: the sync key HPKE-sealed (X25519) to the recovery escrow key.
//!   Its record name derives from the escrow public key, so a recovering
//!   Mac holding only the code finds it.
//! - Key boxes: the sync key HPKE-sealed (P-256) to one Mac's Secure
//!   Enclave key-agreement key; one per Mac, overwritten on rotation.
//! - Both are signed by the sealing Mac's device key ([`Sealer`],
//!   domain-separated over fleet, recipient, key id and ciphertext); a
//!   receiver checks the signer against the latest roster
//!   ([`SealedBy::verify`]) before it uses the key.
//! - Key-agreement keys are self-signed by each Mac's device key
//!   ([`DeviceKeysDoc`]) and checked against that Mac's roster entry before
//!   anything is sealed to them.

use super::{Blob, CloudRecord, Collection, SignedRecord, SyncError};
use fleet_crypto::Zeroizing;
use fleet_crypto::hpke::{self, P256Recipient, Sealed};
use fleet_crypto::sig::{self, Signer};
use fleet_proto::{Device, DeviceId, FleetId, Roster, Signature, X25519Public, decode, encode};

const AAD_DOMAIN: &[u8] = b"fleet/sync-aad/v1";
const SEAL_DOMAIN: &[u8] = b"fleet/sync-key-seal/v1";
const ESCROW_INFO: &[u8] = b"fleet/sync-escrow/v1";
const KEYBOX_INFO: &[u8] = b"fleet/sync-keybox/v1";
const NAME_CONTEXT: &str = "fleet sync record names v1";

/// AES-256 sync key with a random id. Zeroized on drop.
pub struct SyncKey {
    pub id: [u8; 8],
    secret: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for SyncKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SyncKey({})", hex::encode(self.id))
    }
}

impl SyncKey {
    pub fn generate() -> Result<Self, fleet_crypto::Error> {
        let mut id = [0u8; 8];
        fleet_crypto::random_bytes(&mut id)?;
        let mut secret = Zeroizing::new([0u8; 32]);
        fleet_crypto::random_bytes(secret.as_mut())?;
        Ok(Self { id, secret })
    }

    /// `id ‖ secret` (40 bytes), for the Keychain and sealing.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Zeroizing::new(Vec::with_capacity(40));
        v.extend_from_slice(&self.id);
        v.extend_from_slice(self.secret.as_ref());
        v
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, SyncError> {
        if b.len() != 40 {
            return Err(SyncError::Malformed);
        }
        let mut id = [0u8; 8];
        id.copy_from_slice(&b[..8]);
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&b[8..]);
        Ok(Self { id, secret })
    }

    /// CloudKit record name of `(collection, key)` under this key.
    pub fn record_name(&self, collection: Collection, key: &str) -> String {
        let nk = blake3::derive_key(NAME_CONTEXT, self.secret.as_ref());
        let mut h = blake3::Hasher::new_keyed(&nk);
        h.update(&[collection.tag()]);
        h.update(key.as_bytes());
        hex::encode(&h.finalize().as_bytes()[..16])
    }

    fn aad(name: &str, key_id: &[u8; 8]) -> Vec<u8> {
        let mut a = AAD_DOMAIN.to_vec();
        a.extend_from_slice(&(name.len() as u32).to_be_bytes());
        a.extend_from_slice(name.as_bytes());
        a.extend_from_slice(key_id);
        a
    }

    pub fn seal_record(&self, sr: &SignedRecord) -> Result<CloudRecord, SyncError> {
        let name = self.record_name(sr.record.collection, &sr.record.key);
        let pt = Zeroizing::new(encode(sr));
        let sealed = fleet_crypto::aead::seal(&self.secret, &Self::aad(&name, &self.id), &pt)?;
        Ok(CloudRecord {
            data: encode(&Blob::Record {
                key_id: self.id,
                sealed,
            }),
            name,
        })
    }

    /// Opens a data record. `Err(OtherKey)` when another sync key sealed it.
    pub fn open_record(&self, cr: &CloudRecord) -> Result<SignedRecord, SyncError> {
        let Blob::Record { key_id, sealed } = decode(&cr.data).map_err(|_| SyncError::Malformed)?
        else {
            return Err(SyncError::Malformed);
        };
        if key_id != self.id {
            return Err(SyncError::OtherKey);
        }
        let pt = Zeroizing::new(fleet_crypto::aead::open(
            &self.secret,
            &Self::aad(&cr.name, &key_id),
            &sealed,
        )?);
        let sr: SignedRecord = decode(&pt).map_err(|_| SyncError::Malformed)?;
        if self.record_name(sr.record.collection, &sr.record.key) != cr.name {
            return Err(SyncError::Malformed);
        }
        Ok(sr)
    }
}

/// Record name of the escrow for `escrow_pub`.
pub fn escrow_record_name(escrow_pub: &X25519Public) -> String {
    let mut m = b"fleet/escrow-record/v1".to_vec();
    m.extend_from_slice(&escrow_pub.0);
    hex::encode(&fleet_crypto::blake3(&m)[..16])
}

fn fleet_aad(fleet_id: &FleetId, key_id: &[u8; 8]) -> Vec<u8> {
    let mut a = fleet_id.0.to_vec();
    a.extend_from_slice(key_id);
    a
}

/// The Mac sealing a sync key: its id and device key. Key boxes and
/// escrow records carry its signature over
/// `SEAL_DOMAIN ‖ kind ‖ fleet_id ‖ len ‖ recipient ‖ key_id ‖ postcard(sealed)`,
/// so a receiver accepts a (rotated) sync key only from a roster member.
pub struct Sealer<'a> {
    pub id: DeviceId,
    pub device: &'a dyn Signer,
}

/// Who signed an opened key box or escrow, and what. Not trusted until
/// [`SealedBy::verify`] against the roster (for the escrow, once the
/// chain is known: its roster copies are sealed under the key inside).
#[derive(Debug, Clone)]
pub struct SealedBy {
    pub signer: DeviceId,
    msg: Vec<u8>,
    sig: Signature,
}

impl SealedBy {
    /// The signer must be in `roster` (the latest) and its device key must
    /// have signed.
    pub fn verify(&self, roster: &Roster) -> Result<DeviceId, SyncError> {
        let dev = roster.device(&self.signer).ok_or(SyncError::Sealer)?;
        sig::p256_verify(&dev.device_key, &self.msg, &self.sig).map_err(|_| SyncError::Sealer)?;
        Ok(self.signer)
    }
}

const KIND_ESCROW: u8 = 1;
const KIND_KEYBOX: u8 = 2;

fn seal_message(
    kind: u8,
    fleet_id: &FleetId,
    recipient: &[u8],
    key_id: &[u8; 8],
    sealed: &Sealed,
) -> Vec<u8> {
    let mut m = SEAL_DOMAIN.to_vec();
    m.push(kind);
    m.extend_from_slice(&fleet_id.0);
    m.extend_from_slice(&(recipient.len() as u32).to_be_bytes());
    m.extend_from_slice(recipient);
    m.extend_from_slice(key_id);
    m.extend_from_slice(&encode(sealed));
    m
}

fn keybox_recipient(device: &DeviceId, agreement_pub: &[u8]) -> Vec<u8> {
    let mut r = device.0.to_vec();
    r.extend_from_slice(agreement_pub);
    r
}

pub fn seal_escrow(
    key: &SyncKey,
    fleet_id: FleetId,
    escrow_pub: &X25519Public,
    by: &Sealer<'_>,
) -> Result<CloudRecord, SyncError> {
    let sealed = hpke::seal_x25519(
        escrow_pub,
        ESCROW_INFO,
        &fleet_aad(&fleet_id, &key.id),
        &key.to_bytes(),
    )?;
    let msg = seal_message(KIND_ESCROW, &fleet_id, &escrow_pub.0, &key.id, &sealed);
    let sig = sig::p256_sign(by.device, &msg)?;
    Ok(CloudRecord {
        name: escrow_record_name(escrow_pub),
        data: encode(&Blob::Escrow {
            fleet_id,
            key_id: key.id,
            sealed,
            signer: by.id,
            sig,
        }),
    })
}

/// Opens the escrow with the escrow secret derived from the recovery code.
/// The returned [`SealedBy`] must be verified against the roster chain
/// before the restored data is trusted.
pub fn open_escrow(
    cr: &CloudRecord,
    escrow_secret: &Zeroizing<[u8; 32]>,
    escrow_pub: &X25519Public,
) -> Result<(FleetId, SyncKey, SealedBy), SyncError> {
    let Blob::Escrow {
        fleet_id,
        key_id,
        sealed,
        signer,
        sig,
    } = decode(&cr.data).map_err(|_| SyncError::Malformed)?
    else {
        return Err(SyncError::Malformed);
    };
    let pt = hpke::open_x25519(
        escrow_secret,
        &sealed,
        ESCROW_INFO,
        &fleet_aad(&fleet_id, &key_id),
    )?;
    let key = SyncKey::from_bytes(&pt)?;
    if key.id != key_id {
        return Err(SyncError::Malformed);
    }
    let msg = seal_message(KIND_ESCROW, &fleet_id, &escrow_pub.0, &key_id, &sealed);
    Ok((fleet_id, key, SealedBy { signer, msg, sig }))
}

/// Record name of `device`'s key box.
pub fn keybox_record_name(device: &DeviceId, agreement_pub: &[u8]) -> String {
    let mut m = b"fleet/keybox-record/v1".to_vec();
    m.extend_from_slice(&device.0);
    m.extend_from_slice(agreement_pub);
    hex::encode(&fleet_crypto::blake3(&m)[..16])
}

fn keybox_info(device: &DeviceId) -> Vec<u8> {
    let mut i = KEYBOX_INFO.to_vec();
    i.extend_from_slice(&device.0);
    i
}

pub fn seal_keybox(
    key: &SyncKey,
    fleet_id: FleetId,
    device: DeviceId,
    agreement_pub: &[u8],
    name: String,
    by: &Sealer<'_>,
) -> Result<CloudRecord, SyncError> {
    let sealed = hpke::seal_p256(
        agreement_pub,
        &keybox_info(&device),
        &fleet_aad(&fleet_id, &key.id),
        &key.to_bytes(),
    )?;
    let msg = seal_message(
        KIND_KEYBOX,
        &fleet_id,
        &keybox_recipient(&device, agreement_pub),
        &key.id,
        &sealed,
    );
    let sig = sig::p256_sign(by.device, &msg)?;
    Ok(CloudRecord {
        name,
        data: encode(&Blob::KeyBox {
            fleet_id,
            device_id: device,
            key_id: key.id,
            sealed,
            signer: by.id,
            sig,
        }),
    })
}

/// Opens a key box addressed to `me` with the enclave key-agreement key.
/// The returned [`SealedBy`] must be verified against the latest roster
/// (a joining Mac: once the synced chain is verified) before the key is
/// used: only a roster member may hand out (or rotate) the sync key.
pub fn open_keybox(
    cr: &CloudRecord,
    me: DeviceId,
    recipient: &dyn P256Recipient,
) -> Result<(FleetId, SyncKey, SealedBy), SyncError> {
    let Blob::KeyBox {
        fleet_id,
        device_id,
        key_id,
        sealed,
        signer,
        sig,
    } = decode(&cr.data).map_err(|_| SyncError::Malformed)?
    else {
        return Err(SyncError::Malformed);
    };
    if device_id != me {
        return Err(SyncError::Malformed);
    }
    let pt = hpke::open_p256(
        recipient,
        &sealed,
        &keybox_info(&me),
        &fleet_aad(&fleet_id, &key_id),
    )?;
    let key = SyncKey::from_bytes(&pt)?;
    if key.id != key_id {
        return Err(SyncError::Malformed);
    }
    let msg = seal_message(
        KIND_KEYBOX,
        &fleet_id,
        &keybox_recipient(&me, &recipient.public()),
        &key_id,
        &sealed,
    );
    Ok((fleet_id, key, SealedBy { signer, msg, sig }))
}

// ---- key-agreement keys bound to device identity ----

const AGREEMENT_DOMAIN: &[u8] = b"fleet/agreement-key/v1";

/// Body of a `DeviceKeys` record: a Mac's key-agreement public key,
/// self-signed with its device key, so a key box is only ever sealed to a
/// key the roster device vouched for (not whatever a record author wrote).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeviceKeysDoc {
    /// Uncompressed SEC1 (65 bytes).
    pub agreement: Vec<u8>,
    /// Device key over `AGREEMENT_DOMAIN ‖ device_id ‖ agreement`.
    pub sig: Signature,
}

pub fn agreement_message(device: &DeviceId, agreement: &[u8]) -> Vec<u8> {
    let mut m = AGREEMENT_DOMAIN.to_vec();
    m.extend_from_slice(&device.0);
    m.extend_from_slice(agreement);
    m
}

impl DeviceKeysDoc {
    pub fn sign(
        device_id: &DeviceId,
        agreement: Vec<u8>,
        device: &dyn Signer,
    ) -> Result<Self, SyncError> {
        let sig = sig::p256_sign(device, &agreement_message(device_id, &agreement))?;
        Ok(Self { agreement, sig })
    }

    /// The agreement key, if `device`'s roster device key signed it.
    pub fn verified(&self, device: &Device) -> Result<&[u8], SyncError> {
        hpke::p256_check_public(&self.agreement).map_err(|_| SyncError::Malformed)?;
        sig::p256_verify(
            &device.device_key,
            &agreement_message(&device.id, &self.agreement),
            &self.sig,
        )
        .map_err(|_| SyncError::Signature)?;
        Ok(&self.agreement)
    }
}
