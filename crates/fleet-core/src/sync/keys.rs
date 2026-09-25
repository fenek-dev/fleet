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

use super::{Blob, CloudRecord, Collection, SignedRecord, SyncError};
use fleet_crypto::Zeroizing;
use fleet_crypto::hpke::{self, P256Recipient};
use fleet_proto::{DeviceId, FleetId, X25519Public, decode, encode};

const AAD_DOMAIN: &[u8] = b"fleet/sync-aad/v1";
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

pub fn seal_escrow(
    key: &SyncKey,
    fleet_id: FleetId,
    escrow_pub: &X25519Public,
) -> Result<CloudRecord, SyncError> {
    let sealed = hpke::seal_x25519(
        escrow_pub,
        ESCROW_INFO,
        &fleet_aad(&fleet_id, &key.id),
        &key.to_bytes(),
    )?;
    Ok(CloudRecord {
        name: escrow_record_name(escrow_pub),
        data: encode(&Blob::Escrow {
            fleet_id,
            key_id: key.id,
            sealed,
        }),
    })
}

/// Opens the escrow with the escrow secret derived from the recovery code.
pub fn open_escrow(
    cr: &CloudRecord,
    escrow_secret: &Zeroizing<[u8; 32]>,
) -> Result<(FleetId, SyncKey), SyncError> {
    let Blob::Escrow {
        fleet_id,
        key_id,
        sealed,
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
    Ok((fleet_id, key))
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
) -> Result<CloudRecord, SyncError> {
    let sealed = hpke::seal_p256(
        agreement_pub,
        &keybox_info(&device),
        &fleet_aad(&fleet_id, &key.id),
        &key.to_bytes(),
    )?;
    Ok(CloudRecord {
        name,
        data: encode(&Blob::KeyBox {
            fleet_id,
            device_id: device,
            key_id: key.id,
            sealed,
        }),
    })
}

/// Opens a key box addressed to `me` with the enclave key-agreement key.
pub fn open_keybox(
    cr: &CloudRecord,
    me: DeviceId,
    recipient: &dyn P256Recipient,
) -> Result<(FleetId, SyncKey), SyncError> {
    let Blob::KeyBox {
        fleet_id,
        device_id,
        key_id,
        sealed,
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
    Ok((fleet_id, key))
}
