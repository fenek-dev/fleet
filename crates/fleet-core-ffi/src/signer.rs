//! Callback interfaces Swift implements, and the adapter from the FFI
//! signer to `fleet_core::signer::DeviceSigner`.

use crate::types::{AgentEventRow, HostKeyPrompt, KeyRole, SignerError, StateChange};
use fleet_core::signer;
use fleet_crypto::sig::p256_normalize;
use fleet_proto::{P256Public, Signature};

/// The Mac's Secure Enclave P-256 keys (design §5.2, §7.1).
///
/// Calls block and may show Touch ID (root key); the core never makes them
/// on the main thread.
#[uniffi::export(callback_interface)]
pub trait DeviceSigner: Send + Sync {
    /// 33-byte compressed SEC1 public key of `role`.
    fn public_key(&self, role: KeyRole) -> Result<Vec<u8>, SignerError>;
    /// 64-byte raw `r‖s` ECDSA signature over SHA-256(`msg`); high-S is
    /// fine, the adapter normalizes. `reason` is the Touch ID prompt text
    /// for root-key signatures (operation and server count); empty for
    /// the other roles.
    fn sign(&self, role: KeyRole, msg: Vec<u8>, reason: String) -> Result<Vec<u8>, SignerError>;
}

/// Secrets kept in the Keychain (this device only). The enclave can't do
/// X25519 (design §5.2), so the Noise static key crosses the FFI, as does
/// the cache integrity key (MACs over pins and rosters in the local
/// database, `fleet_core::cache`); the core zeroizes its copies.
#[uniffi::export(callback_interface)]
pub trait KeyStore: Send + Sync {
    /// The stored 32-byte secret, or `None` on first launch.
    fn load_noise_key(&self) -> Result<Option<Vec<u8>>, SignerError>;
    fn store_noise_key(&self, secret: Vec<u8>) -> Result<(), SignerError>;
    /// The 32-byte cache integrity key, or `None` before first use.
    fn load_cache_key(&self) -> Result<Option<Vec<u8>>, SignerError>;
    fn store_cache_key(&self, secret: Vec<u8>) -> Result<(), SignerError>;
}

/// Receives manager output on the core thread. Implementations must return
/// quickly (hop to the main actor and return).
#[uniffi::export(callback_interface)]
pub trait CoreListener: Send + Sync {
    fn on_state(&self, change: StateChange);
    fn on_host_key(&self, prompt: HostKeyPrompt);
    fn on_event(&self, event: AgentEventRow);
    /// Events were dropped (slow listener): reload `list_servers`.
    fn on_resync(&self);
    /// Live CPU/memory/disk for the fleet table (10 s telemetry).
    fn on_metrics(&self, row: crate::rows::ServerMetricsRow);
}

/// Checks lengths and normalizes to low-S, which `fleet-exec` requires
/// (rule 3).
pub struct SignerAdapter(pub Box<dyn DeviceSigner>);

impl signer::DeviceSigner for SignerAdapter {
    fn public_key(&self, role: signer::KeyRole) -> Result<P256Public, signer::SignerError> {
        let raw = self.0.public_key(role.into())?;
        let bytes: [u8; 33] = raw
            .as_slice()
            .try_into()
            .map_err(|_| signer::SignerError::Failed)?;
        Ok(P256Public(bytes))
    }

    fn sign(
        &self,
        role: signer::KeyRole,
        msg: &[u8],
        reason: &str,
    ) -> Result<Signature, signer::SignerError> {
        let raw = self.0.sign(role.into(), msg.to_vec(), reason.to_string())?;
        let bytes: [u8; 64] = raw
            .as_slice()
            .try_into()
            .map_err(|_| signer::SignerError::Failed)?;
        p256_normalize(&Signature(bytes)).map_err(|_| signer::SignerError::Failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_core::signer::{DeviceSigner as _, SoftwareDeviceSigner};

    /// Swift stand-in backed by software keys; `truncate` drops a byte.
    pub(crate) struct FakeSigner {
        pub keys: SoftwareDeviceSigner,
        pub truncate: bool,
    }

    impl DeviceSigner for FakeSigner {
        fn public_key(&self, role: KeyRole) -> Result<Vec<u8>, SignerError> {
            let r = role_back(role);
            let pk = self.keys.public_key(r).map_err(|_| SignerError::Failed)?;
            let mut v = pk.0.to_vec();
            if self.truncate {
                v.pop();
            }
            Ok(v)
        }
        fn sign(
            &self,
            role: KeyRole,
            msg: Vec<u8>,
            reason: String,
        ) -> Result<Vec<u8>, SignerError> {
            if role == KeyRole::Root {
                assert_eq!(reason, "approve x (1 server)");
                return Err(SignerError::Cancelled);
            }
            let s = self
                .keys
                .sign(role_back(role), &msg, &reason)
                .map_err(|_| SignerError::Failed)?;
            let mut v = s.0.to_vec();
            if self.truncate {
                v.pop();
            }
            Ok(v)
        }
    }

    fn role_back(r: KeyRole) -> signer::KeyRole {
        match r {
            KeyRole::Root => signer::KeyRole::Root,
            KeyRole::Device => signer::KeyRole::Device,
            KeyRole::Monitor => signer::KeyRole::Monitor,
            KeyRole::Ssh => signer::KeyRole::Ssh,
            KeyRole::MonitorSsh => signer::KeyRole::MonitorSsh,
        }
    }

    fn adapter(truncate: bool) -> SignerAdapter {
        SignerAdapter(Box::new(FakeSigner {
            keys: SoftwareDeviceSigner::generate().unwrap(),
            truncate,
        }))
    }

    #[test]
    fn passes_well_formed_keys_and_signatures() {
        let a = adapter(false);
        let pk = a.public_key(signer::KeyRole::Device).unwrap();
        assert!(pk.0[0] == 2 || pk.0[0] == 3);
        let sig = a.sign(signer::KeyRole::Device, b"msg", "").unwrap();
        // Already low-S: normalizing again is the identity.
        assert_eq!(p256_normalize(&sig).unwrap(), sig);
    }

    #[test]
    fn rejects_wrong_lengths() {
        let a = adapter(true);
        assert_eq!(
            a.public_key(signer::KeyRole::Ssh),
            Err(signer::SignerError::Failed)
        );
        assert_eq!(
            a.sign(signer::KeyRole::Ssh, b"x", ""),
            Err(signer::SignerError::Failed)
        );
    }

    #[test]
    fn maps_cancel() {
        let a = adapter(false);
        assert_eq!(
            a.sign(
                signer::KeyRole::Root,
                b"x",
                &fleet_core::signer::root_reason("x", 1)
            ),
            Err(signer::SignerError::Cancelled)
        );
    }
}
