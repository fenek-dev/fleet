//! Keys the core uses but never holds (design §5.2, §7.1).
//!
//! On a Mac every P-256 key lives in the Secure Enclave. Swift implements
//! [`DeviceSigner`] as a UniFFI callback interface; the core asks it for one
//! signature at a time and never sees private key material (rule 7).
//! [`RoleSigner`] adapts one role to `fleet_crypto`'s [`Signer`], which is
//! what [`crate::CommandSigner::P256`] and the SSH signer take.

use fleet_crypto::sig::{self, Signer, SoftwareP256Signer};
use fleet_proto::{KeyKind, P256Public, Signature};

/// Which Secure Enclave key to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyRole {
    /// Touch ID on every use: rosters, approvals, releases.
    Root,
    /// Usable while the app is unlocked: commands, device sessions.
    Device,
    /// Usable while locked: read-only monitor sessions.
    Monitor,
    /// `ecdsa-sha2-nistp256` SSH client key.
    Ssh,
    /// `ecdsa-sha2-nistp256` SSH key usable while locked; `authorized_keys`
    /// pins it to `fleet-agent bridge --monitor` (design §5.9).
    MonitorSsh,
}

impl KeyRole {
    /// Session key for a session kind; `None` for recovery (Ed25519, not
    /// an enclave key).
    pub fn for_session(kind: KeyKind) -> Option<Self> {
        match kind {
            KeyKind::Device => Some(Self::Device),
            KeyKind::Monitor => Some(Self::Monitor),
            KeyKind::Recovery => None,
        }
    }
}

/// Why a signature could not be produced. Fixed codes; the app words them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignerError {
    /// Not usable now (app locked for device/SSH keys).
    #[error("key unavailable")]
    Unavailable,
    /// Touch ID cancelled or failed.
    #[error("user cancelled")]
    Cancelled,
    #[error("signing failed")]
    Failed,
    /// The key does not exist (Keychain item gone). Never silently
    /// replaced for the root key: the roster lists it.
    #[error("key missing")]
    Missing,
    /// The key was invalidated (root key: enrolled fingerprints changed,
    /// design §5.2). A new key and a roster update are needed.
    #[error("key invalidated")]
    Invalidated,
}

/// The Mac's P-256 keys. FFI shape (UniFFI callback interface):
///
/// ```text
/// callback interface DeviceSigner {
///   [Throws=SignerError] bytes public_key(KeyRole role);  // 33-byte SEC1 compressed
///   // 64-byte r‖s over SHA-256(msg); `reason` is shown in the Touch ID prompt
///   [Throws=SignerError] bytes sign(KeyRole role, bytes msg, string reason);
/// };
/// ```
///
/// `sign` hashes with SHA-256 itself (CryptoKit `signature(for:)`) and may
/// return high-S; callers normalize. Calls are blocking and may show Touch
/// ID (root key), so they must not run on the UI thread. `reason` names the
/// operation and how many servers it affects ([`root_reason`]) so the
/// operator can't be tricked into approving something else (design §5.1).
pub trait DeviceSigner: Send + Sync {
    fn public_key(&self, role: KeyRole) -> Result<P256Public, SignerError>;
    fn sign(&self, role: KeyRole, msg: &[u8], reason: &str) -> Result<Signature, SignerError>;
}

/// Touch ID prompt text for a root-key signature: what is approved and on
/// how many servers.
pub fn root_reason(what: &str, servers: usize) -> String {
    let s = if servers == 1 { "" } else { "s" };
    format!("approve {what} ({servers} server{s})")
}

/// One role of a [`DeviceSigner`] as a `fleet_crypto` [`Signer`]. The
/// public key is fetched once at construction.
pub struct RoleSigner<'a> {
    keys: &'a dyn DeviceSigner,
    role: KeyRole,
    public: P256Public,
    reason: String,
}

impl<'a> RoleSigner<'a> {
    pub fn new(keys: &'a dyn DeviceSigner, role: KeyRole) -> Result<Self, SignerError> {
        Self::with_reason(keys, role, String::new())
    }

    /// With the Touch ID prompt text passed to every `sign` (root key).
    pub fn with_reason(
        keys: &'a dyn DeviceSigner,
        role: KeyRole,
        reason: String,
    ) -> Result<Self, SignerError> {
        let public = keys.public_key(role)?;
        Ok(Self {
            keys,
            role,
            public,
            reason,
        })
    }

    pub fn role(&self) -> KeyRole {
        self.role
    }
}

impl Signer for RoleSigner<'_> {
    fn public(&self) -> P256Public {
        self.public
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature, fleet_crypto::Error> {
        let raw = self
            .keys
            .sign(self.role, msg, &self.reason)
            .map_err(|_| fleet_crypto::Error::Signer)?;
        sig::p256_normalize(&raw)
    }
}

/// [`RoleSigner`] owning its [`DeviceSigner`], so a signature can run on
/// another thread (`CommandSigner::Blocking`).
pub struct SharedRoleSigner {
    keys: std::sync::Arc<dyn DeviceSigner>,
    role: KeyRole,
    public: P256Public,
}

impl SharedRoleSigner {
    pub fn new(keys: std::sync::Arc<dyn DeviceSigner>, role: KeyRole) -> Result<Self, SignerError> {
        let public = keys.public_key(role)?;
        Ok(Self { keys, role, public })
    }
}

impl Signer for SharedRoleSigner {
    fn public(&self) -> P256Public {
        self.public
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature, fleet_crypto::Error> {
        let raw = self
            .keys
            .sign(self.role, msg, "")
            .map_err(|_| fleet_crypto::Error::Signer)?;
        sig::p256_normalize(&raw)
    }
}

/// In-memory keys for tests, development and `fleetctl` without an enclave.
pub struct SoftwareDeviceSigner {
    pub root: SoftwareP256Signer,
    pub device: SoftwareP256Signer,
    pub monitor: SoftwareP256Signer,
    pub ssh: SoftwareP256Signer,
    pub monitor_ssh: SoftwareP256Signer,
}

impl SoftwareDeviceSigner {
    pub fn generate() -> Result<Self, fleet_crypto::Error> {
        Ok(Self {
            root: SoftwareP256Signer::generate()?,
            device: SoftwareP256Signer::generate()?,
            monitor: SoftwareP256Signer::generate()?,
            ssh: SoftwareP256Signer::generate()?,
            monitor_ssh: SoftwareP256Signer::generate()?,
        })
    }

    fn key(&self, role: KeyRole) -> &SoftwareP256Signer {
        match role {
            KeyRole::Root => &self.root,
            KeyRole::Device => &self.device,
            KeyRole::Monitor => &self.monitor,
            KeyRole::Ssh => &self.ssh,
            KeyRole::MonitorSsh => &self.monitor_ssh,
        }
    }
}

impl DeviceSigner for SoftwareDeviceSigner {
    fn public_key(&self, role: KeyRole) -> Result<P256Public, SignerError> {
        Ok(self.key(role).public())
    }

    fn sign(&self, role: KeyRole, msg: &[u8], _reason: &str) -> Result<Signature, SignerError> {
        self.key(role).sign(msg).map_err(|_| SignerError::Failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_reason_names_op_and_count() {
        assert_eq!(root_reason("roster v2", 1), "approve roster v2 (1 server)");
        assert_eq!(
            root_reason("pkg.upgrade", 12),
            "approve pkg.upgrade (12 servers)"
        );
    }
}
