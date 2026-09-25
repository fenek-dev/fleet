//! cloud-init export on the Mac (design §9.7): a fresh Ed25519 `sshd`
//! host key generated here and pinned at the same moment, the enrolled
//! Macs' SSH keys for the admin, rendered by `fleet_cloudinit`.
//!
//! Only each Mac's device SSH key goes into the file: cloud-init writes
//! `~/.ssh/authorized_keys` without options, so the monitor keys and the
//! recovery key (which must stay forced to their bridges) arrive with the
//! roster section once the agent is installed. The host private key is in
//! the returned YAML only; the Mac keeps just the public key as the pin.
//!
//! Handling the YAML (the app does this, `CloudInitExportSheet.swift`): the
//! file is created 0600 from the start (`O_CREAT|O_EXCL` temp + rename),
//! the operator is warned when saving into a synced folder (iCloud Drive,
//! Dropbox, Google Drive, OneDrive, `~/Library/CloudStorage`), and told
//! that the private key stays in the provider's stored user-data and in
//! `/var/lib/cloud/instance/user-data.txt*` after first boot, so both
//! should be deleted and the host key rotated.

use crate::ssh::HostKey;
use fleet_cloudinit::{CloudInit, HostKey as CiHostKey};
use fleet_crypto::Zeroizing;
use fleet_proto::Roster;
use fleet_proto::args::{SshKeyAlgo, SshPublicKey, UserName};
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::ssh_key::{LineEnding, PrivateKey};

#[derive(Debug, thiserror::Error)]
pub enum CloudInitExportError {
    #[error("invalid {0}")]
    Invalid(&'static str),
    #[error("key generation failed")]
    KeyGen,
    #[error("cloud-init: {0}")]
    Render(String),
}

/// The file plus the host key pin to store with the server once it exists.
pub struct Export {
    pub yaml: Zeroizing<String>,
    pub host_key: HostKey,
}

/// A new Ed25519 host key: (OpenSSH private key, public key).
pub fn generate_host_key() -> Result<(Zeroizing<String>, SshPublicKey), CloudInitExportError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    fleet_crypto::random_bytes(seed.as_mut()).map_err(|_| CloudInitExportError::KeyGen)?;
    let kp = Ed25519Keypair::from_seed(&seed);
    let key = PrivateKey::new(KeypairData::from(kp), "fleet-host")
        .map_err(|_| CloudInitExportError::KeyGen)?;
    let private = key
        .to_openssh(LineEnding::LF)
        .map_err(|_| CloudInitExportError::KeyGen)?;
    let blob = key
        .public_key()
        .to_bytes()
        .map_err(|_| CloudInitExportError::KeyGen)?;
    let public = SshPublicKey::new(SshKeyAlgo::Ed25519, blob, "fleet-host".into())
        .map_err(|_| CloudInitExportError::KeyGen)?;
    Ok((Zeroizing::new(private.to_string()), public))
}

/// Renders the cloud-config for `admin` with every roster Mac's SSH key.
pub fn export(
    admin: &str,
    roster: &Roster,
    hostname: Option<String>,
) -> Result<Export, CloudInitExportError> {
    let admin = UserName::new(admin.to_string())
        .map_err(|_| CloudInitExportError::Invalid("admin user"))?;
    let mut keys = Vec::new();
    for d in &roster.devices {
        let blob = crate::ssh::SshPublicKey::EcdsaP256(d.ssh_key)
            .blob()
            .map_err(|_| CloudInitExportError::Invalid("roster SSH key"))?;
        let k = SshPublicKey::new(
            SshKeyAlgo::EcdsaP256,
            blob,
            format!("fleet-device-{}", d.id),
        )
        .map_err(|_| CloudInitExportError::Invalid("roster SSH key"))?;
        keys.push(k);
    }
    let (private, public) = generate_host_key()?;
    let host_key = HostKey::from_blob(public.blob()).map_err(|_| CloudInitExportError::KeyGen)?;
    let doc = CloudInit {
        admin,
        authorized_keys: keys,
        host_keys: vec![CiHostKey {
            private_openssh: private.to_string(),
            public,
        }],
        hostname,
    };
    let yaml =
        fleet_cloudinit::render(&doc).map_err(|e| CloudInitExportError::Render(e.to_string()))?;
    Ok(Export {
        yaml: Zeroizing::new(yaml),
        host_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_key_is_valid_openssh() {
        let (private, public) = generate_host_key().unwrap();
        assert!(private.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
        let parsed = PrivateKey::from_openssh(private.as_bytes()).unwrap();
        assert_eq!(parsed.public_key().to_bytes().unwrap(), public.blob());
        assert!(HostKey::from_blob(public.blob()).is_ok());
    }
}
