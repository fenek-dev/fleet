//! `fleet-agent install --genesis <file> --policy <file> --server-id <id>
//! [--admin-user <name>]` (design §10.1).
//!
//! Creates the state directories with their modes, generates the gate Noise
//! static key and the exec signing key (kept if already present, so a re-run
//! never changes pinned keys), verifies the genesis roster, stores roster and
//! policy, and returns the public keys for the operator to pin.
//!
//! Users and groups (`fleet-gate`, `fleet`) are created by packaging, not
//! here. Ownership is set only when running as root, so tests and macOS
//! development run unprivileged.

use crate::exec::StoredPolicy;
use crate::fsutil::{self, ensure_dir};
use crate::paths::Paths;
use crate::store::{MetaKey, StoreError};
use fleet_crypto::Zeroizing;
use fleet_crypto::noise::StaticKeypair;
use fleet_crypto::roster::{RosterError, verify_genesis};
use fleet_crypto::sig::Ed25519Signer;
use fleet_proto::{Ed25519Public, Policy, ServerId, SignedRoster, X25519Public, encode};
use std::path::Path;

/// Gate user, and the group allowed to reach `exec.sock`.
pub const GATE_USER: &str = "fleet-gate";
/// Group of the gate process and the SSH login users (`agent.sock`).
pub const FLEET_GROUP: &str = "fleet";

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("genesis roster: {0}")]
    Genesis(RosterError),
    #[error("genesis roster file is not a valid encoding")]
    GenesisEncoding,
    #[error("policy: {0}")]
    Policy(String),
    #[error("invalid admin user name")]
    AdminUser,
    #[error("user {GATE_USER} does not exist (packaging creates it)")]
    NoGateUser,
    #[error("group {0} does not exist (packaging creates it)")]
    NoGroup(&'static str),
    #[error("adding the admin user to group fleet failed: {0}")]
    AdminGroup(String),
    #[error("already installed (a roster is stored)")]
    AlreadyInstalled,
    #[error("key file {0} is corrupt")]
    Key(String),
}

pub struct InstallInput {
    pub genesis: SignedRoster,
    pub policy_toml: String,
    pub server_id: ServerId,
    /// Login whose `authorized_keys` roster section exec maintains.
    pub admin_user: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstallOutput {
    pub noise_static: X25519Public,
    pub signing_key: Ed25519Public,
}

/// Parses a genesis file: hex text (as the app exports it) or raw postcard.
pub fn parse_genesis(bytes: &[u8]) -> Result<SignedRoster, InstallError> {
    let from_hex = std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| hex::decode(s.trim()).ok());
    let raw = from_hex.as_deref().unwrap_or(bytes);
    fleet_proto::decode(raw).map_err(|_| InstallError::GenesisEncoding)
}

/// Debian `NAME_REGEX` default, max 32.
fn valid_user(u: &str) -> bool {
    let mut b = u.bytes();
    u.len() <= 32
        && b.next().is_some_and(|c| c.is_ascii_lowercase())
        && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
}

/// Existing key file (no symlinks, exactly 32 bytes), read into a wiped
/// buffer.
fn read_key(path: &Path) -> Result<Option<Zeroizing<[u8; 32]>>, InstallError> {
    fsutil::read_key32(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::InvalidData => InstallError::Key(path.display().to_string()),
        _ => InstallError::Io(e),
    })
}

/// Ids needed to set ownership; only looked up when running as root.
struct Owners {
    gate_uid: u32,
    /// `fleet`: the gate's group and the SSH login users'.
    fleet_gid: u32,
    /// `fleet-gate`: may traverse `/run/fleet-exec` and connect to exec.
    gate_gid: u32,
}

impl Owners {
    fn lookup(paths: &Paths) -> Result<Self, InstallError> {
        let gid = |name: &'static str| {
            fsutil::lookup_gid(&paths.group, name).ok_or(InstallError::NoGroup(name))
        };
        Ok(Self {
            gate_uid: fsutil::lookup_uid(&paths.passwd, GATE_USER)
                .ok_or(InstallError::NoGateUser)?,
            fleet_gid: gid(FLEET_GROUP)?,
            gate_gid: gid(GATE_USER)?,
        })
    }
}

const USERMOD: &str = "/usr/sbin/usermod";

/// Argument list of the fixed-path `usermod` call (never a shell string).
fn usermod_args(user: &str) -> [&str; 4] {
    ["--append", "--groups", FLEET_GROUP, user]
}

/// Adds `user` to `fleet` (idempotent; `usermod --append`).
fn add_to_fleet_group(user: &str) -> Result<(), InstallError> {
    let out = std::process::Command::new(USERMOD)
        .args(usermod_args(user))
        .env_clear()
        .stdin(std::process::Stdio::null())
        .output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(InstallError::AdminGroup(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ))
    }
}

pub fn install(paths: &Paths, input: &InstallInput) -> Result<InstallOutput, InstallError> {
    // Validate everything before touching the filesystem.
    verify_genesis(&input.genesis, crate::now_ms()).map_err(InstallError::Genesis)?;
    let policy =
        Policy::from_toml(&input.policy_toml).map_err(|e| InstallError::Policy(e.to_string()))?;
    if policy.fleet_id != input.genesis.roster.fleet_id {
        return Err(InstallError::Policy(
            "fleet_id differs from the roster".into(),
        ));
    }
    if policy.server_id != input.server_id {
        return Err(InstallError::Policy(
            "server_id differs from --server-id".into(),
        ));
    }
    if input.admin_user.as_deref().is_some_and(|u| !valid_user(u)) {
        return Err(InstallError::AdminUser);
    }

    let owners = if fsutil::current_uid()? == 0 {
        Some(Owners::lookup(paths)?)
    } else {
        None
    };
    // Every directory below has a root-owned parent, so `ensure_dir`'s
    // symlink check can't be raced; ownership is set with lchown.
    let own = |p: &Path, uid: Option<u32>, gid: Option<u32>| match owners {
        Some(_) => fsutil::lchown(p, uid, gid),
        None => Ok(()),
    };
    let (gate_uid, fleet_gid, gate_gid) = owners.as_ref().map_or((None, None, None), |o| {
        (Some(o.gate_uid), Some(o.fleet_gid), Some(o.gate_gid))
    });
    ensure_dir(&paths.exec_dir, 0o700)?;
    ensure_dir(&paths.pending_dir, 0o700)?;
    ensure_dir(&paths.reverted_dir, 0o700)?;
    ensure_dir(&paths.staging_dir, 0o700)?;
    // The admin uploads agent builds here over SFTP (design §10.2); exec
    // copies them out with O_NOFOLLOW while hashing.
    crate::update::ensure_incoming(paths, input.admin_user.as_deref(), owners.is_some())?;
    ensure_dir(&paths.authorized_keys_dir, 0o755)?;
    ensure_dir(&paths.gate_dir, 0o700)?;
    own(&paths.gate_dir, gate_uid, fleet_gid)?;
    // /run is normally recreated by tmpfiles.d at boot; create it now too.
    ensure_dir(&paths.run_dir, 0o750)?;
    own(&paths.run_dir, gate_uid, fleet_gid)?;
    // root:fleet-gate 0710: the gate can reach exec.sock, not replace it.
    ensure_dir(&paths.exec_run_dir, 0o710)?;
    own(&paths.exec_run_dir, None, gate_gid)?;

    let store = crate::store::schema::open_versioned(&paths.state_db)?;
    if store.meta().get(MetaKey::Roster)?.is_some() {
        return Err(InstallError::AlreadyInstalled);
    }

    let noise = match read_key(&paths.noise_key)? {
        Some(b) => StaticKeypair::from_bytes(&b),
        None => {
            let k = StaticKeypair::generate().map_err(|_| InstallError::Key("rng".into()))?;
            // Written, chmod'ed and chown'ed in the root-only exec dir, then
            // renamed into the gate's (gate-writable) dir: no root file
            // operation ever resolves a path the gate controls.
            let staged = paths.exec_dir.join(".noise.key.install");
            let _ = std::fs::remove_file(&staged);
            fsutil::write_atomic_owned(
                &staged,
                k.secret_bytes().as_ref(),
                0o600,
                owners
                    .as_ref()
                    .map(|o| (Some(o.gate_uid), Some(o.fleet_gid))),
            )?;
            std::fs::rename(&staged, &paths.noise_key)?;
            k
        }
    };
    let signer = match read_key(&paths.signing_key)? {
        Some(b) => Ed25519Signer::from_seed(&b),
        None => {
            let k = Ed25519Signer::generate().map_err(|_| InstallError::Key("rng".into()))?;
            fsutil::write_atomic(&paths.signing_key, k.seed().as_ref(), 0o600)?;
            k
        }
    };

    // The admin's SSH sessions run `fleet-agent bridge`, which reaches
    // `agent.sock` (fleet-gate:fleet 0660) only as a member of `fleet`
    // (design §4.1). Sessions opened afterwards carry the new group.
    if let (Some(u), Some(_)) = (&input.admin_user, &owners) {
        add_to_fleet_group(u)?;
    }

    let roster = encode(&input.genesis);
    let policy = encode(&StoredPolicy {
        toml: input.policy_toml.clone(),
        approval: None,
        expected_version: None,
        roster: None,
    });
    let server = input.server_id.as_str().as_bytes();
    let mut changes = vec![
        (MetaKey::ServerId, Some(server)),
        (MetaKey::Policy, Some(&policy[..])),
        (MetaKey::Roster, Some(&roster[..])),
    ];
    if let Some(u) = &input.admin_user {
        changes.push((MetaKey::AdminUser, Some(u.as_bytes())));
        crate::uninstall::record_admin(paths, u);
    }
    store.meta().update(&changes)?;

    Ok(InstallOutput {
        noise_static: noise.public(),
        signing_key: signer.public(),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn usermod_appends_to_fleet() {
        assert_eq!(
            super::usermod_args("ops"),
            ["--append", "--groups", "fleet", "ops"]
        );
    }
}
