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
    #[error("already installed (a roster is stored); use --keep-state or --replace")]
    AlreadyInstalled,
    #[error("key file {0} is corrupt")]
    Key(String),
    /// `state.redb` is locked by a running `fleet-exec`.
    #[error("the agent is running (its state database is locked); stop fleet-exec.service first")]
    AgentRunning,
    #[error("no agent keys found (key file {0} is missing)")]
    NoKeys(String),
    /// A pending change's rollback snapshot would be lost.
    #[error(
        "a change is pending on this server: confirm or wait for the pending change to revert, \
         then try again"
    )]
    PendingChange,
    /// A revert or restart timer/service is still active (or systemd could
    /// not be asked).
    #[error(
        "a revert or restart is still running (fleet-revert-* / fleet-agent-restart-* units): \
         wait for it to finish, then try again"
    )]
    RevertActive,
}

/// What `install` does when a roster is already stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InstallMode {
    /// Refuse with [`InstallError::AlreadyInstalled`].
    #[default]
    Fresh,
    /// Repair or upgrade: a stored roster, policy and keys are left
    /// untouched (a missing roster is installed normally).
    KeepState,
    /// A different fleet takes over: the old state database (and leftover
    /// markers, staged builds, update record) is archived, never deleted;
    /// the key files are kept. Refused while a change is pending. The
    /// caller stops both units first. Transactional: a failure restores
    /// the original database.
    Replace,
}

/// Where a replaced fleet's state database is archived (shared with
/// `uninstall --keep-audit`).
fn archive_dir(paths: &Paths) -> std::path::PathBuf {
    crate::uninstall::host(paths, crate::uninstall::AUDIT_KEEP_DIR)
}

/// The old fleet's database files moved into the archive. Everything
/// fallible is done before the swap; until [`Swap::finish`] the original
/// can be put back with [`Swap::rollback`].
struct Swap {
    dest: std::path::PathBuf,
    /// `(original, archived)` pairs.
    moved: Vec<(std::path::PathBuf, std::path::PathBuf)>,
}

fn is_state_file(name: &std::ffi::OsStr) -> bool {
    name.to_str().is_some_and(|n| n.starts_with("state.redb"))
}

/// Moves `state.redb*` to `<archive>/replaced-<ms>/` (keys stay). On a
/// failure part-way the files already moved are put back.
fn begin_swap(paths: &Paths) -> Result<Swap, InstallError> {
    let dest = archive_dir(paths).join(format!("replaced-{}", crate::now_ms()));
    ensure_dir(&archive_dir(paths), 0o700)?;
    ensure_dir(&dest, 0o700)?;
    let mut swap = Swap {
        dest,
        moved: Vec::new(),
    };
    let names: Vec<_> = std::fs::read_dir(&paths.exec_dir)?
        .flatten()
        .filter(|e| is_state_file(&e.file_name()))
        .collect();
    for e in names {
        let to = swap.dest.join(e.file_name());
        if let Err(err) = std::fs::rename(e.path(), &to) {
            swap.rollback(paths);
            return Err(err.into());
        }
        swap.moved.push((e.path(), to));
    }
    Ok(swap)
}

impl Swap {
    /// Drops whatever new database was created and restores the original.
    fn rollback(self, paths: &Paths) {
        for e in std::fs::read_dir(&paths.exec_dir).into_iter().flatten().flatten() {
            if is_state_file(&e.file_name()) {
                let _ = std::fs::remove_file(e.path());
            }
        }
        for (orig, archived) in self.moved.iter().rev() {
            let _ = std::fs::rename(archived, orig);
        }
        let _ = std::fs::remove_dir(&self.dest);
    }

    /// The swap succeeded: leftovers of the old fleet (reverted markers,
    /// staged builds, the update record) go into the archive too; nothing
    /// is deleted. Best effort: none of it is needed by the new state.
    fn finish(self, paths: &Paths) {
        let sweep = |dir: &Path, name: &str| {
            let to = self.dest.join(name);
            if ensure_dir(&to, 0o700).is_err() {
                return;
            }
            for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                let _ = std::fs::rename(e.path(), to.join(e.file_name()));
            }
        };
        sweep(&paths.pending_dir, "pending");
        sweep(&paths.reverted_dir, "reverted");
        sweep(&paths.staging_dir, "staging");
        let _ = std::fs::rename(&paths.update_state, self.dest.join("update.bin"));
    }
}

/// Pending (or claimed) auto-revert changes: their rollback snapshots are
/// the only way back from an unconfirmed SSH or firewall change.
pub fn pending_changes(paths: &Paths) -> usize {
    std::fs::read_dir(&paths.pending_dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .count()
}

const LIST_UNITS_ARGS: [&str; 7] = [
    "list-units",
    "--plain",
    "--no-legend",
    "--no-pager",
    "--state=active,activating,deactivating",
    "fleet-revert-*",
    "fleet-agent-restart-*",
];

/// Waits (up to 30 s) until no revert or restart timer or service is
/// active, so nothing already triggered is still running against the state
/// about to change. Fails closed.
fn wait_quiescent(runner: &dyn fleet_ops::CommandRunner) -> Result<(), InstallError> {
    for _ in 0..30 {
        let out = runner
            .run_blocking(
                fleet_ops::CommandSpec::new(crate::paths::SYSTEMCTL)
                    .args(LIST_UNITS_ARGS)
                    .timeout(std::time::Duration::from_secs(10)),
            )
            .map_err(|_| InstallError::RevertActive)?;
        if out.code != Some(0) {
            return Err(InstallError::RevertActive);
        }
        if String::from_utf8_lossy(&out.stdout).trim().is_empty() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    Err(InstallError::RevertActive)
}

/// The public halves of the key files, read without opening the state
/// database (which a running `fleet-exec` locks): `fleet-agent keys`.
pub fn read_public_keys(paths: &Paths) -> Result<InstallOutput, InstallError> {
    let noise = read_key(&paths.noise_key)?
        .ok_or_else(|| InstallError::NoKeys(paths.noise_key.display().to_string()))?;
    let signing = read_key(&paths.signing_key)?
        .ok_or_else(|| InstallError::NoKeys(paths.signing_key.display().to_string()))?;
    Ok(InstallOutput {
        noise_static: StaticKeypair::from_bytes(&noise).public(),
        signing_key: Ed25519Signer::from_seed(&signing).public(),
    })
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

/// Opens the state database; a lock held by a running `fleet-exec` becomes
/// [`InstallError::AgentRunning`].
fn open_store(paths: &Paths) -> Result<crate::store::Store, InstallError> {
    use crate::store::schema::SchemaError;
    crate::store::schema::open_versioned(&paths.state_db).map_err(|e| match e {
        SchemaError::Store(s) if s.is_locked() => InstallError::AgentRunning,
        other => other.into(),
    })
}

pub fn install(paths: &Paths, input: &InstallInput) -> Result<InstallOutput, InstallError> {
    install_with(paths, input, InstallMode::Fresh, None)
}

/// `runner` (systemd) is used to wait out revert/restart units before a
/// `KeepState` / `Replace` over an existing install; `None` skips that
/// (development roots, tests).
pub fn install_with(
    paths: &Paths,
    input: &InstallInput,
    mode: InstallMode,
    runner: Option<&dyn fleet_ops::CommandRunner>,
) -> Result<InstallOutput, InstallError> {
    install_hooked(paths, input, mode, runner, &|| Ok(()))
}

/// [`install_with`] with a step run after the database swap and before the
/// new fleet is stored (tests inject a failure there to check the rollback).
#[doc(hidden)]
pub fn install_hooked(
    paths: &Paths,
    input: &InstallInput,
    mode: InstallMode,
    runner: Option<&dyn fleet_ops::CommandRunner>,
    after_swap: &dyn Fn() -> Result<(), InstallError>,
) -> Result<InstallOutput, InstallError> {
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
    // A running agent holds the database lock: find out first, before
    // anything else is written, so a refusal leaves nothing half-done.
    let store = open_store(paths)?;
    let has_roster = store.meta().get(MetaKey::Roster)?.is_some();
    if has_roster && mode == InstallMode::Fresh {
        return Err(InstallError::AlreadyInstalled);
    }
    // Replace / keep-state over an install: never while a change is
    // pending (its rollback snapshot is the way back from an unconfirmed
    // SSH or firewall change) or a revert/restart is running. Checked with
    // the database lock held, before anything is changed.
    if mode == InstallMode::Replace || (mode == InstallMode::KeepState && has_roster) {
        if pending_changes(paths) > 0 {
            return Err(InstallError::PendingChange);
        }
        if let Some(r) = runner {
            wait_quiescent(r)?;
        }
    }
    let keep_roster = has_roster && mode == InstallMode::KeepState;
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

    if keep_roster {
        return Ok(InstallOutput {
            noise_static: noise.public(),
            signing_key: signer.public(),
        });
    }
    // Everything that can fail has run. Replace now swaps the database
    // (archive the old one, create the new) and restores the original if
    // storing the new fleet fails.
    let mut swap = None;
    let store = if mode == InstallMode::Replace {
        drop(store);
        let s = begin_swap(paths)?;
        match open_store(paths) {
            Ok(st) => {
                swap = Some(s);
                st
            }
            Err(e) => {
                s.rollback(paths);
                return Err(e);
            }
        }
    } else {
        store
    };
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
    let stored = after_swap().and_then(|()| store.meta().update(&changes).map_err(Into::into));
    drop(store);
    if let Err(e) = stored {
        if let Some(s) = swap {
            s.rollback(paths);
        }
        return Err(e);
    }
    if let Some(s) = swap {
        s.finish(paths);
    }

    Ok(InstallOutput {
        noise_static: noise.public(),
        signing_key: signer.public(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_ops::{CommandOutput, CommandRunner, CommandSpec, LocalBoxFuture, RunError};

    struct Fixed(Option<i32>, &'static str);
    impl CommandRunner for Fixed {
        fn run(&self, _: CommandSpec) -> LocalBoxFuture<'_, Result<CommandOutput, RunError>> {
            unimplemented!()
        }
        fn run_blocking(&self, _: CommandSpec) -> Result<CommandOutput, RunError> {
            Ok(CommandOutput {
                code: self.0,
                stdout: self.1.as_bytes().to_vec(),
                stderr: vec![],
                truncated: false,
            })
        }
    }

    #[test]
    fn quiescence_fails_closed() {
        assert!(wait_quiescent(&Fixed(Some(0), "")).is_ok());
        assert!(matches!(
            wait_quiescent(&Fixed(Some(1), "")),
            Err(InstallError::RevertActive)
        ));
        assert!(matches!(
            wait_quiescent(&Fixed(None, "")),
            Err(InstallError::RevertActive)
        ));
    }

    #[test]
    fn usermod_appends_to_fleet() {
        assert_eq!(
            super::usermod_args("ops"),
            ["--append", "--groups", "fleet", "ops"]
        );
    }
}
