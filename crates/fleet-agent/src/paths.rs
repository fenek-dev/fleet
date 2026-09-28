//! Every filesystem path the agent touches (design §4.1, §4.4, §10.2).
//!
//! Production uses [`Paths::system`]. Tests and macOS development use
//! [`Paths::under`], which re-roots every path below a directory.
//! Binaries invoked by argv (`systemd-run`, the agent itself inside a unit)
//! are fixed absolute constants and are never re-rooted: they name files on
//! the target host, not state owned by this process.

use std::path::{Path, PathBuf};

/// The installed agent binary, as referenced by units and revert timers.
pub const AGENT_BIN: &str = "/usr/lib/fleet/fleet-agent";
/// The binary an update replaced. Revert timers of `ChangeKind::AgentUpdate`
/// run this one (a broken new build can't block its own rollback).
pub const AGENT_PREV_BIN: &str = "/usr/lib/fleet/fleet-agent.prev";
/// `setpriv`: helpers that touch a user's home run as that user.
pub const SETPRIV: &str = "/usr/bin/setpriv";
/// `systemd-run`, used to arm auto-revert timers (design §4.10).
pub const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
/// `systemctl`, used to disarm revert timers on confirmation.
pub const SYSTEMCTL: &str = "/usr/bin/systemctl";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// Directory holding the gate's public socket (`0750 fleet-gate:fleet`).
    pub run_dir: PathBuf,
    /// Gate socket reached by `fleet-agent bridge` (`0660 fleet-gate:fleet`).
    pub agent_sock: PathBuf,
    /// Exec socket directory (`0710 root:fleet-gate`): the gate may traverse
    /// it and connect, never create, rename or delete entries.
    pub exec_run_dir: PathBuf,
    /// Root-only (`0700`) scratch directory inside `exec_run_dir` where exec
    /// binds its socket and sets mode/group before renaming it into place.
    pub exec_tmp_dir: PathBuf,
    /// Exec socket (`0660 root:fleet-gate`); only the `fleet-gate` uid may
    /// connect (`SO_PEERCRED`).
    pub exec_sock: PathBuf,
    /// Exec state directory (`0700 root`): database, signing key, policy.
    pub exec_dir: PathBuf,
    /// redb database (design §4.4): replay, audit, meta (roster, policy).
    pub state_db: PathBuf,
    /// Agent Ed25519 signing key seed (`0600 root`): receipts, checkpoints.
    pub signing_key: PathBuf,
    /// Pending auto-revert changes, one `<id>.bin` each (`0700 root`, §4.10).
    /// Plain files, not redb, so the independent `revert` process can read
    /// them while exec holds the database lock.
    pub pending_dir: PathBuf,
    /// Markers written by `revert <id>`; exec audits and deletes them.
    pub reverted_dir: PathBuf,
    /// Gate state directory (`0700 fleet-gate`): Noise static key.
    pub gate_dir: PathBuf,
    /// Gate Noise static key (`0600 fleet-gate`).
    pub noise_key: PathBuf,
    /// Root-only (`0700 root`) staged agent builds, `<hex blake3>` plus
    /// `<hex blake3>.manifest`, copied in from `incoming_dir` by
    /// `agent.update.stage` (design §10.2).
    pub staging_dir: PathBuf,
    /// SFTP drop for agent builds (`0700 <admin>`): the admin user uploads
    /// here, exec copies out with `O_NOFOLLOW` while hashing.
    pub incoming_dir: PathBuf,
    /// The installed agent binary (units and timers name [`AGENT_BIN`]).
    pub agent_bin: PathBuf,
    /// The binary an update replaced (auto-revert and manual rollback).
    pub agent_prev_bin: PathBuf,
    /// `postcard(update::UpdateState)`: versions and hashes of the current
    /// and previous binary.
    pub update_state: PathBuf,
    /// The root everything above is under (`/` in production); uninstall
    /// removes host paths below it.
    pub root: PathBuf,
    /// Root-owned `authorized_keys` directory (design §5.9).
    pub authorized_keys_dir: PathBuf,
    /// User database, for the `fleet-gate` uid.
    pub passwd: PathBuf,
    /// Group database, for the `fleet` and `fleet-gate` gids.
    pub group: PathBuf,
    /// Unreadable `pending/` and `reverted/` files are moved here (`0700
    /// root`) so one bad file never blocks startup.
    pub quarantine_dir: PathBuf,
}

impl Paths {
    /// Real host paths.
    pub fn system() -> Self {
        Self::under("/")
    }

    /// Every path re-rooted below `root`.
    pub fn under(root: impl AsRef<Path>) -> Self {
        let r = root.as_ref();
        let run_dir = r.join("run/fleet");
        let exec_run_dir = r.join("run/fleet-exec");
        let exec_dir = r.join("var/lib/fleet/exec");
        let gate_dir = r.join("var/lib/fleet/gate");
        Self {
            agent_sock: run_dir.join("agent.sock"),
            run_dir,
            exec_sock: exec_run_dir.join("exec.sock"),
            exec_tmp_dir: exec_run_dir.join(".tmp"),
            exec_run_dir,
            quarantine_dir: exec_dir.join("quarantine"),
            state_db: exec_dir.join("state.redb"),
            update_state: exec_dir.join("update.bin"),
            signing_key: exec_dir.join("signing.key"),
            pending_dir: exec_dir.join("pending"),
            reverted_dir: exec_dir.join("reverted"),
            exec_dir,
            noise_key: gate_dir.join("noise.key"),
            gate_dir,
            staging_dir: r.join("var/lib/fleet/staging"),
            incoming_dir: r.join("var/lib/fleet/incoming"),
            agent_bin: r.join(&AGENT_BIN[1..]),
            agent_prev_bin: r.join(&AGENT_PREV_BIN[1..]),
            root: r.to_path_buf(),
            authorized_keys_dir: r.join("etc/fleet/authorized_keys"),
            passwd: r.join("etc/passwd"),
            group: r.join("etc/group"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_paths_match_design() {
        let p = Paths::system();
        assert_eq!(p.agent_sock, Path::new("/run/fleet/agent.sock"));
        assert_eq!(p.exec_sock, Path::new("/run/fleet-exec/exec.sock"));
        assert_eq!(p.state_db, Path::new("/var/lib/fleet/exec/state.redb"));
        assert_eq!(p.gate_dir, Path::new("/var/lib/fleet/gate"));
        assert_eq!(p.staging_dir, Path::new("/var/lib/fleet/staging"));
    }

    #[test]
    fn under_reroots() {
        let p = Paths::under("/tmp/x");
        assert_eq!(
            p.state_db,
            Path::new("/tmp/x/var/lib/fleet/exec/state.redb")
        );
    }
}
