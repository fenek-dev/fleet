//! Signed agent updates with rollback (design §10.2, §5.7).
//!
//! - **Stage** (`agent.update.stage`): the Mac uploads the build over SFTP
//!   as the admin user into `/var/lib/fleet/incoming/<hex blake3>` (a
//!   `0700 <admin>` drop directory). Exec checks the root-signed manifest
//!   (a Mac of the current roster, version above the running one, this
//!   architecture, a protocol it speaks), opens the upload `O_NOFOLLOW`
//!   (a regular file, at most [`MAX_BINARY`]) and copies it into root-only
//!   `staging/` **while hashing the bytes it writes**, so swapping the
//!   upload mid-copy can't smuggle in other bytes. The manifest is kept
//!   beside it (`<hex>.manifest`).
//! - **Commit** (`agent.update.commit`, auto-revert `ChangeKind::AgentUpdate`):
//!   re-checks manifest and hash, keeps the running binary as
//!   `fleet-agent.prev`, renames the staged build over
//!   `/usr/lib/fleet/fleet-agent` and schedules `systemctl restart
//!   fleet-exec.service fleet-gate.service` in a transient unit
//!   [`RESTART_DELAY_S`] later, so exec answers (and arms the confirm
//!   timer) before it is restarted. The confirm window is
//!   [`HEALTH_WINDOW_S`] after the restart; the revert timer runs the
//!   **previous** binary (`revert::revert_bin`), so a build that can't
//!   start can't block its own rollback.
//! - **Rollback** ([`UpdateRevert::restore`], the timer or exec): puts
//!   `.prev` back (checked against the snapshot's hash), resets the units'
//!   failed state (a crash-looping build hits the start limit) and
//!   restarts them. Idempotent: if the binary already is the previous
//!   build, nothing is restarted.
//! - **Manual rollback** (`agent.update.rollback`): the same swap to the
//!   build the last update replaced, only while no update is pending.

use crate::fsutil::{self, O_NOFOLLOW};
use crate::paths::{Paths, SYSTEMCTL, SYSTEMD_RUN};
use crate::store::schema::SCHEMA_VERSION;
use fleet_crypto::release::{self, Host, ReleaseError};
use fleet_ops::{CommandSpec, OpError, Revertible, SysCtx};
use fleet_proto::{
    AgentTarget, AgentVersion, ErrorCode, Hash32, Op, PROTO_VERSION, Roster, SignedReleaseManifest,
    decode, encode,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The new build must be confirmed this long after its restart.
pub const HEALTH_WINDOW_S: u32 = 30;
/// Exec answers `agent.update.commit` before the units restart.
pub const RESTART_DELAY_S: u32 = 3;
/// Confirm window of an `AgentUpdate` change.
pub const CONFIRM_WINDOW_S: u32 = HEALTH_WINDOW_S + RESTART_DELAY_S;
/// Largest agent build accepted.
pub const MAX_BINARY: u64 = 64 << 20;
/// The agent's units, restarted together.
pub const UNITS: [&str; 2] = ["fleet-exec.service", "fleet-gate.service"];

/// One binary: version and BLAKE3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Build {
    pub version: AgentVersion,
    pub blake3: Hash32,
}

/// `update.bin`: what the last update installed and what it replaced.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateState {
    pub current: Option<Build>,
    pub prev: Option<Build>,
}

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("manifest: {0}")]
    Release(#[from] ReleaseError),
    #[error("binary hash differs from the manifest")]
    HashMismatch,
    #[error("upload is larger than {MAX_BINARY} bytes")]
    TooLarge,
    #[error("upload is not a regular file (symlink?)")]
    NotRegular,
    #[error("no staged build of that version")]
    NotStaged,
    #[error("no previous build to roll back to")]
    NoPrevious,
    #[error("corrupt update state")]
    Corrupt,
}

/// Versions as one number (`VersionConflict { current }`).
pub fn pack_version(v: AgentVersion) -> u64 {
    (u64::from(v.major) << 32) | (u64::from(v.minor) << 16) | u64::from(v.patch)
}

impl UpdateError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Io(e) if e.kind() == std::io::ErrorKind::NotFound => ErrorCode::NotFound,
            Self::Io(_) | Self::Corrupt => ErrorCode::Internal,
            Self::Release(ReleaseError::UnknownSigner | ReleaseError::BadSignature) => {
                ErrorCode::SignatureInvalid
            }
            Self::Release(ReleaseError::NotNewer { running, .. }) => ErrorCode::VersionConflict {
                current: pack_version(*running),
            },
            Self::Release(_) | Self::HashMismatch | Self::TooLarge | Self::NotRegular => {
                ErrorCode::InvalidArgument
            }
            Self::NotStaged | Self::NoPrevious => ErrorCode::NotFound,
        }
    }
}

impl From<UpdateError> for OpError {
    fn from(e: UpdateError) -> Self {
        OpError::new(e.code()).with_detail(e.to_string())
    }
}

/// This agent, as a release target.
pub fn host() -> Host {
    Host {
        running: crate::agent_version(),
        target: AgentTarget::current(),
        proto: PROTO_VERSION,
    }
}

/// Creates the SFTP drop directory `incoming/` (`0700`, owned by the admin
/// user when running as root and one is known).
pub fn ensure_incoming(paths: &Paths, admin: Option<&str>, chown: bool) -> std::io::Result<()> {
    fsutil::ensure_dir(&paths.incoming_dir, 0o700)?;
    if chown && let Some(u) = admin.and_then(|a| fsutil::lookup_user(&paths.passwd, a)) {
        fsutil::lchown(&paths.incoming_dir, Some(u.uid), Some(u.gid))?;
    }
    Ok(())
}

fn open_nofollow(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
}

/// BLAKE3 of the regular file at `path` (never through a symlink).
pub fn hash_file(path: &Path) -> Result<Hash32, UpdateError> {
    let mut f = open_nofollow(path)?;
    if !f.metadata()?.is_file() {
        return Err(UpdateError::NotRegular);
    }
    let mut h = blake3::Hasher::new();
    let mut buf = vec![0u8; 64 << 10];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(*h.finalize().as_bytes())
}

/// Copies `src` into a new file `dst` (`O_EXCL | O_NOFOLLOW`, `mode`),
/// hashing the bytes written; at most [`MAX_BINARY`]. Removes `dst` on
/// any failure.
fn copy_hashing(src: &mut fs::File, dst: &Path, mode: u32) -> Result<Hash32, UpdateError> {
    let res = (|| {
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(O_NOFOLLOW)
            .mode(mode)
            .open(dst)?;
        out.set_permissions(fs::Permissions::from_mode(mode))?;
        let mut h = blake3::Hasher::new();
        let mut buf = vec![0u8; 64 << 10];
        let mut total = 0u64;
        loop {
            let n = src.read(&mut buf)?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > MAX_BINARY {
                return Err(UpdateError::TooLarge);
            }
            h.update(&buf[..n]);
            out.write_all(&buf[..n])?;
        }
        out.sync_all()?;
        Ok(*h.finalize().as_bytes())
    })();
    if res.is_err() {
        let _ = fs::remove_file(dst);
    }
    res
}

fn tmp_beside(path: &Path, tag: &str) -> PathBuf {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    path.with_file_name(format!(".{name}.{tag}.tmp"))
}

/// Atomically replaces `dst` with a copy of `src` whose hash must be
/// `want`: temp file beside `dst`, then rename (never follows a planted
/// symlink at `dst`).
fn install_copy(src: &Path, dst: &Path, want: Hash32) -> Result<(), UpdateError> {
    let mut f = open_nofollow(src)?;
    if !f.metadata()?.is_file() {
        return Err(UpdateError::NotRegular);
    }
    let tmp = tmp_beside(dst, "new");
    let _ = fs::remove_file(&tmp);
    let got = copy_hashing(&mut f, &tmp, 0o755)?;
    if got != want {
        let _ = fs::remove_file(&tmp);
        return Err(UpdateError::HashMismatch);
    }
    fs::rename(&tmp, dst)?;
    if let Some(dir) = dst.parent() {
        fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

pub fn read_state(paths: &Paths) -> Result<UpdateState, UpdateError> {
    match fs::read(&paths.update_state) {
        Ok(b) => decode(&b).map_err(|_| UpdateError::Corrupt),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(UpdateState::default()),
        Err(e) => Err(e.into()),
    }
}

fn write_state(paths: &Paths, s: &UpdateState) -> Result<(), UpdateError> {
    fsutil::write_atomic(&paths.update_state, &encode(s), 0o600)?;
    Ok(())
}

/// Admission checks of `agent.update.stage` that need no file access.
pub fn check_stage(
    signed: &SignedReleaseManifest,
    staged_hash: Hash32,
    roster: &Roster,
    host: Host,
) -> Result<(), UpdateError> {
    if staged_hash != signed.manifest.blake3 {
        return Err(UpdateError::HashMismatch);
    }
    release::verify_release(signed, roster, host)?;
    Ok(())
}

/// The upload for `hash`: a regular file (never a symlink).
pub fn incoming_file(paths: &Paths, hash: Hash32) -> Result<PathBuf, UpdateError> {
    let p = paths.incoming_dir.join(hex::encode(hash));
    if !fs::symlink_metadata(&p)?.file_type().is_file() {
        return Err(UpdateError::NotRegular);
    }
    Ok(p)
}

/// `agent.update.stage` (module docs).
pub fn stage(
    paths: &Paths,
    signed: &SignedReleaseManifest,
    staged_hash: Hash32,
    roster: &Roster,
    host: Host,
) -> Result<Build, UpdateError> {
    check_stage(signed, staged_hash, roster, host)?;
    let src = incoming_file(paths, staged_hash)?;
    let mut f = open_nofollow(&src)?;
    let md = f.metadata()?;
    if !md.is_file() {
        return Err(UpdateError::NotRegular);
    }
    if md.len() > MAX_BINARY {
        return Err(UpdateError::TooLarge);
    }
    fsutil::ensure_dir(&paths.staging_dir, 0o700)?;
    let name = hex::encode(staged_hash);
    let dst = paths.staging_dir.join(&name);
    let tmp = tmp_beside(&dst, "stage");
    let _ = fs::remove_file(&tmp);
    let got = copy_hashing(&mut f, &tmp, 0o700)?;
    if got != staged_hash {
        let _ = fs::remove_file(&tmp);
        return Err(UpdateError::HashMismatch);
    }
    fs::rename(&tmp, &dst)?;
    fsutil::write_atomic(
        &paths.staging_dir.join(format!("{name}.manifest")),
        &encode(signed),
        0o600,
    )?;
    let _ = fs::remove_file(&src);
    // One staged build at a time: older ones are superseded.
    let keep = [name.clone(), format!("{name}.manifest")];
    for e in fs::read_dir(&paths.staging_dir)?.flatten() {
        if !keep.iter().any(|k| e.file_name().to_str() == Some(k)) {
            let _ = fs::remove_file(e.path());
        }
    }
    Ok(Build {
        version: signed.manifest.version,
        blake3: staged_hash,
    })
}

/// The staged build of `version` and its manifest.
pub fn find_staged(
    paths: &Paths,
    version: AgentVersion,
) -> Result<(SignedReleaseManifest, PathBuf), UpdateError> {
    let entries = match fs::read_dir(&paths.staging_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(UpdateError::NotStaged),
        Err(e) => return Err(e.into()),
    };
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(stem) = name.to_str().and_then(|n| n.strip_suffix(".manifest")) else {
            continue;
        };
        let Ok(bytes) = fs::read(e.path()) else {
            continue;
        };
        let Ok(m) = decode::<SignedReleaseManifest>(&bytes) else {
            continue;
        };
        if m.manifest.version == version && hex::encode(m.manifest.blake3) == stem {
            let bin = paths.staging_dir.join(stem);
            return Ok((m, bin));
        }
    }
    Err(UpdateError::NotStaged)
}

/// Admission checks of `agent.update.commit`: staged, and its manifest
/// still valid against the roster in force now.
pub fn check_commit(
    paths: &Paths,
    version: AgentVersion,
    roster: &Roster,
    host: Host,
) -> Result<(SignedReleaseManifest, PathBuf), UpdateError> {
    let (m, bin) = find_staged(paths, version)?;
    release::verify_release(&m, roster, host)?;
    Ok((m, bin))
}

/// `agent.update.commit`'s swap (module docs). Returns the new build.
pub fn commit(
    paths: &Paths,
    version: AgentVersion,
    roster: &Roster,
    host: Host,
) -> Result<Build, UpdateError> {
    let (m, staged) = check_commit(paths, version, roster, host)?;
    let running = Build {
        version: host.running,
        blake3: hash_file(&paths.agent_bin)?,
    };
    install_copy(&paths.agent_bin, &paths.agent_prev_bin, running.blake3)?;
    install_copy(&staged, &paths.agent_bin, m.manifest.blake3)?;
    let new = Build {
        version: m.manifest.version,
        blake3: m.manifest.blake3,
    };
    write_state(
        paths,
        &UpdateState {
            current: Some(new),
            prev: Some(running),
        },
    )?;
    Ok(new)
}

/// Checks for `agent.update.rollback`: a previous build is recorded and
/// its file intact.
pub fn check_rollback(paths: &Paths) -> Result<Build, UpdateError> {
    let prev = read_state(paths)?.prev.ok_or(UpdateError::NoPrevious)?;
    if hash_file(&paths.agent_prev_bin)? != prev.blake3 {
        return Err(UpdateError::HashMismatch);
    }
    Ok(prev)
}

/// `agent.update.rollback`'s swap: the previous build back in place.
pub fn rollback(paths: &Paths) -> Result<Build, UpdateError> {
    let prev = check_rollback(paths)?;
    install_copy(&paths.agent_prev_bin, &paths.agent_bin, prev.blake3)?;
    write_state(
        paths,
        &UpdateState {
            current: Some(prev),
            prev: None,
        },
    )?;
    Ok(prev)
}

/// Restart of both units in `RESTART_DELAY_S`, from a transient unit
/// (outside exec's cgroup, so restarting exec can't kill it).
pub fn restart_later(unit: &str) -> CommandSpec {
    let mut args = vec![
        format!("--on-active={RESTART_DELAY_S}"),
        "--timer-property=AccuracySec=100ms".to_owned(),
        format!("--unit={unit}"),
        SYSTEMCTL.to_owned(),
        "restart".to_owned(),
    ];
    args.extend(UNITS.iter().map(|u| (*u).to_owned()));
    CommandSpec::new(SYSTEMD_RUN)
        .args(args)
        .timeout(Duration::from_secs(10))
}

/// Restart now without waiting (`--no-block`: exec may be the caller),
/// after clearing a start-limit failure.
pub fn restart_now() -> [CommandSpec; 2] {
    let with = |first: &[&str]| {
        let mut a: Vec<String> = first.iter().map(|s| (*s).to_owned()).collect();
        a.extend(UNITS.iter().map(|u| (*u).to_owned()));
        CommandSpec::new(SYSTEMCTL)
            .args(a)
            .timeout(Duration::from_secs(10))
    };
    [with(&["reset-failed"]), with(&["--no-block", "restart"])]
}

/// Snapshot of an `AgentUpdate` change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateSnapshot {
    /// The build running when the update was committed.
    pub prev: Build,
    /// Its database schema (it reopens that file after a rollback).
    pub schema: u32,
}

/// `Revertible` for `ChangeKind::AgentUpdate` (module docs).
pub struct UpdateRevert {
    pub paths: Paths,
}

impl Revertible for UpdateRevert {
    fn snapshot(&self, _ctx: &SysCtx, op: &Op) -> Result<Vec<u8>, OpError> {
        if !matches!(op, Op::AgentUpdateCommit { .. }) {
            return Err(OpError::new(ErrorCode::Internal));
        }
        let snap = UpdateSnapshot {
            prev: Build {
                version: crate::agent_version(),
                blake3: hash_file(&self.paths.agent_bin)?,
            },
            schema: SCHEMA_VERSION,
        };
        // The guard timer (armed next, before the handler) runs
        // `fleet-agent.prev revert <id>`, and systemd-run refuses a unit
        // whose executable doesn't exist: keep the running build as
        // `.prev` now. Harmless if the update then fails: it is the
        // installed binary's copy.
        install_copy(
            &self.paths.agent_bin,
            &self.paths.agent_prev_bin,
            snap.prev.blake3,
        )?;
        Ok(encode(&snap))
    }

    fn restore(&self, ctx: &SysCtx, snapshot: &[u8]) -> Result<(), OpError> {
        let snap: UpdateSnapshot =
            decode(snapshot).map_err(|_| OpError::internal("corrupt update snapshot"))?;
        if hash_file(&self.paths.agent_bin).ok() == Some(snap.prev.blake3) {
            return Ok(());
        }
        install_copy(
            &self.paths.agent_prev_bin,
            &self.paths.agent_bin,
            snap.prev.blake3,
        )?;
        write_state(
            &self.paths,
            &UpdateState {
                current: Some(snap.prev),
                prev: None,
            },
        )?;
        let [reset, restart] = restart_now();
        // A crash-looping build leaves the units start-limited.
        let _ = ctx.runner.run_blocking(reset);
        let out = ctx
            .runner
            .run_blocking(restart)
            .map_err(|e| OpError::internal(format!("restart agent: {e}")))?;
        if !out.success() {
            return Err(OpError::internal("restart agent units failed"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_crypto::release::sign_release;
    use fleet_crypto::sig::{Signer, SoftwareP256Signer};
    use fleet_proto::{BoundedString, Device, DeviceId, FleetId, ReleaseManifest, Role};

    fn v(minor: u16) -> AgentVersion {
        AgentVersion {
            major: 9,
            minor,
            patch: 0,
        }
    }

    struct Fx {
        _d: tempfile::TempDir,
        paths: Paths,
        root: SoftwareP256Signer,
        roster: Roster,
    }

    fn fx() -> Fx {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::under(d.path());
        fs::create_dir_all(paths.agent_bin.parent().unwrap()).unwrap();
        fs::write(&paths.agent_bin, b"build-1").unwrap();
        fsutil::ensure_dir(paths.incoming_dir.parent().unwrap(), 0o755).unwrap();
        ensure_incoming(&paths, None, false).unwrap();
        fs::create_dir_all(&paths.exec_dir).unwrap();
        let root = SoftwareP256Signer::from_bytes(&[7; 32]).unwrap();
        let k = root.public();
        let roster = Roster {
            fleet_id: FleetId([1; 16]),
            epoch: 0,
            version: 1,
            prev_hash: [0; 32],
            issued_at_ms: 0,
            devices: vec![Device {
                id: DeviceId([2; 16]),
                name: BoundedString::new("mac").unwrap(),
                role: Role::Admin,
                root_key: k,
                device_key: k,
                monitor_key: k,
                ssh_key: k,
                monitor_ssh_key: k,
                noise_static: fleet_proto::X25519Public([6; 32]),
                added_at: 0,
                added_by: DeviceId([2; 16]),
            }],
            recovery_key: fleet_proto::Ed25519Public([3; 32]),
            recovery_ssh_key: fleet_proto::Ed25519Public([4; 32]),
            recovery_escrow_key: fleet_proto::X25519Public([5; 32]),
            recovery_delay_s: 60,
            prev_recovery: None,
        };
        Fx {
            _d: d,
            paths,
            root,
            roster,
        }
    }

    fn host() -> Host {
        Host {
            running: v(1),
            target: AgentTarget::current(),
            proto: PROTO_VERSION,
        }
    }

    impl Fx {
        fn manifest(&self, bytes: &[u8], version: AgentVersion) -> SignedReleaseManifest {
            sign_release(
                ReleaseManifest {
                    version,
                    blake3: fleet_crypto::blake3(bytes),
                    min_proto: 1,
                    target: AgentTarget::current().unwrap(),
                },
                DeviceId([2; 16]),
                &self.root,
            )
            .unwrap()
        }

        fn upload(&self, bytes: &[u8]) -> Hash32 {
            let h = fleet_crypto::blake3(bytes);
            fs::write(self.paths.incoming_dir.join(hex::encode(h)), bytes).unwrap();
            h
        }
    }

    #[test]
    fn stage_commit_and_rollback() {
        let f = fx();
        let h = f.upload(b"build-2");
        let m = f.manifest(b"build-2", v(2));
        stage(&f.paths, &m, h, &f.roster, host()).unwrap();
        assert!(!f.paths.incoming_dir.join(hex::encode(h)).exists());
        let staged = f.paths.staging_dir.join(hex::encode(h));
        assert_eq!(fs::read(&staged).unwrap(), b"build-2");
        assert_eq!(
            fs::metadata(&staged).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let new = commit(&f.paths, v(2), &f.roster, host()).unwrap();
        assert_eq!(new.version, v(2));
        assert_eq!(fs::read(&f.paths.agent_bin).unwrap(), b"build-2");
        assert_eq!(fs::read(&f.paths.agent_prev_bin).unwrap(), b"build-1");
        let st = read_state(&f.paths).unwrap();
        assert_eq!(st.prev.unwrap().blake3, fleet_crypto::blake3(b"build-1"));
        let prev = rollback(&f.paths).unwrap();
        assert_eq!(prev.version, v(1));
        assert_eq!(fs::read(&f.paths.agent_bin).unwrap(), b"build-1");
        assert!(matches!(rollback(&f.paths), Err(UpdateError::NoPrevious)));
    }

    #[test]
    fn stage_refuses_hash_mismatch_symlink_and_old_versions() {
        let f = fx();
        // Uploaded bytes differ from what the manifest signs.
        let m = f.manifest(b"build-2", v(2));
        fs::write(
            f.paths.incoming_dir.join(hex::encode(m.manifest.blake3)),
            b"evil",
        )
        .unwrap();
        let e = stage(&f.paths, &m, m.manifest.blake3, &f.roster, host()).unwrap_err();
        assert!(matches!(e, UpdateError::HashMismatch), "{e}");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert!(
            fs::read_dir(&f.paths.staging_dir).unwrap().next().is_none(),
            "nothing staged"
        );
        // A symlink in the drop directory is refused, not followed.
        let target = f.paths.root.join("secret");
        fs::write(&target, b"build-2").unwrap();
        let link = f.paths.incoming_dir.join(hex::encode(m.manifest.blake3));
        fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let e = stage(&f.paths, &m, m.manifest.blake3, &f.roster, host()).unwrap_err();
        assert!(matches!(e, UpdateError::NotRegular), "{e}");
        // Staged hash argument differs from the manifest.
        let e = stage(&f.paths, &m, [0; 32], &f.roster, host()).unwrap_err();
        assert!(matches!(e, UpdateError::HashMismatch));
        // Same or older version.
        let h = f.upload(b"build-0");
        let old = f.manifest(b"build-0", v(1));
        let e = stage(&f.paths, &old, h, &f.roster, host()).unwrap_err();
        assert_eq!(
            e.code(),
            ErrorCode::VersionConflict {
                current: pack_version(v(1))
            }
        );
        // Commit of something never staged.
        assert!(matches!(
            commit(&f.paths, v(3), &f.roster, host()),
            Err(UpdateError::NotStaged)
        ));
    }

    #[test]
    fn revert_restores_previous_build_once() {
        use fleet_ops::{CommandOutput, FakeRunner};
        use std::rc::Rc;
        let f = fx();
        let h = f.upload(b"build-2");
        stage(
            &f.paths,
            &f.manifest(b"build-2", v(2)),
            h,
            &f.roster,
            host(),
        )
        .unwrap();
        let r = UpdateRevert {
            paths: f.paths.clone(),
        };
        let runner = Rc::new(FakeRunner::new());
        let ctx = SysCtx::new(
            f.paths.root.clone(),
            runner.clone(),
            Rc::new(fleet_ops::SystemClock),
        );
        let snap = r
            .snapshot(&ctx, &Op::AgentUpdateCommit { version: v(2) })
            .unwrap();
        commit(&f.paths, v(2), &f.roster, host()).unwrap();
        let units: Vec<&str> = UNITS.to_vec();
        let mut reset = vec!["reset-failed"];
        reset.extend(&units);
        let mut restart = vec!["--no-block", "restart"];
        restart.extend(&units);
        runner.expect(SYSTEMCTL, &reset, Ok(CommandOutput::ok("")));
        runner.expect(SYSTEMCTL, &restart, Ok(CommandOutput::ok("")));
        r.restore(&ctx, &snap).unwrap();
        assert_eq!(fs::read(&f.paths.agent_bin).unwrap(), b"build-1");
        assert_eq!(runner.pending(), 0);
        // Again (a revert that crashed after restoring): no restart.
        r.restore(&ctx, &snap).unwrap();
        assert_eq!(runner.calls().len(), 2);
    }
}
