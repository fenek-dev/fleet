//! Agent install on an existing server over SSH (design §10.1).
//!
//! The operator's access is this Mac's SSH key (Secure Enclave), which the
//! operator has already put in the admin user's `authorized_keys`; no
//! passwords are handled. The host key must be pinned before anything is
//! uploaded (first-use confirmation happens in the app).
//!
//! 1. Upload over SFTP, each file created with `O_EXCL` under a random name
//!    in `/tmp`: the agent artifact (a `.deb` package or a bare binary), the
//!    genesis roster (hex) and the policy (TOML).
//! 2. `sha256sum` the upload and compare with the local file. This only
//!    catches transport errors: nothing on the server is trusted to verify
//!    the agent (signed-manifest checks come with `agent.update.*`).
//! 3. `.deb`: `dpkg -i` it (creates users, units, `/usr/lib/fleet`), then
//!    run the installed binary; bare binary: run it from `/tmp` (development:
//!    the package's users and units must already exist).
//!    `fleet-agent install --genesis … --policy … --server-id … --admin-user …`
//!    prints `noise_static=<hex>` and `signing_key=<hex>`; those are pinned.
//! 4. `systemctl enable --now` the two units, remove the temp files.
//!
//! **Command lines.** SSH exec requests are strings the remote shell
//! parses, so every command here is built by [`command_line`] from tokens
//! that match `[A-Za-z0-9_./=-]+` (values additionally may not start with
//! `-`). No quoting is ever needed or attempted; anything else is refused
//! before it reaches the wire (security rule 4).

use crate::sftp::{Sftp, SftpError};
use crate::ssh::{ExecOutput, HostKey, SshConnection, SshError, SshSigner, SshTarget};
use fleet_proto::{Ed25519Public, ServerId, SignedRoster, X25519Public, encode};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Duration;

/// Where the package installs the agent (and the bridge command uses).
pub const INSTALLED_AGENT: &str = "/usr/lib/fleet/fleet-agent";
// Fixed binary paths (rule 4): nothing is looked up in the login user's
// `PATH`, which that user controls. Debian 12+ / Ubuntu 22.04+ are
// merged-/usr, so everything is under /usr/bin.
const SUDO: &str = "/usr/bin/sudo";
const SHA256SUM: &str = "/usr/bin/sha256sum";
const DPKG: &str = "/usr/bin/dpkg";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const RM: &str = "/usr/bin/rm";
const MAX_OUTPUT: usize = 64 * 1024;
const STEP_TIMEOUT: Duration = Duration::from_secs(300);
/// Reading the local artifact (a few MB): only a permission prompt or a
/// dead network volume makes this slow.
const READ_TIMEOUT: Duration = Duration::from_secs(20);
/// Opening the SFTP subsystem (two channels and the version handshake).
const SFTP_OPEN_TIMEOUT: Duration = Duration::from_secs(30);
/// One SFTP upload; the artifact is at most [`MAX_ARTIFACT`], and even a
/// slow link moves that in this time. A stalled server fails instead of
/// leaving the install "running" forever.
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(300);
/// Largest agent artifact accepted (budget: binary under 10 MB).
pub const MAX_ARTIFACT: u64 = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error(transparent)]
    Ssh(#[from] SshError),
    #[error(transparent)]
    Sftp(#[from] SftpError),
    #[error("argument {0:?} is not a safe command token")]
    UnsafeToken(String),
    #[error("agent artifact: {0}")]
    Artifact(String),
    #[error("uploaded file hash differs (transport error)")]
    HashMismatch,
    /// A remote step failed; `stderr` is untrusted server text.
    #[error("{step} failed (exit {status:?}): {stderr}")]
    Remote {
        step: &'static str,
        status: Option<u32>,
        stderr: String,
    },
    /// A local step (not a remote command, whose timeout is
    /// [`SshError::Timeout`]) made no progress in time.
    #[error("{0} timed out")]
    StepTimeout(&'static str),
    #[error("agent install printed no keys")]
    NoKeys,
    #[error("rng")]
    Rng,
}

/// Progress for the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallStage {
    Connecting,
    Uploading { done: u64, total: u64 },
    Verifying,
    Installing,
    Starting,
    CleaningUp,
}

/// A shell-safe token: `[A-Za-z0-9_./=-]+`, at most 4096 bytes.
pub fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 4096
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'/' | b'=' | b'-'))
}

/// A value token: [`is_token`] and not starting with `-` (never an option).
pub fn value(s: &str) -> Result<&str, InstallError> {
    if is_token(s) && !s.starts_with('-') {
        Ok(s)
    } else {
        Err(InstallError::UnsafeToken(s.to_string()))
    }
}

/// Joins tokens with single spaces after checking every one.
pub fn command_line(tokens: &[&str]) -> Result<String, InstallError> {
    if let Some(bad) = tokens.iter().find(|t| !is_token(t)) {
        return Err(InstallError::UnsafeToken((*bad).to_string()));
    }
    Ok(tokens.join(" "))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    Deb,
    Binary,
}

impl ArtifactKind {
    pub fn of(path: &Path) -> Self {
        if path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("deb"))
        {
            Self::Deb
        } else {
            Self::Binary
        }
    }
}

/// Parses `noise_static=<64 hex>` / `signing_key=<64 hex>` lines.
pub fn parse_keys(stdout: &[u8]) -> Result<(X25519Public, Ed25519Public), InstallError> {
    let text = String::from_utf8_lossy(stdout);
    let mut noise = None;
    let mut signing = None;
    for line in text.lines() {
        let Some((k, v)) = line.trim().split_once('=') else {
            continue;
        };
        let Ok(raw) = hex::decode(v.trim()) else {
            continue;
        };
        let Ok(arr) = <[u8; 32]>::try_from(raw.as_slice()) else {
            continue;
        };
        match k {
            "noise_static" => noise = Some(X25519Public(arr)),
            "signing_key" => signing = Some(Ed25519Public(arr)),
            _ => {}
        }
    }
    match (noise, signing) {
        (Some(n), Some(s)) => Ok((n, s)),
        _ => Err(InstallError::NoKeys),
    }
}

/// Everything needed for one install.
pub struct InstallRequest<'a> {
    pub server_id: &'a ServerId,
    pub target: &'a SshTarget,
    /// Must be pinned already (first-use confirmed by the operator).
    pub host_key: HostKey,
    /// `--admin-user`: whose `authorized_keys` Fleet will manage.
    pub admin_user: &'a str,
    pub artifact: &'a Path,
    pub genesis: &'a SignedRoster,
    pub policy_toml: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstalledAgent {
    pub noise_static: X25519Public,
    pub signing_key: Ed25519Public,
}

/// Longest stderr excerpt kept in an error.
const MAX_STDERR: usize = 2000;

/// `s` cut to at most `max` bytes on a char boundary (never panics).
fn truncate_chars(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

fn remote_failure(step: &'static str, out: &ExecOutput) -> InstallError {
    let stderr = truncate_chars(
        String::from_utf8_lossy(&out.stderr).into_owned(),
        MAX_STDERR,
    );
    InstallError::Remote {
        step,
        status: out.status,
        stderr,
    }
}

async fn run(
    conn: &SshConnection,
    step: &'static str,
    tokens: &[&str],
) -> Result<ExecOutput, InstallError> {
    let cmd = command_line(tokens)?;
    let out = conn.exec_capture(&cmd, MAX_OUTPUT, STEP_TIMEOUT).await?;
    if out.status != Some(0) {
        return Err(remote_failure(step, &out));
    }
    Ok(out)
}

/// Connects without a pin, authenticates (so a missing `authorized_keys`
/// entry shows up now) and reports the host keys seen, for first-use
/// confirmation before [`install_agent`].
pub async fn probe(
    target: &SshTarget,
    ssh_key: &dyn SshSigner,
) -> Result<crate::ssh::HostKeyObservation, InstallError> {
    let (conn, obs) = SshConnection::connect(target, ssh_key, None).await?;
    conn.disconnect().await;
    Ok(obs)
}

async fn read_artifact(path: &Path, limit: Duration) -> Result<Vec<u8>, InstallError> {
    tokio::time::timeout(limit, tokio::fs::read(path))
        .await
        .map_err(|_| {
            InstallError::Artifact(format!(
                "reading {} timed out (macOS may be waiting for file access permission; \
                 grant it in System Settings or use a file outside Documents, Desktop and Downloads)",
                path.display()
            ))
        })?
        .map_err(|e| InstallError::Artifact(e.to_string()))
}

/// Runs the install; see the module docs.
pub async fn install_agent(
    req: InstallRequest<'_>,
    ssh_key: &dyn SshSigner,
    progress: &mut (dyn FnMut(InstallStage) + Send),
) -> Result<InstalledAgent, InstallError> {
    let server_id = value(req.server_id.as_str())?;
    let admin = value(req.admin_user)?;
    let kind = ArtifactKind::of(req.artifact);
    // macOS can block a read under ~/Documents, ~/Desktop or ~/Downloads
    // forever behind a privacy (TCC) prompt nobody sees; fail instead.
    let artifact = read_artifact(req.artifact, READ_TIMEOUT).await?;
    if artifact.is_empty() || artifact.len() as u64 > MAX_ARTIFACT {
        return Err(InstallError::Artifact("empty or too large".into()));
    }
    let local_hash = hex::encode(Sha256::digest(&artifact));

    progress(InstallStage::Connecting);
    let (conn, obs) =
        SshConnection::connect(req.target, ssh_key, Some(req.host_key.clone())).await?;
    // Jump hops need their pins too; nothing is uploaded through an
    // unconfirmed hop.
    if !obs.all_matched() {
        conn.disconnect().await;
        return Err(SshError::HostKeyUnconfirmed.into());
    }
    let result = async {
        let mut suffix = [0u8; 8];
        fleet_crypto::random_bytes(&mut suffix).map_err(|_| InstallError::Rng)?;
        let suffix = hex::encode(suffix);
        let bin = match kind {
            ArtifactKind::Deb => format!("/tmp/fleet-agent.{suffix}.deb"),
            ArtifactKind::Binary => format!("/tmp/fleet-agent.{suffix}"),
        };
        let genesis_path = format!("/tmp/fleet-genesis.{suffix}");
        let policy_path = format!("/tmp/fleet-policy.{suffix}.toml");
        let temp = [bin.clone(), genesis_path.clone(), policy_path.clone()];
        let sudo: &[&str] = if req.target.user == "root" {
            &[]
        } else {
            &[SUDO, "-n"]
        };

        let outcome = async {
            let sftp = tokio::time::timeout(SFTP_OPEN_TIMEOUT, Sftp::open(&conn))
                .await
                .map_err(|_| InstallError::StepTimeout("opening SFTP"))??;
            let total = artifact.len() as u64;
            let mode = if kind == ArtifactKind::Binary {
                0o700
            } else {
                0o600
            };
            tokio::time::timeout(
                UPLOAD_TIMEOUT,
                sftp.upload_bytes(&artifact, &bin, Some(mode), true, &mut |done, total| {
                    progress(InstallStage::Uploading { done, total })
                }),
            )
            .await
            .map_err(|_| InstallError::StepTimeout("uploading the agent"))??;
            let genesis_hex = hex::encode(encode(req.genesis));
            tokio::time::timeout(
                STEP_TIMEOUT,
                sftp.upload_bytes(
                    genesis_hex.as_bytes(),
                    &genesis_path,
                    Some(0o600),
                    true,
                    &mut |_, _| {},
                ),
            )
            .await
            .map_err(|_| InstallError::StepTimeout("uploading the roster"))??;
            tokio::time::timeout(
                STEP_TIMEOUT,
                sftp.upload_bytes(
                    req.policy_toml.as_bytes(),
                    &policy_path,
                    Some(0o600),
                    true,
                    &mut |_, _| {},
                ),
            )
            .await
            .map_err(|_| InstallError::StepTimeout("uploading the policy"))??;
            progress(InstallStage::Uploading { done: total, total });

            progress(InstallStage::Verifying);
            let out = run(&conn, "sha256sum", &[SHA256SUM, "--", value(&bin)?]).await?;
            let remote_hash = String::from_utf8_lossy(&out.stdout)
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            if remote_hash != local_hash {
                return Err(InstallError::HashMismatch);
            }

            progress(InstallStage::Installing);
            let agent = match kind {
                ArtifactKind::Deb => {
                    let mut t = sudo.to_vec();
                    t.extend([DPKG, "-i", value(&bin)?]);
                    run(&conn, "dpkg -i", &t).await?;
                    INSTALLED_AGENT.to_string()
                }
                ArtifactKind::Binary => bin.clone(),
            };
            let mut t = sudo.to_vec();
            t.extend([
                value(&agent)?,
                "install",
                "--genesis",
                value(&genesis_path)?,
                "--policy",
                value(&policy_path)?,
                "--server-id",
                server_id,
                "--admin-user",
                admin,
            ]);
            let out = run(&conn, "fleet-agent install", &t).await?;
            let (noise_static, signing_key) = parse_keys(&out.stdout)?;

            progress(InstallStage::Starting);
            let mut t = sudo.to_vec();
            t.extend([
                SYSTEMCTL,
                "enable",
                "--now",
                "fleet-exec.service",
                "fleet-gate.service",
            ]);
            run(&conn, "systemctl enable", &t).await?;
            Ok(InstalledAgent {
                noise_static,
                signing_key,
            })
        }
        .await;

        progress(InstallStage::CleaningUp);
        // Best effort; the files are the login user's, no sudo needed.
        let mut t = vec![RM, "-f", "--"];
        for p in &temp {
            t.push(value(p)?);
        }
        if let Ok(cmd) = command_line(&t) {
            let _ = conn
                .exec_capture(&cmd, MAX_OUTPUT, Duration::from_secs(15))
                .await;
        }
        outcome
    }
    .await;
    conn.disconnect().await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens() {
        assert!(is_token("/usr/lib/fleet/fleet-agent"));
        assert!(is_token("--admin-user"));
        assert!(is_token("srv_abc123"));
        for bad in [
            "", "a b", "a;b", "$(x)", "`x`", "a'b", "a\"b", "a\nb", "a|b", "~", "a*",
        ] {
            assert!(!is_token(bad), "{bad:?}");
        }
        assert!(value("-oProxyCommand=x").is_err());
        assert!(value("deploy").is_ok());
        assert_eq!(
            command_line(&["sudo", "-n", "dpkg", "-i", "/tmp/x.deb"]).unwrap(),
            "sudo -n dpkg -i /tmp/x.deb"
        );
        assert!(command_line(&["rm", "-f", "/tmp/a b"]).is_err());
        for bin in [SUDO, SHA256SUM, DPKG, SYSTEMCTL, RM] {
            assert!(bin.starts_with("/usr/bin/") && is_token(bin));
        }
    }

    #[test]
    fn stderr_truncates_on_char_boundary() {
        let s = "é".repeat(MAX_STDERR); // 2 bytes each
        let t = truncate_chars(format!("x{s}"), MAX_STDERR);
        assert!(t.len() <= MAX_STDERR && t.starts_with('x'));
        assert_eq!(truncate_chars("short".into(), MAX_STDERR), "short");
    }

    /// A read that never returns (what a macOS privacy prompt does to a
    /// file read) fails within the limit instead of hanging the install.
    #[cfg(unix)]
    #[tokio::test]
    async fn blocked_artifact_read_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("agent");
        let ok = std::process::Command::new("/usr/bin/mkfifo")
            .arg(&fifo)
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            return; // no mkfifo here
        }
        let started = std::time::Instant::now();
        let err = read_artifact(&fifo, Duration::from_millis(200))
            .await
            .unwrap_err();
        assert!(matches!(err, InstallError::Artifact(m) if m.contains("timed out")));
        assert!(started.elapsed() < Duration::from_secs(5));
        // Unblock the abandoned reader thread so the runtime can shut down.
        let _ = std::fs::OpenOptions::new().write(true).open(&fifo);
    }

    #[test]
    fn keys_parse() {
        let out = format!(
            "noise_static={}\nsigning_key={}\n",
            "ab".repeat(32),
            "cd".repeat(32)
        );
        let (n, s) = parse_keys(out.as_bytes()).unwrap();
        assert_eq!(n.0, [0xab; 32]);
        assert_eq!(s.0, [0xcd; 32]);
        assert!(parse_keys(b"noise_static=00\n").is_err());
        assert!(parse_keys(b"").is_err());
    }

    #[test]
    fn artifact_kind() {
        assert_eq!(
            ArtifactKind::of(Path::new("/x/fleet-agent_0.1.0_amd64.deb")),
            ArtifactKind::Deb
        );
        assert_eq!(
            ArtifactKind::of(Path::new("/x/fleet-agent")),
            ArtifactKind::Binary
        );
    }
}
