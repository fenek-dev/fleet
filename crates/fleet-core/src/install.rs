//! Agent install on an existing server over SSH (design §10.1).
//!
//! The operator's access is this Mac's SSH key (Secure Enclave), which the
//! operator has put in the admin user's `authorized_keys`, or which
//! [`crate::bootstrap::bootstrap_key`] added with a one-time password.
//! That password (if given) is also what answers `sudo -S` below; it is
//! never stored and never on a command line. The host key must be pinned
//! before anything is uploaded or any password sent (first-use
//! confirmation happens in the app).
//!
//! 1. Upload over SFTP, each file created with `O_EXCL` under a random name
//!    in `/tmp`: the agent artifact (a `.deb` package or a bare binary), the
//!    genesis roster (hex) and the policy (TOML).
//! 2. `sha256sum` the upload and compare with the local file. This only
//!    catches transport errors: nothing on the server is trusted to verify
//!    the agent (signed-manifest checks come with `agent.update.*`).
//! 3. `.deb`: `dpkg -i` it (creates users, units, `/usr/lib/fleet`), then
//!    run the installed binary; bare binary: refused up front unless the
//!    package's `fleet-gate` user already exists ([`InstallError::NeedsPackage`]),
//!    else `install(1)`ed root-owned to `/usr/lib/fleet/fleet-agent` and run
//!    from there (`/tmp` is often noexec).
//!    `fleet-agent install` (root) adds the admin user to group `fleet`; a
//!    fresh login must show the group (`id -nG`) before the install is
//!    reported done ([`InstallError::NotInFleetGroup`]).
//!    `fleet-agent install --genesis … --policy … --server-id … --admin-user …`
//!    prints `noise_static=<hex>` and `signing_key=<hex>`; those are pinned.
//! 4. `systemctl enable --now` the two units, remove the temp files.
//!
//! **Command lines.** SSH exec requests are strings the remote shell
//! parses, so every command here is built by [`command_line`] from tokens
//! that match `[A-Za-z0-9_./=-]+` (values additionally may not start with
//! `-`). No quoting is ever needed or attempted; anything else is refused
//! before it reaches the wire (security rule 4).

use crate::secret::SecretString;
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
const CAT: &str = "/usr/bin/cat";
const UNAME: &str = "/usr/bin/uname";
const GETENT: &str = "/usr/bin/getent";
const INSTALL: &str = "/usr/bin/install";
const ID: &str = "/usr/bin/id";
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
    /// The server is not a supported target (checked before any upload).
    #[error("unsupported server: {0}")]
    Unsupported(String),
    #[error("uploaded file hash differs (transport error)")]
    HashMismatch,
    /// A remote step failed; `stderr` is untrusted server text.
    #[error("{step} failed ({}){}", exit_text(*status), stderr_suffix(stderr))]
    Remote {
        step: &'static str,
        status: Option<u32>,
        stderr: String,
    },
    /// A bare binary was chosen but the server has no Fleet package yet
    /// (`fleet-gate` user / `fleet` group), which only the `.deb` creates.
    #[error(
        "this server has no Fleet agent package (users and services are missing), so a bare \
         fleet-agent binary can't be installed; choose the .deb package instead"
    )]
    NeedsPackage,
    /// The install finished but a fresh login of the admin user is not in
    /// group `fleet`, so `fleet-agent bridge` can't reach the agent.
    #[error(
        "the agent is installed, but user {0} is not in the server's `fleet` group, so it can't \
         reach the agent socket; run `sudo usermod -aG fleet {0}` on the server and reconnect"
    )]
    NotInFleetGroup(String),
    /// A local step (not a remote command, whose timeout is
    /// [`SshError::Timeout`]) made no progress in time.
    #[error("{0} timed out")]
    StepTimeout(&'static str),
    #[error("agent install printed no keys")]
    NoKeys,
    /// `sudo` needs a password and none was given.
    #[error(
        "the user has no passwordless sudo: enter the user's password (used once for sudo, not \
         stored) or enable passwordless sudo"
    )]
    SudoPasswordRequired,
    /// `sudo` refused the password.
    #[error("sudo refused the password; check it and try again")]
    SudoPasswordRejected,
    /// The user may not run `sudo` at all.
    #[error("user {0} is not allowed to use sudo on this server (not in the sudoers file)")]
    NotInSudoers(String),
    /// `~/.ssh` or `authorized_keys` is not something Fleet will edit.
    #[error("not adding the key: {0}")]
    UnsafeAuthorizedKeys(String),
    /// The key was written but the server still refuses it.
    #[error(
        "the key was added to authorized_keys, but the server still refuses it (check \
         AuthorizedKeysFile in sshd_config and that the home directory is not group/world \
         writable)"
    )]
    KeyNotAccepted,
    #[error("password: {0}")]
    Password(#[from] crate::secret::SecretError),
    #[error("rng")]
    Rng,
}

impl InstallError {
    /// Every server-provided text in the error (stderr, SFTP status
    /// messages, protocol errors) with `secret` scrubbed, for use while the
    /// password is still in scope, before the error leaves fleet-core.
    pub fn scrubbed(self, secret: &SecretString) -> Self {
        let s = |m: String| secret.scrub(&m);
        match self {
            Self::Remote { step, status, stderr } => Self::Remote {
                step,
                status,
                stderr: s(stderr),
            },
            Self::Sftp(SftpError::Failed(m)) => Self::Sftp(SftpError::Failed(s(m))),
            Self::Sftp(SftpError::Local(m)) => Self::Sftp(SftpError::Local(s(m))),
            Self::Ssh(SshError::Sftp(m)) => Self::Ssh(SshError::Sftp(s(m))),
            Self::Ssh(SshError::BadKey(m)) => Self::Ssh(SshError::BadKey(s(m))),
            Self::Ssh(SshError::Ssh(e)) => {
                let text = e.to_string();
                if text.contains(secret.expose()) {
                    Self::Ssh(SshError::Sftp(s(text)))
                } else {
                    Self::Ssh(SshError::Ssh(e))
                }
            }
            Self::Artifact(m) => Self::Artifact(s(m)),
            Self::Unsupported(m) => Self::Unsupported(s(m)),
            other => other,
        }
    }
}

/// Where the agent artifact comes from.
#[derive(Debug, Clone, Copy)]
pub enum ArtifactSource<'a> {
    /// An operator-chosen file (`.deb` or bare binary); no arch check.
    File(&'a Path),
    /// The app's bundled directory of `fleet-agent_<ver>_<debarch>.deb`;
    /// the one matching the server's architecture is picked after the
    /// preflight.
    Bundled(&'a Path),
}

/// The artifact chosen for this install, reported before the upload so
/// the operator can compare `blake3` with a reproducible build (design
/// §5.7). `blake3` is over the agent binary, as in release manifests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactInfo {
    pub name: String,
    pub blake3: String,
    /// Server architecture (`uname -m`), or empty for an operator file.
    pub arch: String,
    pub bundled: bool,
}

/// Server CPU architecture, from `uname -m`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerArch {
    Amd64,
    Arm64,
}

impl ServerArch {
    /// Debian architecture name (the `.deb` suffix).
    pub fn deb(self) -> &'static str {
        match self {
            Self::Amd64 => "amd64",
            Self::Arm64 => "arm64",
        }
    }
}

/// Parses `uname -m` output; anything but x86_64 / aarch64 is refused.
pub fn parse_arch(uname: &str) -> Result<ServerArch, InstallError> {
    match uname.trim() {
        "x86_64" => Ok(ServerArch::Amd64),
        "aarch64" | "arm64" => Ok(ServerArch::Arm64),
        other => Err(InstallError::Unsupported(format!(
            "CPU architecture {:?} (only x86_64 and aarch64 are supported)",
            truncate_chars(other.to_string(), 40)
        ))),
    }
}

/// Checks `/etc/os-release` text: Debian 12+ or Ubuntu 22.04+.
pub fn check_distro(os_release: &str) -> Result<(), InstallError> {
    let field = |key: &str| -> Option<String> {
        os_release.lines().find_map(|l| {
            let v = l.strip_prefix(key)?.strip_prefix('=')?;
            Some(v.trim().trim_matches('"').trim_matches('\'').to_string())
        })
    };
    let id = field("ID").unwrap_or_default();
    let version = field("VERSION_ID").unwrap_or_default();
    let mut parts = version.split('.').map(|p| p.parse::<u32>().ok());
    let (major, minor) = (parts.next().flatten(), parts.next().flatten().unwrap_or(0));
    let ok = match (id.as_str(), major) {
        ("debian", Some(m)) => m >= 12,
        ("ubuntu", Some(m)) => (m, minor) >= (22, 4),
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(InstallError::Unsupported(format!(
            "distribution {:?} {:?} (Debian 12+ and Ubuntu 22.04+ only)",
            truncate_chars(id, 40),
            truncate_chars(version, 40)
        )))
    }
}

/// The bundled package for `arch` in `dir` (`fleet-agent_*_<arch>.deb`;
/// the highest name if several).
pub fn pick_bundled(dir: &Path, arch: ServerArch) -> Result<std::path::PathBuf, InstallError> {
    let suffix = format!("_{}.deb", arch.deb());
    let mut found: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| InstallError::Artifact(format!("bundled agent directory: {e}")))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("fleet-agent_") && n.ends_with(&suffix))
        })
        .collect();
    found.sort();
    found.pop().ok_or_else(|| {
        InstallError::Artifact(format!(
            "this app build has no bundled agent for {} (choose a package manually)",
            arch.deb()
        ))
    })
}

/// A bundled package must hash (SHA-256 of the whole `.deb`) to the value
/// pinned in the signed app executable at build time, so a swapped file in
/// the bundle's Resources is refused before anything is uploaded.
pub fn verify_pin(
    name: &str,
    sha256_hex: &str,
    pins: &std::collections::BTreeMap<String, String>,
) -> Result<(), InstallError> {
    match pins.get(name) {
        Some(p) if p.eq_ignore_ascii_case(sha256_hex) => Ok(()),
        Some(_) => Err(InstallError::Artifact(format!(
            "bundled package {name} does not match the hash pinned in this app; refusing to upload it"
        ))),
        None => Err(InstallError::Artifact(format!(
            "bundled package {name} has no hash pinned in this app; refusing to upload it"
        ))),
    }
}

/// Progress for the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallStage {
    /// One-time password setup: adding this Mac's SSH key (design §10.1).
    AddingKey,
    Connecting,
    /// Server checked; the artifact that will be uploaded.
    Artifact(ArtifactInfo),
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
    pub artifact: ArtifactSource<'a>,
    /// Pinned SHA-256 (hex) of each bundled package by file name, compiled
    /// into the app; checked for `ArtifactSource::Bundled` only.
    pub bundled_pins: &'a std::collections::BTreeMap<String, String>,
    pub genesis: &'a SignedRoster,
    pub policy_toml: &'a str,
    /// One-time password for `sudo -S` when the user has no passwordless
    /// sudo. Written to the sudo channel's stdin only; never stored.
    pub sudo_password: Option<&'a SecretString>,
}

/// How privileged steps run.
#[derive(Clone, Copy)]
enum SudoMode<'a> {
    /// Root login: no sudo.
    Root,
    /// `sudo -n` (passwordless).
    Passwordless,
    /// `sudo -S -k -p ''` with the password on stdin.
    Password(&'a SecretString),
}

/// sudo's prompt in password mode: a fixed unique token. The password line
/// is written only after this text appears on stderr (sudo asked), never
/// speculatively, so a command sudo runs without asking (NOPASSWD) can't
/// receive it on stdin. `-k` ignores cached credentials so a prompt is
/// always the first thing sudo does.
const SUDO_PROMPT: &str = "fleet-sudo-prompt-7c1e9a42";
const SUDO_PASSWORD_PREFIX: &[&str] = &[SUDO, "-S", "-k", "-p", SUDO_PROMPT];
const TRUE: &str = "/usr/bin/true";

/// Why sudo failed, from its stderr (untrusted text, matched by phrase).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SudoFailure {
    /// `sudo -n` / `sudo -S` wants a (different) password.
    Password,
    NotSudoer,
    Other,
}

/// Classifies sudo's stderr (sudo and sudo-rs wording).
pub fn classify_sudo(stderr: &str) -> SudoFailure {
    let s = stderr.to_ascii_lowercase();
    if s.contains("is not in the sudoers")
        || s.contains("not allowed to run sudo")
        || s.contains("may not run sudo")
        || s.contains("is not allowed to execute")
    {
        SudoFailure::NotSudoer
    } else if s.contains("sorry, try again")
        || s.contains("incorrect password")
        || s.contains("no password was provided")
        || s.contains("a password is required")
        || s.contains("authentication failed")
        || s.contains("incorrect authentication")
    {
        SudoFailure::Password
    } else {
        SudoFailure::Other
    }
}

fn sudo_error(failure: SudoFailure, user: &str, had_password: bool) -> Option<InstallError> {
    match failure {
        SudoFailure::NotSudoer => Some(InstallError::NotInSudoers(user.to_string())),
        SudoFailure::Password if had_password => Some(InstallError::SudoPasswordRejected),
        SudoFailure::Password => Some(InstallError::SudoPasswordRequired),
        SudoFailure::Other => None,
    }
}

/// Runs `tokens` with privileges per `mode`. With a password, the command
/// is [`SUDO_PASSWORD_PREFIX`] + the validated tokens and the password line
/// goes to the channel's stdin once sudo prompts for it.
async fn run_sudo(
    conn: &SshConnection,
    step: &'static str,
    mode: SudoMode<'_>,
    user: &str,
    tokens: &[&str],
) -> Result<ExecOutput, InstallError> {
    match mode {
        SudoMode::Root => run(conn, step, tokens).await,
        SudoMode::Passwordless => {
            let mut t = vec![SUDO, "-n"];
            t.extend_from_slice(tokens);
            run(conn, step, &t).await
        }
        SudoMode::Password(secret) => {
            let mut t = SUDO_PASSWORD_PREFIX.to_vec();
            t.extend_from_slice(tokens);
            let cmd = command_line(&t)?;
            // Sent only once sudo has printed SUDO_PROMPT on stderr.
            let stdin = secret.sudo_stdin();
            let out = conn
                .exec_capture_prompted(
                    &cmd,
                    Some((SUDO_PROMPT, &stdin[..])),
                    MAX_OUTPUT,
                    STEP_TIMEOUT,
                )
                .await?;
            if out.status == Some(0) {
                return Ok(out);
            }
            let stderr = String::from_utf8_lossy(&out.stderr);
            if let Some(e) = sudo_error(classify_sudo(&stderr), user, true) {
                return Err(e);
            }
            // Scrub the whole capture first, then trim and truncate.
            let text = secret.scrub_capture(&out.stderr, out.stderr_truncated);
            Err(InstallError::Remote {
                step,
                status: out.status,
                stderr: truncate_chars(text.trim().to_string(), MAX_STDERR),
            })
        }
    }
}

/// Decides how privileged steps run: root needs nothing; otherwise
/// `sudo -n true` must work, or the one-time password must pass
/// `sudo -S true` (checked before anything is uploaded).
async fn sudo_preflight<'a>(
    conn: &SshConnection,
    user: &str,
    password: Option<&'a SecretString>,
) -> Result<SudoMode<'a>, InstallError> {
    if user == "root" {
        return Ok(SudoMode::Root);
    }
    let out = conn
        .exec_capture(
            &command_line(&[SUDO, "-n", TRUE])?,
            MAX_OUTPUT,
            Duration::from_secs(30),
        )
        .await?;
    if out.status == Some(0) {
        return Ok(SudoMode::Passwordless);
    }
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    match (classify_sudo(&stderr), password) {
        (SudoFailure::Other, _) => Err(remote_failure("sudo", &out)),
        (SudoFailure::NotSudoer, _) => Err(InstallError::NotInSudoers(user.to_string())),
        (SudoFailure::Password, None) => Err(InstallError::SudoPasswordRequired),
        (SudoFailure::Password, Some(p)) => {
            let mode = SudoMode::Password(p);
            run_sudo(conn, "sudo", mode, user, &[TRUE]).await?;
            Ok(mode)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstalledAgent {
    pub noise_static: X25519Public,
    pub signing_key: Ed25519Public,
}

fn exit_text(status: Option<u32>) -> String {
    match status {
        Some(c) => format!("exit {c}"),
        None => "killed by a signal".into(),
    }
}

fn stderr_suffix(stderr: &str) -> String {
    if stderr.is_empty() {
        String::new()
    } else {
        format!(": {stderr}")
    }
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
        String::from_utf8_lossy(&out.stderr).trim().to_string(),
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

/// Connects without a pin and **without authenticating** the final hop,
/// and reports the host keys seen. For a server that doesn't accept this
/// Mac's key yet: the operator confirms the fingerprint before the
/// one-time password is sent ([`crate::bootstrap::bootstrap_key`]).
pub async fn probe_host_key_only(
    target: &SshTarget,
    ssh_key: &dyn SshSigner,
) -> Result<crate::ssh::HostKeyObservation, InstallError> {
    Ok(SshConnection::probe_host_key_only(target, ssh_key, &crate::ssh::SshOptions::default())
        .await?)
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

async fn read_checked(path: &Path) -> Result<Vec<u8>, InstallError> {
    // macOS can block a read under ~/Documents, ~/Desktop or ~/Downloads
    // forever behind a privacy (TCC) prompt nobody sees; fail instead.
    let artifact = read_artifact(path, READ_TIMEOUT).await?;
    if artifact.is_empty() || artifact.len() as u64 > MAX_ARTIFACT {
        return Err(InstallError::Artifact("empty or too large".into()));
    }
    Ok(artifact)
}

/// Runs the install; see the module docs. Server text in errors is
/// scrubbed of the one-time password before it leaves.
pub async fn install_agent(
    req: InstallRequest<'_>,
    ssh_key: &dyn SshSigner,
    progress: &mut (dyn FnMut(InstallStage) + Send),
) -> Result<InstalledAgent, InstallError> {
    let secret = req.sudo_password;
    match (install_agent_inner(req, ssh_key, progress).await, secret) {
        (Err(e), Some(p)) => Err(e.scrubbed(p)),
        (r, _) => r,
    }
}

async fn install_agent_inner(
    req: InstallRequest<'_>,
    ssh_key: &dyn SshSigner,
    progress: &mut (dyn FnMut(InstallStage) + Send),
) -> Result<InstalledAgent, InstallError> {
    let server_id = value(req.server_id.as_str())?;
    let admin = value(req.admin_user)?;
    // An operator-chosen file is read up front (fail fast); a bundled one
    // is picked after the server's architecture is known.
    let mut chosen: Option<(std::path::PathBuf, Vec<u8>)> = None;
    if let ArtifactSource::File(path) = req.artifact {
        chosen = Some((path.to_path_buf(), read_checked(path).await?));
    }

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
        // Preflight (fixed commands, before anything is uploaded): the
        // distribution, and for a bundled package the architecture.
        let os = run(&conn, "os-release", &[CAT, "/etc/os-release"]).await?;
        check_distro(&String::from_utf8_lossy(&os.stdout))?;
        let uname = run(&conn, "uname", &[UNAME, "-m"]).await?;
        let arch = parse_arch(&String::from_utf8_lossy(&uname.stdout))?;
        // Passwordless sudo, or the one-time password verified now.
        let sudo = sudo_preflight(&conn, &req.target.user, req.sudo_password).await?;
        let bundled = if let ArtifactSource::Bundled(dir) = req.artifact {
            let path = pick_bundled(dir, arch)?;
            let bytes = read_checked(&path).await?;
            chosen = Some((path, bytes));
            true
        } else {
            false
        };
        let (path, artifact) = chosen.take().ok_or_else(|| {
            InstallError::Artifact("no artifact".into())
        })?;
        let kind = ArtifactKind::of(&path);
        // A bare binary can't create the `fleet-gate` user, the `fleet`
        // group or the units: refuse before uploading anything.
        if kind == ArtifactKind::Binary {
            let out = conn
                .exec_capture(
                    &command_line(&[GETENT, "passwd", "fleet-gate"])?,
                    MAX_OUTPUT,
                    Duration::from_secs(30),
                )
                .await?;
            if out.status != Some(0) {
                return Err(InstallError::NeedsPackage);
            }
        }
        // Every digest below is computed from these captured bytes: the
        // file is never reopened, so it can't change between the check
        // and the upload.
        let local_hash = hex::encode(Sha256::digest(&artifact));
        if bundled {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            verify_pin(name, &local_hash, req.bundled_pins)?;
        }
        let blake3 = crate::release::bytes_hash(&artifact, kind)
            .map_err(|e| InstallError::Artifact(e.to_string()))?;
        progress(InstallStage::Artifact(ArtifactInfo {
            name: path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            blake3,
            arch: arch.deb().to_string(),
            bundled,
        }));

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
        let user = req.target.user.as_str();

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
                    run_sudo(&conn, "dpkg -i", sudo, user, &[DPKG, "-i", value(&bin)?]).await?;
                    INSTALLED_AGENT.to_string()
                }
                ArtifactKind::Binary => {
                    // /tmp is often noexec (CIS hardening, Fleet's own
                    // Strict profile): copy into the root-owned agent
                    // directory and run it from there.
                    run_sudo(
                        &conn,
                        "install directory",
                        sudo,
                        user,
                        &[INSTALL, "-d", "-m", "0755", "-o", "root", "-g", "root", "/usr/lib/fleet"],
                    )
                    .await?;
                    run_sudo(
                        &conn,
                        "install agent binary",
                        sudo,
                        user,
                        &[
                            INSTALL,
                            "-m",
                            "0755",
                            "-o",
                            "root",
                            "-g",
                            "root",
                            value(&bin)?,
                            INSTALLED_AGENT,
                        ],
                    )
                    .await?;
                    INSTALLED_AGENT.to_string()
                }
            };
            let out = run_sudo(
                &conn,
                "fleet-agent install",
                sudo,
                user,
                &[
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
                ],
            )
            .await?;
            let (noise_static, signing_key) = parse_keys(&out.stdout)?;

            progress(InstallStage::Starting);
            run_sudo(
                &conn,
                "systemctl enable",
                sudo,
                user,
                &[
                    SYSTEMCTL,
                    "enable",
                    "--now",
                    "fleet-exec.service",
                    "fleet-gate.service",
                ],
            )
            .await?;

            // `fleet-agent install` put the admin user in group `fleet`;
            // only a fresh login carries it, and that is what the app's
            // bridge sessions use. Root reaches the socket regardless.
            if req.target.user != "root" {
                let (fresh, _) =
                    SshConnection::connect(req.target, ssh_key, Some(req.host_key.clone()))
                        .await?;
                let groups = run(&fresh, "id", &[ID, "-nG"]).await;
                fresh.disconnect().await;
                let groups = groups?;
                let text = String::from_utf8_lossy(&groups.stdout);
                if !text.split_whitespace().any(|g| g == "fleet") {
                    return Err(InstallError::NotInFleetGroup(admin.to_string()));
                }
            }
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
        for bin in [SUDO, SHA256SUM, DPKG, SYSTEMCTL, RM, CAT, UNAME, GETENT, INSTALL, ID] {
            assert!(bin.starts_with("/usr/bin/") && is_token(bin));
        }
    }

    #[test]
    fn sudo_stderr_classes() {
        for s in [
            "Sorry, try again.\nsudo: 1 incorrect password attempt",
            "sudo: no password was provided",
            "sudo: a password is required",
            "Authentication failed, try again.",
        ] {
            assert_eq!(classify_sudo(s), SudoFailure::Password, "{s}");
        }
        for s in [
            "alice is not in the sudoers file.  This incident will be reported.",
            "Sorry, user alice may not run sudo on host.",
        ] {
            // Not-a-sudoer wins over the retry noise that follows it.
            assert_eq!(classify_sudo(s), SudoFailure::NotSudoer, "{s}");
        }
        assert_eq!(classify_sudo("sudo: command not found"), SudoFailure::Other);
        assert!(matches!(
            sudo_error(SudoFailure::Password, "u", true),
            Some(InstallError::SudoPasswordRejected)
        ));
        assert!(matches!(
            sudo_error(SudoFailure::Password, "u", false),
            Some(InstallError::SudoPasswordRequired)
        ));
        assert!(sudo_error(SudoFailure::Other, "u", true).is_none());
    }

    #[test]
    fn sudo_prefix_is_fixed_and_password_never_in_tokens() {
        // Every token, the prompt marker included, passes the validator.
        assert_eq!(
            command_line(SUDO_PASSWORD_PREFIX).unwrap(),
            "/usr/bin/sudo -S -k -p fleet-sudo-prompt-7c1e9a42"
        );
        assert!(is_token(TRUE) && TRUE.starts_with("/usr/bin/"));
        // A password-looking value can't become a token.
        assert!(command_line(&[DPKG, "-i", "p@ss word'"]).is_err());
    }

    #[test]
    fn server_text_in_errors_is_scrubbed() {
        let secret = SecretString::from_string("s3cr3t-pw".into()).unwrap();
        let e = InstallError::Remote {
            step: "x",
            status: Some(1),
            stderr: "boom s3cr3t-pw".into(),
        }
        .scrubbed(&secret);
        assert!(!e.to_string().contains("s3cr3t"));
        for e in [
            InstallError::Sftp(SftpError::Failed("status: s3cr3t-pw".into())),
            InstallError::Ssh(SshError::Sftp("s3cr3t-pw".into())),
            InstallError::Artifact("s3cr3t-pw".into()),
        ] {
            assert!(!e.scrubbed(&secret).to_string().contains("s3cr3t"));
        }
    }

    #[test]
    fn errors_never_contain_the_secret() {
        let secret = SecretString::from_string("s3cr3t-pw".into()).unwrap();
        for e in [
            InstallError::SudoPasswordRequired,
            InstallError::SudoPasswordRejected,
            InstallError::NotInSudoers("alice".into()),
        ] {
            assert!(!e.to_string().contains("s3cr3t"));
        }
        let mut stderr = "sudo: echoed s3cr3t-pw".to_string();
        stderr = secret.scrub(&stderr);
        assert!(!stderr.contains("s3cr3t"));
    }

    #[test]
    fn arch_parse() {
        assert_eq!(parse_arch("x86_64\n").unwrap(), ServerArch::Amd64);
        assert_eq!(parse_arch("aarch64").unwrap(), ServerArch::Arm64);
        for bad in ["armv7l", "i686", "riscv64", "", "x86_64; rm"] {
            assert!(matches!(parse_arch(bad), Err(InstallError::Unsupported(_))), "{bad}");
        }
    }

    #[test]
    fn distro_gate() {
        let os = |id: &str, v: &str| format!("NAME=x\nID={id}\nVERSION_ID=\"{v}\"\nID_LIKE=debian\n");
        for (id, v) in [("debian", "12"), ("debian", "13"), ("ubuntu", "22.04"), ("ubuntu", "24.04"), ("ubuntu", "26.04")] {
            check_distro(&os(id, v)).unwrap_or_else(|e| panic!("{id} {v}: {e}"));
        }
        for (id, v) in [("debian", "11"), ("ubuntu", "20.04"), ("ubuntu", "21.10"), ("centos", "9"), ("debian", ""), ("linuxmint", "21")] {
            assert!(check_distro(&os(id, v)).is_err(), "{id} {v}");
        }
        // Debian testing has no VERSION_ID.
        assert!(check_distro("ID=debian\n").is_err());
        assert!(check_distro("").is_err());
    }

    #[test]
    fn pin_check() {
        let mut pins = std::collections::BTreeMap::new();
        pins.insert("a.deb".to_string(), "AB12".to_string());
        assert!(verify_pin("a.deb", "ab12", &pins).is_ok());
        assert!(verify_pin("a.deb", "ab13", &pins).is_err());
        assert!(verify_pin("b.deb", "ab12", &pins).is_err());
        assert!(verify_pin("a.deb", "ab12", &Default::default()).is_err());
    }

    #[test]
    fn bundled_pick() {
        let dir = tempfile::tempdir().unwrap();
        for n in ["fleet-agent_0.1.0_amd64.deb", "fleet-agent_0.1.0_arm64.deb", "other.deb"] {
            std::fs::write(dir.path().join(n), b"x").unwrap();
        }
        let p = pick_bundled(dir.path(), ServerArch::Arm64).unwrap();
        assert!(p.ends_with("fleet-agent_0.1.0_arm64.deb"));
        let empty = tempfile::tempdir().unwrap();
        assert!(matches!(
            pick_bundled(empty.path(), ServerArch::Amd64),
            Err(InstallError::Artifact(_))
        ));
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
    fn remote_error_text() {
        let e = InstallError::Remote {
            step: "fleet-agent install",
            status: Some(1),
            stderr: "sudo: nope".into(),
        };
        assert_eq!(e.to_string(), "fleet-agent install failed (exit 1): sudo: nope");
        let e = InstallError::Remote { step: "x", status: None, stderr: String::new() };
        assert_eq!(e.to_string(), "x failed (killed by a signal)");
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
