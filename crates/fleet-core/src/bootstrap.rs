//! One-time password bootstrap of this Mac's SSH key (design §10.1, §3.2):
//! what `ssh-copy-id` does, over SFTP, to a **pinned** host key.
//!
//! 1. Log in with the operator's password (`SshAuth::Password`; refused
//!    unless the host key is pinned).
//! 2. Over SFTP: ensure `~/.ssh` (0700) and `~/.ssh/authorized_keys` (0600)
//!    belong to the login user and are not symlinks, append this Mac's key
//!    line only if it is absent, and write the file atomically (temp file in
//!    `~/.ssh`, renamed over the original). Nothing is built as a shell
//!    string; the only command is the fixed `id -u`.
//! 3. Drop the password session and reconnect with the Secure Enclave key to
//!    prove it works ([`InstallError::KeyNotAccepted`] otherwise).
//!
//! The password lives in a [`SecretString`]; it is not stored anywhere.

use crate::install::{InstallError, InstallStage};
use crate::secret::SecretString;
use crate::sftp::{EntryKind, RemoteEntry, Sftp, SftpError, join};
use crate::ssh::{HostKey, SshAuth, SshConnection, SshError, SshOptions, SshSigner, SshTarget};
use std::time::Duration;

const ID: &str = "/usr/bin/id";
const SFTP_OPEN_TIMEOUT: Duration = Duration::from_secs(30);
const STEP_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest `authorized_keys` Fleet edits.
const MAX_AUTHORIZED_KEYS: u64 = 1024 * 1024;

/// What the bootstrap did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapOutcome {
    /// The key line was appended.
    Added,
    /// The key was already in `authorized_keys`; nothing was written.
    AlreadyPresent,
}

/// Whether `existing` already holds the key `alg b64` (an option prefix and
/// a comment on the line don't matter).
pub fn has_key(existing: &str, alg: &str, b64: &str) -> bool {
    existing.lines().any(|line| {
        let line = line.trim();
        if line.starts_with('#') {
            return false;
        }
        let toks: Vec<&str> = line.split_whitespace().collect();
        toks.windows(2).any(|w| w[0] == alg && w[1] == b64)
    })
}

/// The new file content with `key_line` appended, or `None` when the key is
/// already there. A missing final newline is added first; nothing else of
/// the old content changes.
pub fn plan_authorized_keys(existing: &str, key_line: &str) -> Option<String> {
    let mut parts = key_line.split_whitespace();
    let (alg, b64) = (parts.next()?, parts.next()?);
    if has_key(existing, alg, b64) {
        return None;
    }
    let mut out = String::with_capacity(existing.len() + key_line.len() + 2);
    out.push_str(existing);
    if !existing.is_empty() && !existing.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(key_line);
    out.push('\n');
    Some(out)
}

fn unsafe_path(msg: impl Into<String>) -> InstallError {
    InstallError::UnsafeAuthorizedKeys(msg.into())
}

/// `entry` must be a plain `want` owned by `uid` (lstat: a symlink is
/// reported as one and refused).
fn check_entry(entry: &RemoteEntry, want: EntryKind, uid: u32, what: &str) -> Result<(), InstallError> {
    if entry.kind == EntryKind::Symlink {
        return Err(unsafe_path(format!("{what} is a symbolic link")));
    }
    if entry.kind != want {
        return Err(unsafe_path(format!(
            "{what} is not a {}",
            if want == EntryKind::Dir { "directory" } else { "regular file" }
        )));
    }
    match entry.uid {
        Some(u) if u == uid => Ok(()),
        Some(u) => Err(unsafe_path(format!(
            "{what} is owned by uid {u}, not the login user (uid {uid})"
        ))),
        None => Err(unsafe_path(format!("can't tell who owns {what}"))),
    }
}

/// Adds `key_line` to the login user's `authorized_keys` over `sftp`.
/// `uid`: the login user's uid.
pub async fn install_key_over_sftp(
    sftp: &Sftp,
    uid: u32,
    key_line: &str,
) -> Result<BootstrapOutcome, InstallError> {
    let home = sftp.home().await?;
    let ssh_dir = join(&home, ".ssh")?;
    match sftp.stat(&ssh_dir).await {
        Err(SftpError::NotFound) => {
            sftp.mkdir(&ssh_dir).await?;
            sftp.chmod(&ssh_dir, 0o700).await?;
        }
        Err(e) => return Err(e.into()),
        Ok(e) => {
            check_entry(&e, EntryKind::Dir, uid, "~/.ssh")?;
            // sshd (StrictModes) ignores keys in a group/world-writable dir.
            if e.mode & 0o077 != 0 {
                sftp.chmod(&ssh_dir, 0o700).await?;
            }
        }
    }
    let file = join(&ssh_dir, "authorized_keys")?;
    let existing = match sftp.stat(&file).await {
        Err(SftpError::NotFound) => String::new(),
        Err(e) => return Err(e.into()),
        Ok(e) => {
            check_entry(&e, EntryKind::File, uid, "~/.ssh/authorized_keys")?;
            let bytes = sftp.read_file(&file, MAX_AUTHORIZED_KEYS).await?;
            String::from_utf8(bytes)
                .map_err(|_| unsafe_path("~/.ssh/authorized_keys is not valid UTF-8"))?
        }
    };
    let Some(new) = plan_authorized_keys(&existing, key_line) else {
        return Ok(BootstrapOutcome::AlreadyPresent);
    };
    sftp.write_atomic(&file, new.as_bytes(), 0o600).await?;
    // Read back what the server now has.
    let after = sftp.read_file(&file, MAX_AUTHORIZED_KEYS).await?;
    let mut parts = key_line.split_whitespace();
    let (alg, b64) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if !has_key(&String::from_utf8_lossy(&after), alg, b64) {
        return Err(unsafe_path("the server did not keep the new key"));
    }
    Ok(BootstrapOutcome::Added)
}

/// Runs the whole bootstrap (see the module docs). `host_key` must be the
/// pinned key; `password` is sent only after it matched.
pub async fn bootstrap_key(
    target: &SshTarget,
    host_key: HostKey,
    password: &SecretString,
    ssh_key: &dyn SshSigner,
    progress: &mut (dyn FnMut(InstallStage) + Send),
) -> Result<BootstrapOutcome, InstallError> {
    progress(InstallStage::AddingKey);
    let key_line = format!("{} fleet", ssh_key.public_key().to_openssh()?);
    let opts = SshOptions::default();
    let auth = SshAuth::Password {
        secret: password,
        jump_key: ssh_key,
    };
    let (conn, obs) =
        SshConnection::connect_auth(target, &auth, Some(host_key.clone()), &opts).await?;
    if !obs.all_matched() {
        conn.disconnect().await;
        return Err(SshError::HostKeyUnconfirmed.into());
    }
    let outcome = async {
        let uid = login_uid(&conn).await;
        let sftp = tokio::time::timeout(SFTP_OPEN_TIMEOUT, Sftp::open(&conn))
            .await
            .map_err(|_| InstallError::StepTimeout("opening SFTP"))??;
        let uid = match uid {
            Some(u) => u,
            // No exec (SFTP-only login): the home directory's owner.
            None => sftp.stat(&sftp.home().await?).await?.uid.ok_or_else(|| {
                unsafe_path("can't tell which user owns the home directory")
            })?,
        };
        tokio::time::timeout(STEP_TIMEOUT, install_key_over_sftp(&sftp, uid, &key_line))
            .await
            .map_err(|_| InstallError::StepTimeout("adding the key"))?
    }
    .await;
    // The password session ends here, success or not.
    conn.disconnect().await;
    drop(conn);
    let outcome = outcome?;
    match SshConnection::connect_auth(target, &SshAuth::Key(ssh_key), Some(host_key), &opts).await
    {
        Ok((c, _)) => {
            c.disconnect().await;
            Ok(outcome)
        }
        Err(SshError::AuthRejected) => Err(InstallError::KeyNotAccepted),
        Err(e) => Err(e.into()),
    }
}

/// `id -u` of the login user (fixed command, no arguments from outside).
async fn login_uid(conn: &SshConnection) -> Option<u32> {
    let cmd = crate::install::command_line(&[ID, "-u"]).ok()?;
    let out = conn
        .exec_capture(&cmd, 64, Duration::from_secs(15))
        .await
        .ok()?;
    if out.status != Some(0) {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNh fleet";

    #[test]
    fn appends_once_and_keeps_old_lines() {
        let out = plan_authorized_keys("", KEY).unwrap();
        assert_eq!(out, format!("{KEY}\n"));
        let old = "ssh-ed25519 AAAAC3Nz me@laptop";
        let out = plan_authorized_keys(old, KEY).unwrap();
        assert_eq!(out, format!("{old}\n{KEY}\n"));
        let old = "ssh-ed25519 AAAAC3Nz me@laptop\n";
        assert_eq!(
            plan_authorized_keys(old, KEY).unwrap(),
            format!("{old}{KEY}\n")
        );
        // Idempotent: a second run on the result changes nothing.
        assert!(plan_authorized_keys(&out, KEY).is_none());
    }

    #[test]
    fn present_with_options_or_other_comment() {
        let with_opts = r#"no-pty,from="10.0.0.1" ecdsa-sha2-nistp256 AAAAE2VjZHNh laptop"#;
        assert!(plan_authorized_keys(with_opts, KEY).is_none());
        // A commented-out copy doesn't count; a different key doesn't either.
        assert!(plan_authorized_keys("# ecdsa-sha2-nistp256 AAAAE2VjZHNh", KEY).is_some());
        assert!(plan_authorized_keys("ecdsa-sha2-nistp256 AAAAOTHER x", KEY).is_some());
        // Same blob under another algorithm name is not the same key line.
        assert!(plan_authorized_keys("ssh-ed25519 AAAAE2VjZHNh x", KEY).is_some());
    }

    fn entry(kind: EntryKind, uid: Option<u32>) -> RemoteEntry {
        RemoteEntry {
            name: "x".into(),
            path: "/h/x".into(),
            kind,
            size: 0,
            mode: 0o600,
            uid,
            gid: Some(1000),
            user: None,
            group: None,
            mtime_s: None,
        }
    }

    #[test]
    fn refuses_symlinks_wrong_type_and_wrong_owner() {
        let ok = check_entry(&entry(EntryKind::File, Some(1000)), EntryKind::File, 1000, "f");
        assert!(ok.is_ok());
        for (e, want) in [
            (entry(EntryKind::Symlink, Some(1000)), EntryKind::File),
            (entry(EntryKind::Symlink, Some(1000)), EntryKind::Dir),
            (entry(EntryKind::Dir, Some(1000)), EntryKind::File),
            (entry(EntryKind::File, Some(0)), EntryKind::File),
            (entry(EntryKind::Dir, None), EntryKind::Dir),
        ] {
            assert!(
                matches!(
                    check_entry(&e, want, 1000, "f"),
                    Err(InstallError::UnsafeAuthorizedKeys(_))
                ),
                "{e:?}"
            );
        }
    }
}
