//! A user's own `~/.ssh/authorized_keys`, read and written **as that
//! user** (uninstall, design §10.3).
//!
//! Home directories are user-controlled: root following `~/.ssh` could be
//! pointed at `/root/.ssh` or `/etc` by a symlink. So root never touches
//! them; it runs `setpriv --reuid=<uid> --regid=<gid> --clear-groups
//! --reset-env -- /usr/lib/fleet/fleet-agent user-keys <op> <home>` (fixed
//! binary path, argument vector, content on stdin), and the helper works
//! with the user's own permissions, so a planted symlink can only reach
//! what the user could anyway.

use crate::fsutil::{self, UserEntry};
use crate::paths::{AGENT_BIN, SETPRIV};
use fleet_ops::{CommandRunner, CommandSpec, OpError};
use fleet_proto::ErrorCode;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

/// Largest `authorized_keys` handled.
pub const MAX_KEYS_FILE: usize = 1 << 20;

/// The helper's operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeysOp {
    /// Prints `1` + the file, or `0` if absent.
    Get,
    /// Replaces the file with stdin (creating `~/.ssh` 0700).
    Set,
    /// Removes the file.
    Remove,
    /// Appends each stdin line the file doesn't have yet.
    Merge,
}

impl KeysOp {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Set => "set",
            Self::Remove => "remove",
            Self::Merge => "merge",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "get" => Self::Get,
            "set" => Self::Set,
            "remove" => Self::Remove,
            "merge" => Self::Merge,
            _ => return None,
        })
    }
}

fn keys_path(home: &Path) -> std::path::PathBuf {
    home.join(".ssh").join("authorized_keys")
}

fn ensure_ssh_dir(home: &Path) -> std::io::Result<()> {
    let dir = home.join(".ssh");
    match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

/// Lines of `add` missing from `existing` (compared trimmed), appended.
pub fn merged(existing: &str, add: &str) -> String {
    let have: std::collections::HashSet<&str> = existing.lines().map(str::trim).collect();
    let mut out = existing.to_owned();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    let mut seen = std::collections::HashSet::new();
    for l in add.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if !have.contains(l) && seen.insert(l) {
            out.push_str(l);
            out.push('\n');
        }
    }
    out
}

/// The helper body (`fleet-agent user-keys <op> <home>`), run as the user.
pub fn run_helper(op: KeysOp, home: &Path, input: &[u8]) -> std::io::Result<Vec<u8>> {
    if !home.is_absolute() || input.len() > MAX_KEYS_FILE {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    let path = keys_path(home);
    let read = || match std::fs::read(&path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    };
    match op {
        KeysOp::Get => Ok(match read()? {
            Some(mut b) => {
                b.truncate(MAX_KEYS_FILE);
                let mut out = vec![b'1'];
                out.extend(b);
                out
            }
            None => vec![b'0'],
        }),
        KeysOp::Set => {
            ensure_ssh_dir(home)?;
            fsutil::write_atomic(&path, input, 0o600)?;
            Ok(Vec::new())
        }
        KeysOp::Remove => match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(Vec::new()),
        },
        KeysOp::Merge => {
            ensure_ssh_dir(home)?;
            let old = read()?.unwrap_or_default();
            let old = String::from_utf8_lossy(&old);
            let new = merged(&old, &String::from_utf8_lossy(input));
            if new != old {
                fsutil::write_atomic(&path, new.as_bytes(), 0o600)?;
            } else if let Ok(md) = std::fs::metadata(&path) {
                // Keep sshd's StrictModes happy even if nothing changed.
                if md.permissions().mode() & 0o022 != 0 {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
                }
            }
            Ok(Vec::new())
        }
    }
}

/// `fleet-agent user-keys <op> <home>`: stdin in, stdout out.
pub fn helper_main(op: KeysOp, home: &Path) -> std::io::Result<()> {
    let mut input = Vec::new();
    std::io::Read::read_to_end(
        &mut std::io::Read::take(std::io::stdin(), MAX_KEYS_FILE as u64 + 1),
        &mut input,
    )?;
    let out = run_helper(op, home, &input)?;
    std::io::stdout().write_all(&out)
}

/// Access to users' `~/.ssh/authorized_keys`.
pub trait UserKeys {
    fn call(&self, user: &UserEntry, op: KeysOp, input: &[u8]) -> Result<Vec<u8>, OpError>;

    fn get(&self, user: &UserEntry) -> Result<Option<Vec<u8>>, OpError> {
        let out = self.call(user, KeysOp::Get, &[])?;
        match out.split_first() {
            Some((b'1', rest)) => Ok(Some(rest.to_vec())),
            Some((b'0', [])) => Ok(None),
            _ => Err(OpError::internal("user-keys helper: bad answer")),
        }
    }

    fn set(&self, user: &UserEntry, content: Option<&[u8]>) -> Result<(), OpError> {
        match content {
            Some(c) => self.call(user, KeysOp::Set, c).map(drop),
            None => self.call(user, KeysOp::Remove, &[]).map(drop),
        }
    }

    fn merge(&self, user: &UserEntry, lines: &str) -> Result<(), OpError> {
        self.call(user, KeysOp::Merge, lines.as_bytes()).map(drop)
    }
}

/// How [`UserKeys`] runs: through `setpriv` as the user (production), or
/// in this process (tests, development roots).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UserKeysMode {
    #[default]
    AsUser,
    Direct,
}

/// Production: the helper as the user, through `runner`.
pub struct AsUser<'a>(pub &'a dyn CommandRunner);

/// The helper command for `user`.
pub fn helper_spec(user: &UserEntry, op: KeysOp, input: &[u8]) -> CommandSpec {
    CommandSpec::new(SETPRIV)
        .args(fleet_ops::shell::setpriv_args(user.uid, user.gid, &[]))
        .args([
            "--".to_owned(),
            AGENT_BIN.to_owned(),
            "user-keys".to_owned(),
            op.as_str().to_owned(),
            user.home.clone(),
        ])
        .stdin(input.to_vec())
        .output_cap(MAX_KEYS_FILE + 1)
        .timeout(Duration::from_secs(10))
}

impl UserKeys for AsUser<'_> {
    fn call(&self, user: &UserEntry, op: KeysOp, input: &[u8]) -> Result<Vec<u8>, OpError> {
        let out = self
            .0
            .run_blocking(helper_spec(user, op, input))
            .map_err(|e| OpError::internal(format!("user-keys helper: {e}")))?;
        if !out.success() {
            return Err(OpError::new(ErrorCode::Internal).with_detail(format!(
                "user-keys helper for uid {} exited {:?}",
                user.uid, out.code
            )));
        }
        Ok(out.stdout)
    }
}

/// Tests: the helper body in this process.
pub struct Direct;

impl UserKeys for Direct {
    fn call(&self, user: &UserEntry, op: KeysOp, input: &[u8]) -> Result<Vec<u8>, OpError> {
        run_helper(op, Path::new(&user.home), input)
            .map_err(|e| OpError::internal(format!("user keys: {e}")))
    }
}

/// [`UserKeys`] for `mode`.
pub fn user_keys(mode: UserKeysMode, runner: &dyn CommandRunner) -> Box<dyn UserKeys + '_> {
    match mode {
        UserKeysMode::AsUser => Box::new(AsUser(runner)),
        UserKeysMode::Direct => Box::new(Direct),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_appends_missing_lines_once() {
        assert_eq!(merged("", "a\nb\na\n"), "a\nb\n");
        assert_eq!(merged("a", "a\n c \n"), "a\nc\n");
        assert_eq!(merged("x\n", ""), "x\n");
    }

    #[test]
    fn helper_round_trip() {
        let d = tempfile::tempdir().unwrap();
        let u = UserEntry {
            uid: 1000,
            gid: 1000,
            home: d.path().to_string_lossy().into_owned(),
        };
        assert_eq!(Direct.get(&u).unwrap(), None);
        Direct.merge(&u, "ssh-ed25519 AAAA k1\n").unwrap();
        Direct
            .merge(&u, "ssh-ed25519 AAAA k1\nssh-ed25519 BBBB k2\n")
            .unwrap();
        let got = Direct.get(&u).unwrap().unwrap();
        assert_eq!(got, b"ssh-ed25519 AAAA k1\nssh-ed25519 BBBB k2\n");
        let md = std::fs::metadata(d.path().join(".ssh/authorized_keys")).unwrap();
        assert_eq!(md.permissions().mode() & 0o777, 0o600);
        Direct.set(&u, Some(b"old\n")).unwrap();
        assert_eq!(Direct.get(&u).unwrap().unwrap(), b"old\n");
        Direct.set(&u, None).unwrap();
        assert_eq!(Direct.get(&u).unwrap(), None);
        assert!(run_helper(KeysOp::Get, Path::new("rel"), &[]).is_err());
    }

    #[test]
    fn helper_runs_as_the_user_through_setpriv() {
        let u = UserEntry {
            uid: 1001,
            gid: 1002,
            home: "/home/bob".into(),
        };
        let s = helper_spec(&u, KeysOp::Merge, b"k\n");
        assert_eq!(s.program, SETPRIV);
        let args: Vec<String> = s
            .args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            &args[..3],
            ["--reuid=1001", "--regid=1002", "--clear-groups"]
        );
        assert!(args.contains(&"--reset-env".to_owned()));
        assert_eq!(
            &args[args.len() - 5..],
            ["--", AGENT_BIN, "user-keys", "merge", "/home/bob"]
        );
        assert_eq!(s.stdin.as_deref(), Some(&b"k\n"[..]));
    }
}
