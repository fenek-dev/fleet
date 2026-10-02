//! Hand-rolled argv parsing.
//!
//! `fleet-agent [--root <dir>] <mode> ...`. `--root` re-roots every path
//! (`Paths::under`) for development and tests.

use crate::bridge::BridgeMode;
use crate::install::InstallMode;
use crate::pending::ChangeId;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallArgs {
    pub genesis: PathBuf,
    pub policy: PathBuf,
    pub server_id: String,
    pub admin_user: Option<String>,
    pub mode: InstallMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Gate,
    Exec,
    Bridge(BridgeMode),
    Install(InstallArgs),
    /// `keys`: prints `noise_static=` / `signing_key=` from the key files
    /// only (never opens the state database a running exec locks).
    Keys,
    Revert(ChangeId),
    /// `uninstall [--ssh-restored] [--keep-audit] [--remove-firewall]`.
    Uninstall(crate::uninstall::UninstallOpts),
    /// `user-keys <op> <home>`: the helper run as a user (`userkeys`).
    UserKeys(crate::userkeys::KeysOp, PathBuf),
    /// `version`: prints the version and target.
    Version,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cli {
    pub root: Option<PathBuf>,
    pub mode: Mode,
}

/// Fixed usage text; printed on any parse error.
pub const USAGE: &str = "usage: fleet-agent [--root <dir>] gate | exec \
     | bridge [--recovery | --monitor] \
     | install --genesis <file> --policy <file> --server-id <id> [--admin-user <name>] \
       [--keep-state | --replace] | keys \
     | revert <change-id> \
     | uninstall [--ssh-restored] [--keep-audit] [--remove-firewall] \
     | user-keys get|set|merge|remove <home> | version";

/// Parses argv without the program name, including a leading `--root`.
pub fn parse_cli<S: AsRef<str>>(args: &[S]) -> Option<Cli> {
    let a: Vec<&str> = args.iter().map(AsRef::as_ref).collect();
    match a.as_slice() {
        ["--root", dir, rest @ ..] => Some(Cli {
            root: Some(PathBuf::from(dir)),
            mode: parse(rest)?,
        }),
        rest => Some(Cli {
            root: None,
            mode: parse(rest)?,
        }),
    }
}

/// Parses the mode and its arguments.
pub fn parse<S: AsRef<str>>(args: &[S]) -> Option<Mode> {
    let a: Vec<&str> = args.iter().map(AsRef::as_ref).collect();
    match a.as_slice() {
        ["gate"] => Some(Mode::Gate),
        ["exec"] => Some(Mode::Exec),
        ["bridge", rest @ ..] => Some(Mode::Bridge(bridge_mode(rest))),
        ["install", flags @ ..] => parse_install(flags).map(Mode::Install),
        ["keys"] => Some(Mode::Keys),
        ["revert", id] => ChangeId::parse(id).map(Mode::Revert),
        ["uninstall", flags @ ..] => {
            crate::uninstall::UninstallOpts::parse(flags).map(Mode::Uninstall)
        }
        ["user-keys", op, home] => Some(Mode::UserKeys(
            crate::userkeys::KeysOp::parse(op)?,
            PathBuf::from(home),
        )),
        ["version"] => Some(Mode::Version),
        _ => None,
    }
}

/// The bridge mode from its flags. A restricted key's forced command
/// (`authorized_keys`) fixes the flag; anything else on the command line
/// is ignored (the bridge never reads `SSH_ORIGINAL_COMMAND` either), and
/// the most restricted flag present wins, so extra arguments can never
/// widen a session.
fn bridge_mode(flags: &[&str]) -> BridgeMode {
    if flags.contains(&"--monitor") {
        BridgeMode::Monitor
    } else if flags.contains(&"--recovery") {
        BridgeMode::Recovery
    } else {
        BridgeMode::Normal
    }
}

fn parse_install(flags: &[&str]) -> Option<InstallArgs> {
    let (mut genesis, mut policy, mut server_id, mut admin_user) = (None, None, None, None);
    let mut mode = InstallMode::Fresh;
    let mut it = flags.iter().copied().peekable();
    while let Some(flag) = it.next() {
        let new_mode = match flag {
            "--keep-state" => Some(InstallMode::KeepState),
            "--replace" => Some(InstallMode::Replace),
            _ => None,
        };
        if let Some(m) = new_mode {
            if mode != InstallMode::Fresh {
                return None;
            }
            mode = m;
            continue;
        }
        let value = it.next()?;
        let slot = match flag {
            "--genesis" => &mut genesis,
            "--policy" => &mut policy,
            "--server-id" => &mut server_id,
            "--admin-user" => &mut admin_user,
            _ => return None,
        };
        if slot.replace(value.to_owned()).is_some() {
            return None;
        }
    }
    Some(InstallArgs {
        genesis: genesis?.into(),
        policy: policy?.into(),
        server_id: server_id?,
        admin_user,
        mode,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: [&str; 6] = ["--genesis", "g", "--policy", "p", "--server-id", "srv_x"];

    fn install(extra: &[&str]) -> Option<InstallArgs> {
        let mut a = vec!["install"];
        a.extend(BASE);
        a.extend(extra);
        match parse(&a)? {
            Mode::Install(i) => Some(i),
            _ => None,
        }
    }

    #[test]
    fn install_modes() {
        assert_eq!(install(&[]).unwrap().mode, InstallMode::Fresh);
        assert_eq!(
            install(&["--keep-state"]).unwrap().mode,
            InstallMode::KeepState
        );
        assert_eq!(
            install(&["--admin-user", "ops", "--replace"]).unwrap().mode,
            InstallMode::Replace
        );
        assert!(install(&["--keep-state", "--replace"]).is_none());
        assert!(install(&["--admin-user"]).is_none());
        assert!(install(&["--bogus", "x"]).is_none());
    }

    #[test]
    fn keys_mode() {
        assert_eq!(parse(&["keys"]), Some(Mode::Keys));
        assert!(parse(&["keys", "x"]).is_none());
    }
}
