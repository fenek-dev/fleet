//! Hand-rolled argv parsing.
//!
//! `fleet-agent [--root <dir>] <mode> ...`. `--root` re-roots every path
//! (`Paths::under`) for development and tests.

use crate::bridge::BridgeMode;
use crate::pending::ChangeId;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallArgs {
    pub genesis: PathBuf,
    pub policy: PathBuf,
    pub server_id: String,
    pub admin_user: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Gate,
    Exec,
    Bridge(BridgeMode),
    Install(InstallArgs),
    Revert(ChangeId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cli {
    pub root: Option<PathBuf>,
    pub mode: Mode,
}

/// Fixed usage text; printed on any parse error.
pub const USAGE: &str = "usage: fleet-agent [--root <dir>] gate | exec | bridge [--recovery] \
     | install --genesis <file> --policy <file> --server-id <id> [--admin-user <name>] \
     | revert <change-id>";

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
        ["bridge"] => Some(Mode::Bridge(BridgeMode::Normal)),
        ["bridge", "--recovery"] => Some(Mode::Bridge(BridgeMode::Recovery)),
        ["install", flags @ ..] => parse_install(flags).map(Mode::Install),
        ["revert", id] => ChangeId::parse(id).map(Mode::Revert),
        _ => None,
    }
}

fn parse_install(flags: &[&str]) -> Option<InstallArgs> {
    let (mut genesis, mut policy, mut server_id, mut admin_user) = (None, None, None, None);
    let mut it = flags.chunks(2);
    for pair in it.by_ref() {
        let [flag, value] = pair else { return None };
        let slot = match *flag {
            "--genesis" => &mut genesis,
            "--policy" => &mut policy,
            "--server-id" => &mut server_id,
            "--admin-user" => &mut admin_user,
            _ => return None,
        };
        if slot.replace((*value).to_owned()).is_some() {
            return None;
        }
    }
    Some(InstallArgs {
        genesis: genesis?.into(),
        policy: policy?.into(),
        server_id: server_id?,
        admin_user,
    })
}
