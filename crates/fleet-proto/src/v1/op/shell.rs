//! `shell` group argument types (tags 1600–1699).

use crate::v1::args::{AbsPath, ArgError, ShellCommand, UserName, ensure};
use serde::{Deserialize, Serialize};

/// `shell.exec` (design §4.2): policy-gated, off by default, always
/// Elevated. Runs `/bin/sh -c <command>` as `user` (who must be in the
/// policy's `shell_exec_users`); the full command goes into the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShellExec {
    pub user: UserName,
    pub command: ShellCommand,
    pub cwd: Option<AbsPath>,
    /// 1..=3600 seconds.
    pub timeout_s: u32,
    /// Combined stdout+stderr cap, 1..=[`ShellExec::MAX_OUTPUT`] bytes.
    pub output_cap: u32,
}

impl ShellExec {
    pub const MAX_OUTPUT: u32 = 512 * 1024;

    pub fn validate(&self) -> Result<(), ArgError> {
        ensure((1..=3600).contains(&self.timeout_s), "shell timeout")?;
        ensure(
            (1..=Self::MAX_OUTPUT).contains(&self.output_cap),
            "output cap",
        )
    }
}
