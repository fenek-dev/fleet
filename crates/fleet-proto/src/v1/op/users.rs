//! `users` group argument types (tags 800–899).

use serde::{Deserialize, Serialize};

/// Login shell for `users.create`: a closed set of fixed paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LoginShell {
    Bash,
    Sh,
    Nologin,
}

impl LoginShell {
    pub fn path(self) -> &'static str {
        match self {
            LoginShell::Bash => "/bin/bash",
            LoginShell::Sh => "/bin/sh",
            LoginShell::Nologin => "/usr/sbin/nologin",
        }
    }
}
