//! `packages` group argument types (tags 500–599).

use crate::v1::args::{DebPackageName, DebVersion};
use serde::{Deserialize, Serialize};

/// `pkg.upgrade` scope (design §2.5).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UpgradeScope {
    All,
    SecurityOnly,
    /// Only these installed packages (1..=256).
    Packages(Vec<DebPackageName>),
}

/// A package to install, optionally pinned to a version.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PkgSpec {
    pub name: DebPackageName,
    pub version: Option<DebVersion>,
}
