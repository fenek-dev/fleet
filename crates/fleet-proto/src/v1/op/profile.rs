//! `profile` group argument types (tags 1100–1199).

use crate::v1::args::{ArgError, ModuleId, ProfileToml, at_most};
use serde::{Deserialize, Serialize};

/// Built-in profile level (design §9.4, §9.5), used by `audit.run`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProfileLevel {
    Baseline,
    Strict,
}

/// A provisioning profile (design §9.2) plus the modules to run.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProfileSpec {
    /// The profile TOML, parsed and validated by `fleet-hardening`.
    pub toml: ProfileToml,
    /// Run only these modules (the provisioning phases of design §9.1, or
    /// a one-click audit fix); empty means every module. At most 128.
    pub only: Vec<ModuleId>,
}

impl ProfileSpec {
    pub fn validate(&self) -> Result<(), ArgError> {
        at_most(&self.only, 128, "profile modules")
    }
}
