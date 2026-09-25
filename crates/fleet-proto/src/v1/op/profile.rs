//! `profile` group argument types (tags 1100–1199).

use crate::v1::args::{ArgError, ModuleId, ProfileToml, at_most, ensure};
use serde::{Deserialize, Serialize};

/// Built-in profile level (design §9.4, §9.5), used by `audit.run`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProfileLevel {
    Baseline,
    Strict,
}

/// Built-in role add-on (design §9.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProfileRole {
    Docker,
    Web,
    Game,
}

/// Which profile to run: one shipped with the agent (reviewed with the
/// release) or operator-written TOML. `profile.apply` of a custom profile
/// is Elevated (design §4.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProfileSource {
    /// The agent's own `baseline.toml`/`strict.toml` plus role add-ons
    /// (each at most once).
    Builtin {
        level: ProfileLevel,
        roles: Vec<ProfileRole>,
    },
    /// The profile TOML, parsed and validated by `fleet-hardening`.
    Custom(ProfileToml),
}

/// A provisioning profile (design §9.2) plus the modules to run.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProfileSpec {
    pub source: ProfileSource,
    /// Run only these modules (the provisioning phases of design §9.1, or
    /// a one-click audit fix); empty means every module. At most 128.
    pub only: Vec<ModuleId>,
}

impl ProfileSpec {
    /// Operator-written TOML rather than a built-in profile.
    pub fn is_custom(&self) -> bool {
        matches!(self.source, ProfileSource::Custom(_))
    }

    pub fn validate(&self) -> Result<(), ArgError> {
        if let ProfileSource::Builtin { roles, .. } = &self.source {
            let mut r = roles.clone();
            r.sort();
            r.dedup();
            ensure(r.len() == roles.len(), "duplicate profile role")?;
        }
        at_most(&self.only, 128, "profile modules")
    }
}
