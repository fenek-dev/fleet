//! `profile` group argument types (tags 1100–1199).

use crate::v1::args::{ArgError, ModuleId, ProfileToml, SudoPasswordHash, at_most, ensure};
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

/// Which provisioning phase a `profile.apply` runs (design §9.1). The
/// plan hash always covers the whole spec (`ProfileSpec::only`), so the
/// Mac plans once and applies phase by phase (re-planning in between);
/// the phase only picks which modules of that plan run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProfilePhase {
    /// Phase 1: admin user, its shell files, sudo. No auto-revert (it
    /// can't lock the operator out; the Mac proves admin login next).
    Accounts,
    /// Phase 2: sshd hardening and the firewall
    /// ([`ProfilePhase::ACCESS_MODULES`]), under auto-revert.
    Access,
    /// Phase 3: everything else (packages, sysctl, roles, …). No
    /// auto-revert; exec allows it a long timeout.
    System,
    /// Every module in apply order; auto-revert when an access module is
    /// in scope.
    All,
}

impl ProfilePhase {
    /// Modules that can cut SSH access, so they run only under
    /// auto-revert. `fleet-hardening` checks its phase table against this.
    pub const ACCESS_MODULES: [&'static str; 2] = ["ssh.hardening", "firewall.baseline"];

    pub fn is_access_module(id: &str) -> bool {
        Self::ACCESS_MODULES.contains(&id)
    }

    /// Whether applying `spec` in this phase may run an access module, and
    /// so must run under auto-revert (`Op::auto_revert`).
    pub fn arms_auto_revert(self, spec: &ProfileSpec) -> bool {
        match self {
            ProfilePhase::Access => true,
            ProfilePhase::All => {
                spec.only.is_empty() || spec.only.iter().any(|m| Self::is_access_module(m.as_str()))
            }
            ProfilePhase::Accounts | ProfilePhase::System => false,
        }
    }

    /// The phase may set the admin's sudo password (`admin.user`).
    pub fn sets_password(self) -> bool {
        matches!(self, ProfilePhase::Accounts | ProfilePhase::All)
    }

    /// Cross-field rules of `profile.apply`: an `only` list must fit the
    /// phase as far as access modules go (the agent checks the rest of
    /// the phase table), and a sudo password hash needs a phase that
    /// runs `admin.user` and must not be the redacted audit form.
    pub fn validate(
        self,
        spec: &ProfileSpec,
        password_hash: Option<&SudoPasswordHash>,
    ) -> Result<(), ArgError> {
        let access = |m: &ModuleId| Self::is_access_module(m.as_str());
        match self {
            ProfilePhase::Access => ensure(spec.only.iter().all(access), "phase modules")?,
            ProfilePhase::Accounts | ProfilePhase::System => {
                ensure(!spec.only.iter().any(access), "phase modules")?;
            }
            ProfilePhase::All => {}
        }
        if let Some(h) = password_hash {
            ensure(self.sets_password(), "password phase")?;
            ensure(!h.is_redacted(), "sudo password hash")?;
        }
        Ok(())
    }
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
