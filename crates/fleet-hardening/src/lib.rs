//! Provisioning and the hardening audit (design §9).
//!
//! - [`profile`]: the built-in Baseline/Strict profiles and role manifests
//!   (`profiles/*.toml`, compiled in) and operator TOML (design §9.2,
//!   strict schema, extends a built-in only) resolved into one
//!   [`profile::Resolved`].
//! - [`module`]: the module contract (design §9.3): `check` → [`Status`],
//!   `plan` → human-readable [`Change`]s, `apply(plan)` → [`Applied`],
//!   `revert(applied)`. Modules are idempotent: after `apply` the next
//!   `plan` is empty.
//! - [`modules`]: every Baseline, Strict and role module.
//! - [`facts`]: what modules read from the server that isn't a file
//!   (unit states, `ssh -Q kex`, `auditctl -s`, the firewall table).
//! - [`engine`]: runs a profile's modules: check + score, plan + plan hash,
//!   apply in phase order (design §9.1).
//! - [`handler`]: `profile.check/plan/apply` and `audit.run`.
//! - [`revert`]: the auto-revert module for `ChangeKind::Profile`
//!   (design §4.10): every file the profile's modules may write plus the
//!   firewall table.
//! - [`cloudinit`]: cloud-init export (design §9.7), pure.
//!
//! No shell anywhere: every command is a fixed absolute path plus argv
//! through `fleet_ops::CommandRunner`; files go through `fleet_ops::fswrite`.
#![forbid(unsafe_code)]

pub mod cloudinit;
pub mod engine;
pub mod exec;
pub mod facts;
pub mod handler;
pub mod module;
pub mod modules;
pub mod profile;
pub mod revert;
#[cfg(test)]
mod tests;

pub use module::{Action, Applied, Change, Cmd, Ctx, Module, Phase, Status};

use fleet_ops::{Registry, Reverters};
use fleet_proto::payload::ChangeKind;
use std::rc::Rc;

/// Registers `profile.check/plan/apply` and `audit.run`.
pub fn register(r: &mut Registry) {
    handler::register(r);
}

/// `Reverters::with_generic()` plus [`revert::ProfileRevert`]. Exec and the
/// `fleet-agent revert` process build theirs with this.
pub fn reverters() -> Reverters {
    let mut r = Reverters::with_generic();
    r.register(ChangeKind::Profile, Rc::new(revert::ProfileRevert));
    r
}
