//! Typed operation framework used by `fleet-exec` (design §4.1, §4.2).
//!
//! - [`SysCtx`]: the injectable environment every handler runs against —
//!   filesystem root, child-process runner, clock, `/proc` reader — so ops
//!   are tested against a temp directory and canned command output.
//! - [`OpHandler`]: one typed operation; returns a [`Payload`] or an
//!   [`OpStream`]. [`Registry`] maps op tags to handlers; exec dispatches
//!   through it after verification, policy and the audit intent.
//! - [`runner`]: fixed absolute binary paths plus argument vectors, env
//!   cleared, timeout and output cap. Never a shell.
//! - [`scope`]: `systemd-run --scope` wrapping for long-running children.
//!
//! Generic handlers live here (`system.info`, [`logs`], the stateless
//! [`security`] ops); stateful security services (bans, integrity
//! baseline) are built here and registered by exec. Handlers bound to exec's
//! state (roster, policy, veto, `agent.health`) are registered by exec
//! behind the same trait.
//!
//! [`Payload`]: fleet_proto::Payload
#![forbid(unsafe_code)]

pub mod ctx;
pub mod handler;
pub mod logs;
pub mod procfs;
pub mod runner;
pub mod scope;
pub mod security;
pub mod system;
#[cfg(test)]
pub(crate) mod test_util;

pub use ctx::{Clock, ManualClock, SysCtx, SystemClock};
pub use handler::{
    Invocation, LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, OpStream, Registry, VecStream,
};
pub use procfs::Procfs;
pub use runner::{CommandOutput, CommandRunner, CommandSpec, FakeRunner, RunError, SystemRunner};
