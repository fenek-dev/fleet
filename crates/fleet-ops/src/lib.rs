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
//! Generic handlers live here (`system.info`, [`packages`], [`logs`], the
//! stateless [`security`] ops). [`services`] needs a D-Bus connection, so
//! exec registers it with [`services::register`]; stateful security
//! services (bans, integrity baseline) are built here and registered by
//! exec. Handlers bound to exec's
//! state (roster, policy, veto, `agent.health`) are registered by exec
//! behind the same trait.
//!
//! [`Payload`]: fleet_proto::Payload
#![forbid(unsafe_code)]

pub mod allowed;
pub mod compose;
pub mod confighist;
pub mod cron;
pub mod ctx;
pub mod docker;
pub mod escalation;
pub mod files;
pub mod firewall;
pub mod fswrite;
pub mod game;
pub mod handler;
pub mod health;
pub mod logs;
pub mod mesh;
pub mod nftlock;
pub mod packages;
pub mod procfs;
pub mod revertible;
pub mod runner;
pub mod scope;
pub mod search;
pub mod security;
pub mod services;
pub mod shell;
pub mod system;
pub mod telemetry;
#[cfg(test)]
pub(crate) mod testutil;
pub mod users;

pub use allowed::open_allowed;
pub use ctx::{Clock, ManualClock, SysCtx, SystemClock};
pub use handler::{
    Invocation, LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, OpStream, Registry, VecStream,
};
pub use procfs::Procfs;
pub use revertible::{Reverters, Revertible};
pub use runner::{CommandOutput, CommandRunner, CommandSpec, FakeRunner, RunError, SystemRunner};
