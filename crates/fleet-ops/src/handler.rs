//! [`OpHandler`], its outputs and errors, and the [`Registry`].
//!
//! Exec's pipeline per command (design §5.6): verify → policy →
//! [`OpHandler::supports`] + [`OpHandler::validate`] (no side effects) →
//! consume the nonce → audit intent → [`OpHandler::handle`] → audit result
//! → signed receipt (or stream seals). Everything up to the first `.await`
//! inside `handle` runs without yielding, so no other command interleaves
//! between validation and the start of execution.

use crate::ctx::SysCtx;
use crate::runner::RunError;
use fleet_crypto::verify::VerifiedCommand;
use fleet_proto::{ErrorCode, Op, Payload, RootApproval};
use std::borrow::Cow;
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::time::Duration;

/// Exec is single-threaded, so nothing here is `Send`.
pub type LocalBoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// How the command arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invocation {
    /// `Request` → one `Response`.
    Request,
    /// `StreamOpen` → `StreamData`… `StreamEnd`.
    Stream,
}

/// What a handler knows about the command beyond its `Op`.
#[derive(Debug, Clone)]
pub struct OpMeta {
    /// Verified envelope: body (actor, `expected_version`, …), device, key,
    /// approval leaf, command hash.
    pub command: VerifiedCommand,
    /// The approval exactly as sent (`policy.update` stores it).
    pub approval: Option<RootApproval>,
    /// Audit intent sequence number: `None` during [`OpHandler::validate`]
    /// (no intent yet), `Some` in [`OpHandler::handle`]. Unique per agent
    /// database, so it names transient scopes (`fleet-op-<seq>`).
    pub audit_seq: Option<u64>,
    /// Wall clock when exec took the command.
    pub now_ms: u64,
    pub invocation: Invocation,
}

impl OpMeta {
    /// Id for transient units of this operation (the audit intent seq).
    pub fn op_id(&self) -> Option<u64> {
        self.audit_seq
    }
}

/// A protocol error code plus optional detail for the **local** log only.
/// Only the code goes on the wire (design §6.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpError {
    code: ErrorCode,
    detail: Option<Cow<'static, str>>,
}

impl OpError {
    pub const fn new(code: ErrorCode) -> Self {
        Self { code, detail: None }
    }

    pub fn with_detail(mut self, detail: impl Into<Cow<'static, str>>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// `Internal` with a log detail.
    pub fn internal(detail: impl std::fmt::Display) -> Self {
        Self::new(ErrorCode::Internal).with_detail(detail.to_string())
    }

    pub fn code(&self) -> ErrorCode {
        self.code
    }

    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

impl From<ErrorCode> for OpError {
    fn from(code: ErrorCode) -> Self {
        Self::new(code)
    }
}

impl From<OpError> for ErrorCode {
    fn from(e: OpError) -> Self {
        e.code
    }
}

impl From<RunError> for OpError {
    fn from(e: RunError) -> Self {
        let code = match e {
            RunError::Timeout => ErrorCode::Timeout,
            _ => ErrorCode::Internal,
        };
        Self::new(code).with_detail(e.to_string())
    }
}

impl std::fmt::Display for OpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.detail {
            Some(d) => write!(f, "{:?}: {d}", self.code),
            None => write!(f, "{:?}", self.code),
        }
    }
}

impl std::error::Error for OpError {}

/// Items of a streaming operation (metrics, log follow, long searches).
/// Owns everything it needs (`'static`): it outlives the `handle` call.
pub trait OpStream {
    /// The next item; `None` ends the stream successfully, `Some(Err)` ends
    /// it with that code. Dropping the future (cancel, client gone) must be
    /// harmless.
    fn next(&mut self) -> LocalBoxFuture<'_, Option<Result<Payload, OpError>>>;

    /// Only the newest item matters (metrics): when the client can't keep
    /// up, exec drops items instead of ending the stream.
    fn latest_only(&self) -> bool {
        false
    }
}

pub enum OpOutput {
    Payload(Payload),
    Stream(Box<dyn OpStream>),
}

impl std::fmt::Debug for OpOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpOutput::Payload(p) => f.debug_tuple("Payload").field(p).finish(),
            OpOutput::Stream(_) => f.write_str("Stream(..)"),
        }
    }
}

/// One typed operation (or a family sharing a tag range).
pub trait OpHandler {
    /// Whether `op` can be run this way. Checked before the nonce is
    /// consumed; a mismatch is `Unsupported`. Default: requests only.
    fn supports(&self, _op: &Op, invocation: Invocation) -> bool {
        invocation == Invocation::Request
    }

    /// Argument and precondition checks, before the nonce is consumed and
    /// the audit intent written, so a refused command burns nothing. Must
    /// not change anything.
    fn validate(&self, _ctx: &SysCtx, _op: &Op, _meta: &OpMeta) -> Result<(), OpError> {
        Ok(())
    }

    /// Conditional Elevated from facts the arguments don't carry (design
    /// §4.2): `cron.set` for a user in a privileged group, `compose.deploy`
    /// using a deny-listed feature. Exec asks only for ops where
    /// `Op::may_escalate()` holds (so the Mac knows when to run the same
    /// check), right after [`validate`](Self::validate); `true` without a
    /// valid root approval on the command is `ApprovalRequired`. Must not
    /// change anything. Helpers: [`crate::escalation`].
    fn requires_elevated(&self, _ctx: &SysCtx, _op: &Op, _meta: &OpMeta) -> Result<bool, OpError> {
        Ok(false)
    }

    /// Runs the operation. For `Invocation::Stream` return
    /// [`OpOutput::Stream`]; for requests [`OpOutput::Payload`] (exec
    /// answers a mismatch with `Internal`).
    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        op: &'a Op,
        meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>>;
}

/// Op tag → handler. Tags are the wire tags (`Op::tag`), so every variant
/// the other lanes add is dispatched without touching exec.
#[derive(Default, Clone)]
pub struct Registry {
    handlers: BTreeMap<u16, Rc<dyn OpHandler>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every generic handler in this crate.
    pub fn with_generic() -> Self {
        let mut r = Self::new();
        r.register(
            fleet_proto::op::tag::SYSTEM_INFO,
            Rc::new(crate::system::SystemInfoHandler),
        );
        crate::packages::register(&mut r);
        crate::logs::register(&mut r);
        crate::firewall::register(&mut r);
        crate::files::register(&mut r);
        crate::search::register(&mut r);
        // Exec re-registers `logins.query` with its roster resolver.
        crate::security::register(&mut r, Rc::new(crate::security::NoResolver));
        crate::cron::register(&mut r);
        // Lazy socket connection: fine on servers without Docker. Exec
        // re-registers with its own `api` to share it with `events::watch`.
        crate::docker::register(&mut r, Rc::new(crate::docker::BollardDocker::new()));
        // Null sink here; exec re-registers with its event log.
        crate::users::register(&mut r, Rc::new(crate::security::NullSink));
        crate::mesh::register(&mut r);
        // Refuses everyone; exec re-registers with its policy.
        crate::shell::register(&mut r, Rc::new(crate::shell::DenyAll));
        r
    }

    /// Registers (or replaces, returning the old one) the handler for `tag`.
    pub fn register(&mut self, tag: u16, h: Rc<dyn OpHandler>) -> Option<Rc<dyn OpHandler>> {
        self.handlers.insert(tag, h)
    }

    /// `None` for tags without a handler and for `Op::Unknown` (never run).
    pub fn get(&self, op: &Op) -> Option<Rc<dyn OpHandler>> {
        if matches!(op, Op::Unknown { .. }) {
            return None;
        }
        self.handlers.get(&op.tag()).cloned()
    }

    pub fn tags(&self) -> impl Iterator<Item = u16> + '_ {
        self.handlers.keys().copied()
    }
}

/// A finite stream from a list, optionally paced (tests, fixed results).
pub struct VecStream {
    items: VecDeque<Result<Payload, OpError>>,
    interval: Option<Duration>,
    latest_only: bool,
}

impl VecStream {
    pub fn new(items: impl IntoIterator<Item = Result<Payload, OpError>>) -> Self {
        Self {
            items: items.into_iter().collect(),
            interval: None,
            latest_only: false,
        }
    }

    /// Waits this long before each item.
    pub fn interval(mut self, d: Duration) -> Self {
        self.interval = Some(d);
        self
    }

    pub fn latest_only(mut self) -> Self {
        self.latest_only = true;
        self
    }
}

impl OpStream for VecStream {
    fn next(&mut self) -> LocalBoxFuture<'_, Option<Result<Payload, OpError>>> {
        Box::pin(async move {
            if let Some(d) = self.interval {
                tokio::time::sleep(d).await;
            }
            self.items.pop_front()
        })
    }

    fn latest_only(&self) -> bool {
        self.latest_only
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_dispatch_by_tag() {
        let r = Registry::with_generic();
        assert!(r.get(&Op::SystemInfo).is_some());
        assert!(r.get(&Op::AgentHealth).is_none());
        assert!(r.get(&Op::Unknown { tag: 0 }).is_none());
        use fleet_proto::op::tag;
        let tags: Vec<_> = r.tags().collect();
        for t in [
            tag::SYSTEM_INFO,
            tag::JOURNAL_QUERY,
            tag::JOURNAL_FOLLOW,
            tag::LOGFILE_TAIL,
            tag::LOGINS_QUERY,
            tag::PORTS_LIST,
            tag::CERTS_LIST,
        ] {
            assert!(tags.contains(&t), "missing tag {t}");
        }
    }

    #[test]
    fn errors_map_to_codes() {
        let e: OpError = RunError::Timeout.into();
        assert_eq!(e.code(), ErrorCode::Timeout);
        let e = OpError::internal("disk on fire");
        assert_eq!(ErrorCode::from(e.clone()), ErrorCode::Internal);
        assert_eq!(e.detail(), Some("disk on fire"));
        assert_eq!(e.to_string(), "Internal: disk on fire");
    }

    #[test]
    fn vec_stream_yields_then_ends() {
        let mut s = VecStream::new([Ok(Payload::Empty), Err(ErrorCode::Busy.into())]);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            assert_eq!(s.next().await, Some(Ok(Payload::Empty)));
            assert_eq!(s.next().await, Some(Err(OpError::new(ErrorCode::Busy))));
            assert_eq!(s.next().await, None);
        });
    }
}
