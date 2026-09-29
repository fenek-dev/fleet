//! MCP socket host for the app (design §5.10, §8).
//!
//! Swift owns `~/Library/Application Support/Fleet/mcp.sock` (mode 0600,
//! directory 0700 and owned by the user): it accepts connections (at most
//! 8 at once), checks with `LOCAL_PEERTOKEN` that the peer is our own
//! signed `fleetctl`, reads and validates the code signature of its parent
//! process (with a pid-reuse check), and opens an [`McpConnection`] with
//! that [`McpPeerRow`]. It then passes each frame body (after checking the
//! 4-byte length against [`mcp_max_frame`]) to [`McpConnection::handle`]
//! and writes back the returned frame. Everything else — pause, pairing,
//! lock, rate limit, approvals, validation, redaction — happens in
//! `fleet_core::mcp_host`.
//!
//! Prompts reach Swift through [`McpDelegate`]; the operator's answer comes
//! back with `mcp_resolve_prompt`, echoing the prompt's digest and saying
//! whether Touch ID was taken (required for pairing and non-Elevated
//! approvals; Elevated runs and escalations then get the root key's Touch
//! ID).

use crate::api::{FleetCore, lock};
use crate::types::{FleetError, SessionKind};
use fleet_core::autorevert::{self, ConfirmError};
use fleet_core::bulk::{Approver, BoxFut, BulkExecutor};
use fleet_core::cache::McpClientRecord;
use fleet_core::mcp_host::{
    AiLimits, ConfirmFailure, McpBackend, McpConfig, McpHost, McpSession, McpUi, PeerInfo, Prompt,
    PromptKind, ServerSummary,
};
use fleet_proto::payload::PendingChange;
use fleet_proto::{Actor, ServerId};
use fleetctl_proto::{MAX_FRAME, PROTO_VERSION, ProtoError, Response, encode_frame};
use std::sync::{Arc, Weak};

const SETTING_MCP_PAUSED: &str = "mcp_paused";

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct McpPeerRow {
    /// Team id of `fleetctl`'s parent process ("" when unsigned).
    pub parent_team: String,
    /// Its signing identifier.
    pub parent_signing_id: String,
    /// Its cdhash, hex ("" when not available).
    pub parent_cdhash: String,
    /// Unsigned, shell or interpreter parent: ask on every connection,
    /// never persist (Rust also checks team and identifier itself).
    pub ask_every_time: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum McpPromptKindRow {
    Pairing {
        client_name: String,
        parent_team: String,
        parent_signing_id: String,
        parent_cdhash: String,
        /// Show a warning: this client is asked on every connection.
        ask_every_time: bool,
    },
    Approval {
        client: String,
        tool: String,
        op: String,
        /// Complete (never cut); show scrollable.
        details: String,
        servers: Vec<String>,
        /// The root key's Touch ID follows.
        elevated: bool,
        /// Exec asked for a root approval of a may-escalate op.
        escalation: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct McpPromptRow {
    pub id: u64,
    /// BLAKE3 (hex) of everything shown; pass it back to
    /// `mcp_resolve_prompt`.
    pub digest: String,
    pub kind: McpPromptKindRow,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct McpClientRow {
    pub key: String,
    pub client_name: String,
    pub parent_team: String,
    pub parent_signing_id: String,
    pub paired_ms: u64,
}

#[uniffi::export(callback_interface)]
pub trait McpDelegate: Send + Sync {
    /// Show a pairing or approval prompt; answer with `mcp_resolve_prompt`.
    fn on_prompt(&self, prompt: McpPromptRow);
    /// The prompt timed out, was answered elsewhere, or AI was paused.
    fn on_prompt_closed(&self, id: u64);
}

/// Largest frame body `McpConnection::handle` accepts.
#[uniffi::export]
pub fn mcp_max_frame() -> u32 {
    MAX_FRAME as u32
}

struct Ui(Box<dyn McpDelegate>);

impl McpUi for Ui {
    fn show_prompt(&self, p: Prompt) {
        let kind = match p.kind {
            PromptKind::Pairing {
                identity,
                ask_every_time,
            } => McpPromptKindRow::Pairing {
                client_name: crate::text::line(identity.client_name),
                parent_team: crate::text::line(identity.parent_team),
                parent_signing_id: crate::text::line(identity.parent_signing_id),
                parent_cdhash: crate::text::line(identity.parent_cdhash),
                ask_every_time,
            },
            PromptKind::Approval {
                client,
                tool,
                op,
                details,
                servers,
                elevated,
                escalation,
            } => McpPromptKindRow::Approval {
                client: crate::text::line(client),
                tool,
                op,
                details: crate::text::text(details),
                servers,
                elevated,
                escalation,
            },
        };
        self.0.on_prompt(McpPromptRow {
            id: p.id,
            digest: p.digest,
            kind,
        });
    }

    fn close_prompt(&self, id: u64) {
        self.0.on_prompt_closed(id);
    }
}

struct Backend {
    core: Weak<FleetCore>,
}

impl Backend {
    fn core(&self) -> Result<Arc<FleetCore>, ProtoError> {
        self.core.upgrade().ok_or(ProtoError::NotRunning)
    }
}

impl McpBackend for Backend {
    fn executor(&self) -> Result<Arc<dyn BulkExecutor>, ProtoError> {
        let (h, _) = self.core()?.running().map_err(|_| ProtoError::NotRunning)?;
        Ok(Arc::new(h))
    }

    fn approver(&self) -> Option<Arc<dyn Approver>> {
        self.core().ok()?.root_approver().ok()
    }

    fn locked(&self) -> bool {
        self.core()
            .map(|c| c.session_kind() == SessionKind::Monitor)
            .unwrap_or(true)
    }

    fn servers(&self) -> Vec<ServerSummary> {
        let Ok(core) = self.core() else {
            return Vec::new();
        };
        let handle = core.running().ok().map(|(h, _)| h);
        let recs = lock(&core.cache).servers().unwrap_or_default();
        recs.into_iter()
            .map(|r| ServerSummary {
                state: handle
                    .as_ref()
                    .and_then(|h| h.state(&r.id))
                    .map_or("NotConnected".into(), |s| format!("{s:?}")),
                id: r.id,
                name: r.name,
                group: r.group,
                tags: r.tags,
            })
            .collect()
    }

    fn paired(&self, key: &str) -> bool {
        self.core()
            .ok()
            .is_some_and(|c| matches!(lock(&c.cache).mcp_client(key), Ok(Some(_))))
    }

    fn save_pairing(&self, rec: McpClientRecord) -> Result<(), ProtoError> {
        let core = self.core()?;
        lock(&core.cache)
            .put_mcp_client(&rec)
            .map_err(|_| ProtoError::Internal)
    }

    fn ai_limits(&self, server: &ServerId) -> Option<AiLimits> {
        let core = self.core().ok()?;
        let p = fleet_core::policy::pushed(&lock(&core.cache), server)?;
        Some(AiLimits::from_policy(&p))
    }

    fn confirm_change(
        &self,
        server: ServerId,
        change: PendingChange,
        actor: Actor,
    ) -> BoxFut<Result<(), ConfirmFailure>> {
        let core = self.core();
        Box::pin(async move {
            let core = core.map_err(|_| ConfirmFailure::Unavailable)?;
            let (h, rt) = core.running().map_err(|_| ConfirmFailure::Unavailable)?;
            rt.spawn(async move {
                autorevert::confirm_pending(&h, &server, &change, actor)
                    .await
                    .map_err(confirm_failure)
            })
            .await
            .map_err(|_| ConfirmFailure::Unavailable)?
        })
    }
}

/// Fixed codes only: no agent or transport text goes to the AI.
fn confirm_failure(e: ConfirmError) -> ConfirmFailure {
    match e {
        ConfirmError::Reverted => ConfirmFailure::Reverted,
        ConfirmError::NoConnection => ConfirmFailure::NoConnection,
        ConfirmError::Reconnect(_) => ConfirmFailure::ReconnectFailed,
        ConfirmError::Agent(code) => ConfirmFailure::Agent(code),
        ConfirmError::Request(_) | ConfirmError::Cancelled => ConfirmFailure::RequestFailed,
    }
}

/// One accepted socket connection.
#[derive(uniffi::Object)]
pub struct McpConnection {
    core: Arc<FleetCore>,
    host: Arc<McpHost>,
    session: Arc<tokio::sync::Mutex<McpSession>>,
}

fn request_id(body: &[u8]) -> u64 {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("id").and_then(|i| i.as_u64()))
        .unwrap_or(0)
}

#[uniffi::export]
impl McpConnection {
    /// Handles one frame body; returns the response frame (with header).
    pub async fn handle(&self, body: Vec<u8>) -> Vec<u8> {
        let not_running = |id| {
            encode_frame(&Response {
                v: PROTO_VERSION,
                id,
                body: Err(ProtoError::NotRunning),
            })
            .unwrap_or_default()
        };
        if body.len() > MAX_FRAME {
            return not_running(0);
        }
        let host = self.host.clone();
        let session = self.session.clone();
        let id = request_id(&body);
        self.core
            .on_core(async move {
                let mut s = session.lock().await;
                Ok(host.handle_frame(&mut s, &body).await)
            })
            .await
            .unwrap_or_else(|_| not_running(id))
    }

    /// "client via parent" once paired.
    pub async fn paired_label(&self) -> Option<String> {
        self.session.lock().await.paired_label()
    }
}

impl FleetCore {
    fn mcp_host(self: &Arc<Self>) -> Arc<McpHost> {
        self.mcp
            .get_or_init(|| {
                let host = McpHost::new(
                    Arc::new(Backend {
                        core: Arc::downgrade(self),
                    }),
                    McpConfig::default(),
                );
                let paused = lock(&self.cache)
                    .setting(SETTING_MCP_PAUSED)
                    .ok()
                    .flatten()
                    .is_some_and(|v| v == [1]);
                host.set_paused(paused);
                host
            })
            .clone()
    }
}

#[uniffi::export]
impl FleetCore {
    pub fn mcp_set_delegate(self: Arc<Self>, delegate: Option<Box<dyn McpDelegate>>) {
        self.mcp_host()
            .set_ui(delegate.map(|d| Arc::new(Ui(d)) as Arc<dyn McpUi>));
    }

    /// Global AI pause (app and menu bar); persisted.
    pub fn mcp_set_paused(self: Arc<Self>, paused: bool) -> Result<(), FleetError> {
        lock(&self.cache).set_setting(SETTING_MCP_PAUSED, &[u8::from(paused)])?;
        self.mcp_host().set_paused(paused);
        Ok(())
    }

    pub fn mcp_paused(self: Arc<Self>) -> bool {
        self.mcp_host().paused()
    }

    /// The operator's answer to prompt `id`. `digest` is the prompt's (an
    /// answer carrying another is a denial); `user_verified`: the app took
    /// Touch ID for it (an approval of a pairing or non-Elevated prompt
    /// without it is a denial). False if the prompt is gone or the
    /// approval was turned into a denial.
    pub fn mcp_resolve_prompt(
        self: Arc<Self>,
        id: u64,
        approved: bool,
        digest: String,
        user_verified: bool,
    ) -> bool {
        self.mcp_host()
            .resolve_prompt(id, approved, &digest, user_verified)
    }

    pub fn mcp_clients(&self) -> Result<Vec<McpClientRow>, FleetError> {
        Ok(lock(&self.cache)
            .mcp_clients()?
            .into_iter()
            .map(|c| McpClientRow {
                key: c.key,
                client_name: crate::text::line(c.client_name),
                parent_team: crate::text::line(c.parent_team),
                parent_signing_id: crate::text::line(c.parent_signing_id),
                paired_ms: c.paired_ms,
            })
            .collect())
    }

    /// Takes effect on the client's next call.
    pub fn mcp_revoke_client(&self, key: String) -> Result<(), FleetError> {
        lock(&self.cache).delete_mcp_client(&key)?;
        Ok(())
    }

    /// A connection whose peer Swift has verified.
    pub fn mcp_connect(self: Arc<Self>, peer: McpPeerRow) -> Arc<McpConnection> {
        let host = self.mcp_host();
        let session = host.session(PeerInfo {
            parent_team: peer.parent_team,
            parent_signing_id: peer.parent_signing_id,
            parent_cdhash: peer.parent_cdhash,
            ask_every_time: peer.ask_every_time,
        });
        Arc::new(McpConnection {
            core: self,
            host,
            session: Arc::new(tokio::sync::Mutex::new(session)),
        })
    }
}
