//! Unified timeline (design §2.7), per server and fleet-wide.
//!
//! Sources:
//!
//! - **Agent events**: caught up with `events.query` from a per-server
//!   cursor (the agent keeps 7 days), so events that happened while the
//!   Mac was away appear too. Every event is checked against the server's
//!   pinned agent signing key before it is shown, like a live event
//!   (design §5.6); failures are counted, never shown.
//! - **Audit entries** from the Mac's audit mirror (§7.4): the operations
//!   run on the server with their actor, so AI actions are marked.
//!
//! Text in items is server data (rule 6); the FFI escapes it.

use fleet_crypto::receipt::verify_event;
use fleet_proto::alert::Severity;
use fleet_proto::payload::SignedEventPage;
use fleet_proto::{Actor, AuditEntry, Ed25519Public, Event, Op, Payload, ServerId};
use std::collections::{HashSet, VecDeque};
use std::future::Future;

/// Items kept per server.
pub const MAX_ITEMS: usize = 5_000;
/// `events.query` page size.
pub const PAGE: u32 = 500;
/// Pages fetched per refresh (the first refresh of a busy server reads
/// the rest on the next one).
pub const MAX_PAGES: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    Alert,
    Login,
    Service,
    Package,
    Config,
    Security,
    Network,
    Container,
    Health,
    /// Roster, policy, recovery.
    Fleet,
    /// Auto-revert fired.
    Change,
    /// An operation from the audit log.
    Action,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActorKind {
    Human,
    Ai { client: String },
    Runbook,
    Recovery,
    System,
}

impl From<&Actor> for ActorKind {
    fn from(a: &Actor) -> Self {
        match a {
            Actor::Human => Self::Human,
            Actor::Ai { client, .. } => Self::Ai {
                client: client.as_str().to_string(),
            },
            Actor::Runbook { .. } => Self::Runbook,
            Actor::Recovery => Self::Recovery,
            Actor::System => Self::System,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ItemSource {
    Event { run_id: [u8; 16], seq: u64 },
    Audit { seq: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineItem {
    pub server: ServerId,
    pub time_ms: u64,
    pub category: Category,
    /// Event or operation catalog name (`login`, `pkg.upgrade`).
    pub name: String,
    pub title: String,
    pub detail: String,
    /// Set for alerts.
    pub severity: Option<Severity>,
    /// Who acted (audit entries only).
    pub actor: Option<ActorKind>,
    pub source: ItemSource,
}

impl TimelineItem {
    pub fn is_ai(&self) -> bool {
        matches!(self.actor, Some(ActorKind::Ai { .. }))
    }
}

fn changes_detail(changes: &[fleet_proto::payload::PackageChange]) -> String {
    let mut parts: Vec<String> = changes
        .iter()
        .take(5)
        .map(|c| {
            let v = match (&c.from, &c.to) {
                (Some(f), Some(t)) => format!(" {f} → {t}"),
                (None, Some(t)) => format!(" {t}"),
                (Some(f), None) => format!(" {f}"),
                (None, None) => String::new(),
            };
            format!("{:?} {}{v}", c.action, c.name).to_lowercase()
        })
        .collect();
    if changes.len() > 5 {
        parts.push(format!("+{} more", changes.len() - 5));
    }
    parts.join(", ")
}

/// The item for a verified event.
pub fn from_event(
    server: &ServerId,
    run_id: [u8; 16],
    seq: u64,
    time_ms: u64,
    e: &Event,
) -> TimelineItem {
    use Category as C;
    let (category, title, detail, severity) = match e {
        Event::RosterChanged { epoch, version } => (
            C::Fleet,
            "Roster changed".into(),
            format!("epoch {epoch}, version {version}"),
            None,
        ),
        Event::RecoveryPending(p) => (
            C::Fleet,
            "Recovery roster pending".into(),
            format!("activates at {}", p.activates_at_ms),
            Some(Severity::Critical),
        ),
        Event::RecoveryVetoed { .. } => (C::Fleet, "Recovery vetoed".into(), String::new(), None),
        Event::PolicyChanged { version } => (
            C::Fleet,
            "Policy changed".into(),
            format!("version {version}"),
            None,
        ),
        Event::RebootScheduled { at_ms, audit_seq } => (
            C::Fleet,
            "Reboot scheduled".into(),
            format!("at {at_ms} (audit entry {audit_seq})"),
            Some(Severity::Warning),
        ),
        Event::ChangeReverted { audit_seq, .. } => (
            C::Change,
            "Change auto-reverted".into(),
            format!("audit entry {audit_seq}"),
            Some(Severity::Warning),
        ),
        Event::AlertFired {
            rule_id,
            severity,
            subject,
            value,
        } => (
            C::Alert,
            format!("Alert: {rule_id}"),
            format!("{subject} ({value})"),
            Some(*severity),
        ),
        Event::AlertCleared { rule_id, subject } => (
            C::Alert,
            format!("Alert cleared: {rule_id}"),
            subject.clone(),
            None,
        ),
        Event::ServiceStateChanged { unit, from, to } => (
            C::Service,
            unit.clone(),
            format!("{from:?} → {to:?}").to_lowercase(),
            None,
        ),
        Event::Login {
            user,
            source,
            success,
            new_source,
            ..
        } => {
            let from = source.map(|s| format!("from {s}")).unwrap_or_default();
            let new = if *new_source { " (new source)" } else { "" };
            let (title, sev) = if *success {
                (
                    format!("Login: {user}"),
                    new_source.then_some(Severity::Warning),
                )
            } else {
                (format!("Failed login: {user}"), None)
            };
            (C::Login, title, format!("{from}{new}"), sev)
        }
        Event::BanChanged {
            addr,
            banned,
            reason,
            ..
        } => (
            C::Security,
            if *banned {
                format!("Banned {addr}")
            } else {
                format!("Unbanned {addr}")
            },
            format!("{reason:?}").to_lowercase(),
            None,
        ),
        Event::PackagesChanged { changes } => (
            C::Package,
            format!(
                "{} package change{}",
                changes.len(),
                if changes.len() == 1 { "" } else { "s" }
            ),
            changes_detail(changes),
            None,
        ),
        Event::ConfigChanged {
            path,
            version,
            source,
            ..
        } => (
            C::Config,
            format!("Config changed: {path}"),
            format!("version {version}, {source:?}").to_lowercase(),
            None,
        ),
        Event::NewListeningPort {
            proto,
            addr,
            port,
            process,
            blocked,
        } => (
            C::Network,
            format!("New listening port {port}"),
            format!(
                "{proto:?} {addr}:{port}{}{}",
                process
                    .as_deref()
                    .map(|p| format!(" by {p}"))
                    .unwrap_or_default(),
                if *blocked { ", blocked" } else { "" }
            ),
            Some(Severity::Warning),
        ),
        Event::UserChanged { kind, name } => (
            C::Security,
            format!("{kind:?}: {name}"),
            String::new(),
            Some(Severity::Warning),
        ),
        Event::AuthorizedKeysChanged { user, source } => (
            C::Security,
            format!("authorized_keys changed: {user}"),
            format!("{source:?}").to_lowercase(),
            Some(Severity::Warning),
        ),
        Event::IntegrityViolation { path, kind } => (
            C::Security,
            format!("Integrity: {path}"),
            format!("{kind:?}").to_lowercase(),
            Some(Severity::Critical),
        ),
        Event::CertExpiring {
            source, subject, ..
        } => (
            C::Security,
            format!("Certificate expiring: {subject}"),
            source.clone(),
            Some(Severity::Warning),
        ),
        Event::Container {
            name,
            action,
            exit_code,
            ..
        } => (
            C::Container,
            format!("Container {name}"),
            match exit_code {
                Some(c) => format!("{action:?}, exit {c}").to_lowercase(),
                None => format!("{action:?}").to_lowercase(),
            },
            None,
        ),
        Event::HealthCheckChanged { check_id, ok } => (
            C::Health,
            format!("Health check {check_id}"),
            if *ok { "passing" } else { "failing" }.into(),
            (!ok).then_some(Severity::Warning),
        ),
        Event::Unknown { tag } => (C::Other, format!("Event {tag}"), String::new(), None),
    };
    TimelineItem {
        server: server.clone(),
        time_ms,
        category,
        name: e.name().to_string(),
        title,
        detail,
        severity,
        actor: None,
        source: ItemSource::Event { run_id, seq },
    }
}

/// Operation name for an audit `OpSummary` tag.
pub fn op_name(tag: u16) -> &'static str {
    fleet_proto::op::tag::ALL
        .iter()
        .position(|t| *t == tag)
        .map(|i| fleet_proto::op::tag::NAMES[i])
        .unwrap_or("unknown")
}

/// The item for an audit entry: results only (each operation writes an
/// intent entry and a result entry).
pub fn from_audit(server: &ServerId, e: &AuditEntry) -> Option<TimelineItem> {
    use fleet_proto::{Outcome, Phase, ResultSummary};
    if e.phase != Phase::Result {
        return None;
    }
    let outcome = match e.result {
        ResultSummary::Pending => "pending".to_string(),
        ResultSummary::Done(Outcome::Ok) => "ok".into(),
        ResultSummary::Done(Outcome::Failed(code)) => format!("failed ({code:?})"),
        ResultSummary::Done(Outcome::Interrupted) => "interrupted".into(),
        ResultSummary::Done(Outcome::Reverted) => "reverted".into(),
    };
    let actor = ActorKind::from(&e.actor);
    let who = match &actor {
        ActorKind::Human => "operator".to_string(),
        ActorKind::Ai { client } => format!("AI ({client})"),
        ActorKind::Runbook => "runbook".into(),
        ActorKind::Recovery => "recovery key".into(),
        ActorKind::System => "agent".into(),
    };
    let name = op_name(e.op.tag);
    Some(TimelineItem {
        server: server.clone(),
        time_ms: e.time,
        category: Category::Action,
        name: name.to_string(),
        title: name.to_string(),
        detail: format!("{outcome} · {who}"),
        severity: None,
        actor: Some(actor),
        source: ItemSource::Audit { seq: e.seq },
    })
}

/// Where the next `events.query` starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Cursor {
    pub run_id: Option<[u8; 16]>,
    pub seq: u64,
}

impl Cursor {
    pub fn op(self, limit: u32) -> Op {
        Op::EventsQuery {
            since_run_id: self.run_id,
            since_seq: self.seq,
            limit,
        }
    }

    /// After `page`: its last event, verified or not (a bad one must not
    /// stall the catch-up).
    pub fn after(self, page: &SignedEventPage) -> Self {
        page.events.last().map_or(self, |e| Self {
            run_id: Some(e.run_id),
            seq: e.seq,
        })
    }
}

/// Fetches up to `max_pages` pages from `start` through `run`. Stops at a
/// page without `more`, or an empty one.
pub async fn fetch_pages<F, Fut>(
    start: Cursor,
    max_pages: usize,
    run: F,
) -> Result<Vec<SignedEventPage>, String>
where
    F: Fn(Op) -> Fut,
    Fut: Future<Output = Result<Payload, String>>,
{
    let mut cursor = start;
    let mut pages = Vec::new();
    for _ in 0..max_pages {
        let page = match run(cursor.op(PAGE)).await? {
            Payload::SignedEvents(p) => p,
            _ => return Err("unexpected reply".into()),
        };
        let more = page.more && !page.events.is_empty();
        cursor = cursor.after(&page);
        pages.push(page);
        if !more {
            break;
        }
    }
    Ok(pages)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ingested {
    pub accepted: u64,
    pub duplicates: u64,
    pub rejected: u64,
}

/// One server's timeline: verified events plus its cursor.
#[derive(Debug, Default)]
pub struct ServerTimeline {
    cursor: Cursor,
    items: VecDeque<TimelineItem>,
    seen: HashSet<([u8; 16], u64)>,
    /// Events that failed verification, ever.
    pub rejected: u64,
}

impl ServerTimeline {
    pub fn cursor(&self) -> Cursor {
        self.cursor
    }

    pub fn items(&self) -> impl Iterator<Item = &TimelineItem> {
        self.items.iter()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Verifies and adds a page (oldest first) and moves the cursor.
    pub fn ingest(
        &mut self,
        server: &ServerId,
        agent_key: &Ed25519Public,
        page: &SignedEventPage,
    ) -> Ingested {
        let mut n = Ingested::default();
        for e in &page.events {
            if verify_event(e, agent_key, server).is_err() {
                n.rejected += 1;
                continue;
            }
            if !self.seen.insert((e.run_id, e.seq)) {
                n.duplicates += 1;
                continue;
            }
            if self.items.len() == MAX_ITEMS
                && let Some(old) = self.items.pop_front()
                && let ItemSource::Event { run_id, seq } = old.source
            {
                self.seen.remove(&(run_id, seq));
            }
            self.items
                .push_back(from_event(server, e.run_id, e.seq, e.time_ms, &e.event));
            n.accepted += 1;
        }
        self.rejected += n.rejected;
        self.cursor = self.cursor.after(page);
        n
    }
}

/// Newest first, at most `limit`; ties by server, then source.
pub fn merge<'a>(
    items: impl IntoIterator<Item = &'a TimelineItem>,
    limit: usize,
) -> Vec<TimelineItem> {
    let mut all: Vec<&TimelineItem> = items.into_iter().collect();
    let seq = |s: &ItemSource| match *s {
        ItemSource::Event { seq, .. } | ItemSource::Audit { seq } => seq,
    };
    all.sort_by(|a, b| {
        b.time_ms
            .cmp(&a.time_ms)
            .then_with(|| a.server.as_str().cmp(b.server.as_str()))
            .then_with(|| seq(&b.source).cmp(&seq(&a.source)))
    });
    all.into_iter().take(limit).cloned().collect()
}

#[cfg(test)]
mod tests;
