//! Unified timeline (design §2.7): verified agent events caught up with
//! `events.query` plus the audit mirror, per server and fleet-wide
//! (`fleet_core::timeline`).
//!
//! [`TimelineService`] keeps each server's verified events and cursor in
//! memory for the app's lifetime, so a refresh only asks for what is new.
//! The app refreshes a server's timeline when it is shown and when a live
//! event arrives for it. Item text is server data, escaped (rule 6).

use crate::api::{FleetCore, lock};
use crate::text;
use crate::types::{AlertSeverity, FleetError};
use fleet_core::manager;
use fleet_core::timeline::{
    self, ActorKind, Category, ItemSource, MAX_PAGES, ServerTimeline, TimelineItem,
};
use fleet_proto::{Actor, AuditEntry, Ed25519Public, ServerId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TimelineCategory {
    Alert,
    Login,
    Service,
    Package,
    Config,
    Security,
    Network,
    Container,
    Health,
    Fleet,
    Change,
    Action,
    Other,
}

impl From<Category> for TimelineCategory {
    fn from(c: Category) -> Self {
        match c {
            Category::Alert => Self::Alert,
            Category::Login => Self::Login,
            Category::Service => Self::Service,
            Category::Package => Self::Package,
            Category::Config => Self::Config,
            Category::Security => Self::Security,
            Category::Network => Self::Network,
            Category::Container => Self::Container,
            Category::Health => Self::Health,
            Category::Fleet => Self::Fleet,
            Category::Change => Self::Change,
            Category::Action => Self::Action,
            Category::Other => Self::Other,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TimelineItemRow {
    /// Unique within a timeline: server + source + seq.
    pub id: String,
    pub server_id: String,
    pub server_name: String,
    pub time_ms: u64,
    pub category: TimelineCategory,
    /// Event or operation name (`login`, `pkg.upgrade`).
    pub name: String,
    pub title: String,
    pub detail: String,
    pub severity: Option<AlertSeverity>,
    /// Who acted, for audit entries: `operator`, `AI (client)`, …
    pub actor: Option<String>,
    /// Done by an AI client (MCP).
    pub ai: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TimelineRow {
    /// Newest first.
    pub items: Vec<TimelineItemRow>,
    /// Events that failed signature checks (never shown).
    pub rejected_events: u64,
    /// Servers that could not be refreshed: `name: reason`.
    pub failures: Vec<String>,
}

#[derive(uniffi::Object, Default)]
pub struct TimelineService {
    servers: Mutex<HashMap<ServerId, ServerTimeline>>,
}

#[uniffi::export]
impl TimelineService {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

fn row(i: TimelineItem, name: &str) -> TimelineItemRow {
    let (src, seq) = match i.source {
        ItemSource::Event { seq, .. } => ("e", seq),
        ItemSource::Audit { seq } => ("a", seq),
    };
    let ai = i.is_ai();
    let actor = i.actor.map(|a| match a {
        ActorKind::Human => "operator".to_string(),
        ActorKind::Ai { client } => format!("AI ({client})"),
        ActorKind::Runbook => "runbook".into(),
        ActorKind::Recovery => "recovery key".into(),
        ActorKind::System => "agent".into(),
    });
    TimelineItemRow {
        id: format!("{}:{src}:{seq}:{}", i.server, i.time_ms),
        server_id: i.server.to_string(),
        server_name: name.to_string(),
        time_ms: i.time_ms,
        category: i.category.into(),
        name: i.name,
        title: text::line(i.title),
        detail: text::line(i.detail),
        severity: i.severity.map(Into::into),
        actor: actor.map(text::line),
        ai,
    }
}

impl FleetCore {
    /// Catches `id` up (when connected) and returns its items plus its
    /// mirrored audit entries, unsorted.
    async fn timeline_items(
        &self,
        tl: &TimelineService,
        id: &ServerId,
        ready: bool,
        audit_limit: usize,
    ) -> (Vec<TimelineItem>, Option<String>) {
        let mut failure = None;
        let key: Option<Ed25519Public> = lock(&self.cache)
            .pins(id)
            .ok()
            .flatten()
            .and_then(|p| p.agent_signing);
        if let (true, Some(key)) = (ready, key) {
            let cursor = lock(&tl.servers).entry(id.clone()).or_default().cursor();
            let fetched = match self.running() {
                Ok((handle, _)) => {
                    let sid = id.clone();
                    self.on_core(async move {
                        let h = &handle;
                        let sid = &sid;
                        timeline::fetch_pages(cursor, MAX_PAGES, |op| async move {
                            let reply = h
                                .request(sid, op, Actor::Human, None)
                                .await
                                .map_err(|e| FleetError::from(e).to_string())?;
                            reply.result.map_err(|c| format!("agent error {c:?}"))
                        })
                        .await
                        .map_err(|m| FleetError::Session { message: m })
                    })
                    .await
                }
                Err(e) => Err(e),
            };
            match fetched {
                Ok(pages) => {
                    let mut all = lock(&tl.servers);
                    let t = all.entry(id.clone()).or_default();
                    for p in &pages {
                        t.ingest(id, &key, p);
                    }
                }
                Err(e) => failure = Some(e.to_string()),
            }
            // Audit mirror first, so AI and other actions run since the
            // last refresh show up below (design §5.8).
            if let Err(e) = self.refresh_audit_mirror(id, &key).await {
                failure.get_or_insert(e.to_string());
            }
        }
        let mut items: Vec<TimelineItem> = lock(&tl.servers)
            .get(id)
            .map(|t| t.items().cloned().collect())
            .unwrap_or_default();
        if let Ok(rows) = lock(&self.cache).audit_mirror(id, audit_limit) {
            items.extend(rows.iter().filter_map(|(_, raw)| {
                let e: AuditEntry = fleet_proto::decode(raw).ok()?;
                timeline::from_audit(id, &e)
            }));
        }
        (items, failure)
    }

    /// Fetches `id`'s new audit entries on the core runtime, then verifies
    /// and stores them (a tampered chain raises the critical alert).
    async fn refresh_audit_mirror(&self, id: &ServerId, key: &Ed25519Public) -> Result<(), FleetError> {
        use fleet_core::audit_mirror;
        use fleet_core::runner::OpRunner;
        let after = audit_mirror::known_seq(&lock(&self.cache), id)?;
        let (handle, _) = self.running()?;
        let sid = id.clone();
        let pages = self
            .on_core(async move {
                let (h, sid) = (&handle, &sid);
                match audit_mirror::fetch(after, |op| h.run(sid, op, Actor::Human, None)).await {
                    Ok(p) => Ok(Some(p)),
                    // Monitor session (app locked) or offline: next time.
                    Err(fleet_core::runner::RunError::Locked | fleet_core::runner::RunError::Offline) => {
                        Ok(None)
                    }
                    Err(e) => Err(FleetError::Session {
                        message: e.to_string(),
                    }),
                }
            })
            .await?;
        let Some(pages) = pages else {
            return Ok(());
        };
        let r = audit_mirror::apply(&lock(&self.cache), id, key, &pages, fleet_core::now_ms());
        let failed = r.as_ref().err().map(|e| e.to_string());
        self.audit_mirrored(id, r);
        match failed {
            Some(message) => Err(FleetError::Session { message }),
            None => Ok(()),
        }
    }

    fn rejected(&self, tl: &TimelineService, ids: &[ServerId]) -> u64 {
        let all = lock(&tl.servers);
        ids.iter()
            .filter_map(|i| all.get(i))
            .map(|t| t.rejected)
            .sum()
    }

    fn names(&self) -> HashMap<ServerId, String> {
        lock(&self.cache)
            .servers()
            .map(|v| v.into_iter().map(|r| (r.id, r.name)).collect())
            .unwrap_or_default()
    }
}

fn clamp(limit: u32) -> usize {
    limit.clamp(1, 10_000) as usize
}

#[uniffi::export]
impl FleetCore {
    /// One server's timeline, newest first.
    pub async fn timeline_server(
        &self,
        timeline: Arc<TimelineService>,
        server_id: String,
        limit: u32,
    ) -> Result<TimelineRow, FleetError> {
        let id = crate::validate::server_id(&server_id)?;
        let limit = clamp(limit);
        let ready = self
            .running()
            .ok()
            .and_then(|(h, _)| h.state(&id))
            .is_some_and(|s| s == manager::ConnState::Ready);
        let (items, failure) = self.timeline_items(&timeline, &id, ready, limit).await;
        let names = self.names();
        let name = names.get(&id).cloned().unwrap_or_else(|| id.to_string());
        Ok(TimelineRow {
            items: timeline::merge(&items, limit)
                .into_iter()
                .map(|i| row(i, &name))
                .collect(),
            rejected_events: self.rejected(&timeline, std::slice::from_ref(&id)),
            failures: failure
                .map(|f| vec![text::line(format!("{name}: {f}"))])
                .unwrap_or_default(),
        })
    }

    /// Every server's timeline merged, newest first. Connected servers
    /// are caught up concurrently; the others show what is cached.
    pub async fn timeline_fleet(
        &self,
        timeline: Arc<TimelineService>,
        limit: u32,
    ) -> Result<TimelineRow, FleetError> {
        let limit = clamp(limit);
        let (handle, _) = self.running()?;
        let servers = handle.servers();
        let names = self.names();
        let tl = &timeline;
        let per_server = servers.iter().map(|(id, state)| async move {
            let ready = *state == manager::ConnState::Ready;
            (id, self.timeline_items(tl, id, ready, limit).await)
        });
        let results = futures_util::future::join_all(per_server).await;
        let mut items = Vec::new();
        let mut failures = Vec::new();
        for (id, (mut its, failure)) in results {
            items.append(&mut its);
            if let Some(f) = failure {
                let n = names.get(id).cloned().unwrap_or_else(|| id.to_string());
                failures.push(text::line(format!("{n}: {f}")));
            }
        }
        let ids: Vec<ServerId> = servers.iter().map(|(i, _)| i.clone()).collect();
        Ok(TimelineRow {
            items: timeline::merge(&items, limit)
                .into_iter()
                .map(|i| {
                    let n = names
                        .get(&i.server)
                        .cloned()
                        .unwrap_or_else(|| i.server.to_string());
                    row(i, &n)
                })
                .collect(),
            rejected_events: self.rejected(&timeline, &ids),
            failures,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_proto::Event;

    #[test]
    fn rows_escape_and_mark_ai() {
        let s = ServerId::new("srv_aaaaaaaaaaaa").unwrap();
        let mut i = timeline::from_event(
            &s,
            [0; 16],
            7,
            1000,
            &Event::Login {
                user: "ev\u{202E}il".into(),
                source: None,
                success: false,
                new_source: false,
                device_id: None,
            },
        );
        let r = row(i.clone(), "web-1");
        assert_eq!(r.title, "Failed login: ev\\u{202E}il");
        assert_eq!(r.id, "srv_aaaaaaaaaaaa:e:7:1000");
        assert!(!r.ai && r.actor.is_none());
        i.actor = Some(ActorKind::Ai {
            client: "claude".into(),
        });
        let r = row(i, "web-1");
        assert!(r.ai);
        assert_eq!(r.actor.as_deref(), Some("AI (claude)"));
    }
}
