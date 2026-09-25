//! Fleet search (design §2.7): `search.*` on every connected server at
//! once (`fleet_core::fleetsearch`), merged. Hit text is server data,
//! escaped for display (rule 6).

use crate::api::{FleetCore, lock};
use crate::text;
use crate::types::FleetError;
use fleet_core::fleetsearch::{self, KINDS};
use fleet_core::manager;
use fleet_proto::args::{SearchQuery, SearchTerm, TimeRange};
use fleet_proto::payload::SearchKind;
use fleet_proto::{Actor, ServerId};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum SearchKindRow {
    Package,
    Port,
    Process,
    User,
    File,
    Journal,
}

impl From<SearchKind> for SearchKindRow {
    fn from(k: SearchKind) -> Self {
        match k {
            SearchKind::Package => Self::Package,
            SearchKind::Port => Self::Port,
            SearchKind::Process => Self::Process,
            SearchKind::User => Self::User,
            SearchKind::File => Self::File,
            SearchKind::Journal => Self::Journal,
        }
    }
}

impl From<SearchKindRow> for SearchKind {
    fn from(k: SearchKindRow) -> Self {
        match k {
            SearchKindRow::Package => Self::Package,
            SearchKindRow::Port => Self::Port,
            SearchKindRow::Process => Self::Process,
            SearchKindRow::User => Self::User,
            SearchKindRow::File => Self::File,
            SearchKindRow::Journal => Self::Journal,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FleetSearchArgs {
    pub term: String,
    pub case_sensitive: bool,
    /// Empty: every kind.
    pub kinds: Vec<SearchKindRow>,
    /// Hits per server and kind, 1..=1000.
    pub limit: u32,
    /// Logs only: from this time on.
    pub since_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FleetSearchHitRow {
    pub server_id: String,
    pub server_name: String,
    pub kind: SearchKindRow,
    pub primary: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FleetSearchIssueRow {
    pub server_id: String,
    pub server_name: String,
    pub kind: SearchKindRow,
    /// Failure text; empty for a truncation notice.
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FleetSearchRow {
    /// Grouped by kind (packages, ports, processes, users, files, logs),
    /// then sorted by text.
    pub hits: Vec<FleetSearchHitRow>,
    pub failures: Vec<FleetSearchIssueRow>,
    /// A server returned its limit for that kind: more hits exist.
    pub truncated: Vec<FleetSearchIssueRow>,
    pub servers_searched: u32,
    /// Registered servers that were not connected.
    pub servers_skipped: u32,
    /// Hits over the fleet-wide cap.
    pub dropped: u32,
}

fn invalid(field: &str) -> FleetError {
    FleetError::InvalidArgument {
        field: field.into(),
    }
}

pub(crate) fn query(a: &FleetSearchArgs) -> Result<(SearchQuery, Vec<SearchKind>), FleetError> {
    let term = SearchTerm::new(a.term.trim()).map_err(|_| invalid("term"))?;
    let q = SearchQuery {
        term,
        case_sensitive: a.case_sensitive,
        roots: vec![],
        range: TimeRange {
            since_ms: a.since_ms,
            until_ms: None,
        },
        limit: a.limit,
    };
    q.validate().map_err(|_| invalid("limit"))?;
    let mut kinds: Vec<SearchKind> = if a.kinds.is_empty() {
        KINDS.to_vec()
    } else {
        a.kinds.iter().map(|k| (*k).into()).collect()
    };
    kinds.sort_by_key(|k| fleetsearch::rank(*k));
    kinds.dedup();
    Ok((q, kinds))
}

#[uniffi::export]
impl FleetCore {
    /// Searches every connected server concurrently.
    pub async fn fleet_search(&self, args: FleetSearchArgs) -> Result<FleetSearchRow, FleetError> {
        let (q, kinds) = query(&args)?;
        let (handle, _) = self.running()?;
        let all = handle.servers();
        let ready: Vec<ServerId> = all
            .iter()
            .filter(|(_, s)| *s == manager::ConnState::Ready)
            .map(|(id, _)| id.clone())
            .collect();
        let skipped = (all.len() - ready.len()) as u32;
        let names: HashMap<String, String> = lock(&self.cache)
            .servers()?
            .into_iter()
            .map(|r| (r.id.to_string(), r.name))
            .collect();
        let n = ready.len() as u32;
        let answers = self
            .on_core(async move {
                let h = &handle;
                Ok(
                    fleetsearch::fan_out(ready, &kinds, &q, |id, op| async move {
                        let reply = h
                            .request(&id, op, Actor::Human, None)
                            .await
                            .map_err(|e| FleetError::from(e).to_string())?;
                        reply.result.map_err(|code| format!("agent error {code:?}"))
                    })
                    .await,
                )
            })
            .await?;
        let merged = fleetsearch::merge(answers, n);
        let name = |id: &ServerId| {
            names
                .get(id.as_str())
                .cloned()
                .unwrap_or_else(|| id.to_string())
        };
        Ok(FleetSearchRow {
            hits: merged
                .hits
                .into_iter()
                .map(|h| FleetSearchHitRow {
                    server_name: name(&h.server),
                    server_id: h.server.to_string(),
                    kind: h.kind.into(),
                    primary: text::line(h.primary),
                    detail: text::line(h.detail),
                })
                .collect(),
            failures: merged
                .failures
                .into_iter()
                .map(|f| FleetSearchIssueRow {
                    server_name: name(&f.server),
                    server_id: f.server.to_string(),
                    kind: f.kind.into(),
                    message: text::line(f.message),
                })
                .collect(),
            truncated: merged
                .truncated
                .into_iter()
                .map(|(s, k)| FleetSearchIssueRow {
                    server_name: name(&s),
                    server_id: s.to_string(),
                    kind: k.into(),
                    message: String::new(),
                })
                .collect(),
            servers_searched: merged.servers,
            servers_skipped: skipped,
            dropped: merged.dropped,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(term: &str, kinds: Vec<SearchKindRow>, limit: u32) -> FleetSearchArgs {
        FleetSearchArgs {
            term: term.into(),
            case_sensitive: false,
            kinds,
            limit,
            since_ms: None,
        }
    }

    #[test]
    fn query_validation() {
        let (q, kinds) = query(&args(" nginx ", vec![], 50)).unwrap();
        assert_eq!(q.limit, 50);
        assert_eq!(kinds, KINDS.to_vec());
        let (_, kinds) = query(&args(
            "x1",
            vec![
                SearchKindRow::Journal,
                SearchKindRow::Package,
                SearchKindRow::Journal,
            ],
            1,
        ))
        .unwrap();
        assert_eq!(kinds, [SearchKind::Package, SearchKind::Journal]);
        assert!(query(&args("", vec![], 10)).is_err());
        assert!(query(&args("nginx", vec![], 0)).is_err());
        assert!(query(&args("nginx", vec![], 1001)).is_err());
    }
}
