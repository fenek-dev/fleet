//! Fleet search (design §2.7): one query fanned out as `search.*` ops to
//! every connected server at once, results merged into groups.
//!
//! Servers run concurrently; the kinds for one server run one after the
//! other on its session. One server failing (offline, locked, timeout,
//! agent error) is reported next to the results, never fails the search.
//! Hit text is server data (rule 6): the FFI escapes it for display.

use fleet_proto::args::SearchQuery;
use fleet_proto::payload::{SearchKind, SearchResults};
use fleet_proto::{Op, Payload, ServerId};
use std::future::Future;

/// Result group order in the UI.
pub const KINDS: [SearchKind; 6] = [
    SearchKind::Package,
    SearchKind::Port,
    SearchKind::Process,
    SearchKind::User,
    SearchKind::File,
    SearchKind::Journal,
];

/// Most hits kept across the fleet.
pub const MAX_TOTAL_HITS: usize = 5_000;

pub fn rank(k: SearchKind) -> usize {
    KINDS.iter().position(|x| *x == k).unwrap_or(KINDS.len())
}

pub fn op_for(kind: SearchKind, query: SearchQuery) -> Op {
    match kind {
        SearchKind::Package => Op::SearchPackages(query),
        SearchKind::Port => Op::SearchPorts(query),
        SearchKind::Process => Op::SearchProcesses(query),
        SearchKind::File => Op::SearchFiles(query),
        SearchKind::Journal => Op::SearchJournal(query),
        SearchKind::User => Op::SearchUsers(query),
    }
}

/// One server's answer for one kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAnswer {
    pub server: ServerId,
    pub kind: SearchKind,
    pub result: Result<SearchResults, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetHit {
    pub server: ServerId,
    pub kind: SearchKind,
    pub primary: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub server: ServerId,
    pub kind: SearchKind,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FleetResults {
    /// By kind ([`KINDS`] order), then primary text (case-insensitive),
    /// then server.
    pub hits: Vec<FleetHit>,
    /// `(server, kind)` pairs whose agent returned its limit.
    pub truncated: Vec<(ServerId, SearchKind)>,
    pub failures: Vec<Failure>,
    /// Servers asked.
    pub servers: u32,
    /// Hits dropped by [`MAX_TOTAL_HITS`].
    pub dropped: u32,
}

/// Runs `kinds` on every server in `servers` through `run`, concurrently
/// across servers.
pub async fn fan_out<F, Fut>(
    servers: Vec<ServerId>,
    kinds: &[SearchKind],
    query: &SearchQuery,
    run: F,
) -> Vec<ServerAnswer>
where
    F: Fn(ServerId, Op) -> Fut,
    Fut: Future<Output = Result<Payload, String>>,
{
    let run = &run;
    let per_server = servers.into_iter().map(|server| async move {
        let mut out = Vec::with_capacity(kinds.len());
        for &kind in kinds {
            let result = match run(server.clone(), op_for(kind, query.clone())).await {
                Ok(Payload::SearchResults(r)) => Ok(r),
                Ok(_) => Err("unexpected reply".to_string()),
                Err(e) => Err(e),
            };
            out.push(ServerAnswer {
                server: server.clone(),
                kind,
                result,
            });
        }
        out
    });
    futures_util::future::join_all(per_server)
        .await
        .into_iter()
        .flatten()
        .collect()
}

/// Merges per-server answers into one sorted list.
pub fn merge(answers: Vec<ServerAnswer>, servers: u32) -> FleetResults {
    let mut out = FleetResults {
        servers,
        ..Default::default()
    };
    for a in answers {
        match a.result {
            Ok(r) => {
                if r.truncated {
                    out.truncated.push((a.server.clone(), a.kind));
                }
                out.hits.extend(r.hits.into_iter().map(|h| FleetHit {
                    server: a.server.clone(),
                    // The group is the op that was asked, whatever the
                    // agent labelled the hit.
                    kind: a.kind,
                    primary: h.primary,
                    detail: h.detail,
                }));
            }
            Err(message) => out.failures.push(Failure {
                server: a.server,
                kind: a.kind,
                message,
            }),
        }
    }
    out.hits.sort_by(|a, b| {
        rank(a.kind)
            .cmp(&rank(b.kind))
            .then_with(|| a.primary.to_lowercase().cmp(&b.primary.to_lowercase()))
            .then_with(|| a.server.as_str().cmp(b.server.as_str()))
            .then_with(|| a.detail.cmp(&b.detail))
    });
    if out.hits.len() > MAX_TOTAL_HITS {
        out.dropped = (out.hits.len() - MAX_TOTAL_HITS) as u32;
        out.hits.truncate(MAX_TOTAL_HITS);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_proto::args::{SearchTerm, TimeRange};
    use fleet_proto::payload::SearchHit;
    use std::cell::RefCell;

    fn sid(s: &str) -> ServerId {
        ServerId::new(s).unwrap()
    }

    fn query() -> SearchQuery {
        SearchQuery {
            term: SearchTerm::new("ssl").unwrap(),
            case_sensitive: false,
            roots: vec![],
            range: TimeRange::default(),
            limit: 100,
        }
    }

    fn hit(kind: SearchKind, p: &str) -> SearchHit {
        SearchHit {
            kind,
            primary: p.into(),
            detail: "d".into(),
        }
    }

    fn block_on<F: Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn fans_out_every_kind_to_every_server() {
        let calls = RefCell::new(Vec::new());
        let servers = vec![sid("srv_aaaaaaaaaaaa"), sid("srv_bbbbbbbbbbbb")];
        let answers = block_on(fan_out(servers, &KINDS, &query(), |s, op| {
            calls.borrow_mut().push((s.to_string(), op.name()));
            let bad = s.as_str() == "srv_bbbbbbbbbbbb";
            async move {
                if bad && op.name() == "search.files" {
                    return Err("timed out".into());
                }
                Ok(Payload::SearchResults(SearchResults {
                    hits: vec![hit(SearchKind::Package, &format!("{} hit", op.name()))],
                    truncated: false,
                }))
            }
        }));
        assert_eq!(calls.borrow().len(), 12);
        assert_eq!(answers.len(), 12);
        let merged = merge(answers, 2);
        assert_eq!(merged.hits.len(), 11);
        assert_eq!(merged.failures.len(), 1);
        assert_eq!(merged.failures[0].kind, SearchKind::File);
        // Grouped by the op asked, in KINDS order.
        let kinds: Vec<_> = merged.hits.iter().map(|h| h.kind).collect();
        let mut sorted = kinds.clone();
        sorted.sort_by_key(|k| rank(*k));
        assert_eq!(kinds, sorted);
        assert_eq!(merged.hits[0].primary, "search.packages hit");
    }

    #[test]
    fn merge_sorts_and_caps() {
        let a = sid("srv_aaaaaaaaaaaa");
        let b = sid("srv_bbbbbbbbbbbb");
        let ans = |s: &ServerId, k, hits: Vec<SearchHit>, truncated| ServerAnswer {
            server: s.clone(),
            kind: k,
            result: Ok(SearchResults { hits, truncated }),
        };
        let merged = merge(
            vec![
                ans(
                    &b,
                    SearchKind::Port,
                    vec![hit(SearchKind::Port, "tcp/443")],
                    false,
                ),
                ans(
                    &b,
                    SearchKind::Package,
                    vec![
                        hit(SearchKind::Package, "OpenSSL"),
                        hit(SearchKind::Package, "libssl3"),
                    ],
                    true,
                ),
                ans(
                    &a,
                    SearchKind::Package,
                    vec![hit(SearchKind::Package, "openssl")],
                    false,
                ),
                ServerAnswer {
                    server: a.clone(),
                    kind: SearchKind::Port,
                    result: Err("locked".into()),
                },
            ],
            2,
        );
        let got: Vec<_> = merged
            .hits
            .iter()
            .map(|h| (h.primary.as_str(), h.server.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("libssl3", "srv_bbbbbbbbbbbb"),
                ("openssl", "srv_aaaaaaaaaaaa"),
                ("OpenSSL", "srv_bbbbbbbbbbbb"),
                ("tcp/443", "srv_bbbbbbbbbbbb"),
            ]
        );
        assert_eq!(merged.truncated, [(b.clone(), SearchKind::Package)]);
        assert_eq!(merged.failures.len(), 1);

        let many = (0..MAX_TOTAL_HITS + 7)
            .map(|i| hit(SearchKind::User, &format!("u{i:05}")))
            .collect();
        let merged = merge(vec![ans(&a, SearchKind::User, many, false)], 1);
        assert_eq!(merged.hits.len(), MAX_TOTAL_HITS);
        assert_eq!(merged.dropped, 7);
    }

    #[test]
    fn unexpected_payload_is_a_failure() {
        let answers = block_on(fan_out(
            vec![sid("srv_aaaaaaaaaaaa")],
            &[SearchKind::User],
            &query(),
            |_, _| async { Ok(Payload::Empty) },
        ));
        assert!(answers[0].result.is_err());
    }
}
