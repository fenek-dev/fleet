//! `weblog.query` (design §2.4, §4.6): parsed JSON access logs of Caddy
//! (`http.log.access`) and nginx (the web role's `fleet_json` format),
//! newest first, filtered by time, status range, path prefix and client,
//! with per-status, top-client and top-path counts.
//!
//! Every byte is attacker-influenced (security rule 6): lines are parsed
//! with [`webscan::parse_strict_json`] (duplicate keys refused), fields are
//! length-capped, nothing is interpreted. The files are opened with
//! [`open_nofollow`] like `logfile.tail`.
//!
//! Bounded: the last [`MAX_SCAN_BYTES`] of each log (current and `.1`),
//! [`MAX_SCAN_LINES`] lines overall; `truncated` says a bound was hit.
//! Logs are chronological, so reading a file backwards stops at the first
//! line older than `range.since_ms`.

use super::logfile::open_nofollow;
use crate::ctx::SysCtx;
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput};
use crate::security::utmp::parse_iso8601_ms;
use crate::security::webscan::{AccessHit, is_scanner_probe, parse_strict_json};
use fleet_proto::args::{HttpPath, TimeRange};
use fleet_proto::op::StatusRange;
use fleet_proto::payload::{WebLogEntry, WebLogSummary};
use fleet_proto::{ErrorCode, Op, Payload};
use serde_json::Value;
use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom};
use std::net::IpAddr;

/// Access logs read, newest file first per server (`.1` is the previous).
pub const DEFAULT_LOGS: &[&str] = &[
    "/var/log/caddy/access.log",
    "/var/log/caddy/access.log.1",
    "/var/log/nginx/access.log",
    "/var/log/nginx/access.log.1",
];
pub const MAX_SCAN_BYTES: u64 = 8 << 20;
pub const MAX_SCAN_LINES: usize = 200_000;
const MAX_LINE: usize = 64 * 1024;
const TOP_N: usize = 10;
const MAX_METHOD: usize = 16;
const MAX_PATH: usize = 1024;
const MAX_AGENT: usize = 256;

/// The filters of one query.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub range: TimeRange,
    pub status: Option<StatusRange>,
    pub path_prefix: Option<String>,
    pub client: Option<IpAddr>,
}

impl Filter {
    fn matches(&self, e: &WebLogEntry, time: Option<u64>) -> bool {
        let in_range = match (time, self.range.since_ms, self.range.until_ms) {
            (_, None, None) => true,
            (None, _, _) => false,
            (Some(t), since, until) => since.is_none_or(|s| t >= s) && until.is_none_or(|u| t < u),
        };
        in_range
            && self.status.is_none_or(|s| s.contains(e.status))
            && self
                .path_prefix
                .as_deref()
                .is_none_or(|p| e.path.starts_with(p))
            && self.client.is_none_or(|c| c == e.client)
    }
}

fn clip(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter().try_fold(v, |v, k| v.get(k))?.as_str()
}

fn num_at(v: &Value, key: &str) -> Option<u64> {
    match v.get(key)? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Time of a line: Caddy `ts` (float seconds), nginx `time` (ISO 8601).
fn time_of(v: &Value) -> Option<u64> {
    if let Some(ts) = v.get("ts").and_then(Value::as_f64) {
        return (ts.is_finite() && ts >= 0.0).then_some((ts * 1000.0) as u64);
    }
    parse_iso8601_ms(str_at(v, &["time"])?)
}

/// One Caddy or nginx (`fleet_json`) JSON line; `None` if it isn't one.
/// Returns the entry and its time (if the line has one).
pub fn parse_line(line: &[u8], log: &str) -> Option<(WebLogEntry, Option<u64>)> {
    if line.len() > MAX_LINE {
        return None;
    }
    let v = parse_strict_json(line)?;
    let client: IpAddr = str_at(&v, &["request", "client_ip"])
        .or_else(|| str_at(&v, &["request", "remote_ip"]))
        .or_else(|| str_at(&v, &["remote_addr"]))
        .or_else(|| str_at(&v, &["remote"]))
        .or_else(|| str_at(&v, &["client_ip"]))?
        .parse()
        .ok()?;
    let uri = str_at(&v, &["request", "uri"])
        .or_else(|| str_at(&v, &["request_uri"]))
        .or_else(|| str_at(&v, &["uri"]))?;
    let path = uri.split(['?', '#']).next().unwrap_or("");
    let method = str_at(&v, &["request", "method"])
        .or_else(|| str_at(&v, &["method"]))
        .or_else(|| str_at(&v, &["request_method"]))
        .unwrap_or("");
    let status = u16::try_from(num_at(&v, "status")?).ok()?;
    let bytes = num_at(&v, "size")
        .or_else(|| num_at(&v, "bytes"))
        .or_else(|| num_at(&v, "body_bytes_sent"))
        .unwrap_or(0);
    let agent = v
        .get("request")
        .and_then(|r| r.get("headers"))
        .and_then(|h| h.get("User-Agent"))
        .and_then(|a| a.get(0))
        .and_then(Value::as_str)
        .or_else(|| str_at(&v, &["agent"]))
        .or_else(|| str_at(&v, &["http_user_agent"]))
        .filter(|a| !a.is_empty());
    let time = time_of(&v);
    Some((
        WebLogEntry {
            time_ms: time.unwrap_or(0),
            client,
            method: clip(method, MAX_METHOD),
            path: clip(path, MAX_PATH),
            status,
            bytes,
            user_agent: agent.map(|a| clip(a, MAX_AGENT)),
            log: log.to_owned(),
        },
        time,
    ))
}

/// The last `MAX_SCAN_BYTES` of `f`; `true` when the file is longer.
fn read_tail(f: &mut std::fs::File) -> io::Result<(Vec<u8>, bool)> {
    let len = f.seek(SeekFrom::End(0))?;
    let start = len.saturating_sub(MAX_SCAN_BYTES);
    f.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    f.take(MAX_SCAN_BYTES).read_to_end(&mut buf)?;
    if start > 0 {
        // Drop the partial first line.
        let cut = buf.iter().position(|b| *b == b'\n').map_or(buf.len(), |i| i + 1);
        buf.drain(..cut);
    }
    Ok((buf, start > 0))
}

#[derive(Default)]
struct Acc {
    requests: u64,
    by_status: HashMap<u16, u64>,
    clients: HashMap<IpAddr, u64>,
    paths: HashMap<String, u64>,
    scanner_hits: u64,
    entries: Vec<WebLogEntry>,
    lines: usize,
    truncated: bool,
}

fn top<K: Clone + Ord>(m: HashMap<K, u64>) -> Vec<(K, u64)> {
    let mut v: Vec<(K, u64)> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.truncate(TOP_N);
    v
}

/// Runs the query over `logs` (absolute paths under the context root).
pub fn query(
    ctx: &SysCtx,
    logs: &[&str],
    filter: &Filter,
    limit: usize,
) -> Result<WebLogSummary, OpError> {
    let mut acc = Acc::default();
    'files: for log in logs {
        let mut f = match open_nofollow(ctx, log) {
            Ok((f, _)) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            // A symlinked or hard-linked log is skipped, never followed.
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => continue,
            Err(e) => return Err(OpError::internal(format!("open {log}: {e}"))),
        };
        let (buf, cut) = read_tail(&mut f).map_err(|e| OpError::internal(format!("read {log}: {e}")))?;
        acc.truncated |= cut;
        let mut kept = 0usize;
        for line in buf.split(|b| *b == b'\n').rev() {
            if line.is_empty() {
                continue;
            }
            if acc.lines >= MAX_SCAN_LINES {
                acc.truncated = true;
                break 'files;
            }
            acc.lines += 1;
            let Some((e, time)) = parse_line(line, log) else {
                continue;
            };
            if let (Some(t), Some(s)) = (time, filter.range.since_ms)
                && t < s
            {
                // Older lines follow: this file is done.
                continue 'files;
            }
            if !filter.matches(&e, time) {
                continue;
            }
            acc.requests += 1;
            *acc.by_status.entry(e.status).or_default() += 1;
            *acc.clients.entry(e.client).or_default() += 1;
            *acc.paths.entry(e.path.clone()).or_default() += 1;
            let hit = AccessHit {
                ip: e.client,
                path: e.path.to_ascii_lowercase(),
                status: e.status,
            };
            if is_scanner_probe(&hit) {
                acc.scanner_hits += 1;
            }
            // Keep the newest `limit` of each file; merged below.
            if kept < limit {
                kept += 1;
                acc.entries.push(e);
            }
        }
    }
    let mut entries = acc.entries;
    entries.sort_by_key(|e| std::cmp::Reverse(e.time_ms));
    entries.truncate(limit);
    let mut by_status: Vec<(u16, u64)> = acc.by_status.into_iter().collect();
    by_status.sort();
    Ok(WebLogSummary {
        requests: acc.requests,
        by_status,
        top_clients: top(acc.clients),
        top_paths: top(acc.paths),
        scanner_hits: acc.scanner_hits,
        entries,
        truncated: acc.truncated,
    })
}

/// `weblog.query` over [`DEFAULT_LOGS`].
pub struct WeblogHandler {
    logs: Vec<String>,
}

impl Default for WeblogHandler {
    fn default() -> Self {
        Self::new(DEFAULT_LOGS.iter().map(|s| (*s).to_owned()).collect())
    }
}

impl WeblogHandler {
    pub fn new(logs: Vec<String>) -> Self {
        Self { logs }
    }
}

fn filter_of(op: &Op) -> Option<(Filter, usize)> {
    let Op::WeblogQuery {
        range,
        limit,
        status,
        path_prefix,
        client,
    } = op
    else {
        return None;
    };
    Some((
        Filter {
            range: *range,
            status: *status,
            path_prefix: path_prefix.as_ref().map(|p: &HttpPath| p.as_str().to_owned()),
            client: *client,
        },
        usize::try_from(*limit).unwrap_or(usize::MAX),
    ))
}

impl OpHandler for WeblogHandler {
    fn validate(&self, _ctx: &SysCtx, op: &Op, _meta: &OpMeta) -> Result<(), OpError> {
        filter_of(op).map(drop).ok_or(ErrorCode::Unsupported.into())
    }

    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        op: &'a Op,
        _meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            let (filter, limit) = filter_of(op).ok_or(ErrorCode::Unsupported)?;
            let logs: Vec<&str> = self.logs.iter().map(String::as_str).collect();
            let s = query(ctx, &logs, &filter, limit)?;
            Ok(OpOutput::Payload(Payload::WebLogSummary(s)))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FakeRunner;
    use crate::testutil::{T0, block, ctx_at, meta};
    use proptest::prelude::*;
    use std::rc::Rc;

    const CADDY: &str = "/var/log/caddy/access.log";
    const NGINX: &str = "/var/log/nginx/access.log";

    fn caddy(ts_s: u64, ip: &str, uri: &str, status: u16) -> String {
        format!(
            r#"{{"level":"info","ts":{ts_s}.5,"logger":"http.log.access","request":{{"remote_ip":"10.0.0.1","client_ip":"{ip}","method":"GET","uri":"{uri}","headers":{{"User-Agent":["curl/8"]}}}},"status":{status},"size":42}}"#
        )
    }

    fn nginx(time: &str, ip: &str, uri: &str, status: u16) -> String {
        format!(
            r#"{{"time":"{time}","remote":"{ip}","host":"x","method":"POST","uri":"{uri}","status":{status},"bytes":7,"agent":"","rt":0.001}}"#
        )
    }

    fn fixture() -> (tempfile::TempDir, SysCtx) {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::create_dir_all(d.join("var/log/caddy")).unwrap();
        std::fs::create_dir_all(d.join("var/log/nginx")).unwrap();
        let t = T0 / 1000;
        let lines = [
            caddy(t, "198.51.100.4", "/index.html?x=1", 200),
            caddy(t + 1, "198.51.100.4", "/.env", 404),
            "not json".to_owned(),
            r#"{"remote_addr":"192.0.2.1","remote_addr":"192.0.2.2","request_uri":"/","status":200}"#.to_owned(),
            caddy(t + 2, "203.0.113.9", "/api/v1/users", 500),
        ];
        std::fs::write(d.join(&CADDY[1..]), lines.join("\n") + "\n").unwrap();
        std::fs::write(
            d.join(&NGINX[1..]),
            nginx("2023-11-14T22:13:23+00:00", "2001:db8::5", "/api/login", 401) + "\n",
        )
        .unwrap();
        let c = ctx_at(d, Rc::new(FakeRunner::new()), T0);
        (dir, c)
    }

    #[test]
    fn parses_both_formats() {
        let (e, t) = parse_line(caddy(1_700_000_000, "198.51.100.4", "/a?b", 404).as_bytes(), CADDY).unwrap();
        assert_eq!((e.path.as_str(), e.status, e.bytes, t), ("/a", 404, 42, Some(1_700_000_000_500)));
        assert_eq!(e.user_agent.as_deref(), Some("curl/8"));
        let (e, t) = parse_line(
            nginx("2023-11-14T22:13:20+00:00", "2001:db8::5", "/x", 200).as_bytes(),
            NGINX,
        )
        .unwrap();
        assert_eq!((e.method.as_str(), e.client.to_string().as_str(), t), ("POST", "2001:db8::5", Some(T0)));
        assert_eq!(e.user_agent, None);
        assert!(parse_line(b"127.0.0.1 - - [x] \"GET /\" 200", NGINX).is_none());
    }

    #[test]
    fn filters_and_aggregates() {
        let (_d, c) = fixture();
        let logs = [CADDY, NGINX];
        let all = query(&c, &logs, &Filter::default(), 100).unwrap();
        assert_eq!(all.requests, 4);
        assert_eq!(all.entries[0].path, "/api/login", "newest first");
        assert_eq!(all.scanner_hits, 1);
        assert_eq!(all.top_clients[0], ("198.51.100.4".parse().unwrap(), 2));
        assert!(!all.truncated);
        let f = Filter {
            status: Some(StatusRange { min: 400, max: 499 }),
            ..Filter::default()
        };
        let s = query(&c, &logs, &f, 100).unwrap();
        assert_eq!(s.by_status, vec![(401, 1), (404, 1)]);
        let f = Filter {
            path_prefix: Some("/api/".into()),
            client: Some("203.0.113.9".parse().unwrap()),
            ..Filter::default()
        };
        let s = query(&c, &logs, &f, 100).unwrap();
        assert_eq!(s.requests, 1);
        assert_eq!(s.entries[0].status, 500);
        let f = Filter {
            range: TimeRange {
                since_ms: Some(T0 + 1000),
                until_ms: Some(T0 + 2000),
            },
            ..Filter::default()
        };
        let s = query(&c, &logs, &f, 100).unwrap();
        assert_eq!(s.entries.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(), ["/.env"]);
        let s = query(&c, &logs, &Filter::default(), 1).unwrap();
        assert_eq!((s.entries.len(), s.requests), (1, 4));
    }

    #[test]
    fn handler_and_symlinks() {
        let (d, c) = fixture();
        std::fs::write(d.path().join("secret"), caddy(1, "192.0.2.1", "/s", 200)).unwrap();
        std::os::unix::fs::symlink(d.path().join("secret"), d.path().join("var/log/nginx/access.log.1"))
            .unwrap();
        let op = Op::WeblogQuery {
            range: TimeRange::default(),
            limit: 10,
            status: None,
            path_prefix: None,
            client: None,
        };
        let h = WeblogHandler::default();
        h.validate(&c, &op, &meta(op.clone(), None)).unwrap();
        let OpOutput::Payload(Payload::WebLogSummary(s)) =
            block(h.handle(&c, &op, &meta(op.clone(), Some(1)))).unwrap()
        else {
            panic!()
        };
        assert_eq!(s.requests, 4, "the symlinked log is skipped");
    }

    proptest! {
        #[test]
        fn never_panics(b in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse_line(&b, CADDY);
        }
    }
}
