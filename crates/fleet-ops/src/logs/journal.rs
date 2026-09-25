//! `journal.query` and `journal.follow` (design §4.6): `journalctl -o json`
//! spawned with an argv built from the validated [`JournalQuery`]. Every
//! field of every entry is untrusted server data.
//!
//! - Query without a cursor reads newest-first (`--reverse`) and stops at
//!   `limit` matches, so "the last N lines of unit X" is cheap. With a
//!   cursor it reads forward from it (paging). Entries are returned oldest
//!   first either way, and `cursor` is the newest entry's.
//! - The [`GrepPattern`] is a literal substring match done here, never
//!   passed to `journalctl --grep` (PCRE: catastrophic backtracking).
//! - Follow runs `journalctl -f`, batches entries that arrive within
//!   [`FOLLOW_BATCH_WINDOW`], and kills the child when the stream is dropped.
//!
//! [`GrepPattern`]: fleet_proto::args::GrepPattern

use super::lines::{LineSource, LineSpawner};
use crate::ctx::SysCtx;
use crate::handler::{Invocation, LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, OpStream};
use crate::runner::CommandSpec;
use fleet_proto::args::JournalQuery;
use fleet_proto::payload::{JournalEntries, JournalEntry};
use fleet_proto::{ErrorCode, Op, Payload};
use serde_json::Value;
use std::ffi::OsString;
use std::rc::Rc;
use std::time::{Duration, Instant};

pub const JOURNALCTL: &str = "/usr/bin/journalctl";
/// Longest message kept per entry (characters); the rest is cut.
pub const MAX_MESSAGE: usize = 16 * 1024;
/// Longest unit/identifier kept.
const MAX_NAME: usize = 256;
/// Journal lines scanned per query before giving up on more matches
/// (a narrow grep over a huge journal must not run for minutes).
pub const MAX_SCAN: usize = 500_000;
pub const QUERY_DEADLINE: Duration = Duration::from_secs(20);
pub const FOLLOW_BATCH_WINDOW: Duration = Duration::from_millis(200);

/// Fields requested from journalctl (cursor and timestamps always come).
const OUTPUT_FIELDS: &str = "--output-fields=MESSAGE,PRIORITY,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,_PID";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Query,
    Follow,
}

/// The argv for `journalctl`. Each value is a single `--flag=value`
/// element, so no value can be read as another option.
pub fn journal_args(q: &JournalQuery, mode: Mode) -> Vec<OsString> {
    let mut a: Vec<OsString> = vec![
        "-o".into(),
        "json".into(),
        "--no-pager".into(),
        "--quiet".into(),
        OUTPUT_FIELDS.into(),
    ];
    for u in &q.units {
        a.push(format!("--unit={}", u.as_str()).into());
    }
    if let Some(p) = q.priority {
        a.push(format!("--priority={}", p as u8).into());
    }
    if let Some(s) = q.range.since_ms {
        a.push(format!("--since=@{}", s / 1000).into());
    }
    if let Some(u) = q.range.until_ms {
        a.push(format!("--until=@{}", u.div_ceil(1000)).into());
    }
    match (&q.after_cursor, mode) {
        (Some(c), _) => a.push(format!("--after-cursor={}", c.as_str()).into()),
        (None, Mode::Query) => a.push("--reverse".into()),
        (None, Mode::Follow) => a.push(format!("--lines={}", q.limit).into()),
    }
    if mode == Mode::Follow {
        a.push("--follow".into());
    }
    a
}

/// One parsed line: the entry plus its cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub entry: JournalEntry,
    pub cursor: Option<String>,
}

/// journald JSON values: a string, an array of bytes (non-UTF-8 or binary
/// data), `null` (field too large), or an array of those when a field
/// repeats (the first is taken).
fn field_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Array(items) => {
            if items.iter().all(Value::is_number) {
                let bytes: Vec<u8> = items
                    .iter()
                    .map(|n| {
                        n.as_u64()
                            .and_then(|n| u8::try_from(n).ok())
                            .unwrap_or(b'?')
                    })
                    .collect();
                Some(String::from_utf8_lossy(&bytes).into_owned())
            } else {
                items.first().and_then(field_text)
            }
        }
        _ => None,
    }
}

fn clip(s: String, max: usize) -> String {
    if s.len() <= max {
        s
    } else {
        s.chars().take(max).collect()
    }
}

/// Parses one `journalctl -o json` line; `None` for anything that isn't a
/// JSON object with a timestamp.
pub fn parse_line(line: &[u8]) -> Option<Parsed> {
    let v: Value = serde_json::from_slice(line).ok()?;
    let o = v.as_object()?;
    let text = |k: &str| o.get(k).and_then(field_text);
    let time_us = text("__REALTIME_TIMESTAMP")?.trim().parse().ok()?;
    let priority = text("PRIORITY")
        .and_then(|p| p.trim().parse::<u8>().ok())
        .filter(|p| *p <= 7)
        .unwrap_or(6);
    Some(Parsed {
        entry: JournalEntry {
            time_us,
            priority,
            unit: text("_SYSTEMD_UNIT").map(|s| clip(s, MAX_NAME)),
            identifier: text("SYSLOG_IDENTIFIER").map(|s| clip(s, MAX_NAME)),
            pid: text("_PID").and_then(|p| p.trim().parse().ok()),
            message: clip(text("MESSAGE").unwrap_or_default(), MAX_MESSAGE),
        },
        cursor: text("__CURSOR")
            .filter(|c| c.len() <= 512 && c.bytes().all(|b| b.is_ascii_graphic())),
    })
}

/// In-agent filters journalctl can't do safely: the literal grep and the
/// sub-second range edges.
pub fn matches(q: &JournalQuery, e: &JournalEntry) -> bool {
    let ms = e.time_us / 1000;
    if q.range.since_ms.is_some_and(|s| ms < s) || q.range.until_ms.is_some_and(|u| ms >= u) {
        return false;
    }
    q.grep
        .as_ref()
        .is_none_or(|g| e.message.contains(g.as_str()))
}

/// Reads lines from `src` until `limit` matches, EOF, [`MAX_SCAN`] or the
/// deadline. Returns matches in read order.
pub async fn collect(
    src: &mut dyn LineSource,
    q: &JournalQuery,
    limit: usize,
    deadline: Instant,
) -> Result<Vec<Parsed>, OpError> {
    let mut out = Vec::new();
    let mut scanned = 0usize;
    while out.len() < limit && scanned < MAX_SCAN {
        let left = deadline.saturating_duration_since(Instant::now());
        let Ok(next) = tokio::time::timeout(left, src.next_line()).await else {
            break;
        };
        let Some(line) = next else { break };
        let line = line.map_err(OpError::from)?;
        scanned += 1;
        if let Some(p) = parse_line(&line)
            && matches(q, &p.entry)
        {
            out.push(p);
        }
    }
    Ok(out)
}

fn to_payload(mut items: Vec<Parsed>, reversed: bool) -> Payload {
    if reversed {
        items.reverse();
    }
    let cursor = items.iter().rev().find_map(|p| p.cursor.clone());
    Payload::JournalEntries(JournalEntries {
        entries: items.into_iter().map(|p| p.entry).collect(),
        cursor,
    })
}

fn query_of(op: &Op) -> Option<&JournalQuery> {
    match op {
        Op::JournalQuery(q) | Op::JournalFollow(q) => Some(q),
        _ => None,
    }
}

/// `journal.query` (request) and `journal.follow` (stream).
pub struct JournalHandler {
    spawner: Rc<dyn LineSpawner>,
}

impl JournalHandler {
    pub fn new(spawner: Rc<dyn LineSpawner>) -> Self {
        Self { spawner }
    }
}

impl OpHandler for JournalHandler {
    fn supports(&self, op: &Op, invocation: Invocation) -> bool {
        matches!(
            (op, invocation),
            (Op::JournalQuery(_), Invocation::Request) | (Op::JournalFollow(_), Invocation::Stream)
        )
    }

    fn validate(&self, _ctx: &SysCtx, op: &Op, _meta: &OpMeta) -> Result<(), OpError> {
        let q = query_of(op).ok_or(ErrorCode::Unsupported)?;
        q.validate().map_err(ErrorCode::from)?;
        Ok(())
    }

    fn handle<'a>(
        &'a self,
        _ctx: &'a SysCtx,
        op: &'a Op,
        _meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            let q = query_of(op).ok_or(ErrorCode::Unsupported)?;
            let mode = if matches!(op, Op::JournalFollow(_)) {
                Mode::Follow
            } else {
                Mode::Query
            };
            let spec = CommandSpec::new(JOURNALCTL).args(journal_args(q, mode));
            let mut src = self.spawner.spawn(spec).map_err(OpError::from)?;
            let limit = usize::try_from(q.limit).unwrap_or(usize::MAX);
            match mode {
                Mode::Query => {
                    let deadline = Instant::now() + QUERY_DEADLINE;
                    let items = collect(src.as_mut(), q, limit, deadline).await?;
                    // Dropping `src` kills journalctl if it is still writing.
                    drop(src);
                    Ok(OpOutput::Payload(to_payload(
                        items,
                        q.after_cursor.is_none(),
                    )))
                }
                Mode::Follow => Ok(OpOutput::Stream(Box::new(JournalFollow {
                    src,
                    q: q.clone(),
                    limit,
                }))),
            }
        })
    }
}

/// `journal.follow`: one item per batch of new entries.
pub struct JournalFollow {
    src: Box<dyn LineSource>,
    q: JournalQuery,
    limit: usize,
}

impl OpStream for JournalFollow {
    fn next(&mut self) -> LocalBoxFuture<'_, Option<Result<Payload, OpError>>> {
        Box::pin(async move {
            let mut batch = Vec::new();
            // Wait as long as it takes for the first matching entry…
            loop {
                match self.src.next_line().await {
                    None => return None,
                    Some(Err(e)) => return Some(Err(e.into())),
                    Some(Ok(l)) => {
                        if let Some(p) = parse_line(&l).filter(|p| matches(&self.q, &p.entry)) {
                            batch.push(p);
                            break;
                        }
                    }
                }
            }
            // …then gather whatever else arrives within the batch window.
            let deadline = Instant::now() + FOLLOW_BATCH_WINDOW;
            if batch.len() < self.limit {
                match collect(
                    self.src.as_mut(),
                    &self.q,
                    self.limit - batch.len(),
                    deadline,
                )
                .await
                {
                    Ok(more) => batch.extend(more),
                    Err(e) => return Some(Err(e)),
                }
            }
            Some(Ok(to_payload(batch, false)))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logs::lines::FakeLineSpawner;
    use crate::testutil::{T0, block, ctx_empty, meta_at};
    use fleet_proto::args::{GrepPattern, JournalCursor, Priority, TimeRange, UnitName};

    const SAMPLE: &[&str] = &[
        r#"{"__CURSOR":"s=a;i=1","__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"6","_SYSTEMD_UNIT":"ssh.service","SYSLOG_IDENTIFIER":"sshd","_PID":"812","MESSAGE":"Server listening on 0.0.0.0 port 22."}"#,
        "not json at all",
        r#"{"__CURSOR":"s=a;i=2","__REALTIME_TIMESTAMP":"1700000001000000","PRIORITY":"3","MESSAGE":[104,105,255,10,0]}"#,
        r#"{"__CURSOR":"s=a;i=3","__REALTIME_TIMESTAMP":"1700000002000000","MESSAGE":null,"_PID":"x"}"#,
        r#"{"__CURSOR":"s=a;i=4","__REALTIME_TIMESTAMP":"1700000003000000","MESSAGE":["first","second"],"PRIORITY":"99"}"#,
        r#"["array"]"#,
        r#"{"MESSAGE":"no timestamp"}"#,
    ];

    fn q(limit: u32) -> JournalQuery {
        JournalQuery {
            units: vec![],
            priority: None,
            range: TimeRange::default(),
            grep: None,
            after_cursor: None,
            limit,
        }
    }

    #[test]
    fn parses_untrusted_lines() {
        let parsed: Vec<_> = SAMPLE
            .iter()
            .filter_map(|l| parse_line(l.as_bytes()))
            .collect();
        assert_eq!(parsed.len(), 4);
        let e = &parsed[0].entry;
        assert_eq!(e.time_us, 1_700_000_000_000_000);
        assert_eq!((e.priority, e.pid), (6, Some(812)));
        assert_eq!(e.unit.as_deref(), Some("ssh.service"));
        assert_eq!(e.identifier.as_deref(), Some("sshd"));
        assert_eq!(parsed[1].entry.message, "hi\u{fffd}\n\0");
        assert_eq!(parsed[1].entry.priority, 3);
        assert_eq!(
            (parsed[2].entry.message.as_str(), parsed[2].entry.pid),
            ("", None)
        );
        assert_eq!(parsed[3].entry.message, "first");
        assert_eq!(parsed[3].entry.priority, 6);
        assert_eq!(parsed[3].cursor.as_deref(), Some("s=a;i=4"));
        let huge = format!(
            r#"{{"__REALTIME_TIMESTAMP":"1","MESSAGE":"{}"}}"#,
            "x".repeat(MAX_MESSAGE + 10)
        );
        assert_eq!(
            parse_line(huge.as_bytes()).unwrap().entry.message.len(),
            MAX_MESSAGE
        );
    }

    #[test]
    fn argv_from_query() {
        let mut query = q(50);
        query.units = vec![
            UnitName::new("ssh.service").unwrap(),
            UnitName::new("nginx.service").unwrap(),
        ];
        query.priority = Some(Priority::Warning);
        query.range = TimeRange {
            since_ms: Some(1_700_000_000_500),
            until_ms: Some(1_700_000_001_001),
        };
        query.grep = Some(GrepPattern::new("--help; rm -rf /").unwrap());
        let a: Vec<String> = journal_args(&query, Mode::Query)
            .into_iter()
            .map(|s| s.into_string().unwrap())
            .collect();
        assert_eq!(
            a,
            [
                "-o",
                "json",
                "--no-pager",
                "--quiet",
                OUTPUT_FIELDS,
                "--unit=ssh.service",
                "--unit=nginx.service",
                "--priority=4",
                "--since=@1700000000",
                "--until=@1700000002",
                "--reverse"
            ]
        );
        // Grep never reaches journalctl.
        assert!(!a.iter().any(|s| s.contains("rm -rf")));
        query.after_cursor = Some(JournalCursor::new("s=a;i=9").unwrap());
        let a = journal_args(&query, Mode::Follow);
        assert!(a.ends_with(&["--after-cursor=s=a;i=9".into(), "--follow".into()]));
        let a = journal_args(&q(7), Mode::Follow);
        assert!(a.ends_with(&["--lines=7".into(), "--follow".into()]));
    }

    fn base_args(extra: &[&'static str]) -> Vec<&'static str> {
        let mut v = vec!["-o", "json", "--no-pager", "--quiet", OUTPUT_FIELDS];
        v.extend_from_slice(extra);
        v
    }

    #[test]
    fn query_reverse_limit_and_grep() {
        let sp = Rc::new(FakeLineSpawner::new());
        // Newest first, as `--reverse` prints.
        let lines: Vec<&str> = SAMPLE.iter().rev().copied().collect();
        sp.expect(JOURNALCTL, &base_args(&["--reverse"]), &lines, false);
        let h = JournalHandler::new(sp.clone());
        let c = ctx_empty();
        let op = Op::JournalQuery(q(2));
        h.validate(&c, &op, &meta_at(Op::SystemInfo, Some(1), T0))
            .unwrap();
        let out = block(h.handle(&c, &op, &meta_at(Op::SystemInfo, Some(1), T0))).unwrap();
        let OpOutput::Payload(Payload::JournalEntries(j)) = out else {
            panic!()
        };
        // The two newest, returned oldest first; cursor = newest.
        assert_eq!(
            j.entries
                .iter()
                .map(|e| e.time_us / 1_000_000)
                .collect::<Vec<_>>(),
            [1_700_000_002, 1_700_000_003]
        );
        assert_eq!(j.cursor.as_deref(), Some("s=a;i=4"));

        let mut g = q(10);
        g.grep = Some(GrepPattern::new("listening").unwrap());
        sp.expect(JOURNALCTL, &base_args(&["--reverse"]), SAMPLE, false);
        let out = block(h.handle(
            &c,
            &Op::JournalQuery(g),
            &meta_at(Op::SystemInfo, Some(1), T0),
        ))
        .unwrap();
        let OpOutput::Payload(Payload::JournalEntries(j)) = out else {
            panic!()
        };
        assert_eq!(j.entries.len(), 1);

        assert!(
            h.validate(
                &c,
                &Op::JournalQuery(q(0)),
                &meta_at(Op::SystemInfo, Some(1), T0)
            )
            .is_err()
        );
        assert!(h.supports(&Op::JournalFollow(q(1)), Invocation::Stream));
        assert!(!h.supports(&Op::JournalFollow(q(1)), Invocation::Request));
    }

    #[test]
    fn follow_batches_and_kills_on_drop() {
        let sp = Rc::new(FakeLineSpawner::new());
        sp.expect(
            JOURNALCTL,
            &base_args(&["--lines=3", "--follow"]),
            SAMPLE,
            true,
        );
        let h = JournalHandler::new(sp.clone());
        let c = ctx_empty();
        let out = block(h.handle(
            &c,
            &Op::JournalFollow(q(3)),
            &meta_at(Op::SystemInfo, Some(1), T0),
        ))
        .unwrap();
        let OpOutput::Stream(mut s) = out else {
            panic!()
        };
        block(async {
            let Some(Ok(Payload::JournalEntries(b))) = s.next().await else {
                panic!()
            };
            assert_eq!(b.entries.len(), 3);
            let Some(Ok(Payload::JournalEntries(b))) = s.next().await else {
                panic!()
            };
            assert_eq!(b.entries.len(), 1);
            // Nothing more: next() waits; a timeout stands in for cancel.
            assert!(
                tokio::time::timeout(Duration::from_millis(50), s.next())
                    .await
                    .is_err()
            );
        });
        assert_eq!(sp.dropped.get(), 0);
        drop(s);
        assert_eq!(sp.dropped.get(), 1);
    }
}
