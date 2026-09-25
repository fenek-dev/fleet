//! Agent side of fleet search (design §2.7): `search.packages`,
//! `search.ports`, `search.processes`, `search.files`, `search.journal`.
//! The Mac fans a query out and merges; each agent answers at most
//! `limit` hits (≤ 1000) with `truncated` when more matched or a bound
//! cut the search short.
//!
//! Matching is a literal substring of the term (ASCII case-folded unless
//! `case_sensitive`); `search.files` also takes `*`/`?` globs on the file
//! name. Sources are the other modules' own readers: [`crate::packages`]
//! (dpkg-query), [`crate::security::ports`] (`/proc/net`),
//! [`crate::telemetry::procs`] (`/proc/<pid>`), [`crate::logs::journal`]
//! (journalctl argv and JSON parsing). Everything returned is server data
//! (untrusted on the Mac). `search.users` belongs to the users module.
//!
//! The catalog marks these as requests, so each answer is one bounded
//! `Response`.

use crate::ctx::SysCtx;
use crate::files::Pacer;
use crate::files::walk::{Ev, Kind, MAX_WALK_DEPTH, WalkOpts, Walker, component_match, is_glob};
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, Registry};
use crate::logs::journal::{JOURNALCTL, Mode, QUERY_DEADLINE, journal_args, parse_line};
use crate::logs::{LineSpawner, SystemLineSpawner};
use crate::runner::CommandSpec;
use fleet_proto::args::{AbsPath, JournalQuery, SearchQuery};
use fleet_proto::op::tag;
use fleet_proto::payload::{SearchHit, SearchKind, SearchResults};
use fleet_proto::{ErrorCode, Op, Payload};
use std::rc::Rc;
use std::time::Duration;

pub const TAGS: [u16; 5] = [
    tag::SEARCH_PACKAGES,
    tag::SEARCH_PORTS,
    tag::SEARCH_PROCESSES,
    tag::SEARCH_FILES,
    tag::SEARCH_JOURNAL,
];

/// Roots `search.files` may walk; queries without roots use
/// [`DEFAULT_FILE_ROOTS`].
pub const FILE_ROOTS: &[&str] = &[
    "/etc",
    "/srv",
    "/opt",
    "/home",
    "/root",
    "/var",
    "/usr/local",
];
pub const DEFAULT_FILE_ROOTS: &[&str] = &["/etc", "/srv", "/opt", "/home"];
/// Entries one `search.files` walks (all roots together).
pub const MAX_FILE_ENTRIES: usize = 200_000;
pub const FILE_TIME_BUDGET: Duration = Duration::from_secs(10);
/// Journal lines one `search.journal` reads.
pub const MAX_JOURNAL_LINES: usize = 200_000;
/// Bytes of one hit's text.
pub const MAX_HIT_TEXT: usize = 1024;
/// Bytes of all hits (the frame is 1 MiB).
pub const MAX_REPLY_BYTES: usize = 768 * 1024;
const MAX_CMDLINE: usize = 512;

/// Term matcher.
pub struct Matcher {
    term: String,
    case_sensitive: bool,
}

impl Matcher {
    pub fn new(q: &SearchQuery) -> Self {
        let t = q.term.as_str();
        Self {
            term: if q.case_sensitive {
                t.to_owned()
            } else {
                t.to_ascii_lowercase()
            },
            case_sensitive: q.case_sensitive,
        }
    }

    pub fn matches(&self, s: &str) -> bool {
        if self.case_sensitive {
            s.contains(&self.term)
        } else {
            s.to_ascii_lowercase().contains(&self.term)
        }
    }

    /// File name: glob when the term has `*`/`?`, else substring.
    pub fn matches_name(&self, name: &str) -> bool {
        if is_glob(&self.term) {
            if self.case_sensitive {
                component_match(&self.term, name)
            } else {
                component_match(&self.term, &name.to_ascii_lowercase())
            }
        } else {
            self.matches(name)
        }
    }
}

fn clip(mut s: String) -> String {
    if s.len() > MAX_HIT_TEXT {
        let mut cut = MAX_HIT_TEXT;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
    s
}

/// Collects hits up to `limit` and the reply byte cap.
pub struct Hits {
    hits: Vec<SearchHit>,
    limit: usize,
    bytes: usize,
    truncated: bool,
}

impl Hits {
    pub fn new(limit: u32) -> Self {
        Self {
            hits: Vec::new(),
            limit: usize::try_from(limit).unwrap_or(usize::MAX),
            bytes: 0,
            truncated: false,
        }
    }

    /// `false` once full (the caller stops).
    pub fn push(&mut self, kind: SearchKind, primary: String, detail: String) -> bool {
        if self.full() {
            self.truncated = true;
            return false;
        }
        let (primary, detail) = (clip(primary), clip(detail));
        self.bytes += primary.len() + detail.len() + 8;
        if self.bytes > MAX_REPLY_BYTES {
            self.truncated = true;
            self.limit = self.hits.len();
            return false;
        }
        self.hits.push(SearchHit {
            kind,
            primary,
            detail,
        });
        true
    }

    pub fn full(&self) -> bool {
        self.hits.len() >= self.limit
    }

    pub fn cut(&mut self) {
        self.truncated = true;
    }

    pub fn done(self) -> SearchResults {
        SearchResults {
            hits: self.hits,
            truncated: self.truncated,
        }
    }
}

pub async fn packages(ctx: &SysCtx, q: &SearchQuery) -> Result<SearchResults, OpError> {
    let m = Matcher::new(q);
    let list = crate::packages::list(ctx, None).await?;
    let mut hits = Hits::new(q.limit);
    for p in list.packages {
        if (m.matches(&p.name) || m.matches(&p.version))
            && !hits.push(
                SearchKind::Package,
                p.name,
                format!("{} {}", p.version, p.arch),
            )
        {
            break;
        }
    }
    Ok(hits.done())
}

pub fn ports(ctx: &SysCtx, q: &SearchQuery) -> SearchResults {
    let m = Matcher::new(q);
    let mut hits = Hits::new(q.limit);
    for p in crate::security::ports::collect(ctx).ports {
        let proto = format!("{:?}", p.proto).to_ascii_lowercase();
        let primary = format!("{proto}/{}", p.port);
        let process = p.process.clone().unwrap_or_default();
        let user = p.user.clone().unwrap_or_default();
        let fields = [
            primary.as_str(),
            &p.port.to_string(),
            &p.addr.to_string(),
            &process,
            &user,
        ];
        if !fields.iter().any(|f| m.matches(f)) {
            continue;
        }
        let pid = p.pid.map(|x| x.to_string()).unwrap_or_else(|| "-".into());
        let detail = format!("{} pid {pid} {process} {user}", p.addr);
        if !hits.push(SearchKind::Port, primary, detail.trim_end().to_owned()) {
            break;
        }
    }
    hits.done()
}

fn cmdline(ctx: &SysCtx, pid: u32) -> String {
    let raw = ctx
        .procfs
        .read(&format!("/proc/{pid}/cmdline"))
        .unwrap_or_default();
    let s: String = raw
        .trim_end_matches('\0')
        .chars()
        .map(|c| if c == '\0' { ' ' } else { c })
        .filter(|c| !c.is_control())
        .take(MAX_CMDLINE)
        .collect();
    s
}

pub async fn processes(ctx: &SysCtx, q: &SearchQuery) -> SearchResults {
    let m = Matcher::new(q);
    let mut hits = Hits::new(q.limit);
    let mut buf = String::new();
    let mut pace = Pacer::new();
    for pid in crate::telemetry::procs::pids(ctx) {
        pace.tick().await;
        let Some(s) = crate::telemetry::procs::read_one(ctx, pid, false, &mut buf) else {
            continue;
        };
        let comm = s.stat.comm.clone();
        let cmd = cmdline(ctx, pid);
        if !(m.matches(&comm) || m.matches(&cmd) || m.matches(&pid.to_string())) {
            continue;
        }
        let detail = format!("pid {pid} uid {} rss {} {cmd}", s.uid, s.rss_bytes);
        if !hits.push(SearchKind::Process, comm, detail.trim_end().to_owned()) {
            break;
        }
    }
    hits.done()
}

fn file_roots(q: &SearchQuery) -> Result<Vec<String>, OpError> {
    if q.roots.is_empty() {
        return Ok(DEFAULT_FILE_ROOTS.iter().map(|s| (*s).to_owned()).collect());
    }
    let allowed: Vec<AbsPath> = FILE_ROOTS
        .iter()
        .filter_map(|r| AbsPath::new(*r).ok())
        .collect();
    q.roots
        .iter()
        .map(|r| {
            if allowed.iter().any(|a| r.is_under(a)) {
                Ok(r.as_str().to_owned())
            } else {
                Err(OpError::new(ErrorCode::InvalidArgument).with_detail("search root not allowed"))
            }
        })
        .collect()
}

pub async fn files(ctx: &SysCtx, q: &SearchQuery) -> Result<SearchResults, OpError> {
    let m = Matcher::new(q);
    let roots = file_roots(q)?;
    let mut hits = Hits::new(q.limit);
    let deadline = ctx.clock.monotonic() + FILE_TIME_BUDGET;
    let mut entries = 0usize;
    let mut pace = Pacer::new();
    'roots: for root in roots {
        let opts = WalkOpts::new(MAX_FILE_ENTRIES.saturating_sub(entries), MAX_WALK_DEPTH)
            .deadline(deadline);
        let mut w = match Walker::new(ctx, &root, opts) {
            Ok(w) => w,
            Err(e) if e.code() == ErrorCode::NotFound => continue,
            Err(e) => return Err(e),
        };
        while let Some(ev) = w.next() {
            pace.tick().await;
            let Ev::Entry(e) = ev else { continue };
            if e.depth == 0 {
                continue;
            }
            let name = e.path.rsplit('/').next().unwrap_or("");
            let t = e.meta.mtime_ms();
            if !m.matches_name(name)
                || q.range.since_ms.is_some_and(|s| t < s)
                || q.range.until_ms.is_some_and(|u| t >= u)
            {
                continue;
            }
            let kind = match e.meta.kind {
                Kind::File => "file",
                Kind::Dir => "dir",
                Kind::Symlink => "symlink",
                Kind::Other => "other",
            };
            let detail = format!("{kind} {} bytes mtime {t}", e.meta.size);
            if !hits.push(SearchKind::File, e.path, detail) {
                break 'roots;
            }
        }
        entries += w.entries();
        if w.truncated() {
            hits.cut();
        }
    }
    Ok(hits.done())
}

/// Newest entries first (`journalctl --reverse`), within `q.range`.
pub async fn journal(spawner: &dyn LineSpawner, q: &SearchQuery) -> Result<SearchResults, OpError> {
    let m = Matcher::new(q);
    let jq = JournalQuery {
        units: Vec::new(),
        priority: None,
        range: q.range,
        grep: None,
        after_cursor: None,
        limit: q.limit,
    };
    let spec = CommandSpec::new(JOURNALCTL).args(journal_args(&jq, Mode::Query));
    let mut src = spawner.spawn(spec).map_err(OpError::from)?;
    let deadline = tokio::time::Instant::now() + QUERY_DEADLINE;
    let mut hits = Hits::new(q.limit);
    let mut lines = 0usize;
    loop {
        if lines >= MAX_JOURNAL_LINES {
            hits.cut();
            break;
        }
        let Ok(next) = tokio::time::timeout_at(deadline, src.next_line()).await else {
            hits.cut();
            break;
        };
        let Some(line) = next else { break };
        let line = line.map_err(OpError::from)?;
        lines += 1;
        let Some(p) = parse_line(&line) else { continue };
        let e = p.entry;
        let source = e.unit.clone().or(e.identifier.clone()).unwrap_or_default();
        if !(m.matches(&e.message) || m.matches(&source)) {
            continue;
        }
        let pid = e.pid.map(|p| format!(" [{p}]")).unwrap_or_default();
        let detail = format!("{} {source}{pid} prio {}", e.time_us / 1000, e.priority);
        if !hits.push(SearchKind::Journal, e.message, detail) {
            break;
        }
    }
    // Dropping `src` stops journalctl.
    drop(src);
    Ok(hits.done())
}

pub struct SearchHandler {
    spawner: Rc<dyn LineSpawner>,
}

impl SearchHandler {
    pub fn new(spawner: Rc<dyn LineSpawner>) -> Self {
        Self { spawner }
    }
}

fn query_of(op: &Op) -> Option<&SearchQuery> {
    match op {
        Op::SearchPackages(q)
        | Op::SearchPorts(q)
        | Op::SearchProcesses(q)
        | Op::SearchFiles(q)
        | Op::SearchJournal(q) => Some(q),
        _ => None,
    }
}

impl OpHandler for SearchHandler {
    fn validate(&self, _ctx: &SysCtx, op: &Op, _meta: &OpMeta) -> Result<(), OpError> {
        let q = query_of(op).ok_or(ErrorCode::Unsupported)?;
        q.validate().map_err(ErrorCode::from)?;
        if let Op::SearchFiles(q) = op {
            file_roots(q)?;
        }
        Ok(())
    }

    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        op: &'a Op,
        _meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            let r = match op {
                Op::SearchPackages(q) => packages(ctx, q).await?,
                Op::SearchPorts(q) => ports(ctx, q),
                Op::SearchProcesses(q) => processes(ctx, q).await,
                Op::SearchFiles(q) => files(ctx, q).await?,
                Op::SearchJournal(q) => journal(self.spawner.as_ref(), q).await?,
                _ => return Err(ErrorCode::Unsupported.into()),
            };
            Ok(OpOutput::Payload(Payload::SearchResults(r)))
        })
    }
}

pub fn register(r: &mut Registry) {
    register_with(r, Rc::new(SystemLineSpawner));
}

pub fn register_with(r: &mut Registry, spawner: Rc<dyn LineSpawner>) {
    let h: Rc<dyn OpHandler> = Rc::new(SearchHandler::new(spawner));
    for t in TAGS {
        r.register(t, h.clone());
    }
}

#[cfg(test)]
mod tests;
