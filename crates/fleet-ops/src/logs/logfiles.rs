//! `logfiles.list` (design §4.2 `logs` group): the regular files under the
//! `logfile.tail` allow-list roots (`/var/log`), with size and mtime, so
//! the Mac can offer what may be tailed. The denied paths (binary login
//! databases, the journal, `/var/log/private`) are left out and their
//! directories not entered. Symlinks are never followed (the walker reports
//! them as symlinks; they aren't listed, `logfile.tail` refuses them).
//!
//! Bounded: at most [`MAX_WALK_ENTRIES`] entries visited, [`MAX_DEPTH`]
//! levels, [`MAX_FILES`] files returned (by path).

use super::logfile::{DEFAULT_ROOTS, DENIED};
use crate::ctx::SysCtx;
use crate::files::walk::{Ev, Kind, WalkOpts, Walker};
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput};
use fleet_proto::payload::{LogFile, LogFiles};
use fleet_proto::{ErrorCode, Op, Payload};
use std::time::Duration;

pub const MAX_FILES: usize = 2000;
pub const MAX_WALK_ENTRIES: usize = 20_000;
pub const MAX_DEPTH: usize = 6;
const TIME_BUDGET: Duration = Duration::from_secs(5);

fn denied(path: &str) -> bool {
    DENIED
        .iter()
        .any(|d| path == *d || path.strip_prefix(d).is_some_and(|r| r.starts_with('/')))
}

/// Lists the log files under `roots`.
pub fn list(ctx: &SysCtx, roots: &[&str]) -> Result<LogFiles, OpError> {
    let mut files = Vec::new();
    for root in roots {
        let opts = WalkOpts::new(MAX_WALK_ENTRIES, MAX_DEPTH)
            .deadline(ctx.clock.monotonic() + TIME_BUDGET);
        let mut w = match Walker::new(ctx, root, opts) {
            Ok(w) => w,
            Err(e) if e.code() == ErrorCode::NotFound => continue,
            Err(e) => return Err(e),
        };
        while let Some(ev) = w.next() {
            let Ev::Entry(e) = ev else { continue };
            if denied(&e.path) {
                if e.meta.kind == Kind::Dir {
                    w.prune();
                }
                continue;
            }
            if e.meta.kind == Kind::File {
                files.push(LogFile {
                    path: e.path,
                    size_bytes: e.meta.size,
                    mtime_ms: e.meta.mtime_ms(),
                });
            }
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    files.truncate(MAX_FILES);
    Ok(LogFiles { files })
}

/// `logfiles.list` over [`DEFAULT_ROOTS`].
pub struct LogfilesListHandler;

impl OpHandler for LogfilesListHandler {
    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        _op: &'a Op,
        _meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            // Synchronous and bounded (entries, depth, deadline).
            Ok(OpOutput::Payload(Payload::LogFiles(list(
                ctx,
                DEFAULT_ROOTS,
            )?)))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FakeRunner;
    use crate::testutil::{T0, block, ctx_at, meta};
    use std::rc::Rc;

    #[test]
    fn lists_allowed_files_only() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        for sub in ["var/log/nginx", "var/log/journal/abc", "var/log/private/x"] {
            std::fs::create_dir_all(d.join(sub)).unwrap();
        }
        std::fs::create_dir_all(d.join("etc")).unwrap();
        std::fs::write(d.join("etc/shadow"), "s").unwrap();
        std::fs::write(d.join("var/log/syslog"), "12345").unwrap();
        std::fs::write(d.join("var/log/nginx/access.log"), "a").unwrap();
        std::fs::write(d.join("var/log/btmp"), "secret").unwrap();
        std::fs::write(d.join("var/log/journal/abc/system.journal"), "j").unwrap();
        std::fs::write(d.join("var/log/private/x/y.log"), "p").unwrap();
        std::os::unix::fs::symlink(d.join("etc/shadow"), d.join("var/log/evil")).unwrap();
        let c = ctx_at(d, Rc::new(FakeRunner::new()), T0);
        let out = block(LogfilesListHandler.handle(&c, &Op::LogfilesList, &meta(Op::LogfilesList, None)))
            .unwrap();
        let OpOutput::Payload(Payload::LogFiles(l)) = out else {
            panic!()
        };
        let paths: Vec<&str> = l.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["/var/log/nginx/access.log", "/var/log/syslog"]);
        assert_eq!(l.files[1].size_bytes, 5);
        // No /var/log at all: empty, not an error.
        let empty = tempfile::tempdir().unwrap();
        let c = ctx_at(empty.path(), Rc::new(FakeRunner::new()), T0);
        assert!(list(&c, DEFAULT_ROOTS).unwrap().files.is_empty());
    }
}
