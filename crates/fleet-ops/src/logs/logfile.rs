//! `logfile.tail` (design §4.2): the last N lines of an allow-listed log
//! file, then (with `follow`) new lines as they are written, surviving
//! rotation (inode change) and truncation.
//!
//! Opening is symlink-safe without `unsafe`: every directory component
//! below the context root is checked with `lstat` (no symlinks, must be a
//! directory) and the file itself is opened with `O_NOFOLLOW | O_NONBLOCK`
//! and must be a regular file. (`openat2(RESOLVE_BENEATH)` would close the
//! remaining check-then-open window; that needs a syscall crate.)

use crate::ctx::SysCtx;
use crate::handler::{Invocation, LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, OpStream};
use fleet_proto::args::{AbsPath, AllowedPath};
use fleet_proto::payload::LogLines;
use fleet_proto::{ErrorCode, Op, Payload};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use std::time::Duration;

pub const MAX_LINES: u16 = 10_000;
/// Longest line sent (characters); longer lines are cut.
pub const MAX_LINE_CHARS: usize = 16 * 1024;
/// Bytes read backwards from the end for the initial tail.
pub const MAX_TAIL_BYTES: u64 = 8 << 20;
/// Bytes read per follow poll.
const MAX_POLL_BYTES: u64 = 1 << 20;
/// Lines per stream item.
const BATCH_LINES: usize = 1000;
pub const DEFAULT_POLL: Duration = Duration::from_secs(1);

/// Default allow-list roots.
pub const DEFAULT_ROOTS: &[&str] = &["/var/log"];
/// Never tailed even under an allowed root: binary login databases (btmp
/// holds mistyped passwords entered as user names) and the journal files.
pub const DENIED: &[&str] = &[
    "/var/log/btmp",
    "/var/log/wtmp",
    "/var/log/lastlog",
    "/var/log/journal",
    "/var/log/private",
];

/// Opens `abs` under the context root for reading without following any
/// symlink below the root. The file must be a regular file.
pub fn open_nofollow(ctx: &SysCtx, abs: &str) -> io::Result<(File, PathBuf)> {
    let full = ctx.path(abs).ok_or(io::ErrorKind::InvalidInput)?;
    let mut dir = ctx.root().to_path_buf();
    let comps: Vec<&str> = abs.split('/').filter(|c| !c.is_empty()).collect();
    for c in comps.iter().take(comps.len().saturating_sub(1)) {
        dir.push(c);
        let m = std::fs::symlink_metadata(&dir)?;
        if m.file_type().is_symlink() || !m.is_dir() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&full)?;
    if !f.metadata()?.is_file() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok((f, full))
}

fn decode_line(b: &[u8]) -> String {
    let b = b.strip_suffix(b"\r").unwrap_or(b);
    let s = String::from_utf8_lossy(b);
    if s.len() <= MAX_LINE_CHARS {
        s.into_owned()
    } else {
        s.chars().take(MAX_LINE_CHARS).collect()
    }
}

/// The last `n` complete-or-final lines of `f` (reading at most
/// [`MAX_TAIL_BYTES`] from the end) and the file length they end at.
pub fn tail_lines(f: &mut File, n: usize) -> io::Result<(Vec<String>, u64)> {
    let len = f.metadata()?.len();
    if n == 0 {
        return Ok((Vec::new(), len));
    }
    let start = len.saturating_sub(MAX_TAIL_BYTES);
    let mut pos = len;
    let mut buf: Vec<u8> = Vec::new();
    // Read backwards in chunks until n+1 newlines are in hand.
    while pos > start {
        let step = (pos - start).min(64 * 1024);
        pos -= step;
        f.seek(SeekFrom::Start(pos))?;
        let mut chunk = vec![0u8; usize::try_from(step).unwrap_or(0)];
        f.read_exact(&mut chunk)?;
        chunk.extend_from_slice(&buf);
        buf = chunk;
        if buf.iter().filter(|&&b| b == b'\n').count() > n {
            break;
        }
    }
    let mut lines: Vec<&[u8]> = buf.split(|&b| b == b'\n').collect();
    if lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    // The first piece is partial unless we reached the file start.
    if pos > 0 && !lines.is_empty() {
        lines.remove(0);
    }
    let skip = lines.len().saturating_sub(n);
    Ok((lines[skip..].iter().map(|l| decode_line(l)).collect(), len))
}

/// `logfile.tail` with its allow-list.
pub struct LogfileTailHandler {
    roots: Vec<AbsPath>,
    poll: Duration,
}

impl Default for LogfileTailHandler {
    fn default() -> Self {
        Self::new(
            DEFAULT_ROOTS
                .iter()
                .filter_map(|r| AbsPath::new(*r).ok())
                .collect(),
        )
    }
}

impl LogfileTailHandler {
    pub fn new(roots: Vec<AbsPath>) -> Self {
        Self {
            roots,
            poll: DEFAULT_POLL,
        }
    }

    pub fn with_poll(mut self, d: Duration) -> Self {
        self.poll = d;
        self
    }

    fn allowed(&self, path: &AbsPath) -> Result<AllowedPath, OpError> {
        let denied = DENIED
            .iter()
            .filter_map(|d| AbsPath::new(*d).ok())
            .any(|d| path.is_under(&d));
        if denied {
            return Err(ErrorCode::PolicyDenied.into());
        }
        AllowedPath::new(path, &self.roots).map_err(|_| OpError::new(ErrorCode::PolicyDenied))
    }
}

impl OpHandler for LogfileTailHandler {
    fn supports(&self, op: &Op, invocation: Invocation) -> bool {
        matches!(op, Op::LogfileTail { .. }) && invocation == Invocation::Stream
    }

    fn validate(&self, _ctx: &SysCtx, op: &Op, _meta: &OpMeta) -> Result<(), OpError> {
        let Op::LogfileTail { path, lines, .. } = op else {
            return Err(ErrorCode::Unsupported.into());
        };
        if *lines > MAX_LINES {
            return Err(ErrorCode::InvalidArgument.into());
        }
        self.allowed(path).map(|_| ())
    }

    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        op: &'a Op,
        _meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            let Op::LogfileTail {
                path,
                lines,
                follow,
            } = op
            else {
                return Err(ErrorCode::Unsupported.into());
            };
            let allowed = self.allowed(path)?;
            let abs = allowed.path().as_str().to_owned();
            let (mut f, full) = open_nofollow(ctx, &abs).map_err(io_code)?;
            let (initial, offset) = tail_lines(&mut f, usize::from(*lines)).map_err(io_code)?;
            let ident = file_id(&f).map_err(io_code)?;
            let mut pending: VecDeque<LogLines> = initial
                .chunks(BATCH_LINES)
                .map(|c| LogLines {
                    lines: c.to_vec(),
                    rotated: false,
                })
                .collect();
            if pending.is_empty() {
                pending.push_back(LogLines {
                    lines: Vec::new(),
                    rotated: false,
                });
            }
            Ok(OpOutput::Stream(Box::new(TailStream {
                ctx: ctx.clone(),
                abs,
                full,
                follower: follow.then_some(Follower {
                    f,
                    ident,
                    offset,
                    partial: Vec::new(),
                }),
                pending,
                poll: self.poll,
            })))
        })
    }
}

fn io_code(e: io::Error) -> OpError {
    let code = match e.kind() {
        io::ErrorKind::NotFound => ErrorCode::NotFound,
        io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidInput => ErrorCode::PolicyDenied,
        _ if e.raw_os_error() == Some(libc::ELOOP) => ErrorCode::PolicyDenied,
        _ => ErrorCode::Internal,
    };
    OpError::new(code).with_detail(e.to_string())
}

fn file_id(f: &File) -> io::Result<(u64, u64)> {
    let m = f.metadata()?;
    Ok((m.dev(), m.ino()))
}

struct Follower {
    f: File,
    ident: (u64, u64),
    offset: u64,
    /// Bytes after the last newline (an unfinished line).
    partial: Vec<u8>,
}

impl Follower {
    /// Reads what was appended since the last poll.
    fn read_new(&mut self, lines: &mut Vec<String>, rotated: &mut bool) -> io::Result<()> {
        let len = self.f.metadata()?.len();
        if len < self.offset {
            // Truncated in place (copytruncate).
            self.offset = 0;
            self.partial.clear();
            *rotated = true;
        }
        if len == self.offset {
            return Ok(());
        }
        self.f.seek(SeekFrom::Start(self.offset))?;
        let mut buf = Vec::new();
        (&mut self.f).take(MAX_POLL_BYTES).read_to_end(&mut buf)?;
        self.offset += buf.len() as u64;
        self.partial.extend_from_slice(&buf);
        if let Some(last_nl) = self.partial.iter().rposition(|&b| b == b'\n') {
            let rest = self.partial.split_off(last_nl + 1);
            let done = std::mem::replace(&mut self.partial, rest);
            lines.extend(
                done[..done.len() - 1]
                    .split(|&b| b == b'\n')
                    .map(decode_line),
            );
        }
        if self.partial.len() > MAX_LINE_CHARS * 4 {
            // A line that never ends: flush what we have, cut.
            lines.push(decode_line(&std::mem::take(&mut self.partial)));
        }
        Ok(())
    }
}

struct TailStream {
    ctx: SysCtx,
    abs: String,
    full: PathBuf,
    follower: Option<Follower>,
    pending: VecDeque<LogLines>,
    poll: Duration,
}

impl TailStream {
    fn poll_once(&mut self) -> Result<Option<LogLines>, OpError> {
        let Some(fw) = self.follower.as_mut() else {
            return Ok(None);
        };
        let mut lines = Vec::new();
        let mut rotated = false;
        fw.read_new(&mut lines, &mut rotated).map_err(io_code)?;
        // Rotation: the path now names another file. The old one was
        // drained above; continue with the new one from its start.
        let now = std::fs::symlink_metadata(&self.full)
            .ok()
            .map(|m| (m.dev(), m.ino()));
        if now.is_some_and(|id| id != fw.ident)
            && let Ok((f, _)) = open_nofollow(&self.ctx, &self.abs)
        {
            if !fw.partial.is_empty() {
                lines.push(decode_line(&std::mem::take(&mut fw.partial)));
            }
            *fw = Follower {
                ident: file_id(&f).map_err(io_code)?,
                f,
                offset: 0,
                partial: Vec::new(),
            };
            rotated = true;
            fw.read_new(&mut lines, &mut rotated).map_err(io_code)?;
        }
        if lines.is_empty() && !rotated {
            return Ok(None);
        }
        let mut chunks = lines.chunks(BATCH_LINES).map(<[String]>::to_vec);
        let first = chunks.next().unwrap_or_default();
        self.pending.extend(chunks.map(|c| LogLines {
            lines: c,
            rotated: false,
        }));
        Ok(Some(LogLines {
            lines: first,
            rotated,
        }))
    }
}

impl OpStream for TailStream {
    fn next(&mut self) -> LocalBoxFuture<'_, Option<Result<Payload, OpError>>> {
        Box::pin(async move {
            if let Some(p) = self.pending.pop_front() {
                return Some(Ok(Payload::LogLines(p)));
            }
            self.follower.as_ref()?;
            loop {
                tokio::time::sleep(self.poll).await;
                match self.poll_once() {
                    Ok(Some(l)) => return Some(Ok(Payload::LogLines(l))),
                    Ok(None) => {}
                    Err(e) => return Some(Err(e)),
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FakeRunner;
    use crate::test_util::{block, ctx_at, meta};
    use std::io::Write;
    use std::rc::Rc;

    fn op(path: &str, lines: u16, follow: bool) -> Op {
        Op::LogfileTail {
            path: AbsPath::new(path).unwrap(),
            lines,
            follow,
        }
    }

    fn lines_of(p: Option<Result<Payload, OpError>>) -> LogLines {
        match p {
            Some(Ok(Payload::LogLines(l))) => l,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn tail_reads_last_lines() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        let body: String = (0..100_000).map(|i| format!("line {i}\n")).collect();
        std::fs::write(&p, body).unwrap();
        let mut f = File::open(&p).unwrap();
        let (l, _) = tail_lines(&mut f, 3).unwrap();
        assert_eq!(l, ["line 99997", "line 99998", "line 99999"]);
        std::fs::write(&p, "a\nb").unwrap();
        let (l, len) = tail_lines(&mut File::open(&p).unwrap(), 10).unwrap();
        assert_eq!((l, len), (vec!["a".to_owned(), "b".to_owned()], 3));
        std::fs::write(&p, "").unwrap();
        assert!(
            tail_lines(&mut File::open(&p).unwrap(), 10)
                .unwrap()
                .0
                .is_empty()
        );
    }

    #[test]
    fn allow_list_and_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::create_dir_all(d.join("var/log")).unwrap();
        std::fs::create_dir_all(d.join("etc")).unwrap();
        std::fs::write(d.join("etc/shadow"), "secret\n").unwrap();
        std::fs::write(d.join("var/log/syslog"), "x\n").unwrap();
        std::os::unix::fs::symlink(d.join("etc/shadow"), d.join("var/log/evil")).unwrap();
        std::os::unix::fs::symlink(d.join("etc"), d.join("var/log/dir")).unwrap();
        let c = ctx_at(d, Rc::new(FakeRunner::new()));
        let h = LogfileTailHandler::default();
        let m = meta();
        assert!(
            h.validate(&c, &op("/var/log/syslog", 10, false), &m)
                .is_ok()
        );
        let code = |p: &str| h.validate(&c, &op(p, 10, false), &m).unwrap_err().code();
        assert_eq!(code("/etc/shadow"), ErrorCode::PolicyDenied);
        assert_eq!(code("/var/log/btmp"), ErrorCode::PolicyDenied);
        assert_eq!(
            code("/var/log/journal/x/system.journal"),
            ErrorCode::PolicyDenied
        );
        assert_eq!(
            h.validate(&c, &op("/var/log/syslog", 10_001, false), &m)
                .unwrap_err()
                .code(),
            ErrorCode::InvalidArgument
        );
        // Lexically allowed, but symlinks are refused at open.
        let err = |p: &str| {
            block(h.handle(&c, &op(p, 10, false), &m))
                .unwrap_err()
                .code()
        };
        assert_eq!(err("/var/log/evil"), ErrorCode::PolicyDenied);
        assert_eq!(err("/var/log/dir/shadow"), ErrorCode::PolicyDenied);
        assert_eq!(err("/var/log/missing"), ErrorCode::NotFound);
    }

    #[test]
    fn follow_appends_truncation_and_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::create_dir_all(d.join("var/log")).unwrap();
        let log = d.join("var/log/app.log");
        std::fs::write(&log, "old1\nold2\n").unwrap();
        let c = ctx_at(d, Rc::new(FakeRunner::new()));
        let h = LogfileTailHandler::default().with_poll(Duration::from_millis(5));
        let out = block(h.handle(&c, &op("/var/log/app.log", 1, true), &meta())).unwrap();
        let OpOutput::Stream(mut s) = out else {
            panic!()
        };
        block(async {
            assert_eq!(lines_of(s.next().await).lines, ["old2"]);

            let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
            f.write_all(b"new1\npart").unwrap();
            let l = lines_of(s.next().await);
            assert_eq!((l.lines, l.rotated), (vec!["new1".to_owned()], false));
            f.write_all(b"ial\n").unwrap();
            assert_eq!(lines_of(s.next().await).lines, ["partial"]);

            // copytruncate
            std::fs::write(&log, "t\n").unwrap();
            let l = lines_of(s.next().await);
            assert_eq!((l.lines, l.rotated), (vec!["t".to_owned()], true));

            // rename + recreate: the old file's tail, then the new file.
            f.write_all(b"last-old\n").unwrap();
            std::fs::rename(&log, d.join("var/log/app.log.1")).unwrap();
            std::fs::write(&log, "fresh\n").unwrap();
            let l = lines_of(s.next().await);
            assert_eq!(l.lines, ["last-old", "fresh"]);
            assert!(l.rotated);
        });
    }

    #[test]
    fn no_follow_ends() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("var/log")).unwrap();
        std::fs::write(dir.path().join("var/log/a"), "1\n2\n").unwrap();
        let c = ctx_at(dir.path(), Rc::new(FakeRunner::new()));
        let h = LogfileTailHandler::default();
        let OpOutput::Stream(mut s) =
            block(h.handle(&c, &op("/var/log/a", 5, false), &meta())).unwrap()
        else {
            panic!()
        };
        block(async {
            assert_eq!(lines_of(s.next().await).lines, ["1", "2"]);
            assert!(s.next().await.is_none());
        });
    }
}
