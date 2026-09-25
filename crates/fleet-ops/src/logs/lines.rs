//! Line-by-line child output for long-running readers (`journalctl`,
//! `journalctl -f`). Same rules as [`crate::runner`]: fixed absolute
//! program path, argv only, environment cleared, stdin `/dev/null`. The
//! child is killed when the [`LineSource`] is dropped (stream cancelled,
//! enough lines read).

use crate::handler::LocalBoxFuture;
use crate::runner::{BASE_ENV, CommandSpec, RunError};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::process::Stdio;
use std::rc::Rc;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Longest line kept; longer lines are skipped whole (a journal entry that
/// large is either binary junk or an attack on memory).
pub const MAX_LINE: usize = 256 * 1024;

/// A source of lines. `next_line` must be cancel-safe: a dropped future
/// loses no data (follow batching races it against a timer).
pub trait LineSource {
    /// `None` at end of output.
    fn next_line(&mut self) -> LocalBoxFuture<'_, Option<Result<Vec<u8>, RunError>>>;
}

/// Starts programs whose output is read incrementally.
pub trait LineSpawner {
    fn spawn(&self, spec: CommandSpec) -> Result<Box<dyn LineSource>, RunError>;
}

/// Splits a byte stream into lines of at most [`MAX_LINE`] bytes.
/// Cancel-safe: state lives in the struct and each poll reads at most once.
pub struct CappedLines<R> {
    reader: R,
    buf: Vec<u8>,
    /// Inside an over-long line: drop bytes until the next newline.
    skipping: bool,
    eof: bool,
    cap: usize,
}

impl<R: AsyncRead + Unpin> CappedLines<R> {
    pub fn new(reader: R, cap: usize) -> Self {
        Self {
            reader,
            buf: Vec::new(),
            skipping: false,
            eof: false,
            cap,
        }
    }

    fn take_line(&mut self) -> Option<Vec<u8>> {
        loop {
            let nl = self.buf.iter().position(|&b| b == b'\n')?;
            let mut line: Vec<u8> = self.buf.drain(..=nl).collect();
            line.pop();
            if std::mem::take(&mut self.skipping) || line.len() > self.cap {
                continue;
            }
            return Some(line);
        }
    }

    pub async fn next(&mut self) -> Option<std::io::Result<Vec<u8>>> {
        let mut chunk = [0u8; 8192];
        loop {
            if let Some(l) = self.take_line() {
                return Some(Ok(l));
            }
            if self.buf.len() > self.cap {
                self.buf.clear();
                self.skipping = true;
            }
            if self.eof {
                let rest = std::mem::take(&mut self.buf);
                let skip = std::mem::take(&mut self.skipping);
                return (!rest.is_empty() && !skip).then_some(Ok(rest));
            }
            match self.reader.read(&mut chunk).await {
                Ok(0) => self.eof = true,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) => return Some(Err(e)),
            }
        }
    }
}

/// Real child processes.
pub struct SystemLineSpawner;

struct ChildLines {
    // Held for kill-on-drop.
    _child: tokio::process::Child,
    lines: CappedLines<tokio::process::ChildStdout>,
}

impl LineSource for ChildLines {
    fn next_line(&mut self) -> LocalBoxFuture<'_, Option<Result<Vec<u8>, RunError>>> {
        Box::pin(async move {
            self.lines
                .next()
                .await
                .map(|r| r.map_err(|e| RunError::Io(e.kind())))
        })
    }
}

impl LineSpawner for SystemLineSpawner {
    fn spawn(&self, spec: CommandSpec) -> Result<Box<dyn LineSource>, RunError> {
        if !spec.program.starts_with('/') {
            return Err(RunError::NotAbsolute);
        }
        let mut child = tokio::process::Command::new(spec.program)
            .args(&spec.args)
            .env_clear()
            .envs(BASE_ENV)
            .envs(spec.env.iter().map(|(k, v)| (k, v)))
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| RunError::Spawn(e.kind()))?;
        let out = child
            .stdout
            .take()
            .ok_or(RunError::Io(std::io::ErrorKind::BrokenPipe))?;
        Ok(Box::new(ChildLines {
            _child: child,
            lines: CappedLines::new(out, MAX_LINE),
        }))
    }
}

/// Test spawner: each expected argv answers with canned lines; with
/// `hang` the source then stays open (like `journalctl -f`) instead of
/// ending.
#[derive(Default)]
pub struct FakeLineSpawner {
    #[allow(clippy::type_complexity)]
    expected: RefCell<VecDeque<(&'static str, Vec<String>, Vec<Vec<u8>>, bool)>>,
    calls: RefCell<Vec<CommandSpec>>,
    /// Set when a hanging source is dropped (cancel reached the child).
    pub dropped: Rc<std::cell::Cell<u32>>,
}

impl FakeLineSpawner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn expect(&self, program: &'static str, args: &[&str], lines: &[&str], hang: bool) {
        self.expected.borrow_mut().push_back((
            program,
            args.iter().map(|s| (*s).to_owned()).collect(),
            lines.iter().map(|l| l.as_bytes().to_vec()).collect(),
            hang,
        ));
    }

    pub fn calls(&self) -> Vec<CommandSpec> {
        self.calls.borrow().clone()
    }
}

struct FakeLines {
    lines: VecDeque<Vec<u8>>,
    hang: bool,
    dropped: Rc<std::cell::Cell<u32>>,
}

impl Drop for FakeLines {
    fn drop(&mut self) {
        self.dropped.set(self.dropped.get() + 1);
    }
}

impl LineSource for FakeLines {
    fn next_line(&mut self) -> LocalBoxFuture<'_, Option<Result<Vec<u8>, RunError>>> {
        Box::pin(async move {
            match self.lines.pop_front() {
                Some(l) => Some(Ok(l)),
                None if self.hang => std::future::pending().await,
                None => None,
            }
        })
    }
}

impl LineSpawner for FakeLineSpawner {
    fn spawn(&self, spec: CommandSpec) -> Result<Box<dyn LineSource>, RunError> {
        self.calls.borrow_mut().push(spec.clone());
        let mut q = self.expected.borrow_mut();
        let args: Vec<String> = spec
            .args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        match q.front() {
            Some((p, a, _, _)) if *p == spec.program && *a == args => {
                let (_, _, lines, hang) = q.pop_front().ok_or(RunError::Unexpected)?;
                Ok(Box::new(FakeLines {
                    lines: lines.into(),
                    hang,
                    dropped: self.dropped.clone(),
                }))
            }
            _ => Err(RunError::Unexpected),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::block;

    #[test]
    fn capped_lines_skip_long_and_keep_tail() {
        let data: &[u8] = b"a\nbbbbbbbbbb\ncc\nlast";
        let mut l = CappedLines::new(data, 4);
        block(async {
            assert_eq!(l.next().await.unwrap().unwrap(), b"a");
            assert_eq!(l.next().await.unwrap().unwrap(), b"cc");
            assert_eq!(l.next().await.unwrap().unwrap(), b"last");
            assert!(l.next().await.is_none());
        });
    }

    #[test]
    fn system_spawner_reads_lines() {
        block(async {
            // Spawning needs the runtime's reactor (as in exec).
            let mut src = SystemLineSpawner
                .spawn(CommandSpec::new("/usr/bin/printf").arg("x\\ny\\n"))
                .unwrap();
            assert_eq!(src.next_line().await.unwrap().unwrap(), b"x");
            assert_eq!(src.next_line().await.unwrap().unwrap(), b"y");
            assert!(src.next_line().await.is_none());
        });
        assert!(matches!(
            SystemLineSpawner.spawn(CommandSpec::new("printf")),
            Err(RunError::NotAbsolute)
        ));
    }
}
