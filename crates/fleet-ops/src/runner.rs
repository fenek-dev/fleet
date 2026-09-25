//! Child processes (design §4.2 rule: fixed absolute binary paths plus an
//! argument vector, never a shell). The environment is cleared and replaced
//! by [`BASE_ENV`]; stdin is `/dev/null`; stdout and stderr are capped;
//! a timeout kills the child.

use crate::handler::LocalBoxFuture;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::ffi::OsString;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

/// The whole environment of every child (plus [`CommandSpec::env`]).
pub const BASE_ENV: [(&str, &str); 2] =
    [("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"), ("LC_ALL", "C")];
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
/// Per output stream.
pub const DEFAULT_OUTPUT_CAP: usize = 1 << 20;

/// One program invocation. `program` is a `&'static str` on purpose: binary
/// paths are constants in the source, never built from arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: &'static str,
    pub args: Vec<OsString>,
    /// Added to [`BASE_ENV`] (names are constants too).
    pub env: Vec<(&'static str, OsString)>,
    pub timeout: Duration,
    /// Bytes kept of stdout and of stderr each; the rest is read and dropped.
    pub output_cap: usize,
    /// Written to the child's stdin, which is then closed; `None` means
    /// `/dev/null` (e.g. `crontab -u <user> -`).
    pub stdin: Option<Vec<u8>>,
}

impl CommandSpec {
    pub fn new(program: &'static str) -> Self {
        Self {
            program,
            args: Vec::new(),
            env: Vec::new(),
            timeout: DEFAULT_TIMEOUT,
            output_cap: DEFAULT_OUTPUT_CAP,
            stdin: None,
        }
    }

    pub fn stdin(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(bytes.into());
        self
    }

    pub fn arg(mut self, a: impl Into<OsString>) -> Self {
        self.args.push(a.into());
        self
    }

    pub fn args<I: IntoIterator<Item = A>, A: Into<OsString>>(mut self, args: I) -> Self {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn env(mut self, name: &'static str, value: impl Into<OsString>) -> Self {
        self.env.push((name, value.into()));
        self
    }

    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = d;
        self
    }

    pub fn output_cap(mut self, n: usize) -> Self {
        self.output_cap = n;
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandOutput {
    /// Exit code; `None` if the child was killed by a signal.
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Either stream was longer than the cap.
    pub truncated: bool,
}

impl CommandOutput {
    /// Exit 0 with this stdout.
    pub fn ok(stdout: impl Into<Vec<u8>>) -> Self {
        Self {
            code: Some(0),
            stdout: stdout.into(),
            ..Self::default()
        }
    }

    pub fn exit(code: i32) -> Self {
        Self {
            code: Some(code),
            ..Self::default()
        }
    }

    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RunError {
    #[error("program path is not absolute")]
    NotAbsolute,
    #[error("spawn: {0}")]
    Spawn(std::io::ErrorKind),
    #[error("io: {0}")]
    Io(std::io::ErrorKind),
    #[error("timed out")]
    Timeout,
    /// `FakeRunner`: a call nobody expected (or not the expected one).
    #[error("unexpected command")]
    Unexpected,
}

pub trait CommandRunner {
    fn run(&self, spec: CommandSpec) -> LocalBoxFuture<'_, Result<CommandOutput, RunError>>;
}

/// Real processes via `tokio::process`.
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&self, spec: CommandSpec) -> LocalBoxFuture<'_, Result<CommandOutput, RunError>> {
        Box::pin(run_system(spec))
    }
}

async fn run_system(spec: CommandSpec) -> Result<CommandOutput, RunError> {
    if !spec.program.starts_with('/') {
        return Err(RunError::NotAbsolute);
    }
    let mut cmd = tokio::process::Command::new(spec.program);
    cmd.args(&spec.args)
        .env_clear()
        .envs(BASE_ENV)
        .envs(spec.env.iter().map(|(k, v)| (k, v)))
        .current_dir("/")
        .stdin(if spec.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd.spawn().map_err(|e| RunError::Spawn(e.kind()))?;
    let (Some(out), Some(err)) = (child.stdout.take(), child.stderr.take()) else {
        return Err(RunError::Io(std::io::ErrorKind::BrokenPipe));
    };
    let input = child.stdin.take().zip(spec.stdin);
    let cap = spec.output_cap;
    let res = tokio::time::timeout(spec.timeout, async {
        // Written concurrently with the reads (no pipe deadlock); dropping
        // the handle closes stdin. A child that exits without reading gets
        // EPIPE, which is its business: the exit status decides.
        let feed = async move {
            if let Some((mut w, bytes)) = input {
                let _ = tokio::io::AsyncWriteExt::write_all(&mut w, &bytes).await;
            }
        };
        let (_, out, err, status) = tokio::join!(
            feed,
            read_capped(out, cap),
            read_capped(err, cap),
            child.wait()
        );
        (out, err, status)
    })
    .await;
    let Ok((out, err, status)) = res else {
        let _ = child.kill().await;
        return Err(RunError::Timeout);
    };
    let (stdout, t1) = out.map_err(|e| RunError::Io(e.kind()))?;
    let (stderr, t2) = err.map_err(|e| RunError::Io(e.kind()))?;
    let status = status.map_err(|e| RunError::Io(e.kind()))?;
    Ok(CommandOutput {
        code: status.code(),
        stdout,
        stderr,
        truncated: t1 || t2,
    })
}

/// Reads to EOF, keeping the first `cap` bytes.
async fn read_capped(
    mut r: impl AsyncRead + Unpin,
    cap: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut kept = Vec::new();
    let mut buf = [0u8; 8192];
    let mut truncated = false;
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            return Ok((kept, truncated));
        }
        let room = cap.saturating_sub(kept.len());
        kept.extend_from_slice(&buf[..n.min(room)]);
        truncated |= n > room;
    }
}

/// Test runner: answers queued expectations in order and fails anything
/// else with [`RunError::Unexpected`].
#[derive(Default)]
pub struct FakeRunner {
    expected: RefCell<VecDeque<(CommandSpecKey, Result<CommandOutput, RunError>)>>,
    calls: RefCell<Vec<CommandSpec>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandSpecKey {
    program: &'static str,
    args: Vec<OsString>,
}

impl FakeRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// The next call must be exactly `program args…`.
    pub fn expect(
        &self,
        program: &'static str,
        args: &[&str],
        reply: Result<CommandOutput, RunError>,
    ) -> &Self {
        let key = CommandSpecKey {
            program,
            args: args.iter().map(OsString::from).collect(),
        };
        self.expected.borrow_mut().push_back((key, reply));
        self
    }

    /// Every call made, expected or not.
    pub fn calls(&self) -> Vec<CommandSpec> {
        self.calls.borrow().clone()
    }

    /// Expectations not yet consumed.
    pub fn pending(&self) -> usize {
        self.expected.borrow().len()
    }
}

impl CommandRunner for FakeRunner {
    fn run(&self, spec: CommandSpec) -> LocalBoxFuture<'_, Result<CommandOutput, RunError>> {
        let key = CommandSpecKey {
            program: spec.program,
            args: spec.args.clone(),
        };
        self.calls.borrow_mut().push(spec);
        let mut q = self.expected.borrow_mut();
        let reply = match q.front() {
            Some((k, _)) if *k == key => q.pop_front().map_or(Err(RunError::Unexpected), |e| e.1),
            _ => Err(RunError::Unexpected),
        };
        Box::pin(std::future::ready(reply))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn fake_matches_argv_in_order() {
        let f = FakeRunner::new();
        f.expect("/usr/bin/true", &["a"], Ok(CommandOutput::ok("x")));
        let r = block(f.run(CommandSpec::new("/usr/bin/true").arg("b")));
        assert_eq!(r, Err(RunError::Unexpected));
        let r = block(f.run(CommandSpec::new("/usr/bin/true").arg("a")));
        assert_eq!(r.unwrap().stdout, b"x");
        assert_eq!(f.pending(), 0);
        assert_eq!(f.calls().len(), 2);
    }

    #[test]
    fn system_runner_env_cap_timeout() {
        // /usr/bin/env exists on Linux and macOS: prints exactly the env.
        let out =
            block(SystemRunner.run(CommandSpec::new("/usr/bin/env").env("X_FLEET", "1"))).unwrap();
        assert!(out.success());
        let text = String::from_utf8(out.stdout).unwrap();
        let mut names: Vec<&str> = text.lines().filter_map(|l| l.split('=').next()).collect();
        names.sort_unstable();
        assert_eq!(names, ["LC_ALL", "PATH", "X_FLEET"]);

        let out = block(SystemRunner.run(CommandSpec::new("/usr/bin/env").output_cap(4))).unwrap();
        assert_eq!(out.stdout.len(), 4);
        assert!(out.truncated);

        let r = block(
            SystemRunner.run(
                CommandSpec::new("/bin/sleep")
                    .arg("5")
                    .timeout(Duration::from_millis(100)),
            ),
        );
        assert_eq!(r, Err(RunError::Timeout));

        let out = block(SystemRunner.run(CommandSpec::new("/bin/cat").stdin("in\n"))).unwrap();
        assert_eq!(out.stdout, b"in\n");

        let r = block(SystemRunner.run(CommandSpec::new("relative")));
        assert_eq!(r, Err(RunError::NotAbsolute));
    }
}
