//! Child processes (design §4.2 rule: fixed absolute binary paths plus an
//! argument vector, never a shell). The environment is cleared and replaced
//! by [`BASE_ENV`]; stdin is `/dev/null` unless [`CommandSpec::stdin`]
//! supplies bytes (e.g. `nft -f -`); stdout and stderr are capped. Each
//! child leads its own process group; a timeout SIGKILLs the whole group
//! and, for a scoped child, the `fleet-op-<id>.scope` unit.
//!
//! [`CommandRunner::run_blocking`] is the synchronous variant for callers
//! that can't await (`Revertible::snapshot`/`restore`).

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
    /// Set by [`crate::scope::scoped`]: the transient `fleet-op-<id>.scope`
    /// the child runs in. On timeout the whole unit is SIGKILLed too
    /// (catches processes that left the child's process group).
    pub scope_unit: Option<String>,
    /// Set by [`crate::scope::scoped_limited`]: once the main process
    /// exits, `systemctl stop <scope_unit>.scope` ends whatever it left
    /// behind (background jobs, daemons), so nothing outlives the op.
    pub stop_scope_on_exit: bool,
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
            scope_unit: None,
            stop_scope_on_exit: false,
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

    /// Same contract as [`CommandRunner::run`], blocking the thread. For
    /// synchronous callers only (`Revertible`); the default refuses.
    fn run_blocking(&self, _spec: CommandSpec) -> Result<CommandOutput, RunError> {
        Err(RunError::Spawn(std::io::ErrorKind::Unsupported))
    }
}

/// Real processes via `tokio::process` (or `std::process` when blocking).
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&self, spec: CommandSpec) -> LocalBoxFuture<'_, Result<CommandOutput, RunError>> {
        Box::pin(run_system(spec))
    }

    fn run_blocking(&self, spec: CommandSpec) -> Result<CommandOutput, RunError> {
        run_system_blocking(spec)
    }
}

pub const SYSTEMCTL: &str = "/usr/bin/systemctl";
/// Budget for the post-timeout `systemctl kill` of a scope.
const SCOPE_KILL_TIMEOUT: Duration = Duration::from_secs(10);

/// What to run after `spec` timed out: `systemctl kill --signal=SIGKILL
/// <unit>.scope` for a scoped child, else nothing.
pub fn scope_kill_spec(spec: &CommandSpec) -> Option<CommandSpec> {
    let unit = spec.scope_unit.as_ref()?;
    Some(
        CommandSpec::new(SYSTEMCTL)
            .arg("kill")
            .arg("--signal=SIGKILL")
            .arg(format!("{unit}.scope"))
            .timeout(SCOPE_KILL_TIMEOUT)
            .output_cap(4096),
    )
}

/// What to run once a [`CommandSpec::stop_scope_on_exit`] child exited:
/// `systemctl stop <unit>.scope` (exit 5, "not loaded", means nothing was
/// left).
pub fn scope_stop_spec(spec: &CommandSpec) -> Option<CommandSpec> {
    let unit = spec
        .scope_unit
        .as_ref()
        .filter(|_| spec.stop_scope_on_exit)?;
    Some(
        CommandSpec::new(SYSTEMCTL)
            .arg("stop")
            .arg(format!("{unit}.scope"))
            .timeout(SCOPE_KILL_TIMEOUT)
            .output_cap(4096),
    )
}

/// SIGKILL the child's whole process group (the child leads it:
/// `process_group(0)`). Called before the child is reaped, so the group id
/// can't have been reused.
fn kill_group(pid: Option<u32>) {
    let pid = pid
        .and_then(|p| i32::try_from(p).ok())
        .and_then(rustix::process::Pid::from_raw);
    if let Some(pid) = pid {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
}

fn run_system_blocking(spec: CommandSpec) -> Result<CommandOutput, RunError> {
    use std::io::{Read, Write};
    use std::os::unix::process::CommandExt;
    if !spec.program.starts_with('/') {
        return Err(RunError::NotAbsolute);
    }
    let mut cmd = std::process::Command::new(spec.program);
    cmd.process_group(0)
        .args(&spec.args)
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
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| RunError::Spawn(e.kind()))?;
    let (Some(out), Some(err)) = (child.stdout.take(), child.stderr.take()) else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(RunError::Io(std::io::ErrorKind::BrokenPipe));
    };
    let cap = spec.output_cap;
    let reader = |mut r: Box<dyn Read + Send>| {
        std::thread::spawn(move || -> std::io::Result<(Vec<u8>, bool)> {
            let mut kept = Vec::new();
            let mut buf = [0u8; 8192];
            let mut truncated = false;
            loop {
                let n = r.read(&mut buf)?;
                if n == 0 {
                    return Ok((kept, truncated));
                }
                let room = cap.saturating_sub(kept.len());
                kept.extend_from_slice(&buf[..n.min(room)]);
                truncated |= n > room;
            }
        })
    };
    let t_out = reader(Box::new(out));
    let t_err = reader(Box::new(err));
    let scope_kill = scope_kill_spec(&spec);
    let scope_stop = scope_stop_spec(&spec);
    let t_in = match (child.stdin.take(), spec.stdin) {
        (Some(mut w), Some(bytes)) => Some(std::thread::spawn(move || {
            // A child that exits without reading gets EPIPE; its exit
            // status tells the story.
            let _ = w.write_all(&bytes);
        })),
        _ => None,
    };
    let deadline = std::time::Instant::now() + spec.timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if std::time::Instant::now() >= deadline => {
                kill_group(Some(child.id()));
                let _ = child.kill();
                let _ = child.wait();
                if let Some(k) = scope_kill {
                    let _ = run_system_blocking(k);
                }
                return Err(RunError::Timeout);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(e) => return Err(RunError::Io(e.kind())),
        }
    };
    if let Some(stop) = scope_stop {
        let _ = run_system_blocking(stop);
    }
    if let Some(t) = t_in {
        let _ = t.join();
    }
    let join = |t: std::thread::JoinHandle<std::io::Result<(Vec<u8>, bool)>>| {
        t.join()
            .map_err(|_| RunError::Io(std::io::ErrorKind::Other))?
            .map_err(|e| RunError::Io(e.kind()))
    };
    let (stdout, t1) = join(t_out)?;
    let (stderr, t2) = join(t_err)?;
    Ok(CommandOutput {
        code: status.code(),
        stdout,
        stderr,
        truncated: t1 || t2,
    })
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
        .process_group(0)
        .kill_on_drop(true);
    let mut child = cmd.spawn().map_err(|e| RunError::Spawn(e.kind()))?;
    let pid = child.id();
    let (Some(out), Some(err)) = (child.stdout.take(), child.stderr.take()) else {
        kill_group(pid);
        return Err(RunError::Io(std::io::ErrorKind::BrokenPipe));
    };
    let scope_kill = scope_kill_spec(&spec);
    let scope_stop = scope_stop_spec(&spec);
    let stdin = child.stdin.take().zip(spec.stdin);
    let feed = async move {
        use tokio::io::AsyncWriteExt;
        if let Some((mut w, bytes)) = stdin {
            // EPIPE from a child that exits early: its status tells.
            let _ = w.write_all(&bytes).await;
            let _ = w.shutdown().await;
        }
    };
    let cap = spec.output_cap;
    let res = tokio::time::timeout(spec.timeout, async {
        // Leftovers of a stopped-on-exit scope may hold the pipes open:
        // stopping the scope once the main process exits lets the reads
        // reach EOF.
        let wait = async {
            let s = child.wait().await;
            if let Some(stop) = scope_stop {
                let _ = Box::pin(run_system(stop)).await;
            }
            s
        };
        let (o, e, (), s) = tokio::join!(read_capped(out, cap), read_capped(err, cap), feed, wait);
        (o, e, s)
    })
    .await;
    let Ok((out, err, status)) = res else {
        // Group first: the child is not reaped yet, so its pgid is ours.
        kill_group(pid);
        let _ = child.kill().await;
        if let Some(k) = scope_kill {
            let _ = Box::pin(run_system(k)).await;
        }
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

impl FakeRunner {
    fn answer(&self, spec: CommandSpec) -> Result<CommandOutput, RunError> {
        let key = CommandSpecKey {
            program: spec.program,
            args: spec.args.clone(),
        };
        self.calls.borrow_mut().push(spec);
        let mut q = self.expected.borrow_mut();
        match q.front() {
            Some((k, _)) if *k == key => q.pop_front().map_or(Err(RunError::Unexpected), |e| e.1),
            _ => Err(RunError::Unexpected),
        }
    }
}

impl CommandRunner for FakeRunner {
    fn run(&self, spec: CommandSpec) -> LocalBoxFuture<'_, Result<CommandOutput, RunError>> {
        Box::pin(std::future::ready(self.answer(spec)))
    }

    fn run_blocking(&self, spec: CommandSpec) -> Result<CommandOutput, RunError> {
        self.answer(spec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::block;

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

    /// A grandchild that outlives the child must die with it on timeout
    /// (process-group kill), for both runner variants.
    #[test]
    fn timeout_kills_process_group() {
        let dir = tempfile::tempdir().unwrap();
        for blocking in [false, true] {
            let pidfile = dir.path().join(format!("pid-{blocking}"));
            // Test-only shell: backgrounds a sleeper and records its pid.
            let spec = CommandSpec::new("/bin/sh")
                .args(["-c", "/bin/sleep 30 & echo $! > \"$1\"; wait", "sh"])
                .arg(pidfile.as_os_str())
                .timeout(Duration::from_millis(300));
            let t = std::time::Instant::now();
            let r = if blocking {
                SystemRunner.run_blocking(spec)
            } else {
                block(SystemRunner.run(spec))
            };
            assert_eq!(r, Err(RunError::Timeout));
            assert!(t.elapsed() < Duration::from_secs(5));
            let pid: i32 = std::fs::read_to_string(&pidfile)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            let pid = rustix::process::Pid::from_raw(pid).unwrap();
            let gone = (0..200).any(|_| {
                let dead = rustix::process::test_kill_process(pid).is_err();
                if !dead {
                    std::thread::sleep(Duration::from_millis(10));
                }
                dead
            });
            assert!(gone, "grandchild survived (blocking={blocking})");
        }
    }

    #[test]
    fn stdin_async_and_blocking() {
        let spec = CommandSpec::new("/bin/cat").stdin(b"table inet fleet\n".to_vec());
        let out = block(SystemRunner.run(spec.clone())).unwrap();
        assert_eq!(out.stdout, b"table inet fleet\n");
        let out = SystemRunner.run_blocking(spec).unwrap();
        assert!(out.success());
        assert_eq!(out.stdout, b"table inet fleet\n");
        // No stdin: /dev/null, immediate EOF.
        let out = SystemRunner
            .run_blocking(CommandSpec::new("/bin/cat"))
            .unwrap();
        assert!(out.stdout.is_empty());
        let r = SystemRunner.run_blocking(
            CommandSpec::new("/bin/sleep")
                .arg("5")
                .timeout(Duration::from_millis(100)),
        );
        assert_eq!(r, Err(RunError::Timeout));
    }
}
