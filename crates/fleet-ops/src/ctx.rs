//! [`SysCtx`]: everything an operation touches outside its arguments.

use crate::procfs::Procfs;
use crate::runner::{CommandRunner, SystemRunner};
use std::cell::Cell;
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};

/// Wall and monotonic time, injectable for tests.
pub trait Clock {
    /// Unix milliseconds (0 before 1970).
    fn now_ms(&self) -> u64;
    fn monotonic(&self) -> Instant;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }

    fn monotonic(&self) -> Instant {
        Instant::now()
    }
}

/// Test clock: moves only when told to.
pub struct ManualClock {
    ms: Cell<u64>,
    base: Instant,
    offset: Cell<Duration>,
}

impl ManualClock {
    pub fn new(now_ms: u64) -> Self {
        Self {
            ms: Cell::new(now_ms),
            base: Instant::now(),
            offset: Cell::new(Duration::ZERO),
        }
    }

    /// Advances both clocks.
    pub fn advance(&self, d: Duration) {
        let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        self.ms.set(self.ms.get().saturating_add(ms));
        self.offset.set(self.offset.get() + d);
    }

    /// Sets the wall clock only (a clock step).
    pub fn set_ms(&self, now_ms: u64) {
        self.ms.set(now_ms);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.ms.get()
    }

    fn monotonic(&self) -> Instant {
        self.base + self.offset.get()
    }
}

/// The environment of one exec. Cheap to clone (streams keep a clone for
/// their lifetime). Single-threaded like exec itself.
#[derive(Clone)]
pub struct SysCtx {
    root: PathBuf,
    pub runner: Rc<dyn CommandRunner>,
    pub clock: Rc<dyn Clock>,
    pub procfs: Procfs,
}

impl SysCtx {
    /// Production: `/`, real processes, system clock.
    pub fn system() -> Self {
        Self::new("/", Rc::new(SystemRunner), Rc::new(SystemClock))
    }

    /// `root` prefixes every absolute path ops read or write (a temp
    /// directory in tests). Commands run by `runner` are not re-rooted.
    pub fn new(
        root: impl Into<PathBuf>,
        runner: Rc<dyn CommandRunner>,
        clock: Rc<dyn Clock>,
    ) -> Self {
        let root = root.into();
        Self {
            procfs: Procfs::new(&root),
            root,
            runner,
            clock,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Maps an absolute system path (`/etc/hostname`) under the root.
    /// `None` unless `abs` is absolute and free of `.`/`..` components, so
    /// no argument can climb out of the root.
    pub fn path(&self, abs: &str) -> Option<PathBuf> {
        rooted(&self.root, abs)
    }
}

pub(crate) fn rooted(root: &Path, abs: &str) -> Option<PathBuf> {
    let p = Path::new(abs);
    let mut out = root.to_path_buf();
    let mut comps = p.components();
    if comps.next() != Some(Component::RootDir) {
        return None;
    }
    for c in comps {
        match c {
            Component::Normal(s) => out.push(s),
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_mapping() {
        let ctx = SysCtx::new(
            "/tmp/r",
            Rc::new(crate::FakeRunner::new()),
            Rc::new(ManualClock::new(0)),
        );
        assert_eq!(
            ctx.path("/etc/hostname"),
            Some(PathBuf::from("/tmp/r/etc/hostname"))
        );
        assert_eq!(ctx.path("etc/hostname"), None);
        assert_eq!(ctx.path("/etc/../shadow"), None);
        assert_eq!(ctx.path("/etc/./x"), Some(PathBuf::from("/tmp/r/etc/x")));
        assert_eq!(SysCtx::system().path("/proc/x"), Some("/proc/x".into()));
    }

    #[test]
    fn manual_clock() {
        let c = ManualClock::new(1000);
        let t0 = c.monotonic();
        c.advance(Duration::from_millis(1500));
        assert_eq!(c.now_ms(), 2500);
        assert_eq!(c.monotonic() - t0, Duration::from_millis(1500));
        c.set_ms(5);
        assert_eq!(c.now_ms(), 5);
    }
}
