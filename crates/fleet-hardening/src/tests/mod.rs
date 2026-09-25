//! Unit tests: modules against temp roots with a `FakeRunner` (exact
//! argv), idempotence, profiles, plan hash, revert, cloud-init.

mod cloudinit;
mod engine;
mod modules;
mod profile;

use crate::facts::{Facts, UnitState};
use crate::module::{Change, Ctx, Module};
use crate::profile::{Admin, Resolved, builtin};
use fleet_ops::runner::{CommandOutput, CommandSpec, RunError};
use fleet_ops::{FakeRunner, ManualClock, SysCtx};
use fleet_proto::op::{ProfileLevel, ProfileRole};
use std::future::Future;
use std::rc::Rc;

/// Polls a future to completion; everything here is ready immediately
/// (FakeRunner, uncontended locks).
pub fn block<F: Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

pub struct Env {
    _dir: tempfile::TempDir,
    pub runner: Rc<FakeRunner>,
    pub sys: SysCtx,
}

impl Env {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let runner = Rc::new(FakeRunner::new());
        let sys = SysCtx::new(dir.path(), runner.clone(), Rc::new(ManualClock::new(0)));
        Self {
            _dir: dir,
            runner,
            sys,
        }
    }

    pub fn host(&self, abs: &str) -> std::path::PathBuf {
        self.sys.path(abs).unwrap()
    }

    pub fn put(&self, abs: &str, content: &str) {
        let p = self.host(abs);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    pub fn read(&self, abs: &str) -> Option<String> {
        std::fs::read_to_string(self.host(abs)).ok()
    }

    pub fn mode(&self, abs: &str) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(self.host(abs))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    }

    /// Next call must be exactly `spec` (program and argv).
    pub fn expect_spec(&self, spec: &CommandSpec, reply: Result<CommandOutput, RunError>) {
        let args: Vec<String> = spec
            .args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        self.runner.expect(spec.program, &refs, reply);
    }

    pub fn ok(&self, program: &'static str, args: &[&str]) {
        self.runner.expect(program, args, Ok(CommandOutput::ok("")));
    }

    /// A server with the admin `ops` (uid 1000), roster keys and a stock
    /// `sshd_config`.
    pub fn with_admin(self) -> Self {
        self.put(
            "/etc/passwd",
            "root:x:0:0:root:/root:/bin/bash\nops:x:1000:1000:Fleet admin:/home/ops:/bin/bash\n",
        );
        self.put("/etc/group", "root:x:0:\nsudo:x:27:ops\nops:x:1000:\n");
        self.put(
            "/etc/shadow",
            "root:*:19000:0:99999:7:::\nops:!:19000:0:99999:7:::\n",
        );
        self.put(
            "/etc/fleet/authorized_keys/ops",
            &format!(
                "{}\necdsa-sha2-nistp256 AAAA fleet-device-x\n{}\n",
                fleet_ops::users::authorized_keys::BEGIN,
                fleet_ops::users::authorized_keys::END
            ),
        );
        self.put(
            "/etc/ssh/sshd_config",
            "Include /etc/ssh/sshd_config.d/*.conf\nUsePAM yes\n",
        );
        std::fs::create_dir_all(self.host("/home/ops")).unwrap();
        self
    }
}

pub fn admin(p: &mut Resolved, hash: Option<&str>) {
    p.admin = Some(Admin {
        name: "ops".into(),
        password_hash: hash.map(|h| fleet_proto::args::SudoPasswordHash::crypt(h).unwrap()),
    });
}

pub fn baseline() -> Resolved {
    let mut p = builtin(ProfileLevel::Baseline, &[]).unwrap();
    admin(&mut p, None);
    p
}

pub fn strict() -> Resolved {
    let mut p = builtin(ProfileLevel::Strict, &[]).unwrap();
    admin(&mut p, None);
    p
}

pub fn with_roles(roles: &[ProfileRole]) -> Resolved {
    let mut p = builtin(ProfileLevel::Baseline, roles).unwrap();
    admin(&mut p, None);
    p
}

pub fn facts() -> Facts {
    let mut f = Facts {
        ssh_kex: vec![
            "curve25519-sha256".into(),
            "curve25519-sha256@libssh.org".into(),
            "sntrup761x25519-sha512@openssh.com".into(),
        ],
        boot_id: "boot-1".into(),
        mem_total_kib: 2 * 1024 * 1024,
        apparmor_enabled: Some(true),
        firewall: Some(Ok(fleet_ops::firewall::Table::Absent)),
        ..Facts::default()
    };
    f.os.id = "debian".into();
    f.os.codename = "bookworm".into();
    f
}

pub fn running() -> UnitState {
    UnitState {
        load: "loaded".into(),
        file_state: "enabled".into(),
        active: "active".into(),
    }
}

pub fn ctx(env: &Env, profile: Resolved, facts: Facts) -> Ctx {
    Ctx {
        sys: env.sys.clone(),
        profile,
        facts,
        op_id: 7,
        apt_updated: false,
    }
}

/// Plans `m`, applies the plan, and returns it; the runner must have
/// been primed with the plan's commands.
pub fn plan_apply(m: &dyn Module, c: &mut Ctx) -> Vec<Change> {
    let plan = m.plan(c).unwrap();
    block(m.apply(c, &plan)).unwrap();
    plan
}

pub fn assert_done(env: &Env) {
    assert_eq!(
        env.runner.pending(),
        0,
        "unused expectations: {:?}",
        env.runner.calls()
    );
}
