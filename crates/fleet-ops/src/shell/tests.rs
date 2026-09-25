use super::*;
use crate::runner::{CommandOutput, FakeRunner};
use crate::testutil::{block, ctx, meta};
use fleet_proto::OpSummary;
use fleet_proto::args::{AbsPath, ShellCommand, UserName};
use std::cell::RefCell;

struct Allow(RefCell<Vec<&'static str>>);

impl ShellPolicy for Allow {
    fn may_run_as(&self, user: &str) -> bool {
        self.0.borrow().contains(&user)
    }
}

fn allow(users: &[&'static str]) -> Rc<Allow> {
    Rc::new(Allow(RefCell::new(users.to_vec())))
}

const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
ops:x:1000:1000::/home/ops:/bin/bash\n\
fleet:x:998:998::/var/lib/fleet:/usr/sbin/nologin\n\
toor:x:0:0::/root:/bin/sh\n";

fn root() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("etc")).unwrap();
    std::fs::write(d.path().join("etc/passwd"), PASSWD).unwrap();
    d
}

fn req(user: &str, cmd: &str) -> ShellExec {
    ShellExec {
        user: UserName::new(user).unwrap(),
        command: ShellCommand::new(cmd).unwrap(),
        cwd: None,
        timeout_s: 30,
        output_cap: 8,
    }
}

fn setpriv_argv(uid: u32, dir: &str, cmd: &str) -> Vec<String> {
    [
        "--scope",
        "--quiet",
        "--collect",
        "--unit",
        "fleet-op-9",
        "--",
        SETPRIV,
        &format!("--reuid={uid}"),
        &format!("--regid={uid}"),
        "--init-groups",
        "--reset-env",
        "--",
        ENV,
        "-C",
        dir,
        SH,
        "-c",
        cmd,
    ]
    .map(String::from)
    .to_vec()
}

#[test]
fn argv_is_setpriv_env_sh_in_scope() {
    let d = root();
    let runner = Rc::new(FakeRunner::new());
    let argv = setpriv_argv(1000, "/srv/app", "ls -la | wc -l");
    let a: Vec<&str> = argv.iter().map(String::as_str).collect();
    runner.expect(
        crate::scope::SYSTEMD_RUN,
        &a,
        Ok(CommandOutput {
            code: Some(3),
            stdout: b"hello world".to_vec(),
            stderr: b"err".to_vec(),
            truncated: false,
        }),
    );
    let c = ctx(d.path(), runner.clone());
    let h = ShellHandler::new(allow(&["ops"]));
    let mut r = req("ops", "ls -la | wc -l");
    r.cwd = Some(AbsPath::new("/srv/app").unwrap());
    let op = Op::ShellExec(r);
    h.validate(&c, &op, &meta(op.clone(), None)).unwrap();
    let out = block(h.handle(&c, &op, &meta(op.clone(), Some(9)))).unwrap();
    let OpOutput::Payload(Payload::ShellResult(res)) = out else {
        panic!()
    };
    // Combined cap 8: stdout fills it, stderr is dropped.
    assert_eq!(res.exit_code, Some(3));
    assert_eq!(res.stdout, b"hello wo");
    assert!(res.stderr.is_empty());
    assert!(res.truncated && !res.timed_out);
    let call = &runner.calls()[0];
    assert_eq!(call.timeout, Duration::from_secs(30));
    assert_eq!(call.scope_unit.as_deref(), Some("fleet-op-9"));
    assert_eq!(runner.pending(), 0);
}

#[test]
fn home_is_default_cwd_and_timeout_reported() {
    let d = root();
    let runner = Rc::new(FakeRunner::new());
    let argv = setpriv_argv(1000, "/home/ops", "sleep 99");
    let a: Vec<&str> = argv.iter().map(String::as_str).collect();
    runner.expect(crate::scope::SYSTEMD_RUN, &a, Err(RunError::Timeout));
    let c = ctx(d.path(), runner.clone());
    let h = ShellHandler::new(allow(&["ops"]));
    let op = Op::ShellExec(req("ops", "sleep 99"));
    let out = block(h.handle(&c, &op, &meta(op.clone(), Some(9)))).unwrap();
    let OpOutput::Payload(Payload::ShellResult(res)) = out else {
        panic!()
    };
    assert!(res.timed_out);
    assert_eq!(res.exit_code, None);
}

#[test]
fn refusals() {
    let d = root();
    let runner = Rc::new(FakeRunner::new());
    let c = ctx(d.path(), runner.clone());
    let code = |h: &ShellHandler, r: ShellExec| {
        let op = Op::ShellExec(r);
        h.validate(&c, &op, &meta(op.clone(), None))
            .unwrap_err()
            .code()
    };
    // Policy off / user not listed.
    let none = ShellHandler::new(Rc::new(DenyAll));
    assert_eq!(code(&none, req("ops", "id")), ErrorCode::PolicyDenied);
    let ops_only = ShellHandler::new(allow(&["ops"]));
    assert_eq!(code(&ops_only, req("root", "id")), ErrorCode::PolicyDenied);
    // Listed but unknown.
    let ghost = ShellHandler::new(allow(&["ghost"]));
    assert_eq!(code(&ghost, req("ghost", "id")), ErrorCode::NotFound);
    // Fleet accounts never, even if listed.
    let fleet = ShellHandler::new(allow(&["fleet"]));
    assert_eq!(code(&fleet, req("fleet", "id")), ErrorCode::PolicyDenied);
    // uid 0 under another name.
    let toor = ShellHandler::new(allow(&["toor"]));
    assert_eq!(code(&toor, req("toor", "id")), ErrorCode::PolicyDenied);
    // Bad bounds.
    let mut r = req("ops", "id");
    r.timeout_s = 0;
    assert_eq!(code(&ops_only, r), ErrorCode::InvalidArgument);
    // Nothing ran.
    assert!(runner.calls().is_empty());
}

#[test]
fn root_only_when_listed_and_always_elevated() {
    let d = root();
    let runner = Rc::new(FakeRunner::new());
    let c = ctx(d.path(), runner.clone());
    let h = ShellHandler::new(allow(&["root"]));
    let op = Op::ShellExec(req("root", "id"));
    let m = meta(op.clone(), None);
    h.validate(&c, &op, &m).unwrap();
    assert!(h.requires_elevated(&c, &op, &m).unwrap());
    assert_eq!(op.tier(), fleet_proto::Tier::Elevated);
    assert_eq!(op.authorization(), fleet_proto::Authorization::RootApproval);
    let argv = setpriv_argv(0, "/root", "id");
    let a: Vec<&str> = argv.iter().map(String::as_str).collect();
    runner.expect(
        crate::scope::SYSTEMD_RUN,
        &a,
        Ok(CommandOutput::ok("uid=0")),
    );
    block(h.handle(&c, &op, &meta(op.clone(), Some(9)))).unwrap();
}

#[test]
fn audit_summary_keeps_full_command_text() {
    let text = "for f in /srv/*; do du -sh \"$f\"; done";
    let op = Op::ShellExec(req("ops", text));
    let s = OpSummary::from(&op);
    assert_eq!(s.tag, fleet_proto::op::tag::SHELL_EXEC);
    let (r,): (ShellExec,) = fleet_proto::decode(&s.args).unwrap();
    assert_eq!(r.command.as_str(), text);
}
