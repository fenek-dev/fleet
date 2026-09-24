//! Helpers for [`OpHandler::requires_elevated`](crate::OpHandler::requires_elevated)
//! (conditional Elevated, design §4.2). Handlers of ops with
//! `Op::may_escalate()` call these; exec answers `ApprovalRequired` when one
//! says yes and the command carries no valid root approval.

use crate::compose;
use crate::ctx::SysCtx;
use crate::handler::OpError;
use fleet_proto::args::PRIVILEGED_GROUPS;
use fleet_proto::{ErrorCode, Op};

/// `compose.deploy`: `true` if the file uses a deny-listed feature;
/// `InvalidArgument` if it doesn't parse or has the wrong shape (see
/// [`compose::validate`]). `false` for every other op.
pub fn compose_deploy(op: &Op) -> Result<bool, OpError> {
    let Op::ComposeDeploy { project, file, .. } = op else {
        return Ok(false);
    };
    let v = compose::validate(project, file.as_str());
    if !v.ok {
        return Err(OpError::new(ErrorCode::InvalidArgument)
            .with_detail(format!("compose file: {:?}", v.errors)));
    }
    Ok(v.escalates())
}

/// `cron.set`: `true` for a user that is root-equivalent (uid 0, or a
/// member of a [`PRIVILEGED_GROUPS`] group, primary or supplementary).
/// `root` itself is already Elevated from the arguments.
pub fn cron_set(ctx: &SysCtx, op: &Op) -> Result<bool, OpError> {
    match op {
        Op::CronSet { user, .. } => user_is_privileged(ctx, user.as_str()),
        _ => Ok(false),
    }
}

fn read(ctx: &SysCtx, abs: &str) -> Result<String, OpError> {
    let p = ctx.path(abs).ok_or_else(|| OpError::internal(abs))?;
    std::fs::read_to_string(&p).map_err(|e| OpError::internal(format!("{abs}: {e}")))
}

/// From `/etc/passwd` and `/etc/group` (under the context root). An
/// unknown user is not privileged (the op itself then fails).
pub fn user_is_privileged(ctx: &SysCtx, user: &str) -> Result<bool, OpError> {
    let passwd = read(ctx, "/etc/passwd")?;
    let group = read(ctx, "/etc/group")?;
    let entry = passwd
        .lines()
        .map(|l| l.split(':').collect::<Vec<_>>())
        .find(|f| f.first() == Some(&user));
    let Some(f) = entry else {
        return Ok(false);
    };
    if f.get(2) == Some(&"0") {
        return Ok(true);
    }
    let primary_gid = f.get(3).copied();
    Ok(group.lines().any(|l| {
        let g: Vec<&str> = l.split(':').collect();
        let (Some(name), Some(gid)) = (g.first(), g.get(2)) else {
            return false;
        };
        (PRIVILEGED_GROUPS.contains(name) || *gid == "0")
            && (primary_gid == Some(*gid)
                || g.get(3)
                    .is_some_and(|m| m.split(',').any(|m| m.trim() == user)))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FakeRunner, ManualClock};
    use fleet_proto::args::{ComposeFile, ComposeProject, UserName};
    use std::rc::Rc;

    fn ctx() -> (tempfile::TempDir, SysCtx) {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("etc")).unwrap();
        std::fs::write(
            d.path().join("etc/passwd"),
            "root:x:0:0::/root:/bin/sh\nops:x:1000:1000::/home/ops:/bin/bash\n\
             web:x:1001:1001::/srv:/usr/sbin/nologin\ndock:x:1002:999::/:/bin/sh\n\
             toor:x:0:1003::/:/bin/sh\n",
        )
        .unwrap();
        std::fs::write(
            d.path().join("etc/group"),
            "root:x:0:\nsudo:x:27:ops\nops:x:1000:\nweb:x:1001:\ndocker:x:999:\n",
        )
        .unwrap();
        let c = SysCtx::new(
            d.path(),
            Rc::new(FakeRunner::new()),
            Rc::new(ManualClock::new(0)),
        );
        (d, c)
    }

    #[test]
    fn privileged_users() {
        let (_d, c) = ctx();
        assert!(user_is_privileged(&c, "ops").unwrap()); // sudo member
        assert!(user_is_privileged(&c, "dock").unwrap()); // primary docker
        assert!(user_is_privileged(&c, "toor").unwrap()); // uid 0
        assert!(!user_is_privileged(&c, "web").unwrap());
        assert!(!user_is_privileged(&c, "nobody").unwrap());
        let op = |u: &str| Op::CronSet {
            user: UserName::new(u).unwrap(),
            entries: Vec::new(),
        };
        assert!(cron_set(&c, &op("ops")).unwrap());
        assert!(!cron_set(&c, &op("web")).unwrap());
        assert!(!cron_set(&c, &Op::SystemInfo).unwrap());
    }

    #[test]
    fn compose_escalation() {
        let op = |y: &str| Op::ComposeDeploy {
            project: ComposeProject::new("app").unwrap(),
            file: ComposeFile::new(y).unwrap(),
            pull: false,
        };
        assert!(!compose_deploy(&op("services:\n  w:\n    image: x\n")).unwrap());
        assert!(compose_deploy(&op("services:\n  w:\n    privileged: true\n")).unwrap());
        assert_eq!(
            compose_deploy(&op("a: &x 1\n")).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
    }
}
