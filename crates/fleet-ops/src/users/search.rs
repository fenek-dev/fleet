//! `search.users` (design §2.7): users whose name or GECOS comment matches
//! the term, and groups whose name matches, from `/etc/passwd` and
//! `/etc/group` (the users module's parsers). Hits are `SearchKind::User`:
//! `primary` is the user name, or `group:<name>` for a group; `detail`
//! carries uid/gid, groups or members and the shell. Server data only.

use super::parse::{parse_group, parse_passwd};
use crate::ctx::SysCtx;
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput};
use crate::search::{Hits, Matcher};
use fleet_proto::args::SearchQuery;
use fleet_proto::payload::{SearchKind, SearchResults};
use fleet_proto::{ErrorCode, Op, Payload};

/// Groups named in one hit's detail.
const MAX_LISTED: usize = 32;

fn list(names: impl Iterator<Item = String>) -> String {
    let v: Vec<String> = names.take(MAX_LISTED + 1).collect();
    if v.len() > MAX_LISTED {
        format!("{},…", v[..MAX_LISTED].join(","))
    } else {
        v.join(",")
    }
}

pub fn search(ctx: &SysCtx, q: &SearchQuery) -> SearchResults {
    let m = Matcher::new(q);
    let passwd = parse_passwd(&ctx.procfs.read("/etc/passwd").unwrap_or_default());
    let groups = parse_group(&ctx.procfs.read("/etc/group").unwrap_or_default());
    let mut hits = Hits::new(q.limit);
    for u in &passwd {
        if !(m.matches(&u.name) || m.matches(&u.gecos)) {
            continue;
        }
        let detail = format!(
            "uid {} · groups {} · shell {}{}",
            u.uid,
            list(u.groups_in(&groups).map(|g| g.name.clone())),
            u.shell,
            if u.gecos.is_empty() {
                String::new()
            } else {
                format!(" · {}", u.gecos)
            }
        );
        if !hits.push(SearchKind::User, u.name.clone(), detail) {
            return hits.done();
        }
    }
    for g in &groups {
        if !m.matches(&g.name) {
            continue;
        }
        let detail = format!("gid {} · members {}", g.gid, list(g.members.iter().cloned()));
        if !hits.push(SearchKind::User, format!("group:{}", g.name), detail) {
            break;
        }
    }
    hits.done()
}

/// `search.users`.
pub struct SearchUsersHandler;

impl OpHandler for SearchUsersHandler {
    fn validate(&self, _ctx: &SysCtx, op: &Op, _meta: &OpMeta) -> Result<(), OpError> {
        match op {
            Op::SearchUsers(q) => q.validate().map_err(|e| ErrorCode::from(e).into()),
            _ => Err(ErrorCode::Unsupported.into()),
        }
    }

    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        op: &'a Op,
        _meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            let Op::SearchUsers(q) = op else {
                return Err(ErrorCode::Unsupported.into());
            };
            Ok(OpOutput::Payload(Payload::SearchResults(search(ctx, q))))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FakeRunner;
    use crate::testutil::{T0, block, ctx_at, meta};
    use fleet_proto::args::{SearchTerm, TimeRange};
    use std::rc::Rc;

    fn q(term: &str, limit: u32) -> SearchQuery {
        SearchQuery {
            term: SearchTerm::new(term).unwrap(),
            case_sensitive: false,
            roots: vec![],
            range: TimeRange::default(),
            limit,
        }
    }

    #[test]
    fn users_and_groups() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::create_dir_all(d.join("etc")).unwrap();
        std::fs::write(
            d.join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/bash\nops:x:1000:1000:Ops Team:/home/ops:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n",
        )
        .unwrap();
        std::fs::write(
            d.join("etc/group"),
            "root:x:0:\nsudo:x:27:ops\nops:x:1000:\nopsadmins:x:1001:ops,root\n",
        )
        .unwrap();
        let c = ctx_at(d, Rc::new(FakeRunner::new()), T0);
        let r = search(&c, &q("OPS", 10));
        let p: Vec<&str> = r.hits.iter().map(|h| h.primary.as_str()).collect();
        assert_eq!(p, ["ops", "group:ops", "group:opsadmins"]);
        assert!(r.hits[0].detail.contains("groups sudo,ops,opsadmins"), "{}", r.hits[0].detail);
        assert!(r.hits[2].detail.contains("members ops,root"));
        assert!(!r.truncated);
        // GECOS matches too; the limit truncates.
        assert_eq!(search(&c, &q("team", 10)).hits.len(), 1);
        let r = search(&c, &q("o", 2));
        assert_eq!((r.hits.len(), r.truncated), (2, true));
        let op = Op::SearchUsers(q("root", 10));
        let h = SearchUsersHandler;
        h.validate(&c, &op, &meta(op.clone(), None)).unwrap();
        let out = block(h.handle(&c, &op, &meta(op.clone(), Some(1)))).unwrap();
        assert!(matches!(out, OpOutput::Payload(Payload::SearchResults(r)) if r.hits.len() == 2));
    }
}
