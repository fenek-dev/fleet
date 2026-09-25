//! `/etc/passwd`, `/etc/group`, `/etc/shadow` and `/etc/login.defs`
//! parsers. Shadow parsing keeps only lock/expiry state, never hashes.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub home: String,
    pub shell: String,
}

/// Malformed lines (wrong field count, non-numeric ids, NIS `+` entries)
/// are skipped.
pub fn parse_passwd(s: &str) -> Vec<PasswdEntry> {
    s.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() != 7 || f[0].is_empty() || f[0].starts_with(['+', '-']) {
                return None;
            }
            Some(PasswdEntry {
                name: f[0].to_owned(),
                uid: f[2].parse().ok()?,
                gid: f[3].parse().ok()?,
                gecos: f[4].to_owned(),
                home: f[5].to_owned(),
                shell: f[6].to_owned(),
            })
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEntry {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

pub fn parse_group(s: &str) -> Vec<GroupEntry> {
    s.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() != 4 || f[0].is_empty() || f[0].starts_with(['+', '-']) {
                return None;
            }
            Some(GroupEntry {
                name: f[0].to_owned(),
                gid: f[2].parse().ok()?,
                members: f[3]
                    .split(',')
                    .map(str::trim)
                    .filter(|m| !m.is_empty())
                    .map(str::to_owned)
                    .collect(),
            })
        })
        .collect()
}

/// What `users.list` needs from `/etc/shadow`: no hash, no dates but expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShadowState {
    /// A real password hash locked with `!` (`usermod --lock`). A bare `!`
    /// or `*` (no password set) is not a lock: key login still works.
    pub password_locked: bool,
    /// Account expiry, days since the epoch (`usermod --expiredate`).
    pub expire_day: Option<u64>,
}

impl ShadowState {
    /// Locked for login: locked hash, or expired on or before `today`.
    pub fn locked(&self, today: u64) -> bool {
        self.password_locked || self.expire_day.is_some_and(|d| d <= today)
    }
}

pub fn parse_shadow(s: &str) -> HashMap<String, ShadowState> {
    s.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 8 || f[0].is_empty() {
                return None;
            }
            let pw = f[1];
            let password_locked =
                pw.starts_with('!') && pw.trim_start_matches('!').starts_with('$');
            let expire_day = f[7].trim().parse().ok();
            Some((
                f[0].to_owned(),
                ShadowState {
                    password_locked,
                    expire_day,
                },
            ))
        })
        .collect()
}

/// `(UID_MIN, UID_MAX)` from `/etc/login.defs`; defaults 1000, 60000.
pub fn uid_range(login_defs: &str) -> (u32, u32) {
    let mut r = (1000, 60000);
    for l in login_defs.lines() {
        let mut it = l.split_whitespace();
        match (it.next(), it.next().and_then(|v| v.parse().ok())) {
            (Some("UID_MIN"), Some(v)) => r.0 = v,
            (Some("UID_MAX"), Some(v)) => r.1 = v,
            _ => {}
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwd_group_shadow() {
        let p = parse_passwd(
            "root:x:0:0:root:/root:/bin/bash\n+nis::::::\nbad:x:a:0::/:/bin/sh\n\
             ops:x:1000:1000:Ops,,,:/home/ops:/bin/bash\n",
        );
        assert_eq!(p.len(), 2);
        assert_eq!(p[1].gecos, "Ops,,,");
        let g = parse_group("sudo:x:27:ops, web\nempty:x:5:\nbroken\n");
        assert_eq!(g[0].members, ["ops", "web"]);
        assert!(g[1].members.is_empty());
        assert_eq!(g.len(), 2);
        let s = parse_shadow(
            "a:!$6$salt$hash:19000:0:99999:7:::\nb:!:19000:0:99999:7:::\n\
             c:$6$x$y:19000:0:99999:7::1:\nd:*:1::::::\n",
        );
        assert!(s["a"].password_locked);
        assert!(!s["b"].password_locked);
        assert!(s["c"].locked(20000));
        assert!(!s["c"].password_locked);
        assert!(!s["d"].locked(20000));
        assert_eq!(
            uid_range("UID_MIN 2000\n#UID_MAX 1\nUID_MAX\t50000\n"),
            (2000, 50000)
        );
    }
}
