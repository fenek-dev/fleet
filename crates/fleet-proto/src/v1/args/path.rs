//! Absolute paths and allowed-root checks.

use super::{ArgError, validated_string};

fn abs_ok(s: &str) -> bool {
    if !s.starts_with('/') || s.len() > 4096 || s.chars().any(char::is_control) {
        return false;
    }
    if s == "/" {
        return true;
    }
    // Normalized: no empty ("//", trailing '/'), "." or ".." components.
    s[1..]
        .split('/')
        .all(|c| !c.is_empty() && c != "." && c != "..")
}

validated_string!(
    /// Absolute, normalized path: starts with `/`, no `.`/`..`/empty
    /// components, no trailing `/` (except `/` itself), no NUL or other
    /// control characters, at most 4096 bytes.
    ///
    /// Lexical only: exec must still open it without following symlinks out
    /// of the allowed root (`openat2` with `RESOLVE_BENEATH`/`O_NOFOLLOW`).
    AbsPath,
    "absolute path",
    abs_ok
);

impl AbsPath {
    /// Whether `self` is `root` or lies below it (component-wise).
    pub fn is_under(&self, root: &AbsPath) -> bool {
        let (p, r) = (self.as_str(), root.as_str());
        r == "/" || p == r || (p.starts_with(r) && p.as_bytes().get(r.len()) == Some(&b'/'))
    }

    fn under_str(&self, root: &str) -> bool {
        AbsPath::new(root).is_ok_and(|r| self.is_under(&r))
    }

    /// Protected config paths whose `config.rollback` is Elevated: design
    /// §4.9 (`/etc/sudoers*`, `/etc/shadow`, `/etc/ssh/`, `/etc/fleet/`) plus
    /// the other files that grant root, run code as root (cron, units,
    /// the dynamic linker, apt hooks, logrotate scripts, module and udev
    /// rules, login shells' profiles) or control authentication directly.
    pub fn is_protected_config(&self) -> bool {
        // Files in /etc named with this prefix (`/etc/passwd-`).
        const FILE_PREFIXES: &[&str] = &[
            "/etc/sudoers",
            "/etc/shadow",
            "/etc/gshadow",
            "/etc/passwd",
            "/etc/group",
        ];
        // Anything named with this prefix, and everything below it
        // (`/etc/cron.d/x`, `/etc/ld.so.conf.d/x`, `/etc/profile.d/x`).
        const TREE_PREFIXES: &[&str] = &[
            "/etc/cron.",
            "/etc/ld.so.conf",
            "/etc/apt/sources.list",
            "/etc/profile",
        ];
        // The path itself and everything below it.
        const DIRS: &[&str] = &[
            "/etc/sudoers.d",
            "/etc/ssh",
            "/etc/fleet",
            "/etc/pam.d",
            "/etc/security",
            "/etc/crontab",
            "/etc/systemd/system",
            "/etc/ld.so.preload",
            "/etc/apt/apt.conf.d",
            "/etc/logrotate.d",
            "/etc/modprobe.d",
            "/etc/udev/rules.d",
            "/etc/bash.bashrc",
            "/etc/polkit-1",
            "/etc/sudo.conf",
            "/etc/environment",
        ];
        let p = self.as_str();
        FILE_PREFIXES.iter().any(|f| {
            p.strip_prefix(f)
                .is_some_and(|rest| rest.is_empty() || !rest.contains('/'))
        }) || TREE_PREFIXES.iter().any(|f| p.starts_with(f))
            || DIRS.iter().any(|d| self.under_str(d))
    }

    /// Fleet's own state, binaries and units: never rolled back through
    /// config history (design §4.9) or written by any typed operation.
    pub fn is_fleet_owned(&self) -> bool {
        const DIRS: &[&str] = &["/var/lib/fleet", "/usr/lib/fleet", "/run/fleet"];
        const UNIT_DIRS: &[&str] = &[
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/lib/systemd/system",
        ];
        if DIRS.iter().any(|d| self.under_str(d)) {
            return true;
        }
        let p = self.as_str();
        UNIT_DIRS.iter().any(|d| {
            p.strip_prefix(d)
                .and_then(|rest| rest.strip_prefix('/'))
                .is_some_and(|rest| rest.starts_with("fleet-") || rest.starts_with("fleet@"))
        })
    }
}

/// An [`AbsPath`] proven to lie under one of the caller's allowed roots.
/// Built by exec from a decoded `AbsPath` and the op's allow-list; never
/// decoded from the wire.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AllowedPath(AbsPath);

impl AllowedPath {
    pub fn new<'a>(
        path: &AbsPath,
        roots: impl IntoIterator<Item = &'a AbsPath>,
    ) -> Result<Self, ArgError> {
        if roots.into_iter().any(|r| path.is_under(r)) {
            Ok(Self(path.clone()))
        } else {
            Err(ArgError::NotAllowed)
        }
    }

    pub fn path(&self) -> &AbsPath {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{roundtrip, wire_rejects};
    use super::*;
    use proptest::prelude::*;

    fn p(s: &str) -> AbsPath {
        AbsPath::new(s).unwrap()
    }

    #[test]
    fn examples() {
        for ok in [
            "/",
            "/etc",
            "/etc/ssh/sshd_config",
            "/srv/app/.env",
            "/a..b/c.",
        ] {
            assert!(AbsPath::new(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "etc",
            "/etc/",
            "//etc",
            "/etc//x",
            "/etc/../root",
            "/./etc",
            "/etc/.",
            "/a\0b",
            "/a\nb",
        ] {
            assert!(AbsPath::new(bad).is_err(), "{bad:?}");
        }
        assert!(AbsPath::new(format!("/{}", "a".repeat(4095))).is_ok());
        assert!(AbsPath::new(format!("/{}", "a".repeat(4096))).is_err());

        assert!(p("/var/log/syslog").is_under(&p("/var/log")));
        assert!(p("/var/log").is_under(&p("/var/log")));
        assert!(!p("/var/logs/x").is_under(&p("/var/log")));
        assert!(p("/x").is_under(&p("/")));

        let roots = [p("/var/log"), p("/srv")];
        assert!(AllowedPath::new(&p("/srv/app/log.txt"), &roots).is_ok());
        assert_eq!(
            AllowedPath::new(&p("/etc/shadow"), &roots),
            Err(ArgError::NotAllowed)
        );

        for prot in [
            "/etc/sudoers",
            "/etc/sudoers.d/ops",
            "/etc/shadow",
            "/etc/shadow-",
            "/etc/ssh/sshd_config.d/fleet.conf",
            "/etc/fleet/authorized_keys/ops",
            "/etc/passwd",
            "/etc/pam.d/sshd",
            "/etc/crontab",
            "/etc/cron.d",
            "/etc/cron.d/backup",
            "/etc/cron.daily/logrotate",
            "/etc/cron.hourly/x",
            "/etc/cron.weekly/x",
            "/etc/cron.monthly/x",
            "/etc/cron.allow",
            "/etc/cron.deny",
            "/etc/systemd/system",
            "/etc/systemd/system/nginx.service",
            "/etc/systemd/system/multi-user.target.wants/x.service",
            "/etc/ld.so.preload",
            "/etc/ld.so.conf",
            "/etc/ld.so.conf.d/libc.conf",
            "/etc/apt/apt.conf.d/99hook",
            "/etc/apt/sources.list",
            "/etc/apt/sources.list.d/docker.list",
            "/etc/logrotate.d/nginx",
            "/etc/modprobe.d/blacklist.conf",
            "/etc/udev/rules.d/99-x.rules",
            "/etc/profile",
            "/etc/profile.d/x.sh",
            "/etc/bash.bashrc",
            "/etc/polkit-1/rules.d/49-x.rules",
            "/etc/sudo.conf",
            "/etc/environment",
            "/etc/security/limits.conf",
            "/etc/pam.d",
        ] {
            assert!(p(prot).is_protected_config(), "{prot}");
        }
        for free in [
            "/etc/nginx/nginx.conf",
            "/etc/hosts",
            "/etc/sshd",
            "/etc/fleetish",
            "/etc/crontabs",
            "/etc/systemd/network/10-eth.network",
            "/etc/systemd/journald.conf",
            "/etc/apt/preferences.d/pin",
            "/etc/logrotate.conf",
            "/etc/udev/hwdb.d/x",
            "/etc/bash_completion.d/git",
            "/etc/environment.d",
            "/etc/securityx",
        ] {
            assert!(!p(free).is_protected_config(), "{free}");
        }
        assert!(p("/var/lib/fleet/exec/state.redb").is_fleet_owned());
        assert!(p("/etc/systemd/system/fleet-exec.service").is_fleet_owned());
        assert!(!p("/etc/systemd/system/nginx.service").is_fleet_owned());
        assert!(wire_rejects::<AbsPath>("/a/../b"));
        roundtrip(&p("/srv/app"));
    }

    proptest! {
        #[test]
        fn accepts_normalized(parts in prop::collection::vec("[a-zA-Z0-9_.-]{1,12}", 0..8)) {
            prop_assume!(parts.iter().all(|c| c != "." && c != ".."));
            let s = format!("/{}", parts.join("/"));
            let path = AbsPath::new(s).unwrap();
            prop_assert!(path.is_under(&p("/")));
            roundtrip(&path);
        }

        #[test]
        fn rejects_dot_components(
            a in "[a-z]{1,8}",
            dot in "(\\.|\\.\\.)",
            b in proptest::option::of("[a-z]{1,8}"),
        ) {
            let s = match b {
                Some(b) => format!("/{a}/{dot}/{b}"),
                None => format!("/{a}/{dot}"),
            };
            prop_assert!(AbsPath::new(s.clone()).is_err());
            prop_assert!(wire_rejects::<AbsPath>(&s));
        }

        #[test]
        fn under_is_componentwise(root in "/[a-z]{1,6}", rest in "[a-z]{1,6}") {
            let r = p(&root);
            let (below, sibling) = (format!("{root}/{rest}"), format!("{root}{rest}"));
            prop_assert!(p(&below).is_under(&r));
            prop_assert!(!p(&sibling).is_under(&r));
        }
    }
}
