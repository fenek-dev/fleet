//! Which paths are tracked, which are secrets, and which may never be
//! rolled back (design §4.9).
//!
//! A rule is an absolute path or a glob ([`fleet_proto::glob`]:
//! `*`/`?` within a component, `**` across components). A plain path
//! covers itself and everything below it.

use super::store::OperatorPaths;
use crate::files::walk::{self, MAX_WALK_DEPTH, allow_match, deny_match, is_glob};
use fleet_proto::args::AbsPath;

/// Tracked by default: `/etc` plus role files (Compose projects and
/// Caddyfiles under `/srv/<project>/`).
pub const BUILTIN_TRACKED: &[&str] = &[
    "/etc",
    "/srv/*/compose.yaml",
    "/srv/*/compose.yml",
    "/srv/*/docker-compose.yaml",
    "/srv/*/docker-compose.yml",
    "/srv/*/Caddyfile",
];

/// Tracked by hash only; content is never read into history.
pub const BUILTIN_SECRET: &[&str] = &[
    "/etc/shadow",
    "/etc/shadow-",
    "/etc/gshadow",
    "/etc/gshadow-",
    // Editor and tool backups of the above (`shadow.bak`, `.shadow.swp`, …).
    "/etc/*shadow*",
    "/etc/.*shadow*",
    "/etc/security/opasswd",
    "/etc/ssh/ssh_host_*_key",
    "/etc/letsencrypt/**/privkey*",
    "/etc/letsencrypt/accounts",
    "/etc/ssl/private",
    "/etc/wireguard",
    "/etc/krb5.keytab",
    "/etc/NetworkManager/system-connections",
    "/etc/mysql/debian.cnf",
    "/etc/postfix/sasl_passwd*",
    "/etc/ppp/*-secrets",
    "/srv/**/.env",
];

/// Netplan files: secret when their content configures Wi-Fi or holds a
/// password (see `content::markers_for`).
pub const NETPLAN: &[&str] = &["/etc/netplan/*.yaml", "/etc/netplan/*.yml"];

/// Whether `path` is a netplan file.
pub fn is_netplan(path: &str) -> bool {
    // Netplan files get the secret-content check; oversized: treated as one.
    NETPLAN.iter().any(|r| deny_match(r, path))
}

/// Never rolled back through config history, beyond `AbsPath::is_fleet_owned`
/// (Fleet's state and units): Fleet's own configuration, which has typed,
/// versioned ops of its own (`authorized_keys.set`, `policy.update`).
pub const NO_ROLLBACK: &[&str] = &["/etc/fleet"];

/// Where `config.paths.set` may add tracked rules without a root-key
/// approval (anything else is Elevated: tracking reads content into
/// history that Macs and AI can see).
pub const OPERATOR_ROOTS: &[&str] = &["/etc", "/srv", "/opt", "/usr/local/etc"];

/// Whether an operator tracked rule stays under [`OPERATOR_ROOTS`].
pub fn under_operator_roots(rule: &str) -> bool {
    OPERATOR_ROOTS.iter().any(|r| covers_allow(r, rule))
}

/// Fleet's own state (its database changes constantly; never tracked).
pub const NEVER_TRACKED: &[&str] = &["/var/lib/fleet", "/run/fleet"];

/// Temp files of a rollback in progress (never tracked).
pub const TMP_MARKER: &str = ".fleet-rollback-";

fn plain_covers(rule: &str, path: &str) -> bool {
    path == rule
        || rule == "/"
        || (path.starts_with(rule) && path.as_bytes().get(rule.len()) == Some(&b'/'))
}

/// A rule of a list that GRANTS (tracked paths, operator roots): a glob
/// over the matcher's bounds does not match.
fn covers_allow(rule: &str, path: &str) -> bool {
    if is_glob(rule) {
        allow_match(rule, path)
    } else {
        plain_covers(rule, path)
    }
}

/// A rule of a list that REFUSES or PROTECTS (secret paths, no-rollback,
/// never-tracked): a glob over the matcher's bounds counts as matched.
fn covers_deny(rule: &str, path: &str) -> bool {
    if is_glob(rule) {
        deny_match(rule, path)
    } else {
        plain_covers(rule, path)
    }
}

/// Where a walk for one tracked rule starts, how deep it goes, and the
/// glob the files must match (`None` for a plain path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkRoot {
    pub root: String,
    pub max_depth: usize,
    pub pattern: Option<String>,
}

fn walk_root(rule: &str) -> Option<WalkRoot> {
    if !is_glob(rule) {
        return Some(WalkRoot {
            root: rule.to_owned(),
            max_depth: MAX_WALK_DEPTH,
            pattern: None,
        });
    }
    let comps = walk::components(rule)?;
    let first_glob = comps.iter().position(|c| is_glob(c))?;
    let root = format!("/{}", comps[..first_glob].join("/"));
    let rest = &comps[first_glob..];
    let max_depth = if rest.contains(&"**") {
        MAX_WALK_DEPTH
    } else {
        rest.len()
    };
    Some(WalkRoot {
        root,
        max_depth,
        pattern: Some(rule.to_owned()),
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathRules {
    pub operator: OperatorPaths,
}

impl PathRules {
    pub fn new(operator: OperatorPaths) -> Self {
        Self { operator }
    }

    fn tracked_rules(&self) -> impl Iterator<Item = &str> {
        BUILTIN_TRACKED
            .iter()
            .copied()
            .chain(self.operator.tracked.iter().map(String::as_str))
    }

    fn secret_rules(&self) -> impl Iterator<Item = &str> {
        BUILTIN_SECRET
            .iter()
            .copied()
            .chain(self.operator.secret.iter().map(String::as_str))
    }

    pub fn is_tracked(&self, path: &str) -> bool {
        let name = path.rsplit('/').next().unwrap_or("");
        // Walk and watch names are converted lossily: a name that wasn't
        // UTF-8 can't be opened again under its converted form.
        if name.contains(TMP_MARKER) || path.contains(char::REPLACEMENT_CHARACTER) {
            return false;
        }
        if NEVER_TRACKED.iter().any(|r| covers_deny(r, path)) {
            return false;
        }
        self.tracked_rules().any(|r| covers_allow(r, path))
    }

    /// Path-based secret check (content with a `PRIVATE KEY` block is a
    /// secret too; see `content`).
    pub fn is_secret(&self, path: &str) -> bool {
        self.secret_rules().any(|r| covers_deny(r, path))
    }

    /// Whether `config.rollback` may write `path`.
    pub fn rollback_allowed(path: &AbsPath) -> bool {
        !path.is_fleet_owned() && !NO_ROLLBACK.iter().any(|r| covers_deny(r, path.as_str()))
    }

    /// Walks a full scan makes (one per tracked rule).
    pub fn walk_roots(&self) -> Vec<WalkRoot> {
        let mut v: Vec<WalkRoot> = self.tracked_rules().filter_map(walk_root).collect();
        v.sort_by(|a, b| a.root.cmp(&b.root));
        v.dedup();
        v
    }

    /// Plain tracked directories (inotify watch roots).
    pub fn watch_roots(&self) -> Vec<String> {
        self.tracked_rules()
            .filter(|r| !is_glob(r))
            .map(str::to_owned)
            .collect()
    }

    pub fn builtin_tracked() -> Vec<String> {
        BUILTIN_TRACKED.iter().map(|s| (*s).to_owned()).collect()
    }

    pub fn builtin_secret() -> Vec<String> {
        BUILTIN_SECRET.iter().map(|s| (*s).to_owned()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> AbsPath {
        AbsPath::new(s).unwrap()
    }

    #[test]
    fn builtin_lists() {
        let r = PathRules::default();
        for s in [
            "/etc/shadow",
            "/etc/gshadow-",
            "/etc/ssh/ssh_host_ed25519_key",
            "/etc/letsencrypt/live/x.org/privkey.pem",
            "/etc/ssl/private/site.key",
            "/etc/wireguard/wg0.conf",
            "/srv/app/.env",
            "/srv/a/b/.env",
            "/etc/shadow.bak",
            "/etc/gshadow.dpkg-old",
            "/etc/.shadow.swp",
            "/etc/security/opasswd",
            "/etc/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory/x/private_key.json",
            "/etc/krb5.keytab",
            "/etc/NetworkManager/system-connections/home.nmconnection",
            "/etc/mysql/debian.cnf",
            "/etc/postfix/sasl_passwd",
            "/etc/postfix/sasl_passwd.db",
            "/etc/ppp/chap-secrets",
            "/etc/ppp/pap-secrets",
        ] {
            assert!(r.is_secret(s), "{s}");
        }
        for s in [
            "/etc/ssh/ssh_host_ed25519_key.pub",
            "/etc/passwd",
            "/etc/letsencrypt/live/x.org/fullchain.pem",
            "/srv/app/compose.yaml",
            "/etc/security/limits.conf",
            "/etc/mysql/my.cnf",
            "/etc/ppp/options",
            "/etc/netplan/50-cloud-init.yaml",
        ] {
            assert!(!r.is_secret(s), "{s}");
        }
        assert!(is_netplan("/etc/netplan/50-cloud-init.yaml"));
        assert!(!is_netplan("/etc/netplan/sub/x.yaml"));
        assert!(!r.is_tracked("/etc/bad\u{fffd}name.conf"));
        assert!(r.is_tracked("/etc/nginx/nginx.conf"));
        assert!(r.is_tracked("/srv/app/compose.yaml"));
        assert!(!r.is_tracked("/srv/app/data/compose.yaml"));
        assert!(!r.is_tracked("/etc/.x.fleet-rollback-7"));
        assert!(!r.is_tracked("/var/lib/fleet/exec/state.redb"));
        assert!(!r.is_tracked("/etcetera"));
    }

    #[test]
    fn oversized_input_fails_closed_per_call_site() {
        let long = format!("/etc/{}", "a".repeat(5000));
        let r = PathRules::default();
        // Deny-type: secret, never-tracked, netplan (content check).
        assert!(r.is_secret(&long));
        assert!(is_netplan(&long));
        assert!(covers_deny("/etc/*x*", &long));
        // Allow-type: tracked glob rules and operator roots grant nothing.
        assert!(!covers_allow("/srv/*/compose.yaml", &long));
        let huge_rule = format!("/opt/{}*", "a".repeat(5000));
        let ops = PathRules::new(OperatorPaths {
            tracked: vec![huge_rule.clone()],
            secret: vec![huge_rule],
            version: 1,
        });
        assert!(!ops.is_tracked("/opt/x"), "oversized tracked rule grants nothing");
        assert!(ops.is_secret("/opt/x"), "oversized secret rule protects");
    }

    #[test]
    fn operator_rules_extend() {
        let r = PathRules::new(OperatorPaths {
            tracked: vec!["/opt/game/server.cfg".into(), "/home/*/app/*.toml".into()],
            secret: vec!["/etc/app/token".into(), "/opt/**/*.key".into()],
            version: 1,
        });
        assert!(r.is_tracked("/opt/game/server.cfg"));
        assert!(r.is_tracked("/home/bob/app/x.toml"));
        assert!(r.is_secret("/etc/app/token"));
        assert!(r.is_secret("/opt/game/tls/a.key"));
        let roots = r.walk_roots();
        assert!(roots.contains(&WalkRoot {
            root: "/home".into(),
            max_depth: 3,
            pattern: Some("/home/*/app/*.toml".into()),
        }));
        assert!(
            roots
                .iter()
                .any(|w| w.root == "/etc" && w.pattern.is_none())
        );
    }

    #[test]
    fn operator_roots() {
        for (s, ok) in [
            ("/etc/app.conf", true),
            ("/etc", true),
            ("/srv/*/app.toml", true),
            ("/opt/**/*.cfg", true),
            ("/usr/local/etc/x.conf", true),
            ("/usr/local/bin/x", false),
            ("/home/*/app/*.toml", false),
            ("/root/.ssh/id_ed25519", false),
            ("/etcetera", false),
            ("/etc*", false),
            ("/**", false),
            ("/", false),
        ] {
            assert_eq!(under_operator_roots(s), ok, "{s}");
        }
    }

    #[test]
    fn rollback_refusals() {
        for s in [
            "/etc/fleet/policy.toml",
            "/etc/fleet",
            "/var/lib/fleet/exec/state.redb",
            "/etc/systemd/system/fleet-exec.service",
        ] {
            assert!(!PathRules::rollback_allowed(&p(s)), "{s}");
        }
        assert!(PathRules::rollback_allowed(&p("/etc/nginx/nginx.conf")));
        assert!(PathRules::rollback_allowed(&p("/etc/fleetish")));
    }
}
