//! System names: units, users, groups, Debian packages, game servers.

use super::validated_string;

fn unit_ok(s: &str) -> bool {
    let Some((stem, suffix)) = s.rsplit_once('.') else {
        return false;
    };
    s.len() <= 256
        && matches!(suffix, "service" | "timer" | "socket")
        && !stem.is_empty()
        // Not in the design regex, but a leading '-' could read as an option.
        && !stem.starts_with('-')
        && stem
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"@._-".contains(&c))
}

validated_string!(
    /// systemd unit: `^[A-Za-z0-9@._-]+\.(service|timer|socket)$`, at most
    /// 256 bytes, not starting with `-`.
    UnitName,
    "unit name",
    unit_ok
);

impl UnitName {
    /// Fleet's own units (`fleet-*`), which no operation may change.
    pub fn is_fleet(&self) -> bool {
        self.0.starts_with("fleet-") || self.0.starts_with("fleet@") || self.0.starts_with("fleet.")
    }
}

/// `^[a-z_][a-z0-9_-]{0,31}$`
fn posix_name_ok(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=32).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

validated_string!(
    /// Login name: `^[a-z_][a-z0-9_-]{0,31}$`.
    UserName,
    "user name",
    posix_name_ok
);

impl UserName {
    pub fn is_root(&self) -> bool {
        self.0 == "root"
    }
}

validated_string!(
    /// Group name: `^[a-z_][a-z0-9_-]{0,31}$`.
    GroupName,
    "group name",
    posix_name_ok
);

/// Groups whose membership is root-equivalent on Debian/Ubuntu. Adding a user
/// to one makes `users.create`/`users.groups.set` Elevated (design §4.2 names
/// `sudo` and `docker`; the rest grant root just as directly).
pub const PRIVILEGED_GROUPS: &[&str] = &["root", "sudo", "docker", "disk", "shadow", "lxd"];

impl GroupName {
    pub fn is_privileged(&self) -> bool {
        PRIVILEGED_GROUPS.contains(&self.0.as_str())
    }
}

validated_string!(
    /// Debian package name (Policy §5.6.7): `^[a-z0-9][a-z0-9+.-]+$`,
    /// 2–128 bytes.
    DebPackageName,
    "package name",
    |s| {
        let b = s.as_bytes();
        (2..=128).contains(&b.len())
            && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
            && b.iter()
                .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"+.-".contains(&c))
    }
);

fn deb_version_ok(s: &str) -> bool {
    let upstream = match s.split_once(':') {
        Some((epoch, rest)) => {
            if epoch.is_empty() || epoch.len() > 5 || !epoch.bytes().all(|c| c.is_ascii_digit()) {
                return false;
            }
            rest
        }
        None => s,
    };
    (1..=128).contains(&s.len())
        && upstream.starts_with(|c: char| c.is_ascii_digit())
        && !upstream.ends_with('-')
        && upstream
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".+~:-".contains(&c))
}

validated_string!(
    /// Debian version `[epoch:]upstream[-revision]`, at most 128 bytes:
    /// digits for the epoch, upstream starting with a digit, characters from
    /// `[A-Za-z0-9.+~:-]`.
    DebVersion,
    "package version",
    deb_version_ok
);

validated_string!(
    /// Game server template id: `^[a-z0-9][a-z0-9-]{0,31}$`.
    GameTemplateId,
    "game template id",
    |s| {
        let b = s.as_bytes();
        (1..=32).contains(&b.len())
            && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
            && b.iter()
                .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    }
);

validated_string!(
    /// Game server instance: `^[a-z][a-z0-9-]{0,23}$`. Its system user is
    /// `game-<name>` (at most 29 bytes, a valid [`UserName`]) and its data
    /// lives in `/srv/games/<name>`.
    GameName,
    "game name",
    |s| {
        let b = s.as_bytes();
        (1..=24).contains(&b.len())
            && b[0].is_ascii_lowercase()
            && b.iter()
                .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    }
);

#[cfg(test)]
mod tests {
    use super::super::testutil::{roundtrip, wire_rejects};
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn examples() {
        for ok in [
            "nginx.service",
            "getty@tty1.service",
            "apt-daily.timer",
            "docker.socket",
        ] {
            assert!(UnitName::new(ok).is_ok(), "{ok}");
        }
        for bad in [
            ".service",
            "nginx",
            "nginx.mount",
            "-x.service",
            "a b.service",
            "a/b.service",
            "a;b.service",
            "nginx.service ",
        ] {
            assert!(UnitName::new(bad).is_err(), "{bad}");
        }
        assert!(UnitName::new(format!("{}.service", "a".repeat(248))).is_ok());
        assert!(UnitName::new(format!("{}.service", "a".repeat(249))).is_err());
        assert!(UnitName::new("fleet-exec.service").unwrap().is_fleet());
        assert!(!UnitName::new("fleetwood.service").unwrap().is_fleet());

        assert!(UserName::new("root").unwrap().is_root());
        assert!(UserName::new("_apt").is_ok());
        assert!(UserName::new("1abc").is_err());
        assert!(UserName::new("Admin").is_err());
        assert!(UserName::new("a".repeat(33)).is_err());
        assert!(GroupName::new("sudo").unwrap().is_privileged());
        assert!(!GroupName::new("adm").unwrap().is_privileged());

        assert!(DebPackageName::new("libc6").is_ok());
        assert!(DebPackageName::new("g++").is_ok());
        assert!(DebPackageName::new("a").is_err());
        assert!(DebPackageName::new("-rf").is_err());
        assert!(DebPackageName::new("Foo").is_err());
        assert!(DebPackageName::new("foo_bar").is_err());

        for ok in ["1.2.3", "1:2.36-9+deb12u4", "2.0~rc1-1", "0"] {
            assert!(DebVersion::new(ok).is_ok(), "{ok}");
        }
        for bad in ["", "a1", ":1.0", "x:1.0", "1.0-", "1.0 1", "1.0;rm"] {
            assert!(DebVersion::new(bad).is_err(), "{bad}");
        }
        assert!(GameName::new("valheim-1").is_ok());
        assert!(GameName::new("1valheim").is_err());
        assert!(GameTemplateId::new("minecraft-java").is_ok());
        assert!(wire_rejects::<UnitName>("x.mount"));
        roundtrip(&UnitName::new("ssh.service").unwrap());
    }

    proptest! {
        #[test]
        fn unit_accepts(stem in "[A-Za-z0-9@._][A-Za-z0-9@._-]{0,40}", sfx in "(service|timer|socket)") {
            let s = format!("{stem}.{sfx}");
            prop_assert!(UnitName::new(s.clone()).is_ok());
            roundtrip(&UnitName::new(s).unwrap());
        }

        #[test]
        fn unit_rejects_bad_char(a in "[a-z]{1,8}", c in "[^A-Za-z0-9@._-]", b in "[a-z]{0,8}") {
            let s = format!("{a}{c}{b}.service");
            prop_assert!(UnitName::new(s.clone()).is_err());
            prop_assert!(wire_rejects::<UnitName>(&s));
        }

        #[test]
        fn user_accepts(s in "[a-z_][a-z0-9_-]{0,31}") {
            prop_assert!(UserName::new(s.clone()).is_ok());
            prop_assert!(GroupName::new(s).is_ok());
        }

        #[test]
        fn user_rejects(s in "[A-Z0-9-][a-z]{0,8}|[a-z]{1,4}[^a-z0-9_-][a-z]{0,4}|[a-z]{33,40}") {
            prop_assert!(UserName::new(s.clone()).is_err());
            prop_assert!(wire_rejects::<UserName>(&s));
        }

        #[test]
        fn package_accepts(s in "[a-z0-9][a-z0-9+.-]{1,60}") {
            prop_assert!(DebPackageName::new(s).is_ok());
        }

        #[test]
        fn package_rejects(s in "[a-z]{1,5}[A-Z_ /;$][a-z]{0,5}") {
            prop_assert!(DebPackageName::new(s).is_err());
        }

        #[test]
        fn version_accepts(e in proptest::option::of("[0-9]{1,3}"), u in "[0-9][A-Za-z0-9.+~]{0,20}", r in proptest::option::of("[A-Za-z0-9.+~]{1,10}")) {
            let mut s = String::new();
            if let Some(e) = e { s.push_str(&e); s.push(':'); }
            s.push_str(&u);
            if let Some(r) = r { s.push('-'); s.push_str(&r); }
            prop_assert!(DebVersion::new(s).is_ok());
        }
    }
}
