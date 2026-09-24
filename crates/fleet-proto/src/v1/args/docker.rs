//! Docker and Compose names.

use super::validated_string;
use serde::{Deserialize, Serialize};

validated_string!(
    /// Full or short container id: 12–64 lowercase hex characters.
    ContainerId,
    "container id",
    |s| (12..=64).contains(&s.len()) && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
);

/// Docker's name rule `[a-zA-Z0-9][a-zA-Z0-9_.-]+`, 2–128 bytes.
fn docker_name_ok(s: &str) -> bool {
    let b = s.as_bytes();
    (2..=128).contains(&b.len())
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|&c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
}

validated_string!(
    /// Container name: `^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,127}$`.
    ContainerName,
    "container name",
    docker_name_ok
);

validated_string!(
    /// Volume name: `^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,127}$`.
    VolumeName,
    "volume name",
    docker_name_ok
);

/// A container by id or by name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ContainerRef {
    Id(ContainerId),
    Name(ContainerName),
}

validated_string!(
    /// Compose project: `^[a-z0-9][a-z0-9_-]{0,62}$`. Lives in
    /// `/srv/<project>/`.
    ComposeProject,
    "compose project",
    |s| {
        let b = s.as_bytes();
        (1..=63).contains(&b.len())
            && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
            && b.iter()
                .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
    }
);

fn registry_ok(h: &str) -> bool {
    let (host, port) = match h.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (h, None),
    };
    let port_ok =
        port.is_none_or(|p| (1..=5).contains(&p.len()) && p.bytes().all(|c| c.is_ascii_digit()));
    port_ok
        && (1..=253).contains(&host.len())
        && host.split('.').all(|label| {
            let b = label.as_bytes();
            !b.is_empty()
                && b[0] != b'-'
                && b[b.len() - 1] != b'-'
                && b.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'-')
        })
}

fn path_component_ok(c: &str) -> bool {
    let b = c.as_bytes();
    let alnum = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    !b.is_empty()
        && alnum(b[0])
        && alnum(b[b.len() - 1])
        && b.iter().all(|&c| alnum(c) || b"._-".contains(&c))
}

fn image_ref_ok(s: &str) -> bool {
    if s.is_empty() || s.len() > 512 {
        return false;
    }
    let (rest, digest) = match s.split_once('@') {
        Some((r, d)) => (r, Some(d)),
        None => (s, None),
    };
    if let Some(d) = digest {
        let Some(hex) = d.strip_prefix("sha256:") else {
            return false;
        };
        if hex.len() != 64 || !hex.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
            return false;
        }
    }
    let last_slash = rest.rfind('/');
    let (name, tag) = match rest.rfind(':') {
        Some(i) if last_slash.is_none_or(|j| i > j) => (&rest[..i], Some(&rest[i + 1..])),
        _ => (rest, None),
    };
    if let Some(t) = tag {
        let b = t.as_bytes();
        let ok = (1..=128).contains(&b.len())
            && (b[0].is_ascii_alphanumeric() || b[0] == b'_')
            && b.iter()
                .all(|&c| c.is_ascii_alphanumeric() || b"_.-".contains(&c));
        if !ok {
            return false;
        }
    }
    if name.is_empty() || name.len() > 255 {
        return false;
    }
    let mut parts: Vec<&str> = name.split('/').collect();
    if parts.len() > 1 {
        let first = parts[0];
        if first.contains('.') || first.contains(':') || first == "localhost" {
            if !registry_ok(first) {
                return false;
            }
            parts.remove(0);
        }
    }
    !parts.is_empty() && parts.into_iter().all(path_component_ok)
}

validated_string!(
    /// Image reference `[registry[:port]/]path[:tag][@sha256:<hex>]`, at most
    /// 512 bytes. Path components are lowercase; tags follow Docker's rule.
    ImageRef,
    "image reference",
    image_ref_ok
);

#[cfg(test)]
mod tests {
    use super::super::testutil::{roundtrip, wire_rejects};
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn examples() {
        let digest = format!("@sha256:{}", "a".repeat(64));
        for ok in [
            "nginx".to_owned(),
            "nginx:1.27-alpine".to_owned(),
            "library/nginx:latest".to_owned(),
            "ghcr.io/owner/app:v1.2.3".to_owned(),
            "localhost:5000/app".to_owned(),
            "registry.example.com:443/team/app_x".to_owned(),
            format!("nginx{digest}"),
            format!("ghcr.io/a/b:1{digest}"),
        ] {
            assert!(ImageRef::new(ok.clone()).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "Nginx",
            "nginx:",
            "nginx:-x",
            "-nginx",
            "a//b",
            "nginx@sha256:abc",
            "nginx@md5:00",
            "ghcr.io:x/app",
            "nginx latest",
            "nginx;rm",
        ] {
            assert!(ImageRef::new(bad).is_err(), "{bad}");
        }
        assert!(ContainerId::new("0123456789ab").is_ok());
        assert!(ContainerId::new("0123456789AB").is_err());
        assert!(ContainerId::new("0123456789a").is_err());
        assert!(ContainerName::new("web-1").is_ok());
        assert!(ContainerName::new("/web").is_err());
        assert!(ContainerName::new("w").is_err());
        assert!(ComposeProject::new("my_app-2").is_ok());
        assert!(ComposeProject::new("My").is_err());
        assert!(ComposeProject::new("../etc").is_err());
        assert!(wire_rejects::<ImageRef>("UPPER"));
        roundtrip(&ContainerRef::Name(ContainerName::new("db").unwrap()));
    }

    proptest! {
        #[test]
        fn image_accepts(
            reg in proptest::option::of("[a-z0-9]{1,8}\\.[a-z]{2,4}(:[0-9]{1,5})?"),
            // No '.' in paths: a dotted first component reads as a registry.
            path in prop::collection::vec("[a-z0-9]([a-z0-9_-]{0,8}[a-z0-9])?", 1..4),
            tag in proptest::option::of("[A-Za-z0-9_][A-Za-z0-9_.-]{0,20}"),
        ) {
            let mut s = String::new();
            if let Some(r) = reg { s.push_str(&r); s.push('/'); }
            s.push_str(&path.join("/"));
            if let Some(t) = tag { s.push(':'); s.push_str(&t); }
            prop_assert!(ImageRef::new(s.clone()).is_ok(), "{}", s);
            roundtrip(&ImageRef::new(s).unwrap());
        }

        #[test]
        fn image_rejects_bad_char(a in "[a-z]{1,6}", c in "[^a-zA-Z0-9._/:@-]", b in "[a-z]{0,6}") {
            let s = format!("{a}{c}{b}");
            prop_assert!(ImageRef::new(s).is_err());
        }

        #[test]
        fn names_accept(s in "[a-zA-Z0-9][a-zA-Z0-9_.-]{1,60}") {
            prop_assert!(ContainerName::new(s.clone()).is_ok());
            prop_assert!(VolumeName::new(s).is_ok());
        }

        #[test]
        fn project_rejects(s in "[a-z]{0,4}[A-Z./ ][a-z]{0,4}") {
            prop_assert!(ComposeProject::new(s).is_err());
        }
    }
}
