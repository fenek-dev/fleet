//! cloud-init export (design §9.7): a `#cloud-config` that creates the
//! admin user with the enrolled Macs' public keys, installs `sshd` host
//! keys generated on the Mac (pinned there at the same moment, so the
//! first connection trusts nothing on first use), and turns off root and
//! password login. No bootstrap script: on the first SSH connection the
//! Mac takes over and applies the full profile.
//!
//! The admin gets cloud-init's usual passwordless sudo
//! (`/etc/sudoers.d/90-cloud-init-users`) so the Mac can install the agent
//! (design §10.1 needs root or passwordless sudo); the profile's
//! `sudo.policy` module removes that grant in phase 1 (Accounts), when
//! the per-server sudo password is set.
//!
//! Pure. The YAML is built from a typed tree: keys are fixed identifiers
//! and every value is emitted as a double-quoted scalar with full
//! escaping, so no input can change the document's structure.
#![forbid(unsafe_code)]

use fleet_proto::args::{SshKeyAlgo, SshPublicKey, UserName};
use std::fmt::Write as _;

pub const BOOTSTRAP_SSHD: &str = "/etc/ssh/sshd_config.d/05-fleet-bootstrap.conf";
const MAX_PRIVATE: usize = 8 << 10;
const MAX_KEYS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKey {
    /// OpenSSH private key (`-----BEGIN OPENSSH PRIVATE KEY-----` …).
    pub private_openssh: String,
    /// Its public key; the algorithm picks the cloud-init slot.
    pub public: SshPublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudInit {
    pub admin: UserName,
    /// The enrolled Macs' SSH keys (and the recovery key).
    pub authorized_keys: Vec<SshPublicKey>,
    /// At most one Ed25519 and one ECDSA P-256 host key.
    pub host_keys: Vec<HostKey>,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudInitError(pub &'static str);

impl std::fmt::Display for CloudInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for CloudInitError {}

/// A YAML value; maps keep their order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Yaml {
    Str(String),
    Bool(bool),
    List(Vec<Yaml>),
    Map(Vec<(&'static str, Yaml)>),
}

fn s(v: impl Into<String>) -> Yaml {
    Yaml::Str(v.into())
}

/// YAML double-quoted scalar: `"` and `\` escaped, and every character
/// outside YAML's printable set (controls, DEL, C1, BOM, surrogates are
/// impossible in `str`) as `\uXXXX`.
pub fn quote(v: &str) -> String {
    let mut out = String::with_capacity(v.len() + 2);
    out.push('"');
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20
                || (0x7f..=0x9f).contains(&(c as u32))
                || c == '\u{feff}'
                || c == '\u{fffe}'
                || c == '\u{ffff}' =>
            {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn scalar(y: &Yaml) -> Option<String> {
    match y {
        Yaml::Str(v) => Some(quote(v)),
        Yaml::Bool(b) => Some(b.to_string()),
        Yaml::List(l) if l.is_empty() => Some("[]".into()),
        Yaml::Map(m) if m.is_empty() => Some("{}".into()),
        _ => None,
    }
}

fn emit_map(
    out: &mut String,
    m: &[(&'static str, Yaml)],
    indent: usize,
    first_prefix: Option<&str>,
) {
    for (i, (k, v)) in m.iter().enumerate() {
        match (i, first_prefix) {
            (0, Some(p)) => out.push_str(p),
            _ => out.push_str(&" ".repeat(indent)),
        }
        out.push_str(k);
        out.push(':');
        match scalar(v) {
            Some(sc) => {
                out.push(' ');
                out.push_str(&sc);
                out.push('\n');
            }
            None => {
                out.push('\n');
                emit_block(out, v, indent + 2);
            }
        }
    }
}

fn emit_block(out: &mut String, y: &Yaml, indent: usize) {
    match y {
        Yaml::Map(m) => emit_map(out, m, indent, None),
        Yaml::List(l) => {
            let pad = " ".repeat(indent);
            for item in l {
                match (scalar(item), item) {
                    (Some(sc), _) => {
                        let _ = writeln!(out, "{pad}- {sc}");
                    }
                    (None, Yaml::Map(m)) => emit_map(out, m, indent + 2, Some(&format!("{pad}- "))),
                    (None, other) => {
                        let _ = writeln!(out, "{pad}-");
                        emit_block(out, other, indent + 2);
                    }
                }
            }
        }
        other => {
            if let Some(sc) = scalar(other) {
                let _ = writeln!(out, "{}{sc}", " ".repeat(indent));
            }
        }
    }
}

/// `-----BEGIN/END OPENSSH PRIVATE KEY-----` around base64 lines.
fn valid_private(k: &str) -> bool {
    let k = k.strip_suffix('\n').unwrap_or(k);
    let Some(body) = k
        .strip_prefix("-----BEGIN OPENSSH PRIVATE KEY-----\n")
        .and_then(|b| b.strip_suffix("\n-----END OPENSSH PRIVATE KEY-----"))
    else {
        return false;
    };
    k.len() <= MAX_PRIVATE
        && !body.is_empty()
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=\n".contains(&b))
}

fn valid_hostname(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 63
        && !h.starts_with('-')
        && !h.ends_with('-')
        && h.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The document as a tree (validated).
pub fn document(c: &CloudInit) -> Result<Yaml, CloudInitError> {
    if c.admin.as_str() == "root" {
        return Err(CloudInitError("admin can't be root"));
    }
    if c.authorized_keys.is_empty() || c.authorized_keys.len() > MAX_KEYS {
        return Err(CloudInitError("1-64 authorized keys"));
    }
    let mut host = Vec::new();
    let mut seen = Vec::new();
    for k in &c.host_keys {
        let slot = match k.public.algo() {
            SshKeyAlgo::Ed25519 => "ed25519",
            SshKeyAlgo::EcdsaP256 => "ecdsa",
            _ => return Err(CloudInitError("host keys: ed25519 or ecdsa-sha2-nistp256")),
        };
        if seen.contains(&slot) {
            return Err(CloudInitError("one host key per algorithm"));
        }
        if !valid_private(&k.private_openssh) {
            return Err(CloudInitError("host private key: OpenSSH PEM"));
        }
        seen.push(slot);
        let (private, public) = match slot {
            "ed25519" => ("ed25519_private", "ed25519_public"),
            _ => ("ecdsa_private", "ecdsa_public"),
        };
        host.push((private, s(k.private_openssh.clone())));
        host.push((public, s(k.public.to_line())));
    }
    if host.is_empty() {
        return Err(CloudInitError(
            "at least one host key (nothing is trusted on first use)",
        ));
    }
    let user = Yaml::Map(vec![
        ("name", s(c.admin.as_str())),
        ("groups", s("sudo")),
        // Until `sudo.policy` (phase 1) replaces it; see the module docs.
        ("sudo", s("ALL=(ALL) NOPASSWD:ALL")),
        ("shell", s("/bin/bash")),
        ("lock_passwd", Yaml::Bool(true)),
        (
            "ssh_authorized_keys",
            Yaml::List(c.authorized_keys.iter().map(|k| s(k.to_line())).collect()),
        ),
    ]);
    let mut top = Vec::new();
    if let Some(h) = &c.hostname {
        if !valid_hostname(h) {
            return Err(CloudInitError("hostname"));
        }
        top.push(("hostname", s(h.clone())));
    }
    top.extend([
        ("users", Yaml::List(vec![user])),
        ("disable_root", Yaml::Bool(true)),
        ("ssh_pwauth", Yaml::Bool(false)),
        ("ssh_deletekeys", Yaml::Bool(true)),
        ("ssh_genkeytypes", Yaml::List(Vec::new())),
        ("ssh_keys", Yaml::Map(host)),
        (
            "write_files",
            Yaml::List(vec![Yaml::Map(vec![
                ("path", s(BOOTSTRAP_SSHD)),
                ("owner", s("root:root")),
                ("permissions", s("0644")),
                (
                    "content",
                    s("# Fleet bootstrap (design §9.7); overridden by the profile's 00-fleet.conf.\n\
                       PermitRootLogin no\n\
                       PasswordAuthentication no\n\
                       KbdInteractiveAuthentication no\n"),
                ),
            ])]),
        ),
    ]);
    Ok(Yaml::Map(top))
}

/// The `#cloud-config` text.
pub fn render(c: &CloudInit) -> Result<String, CloudInitError> {
    let doc = document(c)?;
    let mut out = String::from(
        "#cloud-config\n# Generated by Fleet (design §9.7). The Mac applies the full profile on first connection.\n",
    );
    emit_block(&mut out, &doc, 0);
    Ok(out)
}

#[cfg(test)]
mod tests;
