//! Roster section of `/etc/fleet/authorized_keys/<admin>` (design §5.9).
//!
//! The file has a roster section, rewritten by exec from the roster, and an
//! extra section (everything outside the markers), which is never touched
//! here. Written atomically, root-owned, mode 0644. The file format (markers,
//! section split, [`merge`]) lives in `fleet_ops::users::authorized_keys`,
//! shared with `authorized_keys.get/set`.

use crate::fsutil;
use crate::paths::AGENT_BIN;
use fleet_crypto::roster::{RecoveryClock, recovery_ssh_keys_at};
pub use fleet_ops::users::authorized_keys::{BEGIN, END, MergeError, merge};
use fleet_proto::{Ed25519Public, P256Public, Roster};
use std::path::Path;

/// OpenSSH options on the recovery key: it can only open the recovery bridge.
pub fn recovery_options() -> String {
    format!("restrict,command=\"{AGENT_BIN} bridge --recovery\"")
}

/// OpenSSH options on a Mac's monitor SSH key: it can only open the
/// monitor bridge (read-only sessions, design §5.9).
pub fn monitor_options() -> String {
    format!("restrict,command=\"{AGENT_BIN} bridge --monitor\"")
}

/// The roster section, markers included. Each device's SSH key and its
/// restricted monitor SSH key, then the one recovery SSH key accepted now:
/// the rotated-out one while its grace window is open, else the current
/// one (never both).
pub fn roster_section(roster: &Roster, clock: RecoveryClock) -> String {
    let mut out = format!("{BEGIN}\n");
    for d in &roster.devices {
        // A key that isn't a valid point can't be written; skip it rather
        // than fail the whole roster (the roster itself verified).
        if let Some(line) = ecdsa_line(&d.ssh_key) {
            out.push_str(&format!("{line} fleet-device-{}\n", d.id));
        }
        // sshd uses the first matching line: a monitor key equal to the
        // device key (a Mac without its own yet) would only be shadowed.
        if d.monitor_ssh_key != d.ssh_key
            && let Some(line) = ecdsa_line(&d.monitor_ssh_key)
        {
            out.push_str(&format!(
                "{} {line} fleet-monitor-{}\n",
                monitor_options(),
                d.id
            ));
        }
    }
    for k in recovery_ssh_keys_at(roster, clock) {
        out.push_str(&format!(
            "{} {} fleet-recovery\n",
            recovery_options(),
            ed25519_line(&k)
        ));
    }
    out.push_str(END);
    out.push('\n');
    out
}

/// Rewrites `<dir>/<user>` if the roster section changed. Returns whether
/// the file was written.
pub fn sync(
    dir: &Path,
    user: &str,
    roster: &Roster,
    clock: RecoveryClock,
) -> std::io::Result<bool> {
    let path = dir.join(user);
    let existing = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    let new = merge(&existing, &roster_section(roster, clock))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if new == existing {
        return Ok(false);
    }
    fsutil::ensure_dir(dir, 0o755)?;
    fsutil::write_atomic(&path, new.as_bytes(), 0o644)?;
    Ok(true)
}

fn ssh_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// OpenSSH `ecdsa-sha2-nistp256` public key blob (what sshd fingerprints).
pub fn ecdsa_blob(key: &P256Public) -> Option<Vec<u8>> {
    let point = fleet_crypto::sig::p256_uncompressed(key).ok()?;
    let mut blob = Vec::new();
    ssh_string(&mut blob, b"ecdsa-sha2-nistp256");
    ssh_string(&mut blob, b"nistp256");
    ssh_string(&mut blob, &point);
    Some(blob)
}

fn ecdsa_line(key: &P256Public) -> Option<String> {
    Some(format!("ecdsa-sha2-nistp256 {}", base64(&ecdsa_blob(key)?)))
}

fn ed25519_line(key: &Ed25519Public) -> String {
    let mut blob = Vec::new();
    ssh_string(&mut blob, b"ssh-ed25519");
    ssh_string(&mut blob, &key.0);
    format!("ssh-ed25519 {}", base64(&blob))
}

/// Standard base64 with padding.
fn base64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            A[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            A[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_rfc4648() {
        for (i, o) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
        ] {
            assert_eq!(base64(i.as_bytes()), o);
        }
    }

    #[test]
    fn ed25519_blob_prefix() {
        // Every ssh-ed25519 blob starts with the same 19 bytes.
        assert!(
            ed25519_line(&Ed25519Public([0; 32]))
                .starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI")
        );
    }

    #[test]
    fn merge_keeps_extra_section() {
        let s1 = format!("{BEGIN}\nA\n{END}\n");
        let s2 = format!("{BEGIN}\nB\n{END}\n");
        let file = merge("ssh-ed25519 CI ci\n", &s1).unwrap();
        assert_eq!(file, format!("{s1}ssh-ed25519 CI ci\n"));
        assert_eq!(
            merge(&file, &s2).unwrap(),
            format!("{s2}ssh-ed25519 CI ci\n")
        );
    }

    #[test]
    fn monitor_key_pinned_to_monitor_bridge() {
        use fleet_crypto::sig::{Signer, SoftwareP256Signer};
        let key = |s: u8| SoftwareP256Signer::from_bytes(&[s; 32]).unwrap().public();
        let dev = |id: u8, ssh, monitor_ssh| fleet_proto::Device {
            id: fleet_proto::DeviceId([id; 16]),
            name: fleet_proto::BoundedString::new("Mac").unwrap(),
            role: fleet_proto::Role::Admin,
            root_key: key(1),
            device_key: key(1),
            monitor_key: key(1),
            ssh_key: ssh,
            monitor_ssh_key: monitor_ssh,
            noise_static: fleet_proto::X25519Public([0; 32]),
            added_at: 0,
            added_by: fleet_proto::DeviceId([id; 16]),
        };
        let mut r = roster();
        r.devices = vec![dev(1, key(2), key(3)), dev(2, key(4), key(4))];
        let s = roster_section(&r, RecoveryClock::at(0));
        let lines: Vec<&str> = s.lines().collect();
        let d1 = fleet_proto::DeviceId([1; 16]);
        assert!(lines[1].starts_with("ecdsa-sha2-nistp256 "));
        assert!(lines[1].ends_with(&format!("fleet-device-{d1}")));
        assert_eq!(
            lines[2],
            format!(
                "{} {} fleet-monitor-{d1}",
                monitor_options(),
                ecdsa_line(&key(3)).unwrap()
            )
        );
        // Same key as the device key: no shadowed monitor line.
        assert_eq!(s.matches("fleet-monitor-").count(), 1);
    }

    fn roster() -> Roster {
        Roster {
            fleet_id: fleet_proto::FleetId([1; 16]),
            epoch: 0,
            version: 1,
            prev_hash: [0; 32],
            issued_at_ms: 0,
            devices: vec![],
            recovery_key: Ed25519Public([0; 32]),
            recovery_ssh_key: Ed25519Public([0; 32]),
            recovery_escrow_key: fleet_proto::X25519Public([0; 32]),
            recovery_delay_s: 0,
            prev_recovery: None,
        }
    }

    #[test]
    fn merge_strips_duplicate_blocks() {
        let old = format!("{BEGIN}\nOLD1\n{END}\n");
        let s = format!("{BEGIN}\nNEW\n{END}\n");
        let file = format!("x\n{old}y\n{BEGIN}\nOLD2\n{END}\nz\n{END}\n");
        assert_eq!(merge(&file, &s).unwrap(), format!("{s}x\ny\nz\n"));
    }

    #[test]
    fn unterminated_block_refused_and_file_kept() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("admin");
        let file = format!("x\n{BEGIN}\nOLD\n");
        std::fs::write(&path, &file).unwrap();
        assert_eq!(merge(&file, "s\n"), Err(MergeError::Unterminated));
        let roster = Roster {
            fleet_id: fleet_proto::FleetId([1; 16]),
            epoch: 0,
            version: 1,
            prev_hash: [0; 32],
            issued_at_ms: 0,
            devices: vec![],
            recovery_key: Ed25519Public([0; 32]),
            recovery_ssh_key: Ed25519Public([0; 32]),
            recovery_escrow_key: fleet_proto::X25519Public([0; 32]),
            recovery_delay_s: 0,
            prev_recovery: None,
        };
        assert!(sync(d.path(), "admin", &roster, RecoveryClock::at(0)).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), file);
    }
}
