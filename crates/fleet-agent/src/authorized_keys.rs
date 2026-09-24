//! Roster section of `/etc/fleet/authorized_keys/<admin>` (design §5.9).
//!
//! The file has a roster section, rewritten by exec from the roster, and an
//! extra section (everything outside the markers), which is never touched
//! here. Written atomically, root-owned, mode 0644.

use crate::fsutil;
use crate::paths::AGENT_BIN;
use fleet_crypto::roster::{RecoveryClock, recovery_ssh_keys_at};
use fleet_proto::{Ed25519Public, P256Public, Roster};
use std::path::Path;

pub const BEGIN: &str = "# BEGIN fleet roster (managed by fleet-exec; edits are overwritten)";
pub const END: &str = "# END fleet roster";

/// OpenSSH options on the recovery key: it can only open the recovery bridge.
pub fn recovery_options() -> String {
    format!("restrict,command=\"{AGENT_BIN} bridge --recovery\"")
}

/// The roster section, markers included. Device SSH keys, then the one
/// recovery SSH key accepted now: the rotated-out one while its grace
/// window is open, else the current one (never both).
pub fn roster_section(roster: &Roster, clock: RecoveryClock) -> String {
    let mut out = format!("{BEGIN}\n");
    for d in &roster.devices {
        // A key that isn't a valid point can't be written; skip it rather
        // than fail the whole roster (the roster itself verified).
        if let Some(line) = ecdsa_line(&d.ssh_key) {
            out.push_str(&format!("{line} fleet-device-{}\n", d.id));
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MergeError {
    /// A `BEGIN` marker without its `END`: where the managed block stops is
    /// unknown, so the file is left alone rather than risk dropping (or
    /// keeping stale) keys.
    #[error("unterminated managed block (BEGIN without END)")]
    Unterminated,
}

/// Removes every managed block from `existing` (including duplicates left by
/// hand edits) and prepends `section`. Lines outside blocks are kept in
/// order; stray `END` markers are dropped.
pub fn merge(existing: &str, section: &str) -> Result<String, MergeError> {
    let mut extra = String::new();
    let mut inside = false;
    for line in existing.lines() {
        match (inside, line) {
            (_, BEGIN) => inside = true,
            (_, END) => inside = false,
            (true, _) => {}
            (false, _) => {
                extra.push_str(line);
                extra.push('\n');
            }
        }
    }
    if inside {
        return Err(MergeError::Unterminated);
    }
    Ok(format!("{section}{extra}"))
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
