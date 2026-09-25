//! sshd logins as seen in the journal (design §4.6): which sshd process
//! authenticated which roster SSH key, when.
//!
//! Three users:
//! - `change.confirm` needs a login with the confirming device's SSH key
//!   after the change was made (design §4.10: a new connection proves
//!   access still works).
//! - [`SshdTerminator`] ends the sessions of keys removed from the roster
//!   (design §5.3 rule 5): SIGTERM to the per-connection sshd process that
//!   logged `Accepted publickey … SHA256:<fp>`, never the listener.
//! - The source filter [`trusted_entry`]: only sshd itself, as root, and
//!   never a container's log forwarded by dockerd.

use super::SessionTerminator;
use crate::authorized_keys::ecdsa_blob;
use fleet_ops::security::ssh_fingerprint;
use fleet_proto::{DeviceId, P256Public};
use std::cell::RefCell;
use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::rc::Rc;

/// Logins remembered (oldest dropped first).
const MAX_LOGINS: usize = 1024;

/// Programs whose journal entries are sshd's own (`_COMM`, at most 15
/// bytes as the kernel keeps it).
pub const SSHD_COMMS: [&str; 2] = ["sshd", "sshd-session"];
/// Units sshd runs under on Debian/Ubuntu.
pub const SSHD_UNITS: [&str; 2] = ["ssh.service", "sshd.service"];

/// Journal fields the follower asks for, besides message and time.
pub const TRUST_FIELDS: &str = "_UID,_COMM,_SYSTEMD_UNIT,CONTAINER_ID";

/// Whether a `journalctl -o json` line is sshd's own: `_UID=0` (a trusted
/// field: a local user can log with `SYSLOG_IDENTIFIER=sshd` but not as
/// root), `_COMM` sshd/sshd-session **or** `_SYSTEMD_UNIT` ssh(d).service
/// (both trusted), and no `CONTAINER_ID` (dockerd, also root, forwards a
/// container's `sshd` lines with it). Anything unparsable is refused.
pub fn trusted_entry(line: &[u8]) -> bool {
    let Ok(serde_json::Value::Object(o)) = serde_json::from_slice::<serde_json::Value>(line) else {
        return false;
    };
    let text = |k: &str| o.get(k).and_then(serde_json::Value::as_str);
    if o.contains_key("CONTAINER_ID") || text("_UID") != Some("0") {
        return false;
    }
    text("_COMM").is_some_and(|c| SSHD_COMMS.contains(&c))
        || text("_SYSTEMD_UNIT").is_some_and(|u| SSHD_UNITS.contains(&u))
}

/// Which roster key a fingerprint belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    /// The device SSH key (full sessions).
    Device,
    /// The monitor SSH key (forced `bridge --monitor`).
    Monitor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Login {
    /// The per-connection sshd process that logged `Accepted`.
    pub pid: u32,
    pub fingerprint: String,
    pub device: Option<(DeviceId, KeyRole)>,
    /// Journal time (ms).
    pub t: u64,
}

/// Recent public-key logins, bounded.
#[derive(Debug, Default)]
pub struct Logins {
    list: VecDeque<Login>,
}

impl Logins {
    pub fn accepted(&mut self, login: Login) {
        // A reused pid is a new connection.
        self.list.retain(|l| l.pid != login.pid);
        if self.list.len() >= MAX_LOGINS {
            self.list.pop_front();
        }
        self.list.push_back(login);
    }

    /// The connection of `pid` ended.
    pub fn closed(&mut self, pid: u32) {
        self.list.retain(|l| l.pid != pid);
    }

    /// `device` logged in with its device SSH key at or after `since_ms`.
    pub fn device_login_since(&self, device: DeviceId, since_ms: u64) -> bool {
        self.list
            .iter()
            .any(|l| l.device == Some((device, KeyRole::Device)) && l.t >= since_ms)
    }

    /// Pids of logins with any of `fingerprints`.
    pub fn pids_for(&self, fingerprints: &HashSet<String>) -> Vec<u32> {
        self.list
            .iter()
            .filter(|l| fingerprints.contains(&l.fingerprint))
            .map(|l| l.pid)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }
}

/// Whether an sshd message ends the connection its pid belongs to.
pub fn is_disconnect(msg: &str) -> bool {
    let m = msg.trim();
    m.starts_with("Disconnected from user ")
        || m.starts_with("Received disconnect from ")
        || m.contains("session closed for user ")
}

/// `(comm, ppid)` from `<proc>/<pid>/stat` (comm may hold spaces and
/// parentheses: it ends at the last `)`).
pub fn proc_stat(proc_root: &Path, pid: u32) -> Option<(String, u32)> {
    let s = std::fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    let comm = s.get(open + 1..close)?.to_owned();
    let mut rest = s.get(close + 1..)?.split_whitespace();
    let _state = rest.next()?;
    let ppid = rest.next()?.parse().ok()?;
    Some((comm, ppid))
}

/// A per-connection sshd process: `sshd`/`sshd-session` whose parent is
/// the `sshd` listener. The listener itself (parent init) never qualifies,
/// nor does anything else a stale pid may now belong to.
pub fn is_session_process(proc_root: &Path, pid: u32) -> bool {
    if pid <= 1 {
        return false;
    }
    let Some((comm, ppid)) = proc_stat(proc_root, pid) else {
        return false;
    };
    if !SSHD_COMMS.contains(&comm.as_str()) || ppid <= 1 {
        return false;
    }
    proc_stat(proc_root, ppid).is_some_and(|(parent, _)| parent == "sshd")
}

/// Sends SIGTERM (tests record instead).
pub trait ProcessSignaller {
    fn terminate(&self, pid: u32) -> std::io::Result<()>;
}

/// `kill(pid, SIGTERM)` through rustix.
pub struct Sigterm;

impl ProcessSignaller for Sigterm {
    fn terminate(&self, pid: u32) -> std::io::Result<()> {
        let pid = i32::try_from(pid)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .ok_or(std::io::ErrorKind::InvalidInput)?;
        rustix::process::kill_process(pid, rustix::process::Signal::TERM)?;
        Ok(())
    }
}

/// Ends sshd sessions authenticated with removed keys (design §5.3 rule
/// 5), found through [`Logins`].
pub struct SshdTerminator {
    pub logins: Rc<RefCell<Logins>>,
    /// `/proc` (a fixture directory in tests).
    pub proc_root: PathBuf,
    pub signaller: Box<dyn ProcessSignaller>,
}

impl SshdTerminator {
    /// The pids it signalled.
    pub fn end(&self, removed_ssh_keys: &[P256Public]) -> Vec<u32> {
        let fps: HashSet<String> = removed_ssh_keys
            .iter()
            .filter_map(|k| Some(ssh_fingerprint(&ecdsa_blob(k)?)))
            .collect();
        if fps.is_empty() {
            return Vec::new();
        }
        let pids = self.logins.borrow().pids_for(&fps);
        let mut done = Vec::new();
        for pid in pids {
            if !is_session_process(&self.proc_root, pid) {
                continue;
            }
            match self.signaller.terminate(pid) {
                Ok(()) => done.push(pid),
                Err(e) => super::log(&format!("end sshd session {pid}"), e),
            }
        }
        let mut l = self.logins.borrow_mut();
        for pid in &done {
            l.closed(*pid);
        }
        done
    }
}

impl SessionTerminator for SshdTerminator {
    fn end_sessions(&self, removed_ssh_keys: &[P256Public]) {
        let n = self.end(removed_ssh_keys).len();
        if n > 0 {
            super::log("removed devices", format!("ended {n} sshd session(s)"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell as Cell2;

    #[test]
    fn trusted_entry_needs_root_sshd_outside_containers() {
        let ok = |s: &str| trusted_entry(s.as_bytes());
        assert!(ok(r#"{"_UID":"0","_COMM":"sshd","MESSAGE":"x"}"#));
        assert!(ok(r#"{"_UID":"0","_COMM":"sshd-session"}"#));
        assert!(ok(
            r#"{"_UID":"0","_COMM":"x","_SYSTEMD_UNIT":"ssh.service"}"#
        ));
        // `logger -t sshd` as a user, or as root from another program.
        assert!(!ok(r#"{"_UID":"1000","_COMM":"sshd"}"#));
        assert!(!ok(r#"{"_UID":"0","_COMM":"logger"}"#));
        assert!(!ok(r#"{"_COMM":"sshd"}"#));
        // A container's sshd forwarded by dockerd (root).
        assert!(!ok(
            r#"{"_UID":"0","_COMM":"dockerd","_SYSTEMD_UNIT":"docker.service","CONTAINER_ID":"ab"}"#
        ));
        assert!(!ok(r#"{"_UID":"0","_COMM":"sshd","CONTAINER_ID":"ab"}"#));
        assert!(!ok("not json"));
        assert!(!ok(r#"{"_UID":["0"],"_COMM":"sshd"}"#));
    }

    fn stat(root: &Path, pid: u32, comm: &str, ppid: u32) {
        let d = root.join(pid.to_string());
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("stat"), format!("{pid} ({comm}) S {ppid} 1 1 0")).unwrap();
    }

    struct Rec(Cell2<Vec<u32>>);
    impl ProcessSignaller for Rc<Rec> {
        fn terminate(&self, pid: u32) -> std::io::Result<()> {
            self.0.borrow_mut().push(pid);
            Ok(())
        }
    }

    fn key(seed: u8) -> P256Public {
        use fleet_crypto::sig::Signer;
        fleet_crypto::sig::SoftwareP256Signer::from_bytes(&[seed; 32])
            .unwrap()
            .public()
    }

    #[test]
    fn terminator_signals_only_session_processes_of_removed_keys() {
        let proc_dir = tempfile::tempdir().unwrap();
        let p = proc_dir.path();
        stat(p, 500, "sshd", 1); // listener
        stat(p, 600, "sshd-session", 500); // removed key's session
        stat(p, 601, "sshd", 500); // kept key's session
        stat(p, 602, "bash", 600); // pid reused by something else
        let (gone, kept) = (key(1), key(2));
        let fp = |k: &P256Public| ssh_fingerprint(&ecdsa_blob(k).unwrap());
        let logins = Rc::new(RefCell::new(Logins::default()));
        let login = |pid, k: &P256Public| Login {
            pid,
            fingerprint: fp(k),
            device: None,
            t: 1,
        };
        for (pid, k) in [(600, &gone), (601, &kept), (602, &gone), (500, &gone)] {
            logins.borrow_mut().accepted(login(pid, k));
        }
        let rec = Rc::new(Rec(Cell2::default()));
        let t = SshdTerminator {
            logins: logins.clone(),
            proc_root: p.to_owned(),
            signaller: Box::new(rec.clone()),
        };
        assert_eq!(t.end(&[gone]), [600]);
        assert_eq!(*rec.0.borrow(), [600]);
        // Forgotten once ended; the others stay.
        assert_eq!(logins.borrow().len(), 3);
        assert!(t.end(&[]).is_empty());
    }

    #[test]
    fn device_login_needs_device_key_after_time() {
        let d = DeviceId([1; 16]);
        let mut l = Logins::default();
        let at = |pid, role, t| Login {
            pid,
            fingerprint: format!("fp{pid}"),
            device: Some((d, role)),
            t,
        };
        l.accepted(at(10, KeyRole::Device, 100));
        l.accepted(at(11, KeyRole::Monitor, 300));
        assert!(l.device_login_since(d, 100));
        assert!(!l.device_login_since(d, 101), "monitor key doesn't count");
        assert!(!l.device_login_since(DeviceId([2; 16]), 0));
        l.closed(10);
        assert!(!l.device_login_since(d, 0));
        assert!(is_disconnect(
            "Disconnected from user admin 203.0.113.5 port 5"
        ));
        assert!(!is_disconnect("Accepted publickey for admin"));
    }
}
