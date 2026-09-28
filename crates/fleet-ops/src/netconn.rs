//! `connections.list` (design §4.2 `system` group): established and other
//! non-listening TCP/UDP sockets from `/proc/net/{tcp,tcp6,udp,udp6}`, each
//! mapped to its process through `/proc/<pid>/fd` (the same readers as
//! `ports.list`, [`crate::security::ports`]). Listening sockets are
//! `ports.list`'s job and are left out.
//!
//! Bounded: at most [`MAX_CONNECTIONS`] rows (the busiest servers have more;
//! the list is then cut, sorted by process then local port). Per-socket
//! rates need netlink `sock_diag`, which the agent doesn't speak: `rx_bps`
//! and `tx_bps` are 0.

use crate::ctx::SysCtx;
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput};
use crate::security::ports::{endpoint, socket_owners};
use fleet_proto::args::Protocol;
use fleet_proto::payload::{Connection, Connections};
use fleet_proto::{Op, Payload};
use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;

/// Rows returned (well inside a frame: ~100 bytes each).
pub const MAX_CONNECTIONS: usize = 4096;
/// `/proc/net` lines parsed per file.
const MAX_LINES: usize = 65_536;

const TCP_LISTEN: u8 = 0x0A;
const TCP_CLOSE: u8 = 0x07;

/// One non-listening socket of `/proc/net/*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conn {
    pub proto: Protocol,
    pub local: SocketAddr,
    pub remote: Option<SocketAddr>,
    pub state: &'static str,
    pub inode: u64,
}

/// Kernel TCP state names (`include/net/tcp_states.h`).
fn tcp_state(st: u8) -> &'static str {
    match st {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0A => "LISTEN",
        0x0B => "CLOSING",
        0x0C => "NEW_SYN_RECV",
        _ => "UNKNOWN",
    }
}

/// Connections of one `/proc/net` file: TCP sockets not listening, UDP
/// sockets with a remote address (connected). Malformed lines are skipped.
pub fn parse_connections(text: &str, proto: Protocol) -> Vec<Conn> {
    text.lines()
        .skip(1)
        .take(MAX_LINES)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let (la, lp) = endpoint(f.get(1)?)?;
            let (ra, rp) = endpoint(f.get(2)?)?;
            let st = u8::from_str_radix(f.get(3)?, 16).ok()?;
            let remote = (rp != 0 || !ra.is_unspecified()).then_some(SocketAddr::new(ra, rp));
            let state = match proto {
                Protocol::Tcp if st == TCP_LISTEN => return None,
                Protocol::Tcp => tcp_state(st),
                Protocol::Udp if remote.is_none() => return None,
                Protocol::Udp if st == TCP_CLOSE => "UNCONN",
                Protocol::Udp => "ESTABLISHED",
            };
            Some(Conn {
                proto,
                local: SocketAddr::new(la, lp),
                remote,
                state,
                inode: f.get(9)?.parse().ok()?,
            })
        })
        .collect()
}

/// Every connection with its owning process, sorted and capped.
pub fn collect(ctx: &SysCtx) -> Connections {
    let mut conns = Vec::new();
    for (file, proto) in [
        ("/proc/net/tcp", Protocol::Tcp),
        ("/proc/net/tcp6", Protocol::Tcp),
        ("/proc/net/udp", Protocol::Udp),
        ("/proc/net/udp6", Protocol::Udp),
    ] {
        if let Some(t) = ctx.procfs.read(file) {
            conns.extend(parse_connections(&t, proto));
        }
    }
    let wanted: BTreeSet<u64> = conns.iter().map(|c| c.inode).filter(|i| *i != 0).collect();
    let owners = socket_owners(ctx, &wanted);
    let mut names: HashMap<u32, Option<String>> = HashMap::new();
    let mut out: Vec<Connection> = conns
        .into_iter()
        .map(|c| {
            let pid = owners.get(&c.inode).copied();
            let process = pid.and_then(|p| {
                names
                    .entry(p)
                    .or_insert_with(|| {
                        ctx.procfs
                            .read(&format!("/proc/{p}/comm"))
                            .map(|c| c.trim().chars().take(64).collect())
                    })
                    .clone()
            });
            Connection {
                proto: c.proto,
                local: c.local,
                remote: c.remote,
                state: c.state.to_owned(),
                pid,
                process,
                rx_bps: 0,
                tx_bps: 0,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        (a.pid.is_none(), a.pid, a.local.port(), a.proto as u8, a.remote).cmp(&(
            b.pid.is_none(),
            b.pid,
            b.local.port(),
            b.proto as u8,
            b.remote,
        ))
    });
    out.truncate(MAX_CONNECTIONS);
    Connections { connections: out }
}

/// `connections.list`.
pub struct ConnectionsHandler;

impl OpHandler for ConnectionsHandler {
    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        _op: &'a Op,
        _meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move { Ok(OpOutput::Payload(Payload::Connections(collect(ctx)))) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FakeRunner;
    use crate::testutil::{T0, ctx_at};
    use std::rc::Rc;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0
   1: 0200000A:0016 0100000A:D431 01 00000000:00000000 02:000A7E0B 00000000     0        0 1003 4 0000000000000000 20 4 30 10 -1
   2: 0200000A:9C40 22B8D85D:01BB 06 00000000:00000000 03:00001000 00000000     0        0 0 3 0000000000000000
   3: garbage
";
    const UDP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  10: 00000000000000000000000000000000:0035 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 2001 2 0000000000000000 0
  11: 00000000000000000000000001000000:A1B2 00000000000000000000000001000000:0035 01 00000000:00000000 00:00000000 00000000   101        0 2002 2 0000000000000000 0
";

    #[test]
    fn parses_non_listening_sockets() {
        let t = parse_connections(TCP, Protocol::Tcp);
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].local, "10.0.0.2:22".parse().unwrap());
        assert_eq!(t[0].remote, Some("10.0.0.1:54321".parse().unwrap()));
        assert_eq!(t[0].state, "ESTABLISHED");
        assert_eq!(t[1].state, "TIME_WAIT");
        assert_eq!(t[1].inode, 0);
        let u = parse_connections(UDP6, Protocol::Udp);
        assert_eq!(u.len(), 1, "unconnected UDP is a listener");
        assert_eq!(u[0].remote, Some("[::1]:53".parse().unwrap()));
    }

    #[test]
    fn maps_processes_and_caps() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::create_dir_all(d.join("proc/net")).unwrap();
        std::fs::write(d.join("proc/net/tcp"), TCP).unwrap();
        std::fs::write(d.join("proc/net/udp6"), UDP6).unwrap();
        let p = d.join("proc/812");
        std::fs::create_dir_all(p.join("fd")).unwrap();
        std::fs::write(p.join("comm"), "sshd\n").unwrap();
        std::os::unix::fs::symlink("socket:[1003]", p.join("fd/3")).unwrap();
        let c = ctx_at(d, Rc::new(FakeRunner::new()), T0);
        let got = collect(&c).connections;
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].pid, Some(812));
        assert_eq!(got[0].process.as_deref(), Some("sshd"));
        assert!(got[1..].iter().all(|c| c.pid.is_none()));
        // Large tables are cut at the cap.
        let mut big = String::from("header\n");
        for i in 0..(MAX_CONNECTIONS + 10) {
            big.push_str(&format!(
                "{i}: 0200000A:{:04X} 0100000A:0050 01 0:0 0:0 0 0 0 {} 1\n",
                1024 + i,
                5000 + i
            ));
        }
        std::fs::write(d.join("proc/net/tcp"), big).unwrap();
        assert_eq!(collect(&c).connections.len(), MAX_CONNECTIONS);
    }
}
