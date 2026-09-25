//! `ports.list` (design §2.4): listening sockets from
//! `/proc/net/{tcp,tcp6,udp,udp6}`, each mapped to its process through the
//! `socket:[inode]` links in `/proc/<pid>/fd`, plus the new-listening-port
//! detector (§4.5).

use crate::ctx::SysCtx;
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput};
use fleet_proto::args::Protocol;
use fleet_proto::payload::{ListeningPort, Ports};
use fleet_proto::{Event, Op, Payload};
use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const TCP_LISTEN: u8 = 0x0A;
/// Unconnected UDP sockets are in `TCP_CLOSE` with no remote address.
const UDP_CLOSE: u8 = 0x07;
/// Processes scanned for socket inodes.
const MAX_PIDS: usize = 32_768;
const MAX_FDS_PER_PID: usize = 65_536;

/// One socket line of `/proc/net/*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socket {
    pub proto: Protocol,
    pub addr: IpAddr,
    pub port: u16,
    pub uid: u32,
    pub inode: u64,
}

/// `0100007F` (host-order u32 words) → 127.0.0.1; 32 hex digits → IPv6.
fn hex_addr(s: &str) -> Option<IpAddr> {
    let word = |w: &str| u32::from_str_radix(w, 16).ok().map(u32::to_le_bytes);
    match s.len() {
        8 => Some(IpAddr::V4(Ipv4Addr::from(word(s)?))),
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                b[i * 4..i * 4 + 4].copy_from_slice(&word(s.get(i * 8..i * 8 + 8)?)?);
            }
            Some(IpAddr::V6(Ipv6Addr::from(b)))
        }
        _ => None,
    }
}

fn endpoint(s: &str) -> Option<(IpAddr, u16)> {
    let (a, p) = s.split_once(':')?;
    Some((hex_addr(a)?, u16::from_str_radix(p, 16).ok()?))
}

/// Listening sockets of one `/proc/net/{tcp,udp}{,6}` file. Malformed
/// lines are skipped.
pub fn parse_proc_net(text: &str, proto: Protocol) -> Vec<Socket> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let (addr, port) = endpoint(f.get(1)?)?;
            let (_, rport) = endpoint(f.get(2)?)?;
            let st = u8::from_str_radix(f.get(3)?, 16).ok()?;
            let listening = match proto {
                Protocol::Tcp => st == TCP_LISTEN,
                Protocol::Udp => st == UDP_CLOSE && rport == 0,
            };
            listening.then_some(())?;
            Some(Socket {
                proto,
                addr,
                port,
                uid: f.get(7)?.parse().ok()?,
                inode: f.get(9)?.parse().ok()?,
            })
        })
        .collect()
}

/// inode → pid, from `/proc/<pid>/fd/*` links (`socket:[123]`).
pub fn socket_owners(ctx: &SysCtx, wanted: &BTreeSet<u64>) -> HashMap<u64, u32> {
    let mut out = HashMap::new();
    let Some(proc_dir) = ctx.path("/proc") else {
        return out;
    };
    let Ok(rd) = std::fs::read_dir(&proc_dir) else {
        return out;
    };
    for ent in rd.flatten().take(MAX_PIDS) {
        let Some(pid) = ent.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(ent.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten().take(MAX_FDS_PER_PID) {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let inode = target
                .to_str()
                .and_then(|t| t.strip_prefix("socket:["))
                .and_then(|t| t.strip_suffix(']'))
                .and_then(|t| t.parse::<u64>().ok());
            if let Some(i) = inode.filter(|i| wanted.contains(i)) {
                out.entry(i).or_insert(pid);
            }
        }
        if out.len() == wanted.len() {
            break;
        }
    }
    out
}

/// uid → name from `/etc/passwd`.
fn users(ctx: &SysCtx) -> HashMap<u32, String> {
    ctx.procfs
        .read("/etc/passwd")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            Some((
                f.get(2)?.parse().ok()?,
                (*f.first()?).chars().take(64).collect(),
            ))
        })
        .collect()
}

pub fn collect(ctx: &SysCtx) -> Ports {
    let mut socks = Vec::new();
    for (file, proto) in [
        ("/proc/net/tcp", Protocol::Tcp),
        ("/proc/net/tcp6", Protocol::Tcp),
        ("/proc/net/udp", Protocol::Udp),
        ("/proc/net/udp6", Protocol::Udp),
    ] {
        if let Some(t) = ctx.procfs.read(file) {
            socks.extend(parse_proc_net(&t, proto));
        }
    }
    let wanted: BTreeSet<u64> = socks.iter().map(|s| s.inode).filter(|i| *i != 0).collect();
    let owners = socket_owners(ctx, &wanted);
    let names = users(ctx);
    let mut seen = BTreeSet::new();
    let mut ports = Vec::new();
    for s in socks {
        // SO_REUSEPORT groups show one socket per worker.
        if !seen.insert((s.proto as u8, s.addr, s.port)) {
            continue;
        }
        let pid = owners.get(&s.inode).copied();
        let process = pid.and_then(|p| {
            ctx.procfs
                .read(&format!("/proc/{p}/comm"))
                .map(|c| c.trim().chars().take(64).collect())
        });
        ports.push(ListeningPort {
            proto: s.proto,
            addr: s.addr,
            port: s.port,
            pid,
            process,
            user: names.get(&s.uid).cloned(),
            reachable: None,
        });
    }
    ports.sort_by_key(|p| (p.port, p.proto as u8, p.addr));
    Ports { ports }
}

/// `ports.list`.
pub struct PortsHandler;

impl OpHandler for PortsHandler {
    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        _op: &'a Op,
        _meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move { Ok(OpOutput::Payload(Payload::Ports(collect(ctx)))) })
    }
}

/// Emits `port.new` for listening ports not seen before. The first
/// observation only primes the set. UDP ports in the ephemeral range are
/// ignored (DNS clients and the like hold unconnected sockets there).
#[derive(Default)]
pub struct PortWatcher {
    known: Option<BTreeSet<(u8, IpAddr, u16)>>,
}

impl PortWatcher {
    pub fn observe(&mut self, ports: &Ports, ephemeral: (u16, u16)) -> Vec<Event> {
        let cur: BTreeSet<(u8, IpAddr, u16)> = ports
            .ports
            .iter()
            .filter(|p| {
                !(p.proto == Protocol::Udp && (ephemeral.0..=ephemeral.1).contains(&p.port))
            })
            .map(|p| (p.proto as u8, p.addr, p.port))
            .collect();
        let events = match &self.known {
            None => Vec::new(),
            Some(k) => ports
                .ports
                .iter()
                .filter(|p| {
                    let id = (p.proto as u8, p.addr, p.port);
                    cur.contains(&id) && !k.contains(&id)
                })
                .map(|p| Event::NewListeningPort {
                    proto: p.proto,
                    addr: p.addr,
                    port: p.port,
                    process: p.process.clone(),
                    // Filled in by the firewall module once Managed mode
                    // can answer it (design §4.8).
                    blocked: false,
                })
                .collect(),
        };
        self.known = Some(cur);
        events
    }
}

/// `net.ipv4.ip_local_port_range`, default 32768–60999.
pub fn ephemeral_range(ctx: &SysCtx) -> (u16, u16) {
    ctx.procfs
        .read("/proc/sys/net/ipv4/ip_local_port_range")
        .and_then(|t| {
            let mut it = t.split_whitespace().map(|n| n.parse::<u16>().ok());
            Some((it.next()??, it.next()??))
        })
        .unwrap_or((32_768, 60_999))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FakeRunner;
    use crate::testutil::{T0, ctx_at};
    use std::rc::Rc;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   105        0 1002 1 0000000000000000 100 0 0 10 0
   2: 0200000A:0016 0100000A:D431 01 00000000:00000000 02:000A7E0B 00000000     0        0 1003 4 0000000000000000 20 4 30 10 -1
   3: garbage
";
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000    33        0 1004 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1005 1 0000000000000000 100 0 0 10 0
";
    const UDP: &str = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  100: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 1006 2 0000000000000000 0
  101: 0200000A:A1B2 0800080808:0035 01 00000000:00000000 00:00000000 00000000   101        0 1007 2 0000000000000000 0
  102: 00000000:D431 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 1008 2 0000000000000000 0
";

    #[test]
    fn parse_and_map_to_processes() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::create_dir_all(d.join("proc/net")).unwrap();
        std::fs::create_dir_all(d.join("etc")).unwrap();
        std::fs::write(d.join("proc/net/tcp"), TCP).unwrap();
        std::fs::write(d.join("proc/net/tcp6"), TCP6).unwrap();
        std::fs::write(d.join("proc/net/udp"), UDP).unwrap();
        std::fs::write(
            d.join("etc/passwd"),
            "root:x:0:0::/root:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n",
        )
        .unwrap();
        for (pid, comm, inodes) in [
            (812u32, "sshd", &[1001u64, 1005][..]),
            (900, "nginx", &[1004, 1004][..]),
        ] {
            let p = d.join(format!("proc/{pid}"));
            std::fs::create_dir_all(p.join("fd")).unwrap();
            std::fs::write(p.join("comm"), format!("{comm}\n")).unwrap();
            for (n, i) in inodes.iter().enumerate() {
                std::os::unix::fs::symlink(
                    format!("socket:[{i}]"),
                    p.join(format!("fd/{}", n + 3)),
                )
                .unwrap();
            }
            std::os::unix::fs::symlink("/dev/null", p.join("fd/0")).unwrap();
        }
        let ctx = ctx_at(d, Rc::new(FakeRunner::new()), T0);
        let ports = collect(&ctx).ports;
        let summary: Vec<String> = ports
            .iter()
            .map(|p| {
                format!(
                    "{:?} {} {} {:?} {:?}",
                    p.proto, p.addr, p.port, p.process, p.user
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                "Tcp 0.0.0.0 22 Some(\"sshd\") Some(\"root\")",
                "Tcp ::1 22 Some(\"sshd\") Some(\"root\")",
                "Udp 127.0.0.53 53 None None",
                "Tcp :: 80 Some(\"nginx\") Some(\"www-data\")",
                "Tcp 127.0.0.1 3306 None None",
                "Udp 0.0.0.0 54321 None None",
            ]
        );

        let mut w = PortWatcher::default();
        let eph = ephemeral_range(&ctx);
        assert!(
            w.observe(
                &Ports {
                    ports: ports.clone()
                },
                eph
            )
            .is_empty()
        );
        let mut more = ports;
        more.push(ListeningPort {
            proto: Protocol::Tcp,
            addr: "0.0.0.0".parse().unwrap(),
            port: 8080,
            pid: Some(1),
            process: Some("node".into()),
            user: None,
            reachable: None,
        });
        more.push(ListeningPort {
            proto: Protocol::Udp,
            addr: "0.0.0.0".parse().unwrap(),
            port: 40_000,
            pid: None,
            process: None,
            user: None,
            reachable: None,
        });
        let ev = w.observe(
            &Ports {
                ports: more.clone(),
            },
            eph,
        );
        assert_eq!(ev.len(), 1);
        assert!(
            matches!(&ev[0], Event::NewListeningPort { port: 8080, process: Some(p), .. } if p == "node")
        );
        assert!(w.observe(&Ports { ports: more }, eph).is_empty());
    }

    #[test]
    fn hex_addresses() {
        assert_eq!(hex_addr("0100007F"), Some("127.0.0.1".parse().unwrap()));
        assert_eq!(
            hex_addr("B80D01200000000000000000FF000000"),
            Some("2001:db8::ff".parse().unwrap())
        );
        assert_eq!(hex_addr("zz"), None);
        assert_eq!(hex_addr("0100007g"), None);
    }
}
