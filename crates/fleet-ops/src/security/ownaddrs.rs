//! The host's own addresses, for `BanService::set_own_addrs` (web logs
//! never ban them): IPv4 from `/proc/net/fib_trie` (`/32 host LOCAL`
//! leaves), IPv6 from `/proc/net/if_inet6`. Loopback is left out (never
//! bannable anyway).

use crate::ctx::SysCtx;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// At most this many addresses are kept.
pub const MAX_ADDRS: usize = 256;

/// `|-- 203.0.113.7` followed by `/32 host LOCAL` → the address.
pub fn parse_fib_trie(text: &str) -> Vec<Ipv4Addr> {
    let mut out = BTreeSet::new();
    let mut last: Option<Ipv4Addr> = None;
    for line in text.lines() {
        let t = line.trim_start();
        if let Some(a) = t.strip_prefix("|-- ") {
            last = a.trim().parse().ok();
        } else if t.starts_with("/32 host LOCAL")
            && let Some(a) = last
            && !a.is_loopback()
        {
            out.insert(a);
        }
    }
    out.into_iter().take(MAX_ADDRS).collect()
}

/// `20010db8000000000000000000000001 02 40 00 80 eth0` → the address.
pub fn parse_if_inet6(text: &str) -> Vec<Ipv6Addr> {
    let mut out = BTreeSet::new();
    for line in text.lines() {
        let Some(hex) = line.split_whitespace().next() else {
            continue;
        };
        if hex.len() != 32 {
            continue;
        }
        let Ok(v) = u128::from_str_radix(hex, 16) else {
            continue;
        };
        let a = Ipv6Addr::from(v);
        if !a.is_loopback() {
            out.insert(a);
        }
    }
    out.into_iter().take(MAX_ADDRS).collect()
}

/// Both families, from `/proc` under the context root.
pub fn collect(ctx: &SysCtx) -> Vec<IpAddr> {
    let v4 = ctx
        .procfs
        .read("/proc/net/fib_trie")
        .map(|t| parse_fib_trie(&t))
        .unwrap_or_default();
    let v6 = ctx
        .procfs
        .read("/proc/net/if_inet6")
        .map(|t| parse_if_inet6(&t))
        .unwrap_or_default();
    v4.into_iter()
        .map(IpAddr::V4)
        .chain(v6.into_iter().map(IpAddr::V6))
        .take(MAX_ADDRS)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIB: &str = "Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
     +-- 203.0.113.0/24 2 0 2
        |-- 203.0.113.0
           /24 link UNICAST
        |-- 203.0.113.7
           /32 host LOCAL
        |-- 203.0.113.255
           /32 link BROADCAST
Local:
  +-- 0.0.0.0/0 3 0 5
        |-- 203.0.113.7
           /32 host LOCAL
        |-- 10.77.0.1
           /32 host LOCAL
";

    const INET6: &str = "00000000000000000000000000000001 01 80 10 80       lo
20010db8000500060000000000000001 02 40 00 80     eth0
fe80000000000000021122fffe334455 02 40 20 80     eth0
bogus
";

    #[test]
    fn parses_local_addresses() {
        assert_eq!(
            parse_fib_trie(FIB),
            vec![
                "10.77.0.1".parse::<Ipv4Addr>().unwrap(),
                "203.0.113.7".parse().unwrap()
            ]
        );
        assert_eq!(
            parse_if_inet6(INET6),
            vec![
                "2001:db8:5:6::1".parse::<Ipv6Addr>().unwrap(),
                "fe80::211:22ff:fe33:4455".parse().unwrap()
            ]
        );
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("proc/net")).unwrap();
        std::fs::write(d.path().join("proc/net/fib_trie"), FIB).unwrap();
        std::fs::write(d.path().join("proc/net/if_inet6"), INET6).unwrap();
        let c = crate::testutil::ctx(d.path(), std::rc::Rc::new(crate::FakeRunner::new()));
        assert_eq!(collect(&c).len(), 4);
        assert!(collect(&crate::testutil::ctx_empty()).is_empty());
    }
}
