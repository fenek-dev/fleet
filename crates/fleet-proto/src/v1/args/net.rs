//! Network arguments: ports, CIDRs, WireGuard peers.

use super::{ArgError, at_most, ensure};
use core::fmt;
use core::str::FromStr;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// TCP/UDP port, 1–65535.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct Port(u16);

impl Port {
    pub fn new(p: u16) -> Result<Self, ArgError> {
        ensure(p != 0, "port")?;
        Ok(Self(p))
    }

    pub fn get(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for Port {
    type Error = ArgError;
    fn try_from(p: u16) -> Result<Self, ArgError> {
        Self::new(p)
    }
}

impl From<Port> for u16 {
    fn from(p: Port) -> u16 {
        p.0
    }
}

/// Inclusive port range with `start <= end`; a single port is `start == end`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "(Port, Port)", into = "(Port, Port)")]
pub struct PortRange {
    start: Port,
    end: Port,
}

impl PortRange {
    pub fn new(start: Port, end: Port) -> Result<Self, ArgError> {
        ensure(start <= end, "port range")?;
        Ok(Self { start, end })
    }

    pub fn single(p: Port) -> Self {
        Self { start: p, end: p }
    }

    pub fn start(self) -> Port {
        self.start
    }

    pub fn end(self) -> Port {
        self.end
    }
}

impl TryFrom<(Port, Port)> for PortRange {
    type Error = ArgError;
    fn try_from((a, b): (Port, Port)) -> Result<Self, ArgError> {
        Self::new(a, b)
    }
}

impl From<PortRange> for (Port, Port) {
    fn from(r: PortRange) -> Self {
        (r.start, r.end)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Canonical CIDR: prefix within the family's width and no host bits set.
/// Text form `addr/prefix`; a bare address parses as a host route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "(IpAddr, u8)", into = "(IpAddr, u8)")]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

fn host_bits(addr: IpAddr, prefix: u8) -> Option<u128> {
    let (bits, width) = match addr {
        IpAddr::V4(a) => (u128::from(u32::from(a)), 32),
        IpAddr::V6(a) => (u128::from(a), 128),
    };
    if prefix > width {
        return None;
    }
    // Low `width - prefix` bits set.
    let host_mask = match width - prefix {
        128 => u128::MAX,
        n => (1u128 << n) - 1,
    };
    Some(bits & host_mask)
}

impl Cidr {
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, ArgError> {
        ensure(host_bits(addr, prefix) == Some(0), "cidr")?;
        Ok(Self { addr, prefix })
    }

    pub fn host(addr: IpAddr) -> Self {
        let prefix = if addr.is_ipv4() { 32 } else { 128 };
        Self { addr, prefix }
    }

    pub fn addr(self) -> IpAddr {
        self.addr
    }

    pub fn prefix(self) -> u8 {
        self.prefix
    }

    pub fn contains(self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                let width: u8 = if ip.is_ipv4() { 32 } else { 128 };
                let to_bits = |a: IpAddr| match a {
                    IpAddr::V4(a) => u128::from(u32::from(a)),
                    IpAddr::V6(a) => u128::from(a),
                };
                let shift = u32::from(width - self.prefix);
                let hi = |b: u128| b.checked_shr(shift).unwrap_or(0);
                hi(to_bits(self.addr)) == hi(to_bits(ip))
            }
            _ => false,
        }
    }
}

impl TryFrom<(IpAddr, u8)> for Cidr {
    type Error = ArgError;
    fn try_from((a, p): (IpAddr, u8)) -> Result<Self, ArgError> {
        Self::new(a, p)
    }
}

impl From<Cidr> for (IpAddr, u8) {
    fn from(c: Cidr) -> Self {
        (c.addr, c.prefix)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl FromStr for Cidr {
    type Err = ArgError;
    fn from_str(s: &str) -> Result<Self, ArgError> {
        let bad = ArgError::Invalid("cidr");
        match s.split_once('/') {
            Some((a, p)) => {
                let addr = a.parse().map_err(|_| bad)?;
                if p.is_empty() || p.len() > 3 || !p.bytes().all(|c| c.is_ascii_digit()) {
                    return Err(bad);
                }
                Self::new(addr, p.parse().map_err(|_| bad)?)
            }
            None => Ok(Self::host(s.parse().map_err(|_| bad)?)),
        }
    }
}

/// `ip:port` for a WireGuard endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    pub addr: IpAddr,
    pub port: Port,
}

/// Curve25519 public key (WireGuard). All-zero is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "[u8; 32]", into = "[u8; 32]")]
pub struct WgKey([u8; 32]);

impl WgKey {
    pub fn new(k: [u8; 32]) -> Result<Self, ArgError> {
        ensure(k != [0; 32], "wireguard key")?;
        Ok(Self(k))
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl TryFrom<[u8; 32]> for WgKey {
    type Error = ArgError;
    fn try_from(k: [u8; 32]) -> Result<Self, ArgError> {
        Self::new(k)
    }
}

impl From<WgKey> for [u8; 32] {
    fn from(k: WgKey) -> Self {
        k.0
    }
}

/// A WireGuard peer. No preshared key: operation arguments are stored in
/// the audit log, so secrets never travel as arguments.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WgPeer {
    pub public_key: WgKey,
    pub endpoint: Option<Endpoint>,
    /// 1–16 entries.
    pub allowed_ips: Vec<Cidr>,
    /// Seconds, 0 = off.
    pub keepalive_s: u16,
}

impl WgPeer {
    pub fn validate(&self) -> Result<(), ArgError> {
        ensure(!self.allowed_ips.is_empty(), "allowed ips")?;
        at_most(&self.allowed_ips, 16, "allowed ips")
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::roundtrip;
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn examples() {
        assert!(Port::new(0).is_err());
        assert!(crate::decode::<Port>(&crate::encode(&0u16)).is_err());
        let p = |n| Port::new(n).unwrap();
        assert!(PortRange::new(p(10), p(9)).is_err());
        assert!(crate::decode::<PortRange>(&crate::encode(&(10u16, 9u16))).is_err());
        roundtrip(&PortRange::new(p(80), p(443)).unwrap());

        assert_eq!("10.0.0.0/8".parse::<Cidr>().unwrap().prefix(), 8);
        assert!("10.0.0.1/8".parse::<Cidr>().is_err());
        assert!("10.0.0.0/33".parse::<Cidr>().is_err());
        assert!("10.0.0.0/+8".parse::<Cidr>().is_err());
        assert!("2001:db8::/32".parse::<Cidr>().is_ok());
        assert!("2001:db8::1/64".parse::<Cidr>().is_err());
        assert_eq!("1.2.3.4".parse::<Cidr>().unwrap().prefix(), 32);
        assert!("0.0.0.0/0".parse::<Cidr>().is_ok());
        let c: Cidr = "192.168.1.0/24".parse().unwrap();
        assert!(c.contains("192.168.1.77".parse().unwrap()));
        assert!(!c.contains("192.168.2.1".parse().unwrap()));
        assert!(!c.contains("::1".parse().unwrap()));
        assert!(
            "::/0"
                .parse::<Cidr>()
                .unwrap()
                .contains("::1".parse().unwrap())
        );
        assert_eq!(c.to_string(), "192.168.1.0/24");
        let bad = (IpAddr::from([10, 0, 0, 1]), 8u8);
        assert!(crate::decode::<Cidr>(&crate::encode(&bad)).is_err());

        assert!(WgKey::new([0; 32]).is_err());
        let peer = WgPeer {
            public_key: WgKey::new([1; 32]).unwrap(),
            endpoint: None,
            allowed_ips: vec![],
            keepalive_s: 25,
        };
        assert!(peer.validate().is_err());
    }

    proptest! {
        #[test]
        fn port_accepts(n in 1u16..) {
            roundtrip(&Port::new(n).unwrap());
        }

        #[test]
        fn cidr_v4_canonical(a in any::<u32>(), prefix in 0u8..=32) {
            let masked = if prefix == 0 { 0 } else { a & (u32::MAX << (32 - prefix)) };
            let addr = IpAddr::from(masked.to_be_bytes());
            let c = Cidr::new(addr, prefix).unwrap();
            prop_assert!(c.contains(IpAddr::from(a.to_be_bytes())));
            prop_assert_eq!(c.to_string().parse::<Cidr>().unwrap(), c);
            roundtrip(&c);
            if masked != a {
                prop_assert!(Cidr::new(IpAddr::from(a.to_be_bytes()), prefix).is_err());
            }
        }

        #[test]
        fn cidr_v6_canonical(a in any::<u128>(), prefix in 0u8..=128) {
            let masked = if prefix == 0 { 0 } else { a & (u128::MAX << (128 - u32::from(prefix))) };
            let c = Cidr::new(IpAddr::from(masked.to_be_bytes()), prefix).unwrap();
            prop_assert!(c.contains(IpAddr::from(a.to_be_bytes())));
            roundtrip(&c);
            if masked != a {
                prop_assert!(Cidr::new(IpAddr::from(a.to_be_bytes()), prefix).is_err());
            }
        }

        #[test]
        fn cidr_rejects_long_prefix(a in any::<u32>(), prefix in 33u8..) {
            prop_assert!(Cidr::new(IpAddr::from(a.to_be_bytes()), prefix).is_err());
        }
    }
}
