//! `mesh` group argument types (tags 1300–1399).

use crate::v1::args::{ArgError, Cidr, Port, WgPeer, at_most, ensure};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// WireGuard mesh membership (design §2.5). The server generates its own
/// private key; `mesh.status` reports the public key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MeshConfig {
    /// This server's address inside `network`.
    pub address: IpAddr,
    pub network: Cidr,
    pub listen_port: Port,
    pub peers: Vec<WgPeer>,
}

impl MeshConfig {
    pub const MAX_PEERS: usize = 256;

    pub fn validate(&self) -> Result<(), ArgError> {
        ensure(mesh_network_ok(&self.network), "mesh network")?;
        ensure(self.network.contains(self.address), "mesh address")?;
        validate_peers(&self.peers)?;
        // Peers route only mesh addresses: never hijack other traffic.
        let net = self.network;
        ensure(
            self.peers
                .iter()
                .flat_map(|p| &p.allowed_ips)
                .all(|c| c.prefix() >= net.prefix() && net.contains(c.addr())),
            "allowed ips outside mesh network",
        )
    }
}

/// Private ranges a mesh network must lie in: RFC 1918, shared address
/// space (100.64.0.0/10, RFC 6598), unique local IPv6 (fc00::/7).
pub const MESH_RANGES: [(&str, u8); 5] = [
    ("10.0.0.0", 8),
    ("172.16.0.0", 12),
    ("192.168.0.0", 16),
    ("100.64.0.0", 10),
    ("fc00::", 7),
];

/// A mesh `network`: at least /16 (IPv4) or /48 (IPv6) long, and
/// entirely inside one of [`MESH_RANGES`], so joining can't route public
/// or unrelated address space into the tunnel.
pub fn mesh_network_ok(n: &Cidr) -> bool {
    if !allowed_ip_ok(n) {
        return false;
    }
    MESH_RANGES.iter().any(|(a, p)| {
        let Ok(addr) = a.parse::<IpAddr>() else {
            return false;
        };
        Cidr::new(addr, *p).is_ok_and(|r| n.prefix() >= r.prefix() && r.contains(n.addr()))
    })
}

/// Shortest `allowed_ips` prefix: a default route (`/0`) or a wide prefix
/// would pull unrelated traffic into the tunnel.
pub const MIN_ALLOWED_PREFIX_V4: u8 = 16;
pub const MIN_ALLOWED_PREFIX_V6: u8 = 48;

fn allowed_ip_ok(c: &Cidr) -> bool {
    let min = if c.addr().is_ipv4() {
        MIN_ALLOWED_PREFIX_V4
    } else {
        MIN_ALLOWED_PREFIX_V6
    };
    c.prefix() >= min
}

pub(crate) fn validate_peers(peers: &[WgPeer]) -> Result<(), ArgError> {
    at_most(peers, MeshConfig::MAX_PEERS, "mesh peers")?;
    peers.iter().try_for_each(WgPeer::validate)?;
    ensure(
        peers.iter().flat_map(|p| &p.allowed_ips).all(allowed_ip_ok),
        "allowed ips prefix",
    )
}
