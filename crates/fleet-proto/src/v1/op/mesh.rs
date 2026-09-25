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
