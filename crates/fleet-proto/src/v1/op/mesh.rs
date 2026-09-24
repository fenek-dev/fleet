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
        validate_peers(&self.peers)
    }
}

pub(crate) fn validate_peers(peers: &[WgPeer]) -> Result<(), ArgError> {
    at_most(peers, MeshConfig::MAX_PEERS, "mesh peers")?;
    peers.iter().try_for_each(WgPeer::validate)
}
