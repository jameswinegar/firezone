use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use std::{collections::HashSet, fmt, hash::Hash, net::SocketAddr};

use connlib_shared::{
    messages::{Relay, RequestConnection, ReuseConnection},
    Callbacks,
};

use crate::{ConnectedPeer, RoleState, Tunnel, REALM};

mod client;
mod gateway;

const ICE_CANDIDATE_BUFFER: usize = 100;
// We should use not more than 1-2 relays (WebRTC in Firefox breaks at 5) due to combinatoric
// complexity of checking all the ICE candidate pairs
const MAX_RELAYS: usize = 2;

const MAX_HOST_CANDIDATES: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    NewConnection(RequestConnection),
    ReuseConnection(ReuseConnection),
}

impl<CB, TRoleState, TRole, TId> Tunnel<CB, TRoleState, TRole, TId>
where
    CB: Callbacks + 'static,
    TRoleState: RoleState<Id = TId>,
    TId: Eq + Hash + Copy + fmt::Display,
{
    pub fn add_ice_candidate(&self, conn_id: TRoleState::Id, ice_candidate: String) {
        tracing::info!(%ice_candidate, %conn_id, "new remote candidate");
        self.connections
            .lock()
            .connection_pool
            .add_remote_candidate(conn_id, ice_candidate);
    }
}

fn insert_peers<TId: Copy, TTransform>(
    peers_by_ip: &mut IpNetworkTable<ConnectedPeer<TId, TTransform>>,
    ips: &Vec<IpNetwork>,
    peer: ConnectedPeer<TId, TTransform>,
) {
    for ip in ips {
        peers_by_ip.insert(*ip, peer.clone());
    }
}

fn stun(relays: &[Relay]) -> HashSet<SocketAddr> {
    relays
        .iter()
        .filter_map(|r| {
            if let Relay::Stun(r) = r {
                Some(r.addr)
            } else {
                None
            }
        })
        .collect()
}

fn turn(relays: &[Relay]) -> HashSet<(SocketAddr, String, String, String)> {
    relays
        .iter()
        .filter_map(|r| {
            if let Relay::Turn(r) = r {
                Some((
                    r.addr,
                    r.username.clone(),
                    r.password.clone(),
                    REALM.to_string(),
                ))
            } else {
                None
            }
        })
        .collect()
}
