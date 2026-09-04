use super::{
    candidates::{is_private_or_local, NativeAddressFamily, NativeCandidate, NativeCandidateType},
    signaling::NativeDeviceRole,
};
use serde::{Deserialize, Serialize};
use sha2_compat::{Digest, Sha256};
use std::{cmp::Reverse, net::IpAddr};

pub const MAX_CANDIDATE_PAIRS: usize = 256;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EstimatedNativeRoute {
    SameLan,
    Ipv6Direct,
    MappedDirect,
    StunHolePunch,
    MixedDirect,
    ManualDirect,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NativeCandidatePair {
    pub pair_id: String,
    pub local_candidate: NativeCandidate,
    pub remote_candidate: NativeCandidate,
    pub sender_candidate_id: String,
    pub receiver_candidate_id: String,
    pub address_family: NativeAddressFamily,
    pub estimated_route: EstimatedNativeRoute,
    pub priority: u64,
    /// The source endpoint observed from repeated authenticated probes when a
    /// NAT maps peer traffic differently from the advertised STUN endpoint.
    /// Candidate identity remains bound to the signed candidate set; this
    /// endpoint is only a transport destination learned inside that identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_reflexive_remote_endpoint: Option<std::net::SocketAddr>,
}

impl NativeCandidatePair {
    pub fn remote_socket_addr(&self) -> std::net::SocketAddr {
        self.peer_reflexive_remote_endpoint
            .unwrap_or_else(|| self.remote_candidate.socket_addr())
    }
}

pub fn build_candidate_pairs(
    local_candidates: &[NativeCandidate],
    remote_candidates: &[NativeCandidate],
    local_role: NativeDeviceRole,
) -> Vec<NativeCandidatePair> {
    let mut pairs = Vec::new();
    for local in local_candidates {
        for remote in remote_candidates {
            if local.address_family != remote.address_family {
                continue;
            }
            let estimated_route = classify_route(local, remote);
            let (sender_candidate_id, receiver_candidate_id, sender_priority, receiver_priority) =
                if local_role == NativeDeviceRole::Sender {
                    (
                        local.candidate_id.clone(),
                        remote.candidate_id.clone(),
                        local.priority,
                        remote.priority,
                    )
                } else {
                    (
                        remote.candidate_id.clone(),
                        local.candidate_id.clone(),
                        remote.priority,
                        local.priority,
                    )
                };
            let pair_id = pair_id(&sender_candidate_id, &receiver_candidate_id);
            let route_weight = match estimated_route {
                EstimatedNativeRoute::SameLan => 600u64,
                EstimatedNativeRoute::Ipv6Direct => 550,
                EstimatedNativeRoute::MappedDirect => 450,
                EstimatedNativeRoute::StunHolePunch => 400,
                EstimatedNativeRoute::MixedDirect => 300,
                EstimatedNativeRoute::ManualDirect => 100,
            };
            pairs.push(NativeCandidatePair {
                pair_id,
                local_candidate: local.clone(),
                remote_candidate: remote.clone(),
                sender_candidate_id,
                receiver_candidate_id,
                address_family: local.address_family,
                estimated_route,
                priority: route_weight * 1_000_000
                    + sender_priority as u64 * 1000
                    + receiver_priority as u64,
                peer_reflexive_remote_endpoint: None,
            });
        }
    }
    pairs.sort_by_key(|pair| (Reverse(pair.priority), pair.pair_id.clone()));
    pairs.dedup_by(|left, right| left.pair_id == right.pair_id);
    pairs.truncate(MAX_CANDIDATE_PAIRS);
    pairs
}

pub fn pair_id(sender_candidate_id: &str, receiver_candidate_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"flowshare/native/candidate-pair/v1");
    digest.update((sender_candidate_id.len() as u16).to_be_bytes());
    digest.update(sender_candidate_id.as_bytes());
    digest.update((receiver_candidate_id.len() as u16).to_be_bytes());
    digest.update(receiver_candidate_id.as_bytes());
    digest
        .finalize()
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn classify_route(local: &NativeCandidate, remote: &NativeCandidate) -> EstimatedNativeRoute {
    if local.candidate_type == NativeCandidateType::Manual
        || remote.candidate_type == NativeCandidateType::Manual
    {
        return EstimatedNativeRoute::ManualDirect;
    }
    if same_lan_address(local.address, remote.address)
        && matches!(
            local.candidate_type,
            NativeCandidateType::Host | NativeCandidateType::Ipv6
        )
        && matches!(
            remote.candidate_type,
            NativeCandidateType::Host | NativeCandidateType::Ipv6
        )
    {
        return EstimatedNativeRoute::SameLan;
    }
    if local.address_family == NativeAddressFamily::Ipv6
        && !is_private_or_local(local.address)
        && !is_private_or_local(remote.address)
    {
        return EstimatedNativeRoute::Ipv6Direct;
    }
    if local.candidate_type == NativeCandidateType::Mapped
        && remote.candidate_type == NativeCandidateType::Mapped
    {
        return EstimatedNativeRoute::MappedDirect;
    }
    if local.candidate_type == NativeCandidateType::ServerReflexive
        && remote.candidate_type == NativeCandidateType::ServerReflexive
    {
        return EstimatedNativeRoute::StunHolePunch;
    }
    EstimatedNativeRoute::MixedDirect
}

fn same_lan_address(left: IpAddr, right: IpAddr) -> bool {
    match (left, right) {
        (IpAddr::V4(left), IpAddr::V4(right)) => {
            let left = left.octets();
            let right = right.octets();
            is_private_or_local(IpAddr::V4(left.into()))
                && is_private_or_local(IpAddr::V4(right.into()))
                && left[..3] == right[..3]
        }
        (IpAddr::V6(left), IpAddr::V6(right)) => {
            let left = left.octets();
            let right = right.octets();
            is_private_or_local(IpAddr::V6(left.into()))
                && is_private_or_local(IpAddr::V6(right.into()))
                && left[..8] == right[..8]
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidates::ManualCandidateInput;

    fn manual(address: &str, port: u16) -> NativeCandidate {
        ManualCandidateInput {
            address: address.parse().unwrap(),
            port,
            priority: None,
        }
        .into_candidate(1, u64::MAX - 31_000, address.starts_with("127."))
        .unwrap()
    }

    #[test]
    fn pair_identity_is_role_stable() {
        let sender = manual("198.51.100.1", 40000);
        let receiver = manual("203.0.113.2", 41000);
        let sender_view = build_candidate_pairs(
            &[sender.clone()],
            &[receiver.clone()],
            NativeDeviceRole::Sender,
        );
        let receiver_view =
            build_candidate_pairs(&[receiver], &[sender], NativeDeviceRole::Receiver);
        assert_eq!(sender_view[0].pair_id, receiver_view[0].pair_id);
        assert_eq!(
            sender_view[0].sender_candidate_id,
            receiver_view[0].sender_candidate_id
        );
        assert_eq!(sender_view[0].priority, receiver_view[0].priority);
    }
}
