use super::{
    candidates::{InterfaceCandidateDiagnostic, NativeCandidate, NativeCandidateType},
    hole_punch::{HolePunchReport, ProbePairResult},
    path_selection::{EstimatedNativeRoute, NativeCandidatePair},
    port_mapping::PortMappingAttemptDiagnostic,
    signaling::ExistingSignalingAdapterStatus,
    stun::{ObservedNatMappingBehavior, StunObservation},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectivityStateName {
    Gathering,
    AwaitingRemoteCandidates,
    ReadyToCheck,
    Checking,
    Nominated,
    QuicEstablishing,
    QuicEstablished,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectivityOutcome {
    LanDirectSuccess,
    Ipv6DirectSuccess,
    MappedDirectSuccess,
    StunHolePunchSuccess,
    ManualDirectSuccess,
    UdpBlocked,
    FirewallBlockedLikely,
    SymmetricNatLikely,
    CandidateExchangeFailed,
    CandidateAuthenticationFailed,
    NoViablePair,
    QuicHandshakeFailed,
    SecureSessionFailed,
    DirectConnectTimeout,
    RelayRequired,
    Cancelled,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum NativeFallbackDecision {
    NativeDirectSuccess,
    NativeDirectFailedWebRtcEligible,
    RelayRequired,
    UnsupportedNetwork,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectedPathDiagnostic {
    pub pair_id: String,
    pub estimated_route: EstimatedNativeRoute,
    pub local_candidate_type: NativeCandidateType,
    pub remote_candidate_type: NativeCandidateType,
    pub local_endpoint: String,
    pub remote_endpoint: String,
    pub peer_reflexive_remote_endpoint: Option<String>,
    pub sender_candidate_id: String,
    pub receiver_candidate_id: String,
    pub rtt_ms: Option<f64>,
    pub confirmation_count: u8,
    pub source_endpoint_stable: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsFirewallDiagnostic {
    pub udp_bind_succeeded: bool,
    pub outbound_stun_succeeded: bool,
    pub inbound_authenticated_probe_observed: bool,
    pub quic_handshake_reached: bool,
    pub firewall_blocked_likely: bool,
    pub note: &'static str,
}

impl Default for WindowsFirewallDiagnostic {
    fn default() -> Self {
        Self {
            udp_bind_succeeded: false,
            outbound_stun_succeeded: false,
            inbound_authenticated_probe_observed: false,
            quic_handshake_reached: false,
            firewall_blocked_likely: false,
            note: "FlowGet never changes Windows Firewall rules.",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeConnectivityDiagnostics {
    pub connectivity_session_id: String,
    pub transfer_id: String,
    pub candidate_generation: u32,
    pub state: ConnectivityStateName,
    pub interfaces_examined: Vec<InterfaceCandidateDiagnostic>,
    pub host_candidates: Vec<NativeCandidate>,
    pub stun_results: Vec<StunObservation>,
    pub observed_nat_mapping: ObservedNatMappingBehavior,
    pub mapping_consistent_across_stun_servers: Option<bool>,
    pub mapped_candidates: Vec<NativeCandidate>,
    pub port_mapping_attempts: Vec<PortMappingAttemptDiagnostic>,
    pub candidate_pairs_attempted: Vec<NativeCandidatePair>,
    pub probe_results: Vec<ProbePairResult>,
    pub probe_packets_sent: u32,
    pub probe_packets_received: u32,
    pub authenticated_probe_packets_received: u32,
    pub unauthenticated_probe_packets_dropped: u32,
    pub replayed_probe_packets_dropped: u32,
    pub selected_pair: Option<SelectedPathDiagnostic>,
    pub quic_establishment_ms: Option<f64>,
    pub secure_handshake_ms: Option<f64>,
    pub failure_classification: Option<ConnectivityOutcome>,
    pub fallback_decision: Option<NativeFallbackDecision>,
    pub firewall: WindowsFirewallDiagnostic,
    pub signaling_adapter: ExistingSignalingAdapterStatus,
    pub same_udp_port_preserved_for_stun_probe_and_quic: bool,
    pub quinn_udp_buffer_target_bytes: usize,
    pub quinn_udp_send_buffer_bytes: Option<usize>,
    pub quinn_udp_receive_buffer_bytes: Option<usize>,
    pub file_payload_bytes_sent_through_signaling: u64,
    pub last_error: Option<String>,
}

impl NativeConnectivityDiagnostics {
    pub fn empty(
        connectivity_session_id: String,
        transfer_id: String,
        candidate_generation: u32,
        signaling_adapter: ExistingSignalingAdapterStatus,
    ) -> Self {
        Self {
            connectivity_session_id,
            transfer_id,
            candidate_generation,
            state: ConnectivityStateName::Gathering,
            interfaces_examined: Vec::new(),
            host_candidates: Vec::new(),
            stun_results: Vec::new(),
            observed_nat_mapping: ObservedNatMappingBehavior::Unknown,
            mapping_consistent_across_stun_servers: None,
            mapped_candidates: Vec::new(),
            port_mapping_attempts: Vec::new(),
            candidate_pairs_attempted: Vec::new(),
            probe_results: Vec::new(),
            probe_packets_sent: 0,
            probe_packets_received: 0,
            authenticated_probe_packets_received: 0,
            unauthenticated_probe_packets_dropped: 0,
            replayed_probe_packets_dropped: 0,
            selected_pair: None,
            quic_establishment_ms: None,
            secure_handshake_ms: None,
            failure_classification: None,
            fallback_decision: None,
            firewall: WindowsFirewallDiagnostic::default(),
            signaling_adapter,
            same_udp_port_preserved_for_stun_probe_and_quic: false,
            quinn_udp_buffer_target_bytes: super::quinn_connectivity::QUINN_UDP_SOCKET_BUFFER_BYTES,
            quinn_udp_send_buffer_bytes: None,
            quinn_udp_receive_buffer_bytes: None,
            file_payload_bytes_sent_through_signaling: 0,
            last_error: None,
        }
    }

    pub fn apply_hole_punch_report(
        &mut self,
        report: &HolePunchReport,
        selected_pair: Option<&NativeCandidatePair>,
    ) {
        self.probe_results = report.pair_results.clone();
        self.probe_packets_sent = report.total_packets_sent;
        self.probe_packets_received = report.total_packets_received;
        self.authenticated_probe_packets_received = report.authenticated_packets_received;
        self.unauthenticated_probe_packets_dropped = report.unauthenticated_packets_dropped;
        self.replayed_probe_packets_dropped = report.replayed_packets_dropped;
        self.firewall.inbound_authenticated_probe_observed = report
            .pair_results
            .iter()
            .any(|pair| pair.authenticated_requests_received > 0);
        if let Some(pair) = selected_pair {
            let observation = report
                .pair_results
                .iter()
                .find(|result| result.pair_id == pair.pair_id);
            self.selected_pair = Some(selected_path(pair, observation));
            self.state = ConnectivityStateName::Nominated;
            let outcome = success_outcome(pair.estimated_route);
            self.failure_classification = Some(outcome);
            self.fallback_decision = Some(NativeFallbackDecision::NativeDirectSuccess);
            return;
        }
        let outcome = match report.failure {
            Some(super::signaling::NativeConnectivityFailure::UdpBlocked) => {
                // Successful outbound STUN proves local UDP works, but silence
                // from the peer cannot distinguish peer absence, NAT policy,
                // host firewall, router filtering, or ISP filtering. Do not
                // present a speculative firewall diagnosis as the root cause.
                if self.firewall.outbound_stun_succeeded {
                    ConnectivityOutcome::DirectConnectTimeout
                } else {
                    ConnectivityOutcome::UdpBlocked
                }
            }
            Some(super::signaling::NativeConnectivityFailure::NoViablePair) => {
                if self.observed_nat_mapping
                    == ObservedNatMappingBehavior::LikelyAddressAndPortDependent
                {
                    ConnectivityOutcome::SymmetricNatLikely
                } else {
                    ConnectivityOutcome::NoViablePair
                }
            }
            Some(super::signaling::NativeConnectivityFailure::Cancelled) => {
                ConnectivityOutcome::Cancelled
            }
            Some(_) => ConnectivityOutcome::DirectConnectTimeout,
            None => ConnectivityOutcome::Unknown,
        };
        self.firewall.firewall_blocked_likely =
            outcome == ConnectivityOutcome::FirewallBlockedLikely;
        self.state = if outcome == ConnectivityOutcome::Cancelled {
            ConnectivityStateName::Cancelled
        } else {
            ConnectivityStateName::Failed
        };
        self.failure_classification = Some(outcome);
        self.fallback_decision = Some(match outcome {
            ConnectivityOutcome::SymmetricNatLikely | ConnectivityOutcome::RelayRequired => {
                NativeFallbackDecision::RelayRequired
            }
            ConnectivityOutcome::UdpBlocked => NativeFallbackDecision::UnsupportedNetwork,
            _ => NativeFallbackDecision::NativeDirectFailedWebRtcEligible,
        });
    }
}

fn selected_path(
    pair: &NativeCandidatePair,
    result: Option<&ProbePairResult>,
) -> SelectedPathDiagnostic {
    SelectedPathDiagnostic {
        pair_id: pair.pair_id.clone(),
        estimated_route: pair.estimated_route,
        local_candidate_type: pair.local_candidate.candidate_type,
        remote_candidate_type: pair.remote_candidate.candidate_type,
        local_endpoint: pair.local_candidate.socket_addr().to_string(),
        remote_endpoint: pair.remote_socket_addr().to_string(),
        peer_reflexive_remote_endpoint: pair
            .peer_reflexive_remote_endpoint
            .map(|value| value.to_string()),
        sender_candidate_id: pair.sender_candidate_id.clone(),
        receiver_candidate_id: pair.receiver_candidate_id.clone(),
        rtt_ms: result.and_then(|value| value.best_rtt_ms),
        confirmation_count: result.map_or(0, |value| value.confirmation_count),
        source_endpoint_stable: result.is_none_or(|value| value.source_endpoint_stable),
    }
}

fn success_outcome(route: EstimatedNativeRoute) -> ConnectivityOutcome {
    match route {
        EstimatedNativeRoute::SameLan => ConnectivityOutcome::LanDirectSuccess,
        EstimatedNativeRoute::Ipv6Direct => ConnectivityOutcome::Ipv6DirectSuccess,
        EstimatedNativeRoute::MappedDirect => ConnectivityOutcome::MappedDirectSuccess,
        EstimatedNativeRoute::StunHolePunch | EstimatedNativeRoute::MixedDirect => {
            ConnectivityOutcome::StunHolePunchSuccess
        }
        EstimatedNativeRoute::ManualDirect => ConnectivityOutcome::ManualDirectSuccess,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hole_punch::HolePunchReport,
        signaling::{existing_signaling_adapter_status, NativeConnectivityFailure},
    };

    #[test]
    fn hole_punch_packet_totals_are_retained_for_safe_diagnostics() {
        let mut diagnostics = NativeConnectivityDiagnostics::empty(
            "connectivity-session".into(),
            "transfer".into(),
            2,
            existing_signaling_adapter_status(),
        );
        diagnostics.firewall.outbound_stun_succeeded = true;
        diagnostics.apply_hole_punch_report(
            &HolePunchReport {
                started_unix_ms: 1,
                elapsed_ms: 30_000.0,
                total_packets_sent: 24,
                total_packets_received: 7,
                authenticated_packets_received: 3,
                unauthenticated_packets_dropped: 3,
                replayed_packets_dropped: 1,
                rate_limit_packets_per_second: 64,
                pair_results: Vec::new(),
                selected_pair_id: None,
                failure: Some(NativeConnectivityFailure::UdpBlocked),
            },
            None,
        );

        assert_eq!(diagnostics.candidate_generation, 2);
        assert_eq!(diagnostics.probe_packets_sent, 24);
        assert_eq!(diagnostics.probe_packets_received, 7);
        assert_eq!(diagnostics.authenticated_probe_packets_received, 3);
        assert_eq!(diagnostics.unauthenticated_probe_packets_dropped, 3);
        assert_eq!(diagnostics.replayed_probe_packets_dropped, 1);
        assert_eq!(
            diagnostics.failure_classification,
            Some(ConnectivityOutcome::DirectConnectTimeout)
        );
    }
}
