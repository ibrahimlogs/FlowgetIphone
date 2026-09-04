use serde::{Deserialize, Serialize};
use sha2_compat::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

pub const NATIVE_CANDIDATE_VERSION: u16 = 1;
pub const MAX_NATIVE_CANDIDATES: usize = 32;
pub const DEFAULT_CANDIDATE_LIFETIME_MS: u64 = 2 * 60 * 1000;
const CANDIDATE_CLOCK_SKEW_MS: u64 = 30 * 1000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum NativeCandidateType {
    Host,
    ServerReflexive,
    Mapped,
    Ipv6,
    Manual,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NativeCandidateTransport {
    Udp,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum NativeAddressFamily {
    Ipv4,
    Ipv6,
}

impl NativeAddressFamily {
    pub fn for_ip(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CandidatePrivacyPolicy {
    #[default]
    LanFirst,
    PublicOnly,
    AllDirect,
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeCandidate {
    pub version: u16,
    pub candidate_id: String,
    pub candidate_type: NativeCandidateType,
    pub transport: NativeCandidateTransport,
    pub address: IpAddr,
    pub port: u16,
    pub address_family: NativeAddressFamily,
    pub network_identifier: String,
    pub priority: u32,
    pub foundation: String,
    pub related_address: Option<SocketAddr>,
    pub generation: u32,
    pub expires_unix_ms: u64,
}

impl NativeCandidate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        candidate_type: NativeCandidateType,
        address: IpAddr,
        port: u16,
        network_identifier: String,
        priority: u32,
        foundation: String,
        related_address: Option<SocketAddr>,
        generation: u32,
        expires_unix_ms: u64,
    ) -> Result<Self, String> {
        let mut candidate = Self {
            version: NATIVE_CANDIDATE_VERSION,
            candidate_id: String::new(),
            candidate_type,
            transport: NativeCandidateTransport::Udp,
            address,
            port,
            address_family: NativeAddressFamily::for_ip(address),
            network_identifier,
            priority,
            foundation,
            related_address,
            generation,
            expires_unix_ms,
        };
        candidate.candidate_id = candidate.computed_id();
        candidate.validate(true, expires_unix_ms.saturating_sub(1))?;
        Ok(candidate)
    }

    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.port)
    }

    pub fn validate(&self, allow_loopback: bool, now_unix_ms: u64) -> Result<(), String> {
        if self.version != NATIVE_CANDIDATE_VERSION {
            return Err("native-candidate-version-unsupported".into());
        }
        if self.transport != NativeCandidateTransport::Udp || self.port == 0 {
            return Err("native-candidate-transport-invalid".into());
        }
        if NativeAddressFamily::for_ip(self.address) != self.address_family {
            return Err("native-candidate-address-family-mismatch".into());
        }
        if self.address.is_unspecified() || is_multicast(self.address) {
            return Err("native-candidate-address-invalid".into());
        }
        if self.address.is_loopback() && !allow_loopback {
            return Err("native-candidate-loopback-not-permitted".into());
        }
        if matches!(self.address, IpAddr::V4(value) if value.is_broadcast()) {
            return Err("native-candidate-address-invalid".into());
        }
        if matches!(self.address, IpAddr::V6(value) if value.is_unicast_link_local()) {
            return Err("native-candidate-ipv6-scope-required".into());
        }
        if self.network_identifier.is_empty() || self.network_identifier.len() > 64 {
            return Err("native-candidate-network-identifier-invalid".into());
        }
        if self.foundation.is_empty() || self.foundation.len() > 64 {
            return Err("native-candidate-foundation-invalid".into());
        }
        if self.expires_unix_ms.saturating_add(CANDIDATE_CLOCK_SKEW_MS) < now_unix_ms {
            return Err("native-candidate-expired".into());
        }
        if let Some(related) = self.related_address {
            if related.port() == 0
                || related.ip().is_unspecified()
                || is_multicast(related.ip())
                || NativeAddressFamily::for_ip(related.ip()) != self.address_family
            {
                return Err("native-candidate-related-address-invalid".into());
            }
        }
        if self.candidate_id != self.computed_id() {
            return Err("native-candidate-id-mismatch".into());
        }
        Ok(())
    }

    pub fn canonical_bytes_without_id(&self) -> Vec<u8> {
        let mut value = Vec::with_capacity(192);
        value.extend_from_slice(&self.version.to_be_bytes());
        value.push(candidate_type_code(self.candidate_type));
        value.push(1); // UDP
        write_ip(&mut value, self.address);
        value.extend_from_slice(&self.port.to_be_bytes());
        value.push(match self.address_family {
            NativeAddressFamily::Ipv4 => 4,
            NativeAddressFamily::Ipv6 => 6,
        });
        write_bounded_string(&mut value, &self.network_identifier);
        value.extend_from_slice(&self.priority.to_be_bytes());
        write_bounded_string(&mut value, &self.foundation);
        match self.related_address {
            Some(related) => {
                value.push(1);
                write_ip(&mut value, related.ip());
                value.extend_from_slice(&related.port().to_be_bytes());
            }
            None => value.push(0),
        }
        value.extend_from_slice(&self.generation.to_be_bytes());
        value.extend_from_slice(&self.expires_unix_ms.to_be_bytes());
        value
    }

    fn computed_id(&self) -> String {
        let digest = Sha256::digest(self.canonical_bytes_without_id());
        hex(&digest[..16])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManualCandidateInput {
    pub address: IpAddr,
    pub port: u16,
    pub priority: Option<u32>,
}

impl ManualCandidateInput {
    pub fn into_candidate(
        self,
        generation: u32,
        expires_unix_ms: u64,
        allow_loopback: bool,
    ) -> Result<NativeCandidate, String> {
        let family = NativeAddressFamily::for_ip(self.address);
        let network_identifier = "manual".to_string();
        let candidate = NativeCandidate::new(
            NativeCandidateType::Manual,
            self.address,
            self.port,
            network_identifier.clone(),
            self.priority.unwrap_or(10_000),
            foundation(NativeCandidateType::Manual, &network_identifier, family),
            None,
            generation,
            expires_unix_ms,
        )?;
        candidate.validate(allow_loopback, expires_unix_ms.saturating_sub(1))?;
        Ok(candidate)
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceCandidateDiagnostic {
    pub interface_name: String,
    pub interface_identifier: String,
    pub interface_type: String,
    pub local_ip: Option<IpAddr>,
    pub address_family: Option<NativeAddressFamily>,
    pub accepted: bool,
    pub rejection_reason: Option<String>,
    pub is_up: bool,
    pub is_running: bool,
    pub is_physical: bool,
    pub is_vpn_like: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct HostGatherOptions {
    pub allow_vpn: bool,
    pub allow_virtual: bool,
    pub allow_loopback_test: bool,
    pub generation: u32,
    pub expires_unix_ms: u64,
    pub ipv4_port: Option<u16>,
    pub ipv6_port: Option<u16>,
}

#[derive(Debug, Default)]
pub struct HostGatherResult {
    pub candidates: Vec<NativeCandidate>,
    pub diagnostics: Vec<InterfaceCandidateDiagnostic>,
}

pub fn gather_host_candidates(options: HostGatherOptions) -> HostGatherResult {
    let mut result = HostGatherResult::default();
    let mut seen = BTreeSet::new();
    for interface in netdev::interface::get_interfaces() {
        let identifier = format!("if-{}", interface.index);
        let interface_type = format!("{:?}", interface.if_type).to_ascii_lowercase();
        let vpn_like = interface.is_tun()
            || matches!(
                interface.if_type,
                netdev::interface::types::InterfaceType::Tunnel
                    | netdev::interface::types::InterfaceType::Ppp
                    | netdev::interface::types::InterfaceType::ProprietaryVirtual
            )
            || contains_vpn_hint(&interface.name)
            || interface
                .friendly_name
                .as_deref()
                .is_some_and(contains_vpn_hint);
        let virtual_like = !interface.is_physical()
            || matches!(
                interface.if_type,
                netdev::interface::types::InterfaceType::Bridge
                    | netdev::interface::types::InterfaceType::PeerToPeerWireless
                    | netdev::interface::types::InterfaceType::ProprietaryVirtual
            );
        let mut addresses = Vec::new();
        addresses.extend(interface.ipv4_addrs().into_iter().map(IpAddr::V4));
        addresses.extend(interface.ipv6_addrs().into_iter().map(IpAddr::V6));
        if addresses.is_empty() {
            result.diagnostics.push(InterfaceCandidateDiagnostic {
                interface_name: interface
                    .friendly_name
                    .clone()
                    .unwrap_or_else(|| interface.name.clone()),
                interface_identifier: identifier,
                interface_type,
                local_ip: None,
                address_family: None,
                accepted: false,
                rejection_reason: Some("interface-has-no-address".into()),
                is_up: interface.is_up(),
                is_running: interface.is_running(),
                is_physical: interface.is_physical(),
                is_vpn_like: vpn_like,
            });
            continue;
        }
        for address in addresses {
            let family = NativeAddressFamily::for_ip(address);
            let rejection = if !interface.is_up() || !interface.is_running() {
                Some("interface-disconnected")
            } else if (interface.is_loopback() || address.is_loopback())
                && !options.allow_loopback_test
            {
                Some("loopback-filtered")
            } else if address.is_unspecified() || is_multicast(address) {
                Some("address-invalid")
            } else if matches!(address, IpAddr::V6(value) if value.is_unicast_link_local()) {
                Some("ipv6-link-local-scope-not-supported")
            } else if vpn_like && !options.allow_vpn {
                Some("vpn-interface-disabled")
            } else if virtual_like && !vpn_like && !options.allow_virtual {
                Some("virtual-interface-disabled")
            } else if match family {
                NativeAddressFamily::Ipv4 => options.ipv4_port.is_none(),
                NativeAddressFamily::Ipv6 => options.ipv6_port.is_none(),
            } {
                Some("address-family-socket-unavailable")
            } else if !seen.insert(address) {
                Some("duplicate-address")
            } else {
                None
            };
            let accepted = rejection.is_none();
            result.diagnostics.push(InterfaceCandidateDiagnostic {
                interface_name: interface
                    .friendly_name
                    .clone()
                    .unwrap_or_else(|| interface.name.clone()),
                interface_identifier: identifier.clone(),
                interface_type: interface_type.clone(),
                local_ip: Some(address),
                address_family: Some(family),
                accepted,
                rejection_reason: rejection.map(str::to_string),
                is_up: interface.is_up(),
                is_running: interface.is_running(),
                is_physical: interface.is_physical(),
                is_vpn_like: vpn_like,
            });
            if !accepted {
                continue;
            }
            let port = match family {
                NativeAddressFamily::Ipv4 => options.ipv4_port.unwrap_or_default(),
                NativeAddressFamily::Ipv6 => options.ipv6_port.unwrap_or_default(),
            };
            let candidate_type = if family == NativeAddressFamily::Ipv6 {
                NativeCandidateType::Ipv6
            } else {
                NativeCandidateType::Host
            };
            if let Ok(candidate) = NativeCandidate::new(
                candidate_type,
                address,
                port,
                identifier.clone(),
                candidate_priority(candidate_type, interface.is_physical(), vpn_like),
                foundation(candidate_type, &identifier, family),
                None,
                options.generation,
                options.expires_unix_ms,
            ) {
                result.candidates.push(candidate);
            }
        }
    }
    result.candidates.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left.candidate_id.cmp(&right.candidate_id))
    });
    result.candidates.truncate(MAX_NATIVE_CANDIDATES);
    result
}

pub fn validate_candidate_batch(
    candidates: &[NativeCandidate],
    allow_loopback: bool,
    now_unix_ms: u64,
) -> Result<(), String> {
    if candidates.len() > MAX_NATIVE_CANDIDATES {
        return Err("native-candidate-set-oversized".into());
    }
    let mut ids = BTreeSet::new();
    let mut endpoints = BTreeSet::new();
    for candidate in candidates {
        candidate.validate(allow_loopback, now_unix_ms)?;
        if !ids.insert(candidate.candidate_id.clone())
            || !endpoints.insert((candidate.candidate_type, candidate.address, candidate.port))
        {
            return Err("native-candidate-duplicate".into());
        }
    }
    Ok(())
}

pub fn apply_privacy_policy(
    candidates: Vec<NativeCandidate>,
    policy: CandidatePrivacyPolicy,
    expected_same_lan: bool,
    all_direct_approved: bool,
) -> Result<Vec<NativeCandidate>, String> {
    if policy == CandidatePrivacyPolicy::AllDirect && !all_direct_approved {
        return Err("native-private-candidate-approval-required".into());
    }
    let filtered = candidates
        .into_iter()
        .filter(|candidate| match policy {
            CandidatePrivacyPolicy::Manual => {
                candidate.candidate_type == NativeCandidateType::Manual
            }
            CandidatePrivacyPolicy::PublicOnly => is_public_candidate(candidate),
            CandidatePrivacyPolicy::AllDirect => true,
            CandidatePrivacyPolicy::LanFirst => {
                is_public_candidate(candidate)
                    || (expected_same_lan
                        && matches!(
                            candidate.candidate_type,
                            NativeCandidateType::Host | NativeCandidateType::Ipv6
                        ))
            }
        })
        .collect();
    Ok(filtered)
}

pub fn candidate_payload_digest(candidates: &[NativeCandidate]) -> [u8; 32] {
    let mut canonical = candidates.to_vec();
    canonical.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));
    let mut digest = Sha256::new();
    digest.update((canonical.len() as u16).to_be_bytes());
    for candidate in canonical {
        let bytes = candidate.canonical_bytes_without_id();
        digest.update((candidate.candidate_id.len() as u16).to_be_bytes());
        digest.update(candidate.candidate_id.as_bytes());
        digest.update((bytes.len() as u32).to_be_bytes());
        digest.update(bytes);
    }
    digest.finalize().into()
}

pub fn is_private_or_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => {
            value.is_private()
                || value.is_link_local()
                || value.is_loopback()
                || is_shared_ipv4(value)
        }
        IpAddr::V6(value) => {
            value.is_loopback() || value.is_unicast_link_local() || is_unique_local_ipv6(value)
        }
    }
}

fn is_public_candidate(candidate: &NativeCandidate) -> bool {
    matches!(
        candidate.candidate_type,
        NativeCandidateType::ServerReflexive
            | NativeCandidateType::Mapped
            | NativeCandidateType::Manual
    ) || (candidate.candidate_type == NativeCandidateType::Ipv6
        && !is_private_or_local(candidate.address))
}

fn candidate_priority(candidate_type: NativeCandidateType, physical: bool, vpn_like: bool) -> u32 {
    let type_weight = match candidate_type {
        NativeCandidateType::Host => 500,
        NativeCandidateType::Ipv6 => 450,
        NativeCandidateType::Mapped => 350,
        NativeCandidateType::ServerReflexive => 300,
        NativeCandidateType::Manual => 100,
    };
    type_weight * 1000 + u32::from(physical) * 100 + u32::from(!vpn_like) * 10
}

pub fn foundation(
    candidate_type: NativeCandidateType,
    network_identifier: &str,
    family: NativeAddressFamily,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update([candidate_type_code(candidate_type)]);
    hasher.update(network_identifier.as_bytes());
    hasher.update([match family {
        NativeAddressFamily::Ipv4 => 4,
        NativeAddressFamily::Ipv6 => 6,
    }]);
    hex(&hasher.finalize()[..8])
}

fn candidate_type_code(value: NativeCandidateType) -> u8 {
    match value {
        NativeCandidateType::Host => 1,
        NativeCandidateType::ServerReflexive => 2,
        NativeCandidateType::Mapped => 3,
        NativeCandidateType::Ipv6 => 4,
        NativeCandidateType::Manual => 5,
    }
}

fn is_multicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => value.is_multicast(),
        IpAddr::V6(value) => value.is_multicast(),
    }
}

fn is_shared_ipv4(value: Ipv4Addr) -> bool {
    let octets = value.octets();
    octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000
}

fn is_unique_local_ipv6(value: Ipv6Addr) -> bool {
    value.octets()[0] & 0xfe == 0xfc
}

fn contains_vpn_hint(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    [
        "vpn",
        "wireguard",
        "openvpn",
        "tailscale",
        "zerotier",
        "hamachi",
        "tunnel",
        "wintun",
        "tap-",
    ]
    .iter()
    .any(|hint| value.contains(hint))
}

fn write_ip(output: &mut Vec<u8>, address: IpAddr) {
    match address {
        IpAddr::V4(value) => {
            output.push(4);
            output.extend_from_slice(&value.octets());
        }
        IpAddr::V6(value) => {
            output.push(6);
            output.extend_from_slice(&value.octets());
        }
    }
}

fn write_bounded_string(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value.as_bytes());
}

pub fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_id_detects_modification() {
        let mut candidate = NativeCandidate::new(
            NativeCandidateType::Host,
            "192.168.1.20".parse().unwrap(),
            44000,
            "if-7".into(),
            500_110,
            "abcd".into(),
            None,
            1,
            u64::MAX - 31_000,
        )
        .unwrap();
        candidate.port += 1;
        assert_eq!(
            candidate.validate(false, 1).unwrap_err(),
            "native-candidate-id-mismatch"
        );
    }

    #[test]
    fn remote_loopback_and_unscoped_link_local_are_rejected() {
        let loopback = ManualCandidateInput {
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 44000,
            priority: None,
        }
        .into_candidate(1, u64::MAX - 31_000, true)
        .unwrap();
        assert_eq!(
            loopback.validate(false, 1).unwrap_err(),
            "native-candidate-loopback-not-permitted"
        );
        assert_eq!(
            ManualCandidateInput {
                address: "fe80::1".parse().unwrap(),
                port: 44000,
                priority: None,
            }
            .into_candidate(1, u64::MAX - 31_000, false)
            .unwrap_err(),
            "native-candidate-ipv6-scope-required"
        );
    }

    #[test]
    fn public_only_hides_private_host_candidates() {
        let host = NativeCandidate::new(
            NativeCandidateType::Host,
            "10.0.0.2".parse().unwrap(),
            42000,
            "if-1".into(),
            1,
            "host".into(),
            None,
            1,
            u64::MAX - 31_000,
        )
        .unwrap();
        let public = NativeCandidate::new(
            NativeCandidateType::ServerReflexive,
            "203.0.113.5".parse().unwrap(),
            42000,
            "stun".into(),
            1,
            "srflx".into(),
            Some("10.0.0.2:42000".parse().unwrap()),
            1,
            u64::MAX - 31_000,
        )
        .unwrap();
        let filtered = apply_privacy_policy(
            vec![host, public.clone()],
            CandidatePrivacyPolicy::PublicOnly,
            false,
            false,
        )
        .unwrap();
        assert_eq!(filtered, vec![public]);
    }

    #[test]
    fn duplicate_candidate_batch_is_rejected() {
        let candidate = NativeCandidate::new(
            NativeCandidateType::Manual,
            "198.51.100.7".parse().unwrap(),
            42000,
            "manual".into(),
            1,
            "manual".into(),
            None,
            1,
            u64::MAX - 31_000,
        )
        .unwrap();
        assert_eq!(
            validate_candidate_batch(&[candidate.clone(), candidate], false, 1).unwrap_err(),
            "native-candidate-duplicate"
        );
    }
}
