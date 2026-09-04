use super::candidates::{foundation, NativeAddressFamily, NativeCandidate, NativeCandidateType};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

const STUN_HEADER_BYTES: usize = 20;
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_SUCCESS: u16 = 0x0101;
const STUN_BINDING_ERROR: u16 = 0x0111;
const STUN_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const MAX_STUN_PACKET_BYTES: usize = 1500;
const MAX_STUN_ATTRIBUTES: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StunServerConfig {
    pub host: String,
    pub port: u16,
}

impl StunServerConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.host.trim().is_empty() || self.host.len() > 253 || self.port == 0 {
            return Err("native-stun-server-invalid".into());
        }
        Ok(())
    }
}

pub fn default_development_stun_servers() -> Vec<StunServerConfig> {
    vec![
        StunServerConfig {
            host: "stun.l.google.com".into(),
            port: 19302,
        },
        StunServerConfig {
            host: "stun.cloudflare.com".into(),
            port: 3478,
        },
    ]
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ObservedNatMappingBehavior {
    LikelyEndpointIndependent,
    LikelyAddressDependent,
    LikelyAddressAndPortDependent,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StunObservation {
    pub local_udp_endpoint: SocketAddr,
    pub stun_server: String,
    pub resolved_server: Option<SocketAddr>,
    pub discovered_public_endpoint: Option<SocketAddr>,
    pub round_trip_ms: Option<f64>,
    pub attempts: u8,
    pub transaction_matched: bool,
    pub source_endpoint_matched: bool,
    pub port_preserved: Option<bool>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StunDiscoveryReport {
    pub observations: Vec<StunObservation>,
    pub mapping_behavior: ObservedNatMappingBehavior,
    pub mapping_consistent: Option<bool>,
    pub udp_blocked_or_heavily_filtered: bool,
    pub candidates: Vec<NativeCandidate>,
}

#[derive(Debug, Clone, Copy)]
pub struct StunQueryPolicy {
    pub attempts_per_server: u8,
    pub request_timeout: Duration,
    pub generation: u32,
    pub expires_unix_ms: u64,
}

impl Default for StunQueryPolicy {
    fn default() -> Self {
        Self {
            attempts_per_server: 2,
            request_timeout: Duration::from_millis(1500),
            generation: 1,
            expires_unix_ms: u64::MAX - 31_000,
        }
    }
}

pub async fn discover_server_reflexive_candidates(
    socket: &std::net::UdpSocket,
    family: NativeAddressFamily,
    related_endpoint: Option<SocketAddr>,
    servers: &[StunServerConfig],
    policy: StunQueryPolicy,
    cancellation: &CancellationToken,
) -> Result<StunDiscoveryReport, String> {
    if servers.len() > 8 {
        return Err("native-stun-server-set-oversized".into());
    }
    let local_endpoint = socket.local_addr().map_err(|_| "native-udp-bind-failed")?;
    if NativeAddressFamily::for_ip(local_endpoint.ip()) != family {
        return Err("native-stun-socket-family-mismatch".into());
    }
    let mut report = StunDiscoveryReport::default();
    for server in servers {
        server.validate()?;
        if cancellation.is_cancelled() {
            return Err("native-connectivity-cancelled".into());
        }
        let label = format!("{}:{}", server.host, server.port);
        let resolved = resolve_server(server, family).await;
        let server_endpoint = match resolved {
            Ok(value) => value,
            Err(error) => {
                report.observations.push(StunObservation {
                    local_udp_endpoint: local_endpoint,
                    stun_server: label,
                    resolved_server: None,
                    discovered_public_endpoint: None,
                    round_trip_ms: None,
                    attempts: 0,
                    transaction_matched: false,
                    source_endpoint_matched: false,
                    port_preserved: None,
                    error: Some(error),
                });
                continue;
            }
        };
        let mut observation = StunObservation {
            local_udp_endpoint: local_endpoint,
            stun_server: label,
            resolved_server: Some(server_endpoint),
            discovered_public_endpoint: None,
            round_trip_ms: None,
            attempts: 0,
            transaction_matched: false,
            source_endpoint_matched: false,
            port_preserved: None,
            error: None,
        };
        for attempt in 1..=policy.attempts_per_server.clamp(1, 4) {
            observation.attempts = attempt;
            match query_once(
                socket,
                server_endpoint,
                policy.request_timeout,
                cancellation,
            )
            .await
            {
                Ok(result) => {
                    observation.discovered_public_endpoint = Some(result.mapped_endpoint);
                    observation.round_trip_ms = Some(result.round_trip.as_secs_f64() * 1000.0);
                    observation.transaction_matched = true;
                    observation.source_endpoint_matched = true;
                    observation.port_preserved =
                        Some(result.mapped_endpoint.port() == local_endpoint.port());
                    break;
                }
                Err(error) => observation.error = Some(error),
            }
            if attempt < policy.attempts_per_server {
                let mut jitter = [0u8; 2];
                OsRng.fill_bytes(&mut jitter);
                let delay = 50 + u16::from_be_bytes(jitter) as u64 % 151;
                tokio::select! {
                    _ = cancellation.cancelled() => return Err("native-connectivity-cancelled".into()),
                    _ = tokio::time::sleep(Duration::from_millis(delay)) => {}
                }
            }
        }
        report.observations.push(observation);
    }
    classify_mapping(&mut report);
    let mut seen = BTreeSet::new();
    for observation in &report.observations {
        let Some(public) = observation.discovered_public_endpoint else {
            continue;
        };
        if !seen.insert(public) {
            continue;
        }
        let network_identifier = format!(
            "stun-{}",
            observation
                .resolved_server
                .map(|value| value.ip().to_string())
                .unwrap_or_else(|| "unresolved".into())
        );
        let related = related_endpoint.filter(|value| {
            NativeAddressFamily::for_ip(value.ip()) == family
                && !value.ip().is_unspecified()
                && value.port() != 0
        });
        let candidate = NativeCandidate::new(
            NativeCandidateType::ServerReflexive,
            public.ip(),
            public.port(),
            network_identifier.clone(),
            300_000,
            foundation(
                NativeCandidateType::ServerReflexive,
                &network_identifier,
                family,
            ),
            related,
            policy.generation,
            policy.expires_unix_ms,
        )?;
        report.candidates.push(candidate);
    }
    Ok(report)
}

#[derive(Debug)]
struct StunQueryResult {
    mapped_endpoint: SocketAddr,
    round_trip: Duration,
}

async fn query_once(
    socket: &std::net::UdpSocket,
    server: SocketAddr,
    timeout: Duration,
    cancellation: &CancellationToken,
) -> Result<StunQueryResult, String> {
    let mut transaction_id = [0u8; 12];
    OsRng.fill_bytes(&mut transaction_id);
    let request = binding_request(transaction_id);
    let clone = socket
        .try_clone()
        .map_err(|_| "native-stun-socket-clone-failed")?;
    clone
        .set_nonblocking(true)
        .map_err(|_| "native-stun-socket-nonblocking-failed")?;
    let socket =
        tokio::net::UdpSocket::from_std(clone).map_err(|_| "native-stun-socket-runtime-failed")?;
    socket
        .send_to(&request, server)
        .await
        .map_err(|_| "native-stun-send-failed")?;
    let started = Instant::now();
    let deadline = tokio::time::Instant::now()
        + timeout.clamp(Duration::from_millis(250), Duration::from_secs(5));
    let mut packet = [0u8; MAX_STUN_PACKET_BYTES];
    let receive = async {
        loop {
            let (length, source) = socket
                .recv_from(&mut packet)
                .await
                .map_err(|_| "native-stun-receive-failed")?;
            if source != server {
                continue;
            }
            match parse_binding_response(&packet[..length], transaction_id) {
                Ok(mapped_endpoint) => return Ok(mapped_endpoint),
                Err(error) if error == "native-stun-transaction-mismatch" => continue,
                Err(error) => return Err(error),
            }
        }
    };
    tokio::select! {
        _ = cancellation.cancelled() => Err("native-connectivity-cancelled".into()),
        result = tokio::time::timeout_at(deadline, receive) => {
            match result {
                Ok(Ok(mapped_endpoint)) => Ok(StunQueryResult { mapped_endpoint, round_trip: started.elapsed() }),
                Ok(Err(error)) => Err(error),
                Err(_) => Err("native-stun-timeout".into()),
            }
        }
    }
}

fn binding_request(transaction_id: [u8; 12]) -> [u8; STUN_HEADER_BYTES] {
    let mut packet = [0u8; STUN_HEADER_BYTES];
    packet[..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    packet[2..4].copy_from_slice(&0u16.to_be_bytes());
    packet[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    packet[8..20].copy_from_slice(&transaction_id);
    packet
}

fn parse_binding_response(
    packet: &[u8],
    expected_transaction_id: [u8; 12],
) -> Result<SocketAddr, String> {
    if packet.len() < STUN_HEADER_BYTES || packet.len() > MAX_STUN_PACKET_BYTES {
        return Err("native-stun-packet-length-invalid".into());
    }
    let message_type = u16::from_be_bytes([packet[0], packet[1]]);
    let body_length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if (body_length & 3) != 0 || STUN_HEADER_BYTES + body_length != packet.len() {
        return Err("native-stun-packet-length-invalid".into());
    }
    if u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]) != STUN_MAGIC_COOKIE {
        return Err("native-stun-cookie-invalid".into());
    }
    if packet[8..20] != expected_transaction_id {
        return Err("native-stun-transaction-mismatch".into());
    }
    if message_type == STUN_BINDING_ERROR {
        return Err("native-stun-error-response".into());
    }
    if message_type != STUN_BINDING_SUCCESS {
        return Err("native-stun-message-type-invalid".into());
    }
    let mut offset = STUN_HEADER_BYTES;
    let mut attributes = 0usize;
    let mut mapped = None;
    while offset < packet.len() {
        attributes += 1;
        if attributes > MAX_STUN_ATTRIBUTES || offset + 4 > packet.len() {
            return Err("native-stun-attribute-set-invalid".into());
        }
        let attribute_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let length = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) as usize;
        offset += 4;
        if offset + length > packet.len() {
            return Err("native-stun-attribute-length-invalid".into());
        }
        if attribute_type == STUN_XOR_MAPPED_ADDRESS {
            mapped = Some(parse_xor_mapped(
                &packet[offset..offset + length],
                expected_transaction_id,
            )?);
        }
        let padded = (length + 3) & !3;
        if offset + padded > packet.len() {
            return Err("native-stun-attribute-padding-invalid".into());
        }
        offset += padded;
    }
    mapped.ok_or_else(|| "native-stun-xor-mapped-address-missing".into())
}

fn parse_xor_mapped(value: &[u8], transaction_id: [u8; 12]) -> Result<SocketAddr, String> {
    if value.len() < 4 || value[0] != 0 {
        return Err("native-stun-xor-mapped-address-invalid".into());
    }
    let port = u16::from_be_bytes([value[2], value[3]]) ^ (STUN_MAGIC_COOKIE >> 16) as u16;
    if port == 0 {
        return Err("native-stun-xor-mapped-address-invalid".into());
    }
    match value[1] {
        0x01 if value.len() == 8 => {
            let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
            let mut address = [0u8; 4];
            for index in 0..4 {
                address[index] = value[4 + index] ^ cookie[index];
            }
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(address)), port))
        }
        0x02 if value.len() == 20 => {
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(&transaction_id);
            let mut address = [0u8; 16];
            for index in 0..16 {
                address[index] = value[4 + index] ^ mask[index];
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(address)), port))
        }
        _ => Err("native-stun-xor-mapped-address-invalid".into()),
    }
}

async fn resolve_server(
    server: &StunServerConfig,
    family: NativeAddressFamily,
) -> Result<SocketAddr, String> {
    let addresses = tokio::net::lookup_host((server.host.as_str(), server.port))
        .await
        .map_err(|_| "native-stun-dns-failed")?;
    addresses
        .into_iter()
        .find(|address| NativeAddressFamily::for_ip(address.ip()) == family)
        .ok_or_else(|| "native-stun-address-family-unavailable".into())
}

fn classify_mapping(report: &mut StunDiscoveryReport) {
    let successes: Vec<_> = report
        .observations
        .iter()
        .filter_map(|value| Some((value.resolved_server?, value.discovered_public_endpoint?)))
        .collect();
    report.udp_blocked_or_heavily_filtered = report
        .observations
        .iter()
        .all(|value| value.discovered_public_endpoint.is_none())
        && report
            .observations
            .iter()
            .any(|value| value.error.as_deref() == Some("native-stun-timeout"));
    if successes.len() < 2 {
        report.mapping_behavior = ObservedNatMappingBehavior::Unknown;
        report.mapping_consistent = None;
        return;
    }
    let first = successes[0].1;
    let all_same = successes.iter().all(|(_, mapped)| *mapped == first);
    report.mapping_consistent = Some(all_same);
    if all_same {
        report.mapping_behavior = ObservedNatMappingBehavior::LikelyEndpointIndependent;
        return;
    }
    let same_public_ip = successes
        .iter()
        .all(|(_, mapped)| mapped.ip() == first.ip());
    let same_destination_ip = successes
        .iter()
        .all(|(destination, _)| destination.ip() == successes[0].0.ip());
    report.mapping_behavior = if same_public_ip && same_destination_ip {
        ObservedNatMappingBehavior::LikelyAddressAndPortDependent
    } else if same_public_ip {
        ObservedNatMappingBehavior::LikelyAddressDependent
    } else {
        ObservedNatMappingBehavior::Unknown
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(
        transaction: [u8; 12],
        mapped: SocketAddr,
        extra_unknown_attribute: bool,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        if extra_unknown_attribute {
            body.extend_from_slice(&0x8022u16.to_be_bytes());
            body.extend_from_slice(&3u16.to_be_bytes());
            body.extend_from_slice(b"abc");
            body.push(0);
        }
        let mut xor = Vec::new();
        xor.push(0);
        match mapped {
            SocketAddr::V4(value) => {
                xor.push(1);
                xor.extend_from_slice(
                    &(value.port() ^ (STUN_MAGIC_COOKIE >> 16) as u16).to_be_bytes(),
                );
                let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
                for (index, byte) in value.ip().octets().iter().enumerate() {
                    xor.push(byte ^ cookie[index]);
                }
            }
            SocketAddr::V6(value) => {
                xor.push(2);
                xor.extend_from_slice(
                    &(value.port() ^ (STUN_MAGIC_COOKIE >> 16) as u16).to_be_bytes(),
                );
                let mut mask = [0u8; 16];
                mask[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
                mask[4..].copy_from_slice(&transaction);
                for (index, byte) in value.ip().octets().iter().enumerate() {
                    xor.push(byte ^ mask[index]);
                }
            }
        }
        body.extend_from_slice(&STUN_XOR_MAPPED_ADDRESS.to_be_bytes());
        body.extend_from_slice(&(xor.len() as u16).to_be_bytes());
        body.extend_from_slice(&xor);
        while body.len() % 4 != 0 {
            body.push(0);
        }
        let mut packet = Vec::new();
        packet.extend_from_slice(&STUN_BINDING_SUCCESS.to_be_bytes());
        packet.extend_from_slice(&(body.len() as u16).to_be_bytes());
        packet.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        packet.extend_from_slice(&transaction);
        packet.extend_from_slice(&body);
        packet
    }

    #[test]
    fn parses_ipv4_and_tolerates_unknown_attributes() {
        let transaction = [7; 12];
        let expected: SocketAddr = "203.0.113.4:54321".parse().unwrap();
        assert_eq!(
            parse_binding_response(&response(transaction, expected, true), transaction).unwrap(),
            expected
        );
    }

    #[test]
    fn parses_ipv6_xor_mapped_address() {
        let transaction = [9; 12];
        let expected: SocketAddr = "[2001:db8::1234]:40000".parse().unwrap();
        assert_eq!(
            parse_binding_response(&response(transaction, expected, false), transaction).unwrap(),
            expected
        );
    }

    #[test]
    fn rejects_forged_transaction_and_bad_lengths() {
        let transaction = [1; 12];
        let expected: SocketAddr = "198.51.100.8:42000".parse().unwrap();
        assert_eq!(
            parse_binding_response(&response(transaction, expected, false), [2; 12]).unwrap_err(),
            "native-stun-transaction-mismatch"
        );
        let mut malformed = response(transaction, expected, false);
        malformed[3] = malformed[3].saturating_add(4);
        assert_eq!(
            parse_binding_response(&malformed, transaction).unwrap_err(),
            "native-stun-packet-length-invalid"
        );
    }

    #[tokio::test]
    async fn unexpected_source_cannot_supply_binding_response() {
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        client.set_nonblocking(true).unwrap();
        let expected_server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let attacker = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_address = client.local_addr().unwrap();
        let server_address = expected_server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut request = [0u8; 20];
            let (length, source) = expected_server.recv_from(&mut request).await.unwrap();
            let transaction: [u8; 12] = request[8..20].try_into().unwrap();
            let packet = response(transaction, "198.51.100.9:50000".parse().unwrap(), false);
            attacker.send_to(&packet, source).await.unwrap();
            assert_eq!(length, 20);
        });
        let result = query_once(
            &client,
            server_address,
            Duration::from_millis(100),
            &CancellationToken::new(),
        )
        .await;
        task.await.unwrap();
        assert_eq!(client_address, client.local_addr().unwrap());
        assert_eq!(result.unwrap_err(), "native-stun-timeout");
    }
}
