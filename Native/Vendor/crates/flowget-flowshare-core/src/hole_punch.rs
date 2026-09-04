use super::{
    path_selection::NativeCandidatePair,
    secure_protocol::now_unix_ms,
    signaling::{ConnectivityAuthenticator, NativeConnectivityFailure, NativeDeviceRole},
};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use sha2_compat::Sha256;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio_util::sync::CancellationToken;

type HmacSha256 = Hmac<Sha256>;

const PROBE_MAGIC: [u8; 8] = *b"FQPRB001";
const PROBE_VERSION: u16 = 1;
const PROBE_PACKET_BYTES: usize = 132;
const MAX_ACTIVE_PAIRS: usize = 16;
const MAX_REPLAY_ENTRIES: usize = 4096;
const MAX_PROBES_PER_SECOND: u32 = 64;

type ProbeReplaySet = BTreeSet<(u8, u8, u64, [u8; 16])>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
enum ProbeKind {
    Request = 1,
    Response = 2,
    Confirm = 3,
    ConfirmAck = 4,
}

impl ProbeKind {
    fn decode(value: u8) -> Result<Self, String> {
        match value {
            1 => Ok(Self::Request),
            2 => Ok(Self::Response),
            3 => Ok(Self::Confirm),
            4 => Ok(Self::ConfirmAck),
            _ => Err("native-probe-kind-invalid".into()),
        }
    }
}

#[derive(Debug, Clone)]
struct ProbePacket {
    kind: ProbeKind,
    role: NativeDeviceRole,
    connectivity_session_id: [u8; 16],
    transfer_id: [u8; 16],
    pair_id: [u8; 16],
    sequence: u64,
    sender_nonce: [u8; 16],
    sent_unix_ms: u64,
    expires_unix_ms: u64,
    tag: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
pub struct HolePunchConfig {
    pub total_timeout: Duration,
    pub initial_interval: Duration,
    pub max_interval: Duration,
    pub resynchronize_interval: Duration,
    pub confirmation_grace: Duration,
    #[cfg(test)]
    pub drop_initial_confirm_acks: u8,
}

impl Default for HolePunchConfig {
    fn default() -> Self {
        Self {
            total_timeout: Duration::from_secs(15),
            initial_interval: Duration::from_millis(250),
            max_interval: Duration::from_millis(1500),
            resynchronize_interval: Duration::from_secs(3),
            confirmation_grace: Duration::from_secs(2),
            #[cfg(test)]
            drop_initial_confirm_acks: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProbePairResult {
    pub pair_id: String,
    pub remote_endpoint: String,
    pub probes_sent: u32,
    pub authenticated_requests_received: u32,
    pub authenticated_responses_received: u32,
    pub replayed_packets_rejected: u32,
    pub malformed_or_unauthenticated_packets: u32,
    pub source_endpoint_stable: bool,
    pub observed_source_endpoint: Option<String>,
    pub best_rtt_ms: Option<f64>,
    pub confirmation_count: u8,
    pub viable: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HolePunchReport {
    pub started_unix_ms: u64,
    pub elapsed_ms: f64,
    pub total_packets_sent: u32,
    pub total_packets_received: u32,
    pub authenticated_packets_received: u32,
    pub unauthenticated_packets_dropped: u32,
    pub replayed_packets_dropped: u32,
    pub rate_limit_packets_per_second: u32,
    pub pair_results: Vec<ProbePairResult>,
    pub selected_pair_id: Option<String>,
    pub failure: Option<NativeConnectivityFailure>,
}

#[derive(Debug)]
struct PairState {
    pair: NativeCandidatePair,
    probes_sent: u32,
    inbound_requests: u32,
    outbound_responses: u32,
    replayed: u32,
    invalid: u32,
    observed_source: Option<SocketAddr>,
    observed_source_count: u8,
    source_stable: bool,
    best_rtt: Option<Duration>,
    remote_confirm: bool,
    confirm_ack: bool,
    last_confirm_sent: Option<Instant>,
}

impl PairState {
    fn base_bidirectional(&self) -> bool {
        self.outbound_responses >= 2 && self.inbound_requests >= 1 && self.source_stable
    }

    fn viable(&self) -> bool {
        // Both directions must finish the confirmation exchange. Treating
        // either a peer Confirm or our ConfirmAck as sufficient lets one side
        // stop servicing probes before the other side becomes viable.
        self.base_bidirectional() && self.remote_confirm && self.confirm_ack
    }

    fn confirmation_count(&self) -> u8 {
        (u8::from(self.outbound_responses >= 2)
            + u8::from(self.inbound_requests >= 1)
            + u8::from(self.remote_confirm)
            + u8::from(self.confirm_ack))
        .min(4)
    }
}

pub async fn run_authenticated_hole_punch(
    socket: std::net::UdpSocket,
    pairs: Vec<NativeCandidatePair>,
    role: NativeDeviceRole,
    authenticator: ConnectivityAuthenticator,
    config: HolePunchConfig,
    cancellation: CancellationToken,
) -> Result<HolePunchReport, String> {
    if pairs.is_empty() {
        return Err("native-connectivity-no-candidate-pairs".into());
    }
    let family = pairs[0].address_family;
    if pairs.iter().any(|pair| pair.address_family != family) {
        return Err("native-connectivity-mixed-family-check-invalid".into());
    }
    socket
        .set_nonblocking(true)
        .map_err(|_| "native-probe-socket-nonblocking-failed")?;
    let socket = Arc::new(
        tokio::net::UdpSocket::from_std(socket)
            .map_err(|_| "native-probe-socket-runtime-failed")?,
    );
    let key = authenticator.probe_key();
    let connectivity_session_id = authenticator.connectivity_session_id();
    let transfer_id = authenticator.transfer_id();
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let timeout = config
        .total_timeout
        .clamp(Duration::from_secs(1), Duration::from_secs(30));
    let initial_interval = config
        .initial_interval
        .clamp(Duration::from_millis(100), Duration::from_secs(1));
    let max_interval = config
        .max_interval
        .clamp(initial_interval, Duration::from_secs(3));
    let resynchronize_interval = config
        .resynchronize_interval
        .clamp(Duration::from_millis(500), Duration::from_secs(5));
    let confirmation_grace = config
        .confirmation_grace
        .clamp(Duration::from_millis(500), Duration::from_secs(5));
    let started_unix_ms = now_unix_ms();
    let started = Instant::now();
    let search_deadline = tokio::time::Instant::now() + timeout;
    let mut confirmation_deadline: Option<tokio::time::Instant> = None;
    #[cfg(test)]
    let mut confirm_acks_to_drop = config.drop_initial_confirm_acks;
    let mut sequence = 0u64;
    let mut states: BTreeMap<String, PairState> = pairs
        .into_iter()
        .take(MAX_ACTIVE_PAIRS)
        .map(|pair| {
            (
                pair.pair_id.clone(),
                PairState {
                    pair,
                    probes_sent: 0,
                    inbound_requests: 0,
                    outbound_responses: 0,
                    replayed: 0,
                    invalid: 0,
                    observed_source: None,
                    observed_source_count: 0,
                    source_stable: false,
                    best_rtt: None,
                    remote_confirm: false,
                    confirm_ack: false,
                    last_confirm_sent: None,
                },
            )
        })
        .collect();
    let pair_lookup: HashMap<[u8; 16], String> = states
        .keys()
        .map(|id| Ok((decode_pair_id(id)?, id.clone())))
        .collect::<Result<_, String>>()?;
    let mut sent: HashMap<(String, u64, ProbeKind), Instant> = HashMap::new();
    let mut replay = ProbeReplaySet::new();
    let mut next_round = tokio::time::Instant::now();
    let mut next_resynchronization = next_round + resynchronize_interval;
    let mut interval = initial_interval;
    let mut packets_this_window = 0u32;
    let mut rate_window = Instant::now();
    let mut total_sent = 0u32;
    let mut total_received = 0u32;
    let mut authenticated_received = 0u32;
    let mut invalid_received = 0u32;
    let mut replayed_received = 0u32;
    let mut receive_buffer = [0u8; PROBE_PACKET_BYTES + 1];

    loop {
        let now = tokio::time::Instant::now();
        if states.values().any(PairState::viable) {
            let linger_until =
                *confirmation_deadline.get_or_insert_with(|| now + confirmation_grace);
            if now >= linger_until {
                break;
            }
        } else if now >= search_deadline {
            break;
        }
        let phase_deadline = confirmation_deadline.unwrap_or(search_deadline);
        tokio::select! {
            _ = cancellation.cancelled() => return Err("native-connectivity-cancelled".into()),
            _ = tokio::time::sleep_until(next_round) => {
                let round_started = tokio::time::Instant::now();
                if round_started >= next_resynchronization
                    && !states.values().any(PairState::base_bidirectional)
                {
                    // Re-arm the fast probe cadence periodically. Peers do not
                    // enter checking at exactly the same instant after the
                    // WebSocket answer exchange, and permanently backing off
                    // makes two late schedules less likely to overlap.
                    interval = initial_interval;
                    next_resynchronization = round_started + resynchronize_interval;
                }
                if rate_window.elapsed() >= Duration::from_secs(1) {
                    rate_window = Instant::now();
                    packets_this_window = 0;
                }
                for state in states.values_mut() {
                    if packets_this_window >= MAX_PROBES_PER_SECOND {
                        break;
                    }
                    let kind = if state.base_bidirectional() {
                        if state.last_confirm_sent.is_some_and(|last| last.elapsed() < interval) {
                            continue;
                        }
                        state.last_confirm_sent = Some(Instant::now());
                        ProbeKind::Confirm
                    } else {
                        ProbeKind::Request
                    };
                    sequence = sequence.checked_add(1).ok_or("native-probe-sequence-exhausted")?;
                    let packet = ProbePacket::new(
                        kind,
                        role,
                        connectivity_session_id,
                        transfer_id,
                        decode_pair_id(&state.pair.pair_id)?,
                        sequence,
                        nonce,
                        now_unix_ms().saturating_add(timeout.as_millis() as u64).saturating_add(5_000),
                        &key,
                    )?;
                    let encoded = packet.encode();
                    let destination = state
                        .observed_source
                        .unwrap_or_else(|| state.pair.remote_candidate.socket_addr());
                    if socket.send_to(&encoded, destination).await.is_ok() {
                        state.probes_sent += 1;
                        total_sent += 1;
                        packets_this_window += 1;
                        sent.insert((state.pair.pair_id.clone(), sequence, kind), Instant::now());
                    }
                }
                let mut jitter = [0u8; 2];
                OsRng.fill_bytes(&mut jitter);
                let jitter = Duration::from_millis(u16::from_be_bytes(jitter) as u64 % 101);
                next_round = tokio::time::Instant::now() + interval + jitter;
                interval = (interval * 2).min(max_interval);
            }
            receive = socket.recv_from(&mut receive_buffer) => {
                let (length, source) = match receive {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                total_received += 1;
                if length != PROBE_PACKET_BYTES {
                    invalid_received += 1;
                    continue;
                }
                let packet = match ProbePacket::decode(&receive_buffer[..length], &key) {
                    Ok(packet) => packet,
                    Err(_) => {
                        invalid_received += 1;
                        continue;
                    }
                };
                if packet.connectivity_session_id != connectivity_session_id
                    || packet.transfer_id != transfer_id
                    || packet.role != role.opposite()
                    || packet.expires_unix_ms.saturating_add(30_000) < now_unix_ms()
                    || packet.sent_unix_ms > now_unix_ms().saturating_add(30_000)
                {
                    invalid_received += 1;
                    continue;
                }
                let Some(pair_id) = pair_lookup.get(&packet.pair_id).cloned() else {
                    invalid_received += 1;
                    continue;
                };
                let Some(state) = states.get_mut(&pair_id) else {
                    invalid_received += 1;
                    continue;
                };
                if !accept_probe_once(&mut replay, &packet) {
                    state.replayed += 1;
                    replayed_received += 1;
                    continue;
                }
                if !observe_authenticated_source(state, source) {
                    state.invalid += 1;
                    invalid_received += 1;
                    continue;
                }
                authenticated_received += 1;
                match packet.kind {
                    ProbeKind::Request | ProbeKind::Confirm => {
                        if packet.kind == ProbeKind::Request {
                            state.inbound_requests += 1;
                        } else {
                            state.remote_confirm = true;
                        }
                        let response_kind = if packet.kind == ProbeKind::Request {
                            ProbeKind::Response
                        } else {
                            ProbeKind::ConfirmAck
                        };
                        let response = ProbePacket::new(
                            response_kind,
                            role,
                            connectivity_session_id,
                            transfer_id,
                            packet.pair_id,
                            packet.sequence,
                            nonce,
                            now_unix_ms().saturating_add(5_000),
                            &key,
                        )?;
                        #[cfg(test)]
                        if response_kind == ProbeKind::ConfirmAck && confirm_acks_to_drop > 0 {
                            confirm_acks_to_drop -= 1;
                            continue;
                        }
                        // Authenticated requests receive a fixed-size response equal to the request.
                        if socket.send_to(&response.encode(), source).await.is_ok() {
                            total_sent += 1;
                        }
                    }
                    ProbeKind::Response | ProbeKind::ConfirmAck => {
                        let original_kind = if packet.kind == ProbeKind::Response {
                            ProbeKind::Request
                        } else {
                            ProbeKind::Confirm
                        };
                        if let Some(start) = sent.remove(&(pair_id.clone(), packet.sequence, original_kind)) {
                            let rtt = start.elapsed();
                            state.best_rtt = Some(state.best_rtt.map_or(rtt, |best| best.min(rtt)));
                            if packet.kind == ProbeKind::Response {
                                state.outbound_responses += 1;
                            } else {
                                state.confirm_ack = true;
                            }
                        } else {
                            state.invalid += 1;
                            invalid_received += 1;
                        }
                    }
                }
            }
            _ = tokio::time::sleep_until(phase_deadline) => break,
        }
    }

    let selected = states
        .values()
        .filter(|state| state.viable())
        .max_by(|left, right| {
            left.pair
                .priority
                .cmp(&right.pair.priority)
                .then_with(|| right.best_rtt.cmp(&left.best_rtt))
        })
        .map(|state| state.pair.pair_id.clone());
    let failure = if cancellation.is_cancelled() {
        Some(NativeConnectivityFailure::Cancelled)
    } else if selected.is_some() {
        None
    } else if authenticated_received == 0 {
        Some(NativeConnectivityFailure::UdpBlocked)
    } else {
        Some(NativeConnectivityFailure::NoViablePair)
    };
    let pair_results = states
        .values()
        .map(|state| ProbePairResult {
            pair_id: state.pair.pair_id.clone(),
            remote_endpoint: state
                .observed_source
                .unwrap_or_else(|| state.pair.remote_candidate.socket_addr())
                .to_string(),
            probes_sent: state.probes_sent,
            authenticated_requests_received: state.inbound_requests,
            authenticated_responses_received: state.outbound_responses,
            replayed_packets_rejected: state.replayed,
            malformed_or_unauthenticated_packets: state.invalid,
            source_endpoint_stable: state.source_stable,
            observed_source_endpoint: state.observed_source.map(|value| value.to_string()),
            best_rtt_ms: state.best_rtt.map(|value| value.as_secs_f64() * 1000.0),
            confirmation_count: state.confirmation_count(),
            viable: state.viable(),
        })
        .collect();
    Ok(HolePunchReport {
        started_unix_ms,
        elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
        total_packets_sent: total_sent,
        total_packets_received: total_received,
        authenticated_packets_received: authenticated_received,
        unauthenticated_packets_dropped: invalid_received,
        replayed_packets_dropped: replayed_received,
        rate_limit_packets_per_second: MAX_PROBES_PER_SECOND,
        pair_results,
        selected_pair_id: selected,
        failure,
    })
}

/// Record only endpoints carried by an already decoded and HMAC-authenticated
/// probe. A rewritten endpoint must be observed repeatedly before the pair can
/// become viable. If an authenticated peer's endpoint keeps changing, the
/// stability counter continually resets and nomination remains impossible.
fn observe_authenticated_source(state: &mut PairState, source: SocketAddr) -> bool {
    if source.port() == 0
        || source.ip().is_unspecified()
        || source.ip().is_multicast()
        || super::candidates::NativeAddressFamily::for_ip(source.ip()) != state.pair.address_family
    {
        return false;
    }
    match state.observed_source {
        Some(previous) if previous == source => {
            state.observed_source_count = state.observed_source_count.saturating_add(1);
        }
        Some(_) => {
            // Confirmation evidence is endpoint-specific. A NAT rebind must
            // prove the new path from scratch rather than inheriting counters
            // gathered through the previous mapping.
            state.inbound_requests = 0;
            state.outbound_responses = 0;
            state.best_rtt = None;
            state.remote_confirm = false;
            state.confirm_ack = false;
            state.last_confirm_sent = None;
            state.observed_source = Some(source);
            state.observed_source_count = 1;
            state.source_stable = false;
        }
        None => {
            state.observed_source = Some(source);
            state.observed_source_count = 1;
            state.source_stable = false;
        }
    }
    if state.observed_source_count >= 2 {
        state.source_stable = true;
    }
    true
}

fn accept_probe_once(replay: &mut ProbeReplaySet, packet: &ProbePacket) -> bool {
    let accepted = replay.insert((
        packet.role.code(),
        packet.kind as u8,
        packet.sequence,
        packet.sender_nonce,
    ));
    while replay.len() > MAX_REPLAY_ENTRIES {
        replay.pop_first();
    }
    accepted
}

impl ProbePacket {
    #[allow(clippy::too_many_arguments)]
    fn new(
        kind: ProbeKind,
        role: NativeDeviceRole,
        connectivity_session_id: [u8; 16],
        transfer_id: [u8; 16],
        pair_id: [u8; 16],
        sequence: u64,
        sender_nonce: [u8; 16],
        expires_unix_ms: u64,
        key: &[u8; 32],
    ) -> Result<Self, String> {
        let mut packet = Self {
            kind,
            role,
            connectivity_session_id,
            transfer_id,
            pair_id,
            sequence,
            sender_nonce,
            sent_unix_ms: now_unix_ms(),
            expires_unix_ms,
            tag: [0; 32],
        };
        packet.tag = packet.compute_tag(key)?;
        Ok(packet)
    }

    fn encode(&self) -> [u8; PROBE_PACKET_BYTES] {
        let mut bytes = [0u8; PROBE_PACKET_BYTES];
        bytes[..8].copy_from_slice(&PROBE_MAGIC);
        bytes[8..10].copy_from_slice(&PROBE_VERSION.to_be_bytes());
        bytes[10] = self.kind as u8;
        bytes[11] = self.role.code();
        bytes[12..28].copy_from_slice(&self.connectivity_session_id);
        bytes[28..44].copy_from_slice(&self.transfer_id);
        bytes[44..60].copy_from_slice(&self.pair_id);
        bytes[60..68].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[68..84].copy_from_slice(&self.sender_nonce);
        bytes[84..92].copy_from_slice(&self.sent_unix_ms.to_be_bytes());
        bytes[92..100].copy_from_slice(&self.expires_unix_ms.to_be_bytes());
        bytes[100..132].copy_from_slice(&self.tag);
        bytes
    }

    fn decode(bytes: &[u8], key: &[u8; 32]) -> Result<Self, String> {
        if bytes.len() != PROBE_PACKET_BYTES || bytes[..8] != PROBE_MAGIC {
            return Err("native-probe-packet-invalid".into());
        }
        if u16::from_be_bytes([bytes[8], bytes[9]]) != PROBE_VERSION {
            return Err("native-probe-version-invalid".into());
        }
        let packet = Self {
            kind: ProbeKind::decode(bytes[10])?,
            role: NativeDeviceRole::decode_code(bytes[11])
                .map_err(|_| "native-probe-role-invalid")?,
            connectivity_session_id: bytes[12..28].try_into().unwrap(),
            transfer_id: bytes[28..44].try_into().unwrap(),
            pair_id: bytes[44..60].try_into().unwrap(),
            sequence: u64::from_be_bytes(bytes[60..68].try_into().unwrap()),
            sender_nonce: bytes[68..84].try_into().unwrap(),
            sent_unix_ms: u64::from_be_bytes(bytes[84..92].try_into().unwrap()),
            expires_unix_ms: u64::from_be_bytes(bytes[92..100].try_into().unwrap()),
            tag: bytes[100..132].try_into().unwrap(),
        };
        let expected = packet.compute_tag(key)?;
        if packet.tag.ct_eq(&expected).unwrap_u8() != 1 {
            return Err("native-probe-authentication-failed".into());
        }
        Ok(packet)
    }

    fn compute_tag(&self, key: &[u8; 32]) -> Result<[u8; 32], String> {
        let mut mac =
            HmacSha256::new_from_slice(key).map_err(|_| "native-probe-authentication-failed")?;
        mac.update(&PROBE_MAGIC);
        mac.update(&PROBE_VERSION.to_be_bytes());
        mac.update(&[self.kind as u8, self.role.code()]);
        mac.update(&self.connectivity_session_id);
        mac.update(&self.transfer_id);
        mac.update(&self.pair_id);
        mac.update(&self.sequence.to_be_bytes());
        mac.update(&self.sender_nonce);
        mac.update(&self.sent_unix_ms.to_be_bytes());
        mac.update(&self.expires_unix_ms.to_be_bytes());
        Ok(mac.finalize().into_bytes().into())
    }
}

fn decode_pair_id(value: &str) -> Result<[u8; 16], String> {
    if value.len() != 32 {
        return Err("native-candidate-pair-id-invalid".into());
    }
    let mut output = [0u8; 16];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = decode_nibble(chunk[0])? << 4 | decode_nibble(chunk[1])?;
    }
    Ok(output)
}

fn decode_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("native-candidate-pair-id-invalid".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authorization::{clear_for_test, create_registered_invitation},
        candidates::ManualCandidateInput,
        path_selection::build_candidate_pairs,
        signaling::ConnectivityAuthenticator,
    };
    use uuid::Uuid;

    fn authenticator() -> ConnectivityAuthenticator {
        clear_for_test();
        let material =
            create_registered_invitation(*Uuid::new_v4().as_bytes(), [8; 32], 7, 60_000).unwrap();
        ConnectivityAuthenticator::from_authorization(
            &material,
            *Uuid::new_v4().as_bytes(),
            *Uuid::new_v4().as_bytes(),
            1,
            [8; 32],
        )
        .unwrap()
    }

    #[test]
    #[serial_test::serial(flowshare_authorization)]
    fn forged_probe_and_role_modification_are_rejected() {
        let authenticator = authenticator();
        let key = authenticator.probe_key();
        let mut packet = ProbePacket::new(
            ProbeKind::Request,
            NativeDeviceRole::Sender,
            authenticator.connectivity_session_id(),
            authenticator.transfer_id(),
            [4; 16],
            1,
            [5; 16],
            now_unix_ms() + 5_000,
            &key,
        )
        .unwrap()
        .encode();
        packet[11] = 2;
        assert_eq!(
            ProbePacket::decode(&packet, &key).unwrap_err(),
            "native-probe-authentication-failed"
        );
    }

    #[test]
    #[serial_test::serial(flowshare_authorization)]
    fn response_has_exactly_request_size() {
        let authenticator = authenticator();
        let key = authenticator.probe_key();
        let request = ProbePacket::new(
            ProbeKind::Request,
            NativeDeviceRole::Sender,
            authenticator.connectivity_session_id(),
            authenticator.transfer_id(),
            [4; 16],
            1,
            [5; 16],
            now_unix_ms() + 5_000,
            &key,
        )
        .unwrap()
        .encode();
        let response = ProbePacket::new(
            ProbeKind::Response,
            NativeDeviceRole::Receiver,
            authenticator.connectivity_session_id(),
            authenticator.transfer_id(),
            [4; 16],
            1,
            [6; 16],
            now_unix_ms() + 5_000,
            &key,
        )
        .unwrap()
        .encode();
        assert_eq!(request.len(), response.len());
    }

    #[test]
    #[serial_test::serial(flowshare_authorization)]
    fn duplicate_authenticated_probe_is_rejected_as_replay() {
        let authenticator = authenticator();
        let key = authenticator.probe_key();
        let packet = ProbePacket::new(
            ProbeKind::Request,
            NativeDeviceRole::Sender,
            authenticator.connectivity_session_id(),
            authenticator.transfer_id(),
            [4; 16],
            9,
            [5; 16],
            now_unix_ms() + 5_000,
            &key,
        )
        .unwrap();
        let mut replay = ProbeReplaySet::new();
        assert!(accept_probe_once(&mut replay, &packet));
        assert!(!accept_probe_once(&mut replay, &packet));
    }

    fn fast_hole_punch_config() -> HolePunchConfig {
        HolePunchConfig {
            total_timeout: Duration::from_secs(5),
            initial_interval: Duration::from_millis(100),
            max_interval: Duration::from_millis(300),
            resynchronize_interval: Duration::from_millis(500),
            confirmation_grace: Duration::from_millis(700),
            drop_initial_confirm_acks: 0,
        }
    }

    fn pair_state_for_source_learning() -> PairState {
        let local = ManualCandidateInput {
            address: "198.51.100.10".parse().unwrap(),
            port: 40_000,
            priority: None,
        }
        .into_candidate(1, now_unix_ms() + 60_000, false)
        .unwrap();
        let remote = ManualCandidateInput {
            address: "203.0.113.20".parse().unwrap(),
            port: 41_000,
            priority: None,
        }
        .into_candidate(1, now_unix_ms() + 60_000, false)
        .unwrap();
        let pair = build_candidate_pairs(&[local], &[remote], NativeDeviceRole::Sender).remove(0);
        PairState {
            pair,
            probes_sent: 0,
            inbound_requests: 0,
            outbound_responses: 0,
            replayed: 0,
            invalid: 0,
            observed_source: None,
            observed_source_count: 0,
            source_stable: false,
            best_rtt: None,
            remote_confirm: false,
            confirm_ack: false,
            last_confirm_sent: None,
        }
    }

    #[test]
    #[serial_test::serial(flowshare_authorization)]
    fn authenticated_peer_reflexive_source_requires_repeat_stability() {
        let mut state = pair_state_for_source_learning();
        let rewritten: SocketAddr = "203.0.113.20:51000".parse().unwrap();
        assert!(observe_authenticated_source(&mut state, rewritten));
        assert_eq!(state.observed_source, Some(rewritten));
        assert!(!state.source_stable);

        assert!(observe_authenticated_source(&mut state, rewritten));
        assert!(state.source_stable);

        state.inbound_requests = 3;
        state.outbound_responses = 4;
        state.remote_confirm = true;
        state.confirm_ack = true;
        let changed: SocketAddr = "203.0.113.20:52000".parse().unwrap();
        assert!(observe_authenticated_source(&mut state, changed));
        assert_eq!(state.observed_source, Some(changed));
        assert!(!state.source_stable);
        assert_eq!(state.observed_source_count, 1);
        assert_eq!(state.inbound_requests, 0);
        assert_eq!(state.outbound_responses, 0);
        assert!(!state.remote_confirm);
        assert!(!state.confirm_ack);

        let wrong_family: SocketAddr = "[2001:db8::1]:52000".parse().unwrap();
        assert!(!observe_authenticated_source(&mut state, wrong_family));
        assert_eq!(state.observed_source, Some(changed));
    }

    async fn run_two_socket_check(
        sender_config: HolePunchConfig,
        receiver_config: HolePunchConfig,
        receiver_start_delay: Duration,
    ) -> (HolePunchReport, HolePunchReport) {
        let authenticator = authenticator();
        let left = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let right = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let left_address = left.local_addr().unwrap();
        let right_address = right.local_addr().unwrap();
        let left_candidate = ManualCandidateInput {
            address: left_address.ip(),
            port: left_address.port(),
            priority: None,
        }
        .into_candidate(1, now_unix_ms() + 60_000, true)
        .unwrap();
        let right_candidate = ManualCandidateInput {
            address: right_address.ip(),
            port: right_address.port(),
            priority: None,
        }
        .into_candidate(1, now_unix_ms() + 60_000, true)
        .unwrap();
        let sender_pairs = build_candidate_pairs(
            &[left_candidate.clone()],
            &[right_candidate.clone()],
            NativeDeviceRole::Sender,
        );
        let receiver_pairs = build_candidate_pairs(
            &[right_candidate],
            &[left_candidate],
            NativeDeviceRole::Receiver,
        );
        let sender = run_authenticated_hole_punch(
            left,
            sender_pairs,
            NativeDeviceRole::Sender,
            authenticator.clone(),
            sender_config,
            CancellationToken::new(),
        );
        let receiver = async move {
            tokio::time::sleep(receiver_start_delay).await;
            run_authenticated_hole_punch(
                right,
                receiver_pairs,
                NativeDeviceRole::Receiver,
                authenticator,
                receiver_config,
                CancellationToken::new(),
            )
            .await
        };
        let (sender, receiver) = tokio::join!(sender, receiver);
        (sender.unwrap(), receiver.unwrap())
    }

    fn assert_same_nomination(sender: &HolePunchReport, receiver: &HolePunchReport) {
        assert!(sender.selected_pair_id.is_some(), "{sender:?}");
        assert_eq!(sender.selected_pair_id, receiver.selected_pair_id);
        assert_eq!(sender.pair_results[0].confirmation_count, 4);
        assert_eq!(receiver.pair_results[0].confirmation_count, 4);
    }

    #[tokio::test]
    #[serial_test::serial(flowshare_authorization)]
    async fn same_machine_two_socket_check_nominates_bidirectionally() {
        let config = fast_hole_punch_config();
        let (sender, receiver) = run_two_socket_check(config, config, Duration::ZERO).await;
        assert_same_nomination(&sender, &receiver);
    }

    #[tokio::test]
    #[serial_test::serial(flowshare_authorization)]
    async fn staggered_peer_start_still_nominates_bidirectionally() {
        let config = fast_hole_punch_config();
        let (sender, receiver) =
            run_two_socket_check(config, config, Duration::from_millis(900)).await;
        assert_same_nomination(&sender, &receiver);
    }

    #[tokio::test]
    #[serial_test::serial(flowshare_authorization)]
    async fn dropped_final_confirmation_is_retried_before_either_side_exits() {
        let sender_config = fast_hole_punch_config();
        let receiver_config = HolePunchConfig {
            drop_initial_confirm_acks: 1,
            ..sender_config
        };
        let (sender, receiver) =
            run_two_socket_check(sender_config, receiver_config, Duration::ZERO).await;
        assert_same_nomination(&sender, &receiver);
    }
}
