use super::{
    authorization::AuthorizationMaterial,
    candidates::{candidate_payload_digest, hex, validate_candidate_batch, NativeCandidate},
    secure_protocol::{now_unix_ms, SECURE_PROTOCOL_VERSION},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2_compat::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

pub const NATIVE_CONNECTIVITY_PROTOCOL_VERSION: u16 = 1;
pub const MAX_SIGNALING_ENVELOPE_BYTES: usize = 64 * 1024;
pub const MAX_SIGNALING_PAYLOAD_BYTES: usize = 48 * 1024;
pub const MAX_SIGNALING_SEQUENCE_JUMP: u64 = 4096;
pub const DEFAULT_SIGNALING_LIFETIME_MS: u64 = 60 * 1000;
const SIGNALING_CLOCK_SKEW_MS: u64 = 30 * 1000;
const CONNECTIVITY_KEY_LABEL: &[u8] = b"flowshare/native/v3/connectivity/signaling";
const SIGNALING_BODY_LABEL: &[u8] = b"flowshare/native/connectivity-envelope/v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum NativeDeviceRole {
    Sender,
    Receiver,
}

impl NativeDeviceRole {
    pub fn opposite(self) -> Self {
        match self {
            Self::Sender => Self::Receiver,
            Self::Receiver => Self::Sender,
        }
    }

    pub(crate) fn code(self) -> u8 {
        match self {
            Self::Sender => 1,
            Self::Receiver => 2,
        }
    }

    pub(crate) fn decode_code(value: u8) -> Result<Self, String> {
        match value {
            1 => Ok(Self::Sender),
            2 => Ok(Self::Receiver),
            _ => Err("native-signaling-role-invalid".into()),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum NativeConnectivityFailure {
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectivityCheckResultPayload {
    pub attempted_pair_ids: Vec<String>,
    pub viable_pair_ids: Vec<String>,
    pub authenticated_probes_sent: u32,
    pub authenticated_probes_received: u32,
    pub best_rtt_ms: Option<f64>,
    pub failure: Option<NativeConnectivityFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeCandidateNominationPayload {
    pub pair_id: String,
    pub sender_candidate_id: String,
    pub receiver_candidate_id: String,
    pub sender_observed_endpoint: String,
    pub receiver_observed_endpoint: String,
    pub measured_rtt_ms: f64,
    pub confirmation_count: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", content = "data", rename_all = "kebab-case")]
pub enum NativeSignalingPayload {
    NativeConnectivityOffer { candidates: Vec<NativeCandidate> },
    NativeConnectivityAnswer { candidates: Vec<NativeCandidate> },
    NativeCandidateBatch { candidates: Vec<NativeCandidate> },
    NativeConnectivityCheckResult(ConnectivityCheckResultPayload),
    NativeCandidateNomination(NativeCandidateNominationPayload),
    NativeConnectivityCancel { reason: NativeConnectivityFailure },
}

impl NativeSignalingPayload {
    pub fn message_type(&self) -> &'static str {
        match self {
            Self::NativeConnectivityOffer { .. } => "native-connectivity-offer",
            Self::NativeConnectivityAnswer { .. } => "native-connectivity-answer",
            Self::NativeCandidateBatch { .. } => "native-candidate-batch",
            Self::NativeConnectivityCheckResult(_) => "native-connectivity-check-result",
            Self::NativeCandidateNomination(_) => "native-candidate-nomination",
            Self::NativeConnectivityCancel { .. } => "native-connectivity-cancel",
        }
    }

    pub fn candidates(&self) -> &[NativeCandidate] {
        match self {
            Self::NativeConnectivityOffer { candidates }
            | Self::NativeConnectivityAnswer { candidates }
            | Self::NativeCandidateBatch { candidates } => candidates,
            _ => &[],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticatedSignalingEnvelope {
    pub connectivity_protocol_version: u16,
    pub secure_protocol_version: u16,
    pub invitation_id: String,
    pub transfer_id: String,
    pub connectivity_session_id: String,
    pub future_quic_session_id: String,
    pub signaling_generation: u64,
    pub sender_role: NativeDeviceRole,
    pub candidate_generation: u32,
    pub candidate_payload_digest_sha256: String,
    pub payload_digest_sha256: String,
    pub certificate_commitment_sha256: String,
    pub expires_unix_ms: u64,
    pub sequence: u64,
    pub payload: NativeSignalingPayload,
    pub authentication_tag: String,
}

#[derive(Clone)]
pub struct ConnectivityAuthenticator {
    key: Zeroizing<[u8; 32]>,
    invitation_id: [u8; 16],
    transfer_id: [u8; 16],
    connectivity_session_id: [u8; 16],
    future_quic_session_id: [u8; 16],
    signaling_generation: u64,
    certificate_commitment: [u8; 32],
}

impl std::fmt::Debug for ConnectivityAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectivityAuthenticator")
            .field(
                "connectivity_session_id",
                &Uuid::from_bytes(self.connectivity_session_id),
            )
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl ConnectivityAuthenticator {
    pub fn from_authorization(
        authorization: &AuthorizationMaterial,
        connectivity_session_id: [u8; 16],
        future_quic_session_id: [u8; 16],
        signaling_generation: u64,
        certificate_commitment: [u8; 32],
    ) -> Result<Self, String> {
        if signaling_generation == 0 {
            return Err("native-signaling-generation-invalid".into());
        }
        authorization
            .invitation
            .verify(&authorization.master, now_unix_ms())?;
        let invitation_id = authorization.invitation.body.invitation_id;
        let transfer_id = authorization.invitation.body.transfer_id;
        let mut info = Vec::with_capacity(160);
        info.extend_from_slice(CONNECTIVITY_KEY_LABEL);
        info.extend_from_slice(&invitation_id);
        info.extend_from_slice(&transfer_id);
        info.extend_from_slice(&connectivity_session_id);
        info.extend_from_slice(&future_quic_session_id);
        info.extend_from_slice(&signaling_generation.to_be_bytes());
        info.extend_from_slice(&certificate_commitment);
        let salt = authorization.invitation.body.digest();
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), authorization.master.expose());
        let mut key = [0u8; 32];
        hkdf.expand(&info, &mut key)
            .map_err(|_| "native-connectivity-key-derivation-failed")?;
        Ok(Self {
            key: Zeroizing::new(key),
            invitation_id,
            transfer_id,
            connectivity_session_id,
            future_quic_session_id,
            signaling_generation,
            certificate_commitment,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        &self,
        sender_role: NativeDeviceRole,
        candidate_generation: u32,
        expires_unix_ms: u64,
        sequence: u64,
        mut payload: NativeSignalingPayload,
    ) -> Result<AuthenticatedSignalingEnvelope, String> {
        if candidate_generation == 0 || expires_unix_ms <= now_unix_ms() {
            return Err("native-signaling-expiration-invalid".into());
        }
        validate_payload(&payload, true, now_unix_ms())?;
        // Hole-punch timings originate from platform timers with more precision
        // than the authenticated wire format needs. Normalize them before both
        // hashing and JSON serialization so a value sitting on a microsecond
        // rounding boundary cannot produce a false payload-modified rejection
        // after an otherwise lossless signaling round trip.
        normalize_wire_timings(&mut payload);
        let candidate_digest = candidate_payload_digest(payload.candidates());
        let payload_digest = payload_digest(&payload)?;
        let mut envelope = AuthenticatedSignalingEnvelope {
            connectivity_protocol_version: NATIVE_CONNECTIVITY_PROTOCOL_VERSION,
            secure_protocol_version: SECURE_PROTOCOL_VERSION,
            invitation_id: Uuid::from_bytes(self.invitation_id).to_string(),
            transfer_id: Uuid::from_bytes(self.transfer_id).to_string(),
            connectivity_session_id: Uuid::from_bytes(self.connectivity_session_id).to_string(),
            future_quic_session_id: Uuid::from_bytes(self.future_quic_session_id).to_string(),
            signaling_generation: self.signaling_generation,
            sender_role,
            candidate_generation,
            candidate_payload_digest_sha256: hex(&candidate_digest),
            payload_digest_sha256: hex(&payload_digest),
            certificate_commitment_sha256: hex(&self.certificate_commitment),
            expires_unix_ms,
            sequence,
            payload,
            authentication_tag: String::new(),
        };
        envelope.authentication_tag = hex(&self.tag(&envelope)?);
        if envelope.encoded_json()?.len() > MAX_SIGNALING_ENVELOPE_BYTES {
            return Err("native-signaling-envelope-oversized".into());
        }
        Ok(envelope)
    }

    pub fn verify(
        &self,
        envelope: &AuthenticatedSignalingEnvelope,
        expected_role: NativeDeviceRole,
        allow_loopback_test: bool,
        now: u64,
    ) -> Result<(), String> {
        envelope.validate_metadata(self, expected_role, now)?;
        validate_payload(&envelope.payload, allow_loopback_test, now)?;
        let expected_candidate_digest = candidate_payload_digest(envelope.payload.candidates());
        if envelope.candidate_payload_digest_sha256 != hex(&expected_candidate_digest) {
            return Err("native-signaling-candidate-modified".into());
        }
        let expected_payload_digest = payload_digest(&envelope.payload)?;
        if envelope.payload_digest_sha256 != hex(&expected_payload_digest) {
            eprintln!(
                "[FlowShareNativeSignaling] {{\"event\":\"payload-digest-rejected\",\"messageType\":\"{}\",\"senderRole\":\"{:?}\",\"signalingGeneration\":{},\"sequence\":{},\"suppliedDigest\":\"{}\",\"expectedDigest\":\"{}\"}}",
                envelope.payload.message_type(),
                envelope.sender_role,
                envelope.signaling_generation,
                envelope.sequence,
                envelope.payload_digest_sha256,
                hex(&expected_payload_digest),
            );
            return Err("native-signaling-payload-modified".into());
        }
        let supplied = decode_hex_32(&envelope.authentication_tag)
            .map_err(|_| "native-signaling-authentication-failed")?;
        let expected = self.tag(envelope)?;
        if supplied.ct_eq(&expected).unwrap_u8() != 1 {
            return Err("native-signaling-authentication-failed".into());
        }
        Ok(())
    }

    fn tag(&self, envelope: &AuthenticatedSignalingEnvelope) -> Result<[u8; 32], String> {
        let mut mac = HmacSha256::new_from_slice(&self.key[..])
            .map_err(|_| "native-signaling-authentication-failed")?;
        mac.update(&envelope.canonical_body()?);
        Ok(mac.finalize().into_bytes().into())
    }

    pub(crate) fn probe_key(&self) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.key[..]).expect("HMAC accepts 32-byte keys");
        mac.update(b"flowshare/native/connectivity-probe/v1");
        mac.finalize().into_bytes().into()
    }

    pub fn connectivity_session_id(&self) -> [u8; 16] {
        self.connectivity_session_id
    }

    pub fn transfer_id(&self) -> [u8; 16] {
        self.transfer_id
    }
}

impl AuthenticatedSignalingEnvelope {
    pub fn encode(&self) -> Result<String, String> {
        let bytes = self.encoded_json()?;
        if bytes.len() > MAX_SIGNALING_ENVELOPE_BYTES {
            return Err("native-signaling-envelope-oversized".into());
        }
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn decode(encoded: &str) -> Result<Self, String> {
        if encoded.len() > MAX_SIGNALING_ENVELOPE_BYTES * 2 {
            return Err("native-signaling-envelope-oversized".into());
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| "native-signaling-envelope-malformed")?;
        if bytes.len() > MAX_SIGNALING_ENVELOPE_BYTES {
            return Err("native-signaling-envelope-oversized".into());
        }
        serde_json::from_slice(&bytes).map_err(|_| "native-signaling-envelope-malformed".into())
    }

    fn encoded_json(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|_| "native-signaling-envelope-encode-failed".into())
    }

    fn validate_metadata(
        &self,
        authenticator: &ConnectivityAuthenticator,
        expected_role: NativeDeviceRole,
        now: u64,
    ) -> Result<(), String> {
        if self.connectivity_protocol_version != NATIVE_CONNECTIVITY_PROTOCOL_VERSION
            || self.secure_protocol_version != SECURE_PROTOCOL_VERSION
        {
            return Err("native-signaling-protocol-downgrade-rejected".into());
        }
        if parse_uuid(&self.invitation_id)? != authenticator.invitation_id
            || parse_uuid(&self.transfer_id)? != authenticator.transfer_id
        {
            return Err("native-signaling-transfer-mismatch".into());
        }
        if parse_uuid(&self.connectivity_session_id)? != authenticator.connectivity_session_id
            || parse_uuid(&self.future_quic_session_id)? != authenticator.future_quic_session_id
        {
            return Err("native-signaling-session-mismatch".into());
        }
        if self.signaling_generation != authenticator.signaling_generation {
            return Err("native-signaling-generation-stale".into());
        }
        if self.sender_role != expected_role {
            return Err("native-signaling-role-confusion".into());
        }
        if self.candidate_generation == 0 {
            return Err("native-signaling-candidate-generation-invalid".into());
        }
        if decode_hex_32(&self.certificate_commitment_sha256)?
            != authenticator.certificate_commitment
        {
            return Err("native-signaling-certificate-commitment-mismatch".into());
        }
        if self.expires_unix_ms.saturating_add(SIGNALING_CLOCK_SKEW_MS) < now
            || self.expires_unix_ms > now.saturating_add(10 * 60 * 1000)
        {
            return Err("native-signaling-envelope-expired".into());
        }
        Ok(())
    }

    fn canonical_body(&self) -> Result<Vec<u8>, String> {
        let mut writer = CanonicalWriter::new();
        writer.bytes(SIGNALING_BODY_LABEL)?;
        writer.u16(self.connectivity_protocol_version);
        writer.u16(self.secure_protocol_version);
        writer.fixed(&parse_uuid(&self.invitation_id)?);
        writer.fixed(&parse_uuid(&self.transfer_id)?);
        writer.fixed(&parse_uuid(&self.connectivity_session_id)?);
        writer.fixed(&parse_uuid(&self.future_quic_session_id)?);
        writer.u64(self.signaling_generation);
        writer.u8(self.sender_role.code());
        writer.u32(self.candidate_generation);
        writer.fixed(&decode_hex_32(&self.candidate_payload_digest_sha256)?);
        writer.fixed(&decode_hex_32(&self.payload_digest_sha256)?);
        writer.fixed(&decode_hex_32(&self.certificate_commitment_sha256)?);
        writer.u64(self.expires_unix_ms);
        writer.u64(self.sequence);
        writer.bytes(self.payload.message_type().as_bytes())?;
        Ok(writer.finish())
    }
}

#[derive(Debug, Clone, Default)]
pub struct SignalingReplayWindow {
    generation: u64,
    last_sequence: Option<u64>,
}

impl SignalingReplayWindow {
    pub fn new(generation: u64) -> Self {
        Self {
            generation,
            last_sequence: None,
        }
    }

    pub fn accept(&mut self, envelope: &AuthenticatedSignalingEnvelope) -> Result<(), String> {
        if envelope.signaling_generation != self.generation {
            return Err("native-signaling-generation-stale".into());
        }
        if let Some(last) = self.last_sequence {
            if envelope.sequence <= last {
                return Err("native-signaling-replay-detected".into());
            }
            if envelope.sequence - last > MAX_SIGNALING_SEQUENCE_JUMP {
                return Err("native-signaling-sequence-jump-rejected".into());
            }
        }
        self.last_sequence = Some(envelope.sequence);
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalingDeliveryAck {
    pub route: String,
    pub sequence: u64,
    pub accepted: bool,
}

pub trait NativeSignalingTransport: Send + Sync {
    fn send(
        &self,
        route: &str,
        envelope: &AuthenticatedSignalingEnvelope,
    ) -> Result<SignalingDeliveryAck, String>;
    fn receive(
        &self,
        route: &str,
        after_sequence: Option<u64>,
    ) -> Result<Option<AuthenticatedSignalingEnvelope>, String>;
    fn reconnect(&self, route: &str) -> Result<(), String>;
    fn cancel(&self, route: &str) -> Result<(), String>;
}

#[derive(Debug, Default)]
pub struct InMemoryNativeSignalingTransport {
    queues: Mutex<HashMap<String, VecDeque<AuthenticatedSignalingEnvelope>>>,
}

impl NativeSignalingTransport for InMemoryNativeSignalingTransport {
    fn send(
        &self,
        route: &str,
        envelope: &AuthenticatedSignalingEnvelope,
    ) -> Result<SignalingDeliveryAck, String> {
        validate_route(route)?;
        if envelope.encoded_json()?.len() > MAX_SIGNALING_ENVELOPE_BYTES {
            return Err("native-signaling-envelope-oversized".into());
        }
        let mut queues = self
            .queues
            .lock()
            .map_err(|_| "native-signaling-transport-unavailable")?;
        let queue = queues.entry(route.to_string()).or_default();
        if queue.len() >= 128 {
            return Err("native-signaling-queue-full".into());
        }
        if queue.iter().any(|value| {
            value.signaling_generation == envelope.signaling_generation
                && value.sequence == envelope.sequence
                && value.sender_role == envelope.sender_role
        }) {
            return Err("native-signaling-replay-detected".into());
        }
        queue.push_back(envelope.clone());
        Ok(SignalingDeliveryAck {
            route: route.to_string(),
            sequence: envelope.sequence,
            accepted: true,
        })
    }

    fn receive(
        &self,
        route: &str,
        after_sequence: Option<u64>,
    ) -> Result<Option<AuthenticatedSignalingEnvelope>, String> {
        validate_route(route)?;
        let mut queues = self
            .queues
            .lock()
            .map_err(|_| "native-signaling-transport-unavailable")?;
        let Some(queue) = queues.get_mut(route) else {
            return Ok(None);
        };
        let position = queue
            .iter()
            .position(|value| after_sequence.is_none_or(|after| value.sequence > after));
        Ok(position.and_then(|position| queue.remove(position)))
    }

    fn reconnect(&self, route: &str) -> Result<(), String> {
        validate_route(route)
    }

    fn cancel(&self, route: &str) -> Result<(), String> {
        validate_route(route)?;
        self.queues
            .lock()
            .map_err(|_| "native-signaling-transport-unavailable")?
            .remove(route);
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExistingSignalingAdapterStatus {
    pub compiled: bool,
    pub enabled: bool,
    pub metadata_only: bool,
    pub maximum_envelope_bytes: usize,
    pub endpoint: &'static str,
    pub activation_flag: &'static str,
    pub integration_status: &'static str,
}

pub fn existing_signaling_adapter_status() -> ExistingSignalingAdapterStatus {
    ExistingSignalingAdapterStatus {
        compiled: true,
        enabled: true,
        metadata_only: true,
        maximum_envelope_bytes: MAX_SIGNALING_ENVELOPE_BYTES,
        endpoint: "wss://share.flowget.xyz/ws",
        activation_flag: "server:FLOWGET_NATIVE_CONNECTIVITY_SIGNALING=1",
        integration_status: "native-client-available-server-route-also-required",
    }
}

pub fn adapt_envelope_for_existing_signaling(
    share_id: &str,
    receiver_id: &str,
    envelope: &AuthenticatedSignalingEnvelope,
) -> Result<serde_json::Value, String> {
    let status = existing_signaling_adapter_status();
    if !status.enabled {
        return Err("native-signaling-adapter-disabled".into());
    }
    validate_route(share_id)?;
    validate_route(receiver_id)?;
    let encoded = envelope.encode()?;
    Ok(serde_json::json!({
        "type": "native-connectivity-envelope-v1",
        "shareId": share_id,
        "receiverId": receiver_id,
        "envelope": encoded,
        "expiresUnixMs": envelope.expires_unix_ms,
    }))
}

fn validate_payload(
    payload: &NativeSignalingPayload,
    allow_loopback_test: bool,
    now: u64,
) -> Result<(), String> {
    validate_candidate_batch(payload.candidates(), allow_loopback_test, now)?;
    match payload {
        NativeSignalingPayload::NativeConnectivityCheckResult(result) => {
            if result.attempted_pair_ids.len() > 256 || result.viable_pair_ids.len() > 64 {
                return Err("native-signaling-check-result-oversized".into());
            }
            if result
                .best_rtt_ms
                .is_some_and(|value| !value.is_finite() || value < 0.0)
            {
                return Err("native-signaling-check-result-invalid".into());
            }
        }
        NativeSignalingPayload::NativeCandidateNomination(nomination) => {
            if nomination.pair_id.len() > 64
                || nomination.sender_candidate_id.len() > 64
                || nomination.receiver_candidate_id.len() > 64
                || nomination.confirmation_count < 2
                || !nomination.measured_rtt_ms.is_finite()
                || nomination.measured_rtt_ms < 0.0
                || nomination
                    .sender_observed_endpoint
                    .parse::<std::net::SocketAddr>()
                    .is_err()
                || nomination
                    .receiver_observed_endpoint
                    .parse::<std::net::SocketAddr>()
                    .is_err()
            {
                return Err("native-signaling-nomination-invalid".into());
            }
        }
        _ => {}
    }
    let encoded =
        serde_json::to_vec(payload).map_err(|_| "native-signaling-payload-encode-failed")?;
    if encoded.len() > MAX_SIGNALING_PAYLOAD_BYTES {
        return Err("native-signaling-payload-oversized".into());
    }
    Ok(())
}

fn payload_digest(payload: &NativeSignalingPayload) -> Result<[u8; 32], String> {
    let mut writer = CanonicalWriter::new();
    writer.bytes(payload.message_type().as_bytes())?;
    writer.fixed(&candidate_payload_digest(payload.candidates()));
    match payload {
        NativeSignalingPayload::NativeConnectivityCheckResult(value) => {
            let mut attempted = value.attempted_pair_ids.clone();
            attempted.sort();
            let mut viable = value.viable_pair_ids.clone();
            viable.sort();
            writer.u16(attempted.len() as u16);
            for pair in attempted {
                writer.bytes(pair.as_bytes())?;
            }
            writer.u16(viable.len() as u16);
            for pair in viable {
                writer.bytes(pair.as_bytes())?;
            }
            writer.u32(value.authenticated_probes_sent);
            writer.u32(value.authenticated_probes_received);
            writer.u64(
                value
                    .best_rtt_ms
                    .map(|rtt| (rtt * 1000.0).round() as u64)
                    .unwrap_or(u64::MAX),
            );
            writer.u8(value.failure.map(failure_code).unwrap_or(0));
        }
        NativeSignalingPayload::NativeCandidateNomination(value) => {
            writer.bytes(value.pair_id.as_bytes())?;
            writer.bytes(value.sender_candidate_id.as_bytes())?;
            writer.bytes(value.receiver_candidate_id.as_bytes())?;
            writer.bytes(value.sender_observed_endpoint.as_bytes())?;
            writer.bytes(value.receiver_observed_endpoint.as_bytes())?;
            writer.u64((value.measured_rtt_ms * 1000.0).round() as u64);
            writer.u8(value.confirmation_count);
        }
        NativeSignalingPayload::NativeConnectivityCancel { reason } => {
            writer.u8(failure_code(*reason));
        }
        _ => {}
    }
    Ok(Sha256::digest(writer.finish()).into())
}

fn normalize_wire_timings(payload: &mut NativeSignalingPayload) {
    fn round_to_microsecond(value_ms: f64) -> f64 {
        ((value_ms * 1000.0).round() as u64) as f64 / 1000.0
    }

    match payload {
        NativeSignalingPayload::NativeConnectivityCheckResult(value) => {
            if let Some(rtt) = value.best_rtt_ms.as_mut() {
                *rtt = round_to_microsecond(*rtt);
            }
        }
        NativeSignalingPayload::NativeCandidateNomination(value) => {
            value.measured_rtt_ms = round_to_microsecond(value.measured_rtt_ms);
        }
        _ => {}
    }
}

fn failure_code(value: NativeConnectivityFailure) -> u8 {
    match value {
        NativeConnectivityFailure::UdpBlocked => 1,
        NativeConnectivityFailure::FirewallBlockedLikely => 2,
        NativeConnectivityFailure::SymmetricNatLikely => 3,
        NativeConnectivityFailure::CandidateExchangeFailed => 4,
        NativeConnectivityFailure::CandidateAuthenticationFailed => 5,
        NativeConnectivityFailure::NoViablePair => 6,
        NativeConnectivityFailure::QuicHandshakeFailed => 7,
        NativeConnectivityFailure::SecureSessionFailed => 8,
        NativeConnectivityFailure::DirectConnectTimeout => 9,
        NativeConnectivityFailure::RelayRequired => 10,
        NativeConnectivityFailure::Cancelled => 11,
        NativeConnectivityFailure::Unknown => 12,
    }
}

fn parse_uuid(value: &str) -> Result<[u8; 16], String> {
    Ok(*Uuid::parse_str(value)
        .map_err(|_| "native-signaling-identifier-invalid")?
        .as_bytes())
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("native-signaling-digest-invalid".into());
    }
    let mut output = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(chunk[0])?;
        let low = decode_hex_nibble(chunk[1])?;
        output[index] = high << 4 | low;
    }
    Ok(output)
}

fn decode_hex_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("native-signaling-digest-invalid".into()),
    }
}

fn validate_route(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("native-signaling-route-invalid".into());
    }
    Ok(())
}

struct CanonicalWriter {
    bytes: Vec<u8>,
}

impl CanonicalWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(512),
        }
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn fixed<const N: usize>(&mut self, value: &[u8; N]) {
        self.bytes.extend_from_slice(value);
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), String> {
        if value.len() > u16::MAX as usize {
            return Err("native-signaling-canonical-field-oversized".into());
        }
        self.u16(value.len() as u16);
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authorization::{clear_for_test, create_registered_invitation},
        candidates::{ManualCandidateInput, NativeCandidateType},
    };

    fn fixture() -> (
        AuthorizationMaterial,
        ConnectivityAuthenticator,
        NativeCandidate,
    ) {
        clear_for_test();
        let transfer = *Uuid::new_v4().as_bytes();
        let material = create_registered_invitation(transfer, [7; 32], 7, 60_000).unwrap();
        let authenticator = ConnectivityAuthenticator::from_authorization(
            &material,
            *Uuid::new_v4().as_bytes(),
            *Uuid::new_v4().as_bytes(),
            1,
            [7; 32],
        )
        .unwrap();
        let candidate = ManualCandidateInput {
            address: "198.51.100.7".parse().unwrap(),
            port: 45000,
            priority: None,
        }
        .into_candidate(1, now_unix_ms() + 60_000, false)
        .unwrap();
        (material, authenticator, candidate)
    }

    #[test]
    #[serial_test::serial(flowshare_authorization)]
    fn candidate_modification_and_role_swap_are_rejected() {
        let (_, authenticator, candidate) = fixture();
        let mut envelope = authenticator
            .sign(
                NativeDeviceRole::Sender,
                1,
                now_unix_ms() + 30_000,
                0,
                NativeSignalingPayload::NativeConnectivityOffer {
                    candidates: vec![candidate],
                },
            )
            .unwrap();
        assert!(authenticator
            .verify(&envelope, NativeDeviceRole::Sender, false, now_unix_ms())
            .is_ok());
        assert_eq!(
            authenticator
                .verify(&envelope, NativeDeviceRole::Receiver, false, now_unix_ms())
                .unwrap_err(),
            "native-signaling-role-confusion"
        );
        if let NativeSignalingPayload::NativeConnectivityOffer { candidates } =
            &mut envelope.payload
        {
            candidates[0].candidate_type = NativeCandidateType::Mapped;
        }
        assert!(matches!(
            authenticator.verify(
                &envelope,
                NativeDeviceRole::Sender,
                false,
                now_unix_ms()
            ),
            Err(error) if error == "native-candidate-id-mismatch" || error == "native-signaling-candidate-modified"
        ));
    }

    #[test]
    #[serial_test::serial(flowshare_authorization)]
    fn signaling_replay_and_generation_rollback_are_rejected() {
        let (_, authenticator, candidate) = fixture();
        let envelope = authenticator
            .sign(
                NativeDeviceRole::Sender,
                1,
                now_unix_ms() + 30_000,
                5,
                NativeSignalingPayload::NativeCandidateBatch {
                    candidates: vec![candidate],
                },
            )
            .unwrap();
        let mut replay = SignalingReplayWindow::new(1);
        replay.accept(&envelope).unwrap();
        assert_eq!(
            replay.accept(&envelope).unwrap_err(),
            "native-signaling-replay-detected"
        );
        let mut wrong_generation = envelope.clone();
        wrong_generation.signaling_generation = 0;
        assert_eq!(
            replay.accept(&wrong_generation).unwrap_err(),
            "native-signaling-generation-stale"
        );
    }

    #[test]
    #[serial_test::serial(flowshare_authorization)]
    fn nomination_modification_is_rejected() {
        let (_, authenticator, _) = fixture();
        let mut envelope = authenticator
            .sign(
                NativeDeviceRole::Sender,
                1,
                now_unix_ms() + 30_000,
                6,
                NativeSignalingPayload::NativeCandidateNomination(
                    NativeCandidateNominationPayload {
                        pair_id: "00112233445566778899aabbccddeeff".into(),
                        sender_candidate_id: "sender-candidate".into(),
                        receiver_candidate_id: "receiver-candidate".into(),
                        sender_observed_endpoint: "198.51.100.7:45000".into(),
                        receiver_observed_endpoint: "203.0.113.9:46000".into(),
                        measured_rtt_ms: 12.5,
                        confirmation_count: 2,
                    },
                ),
            )
            .unwrap();
        if let NativeSignalingPayload::NativeCandidateNomination(nomination) = &mut envelope.payload
        {
            nomination.receiver_observed_endpoint = "203.0.113.9:46001".into();
        }
        assert_eq!(
            authenticator
                .verify(&envelope, NativeDeviceRole::Sender, false, now_unix_ms())
                .unwrap_err(),
            "native-signaling-payload-modified"
        );
    }

    #[test]
    #[serial_test::serial(flowshare_authorization)]
    fn nomination_rtt_is_normalized_before_authenticated_round_trip() {
        let (_, authenticator, _) = fixture();
        let envelope = authenticator
            .sign(
                NativeDeviceRole::Receiver,
                1,
                now_unix_ms() + 30_000,
                7,
                NativeSignalingPayload::NativeCandidateNomination(
                    NativeCandidateNominationPayload {
                        pair_id: "00112233445566778899aabbccddeeff".into(),
                        sender_candidate_id: "sender-candidate".into(),
                        receiver_candidate_id: "receiver-candidate".into(),
                        sender_observed_endpoint: "198.51.100.7:45000".into(),
                        receiver_observed_endpoint: "203.0.113.9:46000".into(),
                        measured_rtt_ms: 0.371_131_000_000_000_04,
                        confirmation_count: 2,
                    },
                ),
            )
            .unwrap();
        let decoded = AuthenticatedSignalingEnvelope::decode(&envelope.encode().unwrap()).unwrap();
        let NativeSignalingPayload::NativeCandidateNomination(nomination) = &decoded.payload else {
            panic!("nomination payload expected");
        };
        assert_eq!(nomination.measured_rtt_ms, 0.371);
        authenticator
            .verify(&decoded, NativeDeviceRole::Receiver, false, now_unix_ms())
            .unwrap();
    }

    #[test]
    #[serial_test::serial(flowshare_authorization)]
    fn envelope_round_trip_and_in_memory_delivery_are_bounded() {
        let (_, authenticator, candidate) = fixture();
        let envelope = authenticator
            .sign(
                NativeDeviceRole::Receiver,
                1,
                now_unix_ms() + 30_000,
                1,
                NativeSignalingPayload::NativeConnectivityAnswer {
                    candidates: vec![candidate],
                },
            )
            .unwrap();
        let encoded = envelope.encode().unwrap();
        assert_eq!(
            AuthenticatedSignalingEnvelope::decode(&encoded).unwrap(),
            envelope
        );
        let transport = InMemoryNativeSignalingTransport::default();
        assert!(transport.send("route-1", &envelope).unwrap().accepted);
        assert_eq!(
            transport.receive("route-1", None).unwrap().unwrap(),
            envelope
        );
    }

    #[test]
    #[serial_test::serial(flowshare_authorization)]
    fn oversized_candidate_set_is_rejected_before_authentication() {
        let (_, authenticator, candidate) = fixture();
        let candidates = (0..=super::super::candidates::MAX_NATIVE_CANDIDATES)
            .map(|index| {
                ManualCandidateInput {
                    address: "198.51.100.7".parse().unwrap(),
                    port: candidate.port.saturating_add(index as u16),
                    priority: None,
                }
                .into_candidate(1, now_unix_ms() + 60_000, false)
                .unwrap()
            })
            .collect();
        assert_eq!(
            authenticator
                .sign(
                    NativeDeviceRole::Sender,
                    1,
                    now_unix_ms() + 30_000,
                    0,
                    NativeSignalingPayload::NativeConnectivityOffer { candidates },
                )
                .unwrap_err(),
            "native-candidate-set-oversized"
        );
    }
}
