use super::{
    authorization,
    candidates::{
        apply_privacy_policy, gather_host_candidates, validate_candidate_batch,
        CandidatePrivacyPolicy, HostGatherOptions, ManualCandidateInput, NativeAddressFamily,
        NativeCandidate, MAX_NATIVE_CANDIDATES,
    },
    connectivity_diagnostics::{ConnectivityStateName, NativeConnectivityDiagnostics},
    hole_punch::{run_authenticated_hole_punch, HolePunchConfig, HolePunchReport},
    path_selection::{build_candidate_pairs, NativeCandidatePair},
    port_mapping::{start_optional_port_mapping, ActivePortMapping, PortMappingDevelopmentOptions},
    secure_protocol::now_unix_ms,
    signaling::{
        existing_signaling_adapter_status, AuthenticatedSignalingEnvelope,
        ConnectivityAuthenticator, ConnectivityCheckResultPayload,
        NativeCandidateNominationPayload, NativeDeviceRole, NativeSignalingPayload,
        SignalingReplayWindow, DEFAULT_SIGNALING_LIFETIME_MS,
    },
    stun::{
        default_development_stun_servers, discover_server_reflexive_candidates,
        ObservedNatMappingBehavior, StunDiscoveryReport, StunQueryPolicy, StunServerConfig,
    },
};
use futures::future::join_all;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2_compat::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::{Arc, LazyLock, Mutex as StdMutex},
    time::Duration,
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const MAX_CONNECTIVITY_SESSIONS: usize = 64;
const MIN_CONNECTIVITY_LIFETIME_MS: u64 = 30_000;
const MAX_CONNECTIVITY_LIFETIME_MS: u64 = 5 * 60_000;

static CONNECTIVITY_SESSIONS: LazyLock<StdMutex<HashMap<String, Arc<ConnectivitySession>>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectivityGatherOptions {
    pub privacy_policy: Option<CandidatePrivacyPolicy>,
    pub expected_same_lan: Option<bool>,
    pub all_direct_approved: Option<bool>,
    pub allow_vpn: Option<bool>,
    pub allow_virtual_adapters: Option<bool>,
    pub allow_loopback_test: Option<bool>,
    pub enable_stun: Option<bool>,
    pub stun_servers: Option<Vec<StunServerConfig>>,
    pub manual_candidates: Option<Vec<ManualCandidateInput>>,
    pub port_mapping: Option<PortMappingDevelopmentOptions>,
    pub candidate_lifetime_ms: Option<u64>,
}

impl Default for ConnectivityGatherOptions {
    fn default() -> Self {
        Self {
            privacy_policy: Some(CandidatePrivacyPolicy::LanFirst),
            expected_same_lan: Some(false),
            all_direct_approved: Some(false),
            allow_vpn: Some(false),
            allow_virtual_adapters: Some(false),
            allow_loopback_test: Some(false),
            enable_stun: Some(true),
            stun_servers: None,
            manual_candidates: None,
            port_mapping: None,
            candidate_lifetime_ms: Some(DEFAULT_SIGNALING_LIFETIME_MS),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateConnectivityOfferRequest {
    pub transfer_id: String,
    pub role: Option<NativeDeviceRole>,
    pub signaling_generation: Option<u64>,
    pub candidate_generation: Option<u32>,
    pub future_quic_session_id: Option<String>,
    pub gathering: Option<ConnectivityGatherOptions>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptConnectivityOfferRequest {
    pub encoded_offer: String,
    pub candidate_generation: Option<u32>,
    pub gathering: Option<ConnectivityGatherOptions>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AddRemoteCandidatesRequest {
    pub connectivity_session_id: String,
    pub encoded_envelope: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartConnectivityChecksRequest {
    pub connectivity_session_id: String,
    pub total_timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectivitySessionRequest {
    pub connectivity_session_id: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectivityDiagnosticsRequest {
    pub gathering: Option<ConnectivityGatherOptions>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectivityEnvelopeResponse {
    pub connectivity_session_id: String,
    pub future_quic_session_id: String,
    pub signaling_generation: u64,
    pub candidate_generation: u32,
    pub role: NativeDeviceRole,
    pub encoded_envelope: String,
    pub local_candidates: Vec<NativeCandidate>,
    pub diagnostics: NativeConnectivityDiagnostics,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddRemoteCandidatesResponse {
    pub connectivity_session_id: String,
    pub accepted_message_type: String,
    pub remote_candidate_count: usize,
    pub state: ConnectivityStateName,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectivityChecksResponse {
    pub connectivity_session_id: String,
    pub state: ConnectivityStateName,
    pub check_result_envelope: String,
    pub nomination_envelope: Option<String>,
    pub diagnostics: NativeConnectivityDiagnostics,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectivityStateResponse {
    pub connectivity_session_id: String,
    pub role: NativeDeviceRole,
    pub state: ConnectivityStateName,
    pub local_candidate_count: usize,
    pub remote_candidate_count: usize,
    pub network_change_detected: bool,
    pub renegotiation_required: bool,
    pub production_native_enabled: bool,
    pub diagnostics: NativeConnectivityDiagnostics,
}

struct ConnectivitySession {
    id: String,
    registry_id: StdMutex<String>,
    future_quic_session_id: String,
    transfer_id: [u8; 16],
    role: NativeDeviceRole,
    candidate_generation: u32,
    expires_unix_ms: u64,
    allow_loopback_test: bool,
    authenticator: ConnectivityAuthenticator,
    local_candidates: Vec<NativeCandidate>,
    sockets: StdMutex<BoundUdpSockets>,
    mapping: Mutex<Option<ActivePortMapping>>,
    cancellation: CancellationToken,
    mutable: Mutex<ConnectivityMutable>,
    diagnostics: Mutex<NativeConnectivityDiagnostics>,
    network_snapshot: [u8; 32],
}

struct ConnectivityMutable {
    state: ConnectivityStateName,
    remote_candidates: Vec<NativeCandidate>,
    remote_candidate_generation: Option<u32>,
    replay: SignalingReplayWindow,
    next_sequence: u64,
    checks_active: bool,
    nominated_pair: Option<NativeCandidatePair>,
    remote_nomination_authenticated: bool,
}

#[derive(Debug, Clone)]
pub struct NominatedPathContext {
    pub connectivity_session_id: String,
    pub future_quic_session_id: [u8; 16],
    pub transfer_id: [u8; 16],
    pub role: NativeDeviceRole,
    pub pair: NativeCandidatePair,
    pub expires_unix_ms: u64,
}

#[derive(Debug)]
struct BoundUdpSockets {
    ipv4: Option<UdpSocket>,
    ipv6: Option<UdpSocket>,
}

impl BoundUdpSockets {
    fn bind() -> Result<Self, String> {
        let ipv4 = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).ok();
        let ipv6 = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)).ok();
        if ipv4.is_none() && ipv6.is_none() {
            return Err("native-udp-bind-failed".into());
        }
        for socket in [&ipv4, &ipv6].into_iter().flatten() {
            socket
                .set_nonblocking(true)
                .map_err(|_| "native-udp-bind-failed")?;
        }
        Ok(Self { ipv4, ipv6 })
    }

    fn port(&self, family: NativeAddressFamily) -> Option<u16> {
        self.socket(family)
            .and_then(|socket| socket.local_addr().ok())
            .map(|address| address.port())
    }

    fn socket(&self, family: NativeAddressFamily) -> Option<&UdpSocket> {
        match family {
            NativeAddressFamily::Ipv4 => self.ipv4.as_ref(),
            NativeAddressFamily::Ipv6 => self.ipv6.as_ref(),
        }
    }

    fn clone_socket(&self, family: NativeAddressFamily) -> Result<UdpSocket, String> {
        self.socket(family)
            .ok_or_else(|| "native-udp-address-family-unavailable".to_string())?
            .try_clone()
            .map_err(|_| "native-udp-socket-clone-failed".into())
    }

    fn close(&mut self) {
        self.ipv4.take();
        self.ipv6.take();
    }
}

struct GatheredConnectivity {
    sockets: BoundUdpSockets,
    local_candidates: Vec<NativeCandidate>,
    mapping: Option<ActivePortMapping>,
    diagnostics: NativeConnectivityDiagnostics,
    expires_unix_ms: u64,
    allow_loopback_test: bool,
}

pub async fn flowshare_native_create_connectivity_offer(
    request: CreateConnectivityOfferRequest,
) -> Result<ConnectivityEnvelopeResponse, String> {
    ensure_native_beta_available()?;
    let transfer_id = parse_uuid(
        &request.transfer_id,
        "native-connectivity-transfer-id-invalid",
    )?;
    let authorization = authorization::material_for_transfer(&transfer_id)?;
    let role = request.role.unwrap_or(NativeDeviceRole::Sender);
    let connectivity_session_id = *Uuid::new_v4().as_bytes();
    let future_quic_session_id = request
        .future_quic_session_id
        .as_deref()
        .map(|value| parse_uuid(value, "native-connectivity-quic-session-id-invalid"))
        .transpose()?
        .unwrap_or_else(|| *Uuid::new_v4().as_bytes());
    let signaling_generation = request
        .signaling_generation
        .unwrap_or_else(random_nonzero_u64);
    if signaling_generation == 0 {
        return Err("native-signaling-generation-invalid".into());
    }
    let candidate_generation = request.candidate_generation.unwrap_or(1);
    if candidate_generation == 0 {
        return Err("native-signaling-candidate-generation-invalid".into());
    }
    let certificate_commitment = authorization.invitation.body.server_certificate_fingerprint;
    let authenticator = ConnectivityAuthenticator::from_authorization(
        &authorization,
        connectivity_session_id,
        future_quic_session_id,
        signaling_generation,
        certificate_commitment,
    )?;
    let gathering = request.gathering.unwrap_or_default();
    let cancellation = CancellationToken::new();
    let gathered = gather_connectivity_candidates(
        Uuid::from_bytes(connectivity_session_id).to_string(),
        request.transfer_id.clone(),
        candidate_generation,
        gathering,
        cancellation.clone(),
    )
    .await?;
    if gathered.local_candidates.is_empty() {
        return Err("native-connectivity-no-local-candidates".into());
    }
    let envelope = authenticator.sign(
        role,
        candidate_generation,
        gathered.expires_unix_ms,
        0,
        NativeSignalingPayload::NativeConnectivityOffer {
            candidates: gathered.local_candidates.clone(),
        },
    )?;
    let session = Arc::new(ConnectivitySession {
        id: Uuid::from_bytes(connectivity_session_id).to_string(),
        registry_id: StdMutex::new(Uuid::from_bytes(connectivity_session_id).to_string()),
        future_quic_session_id: Uuid::from_bytes(future_quic_session_id).to_string(),
        transfer_id,
        role,
        candidate_generation,
        expires_unix_ms: gathered.expires_unix_ms,
        allow_loopback_test: gathered.allow_loopback_test,
        authenticator,
        local_candidates: gathered.local_candidates.clone(),
        sockets: StdMutex::new(gathered.sockets),
        mapping: Mutex::new(gathered.mapping),
        cancellation,
        mutable: Mutex::new(ConnectivityMutable {
            state: ConnectivityStateName::AwaitingRemoteCandidates,
            remote_candidates: Vec::new(),
            remote_candidate_generation: None,
            replay: SignalingReplayWindow::new(signaling_generation),
            next_sequence: 1,
            checks_active: false,
            nominated_pair: None,
            remote_nomination_authenticated: false,
        }),
        diagnostics: Mutex::new({
            let mut diagnostics = gathered.diagnostics;
            diagnostics.state = ConnectivityStateName::AwaitingRemoteCandidates;
            diagnostics
        }),
        network_snapshot: current_network_snapshot(),
    });
    insert_session(session.clone())?;
    let diagnostics = session.diagnostics.lock().await.clone();
    Ok(ConnectivityEnvelopeResponse {
        connectivity_session_id: session_registry_id(&session)?,
        future_quic_session_id: session.future_quic_session_id.clone(),
        signaling_generation,
        candidate_generation,
        role,
        encoded_envelope: envelope.encode()?,
        local_candidates: session.local_candidates.clone(),
        diagnostics,
    })
}

pub async fn flowshare_native_accept_connectivity_offer(
    request: AcceptConnectivityOfferRequest,
) -> Result<ConnectivityEnvelopeResponse, String> {
    ensure_native_beta_available()?;
    let offer = AuthenticatedSignalingEnvelope::decode(&request.encoded_offer)?;
    if !matches!(
        &offer.payload,
        NativeSignalingPayload::NativeConnectivityOffer { .. }
    ) {
        return Err("native-signaling-offer-required".into());
    }
    let transfer_id = parse_uuid(
        &offer.transfer_id,
        "native-connectivity-transfer-id-invalid",
    )?;
    let connectivity_session_id = parse_uuid(
        &offer.connectivity_session_id,
        "native-connectivity-session-id-invalid",
    )?;
    let future_quic_session_id = parse_uuid(
        &offer.future_quic_session_id,
        "native-connectivity-quic-session-id-invalid",
    )?;
    let certificate_commitment =
        super::secure_protocol::decode_hex_32(&offer.certificate_commitment_sha256)?;
    let authorization = authorization::material_for_transfer(&transfer_id)?;
    if authorization.invitation.body.invitation_id
        != parse_uuid(
            &offer.invitation_id,
            "native-connectivity-invitation-id-invalid",
        )?
    {
        return Err("native-signaling-transfer-mismatch".into());
    }
    let authenticator = ConnectivityAuthenticator::from_authorization(
        &authorization,
        connectivity_session_id,
        future_quic_session_id,
        offer.signaling_generation,
        certificate_commitment,
    )?;
    authenticator.verify(
        &offer,
        offer.sender_role,
        request
            .gathering
            .as_ref()
            .and_then(|value| value.allow_loopback_test)
            .unwrap_or(false),
        now_unix_ms(),
    )?;
    let role = offer.sender_role.opposite();
    let candidate_generation = request.candidate_generation.unwrap_or(1);
    if candidate_generation == 0 {
        return Err("native-signaling-candidate-generation-invalid".into());
    }
    let gathering = request.gathering.unwrap_or_default();
    let cancellation = CancellationToken::new();
    let gathered = gather_connectivity_candidates(
        offer.connectivity_session_id.clone(),
        offer.transfer_id.clone(),
        candidate_generation,
        gathering,
        cancellation.clone(),
    )
    .await?;
    if gathered.local_candidates.is_empty() {
        return Err("native-connectivity-no-local-candidates".into());
    }
    let remote_candidates = offer.payload.candidates().to_vec();
    let mut replay = SignalingReplayWindow::new(offer.signaling_generation);
    replay.accept(&offer)?;
    let envelope = authenticator.sign(
        role,
        candidate_generation,
        gathered.expires_unix_ms,
        0,
        NativeSignalingPayload::NativeConnectivityAnswer {
            candidates: gathered.local_candidates.clone(),
        },
    )?;
    let mut diagnostics = gathered.diagnostics;
    diagnostics.state = ConnectivityStateName::ReadyToCheck;
    let session = Arc::new(ConnectivitySession {
        id: offer.connectivity_session_id.clone(),
        registry_id: StdMutex::new(offer.connectivity_session_id.clone()),
        future_quic_session_id: offer.future_quic_session_id.clone(),
        transfer_id,
        role,
        candidate_generation,
        expires_unix_ms: gathered.expires_unix_ms,
        allow_loopback_test: gathered.allow_loopback_test,
        authenticator,
        local_candidates: gathered.local_candidates.clone(),
        sockets: StdMutex::new(gathered.sockets),
        mapping: Mutex::new(gathered.mapping),
        cancellation,
        mutable: Mutex::new(ConnectivityMutable {
            state: ConnectivityStateName::ReadyToCheck,
            remote_candidates,
            remote_candidate_generation: Some(offer.candidate_generation),
            replay,
            next_sequence: 1,
            checks_active: false,
            nominated_pair: None,
            remote_nomination_authenticated: false,
        }),
        diagnostics: Mutex::new(diagnostics),
        network_snapshot: current_network_snapshot(),
    });
    insert_session(session.clone())?;
    let diagnostics = session.diagnostics.lock().await.clone();
    Ok(ConnectivityEnvelopeResponse {
        connectivity_session_id: session_registry_id(&session)?,
        future_quic_session_id: session.future_quic_session_id.clone(),
        signaling_generation: offer.signaling_generation,
        candidate_generation,
        role,
        encoded_envelope: envelope.encode()?,
        local_candidates: session.local_candidates.clone(),
        diagnostics,
    })
}

pub async fn flowshare_native_add_remote_candidates(
    request: AddRemoteCandidatesRequest,
) -> Result<AddRemoteCandidatesResponse, String> {
    ensure_native_beta_available()?;
    let session = lookup_session(&request.connectivity_session_id)?;
    let envelope = AuthenticatedSignalingEnvelope::decode(&request.encoded_envelope)?;
    let expected_role = session.role.opposite();
    if let Err(error) = session.authenticator.verify(
        &envelope,
        expected_role,
        session.allow_loopback_test,
        now_unix_ms(),
    ) {
        authorization::record_security_rejection(
            "native-connectivity-signaling-rejected",
            session.transfer_id,
            parse_uuid(
                &envelope.invitation_id,
                "native-connectivity-invitation-id-invalid",
            )
            .unwrap_or([0; 16]),
            Some(session.authenticator.connectivity_session_id()),
            &error,
            Some(envelope.candidate_generation as u64),
        );
        return Err(error);
    }
    let mut mutable = session.mutable.lock().await;
    mutable.replay.accept(&envelope)?;
    if mutable
        .remote_candidate_generation
        .is_some_and(|generation| envelope.candidate_generation < generation)
    {
        return Err("native-signaling-candidate-generation-rollback".into());
    }
    let message_type = envelope.payload.message_type().to_string();
    match &envelope.payload {
        NativeSignalingPayload::NativeConnectivityAnswer { candidates }
        | NativeSignalingPayload::NativeCandidateBatch { candidates } => {
            merge_candidates(
                &mut mutable.remote_candidates,
                candidates,
                session.allow_loopback_test,
            )?;
            mutable.remote_candidate_generation = Some(envelope.candidate_generation);
            if !mutable.remote_candidates.is_empty() {
                mutable.state = ConnectivityStateName::ReadyToCheck;
            }
        }
        NativeSignalingPayload::NativeCandidateNomination(nomination) => {
            validate_remote_nomination(&mut mutable, nomination, expected_role)?;
        }
        NativeSignalingPayload::NativeConnectivityCancel { .. } => {
            session.cancellation.cancel();
            mutable.state = ConnectivityStateName::Cancelled;
        }
        NativeSignalingPayload::NativeConnectivityCheckResult(_) => {}
        NativeSignalingPayload::NativeConnectivityOffer { .. } => {
            return Err("native-signaling-unexpected-offer".into())
        }
    }
    let state = mutable.state;
    let remote_candidate_count = mutable.remote_candidates.len();
    drop(mutable);
    session.diagnostics.lock().await.state = state;
    Ok(AddRemoteCandidatesResponse {
        connectivity_session_id: session_registry_id(&session)?,
        accepted_message_type: message_type,
        remote_candidate_count,
        state,
    })
}

pub async fn flowshare_native_start_connectivity_checks(
    request: StartConnectivityChecksRequest,
) -> Result<ConnectivityChecksResponse, String> {
    ensure_native_beta_available()?;
    let session = lookup_session(&request.connectivity_session_id)?;
    if now_unix_ms() > session.expires_unix_ms.saturating_add(30_000) {
        return Err("native-connectivity-session-expired".into());
    }
    let remote_candidates = {
        let mut mutable = session.mutable.lock().await;
        if mutable.checks_active {
            return Err("native-connectivity-checks-already-active".into());
        }
        if mutable.remote_candidates.is_empty() {
            return Err("native-connectivity-remote-candidates-required".into());
        }
        mutable.checks_active = true;
        mutable.state = ConnectivityStateName::Checking;
        mutable.remote_candidates.clone()
    };
    session.diagnostics.lock().await.state = ConnectivityStateName::Checking;
    let pairs = build_candidate_pairs(&session.local_candidates, &remote_candidates, session.role);
    if pairs.is_empty() {
        finish_checks_with_error(&session, "native-connectivity-no-candidate-pairs").await;
        return Err("native-connectivity-no-candidate-pairs".into());
    }
    session.diagnostics.lock().await.candidate_pairs_attempted = pairs.clone();
    let timeout = Duration::from_millis(
        request
            .total_timeout_ms
            .unwrap_or(15_000)
            .clamp(1_000, 30_000),
    );
    let config = HolePunchConfig {
        total_timeout: timeout,
        ..HolePunchConfig::default()
    };
    let mut family_tasks = Vec::new();
    for family in [NativeAddressFamily::Ipv4, NativeAddressFamily::Ipv6] {
        let family_pairs: Vec<_> = pairs
            .iter()
            .filter(|pair| pair.address_family == family)
            .cloned()
            .collect();
        if family_pairs.is_empty() {
            continue;
        }
        let socket = session
            .sockets
            .lock()
            .map_err(|_| "native-connectivity-socket-unavailable")?
            .clone_socket(family)?;
        family_tasks.push(run_authenticated_hole_punch(
            socket,
            family_pairs,
            session.role,
            session.authenticator.clone(),
            config,
            session.cancellation.child_token(),
        ));
    }
    let results = join_all(family_tasks).await;
    let mut reports = Vec::new();
    let mut errors = Vec::new();
    for result in results {
        match result {
            Ok(report) => reports.push(report),
            Err(error) => errors.push(error),
        }
    }
    if reports.is_empty() {
        let error = errors
            .into_iter()
            .next()
            .unwrap_or_else(|| "native-connectivity-checks-failed".into());
        finish_checks_with_error(&session, &error).await;
        return Err(error);
    }
    let combined = combine_hole_punch_reports(reports, &pairs);
    let selected_pair = combined
        .selected_pair_id
        .as_ref()
        .and_then(|id| pairs.iter().find(|pair| &pair.pair_id == id))
        .cloned()
        .map(|pair| pair_with_authenticated_remote_endpoint(pair, &combined));
    let check_result = ConnectivityCheckResultPayload {
        attempted_pair_ids: combined
            .pair_results
            .iter()
            .map(|result| result.pair_id.clone())
            .collect(),
        viable_pair_ids: combined
            .pair_results
            .iter()
            .filter(|result| result.viable)
            .map(|result| result.pair_id.clone())
            .collect(),
        authenticated_probes_sent: combined
            .pair_results
            .iter()
            .map(|result| result.probes_sent)
            .sum(),
        authenticated_probes_received: combined.authenticated_packets_received,
        best_rtt_ms: combined
            .pair_results
            .iter()
            .filter_map(|result| result.best_rtt_ms)
            .reduce(f64::min),
        failure: combined.failure,
    };
    let check_result_sequence = {
        let mut mutable = session.mutable.lock().await;
        let sequence = mutable.next_sequence;
        mutable.next_sequence = mutable.next_sequence.saturating_add(1);
        sequence
    };
    let check_result_envelope = session
        .authenticator
        .sign(
            session.role,
            session.candidate_generation,
            session.expires_unix_ms,
            check_result_sequence,
            NativeSignalingPayload::NativeConnectivityCheckResult(check_result),
        )?
        .encode()?;
    let nomination_envelope = if let Some(pair) = selected_pair.clone() {
        let observation = combined
            .pair_results
            .iter()
            .find(|result| result.pair_id == pair.pair_id);
        let nomination = nomination_payload(&pair, observation);
        let sequence = {
            let mut mutable = session.mutable.lock().await;
            mutable.checks_active = false;
            mutable.state = ConnectivityStateName::Nominated;
            mutable.nominated_pair = Some(pair.clone());
            let sequence = mutable.next_sequence;
            mutable.next_sequence = mutable.next_sequence.saturating_add(1);
            sequence
        };
        Some(
            session
                .authenticator
                .sign(
                    session.role,
                    session.candidate_generation,
                    session.expires_unix_ms,
                    sequence,
                    NativeSignalingPayload::NativeCandidateNomination(nomination),
                )?
                .encode()?,
        )
    } else {
        let mut mutable = session.mutable.lock().await;
        mutable.checks_active = false;
        mutable.state = ConnectivityStateName::Failed;
        None
    };
    let mut diagnostics = session.diagnostics.lock().await;
    diagnostics.apply_hole_punch_report(&combined, selected_pair.as_ref());
    // Nomination proves that STUN and authenticated probes used the prepared
    // socket. Quinn preservation is recorded only after Endpoint::new has
    // successfully adopted a clone and confirmed the local port below.
    diagnostics.same_udp_port_preserved_for_stun_probe_and_quic = false;
    let state = diagnostics.state;
    Ok(ConnectivityChecksResponse {
        connectivity_session_id: session_registry_id(&session)?,
        state,
        check_result_envelope,
        nomination_envelope,
        diagnostics: diagnostics.clone(),
    })
}

pub async fn flowshare_native_get_connectivity_state(
    request: ConnectivitySessionRequest,
) -> Result<ConnectivityStateResponse, String> {
    ensure_native_beta_available()?;
    let session = lookup_session(&request.connectivity_session_id)?;
    let mutable = session.mutable.lock().await;
    let network_change_detected = session.network_snapshot != current_network_snapshot();
    let state = mutable.state;
    let remote_candidate_count = mutable.remote_candidates.len();
    drop(mutable);
    let diagnostics = session.diagnostics.lock().await.clone();
    Ok(ConnectivityStateResponse {
        connectivity_session_id: session_registry_id(&session)?,
        role: session.role,
        state,
        local_candidate_count: session.local_candidates.len(),
        remote_candidate_count,
        network_change_detected,
        renegotiation_required: network_change_detected,
        production_native_enabled: true,
        diagnostics,
    })
}

pub async fn flowshare_native_cancel_connectivity(
    request: ConnectivitySessionRequest,
) -> Result<ConnectivityStateResponse, String> {
    ensure_native_beta_available()?;
    let session = lookup_session(&request.connectivity_session_id)?;
    session.cancellation.cancel();
    if let Some(mapping) = session.mapping.lock().await.take() {
        let final_diagnostic = mapping.shutdown().await;
        session
            .diagnostics
            .lock()
            .await
            .port_mapping_attempts
            .push(final_diagnostic);
    }
    session
        .sockets
        .lock()
        .map_err(|_| "native-connectivity-socket-unavailable")?
        .close();
    {
        let mut mutable = session.mutable.lock().await;
        mutable.state = ConnectivityStateName::Cancelled;
        mutable.checks_active = false;
    }
    {
        let mut diagnostics = session.diagnostics.lock().await;
        diagnostics.state = ConnectivityStateName::Cancelled;
        diagnostics.failure_classification =
            Some(super::connectivity_diagnostics::ConnectivityOutcome::Cancelled);
    }
    flowshare_native_get_connectivity_state(request).await
}

pub(crate) async fn discard_connectivity_session(
    connectivity_session_id: &str,
) -> Result<(), String> {
    let canonical = canonical_registry_id(connectivity_session_id)?;
    flowshare_native_cancel_connectivity(ConnectivitySessionRequest {
        connectivity_session_id: canonical.clone(),
    })
    .await?;
    CONNECTIVITY_SESSIONS
        .lock()
        .map_err(|_| "native-connectivity-registry-unavailable")?
        .remove(&canonical)
        .ok_or_else(|| "native-connectivity-session-not-found".to_string())?;
    Ok(())
}

pub async fn flowshare_native_connectivity_diagnostics(
    request: Option<ConnectivityDiagnosticsRequest>,
) -> Result<NativeConnectivityDiagnostics, String> {
    ensure_native_beta_available()?;
    let request = request.unwrap_or_default();
    let cancellation = CancellationToken::new();
    let gathered = gather_connectivity_candidates(
        Uuid::new_v4().to_string(),
        Uuid::new_v4().to_string(),
        1,
        request.gathering.unwrap_or_default(),
        cancellation,
    )
    .await?;
    let mut diagnostics = gathered.diagnostics;
    if let Some(mapping) = gathered.mapping {
        diagnostics
            .port_mapping_attempts
            .push(mapping.shutdown().await);
    }
    // Temporary diagnostic sockets are dropped here. No candidate is retained or advertised.
    drop(gathered.sockets);
    Ok(diagnostics)
}

async fn gather_connectivity_candidates(
    connectivity_session_id: String,
    transfer_id: String,
    candidate_generation: u32,
    options: ConnectivityGatherOptions,
    cancellation: CancellationToken,
) -> Result<GatheredConnectivity, String> {
    let lifetime_ms = options
        .candidate_lifetime_ms
        .unwrap_or(DEFAULT_SIGNALING_LIFETIME_MS)
        .clamp(MIN_CONNECTIVITY_LIFETIME_MS, MAX_CONNECTIVITY_LIFETIME_MS);
    let expires_unix_ms = now_unix_ms().saturating_add(lifetime_ms);
    let allow_loopback_test = options.allow_loopback_test.unwrap_or(false);
    let sockets = BoundUdpSockets::bind()?;
    let host = gather_host_candidates(HostGatherOptions {
        allow_vpn: options.allow_vpn.unwrap_or(false),
        allow_virtual: options.allow_virtual_adapters.unwrap_or(false),
        allow_loopback_test,
        generation: candidate_generation,
        expires_unix_ms,
        ipv4_port: sockets.port(NativeAddressFamily::Ipv4),
        ipv6_port: sockets.port(NativeAddressFamily::Ipv6),
    });
    let mut diagnostics = NativeConnectivityDiagnostics::empty(
        connectivity_session_id,
        transfer_id,
        candidate_generation,
        existing_signaling_adapter_status(),
    );
    diagnostics.firewall.udp_bind_succeeded = true;
    diagnostics.interfaces_examined = host.diagnostics;
    diagnostics.host_candidates = host.candidates.clone();
    let mut candidates = host.candidates;
    let mut combined_stun = StunDiscoveryReport::default();
    if options.enable_stun.unwrap_or(true) {
        let servers = options
            .stun_servers
            .unwrap_or_else(default_development_stun_servers);
        for family in [NativeAddressFamily::Ipv4, NativeAddressFamily::Ipv6] {
            let Ok(socket) = sockets.clone_socket(family) else {
                continue;
            };
            let related = candidates
                .iter()
                .find(|candidate| candidate.address_family == family)
                .map(NativeCandidate::socket_addr);
            let report = discover_server_reflexive_candidates(
                &socket,
                family,
                related,
                &servers,
                StunQueryPolicy {
                    attempts_per_server: 2,
                    request_timeout: Duration::from_millis(1200),
                    generation: candidate_generation,
                    expires_unix_ms,
                },
                &cancellation,
            )
            .await?;
            combined_stun.observations.extend(report.observations);
            combined_stun.candidates.extend(report.candidates);
            combined_stun.udp_blocked_or_heavily_filtered |= report.udp_blocked_or_heavily_filtered;
            if report.mapping_behavior != ObservedNatMappingBehavior::Unknown {
                combined_stun.mapping_behavior = report.mapping_behavior;
                combined_stun.mapping_consistent = report.mapping_consistent;
            }
        }
        diagnostics.firewall.outbound_stun_succeeded = combined_stun
            .observations
            .iter()
            .any(|observation| observation.discovered_public_endpoint.is_some());
        diagnostics.stun_results = combined_stun.observations.clone();
        diagnostics.observed_nat_mapping = combined_stun.mapping_behavior;
        diagnostics.mapping_consistent_across_stun_servers = combined_stun.mapping_consistent;
        candidates.extend(combined_stun.candidates.clone());
    }
    let mapping_options = options.port_mapping.unwrap_or_default();
    let mut mapping = None;
    if let Some(port) = sockets.port(NativeAddressFamily::Ipv4) {
        let started = start_optional_port_mapping(
            port,
            candidate_generation,
            expires_unix_ms,
            &mapping_options,
            &cancellation,
        )
        .await?;
        diagnostics.port_mapping_attempts = started.attempts;
        if let Some(active) = started.active {
            diagnostics.mapped_candidates.push(active.candidate.clone());
            candidates.push(active.candidate.clone());
            mapping = Some(active);
        }
    }
    for mut manual in options.manual_candidates.unwrap_or_default() {
        if manual.port == 0 {
            manual.port = sockets
                .port(NativeAddressFamily::for_ip(manual.address))
                .ok_or("native-manual-candidate-family-unavailable")?;
        }
        candidates.push(manual.into_candidate(
            candidate_generation,
            expires_unix_ms,
            allow_loopback_test,
        )?);
    }
    deduplicate_candidates(&mut candidates);
    let policy = options.privacy_policy.unwrap_or_default();
    let candidates = apply_privacy_policy(
        candidates,
        policy,
        options.expected_same_lan.unwrap_or(false),
        options.all_direct_approved.unwrap_or(false),
    )?;
    validate_candidate_batch(&candidates, allow_loopback_test, now_unix_ms())?;
    diagnostics.state = ConnectivityStateName::Gathering;
    Ok(GatheredConnectivity {
        sockets,
        local_candidates: candidates,
        mapping,
        diagnostics,
        expires_unix_ms,
        allow_loopback_test,
    })
}

fn combine_hole_punch_reports(
    reports: Vec<HolePunchReport>,
    pairs: &[NativeCandidatePair],
) -> HolePunchReport {
    let started_unix_ms = reports
        .iter()
        .map(|report| report.started_unix_ms)
        .min()
        .unwrap_or_else(now_unix_ms);
    let elapsed_ms = reports
        .iter()
        .map(|report| report.elapsed_ms)
        .fold(0.0, f64::max);
    let selected_pair_id = reports
        .iter()
        .filter_map(|report| report.selected_pair_id.as_ref())
        .filter_map(|id| pairs.iter().find(|pair| &pair.pair_id == id))
        .max_by_key(|pair| pair.priority)
        .map(|pair| pair.pair_id.clone());
    let failure = if selected_pair_id.is_some() {
        None
    } else if reports.iter().all(|report| {
        report.failure == Some(super::signaling::NativeConnectivityFailure::UdpBlocked)
    }) {
        Some(super::signaling::NativeConnectivityFailure::UdpBlocked)
    } else {
        Some(super::signaling::NativeConnectivityFailure::NoViablePair)
    };
    HolePunchReport {
        started_unix_ms,
        elapsed_ms,
        total_packets_sent: reports.iter().map(|value| value.total_packets_sent).sum(),
        total_packets_received: reports
            .iter()
            .map(|value| value.total_packets_received)
            .sum(),
        authenticated_packets_received: reports
            .iter()
            .map(|value| value.authenticated_packets_received)
            .sum(),
        unauthenticated_packets_dropped: reports
            .iter()
            .map(|value| value.unauthenticated_packets_dropped)
            .sum(),
        replayed_packets_dropped: reports
            .iter()
            .map(|value| value.replayed_packets_dropped)
            .sum(),
        rate_limit_packets_per_second: reports
            .iter()
            .map(|value| value.rate_limit_packets_per_second)
            .max()
            .unwrap_or(64),
        pair_results: reports
            .into_iter()
            .flat_map(|report| report.pair_results)
            .collect(),
        selected_pair_id,
        failure,
    }
}

fn nomination_payload(
    pair: &NativeCandidatePair,
    observation: Option<&super::hole_punch::ProbePairResult>,
) -> NativeCandidateNominationPayload {
    let (sender_endpoint, receiver_endpoint) =
        if pair.local_candidate.candidate_id == pair.sender_candidate_id {
            (
                pair.local_candidate.socket_addr(),
                pair.remote_socket_addr(),
            )
        } else {
            (
                pair.remote_socket_addr(),
                pair.local_candidate.socket_addr(),
            )
        };
    NativeCandidateNominationPayload {
        pair_id: pair.pair_id.clone(),
        sender_candidate_id: pair.sender_candidate_id.clone(),
        receiver_candidate_id: pair.receiver_candidate_id.clone(),
        sender_observed_endpoint: sender_endpoint.to_string(),
        receiver_observed_endpoint: receiver_endpoint.to_string(),
        measured_rtt_ms: observation
            .and_then(|value| value.best_rtt_ms)
            .unwrap_or(0.0),
        confirmation_count: observation.map_or(2, |value| value.confirmation_count.max(2)),
    }
}

fn validate_remote_nomination(
    mutable: &mut ConnectivityMutable,
    nomination: &NativeCandidateNominationPayload,
    remote_role: NativeDeviceRole,
) -> Result<(), String> {
    let local = mutable
        .nominated_pair
        .as_ref()
        .ok_or("native-signaling-nomination-before-direct-verification")?;
    if nomination.pair_id != local.pair_id
        || nomination.sender_candidate_id != local.sender_candidate_id
        || nomination.receiver_candidate_id != local.receiver_candidate_id
    {
        return Err("native-signaling-nomination-inconsistent".into());
    }
    let sender: SocketAddr = nomination
        .sender_observed_endpoint
        .parse()
        .map_err(|_| "native-signaling-nomination-invalid")?;
    let receiver: SocketAddr = nomination
        .receiver_observed_endpoint
        .parse()
        .map_err(|_| "native-signaling-nomination-invalid")?;
    let (remote_claim, local_claim) = if remote_role == NativeDeviceRole::Sender {
        (sender, receiver)
    } else {
        (receiver, sender)
    };
    let expected_remote_advertised = local.remote_candidate.socket_addr();
    let expected_remote_authenticated = local.remote_socket_addr();
    if !matches!(remote_claim, value if value == expected_remote_advertised || value == expected_remote_authenticated)
        || remote_claim.port() == 0
        || local_claim.port() == 0
        || remote_claim.ip().is_unspecified()
        || local_claim.ip().is_unspecified()
        || remote_claim.ip().is_multicast()
        || local_claim.ip().is_multicast()
        || NativeAddressFamily::for_ip(remote_claim.ip()) != local.address_family
        || NativeAddressFamily::for_ip(local_claim.ip()) != local.address_family
    {
        return Err("native-signaling-nomination-endpoint-changed".into());
    }
    // The sender role wins a simultaneous nomination tie, but both nominations
    // must identify the same already-verified direct pair.
    if remote_role == NativeDeviceRole::Sender || !mutable.remote_nomination_authenticated {
        mutable.remote_nomination_authenticated = true;
    }
    Ok(())
}

fn pair_with_authenticated_remote_endpoint(
    mut pair: NativeCandidatePair,
    report: &HolePunchReport,
) -> NativeCandidatePair {
    let observed = report
        .pair_results
        .iter()
        .find(|result| result.pair_id == pair.pair_id && result.viable)
        .filter(|result| result.source_endpoint_stable)
        .and_then(|result| result.observed_source_endpoint.as_deref())
        .and_then(|value| value.parse::<SocketAddr>().ok())
        .filter(|endpoint| {
            endpoint.port() != 0
                && !endpoint.ip().is_unspecified()
                && !endpoint.ip().is_multicast()
                && NativeAddressFamily::for_ip(endpoint.ip()) == pair.address_family
        });
    if let Some(observed) = observed {
        if observed != pair.remote_candidate.socket_addr() {
            pair.peer_reflexive_remote_endpoint = Some(observed);
        }
    }
    pair
}

fn merge_candidates(
    existing: &mut Vec<NativeCandidate>,
    incoming: &[NativeCandidate],
    allow_loopback: bool,
) -> Result<(), String> {
    let mut combined = existing.clone();
    combined.extend_from_slice(incoming);
    deduplicate_candidates(&mut combined);
    validate_candidate_batch(&combined, allow_loopback, now_unix_ms())?;
    *existing = combined;
    Ok(())
}

fn deduplicate_candidates(candidates: &mut Vec<NativeCandidate>) {
    candidates.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left.candidate_id.cmp(&right.candidate_id))
    });
    let mut seen = BTreeSet::new();
    candidates.retain(|candidate| {
        seen.insert((candidate.candidate_type, candidate.address, candidate.port))
    });
    candidates.truncate(MAX_NATIVE_CANDIDATES);
}

async fn finish_checks_with_error(session: &ConnectivitySession, error: &str) {
    {
        let mut mutable = session.mutable.lock().await;
        mutable.checks_active = false;
        mutable.state = ConnectivityStateName::Failed;
    }
    let mut diagnostics = session.diagnostics.lock().await;
    diagnostics.state = ConnectivityStateName::Failed;
    diagnostics.last_error = Some(error.to_string());
}

fn insert_session(session: Arc<ConnectivitySession>) -> Result<(), String> {
    let mut sessions = CONNECTIVITY_SESSIONS
        .lock()
        .map_err(|_| "native-connectivity-registry-unavailable")?;
    let now = now_unix_ms();
    sessions.retain(|_, value| value.expires_unix_ms.saturating_add(30_000) >= now);
    let mut registry_id = session.id.clone();
    if sessions.contains_key(&registry_id) {
        registry_id = format!("{}@{}", session.id, role_label(session.role));
    }
    if sessions.len() >= MAX_CONNECTIVITY_SESSIONS && !sessions.contains_key(&registry_id) {
        return Err("native-connectivity-session-limit-reached".into());
    }
    if sessions.contains_key(&registry_id) {
        return Err("native-connectivity-session-already-exists".into());
    }
    *session
        .registry_id
        .lock()
        .map_err(|_| "native-connectivity-registry-unavailable")? = registry_id.clone();
    sessions.insert(registry_id, session);
    Ok(())
}

fn lookup_session(id: &str) -> Result<Arc<ConnectivitySession>, String> {
    let canonical = canonical_registry_id(id)?;
    CONNECTIVITY_SESSIONS
        .lock()
        .map_err(|_| "native-connectivity-registry-unavailable")?
        .get(&canonical)
        .cloned()
        .ok_or_else(|| "native-connectivity-session-not-found".into())
}

fn session_registry_id(session: &ConnectivitySession) -> Result<String, String> {
    session
        .registry_id
        .lock()
        .map(|value| value.clone())
        .map_err(|_| "native-connectivity-registry-unavailable".into())
}

fn role_label(role: NativeDeviceRole) -> &'static str {
    match role {
        NativeDeviceRole::Sender => "sender",
        NativeDeviceRole::Receiver => "receiver",
    }
}

fn canonical_registry_id(id: &str) -> Result<String, String> {
    let (wire_id, suffix) = id
        .split_once('@')
        .map_or((id, None), |(wire, suffix)| (wire, Some(suffix)));
    let wire_id = Uuid::parse_str(wire_id)
        .map_err(|_| "native-connectivity-session-id-invalid")?
        .to_string();
    match suffix {
        None => Ok(wire_id),
        Some(label @ ("sender" | "receiver")) => Ok(format!("{wire_id}@{label}")),
        Some(_) => Err("native-connectivity-session-id-invalid".into()),
    }
}

fn parse_uuid(value: &str, error: &str) -> Result<[u8; 16], String> {
    Ok(*Uuid::parse_str(value)
        .map_err(|_| error.to_string())?
        .as_bytes())
}

fn random_nonzero_u64() -> u64 {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    u64::from_be_bytes(bytes).max(1)
}

fn current_network_snapshot() -> [u8; 32] {
    let mut interfaces: Vec<_> = netdev::interface::get_interfaces()
        .into_iter()
        .flat_map(|interface| {
            let name = interface.name.clone();
            let mut rows: Vec<String> = interface
                .ipv4_addrs()
                .into_iter()
                .map(|address| format!("{name}|4|{address}"))
                .collect();
            rows.extend(
                interface
                    .ipv6_addrs()
                    .into_iter()
                    .map(|address| format!("{name}|6|{address}")),
            );
            rows
        })
        .collect();
    interfaces.sort();
    let mut digest = Sha256::new();
    for row in interfaces {
        digest.update((row.len() as u16).to_be_bytes());
        digest.update(row.as_bytes());
    }
    digest.finalize().into()
}

fn ensure_native_beta_available() -> Result<(), String> {
    Ok(())
}

async fn nominated_socket_clone(
    connectivity_session_id: &str,
) -> Result<(UdpSocket, NativeCandidatePair), String> {
    let session = lookup_session(connectivity_session_id)?;
    let pair = session
        .mutable
        .lock()
        .await
        .nominated_pair
        .clone()
        .ok_or("native-connectivity-path-not-nominated")?;
    let socket = session
        .sockets
        .lock()
        .map_err(|_| "native-connectivity-socket-unavailable")?
        .clone_socket(pair.address_family)?;
    Ok((socket, pair))
}

pub async fn server_endpoint_for_nominated_path(
    connectivity_session_id: &str,
    server_config: quinn::ServerConfig,
) -> Result<
    (
        quinn::Endpoint,
        NativeCandidatePair,
        super::quinn_connectivity::QuinnSocketHandoffDiagnostic,
    ),
    String,
> {
    let (socket, pair) = nominated_socket_clone(connectivity_session_id).await?;
    let (endpoint, diagnostic) =
        super::quinn_connectivity::server_endpoint_from_prepared_socket(socket, server_config)?;
    record_quinn_socket_handoff(connectivity_session_id, &diagnostic).await;
    Ok((endpoint, pair, diagnostic))
}

pub async fn client_endpoint_for_nominated_path(
    connectivity_session_id: &str,
    client_config: quinn::ClientConfig,
) -> Result<
    (
        quinn::Endpoint,
        NativeCandidatePair,
        super::quinn_connectivity::QuinnSocketHandoffDiagnostic,
    ),
    String,
> {
    let (socket, pair) = nominated_socket_clone(connectivity_session_id).await?;
    let (endpoint, diagnostic) =
        super::quinn_connectivity::client_endpoint_from_prepared_socket(socket, client_config)?;
    record_quinn_socket_handoff(connectivity_session_id, &diagnostic).await;
    Ok((endpoint, pair, diagnostic))
}

pub async fn nominated_path_context(
    connectivity_session_id: &str,
    expected_transfer_id: [u8; 16],
    expected_role: NativeDeviceRole,
) -> Result<NominatedPathContext, String> {
    let session = lookup_session(connectivity_session_id)?;
    if session.transfer_id != expected_transfer_id {
        return Err("native-connectivity-transfer-mismatch".into());
    }
    if session.role != expected_role {
        return Err("native-connectivity-role-mismatch".into());
    }
    if now_unix_ms() > session.expires_unix_ms.saturating_add(30_000) {
        return Err("native-connectivity-session-expired".into());
    }
    let mutable = session.mutable.lock().await;
    if mutable.state != ConnectivityStateName::Nominated {
        return Err("native-connectivity-path-not-nominated".into());
    }
    if !mutable.remote_nomination_authenticated {
        return Err("native-connectivity-peer-nomination-required".into());
    }
    let pair = mutable
        .nominated_pair
        .clone()
        .ok_or("native-connectivity-path-not-nominated")?;
    drop(mutable);
    Ok(NominatedPathContext {
        connectivity_session_id: session_registry_id(&session)?,
        future_quic_session_id: parse_uuid(
            &session.future_quic_session_id,
            "native-connectivity-quic-session-id-invalid",
        )?,
        transfer_id: session.transfer_id,
        role: session.role,
        pair,
        expires_unix_ms: session.expires_unix_ms,
    })
}

async fn record_quinn_socket_handoff(
    connectivity_session_id: &str,
    handoff: &super::quinn_connectivity::QuinnSocketHandoffDiagnostic,
) {
    let Ok(session) = lookup_session(connectivity_session_id) else {
        return;
    };
    let mut diagnostics = session.diagnostics.lock().await;
    diagnostics.same_udp_port_preserved_for_stun_probe_and_quic = handoff.same_local_port;
    diagnostics.quinn_udp_buffer_target_bytes = handoff.requested_udp_buffer_bytes;
    diagnostics.quinn_udp_send_buffer_bytes = Some(handoff.udp_send_buffer_bytes);
    diagnostics.quinn_udp_receive_buffer_bytes = Some(handoff.udp_receive_buffer_bytes);
}

#[cfg(test)]
pub fn clear_for_test() {
    if let Ok(mut sessions) = CONNECTIVITY_SESSIONS.lock() {
        for session in sessions.values() {
            session.cancellation.cancel();
        }
        sessions.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authorization::{clear_for_test as clear_auth, create_registered_invitation},
        candidates::NativeCandidateType,
        hole_punch::ProbePairResult,
    };

    fn manual_pair(role: NativeDeviceRole) -> NativeCandidatePair {
        let sender = ManualCandidateInput {
            address: "198.51.100.10".parse().unwrap(),
            port: 40_000,
            priority: None,
        }
        .into_candidate(1, now_unix_ms() + 60_000, false)
        .unwrap();
        let receiver = ManualCandidateInput {
            address: "203.0.113.20".parse().unwrap(),
            port: 41_000,
            priority: None,
        }
        .into_candidate(1, now_unix_ms() + 60_000, false)
        .unwrap();
        let (local, remote) = if role == NativeDeviceRole::Sender {
            (sender, receiver)
        } else {
            (receiver, sender)
        };
        build_candidate_pairs(&[local], &[remote], role).remove(0)
    }

    fn loopback_gathering() -> ConnectivityGatherOptions {
        ConnectivityGatherOptions {
            privacy_policy: Some(CandidatePrivacyPolicy::Manual),
            expected_same_lan: Some(true),
            all_direct_approved: Some(false),
            allow_vpn: Some(false),
            allow_virtual_adapters: Some(false),
            allow_loopback_test: Some(true),
            enable_stun: Some(false),
            stun_servers: None,
            manual_candidates: Some(vec![ManualCandidateInput {
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 0,
                priority: None,
            }]),
            port_mapping: None,
            candidate_lifetime_ms: Some(60_000),
        }
    }

    #[tokio::test]
    async fn command_level_offer_and_answer_are_authenticated() {
        clear_for_test();
        clear_auth();
        let transfer = Uuid::new_v4();
        create_registered_invitation(*transfer.as_bytes(), [4; 32], 7, 60_000).unwrap();
        let offer = flowshare_native_create_connectivity_offer(CreateConnectivityOfferRequest {
            transfer_id: transfer.to_string(),
            role: Some(NativeDeviceRole::Sender),
            signaling_generation: Some(1),
            candidate_generation: Some(1),
            future_quic_session_id: Some(Uuid::new_v4().to_string()),
            gathering: Some(loopback_gathering()),
        })
        .await
        .unwrap();
        assert_eq!(
            offer.local_candidates[0].candidate_type,
            NativeCandidateType::Manual
        );
        // A real peer has a separate process-local registry. Remove the sender
        // instance before simulating the receiver in this process.
        CONNECTIVITY_SESSIONS
            .lock()
            .unwrap()
            .remove(&offer.connectivity_session_id);
        let answer = flowshare_native_accept_connectivity_offer(AcceptConnectivityOfferRequest {
            encoded_offer: offer.encoded_envelope,
            candidate_generation: Some(1),
            gathering: Some(loopback_gathering()),
        })
        .await
        .unwrap();
        assert_eq!(
            answer.diagnostics.state,
            ConnectivityStateName::ReadyToCheck
        );
        assert_eq!(
            answer.diagnostics.file_payload_bytes_sent_through_signaling,
            0
        );
    }

    #[tokio::test]
    async fn cancellation_closes_session_with_native_beta_available() {
        clear_for_test();
        clear_auth();
        let transfer = Uuid::new_v4();
        create_registered_invitation(*transfer.as_bytes(), [5; 32], 7, 60_000).unwrap();
        let offer = flowshare_native_create_connectivity_offer(CreateConnectivityOfferRequest {
            transfer_id: transfer.to_string(),
            role: None,
            signaling_generation: Some(2),
            candidate_generation: Some(1),
            future_quic_session_id: None,
            gathering: Some(loopback_gathering()),
        })
        .await
        .unwrap();
        let state = flowshare_native_cancel_connectivity(ConnectivitySessionRequest {
            connectivity_session_id: offer.connectivity_session_id,
        })
        .await
        .unwrap();
        assert_eq!(state.state, ConnectivityStateName::Cancelled);
        assert!(state.production_native_enabled);
    }

    #[tokio::test]
    async fn discarded_failed_attempt_releases_the_registry_slot() {
        clear_for_test();
        clear_auth();
        let transfer = Uuid::new_v4();
        create_registered_invitation(*transfer.as_bytes(), [6; 32], 7, 60_000).unwrap();
        let offer = flowshare_native_create_connectivity_offer(CreateConnectivityOfferRequest {
            transfer_id: transfer.to_string(),
            role: Some(NativeDeviceRole::Sender),
            signaling_generation: Some(3),
            candidate_generation: Some(1),
            future_quic_session_id: None,
            gathering: Some(loopback_gathering()),
        })
        .await
        .unwrap();
        let session_id = offer.connectivity_session_id;
        assert!(lookup_session(&session_id).is_ok());
        discard_connectivity_session(&session_id).await.unwrap();
        assert_eq!(
            lookup_session(&session_id).err().unwrap(),
            "native-connectivity-session-not-found"
        );
    }

    #[tokio::test]
    async fn authenticated_check_result_is_accepted_once_and_replay_rejected() {
        clear_for_test();
        clear_auth();
        let transfer = Uuid::new_v4();
        create_registered_invitation(*transfer.as_bytes(), [7; 32], 7, 60_000).unwrap();
        let offer = flowshare_native_create_connectivity_offer(CreateConnectivityOfferRequest {
            transfer_id: transfer.to_string(),
            role: Some(NativeDeviceRole::Sender),
            signaling_generation: Some(4),
            candidate_generation: Some(1),
            future_quic_session_id: None,
            gathering: Some(loopback_gathering()),
        })
        .await
        .unwrap();
        let session = lookup_session(&offer.connectivity_session_id).unwrap();
        let result = session
            .authenticator
            .sign(
                NativeDeviceRole::Receiver,
                1,
                session.expires_unix_ms,
                0,
                NativeSignalingPayload::NativeConnectivityCheckResult(
                    ConnectivityCheckResultPayload {
                        attempted_pair_ids: Vec::new(),
                        viable_pair_ids: Vec::new(),
                        authenticated_probes_sent: 1,
                        authenticated_probes_received: 0,
                        best_rtt_ms: None,
                        failure: Some(
                            super::super::signaling::NativeConnectivityFailure::UdpBlocked,
                        ),
                    },
                ),
            )
            .unwrap()
            .encode()
            .unwrap();
        let request = || AddRemoteCandidatesRequest {
            connectivity_session_id: offer.connectivity_session_id.clone(),
            encoded_envelope: result.clone(),
        };
        let accepted = flowshare_native_add_remote_candidates(request())
            .await
            .unwrap();
        assert_eq!(
            accepted.accepted_message_type,
            "native-connectivity-check-result"
        );
        assert_eq!(
            flowshare_native_add_remote_candidates(request())
                .await
                .unwrap_err(),
            "native-signaling-replay-detected"
        );
    }

    #[test]
    fn stable_authenticated_peer_reflexive_endpoint_is_carried_to_quinn() {
        let pair = manual_pair(NativeDeviceRole::Sender);
        let observed: SocketAddr = "203.0.113.20:51000".parse().unwrap();
        let result = ProbePairResult {
            pair_id: pair.pair_id.clone(),
            source_endpoint_stable: true,
            observed_source_endpoint: Some(observed.to_string()),
            viable: true,
            ..ProbePairResult::default()
        };
        let report = HolePunchReport {
            started_unix_ms: now_unix_ms(),
            elapsed_ms: 1.0,
            total_packets_sent: 4,
            total_packets_received: 4,
            authenticated_packets_received: 4,
            unauthenticated_packets_dropped: 0,
            replayed_packets_dropped: 0,
            rate_limit_packets_per_second: 64,
            pair_results: vec![result],
            selected_pair_id: Some(pair.pair_id.clone()),
            failure: None,
        };

        let learned = pair_with_authenticated_remote_endpoint(pair.clone(), &report);
        assert_eq!(learned.remote_socket_addr(), observed);
        assert_eq!(learned.peer_reflexive_remote_endpoint, Some(observed));

        let mut unstable = report;
        unstable.pair_results[0].source_endpoint_stable = false;
        let unchanged = pair_with_authenticated_remote_endpoint(pair.clone(), &unstable);
        assert_eq!(
            unchanged.remote_socket_addr(),
            pair.remote_candidate.socket_addr()
        );
        assert_eq!(unchanged.peer_reflexive_remote_endpoint, None);
    }

    #[test]
    fn nomination_accepts_only_authenticated_remote_endpoint_learning() {
        let mut pair = manual_pair(NativeDeviceRole::Sender);
        let authenticated_remote: SocketAddr = "203.0.113.20:51000".parse().unwrap();
        pair.peer_reflexive_remote_endpoint = Some(authenticated_remote);
        let mut mutable = ConnectivityMutable {
            state: ConnectivityStateName::Nominated,
            remote_candidates: vec![pair.remote_candidate.clone()],
            remote_candidate_generation: Some(1),
            replay: SignalingReplayWindow::default(),
            next_sequence: 1,
            checks_active: false,
            nominated_pair: Some(pair.clone()),
            remote_nomination_authenticated: false,
        };
        let mut nomination = nomination_payload(&pair, None);
        // The remote peer may report the NAT-rewritten endpoint it observed
        // for us. It is informational here and never becomes our destination.
        nomination.sender_observed_endpoint = "198.51.100.10:55000".into();
        assert!(
            validate_remote_nomination(&mut mutable, &nomination, NativeDeviceRole::Receiver,)
                .is_ok()
        );

        nomination.receiver_observed_endpoint = "203.0.113.20:52000".into();
        assert_eq!(
            validate_remote_nomination(&mut mutable, &nomination, NativeDeviceRole::Receiver,)
                .unwrap_err(),
            "native-signaling-nomination-endpoint-changed"
        );
    }

    #[tokio::test]
    async fn nominated_socket_handoff_waits_for_state_lock_instead_of_failing_busy() {
        clear_for_test();
        clear_auth();
        let transfer = Uuid::new_v4();
        create_registered_invitation(*transfer.as_bytes(), [6; 32], 7, 60_000).unwrap();
        let offer = flowshare_native_create_connectivity_offer(CreateConnectivityOfferRequest {
            transfer_id: transfer.to_string(),
            role: Some(NativeDeviceRole::Sender),
            signaling_generation: Some(1),
            candidate_generation: Some(1),
            future_quic_session_id: Some(Uuid::new_v4().to_string()),
            gathering: Some(loopback_gathering()),
        })
        .await
        .unwrap();
        let session = lookup_session(&offer.connectivity_session_id).unwrap();
        let pair = build_candidate_pairs(
            &[offer.local_candidates[0].clone()],
            &[offer.local_candidates[0].clone()],
            NativeDeviceRole::Sender,
        )
        .remove(0);
        session.mutable.lock().await.nominated_pair = Some(pair);

        let guard = session.mutable.lock().await;
        let session_id = offer.connectivity_session_id.clone();
        let handoff = tokio::spawn(async move { nominated_socket_clone(&session_id).await });
        tokio::task::yield_now().await;
        assert!(!handoff.is_finished());
        drop(guard);
        let (socket, _) = tokio::time::timeout(Duration::from_secs(1), handoff)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_ne!(socket.local_addr().unwrap().port(), 0);
        clear_for_test();
    }
}
