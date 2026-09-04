use super::{
    authorization,
    authorization_delivery::{
        decode_manual_invitation_package, decode_receiver_bootstrap,
        export_manual_invitation_package, prepare_receiver_bootstrap, PreparedReceiverBootstrap,
        MANUAL_PACKAGE_POSSESSION_WARNING,
    },
    candidates::CandidatePrivacyPolicy,
    connectivity::{
        self, AcceptConnectivityOfferRequest, AddRemoteCandidatesRequest,
        ConnectivityChecksResponse, ConnectivityGatherOptions, CreateConnectivityOfferRequest,
        StartConnectivityChecksRequest,
    },
    file_transfer::{now_unix_ms, sha256_file},
    protocol::RESUME_REQUIRED_CAPABILITIES,
    secret_store,
    secure_protocol::DEFAULT_INVITATION_LIFETIME_MS,
    security::EphemeralIdentity,
    signaling::{
        AuthenticatedSignalingEnvelope, ConnectivityCheckResultPayload, NativeConnectivityFailure,
        NativeDeviceRole, NativeSignalingPayload,
    },
    signaling_websocket::{
        NativeWebSocketRole, NativeWebSocketSignalingOptions, NativeWebSocketSignalingTransport,
    },
    split_resume, split_transfer,
};
use fs2::available_space;
use futures::FutureExt;
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use sha2_compat::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    io::SeekFrom,
    panic::AssertUnwindSafe,
    path::{Component, Path, PathBuf},
    sync::{Arc, LazyLock},
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    fs::{self, OpenOptions},
    io::{AsyncSeekExt, AsyncWriteExt},
    sync::Mutex,
    task::{AbortHandle, JoinHandle},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const NATIVE_BLOCK_BYTES: usize = 2 * 1024 * 1024;
const MAX_SPLIT_ROLE_RECORDS: usize = 64;
const DEFAULT_MANUAL_PACKAGE_LIFETIME_MS: u64 = 10 * 60 * 1000;
const RECEIPT_MAGIC: [u8; 16] = *b"FQINVRECEIPT0004";
const INCOMING_RETENTION_VERSION: u16 = 1;
const MAX_INCOMING_RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1000;

static RECEIVER_BOOTSTRAPS: LazyLock<Mutex<HashMap<String, ReceiverBootstrapRecord>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static OUTGOING_TRANSFERS: LazyLock<Mutex<HashMap<String, Arc<OutgoingNativeTransfer>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static INCOMING_TRANSFERS: LazyLock<Mutex<HashMap<String, Arc<IncomingNativeTransfer>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static IMPORTED_PACKAGE_DIGESTS: LazyLock<Mutex<HashSet<[u8; 32]>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));
static RECEIPT_COMMIT_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
static INCOMING_RESUME_SETUP_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
const MAX_DIRECT_CONNECT_ATTEMPTS: u32 = 2;

struct ReceiverBootstrapRecord {
    identity: EphemeralIdentity,
    expires_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum NativeAuthorizationDeliveryMode {
    ManualPackage,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum OutgoingNativeState {
    Created,
    AwaitingReceiver,
    AuthorizationDelivering,
    GatheringCandidates,
    Connecting,
    Transferring,
    Finalizing,
    Paused,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum IncomingNativeState {
    InvitationImported,
    AwaitingAcceptance,
    Accepted,
    GatheringCandidates,
    Connecting,
    Receiving,
    Finalizing,
    Paused,
    Completed,
    Cancelled,
    Declined,
    Failed,
}

pub(crate) struct OutgoingNativeTransfer {
    pub(crate) transfer_id: String,
    pub(crate) invitation_id: String,
    pub(crate) source_path: PathBuf,
    pub(crate) source_identity: super::resume::SourceIdentity,
    pub(crate) display_filename: String,
    pub(crate) file_size: u64,
    pub(crate) expected_sha256: [u8; 32],
    pub(crate) receiver_certificate: CertificateDer<'static>,
    pub(crate) receiver_certificate_fingerprint_sha256: [u8; 32],
    pub(crate) candidate_privacy_policy: CandidatePrivacyPolicy,
    pub(crate) authorization_resume_path: PathBuf,
    pub(crate) outgoing_state_path: PathBuf,
    pub(crate) previous_quic_session_id: Option<String>,
    pub(crate) expires_unix_ms: u64,
    pub(crate) created_unix_ms: u64,
    pub(crate) mutable: Mutex<OutgoingMutable>,
}

pub(crate) struct OutgoingMutable {
    pub(crate) state: OutgoingNativeState,
    pub(crate) control_request: CancellationToken,
    pub(crate) cancellation: CancellationToken,
    pub(crate) local_stop: Option<LocalStopIntent>,
    pub(crate) pause_request_id: Option<[u8; 16]>,
    pub(crate) task_abort: Option<AbortHandle>,
    pub(crate) connectivity_session_id: Option<String>,
    pub(crate) quic_session_id: Option<String>,
    pub(crate) selected_path: Option<String>,
    pub(crate) bytes_sent: u64,
    pub(crate) bytes_skipped: u64,
    pub(crate) peer_checkpoint_generation: Option<u64>,
    pub(crate) peer_state_digest: Option<[u8; 32]>,
    pub(crate) peer_completed_bytes: u64,
    pub(crate) integrity_result: Option<String>,
    pub(crate) performance: Option<split_transfer::SplitTransferResult>,
    pub(crate) signaling_file_payload_bytes: u64,
    pub(crate) terminal_error: Option<String>,
}

pub(crate) struct IncomingNativeTransfer {
    pub(crate) transfer_id: String,
    pub(crate) invitation_id: String,
    pub(crate) destination_directory: Mutex<PathBuf>,
    pub(crate) artifact_directory: Mutex<PathBuf>,
    pub(crate) authorization_resume_path: Mutex<PathBuf>,
    pub(crate) receiver_identity: Mutex<Option<EphemeralIdentity>>,
    pub(crate) receiver_certificate_fingerprint_sha256: [u8; 32],
    pub(crate) expires_unix_ms: u64,
    pub(crate) retention_expires_unix_ms: u64,
    pub(crate) created_unix_ms: u64,
    pub(crate) mutable: Mutex<IncomingMutable>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistedIncomingRetention {
    version: u16,
    transfer_id: String,
    destination_directory: String,
    created_unix_ms: u64,
    expires_unix_ms: u64,
}

pub(crate) struct IncomingMutable {
    pub(crate) state: IncomingNativeState,
    pub(crate) control_request: CancellationToken,
    pub(crate) cancellation: CancellationToken,
    pub(crate) local_stop: Option<LocalStopIntent>,
    pub(crate) peer_cancel_retain_partial: Option<bool>,
    pub(crate) pause_request_id: Option<[u8; 16]>,
    pub(crate) task_abort: Option<AbortHandle>,
    pub(crate) connectivity_session_id: Option<String>,
    pub(crate) quic_session_id: Option<String>,
    pub(crate) selected_path: Option<String>,
    pub(crate) accepted_filename: Option<String>,
    pub(crate) expected_file_size: Option<u64>,
    pub(crate) expected_sha256: Option<[u8; 32]>,
    pub(crate) final_path: Option<PathBuf>,
    pub(crate) part_path: Option<PathBuf>,
    pub(crate) bytes_received: u64,
    pub(crate) bytes_written: u64,
    pub(crate) bytes_skipped: u64,
    pub(crate) committed_intervals: Vec<(u64, u64)>,
    pub(crate) checkpoint_generation: u64,
    pub(crate) secure_state_digest: Option<[u8; 32]>,
    pub(crate) completed_checkpoint_bytes: u64,
    pub(crate) integrity_result: Option<String>,
    pub(crate) performance: Option<split_transfer::SplitTransferResult>,
    pub(crate) signaling_file_payload_bytes: u64,
    pub(crate) terminal_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalStopIntent {
    Cancel { retain_partial: bool },
    Pause,
}

const OUTGOING_STATE_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistedOutgoingState {
    version: u16,
    transfer_id: String,
    invitation_id: String,
    source_path: String,
    source_identity: super::resume::SourceIdentity,
    display_filename: String,
    file_size: u64,
    expected_sha256: [u8; 32],
    candidate_privacy_policy: CandidatePrivacyPolicy,
    expires_unix_ms: u64,
    created_unix_ms: u64,
    previous_quic_session_id: Option<String>,
    peer_checkpoint_generation: Option<u64>,
    peer_state_digest: Option<[u8; 32]>,
    peer_completed_bytes: u64,
    authentication_tag: [u8; 32],
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrepareIncomingReceiverRequest {
    pub lifetime_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareIncomingReceiverResponse {
    pub receiver_bootstrap_id: String,
    pub receiver_bootstrap_package: String,
    pub certificate_fingerprint_sha256: String,
    pub expires_unix_ms: u64,
    pub contains_private_key: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateOutgoingTransferRequest {
    pub source_path: String,
    pub receiver_bootstrap_package: String,
    pub authorization_delivery_mode: NativeAuthorizationDeliveryMode,
    pub candidate_privacy_policy: Option<CandidatePrivacyPolicy>,
    pub invitation_lifetime_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateOutgoingTransferResponse {
    pub transfer: OutgoingNativeTransferSnapshot,
    pub invitation_package: String,
    pub possession_warning: &'static str,
    pub secret_redacted_in_future_responses: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportIncomingInvitationRequest {
    pub receiver_bootstrap_id: String,
    pub invitation_package: String,
    pub destination_directory: String,
    pub retention_expires_unix_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportIncomingInvitationResponse {
    pub transfer: IncomingNativeTransferSnapshot,
    pub authorization_secret: &'static str,
    pub protected_with_dpapi: bool,
    pub package_consumed_locally: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptIncomingTransferRequest {
    pub transfer_id: String,
    pub display_filename: String,
    pub file_size: u64,
    pub expected_sha256: String,
    pub overwrite: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetIncomingDestinationRequest {
    pub transfer_id: String,
    pub destination_directory: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplitTransferIdRequest {
    pub transfer_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CancelSplitTransferRequest {
    pub transfer_id: String,
    pub retain_partial: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartSplitTransferRequest {
    pub transfer_id: String,
    pub signaling_endpoint: String,
    pub gathering: Option<ConnectivityGatherOptions>,
    pub signaling_timeout_ms: Option<u64>,
    pub connectivity_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResumeOutgoingTransferRequest {
    pub transfer_id: String,
    pub receiver_bootstrap_package: String,
    /// Optional process-local source descriptor token used by Android after
    /// reopening a persisted SAF URI. Never serialized into transfer state.
    #[serde(default)]
    pub source_handle: Option<String>,
    pub expected_checkpoint_generation: Option<u64>,
    pub signaling_endpoint: String,
    pub gathering: Option<ConnectivityGatherOptions>,
    pub signaling_timeout_ms: Option<u64>,
    pub connectivity_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResumeIncomingTransferRequest {
    pub transfer_id: String,
    pub receiver_bootstrap_id: String,
    pub destination_directory: String,
    pub expected_checkpoint_generation: Option<u64>,
    pub signaling_endpoint: String,
    pub gathering: Option<ConnectivityGatherOptions>,
    pub signaling_timeout_ms: Option<u64>,
    pub connectivity_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanIncomingResumableRequest {
    pub destination_directories: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiscardOutgoingResumableRequest {
    pub transfer_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiscardIncomingResumableRequest {
    pub transfer_id: String,
    pub destination_directory: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IncomingResumableDiscovery {
    pub transfer_id: String,
    pub invitation_id: String,
    pub destination_directory: String,
    pub resume_metadata_path: String,
    pub final_filename: String,
    pub file_size: u64,
    pub checkpoint_generation: u64,
    pub completed_bytes: u64,
    pub missing_bytes: u64,
    pub checkpoint_authenticated: bool,
    pub block_hashes_authenticated: bool,
    pub part_file_present: bool,
    pub authorization_secret: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutgoingResumableDiscovery {
    pub transfer_id: String,
    pub invitation_id: String,
    pub source_path: String,
    pub display_filename: String,
    pub file_size: u64,
    pub checkpoint_generation: u64,
    pub peer_completed_bytes: u64,
    pub missing_bytes: u64,
    pub protected_state_authenticated: bool,
    pub source_identity_matches: bool,
    pub authorization_secret: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutgoingNativeTransferSnapshot {
    pub transfer_id: String,
    pub invitation_id: String,
    pub state: OutgoingNativeState,
    pub source_path: String,
    pub display_filename: String,
    pub file_size: u64,
    pub expected_sha256: String,
    pub receiver_certificate_fingerprint_sha256: String,
    pub candidate_privacy_policy: CandidatePrivacyPolicy,
    pub expires_unix_ms: u64,
    pub created_unix_ms: u64,
    pub bytes_sent: u64,
    pub bytes_skipped: u64,
    pub peer_checkpoint_generation: Option<u64>,
    pub peer_state_digest: Option<String>,
    pub peer_completed_bytes: u64,
    pub connectivity_session_id: Option<String>,
    pub quic_session_id: Option<String>,
    pub selected_path: Option<String>,
    pub integrity_result: Option<String>,
    pub performance: Option<split_transfer::SplitTransferResult>,
    pub signaling_file_payload_bytes: u64,
    pub terminal_error: Option<String>,
    pub runtime_active: bool,
    pub production_native_enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IncomingNativeTransferSnapshot {
    pub transfer_id: String,
    pub invitation_id: String,
    pub state: IncomingNativeState,
    pub destination_directory: String,
    pub accepted_filename: Option<String>,
    pub expected_file_size: Option<u64>,
    pub expected_sha256: Option<String>,
    pub final_path: Option<String>,
    pub part_path: Option<String>,
    pub receiver_certificate_fingerprint_sha256: String,
    pub expires_unix_ms: u64,
    pub retention_expires_unix_ms: u64,
    pub created_unix_ms: u64,
    pub bytes_received: u64,
    pub bytes_written: u64,
    pub bytes_skipped: u64,
    pub checkpoint_generation: u64,
    pub secure_state_digest: Option<String>,
    pub completed_checkpoint_bytes: u64,
    pub connectivity_session_id: Option<String>,
    pub quic_session_id: Option<String>,
    pub selected_path: Option<String>,
    pub integrity_result: Option<String>,
    pub performance: Option<split_transfer::SplitTransferResult>,
    pub signaling_file_payload_bytes: u64,
    pub terminal_error: Option<String>,
    pub runtime_active: bool,
    pub source_path_exposed: bool,
    pub authorization_secret: &'static str,
    pub production_native_enabled: bool,
}

pub async fn flowshare_native_prepare_incoming_receiver(
    request: Option<PrepareIncomingReceiverRequest>,
) -> Result<PrepareIncomingReceiverResponse, String> {
    ensure_native_beta_available()?;
    let lifetime_ms = request
        .and_then(|value| value.lifetime_ms)
        .unwrap_or(DEFAULT_MANUAL_PACKAGE_LIFETIME_MS)
        .clamp(30_000, 15 * 60_000);
    let prepared = prepare_receiver_bootstrap(Duration::from_millis(lifetime_ms))?;
    let response = PrepareIncomingReceiverResponse {
        receiver_bootstrap_id: Uuid::from_bytes(prepared.bootstrap_id).to_string(),
        receiver_bootstrap_package: prepared.encoded_package.clone(),
        certificate_fingerprint_sha256: hex(&prepared.certificate_fingerprint_sha256),
        expires_unix_ms: prepared.expires_unix_ms,
        contains_private_key: false,
    };
    insert_receiver_bootstrap(prepared).await?;
    Ok(response)
}

pub async fn flowshare_native_create_outgoing_transfer(
    request: CreateOutgoingTransferRequest,
) -> Result<CreateOutgoingTransferResponse, String> {
    ensure_native_beta_available()?;
    if request.authorization_delivery_mode != NativeAuthorizationDeliveryMode::ManualPackage {
        return Err("native-authorization-delivery-mode-unsupported".into());
    }
    let bootstrap = decode_receiver_bootstrap(&request.receiver_bootstrap_package, now_unix_ms())?;
    let (source_path, registered_display_name) =
        resolve_outgoing_source(&request.source_path, "native-outgoing-source-unavailable").await?;
    let metadata = fs::metadata(&source_path)
        .await
        .map_err(|_| "native-outgoing-source-unavailable")?;
    if !metadata.is_file() {
        return Err("native-outgoing-source-not-file".into());
    }
    let display_filename = sanitize_received_filename(match registered_display_name.as_deref() {
        Some(value) => value,
        None => source_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or("native-outgoing-filename-invalid")?,
    })?;
    let source_identity = super::resume::capture_source_identity(&source_path).await?;
    let (expected_sha256, _) = sha256_file(&source_path, NATIVE_BLOCK_BYTES).await?;
    let transfer_id = *Uuid::new_v4().as_bytes();
    let lifetime_ms = request
        .invitation_lifetime_ms
        .unwrap_or(DEFAULT_INVITATION_LIFETIME_MS)
        .clamp(30_000, 15 * 60_000);
    let material = authorization::create_registered_invitation(
        transfer_id,
        bootstrap.certificate_fingerprint_sha256,
        RESUME_REQUIRED_CAPABILITIES,
        lifetime_ms,
    )?;
    let (invitation_package, inspection) =
        export_manual_invitation_package(&material, Duration::from_millis(lifetime_ms))?;
    let authorization_resume_path = outgoing_authorization_resume_path(&transfer_id)?;
    let outgoing_state_path = authorization_resume_path
        .parent()
        .ok_or("native-outgoing-state-directory-unavailable")?
        .join("outgoing-state.json");
    if let Err(error) = secret_store::store(&authorization_resume_path, &material).await {
        let _ = authorization::revoke(&transfer_id);
        return Err(error);
    }
    let record = Arc::new(OutgoingNativeTransfer {
        transfer_id: Uuid::from_bytes(transfer_id).to_string(),
        invitation_id: Uuid::from_bytes(material.invitation.body.invitation_id).to_string(),
        source_path,
        source_identity,
        display_filename,
        file_size: metadata.len(),
        expected_sha256,
        receiver_certificate: bootstrap.certificate,
        receiver_certificate_fingerprint_sha256: bootstrap.certificate_fingerprint_sha256,
        candidate_privacy_policy: request.candidate_privacy_policy.unwrap_or_default(),
        authorization_resume_path,
        outgoing_state_path,
        previous_quic_session_id: None,
        expires_unix_ms: inspection.expires_unix_ms,
        created_unix_ms: now_unix_ms(),
        mutable: Mutex::new(OutgoingMutable {
            state: OutgoingNativeState::AwaitingReceiver,
            control_request: CancellationToken::new(),
            cancellation: CancellationToken::new(),
            local_stop: None,
            pause_request_id: None,
            task_abort: None,
            connectivity_session_id: None,
            quic_session_id: None,
            selected_path: None,
            bytes_sent: 0,
            bytes_skipped: 0,
            peer_checkpoint_generation: None,
            peer_state_digest: None,
            peer_completed_bytes: 0,
            integrity_result: None,
            performance: None,
            signaling_file_payload_bytes: 0,
            terminal_error: None,
        }),
    });
    if let Err(error) = persist_outgoing_state(&record).await {
        let _ = secret_store::delete(&record.authorization_resume_path).await;
        let _ = authorization::revoke(&transfer_id);
        return Err(error);
    }
    insert_outgoing(record.clone()).await?;
    Ok(CreateOutgoingTransferResponse {
        transfer: outgoing_snapshot(&record).await,
        invitation_package,
        possession_warning: MANUAL_PACKAGE_POSSESSION_WARNING,
        secret_redacted_in_future_responses: true,
    })
}

pub async fn flowshare_native_import_incoming_invitation(
    request: ImportIncomingInvitationRequest,
) -> Result<ImportIncomingInvitationResponse, String> {
    ensure_native_beta_available()?;
    let bootstrap_id = Uuid::parse_str(&request.receiver_bootstrap_id)
        .map_err(|_| "native-receiver-bootstrap-id-invalid")?
        .to_string();
    // Temporarily lease the one-time bootstrap so concurrent imports cannot
    // use the same private identity. Validation/setup failures return the
    // lease, allowing the normal app-link flow to retry without making the
    // receiver prepare a new request.
    let bootstrap = take_receiver_bootstrap(&bootstrap_id).await?;
    if bootstrap.expires_unix_ms.saturating_add(30_000) < now_unix_ms() {
        return Err("native-receiver-bootstrap-expired".into());
    }

    let prepared = async {
        let decoded = decode_manual_invitation_package(
            &request.invitation_package,
            Some(bootstrap.identity.fingerprint_sha256_bytes),
            now_unix_ms(),
        )?;
        if IMPORTED_PACKAGE_DIGESTS
            .lock()
            .await
            .contains(&decoded.package_digest_sha256)
        {
            return Err("native-manual-package-replayed".into());
        }
        let destination_directory =
            canonical_destination_directory(&request.destination_directory).await?;
        let transfer_id = decoded.material.invitation.body.transfer_id;
        let created_unix_ms = now_unix_ms();
        let retention_expires_unix_ms = request
            .retention_expires_unix_ms
            .unwrap_or_else(|| created_unix_ms.saturating_add(MAX_INCOMING_RETENTION_MS))
            .min(created_unix_ms.saturating_add(MAX_INCOMING_RETENTION_MS));
        if retention_expires_unix_ms <= created_unix_ms {
            return Err("share-offline-or-expired".into());
        }
        let artifact_directory =
            canonical_incoming_artifact_directory(&destination_directory, &transfer_id, true)
                .await?;
        let state_directory = canonical_incoming_state_directory(&transfer_id, true).await?;
        let authorization_resume_path = state_directory.join("transfer.resume.current");
        let receipt_path = state_directory.join("invitation.imported");
        if fs::try_exists(&receipt_path)
            .await
            .map_err(|_| "native-manual-package-receipt-failed")?
        {
            return Err("native-manual-package-replayed".into());
        }
        write_import_receipt(&receipt_path, decoded.package_digest_sha256).await?;
        if let Err(error) = secret_store::store(&authorization_resume_path, &decoded.material).await
        {
            let _ = secret_store::delete(&authorization_resume_path).await;
            let _ = fs::remove_file(&receipt_path).await;
            let _ = remove_incoming_workspace(&transfer_id, &destination_directory).await;
            return Err(error);
        }
        let retention = PersistedIncomingRetention {
            version: INCOMING_RETENTION_VERSION,
            transfer_id: Uuid::from_bytes(transfer_id).to_string(),
            destination_directory: destination_directory.display().to_string(),
            created_unix_ms,
            expires_unix_ms: retention_expires_unix_ms,
        };
        if let Err(error) = persist_incoming_retention(&state_directory, &retention).await {
            let _ = secret_store::delete(&authorization_resume_path).await;
            let _ = fs::remove_file(&receipt_path).await;
            let _ = remove_incoming_workspace(&transfer_id, &destination_directory).await;
            return Err(error);
        }
        Ok((
            decoded,
            destination_directory,
            artifact_directory,
            authorization_resume_path,
            receipt_path,
            created_unix_ms,
            retention_expires_unix_ms,
        ))
    }
    .await;
    let (
        decoded,
        destination_directory,
        artifact_directory,
        authorization_resume_path,
        receipt_path,
        created_unix_ms,
        retention_expires_unix_ms,
    ) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            restore_receiver_bootstrap(bootstrap_id, bootstrap).await;
            return Err(error);
        }
    };
    let transfer_id = decoded.material.invitation.body.transfer_id;

    // Commit the authorization, replay marker, and incoming registry entry as
    // one non-awaiting critical section. Nothing fallible remains after the
    // authorization is installed, so a retry cannot inherit half-committed
    // process state.
    let mut incoming_records = INCOMING_TRANSFERS.lock().await;
    let mut imported_digests = IMPORTED_PACKAGE_DIGESTS.lock().await;
    let canonical_transfer_id = Uuid::from_bytes(transfer_id).to_string();
    let commit_error = if imported_digests.contains(&decoded.package_digest_sha256) {
        Some("native-manual-package-replayed".to_string())
    } else if incoming_records.len() >= MAX_SPLIT_ROLE_RECORDS {
        Some("native-incoming-registry-capacity-reached".to_string())
    } else if incoming_records.contains_key(&canonical_transfer_id) {
        Some("native-incoming-transfer-exists".to_string())
    } else {
        authorization::install_imported_available(decoded.material.clone()).err()
    };
    if let Some(error) = commit_error {
        drop(imported_digests);
        drop(incoming_records);
        let _ = fs::remove_file(&receipt_path).await;
        let _ = secret_store::delete(&authorization_resume_path).await;
        let _ = remove_incoming_workspace(&transfer_id, &destination_directory).await;
        restore_receiver_bootstrap(bootstrap_id, bootstrap).await;
        return Err(error);
    }
    let record = Arc::new(IncomingNativeTransfer {
        transfer_id: canonical_transfer_id.clone(),
        invitation_id: Uuid::from_bytes(decoded.material.invitation.body.invitation_id).to_string(),
        destination_directory: Mutex::new(destination_directory),
        artifact_directory: Mutex::new(artifact_directory),
        authorization_resume_path: Mutex::new(authorization_resume_path),
        receiver_identity: Mutex::new(Some(bootstrap.identity)),
        receiver_certificate_fingerprint_sha256: decoded.receiver_certificate_fingerprint_sha256,
        expires_unix_ms: decoded.expires_unix_ms,
        retention_expires_unix_ms,
        created_unix_ms,
        mutable: Mutex::new(IncomingMutable {
            state: IncomingNativeState::AwaitingAcceptance,
            control_request: CancellationToken::new(),
            cancellation: CancellationToken::new(),
            local_stop: None,
            peer_cancel_retain_partial: None,
            pause_request_id: None,
            task_abort: None,
            connectivity_session_id: None,
            quic_session_id: None,
            selected_path: None,
            accepted_filename: None,
            expected_file_size: None,
            expected_sha256: None,
            final_path: None,
            part_path: None,
            bytes_received: 0,
            bytes_written: 0,
            bytes_skipped: 0,
            committed_intervals: Vec::new(),
            checkpoint_generation: 0,
            secure_state_digest: None,
            completed_checkpoint_bytes: 0,
            integrity_result: None,
            performance: None,
            signaling_file_payload_bytes: 0,
            terminal_error: None,
        }),
    });
    imported_digests.insert(decoded.package_digest_sha256);
    incoming_records.insert(canonical_transfer_id, record.clone());
    drop(imported_digests);
    drop(incoming_records);
    Ok(ImportIncomingInvitationResponse {
        transfer: incoming_snapshot(&record).await,
        authorization_secret: "[REDACTED]",
        protected_with_dpapi: cfg!(windows),
        package_consumed_locally: true,
    })
}

pub async fn flowshare_native_accept_incoming_transfer(
    request: AcceptIncomingTransferRequest,
) -> Result<IncomingNativeTransferSnapshot, String> {
    ensure_native_beta_available()?;
    let record = lookup_incoming(&request.transfer_id).await?;
    let filename = sanitize_received_filename(&request.display_filename)?;
    let expected_sha256 = decode_hex_32(&request.expected_sha256)?;
    let destination = record.destination_directory.lock().await.clone();
    let final_path =
        duplicate_destination_name(&destination, &filename, request.overwrite.unwrap_or(false))?;
    ensure_contained_destination(&destination, &final_path)?;
    let artifact = record.artifact_directory.lock().await.clone();
    let part_path = artifact.join("payload.part");
    let available_bytes = available_space(&artifact).ok();
    ensure_incoming_storage_capacity(request.file_size, available_bytes)?;
    let mut part = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&part_path)
        .await
        .map_err(|error| format!("native-incoming-part-create-failed: {error}"))?;
    if let Err(error) = prepare_incoming_part_length(&mut part, request.file_size).await {
        drop(part);
        let _ = fs::remove_file(&part_path).await;
        return Err(error);
    }
    drop(part);
    let mut mutable = record.mutable.lock().await;
    if mutable.state != IncomingNativeState::AwaitingAcceptance {
        drop(mutable);
        let _ = fs::remove_file(&part_path).await;
        return Err("native-incoming-acceptance-state-invalid".into());
    }
    mutable.accepted_filename = Some(filename);
    mutable.expected_file_size = Some(request.file_size);
    mutable.expected_sha256 = Some(expected_sha256);
    mutable.final_path = Some(final_path);
    mutable.part_path = Some(part_path);
    mutable.state = IncomingNativeState::Accepted;
    drop(mutable);
    Ok(incoming_snapshot(&record).await)
}

fn ensure_incoming_storage_capacity(
    required_bytes: u64,
    available_bytes: Option<u64>,
) -> Result<(), String> {
    if let Some(available_bytes) = available_bytes {
        if available_bytes < required_bytes {
            return Err(format!(
                "native-incoming-insufficient-space: required-bytes={required_bytes}; available-bytes={available_bytes}"
            ));
        }
    }
    Ok(())
}

async fn prepare_incoming_part_length(
    part: &mut tokio::fs::File,
    file_size: u64,
) -> Result<(), String> {
    match part.set_len(file_size).await {
        Ok(()) => Ok(()),
        Err(_) if file_size == 0 => Ok(()),
        Err(preallocation_error) => {
            extend_incoming_part_length(part, file_size)
                .await
                .map_err(|extension_error| {
                    format!(
                        "native-incoming-part-preallocate-failed: set-len={preallocation_error}; extension={extension_error}"
                    )
                })
        }
    }
}

async fn extend_incoming_part_length(
    part: &mut tokio::fs::File,
    file_size: u64,
) -> Result<(), std::io::Error> {
    if file_size == 0 {
        return Ok(());
    }
    part.seek(SeekFrom::Start(file_size - 1)).await?;
    part.write_all(&[0]).await?;
    part.flush().await?;
    Ok(())
}

pub async fn flowshare_native_set_incoming_destination(
    request: SetIncomingDestinationRequest,
) -> Result<IncomingNativeTransferSnapshot, String> {
    ensure_native_beta_available()?;
    let record = lookup_incoming(&request.transfer_id).await?;
    if record.mutable.lock().await.state != IncomingNativeState::AwaitingAcceptance {
        return Err("native-incoming-destination-locked".into());
    }
    let destination = canonical_destination_directory(&request.destination_directory).await?;
    let transfer_id = parse_transfer_id(&record.transfer_id)?;
    let old_destination = record.destination_directory.lock().await.clone();
    let new_artifact =
        canonical_incoming_artifact_directory(&destination, &transfer_id, true).await?;
    let state_directory = canonical_incoming_state_directory(&transfer_id, false).await?;
    if let Err(error) = persist_incoming_retention(
        &state_directory,
        &PersistedIncomingRetention {
            version: INCOMING_RETENTION_VERSION,
            transfer_id: record.transfer_id.clone(),
            destination_directory: destination.display().to_string(),
            created_unix_ms: record.created_unix_ms,
            expires_unix_ms: record.retention_expires_unix_ms,
        },
    )
    .await
    {
        if destination != old_destination {
            let _ = remove_incoming_artifact_directory(&transfer_id, &destination).await;
        }
        return Err(error);
    }
    *record.destination_directory.lock().await = destination;
    *record.artifact_directory.lock().await = new_artifact;
    if old_destination != *record.destination_directory.lock().await {
        let _ = remove_incoming_artifact_directory(&transfer_id, &old_destination).await;
    }
    Ok(incoming_snapshot(&record).await)
}

pub async fn flowshare_native_get_outgoing_transfer(
    request: SplitTransferIdRequest,
) -> Result<OutgoingNativeTransferSnapshot, String> {
    ensure_native_beta_available()?;
    let record = lookup_outgoing(&request.transfer_id).await?;
    Ok(outgoing_snapshot(&record).await)
}

pub async fn flowshare_native_get_incoming_transfer(
    request: SplitTransferIdRequest,
) -> Result<IncomingNativeTransferSnapshot, String> {
    ensure_native_beta_available()?;
    let record = lookup_incoming(&request.transfer_id).await?;
    Ok(incoming_snapshot(&record).await)
}

pub async fn flowshare_native_start_outgoing_transfer(
    request: StartSplitTransferRequest,
) -> Result<OutgoingNativeTransferSnapshot, String> {
    ensure_native_beta_available()?;
    let record = lookup_outgoing(&request.transfer_id).await?;
    {
        let mut mutable = record.mutable.lock().await;
        if mutable.task_abort.is_some() {
            return Err("native-outgoing-runtime-already-active".into());
        }
        if mutable.state != OutgoingNativeState::AwaitingReceiver {
            return Err("native-outgoing-start-state-invalid".into());
        }
        mutable.cancellation = CancellationToken::new();
        mutable.control_request = CancellationToken::new();
        mutable.local_stop = None;
        mutable.pause_request_id = None;
        mutable.state = OutgoingNativeState::GatheringCandidates;
        mutable.terminal_error = None;
        mutable.integrity_result = None;
    }
    let runtime_record = record.clone();
    let task = tokio::spawn(async move {
        let result =
            panic_safe_native_runtime(run_outgoing_lifecycle(runtime_record.clone(), request))
                .await;
        finish_outgoing_runtime(&runtime_record, result).await;
    });
    register_outgoing_task(&record, &task).await;
    Ok(outgoing_snapshot(&record).await)
}

pub async fn flowshare_native_start_incoming_transfer(
    request: StartSplitTransferRequest,
) -> Result<IncomingNativeTransferSnapshot, String> {
    ensure_native_beta_available()?;
    let record = lookup_incoming(&request.transfer_id).await?;
    {
        let mut mutable = record.mutable.lock().await;
        if mutable.task_abort.is_some() {
            return Err("native-incoming-runtime-already-active".into());
        }
        if mutable.state != IncomingNativeState::Accepted {
            return Err("native-incoming-start-state-invalid".into());
        }
        mutable.cancellation = CancellationToken::new();
        mutable.control_request = CancellationToken::new();
        mutable.local_stop = None;
        mutable.peer_cancel_retain_partial = None;
        mutable.pause_request_id = None;
        mutable.state = IncomingNativeState::GatheringCandidates;
        mutable.terminal_error = None;
        mutable.integrity_result = None;
    }
    let runtime_record = record.clone();
    let task = tokio::spawn(async move {
        let result =
            panic_safe_native_runtime(run_incoming_lifecycle(runtime_record.clone(), request))
                .await;
        finish_incoming_runtime(&runtime_record, result).await;
    });
    register_incoming_task(&record, &task).await;
    Ok(incoming_snapshot(&record).await)
}

pub async fn flowshare_native_cancel_outgoing_transfer(
    request: CancelSplitTransferRequest,
) -> Result<OutgoingNativeTransferSnapshot, String> {
    ensure_native_beta_available()?;
    let record = lookup_outgoing(&request.transfer_id).await?;
    let mut mutable = record.mutable.lock().await;
    if matches!(
        mutable.state,
        OutgoingNativeState::Finalizing
            | OutgoingNativeState::Completed
            | OutgoingNativeState::Cancelled
    ) {
        drop(mutable);
        return Ok(outgoing_snapshot(&record).await);
    }
    let active = mutable.task_abort.is_some();
    let authenticated_session_active = mutable.state == OutgoingNativeState::Transferring;
    mutable.local_stop = Some(LocalStopIntent::Cancel {
        retain_partial: request.retain_partial.unwrap_or(true),
    });
    if authenticated_session_active {
        mutable.control_request.cancel();
    } else {
        mutable.cancellation.cancel();
    }
    mutable.state = OutgoingNativeState::Cancelled;
    drop(mutable);
    if !active {
        let transfer_id = parse_transfer_id(&record.transfer_id)?;
        let _ = authorization::revoke(&transfer_id);
        let _ = secret_store::delete(&record.authorization_resume_path).await;
        remove_outgoing_state(&record).await;
    }
    Ok(outgoing_snapshot(&record).await)
}

pub async fn flowshare_native_cancel_incoming_transfer(
    request: CancelSplitTransferRequest,
) -> Result<IncomingNativeTransferSnapshot, String> {
    ensure_native_beta_available()?;
    let record = lookup_incoming(&request.transfer_id).await?;
    let active = {
        let mut mutable = record.mutable.lock().await;
        if matches!(
            mutable.state,
            IncomingNativeState::Finalizing
                | IncomingNativeState::Completed
                | IncomingNativeState::Cancelled
                | IncomingNativeState::Declined
        ) {
            drop(mutable);
            return Ok(incoming_snapshot(&record).await);
        }
        let active = mutable.task_abort.is_some();
        let authenticated_session_active = mutable.state == IncomingNativeState::Receiving;
        mutable.local_stop = Some(LocalStopIntent::Cancel {
            retain_partial: request.retain_partial.unwrap_or(true),
        });
        if authenticated_session_active {
            mutable.control_request.cancel();
        } else {
            mutable.cancellation.cancel();
        }
        mutable.state = IncomingNativeState::Cancelled;
        active
    };
    let delete_workspace = !request.retain_partial.unwrap_or(true);
    if delete_workspace && !active {
        let transfer_id = parse_transfer_id(&record.transfer_id)?;
        let destination = record.destination_directory.lock().await.clone();
        let _ = remove_incoming_workspace(&transfer_id, &destination).await;
    }
    if !active {
        let transfer_id = parse_transfer_id(&record.transfer_id)?;
        let _ = authorization::revoke(&transfer_id);
    }
    Ok(incoming_snapshot(&record).await)
}

/// Rejects a pending incoming transfer before payload work starts.
pub async fn flowshare_native_reject_incoming_transfer(
    request: SplitTransferIdRequest,
) -> Result<IncomingNativeTransferSnapshot, String> {
    ensure_native_beta_available()?;
    let record = lookup_incoming(&request.transfer_id).await?;
    {
        let mut mutable = record.mutable.lock().await;
        if mutable.state == IncomingNativeState::Declined {
            drop(mutable);
            return Ok(incoming_snapshot(&record).await);
        }
        if !matches!(
            mutable.state,
            IncomingNativeState::InvitationImported | IncomingNativeState::AwaitingAcceptance
        ) {
            return Err("native-incoming-reject-state-invalid".into());
        }
        mutable.local_stop = Some(LocalStopIntent::Cancel {
            retain_partial: false,
        });
        mutable.cancellation.cancel();
        mutable.state = IncomingNativeState::Declined;
    }
    let transfer_id = parse_transfer_id(&record.transfer_id)?;
    let destination = record.destination_directory.lock().await.clone();
    let _ = remove_incoming_workspace(&transfer_id, &destination).await;
    let _ = authorization::revoke(&transfer_id);
    Ok(incoming_snapshot(&record).await)
}

/// Returns the shared engine's authoritative outgoing registry snapshots.
pub async fn list_outgoing_transfers() -> Vec<OutgoingNativeTransferSnapshot> {
    let records: Vec<_> = OUTGOING_TRANSFERS.lock().await.values().cloned().collect();
    let mut snapshots = Vec::with_capacity(records.len());
    for record in records {
        snapshots.push(outgoing_snapshot(&record).await);
    }
    snapshots.sort_by(|left, right| left.created_unix_ms.cmp(&right.created_unix_ms));
    snapshots
}

/// Returns the shared engine's authoritative incoming registry snapshots.
pub async fn list_incoming_transfers() -> Vec<IncomingNativeTransferSnapshot> {
    let records: Vec<_> = INCOMING_TRANSFERS.lock().await.values().cloned().collect();
    let mut snapshots = Vec::with_capacity(records.len());
    for record in records {
        snapshots.push(incoming_snapshot(&record).await);
    }
    snapshots.sort_by(|left, right| left.created_unix_ms.cmp(&right.created_unix_ms));
    snapshots
}

pub async fn flowshare_native_pause_outgoing_transfer(
    request: SplitTransferIdRequest,
) -> Result<OutgoingNativeTransferSnapshot, String> {
    ensure_native_beta_available()?;
    let record = lookup_outgoing(&request.transfer_id).await?;
    let mut mutable = record.mutable.lock().await;
    if mutable.state == OutgoingNativeState::Paused {
        drop(mutable);
        return Ok(outgoing_snapshot(&record).await);
    }
    if mutable.state != OutgoingNativeState::Transferring {
        return Err("native-outgoing-pause-state-invalid".into());
    }
    mutable.local_stop = Some(LocalStopIntent::Pause);
    mutable.pause_request_id = Some(*Uuid::new_v4().as_bytes());
    mutable.control_request.cancel();
    mutable.state = OutgoingNativeState::Paused;
    drop(mutable);
    Ok(outgoing_snapshot(&record).await)
}

pub async fn flowshare_native_pause_incoming_transfer(
    request: SplitTransferIdRequest,
) -> Result<IncomingNativeTransferSnapshot, String> {
    ensure_native_beta_available()?;
    let record = lookup_incoming(&request.transfer_id).await?;
    let mut mutable = record.mutable.lock().await;
    if mutable.state == IncomingNativeState::Paused {
        drop(mutable);
        return Ok(incoming_snapshot(&record).await);
    }
    if mutable.state != IncomingNativeState::Receiving {
        return Err("native-incoming-pause-state-invalid".into());
    }
    mutable.local_stop = Some(LocalStopIntent::Pause);
    mutable.pause_request_id = Some(*Uuid::new_v4().as_bytes());
    mutable.control_request.cancel();
    mutable.state = IncomingNativeState::Paused;
    drop(mutable);
    Ok(incoming_snapshot(&record).await)
}

pub async fn flowshare_native_scan_incoming_resumable_transfers(
    request: ScanIncomingResumableRequest,
) -> Result<Vec<IncomingResumableDiscovery>, String> {
    ensure_native_beta_available()?;
    if request.destination_directories.is_empty() || request.destination_directories.len() > 16 {
        return Err("resume-scan-location-count-invalid".into());
    }
    let _ = cleanup_expired_incoming_transfers().await;
    let mut discovered = Vec::new();
    let mut seen = HashSet::new();

    if let Ok(root_path) = incoming_state_root() {
        if fs::try_exists(&root_path).await.unwrap_or(false) {
            reject_reparse_path(&root_path).await?;
            let mut entries = fs::read_dir(&root_path)
                .await
                .map_err(|_| "native-incoming-state-directory-unavailable")?;
            while let Some(entry) = entries
                .next_entry()
                .await
                .map_err(|_| "native-incoming-state-directory-unavailable")?
            {
                if discovered.len() >= MAX_SPLIT_ROLE_RECORDS {
                    break;
                }
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                let Ok(uuid) = Uuid::parse_str(&name) else {
                    continue;
                };
                let transfer_id = *uuid.as_bytes();
                let Ok(retention) = load_incoming_retention(&transfer_id).await else {
                    continue;
                };
                if retention.expires_unix_ms <= now_unix_ms() {
                    continue;
                }
                let Ok(destination) =
                    canonical_destination_directory(&retention.destination_directory).await
                else {
                    continue;
                };
                let Ok(artifact) =
                    canonical_incoming_artifact_directory(&destination, &transfer_id, false).await
                else {
                    continue;
                };
                let Ok(state) = canonical_incoming_state_directory(&transfer_id, false).await
                else {
                    continue;
                };
                if let Some(item) = inspect_incoming_resumable(
                    &destination,
                    &artifact,
                    &state.join("transfer.resume.current"),
                    &transfer_id,
                )
                .await?
                {
                    seen.insert(item.transfer_id.clone());
                    discovered.push(item);
                }
            }
        }
    }

    for configured in request.destination_directories {
        let destination = canonical_destination_directory(&configured).await?;
        let configured_root = destination.join(".flowshare-native");
        if !fs::try_exists(&configured_root)
            .await
            .map_err(|_| "resume-scan-location-unavailable")?
        {
            continue;
        }
        let root = canonical_native_storage_root(&destination, false).await?;
        let mut entries = match fs::read_dir(&root).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err("resume-scan-location-unavailable".into()),
        };
        let mut inspected = 0usize;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|_| "resume-scan-location-unavailable")?
        {
            inspected += 1;
            if inspected > MAX_SPLIT_ROLE_RECORDS {
                break;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(transfer_uuid) = Uuid::parse_str(&name) else {
                continue;
            };
            reject_reparse_path(&entry.path()).await?;
            let artifact = fs::canonicalize(entry.path())
                .await
                .map_err(|_| "native-incoming-artifact-unsafe")?;
            if artifact.parent() != Some(root.as_path()) {
                return Err("native-incoming-artifact-unsafe".into());
            }
            let transfer_id = *transfer_uuid.as_bytes();
            if seen.contains(&transfer_uuid.to_string()) {
                continue;
            }
            if let Some(item) = inspect_incoming_resumable(
                &destination,
                &artifact,
                &artifact.join("transfer.resume.current"),
                &transfer_id,
            )
            .await?
            {
                seen.insert(item.transfer_id.clone());
                discovered.push(item);
            }
        }
    }
    discovered.sort_by(|left, right| left.transfer_id.cmp(&right.transfer_id));
    discovered.truncate(MAX_SPLIT_ROLE_RECORDS);
    Ok(discovered)
}

async fn inspect_incoming_resumable(
    destination: &Path,
    artifact: &Path,
    resume_path: &Path,
    transfer_id: &[u8; 16],
) -> Result<Option<IncomingResumableDiscovery>, String> {
    reject_reparse_path(resume_path).await?;
    let Ok(protected) = secret_store::load(resume_path).await else {
        return Ok(None);
    };
    if protected.material.invitation.body.transfer_id != *transfer_id {
        return Ok(None);
    }
    let invitation_id = protected.material.invitation.body.invitation_id;
    let checkpoint_key = super::secure_protocol::derive_checkpoint_key(
        &protected.material.master,
        transfer_id,
        &invitation_id,
    )?;
    let Ok(selection) = super::resume::load_highest_valid_authenticated(
        resume_path,
        &checkpoint_key,
        transfer_id,
        &invitation_id,
    )
    .await
    else {
        return Ok(None);
    };
    let metadata = selection.metadata;
    if metadata
        .created_unix_ms
        .saturating_add(MAX_INCOMING_RETENTION_MS)
        <= now_unix_ms()
    {
        return Ok(None);
    }
    let sidecar = super::block_hash::load_for_generation_authenticated(
        resume_path,
        transfer_id,
        &invitation_id,
        metadata.checkpoint_generation,
        &metadata.part_identity_digest,
        &metadata.block_hash_sidecar_digest,
        &checkpoint_key,
    )
    .await;
    if sidecar.manifest.is_none()
        || sanitize_received_filename(&metadata.final_filename).is_err()
        || metadata.part_filename != "payload.part"
    {
        return Ok(None);
    }
    let part_path = artifact.join(&metadata.part_filename);
    let part_file_present = fs::metadata(&part_path)
        .await
        .is_ok_and(|value| value.is_file() && value.len() == metadata.source.size)
        && reject_reparse_path(&part_path).await.is_ok()
        && super::resume::part_identity_digest(&part_path)
            .await
            .is_ok_and(|value| value == metadata.part_identity_digest);
    Ok(Some(IncomingResumableDiscovery {
        transfer_id: Uuid::from_bytes(*transfer_id).to_string(),
        invitation_id: Uuid::from_bytes(invitation_id).to_string(),
        destination_directory: destination.display().to_string(),
        resume_metadata_path: resume_path.display().to_string(),
        final_filename: metadata.final_filename,
        file_size: metadata.source.size,
        checkpoint_generation: metadata.checkpoint_generation,
        completed_bytes: metadata.completed_bytes,
        missing_bytes: metadata
            .source
            .size
            .saturating_sub(metadata.completed_bytes),
        checkpoint_authenticated: true,
        block_hashes_authenticated: true,
        part_file_present,
        authorization_secret: "[REDACTED]",
    }))
}

pub async fn flowshare_native_scan_outgoing_resumable_transfers(
) -> Result<Vec<OutgoingResumableDiscovery>, String> {
    ensure_native_beta_available()?;
    let root = super::platform_handles::state_root()
        .map_err(|_| "native-outgoing-state-directory-unavailable")?
        .join("FlowGet")
        .join("flowshare-native")
        .join("outgoing");
    let mut entries = match fs::read_dir(&root).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err("native-outgoing-state-directory-unavailable".into()),
    };
    let mut discovered = Vec::new();
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|_| "native-outgoing-state-directory-unavailable")?
    {
        if discovered.len() >= MAX_SPLIT_ROLE_RECORDS {
            break;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(uuid) = Uuid::parse_str(&name) else {
            continue;
        };
        let transfer_id = *uuid.as_bytes();
        let resume_path = entry.path().join("transfer.resume.current");
        let Ok(protected) = secret_store::load(&resume_path).await else {
            continue;
        };
        if protected.material.invitation.body.transfer_id != transfer_id {
            continue;
        }
        let Ok(state) = load_persisted_outgoing(&transfer_id, &protected.material).await else {
            continue;
        };
        let Some(generation) = state.peer_checkpoint_generation else {
            continue;
        };
        if state.peer_state_digest.is_none() || state.previous_quic_session_id.is_none() {
            continue;
        }
        let source_identity_matches = match fs::canonicalize(&state.source_path).await {
            Ok(path) => super::resume::capture_source_identity(&path)
                .await
                .is_ok_and(|identity| identity == state.source_identity),
            Err(_) => false,
        };
        discovered.push(OutgoingResumableDiscovery {
            transfer_id: state.transfer_id,
            invitation_id: state.invitation_id,
            source_path: state.source_path,
            display_filename: state.display_filename,
            file_size: state.file_size,
            checkpoint_generation: generation,
            peer_completed_bytes: state.peer_completed_bytes,
            missing_bytes: state.file_size.saturating_sub(state.peer_completed_bytes),
            protected_state_authenticated: true,
            source_identity_matches,
            authorization_secret: "[REDACTED]",
        });
    }
    discovered.sort_by(|left, right| left.transfer_id.cmp(&right.transfer_id));
    Ok(discovered)
}

pub async fn flowshare_native_discard_outgoing_resumable_transfer(
    request: DiscardOutgoingResumableRequest,
) -> Result<bool, String> {
    ensure_native_beta_available()?;
    let transfer_id = parse_transfer_id(&request.transfer_id)?;
    let canonical = Uuid::from_bytes(transfer_id).to_string();
    if OUTGOING_TRANSFERS.lock().await.contains_key(&canonical) {
        return Err("resume-already-active".into());
    }
    let base = super::platform_handles::state_root()
        .map_err(|_| "native-outgoing-state-directory-unavailable")?
        .join("FlowGet")
        .join("flowshare-native")
        .join("outgoing");
    reject_reparse_path(&base).await?;
    let base = fs::canonicalize(base)
        .await
        .map_err(|_| "native-outgoing-state-directory-unavailable")?;
    let root = base.join(&canonical);
    reject_reparse_path(&root).await?;
    let root = fs::canonicalize(root)
        .await
        .map_err(|_| "native-outgoing-state-directory-unavailable")?;
    if root.parent() != Some(base.as_path()) {
        return Err("native-outgoing-state-directory-unavailable".into());
    }
    let resume_path = root.join("transfer.resume.current");
    reject_reparse_path(&resume_path).await?;
    let protected = secret_store::load(&resume_path).await?;
    if protected.material.invitation.body.transfer_id != transfer_id {
        return Err("resume-state-mismatch".into());
    }
    load_persisted_outgoing(&transfer_id, &protected.material).await?;
    let _ = secret_store::delete(&resume_path).await?;
    reject_nested_or_reparse_entries(&root).await?;
    fs::remove_dir_all(&root)
        .await
        .map_err(|_| "native-outgoing-state-delete-failed")?;
    Ok(true)
}

pub async fn flowshare_native_discard_incoming_resumable_transfer(
    request: DiscardIncomingResumableRequest,
) -> Result<bool, String> {
    ensure_native_beta_available()?;
    let transfer_id = parse_transfer_id(&request.transfer_id)?;
    let canonical = Uuid::from_bytes(transfer_id).to_string();
    if INCOMING_TRANSFERS.lock().await.contains_key(&canonical) {
        return Err("resume-already-active".into());
    }
    let destination = canonical_destination_directory(&request.destination_directory).await?;
    let artifact = canonical_incoming_artifact_directory(&destination, &transfer_id, false).await?;
    let (resume_path, central_state) = match load_incoming_retention(&transfer_id).await {
        Ok(retention) => {
            let retained_destination =
                canonical_destination_directory(&retention.destination_directory).await?;
            if retained_destination != destination {
                return Err("resume-state-mismatch".into());
            }
            (
                canonical_incoming_state_directory(&transfer_id, false)
                    .await?
                    .join("transfer.resume.current"),
                true,
            )
        }
        Err(_) => (artifact.join("transfer.resume.current"), false),
    };
    reject_reparse_path(&resume_path).await?;
    let protected = secret_store::load(&resume_path).await?;
    if protected.material.invitation.body.transfer_id != transfer_id {
        return Err("resume-state-mismatch".into());
    }
    let checkpoint_key = super::secure_protocol::derive_checkpoint_key(
        &protected.material.master,
        &transfer_id,
        &protected.material.invitation.body.invitation_id,
    )?;
    let selected = super::resume::load_highest_valid_authenticated(
        &resume_path,
        &checkpoint_key,
        &transfer_id,
        &protected.material.invitation.body.invitation_id,
    )
    .await?;
    if selected.metadata.part_filename != "payload.part" {
        return Err("resume-state-mismatch".into());
    }
    let part_path = artifact.join(&selected.metadata.part_filename);
    ensure_contained_destination(&artifact, &part_path)?;
    if fs::try_exists(&part_path).await.unwrap_or(false) {
        reject_reparse_path(&part_path).await?;
        fs::remove_file(&part_path)
            .await
            .map_err(|_| "native-incoming-part-delete-failed")?;
    }
    let _ = secret_store::delete(&resume_path).await?;
    if central_state {
        remove_incoming_workspace(&transfer_id, &destination).await?;
    } else {
        reject_nested_or_reparse_entries(&artifact).await?;
        fs::remove_dir_all(&artifact)
            .await
            .map_err(|_| "native-incoming-state-delete-failed")?;
        if let Some(root) = artifact.parent() {
            remove_empty_directory(root).await;
        }
    }
    Ok(true)
}

pub async fn flowshare_native_resume_outgoing_transfer(
    request: ResumeOutgoingTransferRequest,
) -> Result<OutgoingNativeTransferSnapshot, String> {
    ensure_native_beta_available()?;
    let transfer_id = parse_transfer_id(&request.transfer_id)?;
    let canonical_id = Uuid::from_bytes(transfer_id).to_string();
    if OUTGOING_TRANSFERS.lock().await.contains_key(&canonical_id) {
        return Err("resume-already-active".into());
    }
    let authorization_resume_path = outgoing_authorization_resume_path(&transfer_id)?;
    let protected = secret_store::load(&authorization_resume_path).await?;
    if protected.material.invitation.body.transfer_id != transfer_id {
        return Err("resume-state-mismatch".into());
    }
    authorization::restore_persisted(protected.material.clone())?;
    let persisted = load_persisted_outgoing(&transfer_id, &protected.material).await?;
    let generation = persisted
        .peer_checkpoint_generation
        .ok_or("resume-state-mismatch")?;
    if request
        .expected_checkpoint_generation
        .is_some_and(|expected| expected != generation)
        || persisted.peer_state_digest.is_none()
        || persisted.peer_completed_bytes > persisted.file_size
        || persisted.previous_quic_session_id.is_none()
    {
        return Err("resume-state-mismatch".into());
    }
    let bootstrap = decode_receiver_bootstrap(&request.receiver_bootstrap_package, now_unix_ms())?;
    let requested_source = request
        .source_handle
        .as_deref()
        .map(str::to_owned)
        .unwrap_or_else(|| persisted.source_path.clone());
    let (source_path, registered_display_name) =
        resolve_outgoing_source(&requested_source, "resume-source-missing").await?;
    let source_identity = super::resume::capture_source_identity(&source_path).await?;
    let descriptor_rebound = request.source_handle.is_some();
    let descriptor_hash_matches = if descriptor_rebound
        && source_identity.size == persisted.file_size
        && source_identity != persisted.source_identity
    {
        sha256_file(&source_path, NATIVE_BLOCK_BYTES)
            .await
            .is_ok_and(|(hash, _)| hash == persisted.expected_sha256)
    } else {
        false
    };
    if (!descriptor_rebound && source_identity != persisted.source_identity)
        || (descriptor_rebound
            && source_identity != persisted.source_identity
            && !descriptor_hash_matches)
        || source_identity.size != persisted.file_size
        || registered_display_name
            .as_deref()
            .is_some_and(|name| name != persisted.display_filename)
        || persisted.display_filename != sanitize_received_filename(&persisted.display_filename)?
    {
        return Err("resume-source-changed".into());
    }
    let outgoing_state_path = authorization_resume_path
        .parent()
        .ok_or("native-outgoing-state-directory-unavailable")?
        .join("outgoing-state.json");
    let record = Arc::new(OutgoingNativeTransfer {
        transfer_id: canonical_id,
        invitation_id: persisted.invitation_id,
        source_path,
        source_identity,
        display_filename: persisted.display_filename,
        file_size: persisted.file_size,
        expected_sha256: persisted.expected_sha256,
        receiver_certificate: bootstrap.certificate,
        receiver_certificate_fingerprint_sha256: bootstrap.certificate_fingerprint_sha256,
        candidate_privacy_policy: persisted.candidate_privacy_policy,
        authorization_resume_path,
        outgoing_state_path,
        previous_quic_session_id: persisted.previous_quic_session_id,
        expires_unix_ms: persisted.expires_unix_ms,
        created_unix_ms: persisted.created_unix_ms,
        mutable: Mutex::new(OutgoingMutable {
            state: OutgoingNativeState::GatheringCandidates,
            control_request: CancellationToken::new(),
            cancellation: CancellationToken::new(),
            local_stop: None,
            pause_request_id: None,
            task_abort: None,
            connectivity_session_id: None,
            quic_session_id: None,
            selected_path: None,
            bytes_sent: 0,
            bytes_skipped: persisted.peer_completed_bytes,
            peer_checkpoint_generation: Some(generation),
            peer_state_digest: persisted.peer_state_digest,
            peer_completed_bytes: persisted.peer_completed_bytes,
            integrity_result: None,
            performance: None,
            signaling_file_payload_bytes: 0,
            terminal_error: None,
        }),
    });
    insert_outgoing(record.clone()).await?;
    let lifecycle_request = StartSplitTransferRequest {
        transfer_id: record.transfer_id.clone(),
        signaling_endpoint: request.signaling_endpoint,
        gathering: request.gathering,
        signaling_timeout_ms: request.signaling_timeout_ms,
        connectivity_timeout_ms: request.connectivity_timeout_ms,
    };
    let runtime_record = record.clone();
    let task = tokio::spawn(async move {
        let result = panic_safe_native_runtime(run_outgoing_resume_lifecycle(
            runtime_record.clone(),
            lifecycle_request,
        ))
        .await;
        finish_outgoing_runtime(&runtime_record, result).await;
    });
    register_outgoing_task(&record, &task).await;
    Ok(outgoing_snapshot(&record).await)
}

async fn resolve_outgoing_source(
    source_handle: &str,
    unavailable_error: &'static str,
) -> Result<(PathBuf, Option<String>), String> {
    if super::platform_handles::is_registered_source_token(source_handle) {
        let registered = super::platform_handles::resolve_registered_source(source_handle)?;
        let path = registered.io_path();
        fs::metadata(&path).await.map_err(|_| unavailable_error)?;
        return Ok((path, Some(registered.display_name().to_string())));
    }
    Ok((
        fs::canonicalize(source_handle)
            .await
            .map_err(|_| unavailable_error)?,
        None,
    ))
}

pub async fn flowshare_native_resume_incoming_transfer(
    request: ResumeIncomingTransferRequest,
) -> Result<IncomingNativeTransferSnapshot, String> {
    ensure_native_beta_available()?;
    let transfer_id = parse_transfer_id(&request.transfer_id)?;
    let canonical_id = Uuid::from_bytes(transfer_id).to_string();
    // The authorization restore lease is process-global. Serialize the short
    // setup transaction so one concurrent resume cannot adopt another
    // attempt's newly restored authorization while that attempt rolls back.
    let _resume_setup = INCOMING_RESUME_SETUP_LOCK.lock().await;
    if INCOMING_TRANSFERS.lock().await.contains_key(&canonical_id) {
        return Err("resume-already-active".into());
    }
    let bootstrap_id = Uuid::parse_str(&request.receiver_bootstrap_id)
        .map_err(|_| "native-receiver-bootstrap-id-invalid")?
        .to_string();
    let bootstrap = take_receiver_bootstrap(&bootstrap_id).await?;
    if bootstrap.expires_unix_ms.saturating_add(30_000) < now_unix_ms() {
        return Err("native-receiver-bootstrap-expired".into());
    }
    let bootstrap_expires_unix_ms = bootstrap.expires_unix_ms;
    let preauthorization = async {
        let destination_directory =
            canonical_destination_directory(&request.destination_directory).await?;
        let artifact_directory =
            canonical_incoming_artifact_directory(&destination_directory, &transfer_id, false)
                .await?;
        let (authorization_resume_path, receipt_path, retention_expires_unix_ms) =
            match load_incoming_retention(&transfer_id).await {
                Ok(retention) => {
                    let retained_destination =
                        canonical_destination_directory(&retention.destination_directory).await?;
                    if retained_destination != destination_directory {
                        return Err("resume-state-mismatch".to_string());
                    }
                    if retention.expires_unix_ms <= now_unix_ms() {
                        let _ =
                            remove_incoming_workspace(&transfer_id, &destination_directory).await;
                        return Err("share-offline-or-expired".to_string());
                    }
                    let state = canonical_incoming_state_directory(&transfer_id, false).await?;
                    (
                        state.join("transfer.resume.current"),
                        state.join("invitation.imported"),
                        retention.expires_unix_ms,
                    )
                }
                Err(_) => (
                    artifact_directory.join("transfer.resume.current"),
                    artifact_directory.join("invitation.imported"),
                    0,
                ),
            };
        reject_reparse_path(&authorization_resume_path).await?;
        let protected = secret_store::load(&authorization_resume_path).await?;
        Ok::<_, String>((
            destination_directory,
            artifact_directory,
            authorization_resume_path,
            receipt_path,
            retention_expires_unix_ms,
            protected,
        ))
    }
    .await;
    let (
        destination_directory,
        artifact_directory,
        authorization_resume_path,
        receipt_path,
        persisted_retention_expires_unix_ms,
        protected,
    ) = match preauthorization {
        Ok(prepared) => prepared,
        Err(error) => {
            restore_receiver_bootstrap(bootstrap_id, bootstrap).await;
            return Err(error);
        }
    };
    if protected.material.invitation.body.transfer_id != transfer_id {
        restore_receiver_bootstrap(bootstrap_id, bootstrap).await;
        return Err("resume-state-mismatch".into());
    }
    let authorization_lease =
        match authorization::restore_persisted_leased(protected.material.clone()) {
            Ok(lease) => lease,
            Err(error) => {
                restore_receiver_bootstrap(bootstrap_id, bootstrap).await;
                return Err(error);
            }
        };
    let prepared = async {
        let checkpoint_key = super::secure_protocol::derive_checkpoint_key(
            &protected.material.master,
            &transfer_id,
            &protected.material.invitation.body.invitation_id,
        )?;
        let selected = super::resume::load_highest_valid_authenticated(
            &authorization_resume_path,
            &checkpoint_key,
            &transfer_id,
            &protected.material.invitation.body.invitation_id,
        )
        .await?;
        let metadata = selected.metadata;
        let retention_expires_unix_ms = if persisted_retention_expires_unix_ms == 0 {
            metadata
                .created_unix_ms
                .saturating_add(MAX_INCOMING_RETENTION_MS)
        } else {
            persisted_retention_expires_unix_ms
        };
        if retention_expires_unix_ms <= now_unix_ms() {
            return Err("share-offline-or-expired".to_string());
        }
        if request
            .expected_checkpoint_generation
            .is_some_and(|expected| expected != metadata.checkpoint_generation)
            || metadata.part_filename != "payload.part"
        {
            return Err("resume-state-mismatch".to_string());
        }
        let filename = sanitize_received_filename(&metadata.final_filename)?;
        let final_path = destination_directory.join(&filename);
        ensure_contained_destination(&destination_directory, &final_path)?;
        let part_path = artifact_directory.join(&metadata.part_filename);
        ensure_contained_destination(&artifact_directory, &part_path)?;
        reject_reparse_path(&part_path).await?;
        reject_reparse_path(&receipt_path).await?;
        let _package_digest_sha256 = read_import_receipt(&receipt_path).await?;
        Ok::<_, String>((
            metadata,
            filename,
            final_path,
            part_path,
            retention_expires_unix_ms,
        ))
    }
    .await;
    let (metadata, filename, final_path, part_path, retention_expires_unix_ms) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            authorization::rollback_persisted_restore(authorization_lease);
            restore_receiver_bootstrap(bootstrap_id, bootstrap).await;
            return Err(error);
        }
    };
    let invitation_id = protected.material.invitation.body.invitation_id;
    let fingerprint = bootstrap.identity.fingerprint_sha256_bytes;
    let record = Arc::new(IncomingNativeTransfer {
        transfer_id: canonical_id,
        invitation_id: Uuid::from_bytes(invitation_id).to_string(),
        destination_directory: Mutex::new(destination_directory),
        artifact_directory: Mutex::new(artifact_directory),
        authorization_resume_path: Mutex::new(authorization_resume_path),
        receiver_identity: Mutex::new(Some(bootstrap.identity)),
        receiver_certificate_fingerprint_sha256: fingerprint,
        expires_unix_ms: protected.material.invitation.body.expires_unix_ms,
        retention_expires_unix_ms,
        created_unix_ms: metadata.created_unix_ms,
        mutable: Mutex::new(IncomingMutable {
            state: IncomingNativeState::GatheringCandidates,
            control_request: CancellationToken::new(),
            cancellation: CancellationToken::new(),
            local_stop: None,
            peer_cancel_retain_partial: None,
            pause_request_id: None,
            task_abort: None,
            connectivity_session_id: None,
            quic_session_id: None,
            selected_path: None,
            accepted_filename: Some(filename),
            expected_file_size: Some(metadata.source.size),
            expected_sha256: Some(metadata.expected_sha256),
            final_path: Some(final_path),
            part_path: Some(part_path),
            bytes_received: 0,
            bytes_written: 0,
            bytes_skipped: metadata.completed_bytes,
            committed_intervals: Vec::new(),
            checkpoint_generation: metadata.checkpoint_generation,
            secure_state_digest: Some(metadata.secure_state_digest),
            completed_checkpoint_bytes: metadata.completed_bytes,
            integrity_result: None,
            performance: None,
            signaling_file_payload_bytes: 0,
            terminal_error: None,
        }),
    });
    if let Err(error) = split_resume::validate_incoming_checkpoint(&record).await {
        rollback_incoming_resume_setup(
            bootstrap_id,
            bootstrap_expires_unix_ms,
            &record,
            authorization_lease,
        )
        .await;
        return Err(error);
    }
    if let Err(error) = insert_incoming(record.clone()).await {
        rollback_incoming_resume_setup(
            bootstrap_id,
            bootstrap_expires_unix_ms,
            &record,
            authorization_lease,
        )
        .await;
        return Err(error);
    }
    let lifecycle_request = StartSplitTransferRequest {
        transfer_id: record.transfer_id.clone(),
        signaling_endpoint: request.signaling_endpoint,
        gathering: request.gathering,
        signaling_timeout_ms: request.signaling_timeout_ms,
        connectivity_timeout_ms: request.connectivity_timeout_ms,
    };
    let runtime_record = record.clone();
    let task = tokio::spawn(async move {
        let result = panic_safe_native_runtime(run_incoming_resume_lifecycle(
            runtime_record.clone(),
            lifecycle_request,
        ))
        .await;
        finish_incoming_runtime(&runtime_record, result).await;
    });
    register_incoming_task(&record, &task).await;
    Ok(incoming_snapshot(&record).await)
}

async fn run_outgoing_lifecycle(
    record: Arc<OutgoingNativeTransfer>,
    request: StartSplitTransferRequest,
) -> Result<split_transfer::SplitTransferResult, String> {
    run_outgoing_lifecycle_mode(record, request, false).await
}

async fn panic_safe_native_runtime<F>(
    future: F,
) -> Result<split_transfer::SplitTransferResult, String>
where
    F: Future<Output = Result<split_transfer::SplitTransferResult, String>>,
{
    match AssertUnwindSafe(future).catch_unwind().await {
        Ok(result) => result,
        Err(_) => Err("native-runtime-panic".into()),
    }
}

async fn run_outgoing_resume_lifecycle(
    record: Arc<OutgoingNativeTransfer>,
    request: StartSplitTransferRequest,
) -> Result<split_transfer::SplitTransferResult, String> {
    run_outgoing_lifecycle_mode(record, request, true).await
}

async fn run_outgoing_lifecycle_mode(
    record: Arc<OutgoingNativeTransfer>,
    request: StartSplitTransferRequest,
    resume: bool,
) -> Result<split_transfer::SplitTransferResult, String> {
    if !resume && now_unix_ms() > record.expires_unix_ms.saturating_add(30_000) {
        return Err("authorization-delivery-failed: invitation-expired".into());
    }
    let signaling_timeout = bounded_timeout(request.signaling_timeout_ms, 30_000);
    let connectivity_timeout = bounded_timeout(request.connectivity_timeout_ms, 15_000);
    let cancellation = record.mutable.lock().await.cancellation.clone();
    let transport = connect_signaling_with_retry(
        NativeWebSocketSignalingOptions {
            endpoint: request.signaling_endpoint,
            share_id: record.transfer_id.clone(),
            role: NativeWebSocketRole::Sender,
            display_filename: Some(record.display_filename.clone()),
            file_size: Some(record.file_size.max(1)),
            file_sha256: Some(hex(&record.expected_sha256)),
            expires_at_rfc3339: None,
        },
        signaling_timeout,
        &cancellation,
    )
    .await?;
    wait_for_receiver_id(&transport, signaling_timeout, &cancellation)
        .await
        .map_err(|error| classify_receiver_wait_error(&error))?;
    let transfer_id = parse_transfer_id(&record.transfer_id)?;
    let mut gathering = request.gathering.unwrap_or_default();
    gathering.privacy_policy = Some(record.candidate_privacy_policy);
    let (offer, nomination) = {
        let mut attempt = 1u32;
        loop {
            let offer = connectivity::flowshare_native_create_connectivity_offer(
                CreateConnectivityOfferRequest {
                    transfer_id: record.transfer_id.clone(),
                    role: Some(NativeDeviceRole::Sender),
                    signaling_generation: None,
                    candidate_generation: Some(attempt),
                    future_quic_session_id: None,
                    gathering: Some(gathering.clone()),
                },
            )
            .await
            .map_err(|error| classify_candidate_setup_error(&error))?;
            {
                let mut mutable = record.mutable.lock().await;
                mutable.connectivity_session_id = Some(offer.connectivity_session_id.clone());
                mutable.quic_session_id = Some(offer.future_quic_session_id.clone());
            }
            send_signaling_envelope(
                &transport,
                &offer.encoded_envelope,
                signaling_timeout,
                &cancellation,
            )
            .await?;
            let answer = receive_signaling_envelope(&transport, signaling_timeout, &cancellation)
                .await
                .map_err(|error| classify_signaling_exchange_error(&error))?;
            connectivity::flowshare_native_add_remote_candidates(AddRemoteCandidatesRequest {
                connectivity_session_id: offer.connectivity_session_id.clone(),
                encoded_envelope: answer.encode()?,
            })
            .await
            .map_err(|error| classify_failure("candidate-exchange-failed", &error))?;
            record.mutable.lock().await.state = OutgoingNativeState::Connecting;
            let checks = connectivity::flowshare_native_start_connectivity_checks(
                StartConnectivityChecksRequest {
                    connectivity_session_id: offer.connectivity_session_id.clone(),
                    total_timeout_ms: Some(connectivity_timeout.as_millis() as u64),
                },
            )
            .await
            .map_err(|error| classify_connectivity_checks_error(&error))?;
            let peer_result = exchange_connectivity_check_result(
                &transport,
                &offer.connectivity_session_id,
                &checks,
                signaling_timeout,
                &cancellation,
            )
            .await?;
            if connectivity_attempt_agreed(&checks, &peer_result)? {
                let nomination = checks
                    .nomination_envelope
                    .as_ref()
                    .cloned()
                    .ok_or_else(|| connectivity_checks_failure(&checks.diagnostics))?;
                break (offer, nomination);
            }
            let failure = connectivity_attempt_failure(&checks, &peer_result);
            if !should_retry_connectivity_attempt(attempt, &peer_result) {
                return Err(failure);
            }
            close_failed_connectivity_attempt(&offer.connectivity_session_id).await?;
            attempt = attempt.saturating_add(1);
        }
    };
    send_signaling_envelope(&transport, &nomination, signaling_timeout, &cancellation).await?;
    let peer_nomination = receive_signaling_envelope(&transport, signaling_timeout, &cancellation)
        .await
        .map_err(|error| classify_signaling_exchange_error(&error))?;
    connectivity::flowshare_native_add_remote_candidates(AddRemoteCandidatesRequest {
        connectivity_session_id: offer.connectivity_session_id.clone(),
        encoded_envelope: peer_nomination.encode()?,
    })
    .await
    .map_err(|error| classify_failure("candidate-exchange-failed", &error))?;
    let context = connectivity::nominated_path_context(
        &offer.connectivity_session_id,
        transfer_id,
        NativeDeviceRole::Sender,
    )
    .await
    .map_err(|error| classify_failure("no-direct-path", &error))?;
    let client_config = split_transfer::sender_client_config(&record)?;
    let (endpoint, _, _) = connectivity::client_endpoint_for_nominated_path(
        &offer.connectivity_session_id,
        client_config,
    )
    .await
    .map_err(|error| classify_failure("quic-connect-failed", &error))?;
    {
        let status = transport.status();
        let mut mutable = record.mutable.lock().await;
        mutable.selected_path = Some(split_transfer::selected_path_label(&context));
        mutable.signaling_file_payload_bytes = status.file_payload_bytes_sent;
    }
    transport.shutdown().await;
    if resume {
        split_resume::run_outgoing_resume(record, endpoint, context).await
    } else {
        split_transfer::run_outgoing_transfer(record, endpoint, context).await
    }
}

async fn run_incoming_lifecycle(
    record: Arc<IncomingNativeTransfer>,
    request: StartSplitTransferRequest,
) -> Result<split_transfer::SplitTransferResult, String> {
    run_incoming_lifecycle_mode(record, request, false).await
}

async fn run_incoming_resume_lifecycle(
    record: Arc<IncomingNativeTransfer>,
    request: StartSplitTransferRequest,
) -> Result<split_transfer::SplitTransferResult, String> {
    run_incoming_lifecycle_mode(record, request, true).await
}

async fn run_incoming_lifecycle_mode(
    record: Arc<IncomingNativeTransfer>,
    request: StartSplitTransferRequest,
    resume: bool,
) -> Result<split_transfer::SplitTransferResult, String> {
    if !resume && now_unix_ms() > record.expires_unix_ms.saturating_add(30_000) {
        return Err("authorization-delivery-failed: invitation-expired".into());
    }
    let signaling_timeout = bounded_timeout(request.signaling_timeout_ms, 30_000);
    let connectivity_timeout = bounded_timeout(request.connectivity_timeout_ms, 15_000);
    let cancellation = record.mutable.lock().await.cancellation.clone();
    let transport = connect_signaling_with_retry(
        NativeWebSocketSignalingOptions {
            endpoint: request.signaling_endpoint,
            share_id: record.transfer_id.clone(),
            role: NativeWebSocketRole::Receiver,
            display_filename: None,
            file_size: None,
            file_sha256: None,
            expires_at_rfc3339: None,
        },
        signaling_timeout,
        &cancellation,
    )
    .await?;
    wait_for_receiver_id(&transport, signaling_timeout, &cancellation)
        .await
        .map_err(|error| classify_signaling_exchange_error(&error))?;
    let gathering = request.gathering.unwrap_or_default();
    let (answer, nomination) = {
        let mut attempt = 1u32;
        loop {
            let offer = receive_signaling_envelope(&transport, signaling_timeout, &cancellation)
                .await
                .map_err(|error| classify_signaling_exchange_error(&error))?;
            let candidate_generation = offer.candidate_generation;
            let answer = connectivity::flowshare_native_accept_connectivity_offer(
                AcceptConnectivityOfferRequest {
                    encoded_offer: offer.encode()?,
                    candidate_generation: Some(candidate_generation),
                    gathering: Some(gathering.clone()),
                },
            )
            .await
            .map_err(|error| classify_candidate_setup_error(&error))?;
            {
                let mut mutable = record.mutable.lock().await;
                mutable.connectivity_session_id = Some(answer.connectivity_session_id.clone());
                mutable.quic_session_id = Some(answer.future_quic_session_id.clone());
            }
            send_signaling_envelope(
                &transport,
                &answer.encoded_envelope,
                signaling_timeout,
                &cancellation,
            )
            .await?;
            record.mutable.lock().await.state = IncomingNativeState::Connecting;
            let checks = connectivity::flowshare_native_start_connectivity_checks(
                StartConnectivityChecksRequest {
                    connectivity_session_id: answer.connectivity_session_id.clone(),
                    total_timeout_ms: Some(connectivity_timeout.as_millis() as u64),
                },
            )
            .await
            .map_err(|error| classify_connectivity_checks_error(&error))?;
            let peer_result = exchange_connectivity_check_result(
                &transport,
                &answer.connectivity_session_id,
                &checks,
                signaling_timeout,
                &cancellation,
            )
            .await?;
            if connectivity_attempt_agreed(&checks, &peer_result)? {
                let nomination = checks
                    .nomination_envelope
                    .as_ref()
                    .cloned()
                    .ok_or_else(|| connectivity_checks_failure(&checks.diagnostics))?;
                break (answer, nomination);
            }
            let failure = connectivity_attempt_failure(&checks, &peer_result);
            if !should_retry_connectivity_attempt(attempt, &peer_result) {
                return Err(failure);
            }
            close_failed_connectivity_attempt(&answer.connectivity_session_id).await?;
            attempt = attempt.saturating_add(1);
        }
    };
    let server_config = split_transfer::receiver_server_config(&record).await?;
    let (endpoint, _, _) = connectivity::server_endpoint_for_nominated_path(
        &answer.connectivity_session_id,
        server_config,
    )
    .await
    .map_err(|error| classify_failure("quic-connect-failed", &error))?;
    send_signaling_envelope(&transport, &nomination, signaling_timeout, &cancellation).await?;
    let peer_nomination = receive_signaling_envelope(&transport, signaling_timeout, &cancellation)
        .await
        .map_err(|error| classify_signaling_exchange_error(&error))?;
    connectivity::flowshare_native_add_remote_candidates(AddRemoteCandidatesRequest {
        connectivity_session_id: answer.connectivity_session_id.clone(),
        encoded_envelope: peer_nomination.encode()?,
    })
    .await
    .map_err(|error| classify_failure("candidate-exchange-failed", &error))?;
    let transfer_id = parse_transfer_id(&record.transfer_id)?;
    let context = connectivity::nominated_path_context(
        &answer.connectivity_session_id,
        transfer_id,
        NativeDeviceRole::Receiver,
    )
    .await
    .map_err(|error| classify_failure("no-direct-path", &error))?;
    {
        let status = transport.status();
        let mut mutable = record.mutable.lock().await;
        mutable.selected_path = Some(split_transfer::selected_path_label(&context));
        mutable.signaling_file_payload_bytes = status.file_payload_bytes_sent;
    }
    transport.shutdown().await;
    if resume {
        split_resume::run_incoming_resume(record, endpoint, context).await
    } else {
        split_transfer::run_incoming_transfer(record, endpoint, context).await
    }
}

async fn send_signaling_envelope(
    transport: &NativeWebSocketSignalingTransport,
    encoded: &str,
    timeout: Duration,
    cancellation: &CancellationToken,
) -> Result<(), String> {
    let envelope = AuthenticatedSignalingEnvelope::decode(encoded)
        .map_err(|error| classify_failure("candidate-exchange-failed", &error))?;
    let acknowledgment = await_signaling_operation(
        cancellation,
        transport.send_and_wait_delivery_current(envelope, timeout),
    )
    .await
    .map_err(|error| classify_signaling_exchange_error(&error))?;
    if !acknowledgment.accepted {
        return Err("candidate-exchange-failed: delivery-rejected".into());
    }
    Ok(())
}

async fn wait_for_receiver_id(
    transport: &NativeWebSocketSignalingTransport,
    timeout: Duration,
    cancellation: &CancellationToken,
) -> Result<String, String> {
    await_signaling_operation(cancellation, transport.wait_for_receiver_id(timeout)).await
}

async fn receive_signaling_envelope(
    transport: &NativeWebSocketSignalingTransport,
    timeout: Duration,
    cancellation: &CancellationToken,
) -> Result<AuthenticatedSignalingEnvelope, String> {
    await_signaling_operation(cancellation, transport.receive_with_timeout(timeout)).await
}

async fn exchange_connectivity_check_result(
    transport: &NativeWebSocketSignalingTransport,
    connectivity_session_id: &str,
    checks: &ConnectivityChecksResponse,
    timeout: Duration,
    cancellation: &CancellationToken,
) -> Result<ConnectivityCheckResultPayload, String> {
    send_signaling_envelope(
        transport,
        &checks.check_result_envelope,
        timeout,
        cancellation,
    )
    .await?;
    let peer = receive_signaling_envelope(transport, timeout, cancellation)
        .await
        .map_err(|error| classify_signaling_exchange_error(&error))?;
    connectivity::flowshare_native_add_remote_candidates(AddRemoteCandidatesRequest {
        connectivity_session_id: connectivity_session_id.to_string(),
        encoded_envelope: peer.encode()?,
    })
    .await
    .map_err(|error| classify_failure("candidate-exchange-failed", &error))?;
    match peer.payload {
        NativeSignalingPayload::NativeConnectivityCheckResult(result) => Ok(result),
        _ => Err("candidate-exchange-failed: native-connectivity-check-result-required".into()),
    }
}

fn nominated_pair_id(checks: &ConnectivityChecksResponse) -> Result<Option<String>, String> {
    let Some(encoded) = checks.nomination_envelope.as_deref() else {
        return Ok(None);
    };
    let envelope = AuthenticatedSignalingEnvelope::decode(encoded)
        .map_err(|error| classify_failure("candidate-exchange-failed", &error))?;
    match envelope.payload {
        NativeSignalingPayload::NativeCandidateNomination(nomination) => {
            Ok(Some(nomination.pair_id))
        }
        _ => Err("candidate-exchange-failed: native-connectivity-nomination-required".into()),
    }
}

fn connectivity_attempt_agreed(
    checks: &ConnectivityChecksResponse,
    peer: &ConnectivityCheckResultPayload,
) -> Result<bool, String> {
    let pair_id = nominated_pair_id(checks)?;
    Ok(connectivity_results_agree(pair_id.as_deref(), peer))
}

fn connectivity_results_agree(
    local_pair_id: Option<&str>,
    peer: &ConnectivityCheckResultPayload,
) -> bool {
    local_pair_id.is_some_and(|pair_id| {
        peer.failure.is_none()
            && peer
                .viable_pair_ids
                .iter()
                .any(|peer_pair_id| peer_pair_id == pair_id)
    })
}

fn connectivity_attempt_failure(
    checks: &ConnectivityChecksResponse,
    peer: &ConnectivityCheckResultPayload,
) -> String {
    if checks.nomination_envelope.is_none() {
        return connectivity_checks_failure(&checks.diagnostics);
    }
    match peer.failure {
        Some(NativeConnectivityFailure::UdpBlocked)
        | Some(NativeConnectivityFailure::DirectConnectTimeout) => classify_failure(
            "direct-connect-timeout",
            "the peer did not receive an authenticated UDP probe",
        ),
        Some(NativeConnectivityFailure::SymmetricNatLikely) => classify_failure(
            "endpoint-dependent-nat-likely",
            "the peer reported endpoint-dependent mapping during direct checks",
        ),
        Some(NativeConnectivityFailure::NoViablePair) => classify_failure(
            "authenticated-udp-no-viable-pair",
            "the peer received authenticated UDP but did not confirm a viable pair",
        ),
        Some(NativeConnectivityFailure::Cancelled) => "peer-cancelled".into(),
        Some(_) => classify_failure(
            "no-direct-path",
            "the peer rejected the authenticated direct-connect attempt",
        ),
        None => classify_failure(
            "no-direct-path",
            "the peers did not agree on the same authenticated candidate pair",
        ),
    }
}

fn connectivity_attempt_recoverable(peer: &ConnectivityCheckResultPayload) -> bool {
    matches!(
        peer.failure,
        None | Some(NativeConnectivityFailure::UdpBlocked)
            | Some(NativeConnectivityFailure::DirectConnectTimeout)
            | Some(NativeConnectivityFailure::NoViablePair)
            | Some(NativeConnectivityFailure::SymmetricNatLikely)
    )
}

fn should_retry_connectivity_attempt(attempt: u32, peer: &ConnectivityCheckResultPayload) -> bool {
    attempt < MAX_DIRECT_CONNECT_ATTEMPTS && connectivity_attempt_recoverable(peer)
}

async fn close_failed_connectivity_attempt(connectivity_session_id: &str) -> Result<(), String> {
    connectivity::discard_connectivity_session(connectivity_session_id)
        .await
        .map_err(|error| classify_failure("direct-connect-recovery-failed", &error))
}

async fn await_signaling_operation<T, F>(
    cancellation: &CancellationToken,
    operation: F,
) -> Result<T, String>
where
    F: Future<Output = Result<T, String>>,
{
    tokio::select! {
        _ = cancellation.cancelled() => Err("native-transfer-cancelled".into()),
        result = operation => result,
    }
}

fn signaling_connect_error_retryable(error: &str) -> bool {
    !matches!(
        error,
        "native-signaling-endpoint-invalid"
            | "native-signaling-route-invalid"
            | "native-signaling-file-summary-required"
            | "native-signaling-file-summary-invalid"
            | "native-signaling-state-unavailable"
            | "native-signaling-disabled"
            | "native-route-unauthorized"
            | "invalid-native-envelope"
            | "invalid-native-capability"
            | "invalid-native-control"
    )
}

fn classify_receiver_wait_error(error: &str) -> String {
    if error == "native-signaling-cancelled" {
        "native-transfer-cancelled".into()
    } else if let Some(classified) = classify_signaling_server_failure(error) {
        classified
    } else if error == "native-signaling-receiver-timeout" {
        classify_failure("receiver-not-ready", error)
    } else {
        classify_failure("signaling-unavailable", error)
    }
}

fn classify_signaling_exchange_error(error: &str) -> String {
    if error == "native-signaling-cancelled" {
        "native-transfer-cancelled".into()
    } else if let Some(classified) = classify_signaling_server_failure(error) {
        classified
    } else if error.contains("reconnect-exhausted")
        || error.contains("state-unavailable")
        || error.contains("transport-unavailable")
        || error.contains("connect-failed")
        || error.contains("connect-timeout")
    {
        classify_failure("signaling-unavailable", error)
    } else {
        classify_failure("candidate-exchange-failed", error)
    }
}

fn classify_signaling_server_failure(error: &str) -> Option<String> {
    const CODES: [&str; 8] = [
        "native-signaling-disabled",
        "native-peer-offline",
        "native-route-unauthorized",
        "invalid-native-envelope",
        "share-offline-or-expired",
        "receiver-announcement-failed",
        "invalid-native-capability",
        "invalid-native-control",
    ];
    CODES
        .into_iter()
        .find(|code| error == *code || error.ends_with(&format!(": {code}")))
        .map(|code| classify_failure(code, error))
}

fn classify_candidate_setup_error(error: &str) -> String {
    let classification = if error.contains("authorization") || error.contains("invitation") {
        "authorization-delivery-failed"
    } else if error.contains("native-udp-bind")
        || error.contains("native-udp-address-family-unavailable")
    {
        "udp-bind-failed"
    } else if error.contains("native-connectivity-no-local-candidates") {
        "no-local-candidates"
    } else if error.contains("native-stun") {
        "stun-discovery-failed"
    } else if error.contains("authentication") || error.contains("signature") {
        "candidate-authentication-failed"
    } else {
        "candidate-gathering-failed"
    };
    classify_failure(classification, error)
}

fn classify_connectivity_checks_error(error: &str) -> String {
    if error == "native-connectivity-cancelled" {
        "native-transfer-cancelled".into()
    } else if error.contains("remote-candidates-required") {
        classify_failure("remote-candidates-missing", error)
    } else if error.contains("no-candidate-pairs") {
        classify_failure("no-compatible-candidate-pair", error)
    } else if error.contains("socket") || error.contains("udp-address-family") {
        classify_failure("udp-runtime-failed", error)
    } else {
        classify_failure("no-direct-path", error)
    }
}

fn connectivity_checks_failure(
    diagnostics: &super::connectivity_diagnostics::NativeConnectivityDiagnostics,
) -> String {
    use super::connectivity_diagnostics::ConnectivityOutcome;

    match diagnostics.failure_classification {
        Some(ConnectivityOutcome::UdpBlocked) => classify_failure(
            "udp-unavailable",
            "local UDP/STUN did not establish a usable path; UDP filtering or local network failure remains possible",
        ),
        Some(ConnectivityOutcome::FirewallBlockedLikely) => classify_failure(
            "authenticated-probe-timeout",
            "local STUN succeeded but no authenticated peer UDP probe arrived; peer availability, NAT mapping, and filtering remain unverified",
        ),
        Some(ConnectivityOutcome::SymmetricNatLikely) => classify_failure(
            "endpoint-dependent-nat-likely",
            "STUN observed destination-dependent address or port mapping and authenticated nomination did not complete",
        ),
        Some(ConnectivityOutcome::NoViablePair) => classify_failure(
            "authenticated-udp-no-viable-pair",
            "authenticated UDP was observed but the bidirectional confirmation exchange did not complete",
        ),
        Some(ConnectivityOutcome::Cancelled) => "native-transfer-cancelled".into(),
        Some(ConnectivityOutcome::DirectConnectTimeout) => classify_failure(
            "direct-connect-timeout",
            "native candidate checks expired before an authenticated pair was nominated",
        ),
        Some(ConnectivityOutcome::CandidateAuthenticationFailed) => classify_failure(
            "candidate-authentication-failed",
            "the peer connectivity message or probe could not be authenticated",
        ),
        Some(ConnectivityOutcome::CandidateExchangeFailed) => classify_failure(
            "candidate-exchange-failed",
            "the peers did not complete authenticated candidate exchange",
        ),
        _ => classify_failure(
            "no-direct-path",
            diagnostics
                .last_error
                .as_deref()
                .unwrap_or("nomination-unavailable"),
        ),
    }
}

async fn connect_signaling_with_retry(
    options: NativeWebSocketSignalingOptions,
    timeout: Duration,
    cancellation: &CancellationToken,
) -> Result<NativeWebSocketSignalingTransport, String> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last_error = "native-signaling-connect-failed".to_string();
    loop {
        if cancellation.is_cancelled() {
            return Err("native-transfer-cancelled".into());
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(classify_signaling_server_failure(&last_error)
                .unwrap_or_else(|| classify_failure("signaling-unavailable", &last_error)));
        }
        let attempt = tokio::select! {
            _ = cancellation.cancelled() => return Err("native-transfer-cancelled".into()),
            result = tokio::time::timeout(
                remaining,
                NativeWebSocketSignalingTransport::connect(options.clone()),
            ) => result,
        };
        let error = match attempt {
            Ok(Ok(transport)) => return Ok(transport),
            Ok(Err(error)) => error,
            Err(_) => {
                return Err(classify_signaling_server_failure(&last_error)
                    .unwrap_or_else(|| classify_failure("signaling-unavailable", &last_error)));
            }
        };
        if !signaling_connect_error_retryable(&error) {
            return Err(classify_signaling_server_failure(&error)
                .unwrap_or_else(|| classify_failure("signaling-unavailable", &error)));
        }
        last_error = error;
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(classify_signaling_server_failure(&last_error)
                .unwrap_or_else(|| classify_failure("signaling-unavailable", &last_error)));
        }
        let retry_delay = Duration::from_millis(350).min(remaining);
        tokio::select! {
            _ = cancellation.cancelled() => return Err("native-transfer-cancelled".into()),
            _ = tokio::time::sleep(retry_delay) => {}
        }
    }
}

fn install_task_abort_if_running(slot: &mut Option<AbortHandle>, task: &JoinHandle<()>) {
    if !task.is_finished() {
        *slot = Some(task.abort_handle());
    }
}

async fn register_outgoing_task(record: &OutgoingNativeTransfer, task: &JoinHandle<()>) {
    let mut mutable = record.mutable.lock().await;
    install_task_abort_if_running(&mut mutable.task_abort, task);
}

async fn register_incoming_task(record: &IncomingNativeTransfer, task: &JoinHandle<()>) {
    let mut mutable = record.mutable.lock().await;
    install_task_abort_if_running(&mut mutable.task_abort, task);
}

pub(crate) async fn claim_outgoing_finalization(
    record: &OutgoingNativeTransfer,
) -> Result<(), String> {
    let mut mutable = record.mutable.lock().await;
    if mutable.local_stop == Some(LocalStopIntent::Pause)
        || mutable.state == OutgoingNativeState::Paused
    {
        return Err("native-transfer-paused".into());
    }
    if matches!(mutable.local_stop, Some(LocalStopIntent::Cancel { .. }))
        || mutable.state == OutgoingNativeState::Cancelled
    {
        return Err("native-transfer-cancelled".into());
    }
    if mutable.state != OutgoingNativeState::Transferring {
        return Err("native-outgoing-finalization-state-invalid".into());
    }
    mutable.state = OutgoingNativeState::Finalizing;
    Ok(())
}

pub(crate) async fn claim_incoming_finalization(
    record: &IncomingNativeTransfer,
) -> Result<(), String> {
    let mut mutable = record.mutable.lock().await;
    if mutable.local_stop == Some(LocalStopIntent::Pause)
        || mutable.state == IncomingNativeState::Paused
    {
        return Err("native-transfer-paused".into());
    }
    if matches!(mutable.local_stop, Some(LocalStopIntent::Cancel { .. }))
        || mutable.state == IncomingNativeState::Cancelled
    {
        return Err("native-transfer-cancelled".into());
    }
    if mutable.state != IncomingNativeState::Receiving {
        return Err("native-incoming-finalization-state-invalid".into());
    }
    mutable.state = IncomingNativeState::Finalizing;
    Ok(())
}

async fn finish_outgoing_runtime(
    record: &OutgoingNativeTransfer,
    result: Result<split_transfer::SplitTransferResult, String>,
) {
    let mut mutable = record.mutable.lock().await;
    mutable.task_abort = None;
    match result {
        Ok(result) => {
            mutable.bytes_sent = result.payload_bytes;
            mutable.bytes_skipped = result.bytes_skipped;
            mutable.integrity_result = Some(result.integrity_result.into());
            mutable.signaling_file_payload_bytes = result.signaling_file_payload_bytes;
            mutable.performance = Some(result);
            mutable.state = OutgoingNativeState::Completed;
            mutable.terminal_error = None;
        }
        Err(error) => {
            mutable.state = terminal_outgoing_state(mutable.state, &error);
            mutable.terminal_error = if mutable.state == OutgoingNativeState::Completed {
                None
            } else {
                Some(match mutable.local_stop {
                    Some(LocalStopIntent::Cancel { .. }) => "native-transfer-cancelled".into(),
                    Some(LocalStopIntent::Pause) => "native-transfer-paused".into(),
                    None => classify_runtime_error(&error),
                })
            };
        }
    }
    let state = mutable.state;
    drop(mutable);
    if state == OutgoingNativeState::Paused {
        if let Err(error) = persist_outgoing_state(record).await {
            let mut mutable = record.mutable.lock().await;
            mutable.state = OutgoingNativeState::Failed;
            mutable.terminal_error = Some(classify_failure("resume-state-mismatch", &error));
        }
    }
    if matches!(
        state,
        OutgoingNativeState::Completed | OutgoingNativeState::Cancelled
    ) {
        remove_outgoing_state(record).await;
    }
    if state == OutgoingNativeState::Cancelled {
        if let Ok(transfer_id) = parse_transfer_id(&record.transfer_id) {
            let _ = authorization::revoke(&transfer_id);
        }
        let _ = secret_store::delete(&record.authorization_resume_path).await;
    }
}

async fn finish_incoming_runtime(
    record: &IncomingNativeTransfer,
    result: Result<split_transfer::SplitTransferResult, String>,
) {
    let mut mutable = record.mutable.lock().await;
    mutable.task_abort = None;
    match result {
        Ok(result) => {
            mutable.bytes_received = result.payload_bytes;
            mutable.bytes_written = result.payload_bytes;
            mutable.bytes_skipped = result.bytes_skipped;
            mutable.integrity_result = Some(result.integrity_result.into());
            mutable.signaling_file_payload_bytes = result.signaling_file_payload_bytes;
            mutable.performance = Some(result);
            mutable.state = IncomingNativeState::Completed;
            mutable.terminal_error = None;
        }
        Err(error) => {
            mutable.state = terminal_incoming_state(mutable.state, &error);
            mutable.terminal_error = if mutable.state == IncomingNativeState::Completed {
                None
            } else {
                Some(match mutable.local_stop {
                    Some(LocalStopIntent::Cancel { .. }) => "native-transfer-cancelled".into(),
                    Some(LocalStopIntent::Pause) => "native-transfer-paused".into(),
                    None => classify_runtime_error(&error),
                })
            };
        }
    }
    let cancelled = mutable.state == IncomingNativeState::Cancelled;
    let completed = mutable.state == IncomingNativeState::Completed;
    let delete_partial = matches!(
        mutable.local_stop,
        Some(LocalStopIntent::Cancel {
            retain_partial: false
        })
    ) || mutable.peer_cancel_retain_partial == Some(false);
    let part_path = mutable.part_path.clone();
    drop(mutable);
    if cancelled {
        if delete_partial {
            if let Some(part_path) = part_path {
                if reject_reparse_path(&part_path).await.is_ok() {
                    let _ = fs::remove_file(part_path).await;
                }
            }
        }
        if let Ok(transfer_id) = parse_transfer_id(&record.transfer_id) {
            let _ = authorization::revoke(&transfer_id);
        }
        let resume_path = record.authorization_resume_path.lock().await.clone();
        let _ = secret_store::delete(&resume_path).await;
    }
    if completed {
        if let Ok(transfer_id) = parse_transfer_id(&record.transfer_id) {
            let _ = authorization::consume(&transfer_id);
        }
        let resume_path = record.authorization_resume_path.lock().await.clone();
        let _ = secret_store::delete(&resume_path).await;
    }
    if completed || delete_partial || now_unix_ms() >= record.retention_expires_unix_ms {
        if let Ok(transfer_id) = parse_transfer_id(&record.transfer_id) {
            let destination = record.destination_directory.lock().await.clone();
            let _ = remove_incoming_workspace(&transfer_id, &destination).await;
        }
    }
}

fn terminal_outgoing_state(current: OutgoingNativeState, error: &str) -> OutgoingNativeState {
    if current == OutgoingNativeState::Completed {
        OutgoingNativeState::Completed
    } else if current == OutgoingNativeState::Cancelled
        || matches!(error, "native-transfer-cancelled" | "peer-cancelled")
    {
        OutgoingNativeState::Cancelled
    } else if current == OutgoingNativeState::Paused
        || matches!(error, "native-transfer-paused" | "peer-paused")
    {
        OutgoingNativeState::Paused
    } else {
        OutgoingNativeState::Failed
    }
}

fn terminal_incoming_state(current: IncomingNativeState, error: &str) -> IncomingNativeState {
    if current == IncomingNativeState::Completed {
        IncomingNativeState::Completed
    } else if current == IncomingNativeState::Cancelled
        || matches!(error, "native-transfer-cancelled" | "peer-cancelled")
    {
        IncomingNativeState::Cancelled
    } else if current == IncomingNativeState::Paused
        || matches!(error, "native-transfer-paused" | "peer-paused")
    {
        IncomingNativeState::Paused
    } else {
        IncomingNativeState::Failed
    }
}

fn classify_runtime_error(error: &str) -> String {
    if error.contains(':')
        || matches!(
            error,
            "peer-cancelled"
                | "native-transfer-cancelled"
                | "native-transfer-paused"
                | "peer-paused"
                | "completed-ack-lost"
                | "integrity-mismatch"
                | "source-file-changed"
                | "native-runtime-panic"
        )
    {
        return error.to_string();
    }
    let class = if error.contains("authorization") || error.contains("invitation") {
        "authorization-delivery-failed"
    } else if error.contains("signaling") {
        "signaling-unavailable"
    } else if error.contains("candidate") {
        "candidate-exchange-failed"
    } else if error.contains("direct") || error.contains("nomination") {
        "no-direct-path"
    } else if error.contains("quic") || error.contains("connect") {
        "quic-connect-failed"
    } else if error.contains("handshake") || error.contains("authentication") {
        "secure-handshake-failed"
    } else {
        "transfer-interrupted"
    };
    classify_failure(class, error)
}

fn classify_failure(classification: &str, detail: &str) -> String {
    format!("{classification}: {detail}")
}

fn bounded_timeout(value: Option<u64>, default_ms: u64) -> Duration {
    Duration::from_millis(value.unwrap_or(default_ms).clamp(5_000, 120_000))
}

async fn insert_receiver_bootstrap(prepared: PreparedReceiverBootstrap) -> Result<(), String> {
    let key = Uuid::from_bytes(prepared.bootstrap_id).to_string();
    decode_receiver_bootstrap(&prepared.encoded_package, now_unix_ms())?;
    let mut records = RECEIVER_BOOTSTRAPS.lock().await;
    prune_bootstraps(&mut records);
    if records.len() >= MAX_SPLIT_ROLE_RECORDS {
        return Err("native-receiver-bootstrap-capacity-reached".into());
    }
    records.insert(
        key,
        ReceiverBootstrapRecord {
            identity: prepared.identity,
            expires_unix_ms: prepared.expires_unix_ms,
        },
    );
    Ok(())
}

async fn take_receiver_bootstrap(bootstrap_id: &str) -> Result<ReceiverBootstrapRecord, String> {
    RECEIVER_BOOTSTRAPS
        .lock()
        .await
        .remove(bootstrap_id)
        .ok_or_else(|| "native-receiver-bootstrap-unavailable".into())
}

async fn restore_receiver_bootstrap(bootstrap_id: String, bootstrap: ReceiverBootstrapRecord) {
    if bootstrap.expires_unix_ms.saturating_add(30_000) < now_unix_ms() {
        return;
    }
    let mut records = RECEIVER_BOOTSTRAPS.lock().await;
    prune_bootstraps(&mut records);
    if records.len() < MAX_SPLIT_ROLE_RECORDS && !records.contains_key(&bootstrap_id) {
        records.insert(bootstrap_id, bootstrap);
    }
}

async fn rollback_incoming_resume_setup(
    bootstrap_id: String,
    bootstrap_expires_unix_ms: u64,
    record: &IncomingNativeTransfer,
    authorization_lease: authorization::PersistedAuthorizationRestoreLease,
) {
    authorization::rollback_persisted_restore(authorization_lease);
    if let Some(identity) = record.receiver_identity.lock().await.take() {
        restore_receiver_bootstrap(
            bootstrap_id,
            ReceiverBootstrapRecord {
                identity,
                expires_unix_ms: bootstrap_expires_unix_ms,
            },
        )
        .await;
    }
}

fn prune_bootstraps(records: &mut HashMap<String, ReceiverBootstrapRecord>) {
    let now = now_unix_ms();
    records.retain(|_, value| value.expires_unix_ms.saturating_add(30_000) >= now);
}

async fn insert_outgoing(record: Arc<OutgoingNativeTransfer>) -> Result<(), String> {
    let mut records = OUTGOING_TRANSFERS.lock().await;
    if records.len() >= MAX_SPLIT_ROLE_RECORDS {
        return Err("native-outgoing-registry-capacity-reached".into());
    }
    if records.contains_key(&record.transfer_id) {
        return Err("native-outgoing-transfer-exists".into());
    }
    records.insert(record.transfer_id.clone(), record);
    Ok(())
}

async fn insert_incoming(record: Arc<IncomingNativeTransfer>) -> Result<(), String> {
    let mut records = INCOMING_TRANSFERS.lock().await;
    if records.len() >= MAX_SPLIT_ROLE_RECORDS {
        return Err("native-incoming-registry-capacity-reached".into());
    }
    if records.contains_key(&record.transfer_id) {
        return Err("native-incoming-transfer-exists".into());
    }
    records.insert(record.transfer_id.clone(), record);
    Ok(())
}

async fn lookup_outgoing(transfer_id: &str) -> Result<Arc<OutgoingNativeTransfer>, String> {
    let canonical = Uuid::parse_str(transfer_id)
        .map_err(|_| "native-outgoing-transfer-id-invalid")?
        .to_string();
    OUTGOING_TRANSFERS
        .lock()
        .await
        .get(&canonical)
        .cloned()
        .ok_or_else(|| "native-outgoing-transfer-not-found".into())
}

async fn lookup_incoming(transfer_id: &str) -> Result<Arc<IncomingNativeTransfer>, String> {
    let canonical = Uuid::parse_str(transfer_id)
        .map_err(|_| "native-incoming-transfer-id-invalid")?
        .to_string();
    INCOMING_TRANSFERS
        .lock()
        .await
        .get(&canonical)
        .cloned()
        .ok_or_else(|| "native-incoming-transfer-not-found".into())
}

async fn outgoing_snapshot(record: &OutgoingNativeTransfer) -> OutgoingNativeTransferSnapshot {
    let mutable = record.mutable.lock().await;
    OutgoingNativeTransferSnapshot {
        transfer_id: record.transfer_id.clone(),
        invitation_id: record.invitation_id.clone(),
        state: mutable.state,
        source_path: record.source_path.display().to_string(),
        display_filename: record.display_filename.clone(),
        file_size: record.file_size,
        expected_sha256: hex(&record.expected_sha256),
        receiver_certificate_fingerprint_sha256: hex(
            &record.receiver_certificate_fingerprint_sha256
        ),
        candidate_privacy_policy: record.candidate_privacy_policy,
        expires_unix_ms: record.expires_unix_ms,
        created_unix_ms: record.created_unix_ms,
        bytes_sent: mutable.bytes_sent,
        bytes_skipped: mutable.bytes_skipped,
        peer_checkpoint_generation: mutable.peer_checkpoint_generation,
        peer_state_digest: mutable.peer_state_digest.map(|value| hex(&value)),
        peer_completed_bytes: mutable.peer_completed_bytes,
        connectivity_session_id: mutable.connectivity_session_id.clone(),
        quic_session_id: mutable.quic_session_id.clone(),
        selected_path: mutable.selected_path.clone(),
        integrity_result: mutable.integrity_result.clone(),
        performance: mutable.performance.clone(),
        signaling_file_payload_bytes: mutable.signaling_file_payload_bytes,
        terminal_error: mutable.terminal_error.clone(),
        runtime_active: mutable.task_abort.is_some(),
        production_native_enabled: true,
    }
}

async fn incoming_snapshot(record: &IncomingNativeTransfer) -> IncomingNativeTransferSnapshot {
    let destination = record.destination_directory.lock().await.clone();
    let mutable = record.mutable.lock().await;
    IncomingNativeTransferSnapshot {
        transfer_id: record.transfer_id.clone(),
        invitation_id: record.invitation_id.clone(),
        state: mutable.state,
        destination_directory: destination.display().to_string(),
        accepted_filename: mutable.accepted_filename.clone(),
        expected_file_size: mutable.expected_file_size,
        expected_sha256: mutable.expected_sha256.map(|value| hex(&value)),
        final_path: mutable
            .final_path
            .as_ref()
            .map(|value| value.display().to_string()),
        part_path: mutable
            .part_path
            .as_ref()
            .map(|value| value.display().to_string()),
        receiver_certificate_fingerprint_sha256: hex(
            &record.receiver_certificate_fingerprint_sha256
        ),
        expires_unix_ms: record.expires_unix_ms,
        retention_expires_unix_ms: record.retention_expires_unix_ms,
        created_unix_ms: record.created_unix_ms,
        bytes_received: mutable.bytes_received,
        bytes_written: mutable.bytes_written,
        bytes_skipped: mutable.bytes_skipped,
        checkpoint_generation: mutable.checkpoint_generation,
        secure_state_digest: mutable.secure_state_digest.map(|value| hex(&value)),
        completed_checkpoint_bytes: mutable.completed_checkpoint_bytes,
        connectivity_session_id: mutable.connectivity_session_id.clone(),
        quic_session_id: mutable.quic_session_id.clone(),
        selected_path: mutable.selected_path.clone(),
        integrity_result: mutable.integrity_result.clone(),
        performance: mutable.performance.clone(),
        signaling_file_payload_bytes: mutable.signaling_file_payload_bytes,
        terminal_error: mutable.terminal_error.clone(),
        runtime_active: mutable.task_abort.is_some(),
        source_path_exposed: false,
        authorization_secret: "[REDACTED]",
        production_native_enabled: true,
    }
}

pub fn sanitize_received_filename(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > 255
        || value.chars().count() > 240
        || value.chars().any(|character| character.is_control())
        || value.contains(['/', '\\', ':'])
    {
        return Err("native-incoming-filename-unsafe".into());
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("native-incoming-filename-unsafe".into());
    }
    let normalized = value.trim_end_matches([' ', '.']);
    if normalized.is_empty() || normalized == "." || normalized == ".." {
        return Err("native-incoming-filename-unsafe".into());
    }
    let stem = Path::new(normalized)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(normalized)
        .trim_end_matches([' ', '.'])
        .to_ascii_uppercase();
    if is_windows_reserved_name(&stem) {
        return Err("native-incoming-filename-reserved".into());
    }
    Ok(normalized.to_string())
}

fn is_windows_reserved_name(stem: &str) -> bool {
    matches!(stem, "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$")
        || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|suffix| suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9'))
}

async fn canonical_destination_directory(value: &str) -> Result<PathBuf, String> {
    if value.trim().is_empty() {
        return Err("native-incoming-destination-unavailable".into());
    }
    let configured = PathBuf::from(value);
    reject_reparse_if_present(&configured).await?;
    fs::create_dir_all(&configured)
        .await
        .map_err(|_| "native-incoming-destination-create-failed")?;
    reject_reparse_path(&configured).await?;
    let path = fs::canonicalize(&configured)
        .await
        .map_err(|_| "native-incoming-destination-unavailable")?;
    if !fs::metadata(&path)
        .await
        .map_err(|_| "native-incoming-destination-unavailable")?
        .is_dir()
    {
        return Err("native-incoming-destination-not-directory".into());
    }
    Ok(path)
}

async fn canonical_existing_destination_directory(value: &str) -> Result<PathBuf, String> {
    if value.trim().is_empty() {
        return Err("native-incoming-destination-unavailable".into());
    }
    let configured = PathBuf::from(value);
    reject_reparse_path(&configured).await?;
    let path = fs::canonicalize(&configured)
        .await
        .map_err(|_| "native-incoming-destination-unavailable")?;
    if !fs::metadata(&path)
        .await
        .map_err(|_| "native-incoming-destination-unavailable")?
        .is_dir()
    {
        return Err("native-incoming-destination-not-directory".into());
    }
    Ok(path)
}

fn duplicate_destination_name(
    directory: &Path,
    filename: &str,
    overwrite: bool,
) -> Result<PathBuf, String> {
    let requested = directory.join(filename);
    if overwrite || !requested.exists() {
        return Ok(requested);
    }
    let path = Path::new(filename);
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("file");
    let extension = path.extension().and_then(|value| value.to_str());
    for index in 1..100_000u32 {
        let candidate = match extension {
            Some(extension) => directory.join(format!("{stem} ({index}).{extension}")),
            None => directory.join(format!("{stem} ({index})")),
        };
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err("native-incoming-destination-name-exhausted".into())
}

fn ensure_contained_destination(directory: &Path, target: &Path) -> Result<(), String> {
    if target.parent() != Some(directory) || !target.starts_with(directory) {
        return Err("native-incoming-destination-escaped".into());
    }
    Ok(())
}

fn incoming_artifact_directory(destination: &Path, transfer_id: &[u8; 16]) -> PathBuf {
    destination
        .join(".flowshare-native")
        .join(Uuid::from_bytes(*transfer_id).to_string())
}

fn incoming_state_root() -> Result<PathBuf, String> {
    Ok(super::platform_handles::state_root()
        .map_err(|_| "native-incoming-state-directory-unavailable")?
        .join("FlowGet")
        .join("flowshare-native")
        .join("incoming"))
}

async fn canonical_incoming_state_directory(
    transfer_id: &[u8; 16],
    create: bool,
) -> Result<PathBuf, String> {
    let root = incoming_state_root()?;
    reject_reparse_if_present(&root).await?;
    if create {
        fs::create_dir_all(&root)
            .await
            .map_err(|_| "native-incoming-state-directory-unavailable")?;
    }
    reject_reparse_path(&root).await?;
    let root = fs::canonicalize(root)
        .await
        .map_err(|_| "native-incoming-state-directory-unavailable")?;
    let state = root.join(Uuid::from_bytes(*transfer_id).to_string());
    reject_reparse_if_present(&state).await?;
    if create {
        fs::create_dir_all(&state)
            .await
            .map_err(|_| "native-incoming-state-directory-unavailable")?;
    }
    reject_reparse_path(&state).await?;
    let state = fs::canonicalize(state)
        .await
        .map_err(|_| "native-incoming-state-directory-unavailable")?;
    if state.parent() != Some(root.as_path()) {
        return Err("native-incoming-state-directory-unavailable".into());
    }
    Ok(state)
}

async fn persist_incoming_retention(
    state_directory: &Path,
    retention: &PersistedIncomingRetention,
) -> Result<(), String> {
    let bytes =
        serde_json::to_vec(retention).map_err(|_| "native-incoming-retention-encode-failed")?;
    let current = state_directory.join("retention.json");
    let pending = state_directory.join("retention.pending");
    let previous = state_directory.join("retention.previous");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&pending)
        .await
        .map_err(|_| "native-incoming-retention-write-failed")?;
    file.write_all(&bytes)
        .await
        .map_err(|_| "native-incoming-retention-write-failed")?;
    file.sync_all()
        .await
        .map_err(|_| "native-incoming-retention-write-failed")?;
    drop(file);
    if fs::try_exists(&current)
        .await
        .map_err(|_| "native-incoming-retention-write-failed")?
    {
        let _ = fs::remove_file(&previous).await;
        fs::rename(&current, &previous)
            .await
            .map_err(|_| "native-incoming-retention-write-failed")?;
    }
    if fs::rename(&pending, &current).await.is_err() {
        if fs::try_exists(&previous).await.unwrap_or(false) {
            let _ = fs::rename(&previous, &current).await;
        }
        return Err("native-incoming-retention-write-failed".into());
    }
    let _ = fs::remove_file(&previous).await;
    Ok(())
}

async fn load_incoming_retention(
    transfer_id: &[u8; 16],
) -> Result<PersistedIncomingRetention, String> {
    let state = canonical_incoming_state_directory(transfer_id, false).await?;
    let canonical = Uuid::from_bytes(*transfer_id).to_string();
    for filename in ["retention.json", "retention.previous"] {
        let Ok(bytes) = fs::read(state.join(filename)).await else {
            continue;
        };
        let Ok(retention) = serde_json::from_slice::<PersistedIncomingRetention>(&bytes) else {
            continue;
        };
        if retention.version == INCOMING_RETENTION_VERSION
            && retention.transfer_id == canonical
            && retention.expires_unix_ms > retention.created_unix_ms
            && retention.expires_unix_ms
                <= retention
                    .created_unix_ms
                    .saturating_add(MAX_INCOMING_RETENTION_MS)
        {
            return Ok(retention);
        }
    }
    Err("native-incoming-retention-invalid".into())
}

async fn remove_empty_directory(path: &Path) {
    if let Ok(mut entries) = fs::read_dir(path).await {
        if entries.next_entry().await.ok().flatten().is_none() {
            let _ = fs::remove_dir(path).await;
        }
    }
}

async fn remove_incoming_artifact_directory(
    transfer_id: &[u8; 16],
    destination: &Path,
) -> Result<(), String> {
    let root_path = destination.join(".flowshare-native");
    if !fs::try_exists(&root_path).await.unwrap_or(false) {
        return Ok(());
    }
    let root = canonical_native_storage_root(destination, false).await?;
    let artifact_path = incoming_artifact_directory(destination, transfer_id);
    if !fs::try_exists(&artifact_path).await.unwrap_or(false) {
        remove_empty_directory(&root).await;
        return Ok(());
    }
    let artifact = canonical_incoming_artifact_directory(destination, transfer_id, false).await?;
    reject_nested_or_reparse_entries(&artifact).await?;
    fs::remove_dir_all(&artifact)
        .await
        .map_err(|_| "native-incoming-state-delete-failed")?;
    remove_empty_directory(&root).await;
    Ok(())
}

async fn remove_incoming_state_directory(transfer_id: &[u8; 16]) -> Result<(), String> {
    let state = match canonical_incoming_state_directory(transfer_id, false).await {
        Ok(state) => state,
        Err(_)
            if !incoming_state_root()?
                .join(Uuid::from_bytes(*transfer_id).to_string())
                .exists() =>
        {
            return Ok(())
        }
        Err(error) => return Err(error),
    };
    reject_nested_or_reparse_entries(&state).await?;
    fs::remove_dir_all(&state)
        .await
        .map_err(|_| "native-incoming-state-delete-failed")?;
    if let Ok(root) = incoming_state_root() {
        remove_empty_directory(&root).await;
    }
    Ok(())
}

async fn remove_incoming_workspace(
    transfer_id: &[u8; 16],
    destination: &Path,
) -> Result<(), String> {
    remove_incoming_artifact_directory(transfer_id, destination).await?;
    remove_incoming_state_directory(transfer_id).await
}

pub async fn cleanup_expired_incoming_transfers() -> Result<usize, String> {
    let root_path = incoming_state_root()?;
    if !fs::try_exists(&root_path).await.unwrap_or(false) {
        return Ok(0);
    }
    reject_reparse_path(&root_path).await?;
    let root = fs::canonicalize(&root_path)
        .await
        .map_err(|_| "native-incoming-state-directory-unavailable")?;
    let mut entries = fs::read_dir(&root)
        .await
        .map_err(|_| "native-incoming-state-directory-unavailable")?;
    let mut cleaned = 0usize;
    let mut inspected = 0usize;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|_| "native-incoming-state-directory-unavailable")?
    {
        inspected += 1;
        if inspected > 4096 {
            break;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(uuid) = Uuid::parse_str(&name) else {
            continue;
        };
        let transfer_id = *uuid.as_bytes();
        let canonical_id = uuid.to_string();
        let Ok(retention) = load_incoming_retention(&transfer_id).await else {
            continue;
        };
        if retention.expires_unix_ms > now_unix_ms() {
            continue;
        }
        let active_record = INCOMING_TRANSFERS.lock().await.get(&canonical_id).cloned();
        if let Some(record) = &active_record {
            if record.mutable.lock().await.task_abort.is_some() {
                continue;
            }
        }
        let destination = match canonical_existing_destination_directory(
            &retention.destination_directory,
        )
        .await
        {
            Ok(destination) => destination,
            Err(_) => continue,
        };
        if let Some(record) = active_record {
            INCOMING_TRANSFERS.lock().await.remove(&record.transfer_id);
        }
        let _ = authorization::revoke(&transfer_id);
        remove_incoming_workspace(&transfer_id, &destination).await?;
        cleaned += 1;
    }
    Ok(cleaned)
}

fn metadata_is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    false
}

pub(crate) async fn reject_reparse_if_present(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path).await {
        Ok(metadata) if metadata_is_reparse_point(&metadata) => {
            Err("native-incoming-reparse-point-rejected".into())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("native-incoming-artifact-unsafe".into()),
    }
}

async fn reject_nested_or_reparse_entries(directory: &Path) -> Result<(), String> {
    let mut entries = fs::read_dir(directory)
        .await
        .map_err(|_| "native-incoming-artifact-unsafe")?;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|_| "native-incoming-artifact-unsafe")?
    {
        let metadata = fs::symlink_metadata(entry.path())
            .await
            .map_err(|_| "native-incoming-artifact-unsafe")?;
        if metadata.is_dir() || metadata_is_reparse_point(&metadata) {
            return Err("native-incoming-reparse-point-rejected".into());
        }
    }
    Ok(())
}

pub(crate) async fn reject_reparse_path(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .await
        .map_err(|_| "native-incoming-artifact-unsafe")?;
    if metadata_is_reparse_point(&metadata) {
        return Err("native-incoming-reparse-point-rejected".into());
    }
    Ok(())
}

async fn canonical_native_storage_root(
    destination: &Path,
    create: bool,
) -> Result<PathBuf, String> {
    let root = destination.join(".flowshare-native");
    reject_reparse_if_present(&root).await?;
    if create {
        fs::create_dir_all(&root)
            .await
            .map_err(|_| "native-incoming-artifact-create-failed")?;
    }
    reject_reparse_path(&root).await?;
    let root = fs::canonicalize(root)
        .await
        .map_err(|_| "native-incoming-artifact-unsafe")?;
    if root.parent() != Some(destination) {
        return Err("native-incoming-artifact-unsafe".into());
    }
    Ok(root)
}

async fn canonical_incoming_artifact_directory(
    destination: &Path,
    transfer_id: &[u8; 16],
    create: bool,
) -> Result<PathBuf, String> {
    let root = canonical_native_storage_root(destination, create).await?;
    let artifact = incoming_artifact_directory(destination, transfer_id);
    reject_reparse_if_present(&artifact).await?;
    if create {
        fs::create_dir_all(&artifact)
            .await
            .map_err(|_| "native-incoming-artifact-create-failed")?;
    }
    reject_reparse_path(&artifact).await?;
    let artifact = fs::canonicalize(artifact)
        .await
        .map_err(|_| "native-incoming-artifact-unsafe")?;
    if artifact.parent() != Some(root.as_path()) {
        return Err("native-incoming-artifact-unsafe".into());
    }
    Ok(artifact)
}

fn outgoing_authorization_resume_path(transfer_id: &[u8; 16]) -> Result<PathBuf, String> {
    let root = super::platform_handles::state_root()
        .map_err(|_| "native-outgoing-state-directory-unavailable")?
        .join("FlowGet")
        .join("flowshare-native")
        .join("outgoing")
        .join(Uuid::from_bytes(*transfer_id).to_string());
    std::fs::create_dir_all(&root).map_err(|_| "native-outgoing-state-directory-unavailable")?;
    Ok(root.join("transfer.resume.current"))
}

async fn persist_outgoing_state(record: &OutgoingNativeTransfer) -> Result<(), String> {
    let mutable = record.mutable.lock().await;
    let mut state = PersistedOutgoingState {
        version: OUTGOING_STATE_VERSION,
        transfer_id: record.transfer_id.clone(),
        invitation_id: record.invitation_id.clone(),
        source_path: record.source_path.display().to_string(),
        source_identity: record.source_identity.clone(),
        display_filename: record.display_filename.clone(),
        file_size: record.file_size,
        expected_sha256: record.expected_sha256,
        candidate_privacy_policy: record.candidate_privacy_policy,
        expires_unix_ms: record.expires_unix_ms,
        created_unix_ms: record.created_unix_ms,
        previous_quic_session_id: mutable.quic_session_id.clone(),
        peer_checkpoint_generation: mutable.peer_checkpoint_generation,
        peer_state_digest: mutable.peer_state_digest,
        peer_completed_bytes: mutable.peer_completed_bytes,
        authentication_tag: [0; 32],
    };
    drop(mutable);
    let transfer_id = parse_transfer_id(&record.transfer_id)?;
    let material = authorization::material_for_transfer(&transfer_id)?;
    let checkpoint_key = super::secure_protocol::derive_checkpoint_key(
        &material.master,
        &transfer_id,
        &material.invitation.body.invitation_id,
    )?;
    state.authentication_tag = persisted_outgoing_state_tag(&state, &checkpoint_key)?;
    let bytes = serde_json::to_vec(&state).map_err(|_| "native-outgoing-state-encode-failed")?;
    let pending = record.outgoing_state_path.with_extension("pending");
    let previous = record.outgoing_state_path.with_extension("previous");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&pending)
        .await
        .map_err(|_| "native-outgoing-state-write-failed")?;
    file.write_all(&bytes)
        .await
        .map_err(|_| "native-outgoing-state-write-failed")?;
    file.sync_all()
        .await
        .map_err(|_| "native-outgoing-state-write-failed")?;
    drop(file);
    if fs::try_exists(&record.outgoing_state_path)
        .await
        .map_err(|_| "native-outgoing-state-write-failed")?
    {
        let _ = fs::remove_file(&previous).await;
        fs::rename(&record.outgoing_state_path, &previous)
            .await
            .map_err(|_| "native-outgoing-state-write-failed")?;
    }
    fs::rename(&pending, &record.outgoing_state_path)
        .await
        .map_err(|_| "native-outgoing-state-write-failed".to_string())
}

async fn load_persisted_outgoing(
    transfer_id: &[u8; 16],
    material: &authorization::AuthorizationMaterial,
) -> Result<PersistedOutgoingState, String> {
    let resume_path = outgoing_authorization_resume_path(transfer_id)?;
    let current = resume_path
        .parent()
        .ok_or("native-outgoing-state-directory-unavailable")?
        .join("outgoing-state.json");
    let previous = current.with_extension("previous");
    for candidate in [&current, &previous] {
        let Ok(bytes) = fs::read(candidate).await else {
            continue;
        };
        let Ok(state) = serde_json::from_slice::<PersistedOutgoingState>(&bytes) else {
            continue;
        };
        if state.version != OUTGOING_STATE_VERSION
            || parse_transfer_id(&state.transfer_id).ok() != Some(*transfer_id)
            || state.invitation_id
                != Uuid::from_bytes(material.invitation.body.invitation_id).to_string()
        {
            continue;
        }
        let checkpoint_key = super::secure_protocol::derive_checkpoint_key(
            &material.master,
            transfer_id,
            &material.invitation.body.invitation_id,
        )?;
        let expected = persisted_outgoing_state_tag(&state, &checkpoint_key)?;
        if bool::from(state.authentication_tag.ct_eq(&expected)) {
            return Ok(state);
        }
    }
    Err("native-outgoing-state-unavailable".into())
}

fn persisted_outgoing_state_tag(
    state: &PersistedOutgoingState,
    checkpoint_key: &[u8; 32],
) -> Result<[u8; 32], String> {
    let mut canonical = state.clone();
    canonical.authentication_tag = [0; 32];
    let payload =
        serde_json::to_vec(&canonical).map_err(|_| "native-outgoing-state-encode-failed")?;
    super::secure_protocol::checkpoint_mac(checkpoint_key, &payload)
}

async fn remove_outgoing_state(record: &OutgoingNativeTransfer) {
    for path in [
        record.outgoing_state_path.clone(),
        record.outgoing_state_path.with_extension("previous"),
        record.outgoing_state_path.with_extension("pending"),
    ] {
        let _ = fs::remove_file(path).await;
    }
}

async fn write_import_receipt(path: &Path, digest: [u8; 32]) -> Result<(), String> {
    let mut bytes = Vec::with_capacity(80);
    bytes.extend_from_slice(&RECEIPT_MAGIC);
    bytes.extend_from_slice(&digest);
    bytes.extend_from_slice(&now_unix_ms().to_be_bytes());
    let checksum = Sha256::digest(&bytes);
    bytes.extend_from_slice(&checksum);
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("native-manual-package-receipt-failed")?;
    let pending_path =
        path.with_file_name(format!(".{filename}.{}.pending", Uuid::new_v4().simple()));
    let result = async {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&pending_path)
            .await
            .map_err(|_| "native-manual-package-receipt-failed")?;
        file.write_all(&bytes)
            .await
            .map_err(|_| "native-manual-package-receipt-failed")?;
        file.sync_all()
            .await
            .map_err(|_| "native-manual-package-receipt-failed")?;
        drop(file);

        // Serialize the no-clobber check and atomic rename inside this process.
        // The final receipt name is never visible with partial contents: a
        // crash leaves only the uniquely named pending file.
        let _commit = RECEIPT_COMMIT_LOCK.lock().await;
        if fs::try_exists(path)
            .await
            .map_err(|_| "native-manual-package-receipt-failed")?
        {
            return Err("native-manual-package-receipt-failed".to_string());
        }
        fs::rename(&pending_path, path)
            .await
            .map_err(|_| "native-manual-package-receipt-failed")?;
        Ok(())
    }
    .await;
    if result.is_err() {
        let _ = fs::remove_file(&pending_path).await;
    }
    result
}

async fn read_import_receipt(path: &Path) -> Result<[u8; 32], String> {
    let bytes = fs::read(path)
        .await
        .map_err(|_| "native-manual-package-receipt-failed")?;
    if bytes.len() != 16 + 32 + 8 + 32 || bytes[..16] != RECEIPT_MAGIC {
        return Err("native-manual-package-receipt-failed".into());
    }
    let expected: [u8; 32] = Sha256::digest(&bytes[..56]).into();
    if !bool::from(expected.ct_eq(&bytes[56..88])) {
        return Err("native-manual-package-receipt-failed".into());
    }
    Ok(bytes[16..48]
        .try_into()
        .map_err(|_| "native-manual-package-receipt-failed")?)
}

fn parse_transfer_id(value: &str) -> Result<[u8; 16], String> {
    Ok(*Uuid::parse_str(value)
        .map_err(|_| "native-transfer-id-invalid")?
        .as_bytes())
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("native-sha256-invalid".into());
    }
    let mut output = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (decode_nibble(chunk[0])? << 4) | decode_nibble(chunk[1])?;
    }
    Ok(output)
}

fn decode_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("native-sha256-invalid".into()),
    }
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn ensure_native_beta_available() -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
pub async fn clear_for_test() {
    RECEIVER_BOOTSTRAPS.lock().await.clear();
    OUTGOING_TRANSFERS.lock().await.clear();
    INCOMING_TRANSFERS.lock().await.clear();
    IMPORTED_PACKAGE_DIGESTS.lock().await.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outgoing_record(state: OutgoingNativeState) -> Arc<OutgoingNativeTransfer> {
        let transfer_id = Uuid::new_v4();
        Arc::new(OutgoingNativeTransfer {
            transfer_id: transfer_id.to_string(),
            invitation_id: Uuid::new_v4().to_string(),
            source_path: PathBuf::from("source.bin"),
            source_identity: super::super::resume::SourceIdentity {
                size: 16,
                modified_unix_ms: None,
                platform_file_id: None,
                canonical_path: None,
            },
            display_filename: "source.bin".into(),
            file_size: 16,
            expected_sha256: [1; 32],
            receiver_certificate: CertificateDer::from(Vec::new()),
            receiver_certificate_fingerprint_sha256: [2; 32],
            candidate_privacy_policy: CandidatePrivacyPolicy::LanFirst,
            authorization_resume_path: PathBuf::from("transfer.resume.current"),
            outgoing_state_path: PathBuf::from("outgoing-state.json"),
            previous_quic_session_id: None,
            expires_unix_ms: now_unix_ms().saturating_add(60_000),
            created_unix_ms: now_unix_ms(),
            mutable: Mutex::new(OutgoingMutable {
                state,
                control_request: CancellationToken::new(),
                cancellation: CancellationToken::new(),
                local_stop: None,
                pause_request_id: None,
                task_abort: None,
                connectivity_session_id: None,
                quic_session_id: None,
                selected_path: None,
                bytes_sent: 0,
                bytes_skipped: 0,
                peer_checkpoint_generation: None,
                peer_state_digest: None,
                peer_completed_bytes: 0,
                integrity_result: None,
                performance: None,
                signaling_file_payload_bytes: 0,
                terminal_error: None,
            }),
        })
    }

    #[test]
    fn filename_validation_rejects_traversal_drives_and_windows_devices() {
        for unsafe_name in [
            "../escape.bin",
            "..\\escape.bin",
            "C:\\escape.bin",
            "\\\\server\\share.bin",
            "CON",
            "con.txt",
            "LPT9.log",
            "NUL.bin",
            "file/child.bin",
            "file\\child.bin",
        ] {
            assert!(
                sanitize_received_filename(unsafe_name).is_err(),
                "accepted unsafe filename {unsafe_name:?}"
            );
        }
    }

    #[test]
    fn filename_validation_normalizes_trailing_dots_and_preserves_extension() {
        assert_eq!(
            sanitize_received_filename("report.final.pdf...  ").unwrap(),
            "report.final.pdf"
        );
        assert_eq!(
            sanitize_received_filename("archive.tar.zst").unwrap(),
            "archive.tar.zst"
        );
    }

    #[test]
    fn destination_containment_is_strict() {
        let directory = Path::new("C:\\Downloads");
        assert!(ensure_contained_destination(directory, &directory.join("file.bin")).is_ok());
        assert!(ensure_contained_destination(directory, Path::new("C:\\file.bin")).is_err());
    }

    #[test]
    fn persisted_outgoing_state_mac_rejects_local_field_tampering() {
        let transfer_id = *Uuid::new_v4().as_bytes();
        let (invitation, master) = super::super::secure_protocol::create_invitation(
            transfer_id,
            [7; 32],
            super::super::secure_protocol::capability_digest(RESUME_REQUIRED_CAPABILITIES),
            60_000,
        )
        .unwrap();
        let key = super::super::secure_protocol::derive_checkpoint_key(
            &master,
            &transfer_id,
            &invitation.body.invitation_id,
        )
        .unwrap();
        let mut state = PersistedOutgoingState {
            version: OUTGOING_STATE_VERSION,
            transfer_id: Uuid::from_bytes(transfer_id).to_string(),
            invitation_id: Uuid::from_bytes(invitation.body.invitation_id).to_string(),
            source_path: "C:\\source.bin".into(),
            source_identity: super::super::resume::SourceIdentity {
                size: 10,
                modified_unix_ms: Some(2),
                platform_file_id: Some("volume:file".into()),
                canonical_path: Some("C:\\source.bin".into()),
            },
            display_filename: "source.bin".into(),
            file_size: 10,
            expected_sha256: [9; 32],
            candidate_privacy_policy: CandidatePrivacyPolicy::LanFirst,
            expires_unix_ms: invitation.body.expires_unix_ms,
            created_unix_ms: invitation.body.created_unix_ms,
            previous_quic_session_id: Some(Uuid::new_v4().to_string()),
            peer_checkpoint_generation: Some(1),
            peer_state_digest: Some([8; 32]),
            peer_completed_bytes: 4,
            authentication_tag: [0; 32],
        };
        state.authentication_tag = persisted_outgoing_state_tag(&state, &key).unwrap();
        assert_eq!(
            state.authentication_tag,
            persisted_outgoing_state_tag(&state, &key).unwrap()
        );
        state.peer_completed_bytes = 5;
        assert_ne!(
            state.authentication_tag,
            persisted_outgoing_state_tag(&state, &key).unwrap()
        );
    }

    #[tokio::test]
    async fn import_receipt_rejects_tampering() {
        let root = std::env::temp_dir().join(format!("flowshare-receipt-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).await.unwrap();
        let path = root.join("invitation.imported");
        let digest = [5; 32];
        write_import_receipt(&path, digest).await.unwrap();
        assert_eq!(read_import_receipt(&path).await.unwrap(), digest);
        let mut bytes = fs::read(&path).await.unwrap();
        bytes[20] ^= 1;
        fs::write(&path, bytes).await.unwrap();
        assert_eq!(
            read_import_receipt(&path).await.unwrap_err(),
            "native-manual-package-receipt-failed"
        );
        let _ = fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn import_receipt_reservation_is_atomic() {
        let root = std::env::temp_dir().join(format!("flowshare-receipt-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).await.unwrap();
        let path = root.join("invitation.imported");
        let (first, second) = tokio::join!(
            write_import_receipt(&path, [1; 32]),
            write_import_receipt(&path, [2; 32])
        );
        assert_ne!(first.is_ok(), second.is_ok());
        let stored = read_import_receipt(&path).await.unwrap();
        assert!(stored == [1; 32] || stored == [2; 32]);
        let _ = fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn import_receipt_commit_never_overwrites_a_complete_receipt() {
        let root = std::env::temp_dir().join(format!("flowshare-receipt-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).await.unwrap();
        let path = root.join("invitation.imported");
        write_import_receipt(&path, [7; 32]).await.unwrap();
        assert_eq!(
            write_import_receipt(&path, [8; 32]).await.unwrap_err(),
            "native-manual-package-receipt-failed"
        );
        assert_eq!(read_import_receipt(&path).await.unwrap(), [7; 32]);
        let mut entries = fs::read_dir(&root).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            let name = entry.file_name().to_string_lossy().to_string();
            assert!(!name.ends_with(".pending"), "stale receipt temp: {name}");
        }
        let _ = fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn missing_selected_destination_is_created_before_canonicalization() {
        let root = std::env::temp_dir().join(format!("flowshare-destination-{}", Uuid::new_v4()));
        let selected = root.join("Downloads").join("FlowShare");
        assert!(!selected.exists());
        let canonical = canonical_destination_directory(&selected.to_string_lossy())
            .await
            .unwrap();
        assert!(canonical.is_dir());
        assert_eq!(canonical, fs::canonicalize(&selected).await.unwrap());
        let _ = fs::remove_dir_all(root).await;
    }

    #[test]
    fn incoming_storage_preflight_reports_required_and_available_bytes() {
        assert_eq!(
            ensure_incoming_storage_capacity(4_096, Some(1_024)).unwrap_err(),
            "native-incoming-insufficient-space: required-bytes=4096; available-bytes=1024"
        );
        assert!(ensure_incoming_storage_capacity(4_096, Some(4_096)).is_ok());
        assert!(ensure_incoming_storage_capacity(4_096, None).is_ok());
    }

    #[tokio::test]
    async fn incoming_part_extension_fallback_preserves_resumable_length() {
        let root = std::env::temp_dir().join(format!("flowshare-part-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).await.unwrap();
        let path = root.join("payload.part");
        let mut part = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .await
            .unwrap();
        extend_incoming_part_length(&mut part, 2 * 1024 * 1024 + 17)
            .await
            .unwrap();
        drop(part);
        assert_eq!(
            fs::metadata(&path).await.unwrap().len(),
            2 * 1024 * 1024 + 17
        );
        let _ = fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn failed_incoming_resume_preparation_restores_receiver_bootstrap() {
        clear_for_test().await;
        let prepared =
            flowshare_native_prepare_incoming_receiver(Some(PrepareIncomingReceiverRequest {
                lifetime_ms: Some(60_000),
            }))
            .await
            .unwrap();
        let bootstrap_id = prepared.receiver_bootstrap_id.clone();
        let root = std::env::temp_dir().join(format!("flowshare-resume-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).await.unwrap();
        let error = flowshare_native_resume_incoming_transfer(ResumeIncomingTransferRequest {
            transfer_id: Uuid::new_v4().to_string(),
            receiver_bootstrap_id: bootstrap_id.clone(),
            destination_directory: root.to_string_lossy().to_string(),
            expected_checkpoint_generation: None,
            signaling_endpoint: "ws://127.0.0.1:9/ws".into(),
            gathering: None,
            signaling_timeout_ms: Some(5_000),
            connectivity_timeout_ms: Some(5_000),
        })
        .await
        .unwrap_err();
        assert!(error.starts_with("native-incoming-artifact"), "{error}");
        assert!(RECEIVER_BOOTSTRAPS.lock().await.contains_key(&bootstrap_id));
        let _ = fs::remove_dir_all(root).await;
        clear_for_test().await;
    }

    #[tokio::test]
    async fn duplicate_outgoing_insert_keeps_the_original_record() {
        clear_for_test().await;
        let original = outgoing_record(OutgoingNativeState::AwaitingReceiver);
        let mut duplicate = outgoing_record(OutgoingNativeState::Failed);
        Arc::get_mut(&mut duplicate).unwrap().transfer_id = original.transfer_id.clone();
        insert_outgoing(original.clone()).await.unwrap();
        assert_eq!(
            insert_outgoing(duplicate).await.unwrap_err(),
            "native-outgoing-transfer-exists"
        );
        let stored = lookup_outgoing(&original.transfer_id).await.unwrap();
        assert!(Arc::ptr_eq(&stored, &original));
        clear_for_test().await;
    }

    #[tokio::test]
    async fn signaling_operation_observes_transfer_cancellation_promptly() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            await_signaling_operation(&cancellation, std::future::pending::<Result<(), String>>()),
        )
        .await
        .expect("cancelled signaling operation must not wait for its network timeout")
        .unwrap_err();
        assert_eq!(result, "native-transfer-cancelled");
    }

    #[tokio::test]
    async fn task_registration_does_not_resurrect_completed_runtime() {
        let completed = tokio::spawn(async {});
        while !completed.is_finished() {
            tokio::task::yield_now().await;
        }
        let mut slot = None;
        install_task_abort_if_running(&mut slot, &completed);
        assert!(slot.is_none());
        completed.await.unwrap();

        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        let active = tokio::spawn(async move {
            let _ = wait.await;
        });
        install_task_abort_if_running(&mut slot, &active);
        assert!(slot.is_some());
        let _ = release.send(());
        active.await.unwrap();
    }

    #[tokio::test]
    async fn lifecycle_panic_is_converted_to_terminal_failed_state() {
        let record = outgoing_record(OutgoingNativeState::GatheringCandidates);
        let result = panic_safe_native_runtime(async {
            panic!("simulated native runtime panic");
            #[allow(unreachable_code)]
            Err::<split_transfer::SplitTransferResult, String>("unreachable".into())
        })
        .await;
        assert_eq!(result.as_ref().unwrap_err(), "native-runtime-panic");
        finish_outgoing_runtime(&record, result).await;
        let mutable = record.mutable.lock().await;
        assert_eq!(mutable.state, OutgoingNativeState::Failed);
        assert_eq!(
            mutable.terminal_error.as_deref(),
            Some("native-runtime-panic")
        );
        assert!(mutable.task_abort.is_none());
    }

    #[tokio::test]
    async fn failed_invitation_validation_restores_receiver_bootstrap_for_retry() {
        clear_for_test().await;
        let prepared =
            flowshare_native_prepare_incoming_receiver(Some(PrepareIncomingReceiverRequest {
                lifetime_ms: Some(60_000),
            }))
            .await
            .unwrap();
        let bootstrap_id = prepared.receiver_bootstrap_id.clone();
        let request = || ImportIncomingInvitationRequest {
            receiver_bootstrap_id: bootstrap_id.clone(),
            invitation_package: "not-a-secure-invitation".into(),
            destination_directory: std::env::temp_dir().display().to_string(),
            retention_expires_unix_ms: None,
        };

        let first = flowshare_native_import_incoming_invitation(request())
            .await
            .unwrap_err();
        assert!(first.starts_with("native-manual-package"), "{first}");
        assert!(RECEIVER_BOOTSTRAPS.lock().await.contains_key(&bootstrap_id));

        let second = flowshare_native_import_incoming_invitation(request())
            .await
            .unwrap_err();
        assert!(second.starts_with("native-manual-package"), "{second}");
        assert_ne!(second, "native-receiver-bootstrap-unavailable");
        clear_for_test().await;
    }

    #[test]
    fn connectivity_failure_classification_does_not_invent_peer_decline_or_cgnat() {
        assert_eq!(
            classify_receiver_wait_error("native-signaling-receiver-timeout"),
            "receiver-not-ready: native-signaling-receiver-timeout"
        );
        assert_eq!(
            classify_candidate_setup_error("native-udp-bind-failed"),
            "udp-bind-failed: native-udp-bind-failed"
        );
        assert_eq!(
            classify_connectivity_checks_error("native-connectivity-no-candidate-pairs"),
            "no-compatible-candidate-pair: native-connectivity-no-candidate-pairs"
        );
        assert_eq!(
            classify_signaling_exchange_error("native-signaling-disabled"),
            "native-signaling-disabled: native-signaling-disabled"
        );
        assert_eq!(
            classify_signaling_exchange_error(
                "native-signaling-delivery-retry-exhausted: native-peer-offline"
            ),
            "native-peer-offline: native-signaling-delivery-retry-exhausted: native-peer-offline"
        );
        assert!(!signaling_connect_error_retryable(
            "native-route-unauthorized"
        ));
        assert!(signaling_connect_error_retryable("native-peer-offline"));
        assert!(signaling_connect_error_retryable(
            "share-offline-or-expired"
        ));
    }

    #[test]
    fn bounded_recovery_barrier_makes_symmetric_retry_and_stop_decisions() {
        let failed = ConnectivityCheckResultPayload {
            attempted_pair_ids: vec!["pair-a".into()],
            viable_pair_ids: Vec::new(),
            authenticated_probes_sent: 4,
            authenticated_probes_received: 0,
            best_rtt_ms: None,
            failure: Some(NativeConnectivityFailure::UdpBlocked),
        };
        assert!(!connectivity_results_agree(Some("pair-a"), &failed));
        assert!(should_retry_connectivity_attempt(1, &failed));
        assert!(!should_retry_connectivity_attempt(
            MAX_DIRECT_CONNECT_ATTEMPTS,
            &failed
        ));

        let succeeded = ConnectivityCheckResultPayload {
            viable_pair_ids: vec!["pair-a".into()],
            failure: None,
            ..failed.clone()
        };
        assert!(connectivity_results_agree(Some("pair-a"), &succeeded));
        assert!(!connectivity_results_agree(Some("pair-b"), &succeeded));

        let fatal = ConnectivityCheckResultPayload {
            failure: Some(NativeConnectivityFailure::CandidateAuthenticationFailed),
            ..failed
        };
        assert!(!should_retry_connectivity_attempt(1, &fatal));
    }

    #[tokio::test]
    async fn finalization_boundary_preserves_terminal_ownership() {
        let record = outgoing_record(OutgoingNativeState::Transferring);
        assert!(claim_outgoing_finalization(&record).await.is_ok());
        assert_eq!(
            record.mutable.lock().await.state,
            OutgoingNativeState::Finalizing
        );

        clear_for_test().await;
        insert_outgoing(record.clone()).await.unwrap();
        let snapshot = flowshare_native_cancel_outgoing_transfer(CancelSplitTransferRequest {
            transfer_id: record.transfer_id.clone(),
            retain_partial: Some(false),
        })
        .await
        .unwrap();
        assert_eq!(snapshot.state, OutgoingNativeState::Finalizing);
        assert_eq!(
            terminal_outgoing_state(OutgoingNativeState::Completed, "transfer-interrupted"),
            OutgoingNativeState::Completed
        );
        assert_eq!(
            terminal_incoming_state(IncomingNativeState::Completed, "completed-ack-lost"),
            IncomingNativeState::Completed
        );
        clear_for_test().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn native_artifact_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!("flowshare-link-{}", Uuid::new_v4()));
        let outside = std::env::temp_dir().join(format!("flowshare-outside-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).await.unwrap();
        fs::create_dir_all(&outside).await.unwrap();
        symlink(&outside, root.join("linked")).unwrap();
        assert_eq!(
            reject_reparse_path(&root.join("linked")).await.unwrap_err(),
            "native-incoming-reparse-point-rejected"
        );
        let _ = fs::remove_dir_all(root).await;
        let _ = fs::remove_dir_all(outside).await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn native_artifact_reparse_point_is_rejected_when_symlinks_are_available() {
        use std::os::windows::fs::symlink_file;

        let root = std::env::temp_dir().join(format!("flowshare-link-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).await.unwrap();
        let target = root.join("target.bin");
        let link = root.join("linked.bin");
        fs::write(&target, b"test").await.unwrap();
        if symlink_file(&target, &link).is_ok() {
            assert_eq!(
                reject_reparse_path(&link).await.unwrap_err(),
                "native-incoming-reparse-point-rejected"
            );
        }
        let _ = fs::remove_dir_all(root).await;
    }
}
