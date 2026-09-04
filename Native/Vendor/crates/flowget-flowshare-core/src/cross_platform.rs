use crate::{
    candidates::CandidatePrivacyPolicy,
    cross_device::{self, IncomingNativeState, OutgoingNativeState},
    device_protocol::DevicePlatform,
    protocol::NATIVE_QUIC_PROTOCOL_VERSION,
    secret_store::{self, SecretProtector},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Duration,
};
use tokio::runtime::{Builder, Runtime};
use tokio_util::sync::CancellationToken;

pub const CAPABILITY_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
pub enum FlowShareErrorCode {
    SignalingUnavailable,
    PeerOffline,
    NativeConnectFailed,
    QuicConnectFailed,
    StunFailed,
    DirectConnectUnavailable,
    ProtocolMismatch,
    AuthorizationFailed,
    InvitationExpired,
    SourceUnavailable,
    DestinationUnavailable,
    DiskFull,
    SourceChanged,
    CheckpointInvalid,
    HashMismatch,
    Cancelled,
    InvalidRequest,
    UnsupportedPlatform,
    Internal,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
pub enum FlowShareErrorCategory {
    Connectivity,
    Security,
    Compatibility,
    Storage,
    User,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct FlowShareFailure {
    pub code: FlowShareErrorCode,
    pub category: FlowShareErrorCategory,
    pub retryable: bool,
    pub fallback_eligible: bool,
}

impl FlowShareFailure {
    pub fn classify(code: FlowShareErrorCode) -> Self {
        use FlowShareErrorCategory::*;
        use FlowShareErrorCode::*;
        let (category, retryable, fallback_eligible) = match code {
            SignalingUnavailable | PeerOffline => (Connectivity, true, false),
            NativeConnectFailed | QuicConnectFailed | StunFailed | DirectConnectUnavailable => {
                (Connectivity, true, true)
            }
            ProtocolMismatch | UnsupportedPlatform | InvalidRequest => {
                (Compatibility, false, false)
            }
            AuthorizationFailed | InvitationExpired => (Security, false, false),
            HashMismatch | SourceChanged | CheckpointInvalid => (Security, true, false),
            DiskFull | SourceUnavailable | DestinationUnavailable => (Storage, true, false),
            Cancelled => (User, false, false),
            FlowShareErrorCode::Internal => (FlowShareErrorCategory::Internal, true, false),
        };
        Self {
            code,
            category,
            retryable,
            fallback_eligible,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Error))]
pub enum FlowShareApiError {
    SignalingUnavailable,
    PeerOffline,
    AuthorizationFailed,
    InvitationExpired,
    ProtocolMismatch,
    StunFailed,
    DirectConnectUnavailable,
    QuicConnectFailed,
    SourceUnavailable,
    DestinationUnavailable,
    DiskFull,
    SourceChanged,
    CheckpointInvalid,
    HashMismatch,
    Cancelled,
    InvalidRequest,
    EngineNotInitialized,
    EngineShutdown,
    Internal,
}

impl std::fmt::Display for FlowShareApiError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for FlowShareApiError {}

fn api_error(message: &str) -> FlowShareApiError {
    let message = message.to_ascii_lowercase();
    if message.contains("signaling") || message.contains("websocket") {
        FlowShareApiError::SignalingUnavailable
    } else if message.contains("peer-offline") || message.contains("peer offline") {
        FlowShareApiError::PeerOffline
    } else if message.contains("authorization") || message.contains("invitation-signature") {
        FlowShareApiError::AuthorizationFailed
    } else if message.contains("expired") {
        FlowShareApiError::InvitationExpired
    } else if message.contains("protocol") || message.contains("version") {
        FlowShareApiError::ProtocolMismatch
    } else if message.contains("stun") {
        FlowShareApiError::StunFailed
    } else if message.contains("direct-connect") || message.contains("candidate") {
        FlowShareApiError::DirectConnectUnavailable
    } else if message.contains("quic") || message.contains("connect-failed") {
        FlowShareApiError::QuicConnectFailed
    } else if message.contains("source-changed") || message.contains("source-identity") {
        FlowShareApiError::SourceChanged
    } else if message.contains("source") {
        FlowShareApiError::SourceUnavailable
    } else if message.contains("disk") || message.contains("space") {
        FlowShareApiError::DiskFull
    } else if message.contains("destination") || message.contains("output") {
        FlowShareApiError::DestinationUnavailable
    } else if message.contains("checkpoint") || message.contains("resume") {
        FlowShareApiError::CheckpointInvalid
    } else if message.contains("hash") || message.contains("integrity") {
        FlowShareApiError::HashMismatch
    } else if message.contains("cancel") || message.contains("declined") {
        FlowShareApiError::Cancelled
    } else if message.contains("invalid") || message.contains("not-found") {
        FlowShareApiError::InvalidRequest
    } else {
        FlowShareApiError::Internal
    }
}

fn failure_for_api_error(error: FlowShareApiError) -> FlowShareFailure {
    let code = match error {
        FlowShareApiError::SignalingUnavailable => FlowShareErrorCode::SignalingUnavailable,
        FlowShareApiError::PeerOffline => FlowShareErrorCode::PeerOffline,
        FlowShareApiError::AuthorizationFailed => FlowShareErrorCode::AuthorizationFailed,
        FlowShareApiError::InvitationExpired => FlowShareErrorCode::InvitationExpired,
        FlowShareApiError::ProtocolMismatch => FlowShareErrorCode::ProtocolMismatch,
        FlowShareApiError::StunFailed => FlowShareErrorCode::StunFailed,
        FlowShareApiError::DirectConnectUnavailable => FlowShareErrorCode::DirectConnectUnavailable,
        FlowShareApiError::QuicConnectFailed => FlowShareErrorCode::QuicConnectFailed,
        FlowShareApiError::SourceUnavailable => FlowShareErrorCode::SourceUnavailable,
        FlowShareApiError::DestinationUnavailable => FlowShareErrorCode::DestinationUnavailable,
        FlowShareApiError::DiskFull => FlowShareErrorCode::DiskFull,
        FlowShareApiError::SourceChanged => FlowShareErrorCode::SourceChanged,
        FlowShareApiError::CheckpointInvalid => FlowShareErrorCode::CheckpointInvalid,
        FlowShareApiError::HashMismatch => FlowShareErrorCode::HashMismatch,
        FlowShareApiError::Cancelled => FlowShareErrorCode::Cancelled,
        FlowShareApiError::InvalidRequest => FlowShareErrorCode::InvalidRequest,
        FlowShareApiError::EngineNotInitialized
        | FlowShareApiError::EngineShutdown
        | FlowShareApiError::Internal => FlowShareErrorCode::Internal,
    };
    FlowShareFailure::classify(code)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct FlowShareCapabilities {
    pub schema_version: u16,
    pub protocol_version: u16,
    pub platform: DevicePlatform,
    pub native_quic: bool,
    pub webrtc_direct: bool,
    pub resume: bool,
    pub completion_ack: bool,
    pub sha256: bool,
    pub lan_discovery: bool,
    pub device_mode: bool,
    pub max_file_size: u64,
    pub app_version: String,
}

impl FlowShareCapabilities {
    pub fn validate(&self) -> Result<(), FlowShareFailure> {
        if self.schema_version != CAPABILITY_SCHEMA_VERSION
            || self.protocol_version != NATIVE_QUIC_PROTOCOL_VERSION
        {
            return Err(FlowShareFailure::classify(
                FlowShareErrorCode::ProtocolMismatch,
            ));
        }
        if matches!(self.platform, DevicePlatform::Unknown) {
            return Err(FlowShareFailure::classify(
                FlowShareErrorCode::UnsupportedPlatform,
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct NegotiatedCapabilities {
    pub compatible: bool,
    pub native_quic: bool,
    pub webrtc_direct: bool,
    pub resume: bool,
    pub completion_ack: bool,
    pub sha256: bool,
    pub max_file_size: u64,
    pub failure: Option<FlowShareFailure>,
}

fn negotiate(
    local: &FlowShareCapabilities,
    peer: &FlowShareCapabilities,
) -> NegotiatedCapabilities {
    let failure = local.validate().err().or_else(|| peer.validate().err());
    let compatible = failure.is_none();
    NegotiatedCapabilities {
        compatible,
        native_quic: compatible && local.native_quic && peer.native_quic,
        webrtc_direct: compatible && local.webrtc_direct && peer.webrtc_direct,
        resume: compatible && local.resume && peer.resume,
        completion_ack: compatible && local.completion_ack && peer.completion_ack,
        sha256: compatible && local.sha256 && peer.sha256,
        max_file_size: local.max_file_size.min(peer.max_file_size),
        failure,
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
pub enum FlowShareDirection {
    Send,
    Receive,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
pub enum FlowShareTransferState {
    Prepared,
    Incoming,
    AwaitingAcceptance,
    WaitingForPeer,
    Connecting,
    Connected,
    Transferring,
    Paused,
    Resuming,
    Verifying,
    Completed,
    Cancelled,
    Rejected,
    Failed,
}

impl FlowShareTransferState {
    fn terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Cancelled | Self::Rejected | Self::Failed
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct FlowShareTransferStatus {
    pub schema_version: u16,
    pub transfer_id: String,
    pub direction: FlowShareDirection,
    pub state: FlowShareTransferState,
    pub bytes_transferred: u64,
    pub total_bytes: u64,
    pub bytes_per_second: u64,
    pub transport: Option<String>,
    pub checkpoint_generation: u64,
    pub runtime_active: bool,
    pub failure: Option<FlowShareFailure>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
pub enum FlowShareEventKind {
    TransferPrepared,
    IncomingTransfer,
    WaitingForPeer,
    Connecting,
    Connected,
    TransferStarted,
    Progress,
    Paused,
    Resuming,
    Verifying,
    Completed,
    Cancelled,
    Rejected,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct FlowShareEvent {
    pub sequence: u64,
    pub kind: FlowShareEventKind,
    pub status: FlowShareTransferStatus,
}

#[cfg_attr(feature = "uniffi-bindings", uniffi::export(callback_interface))]
pub trait FlowShareEventListener: Send + Sync {
    fn on_event(&self, event: FlowShareEvent);
}

/// Platform secure-storage callback. Only small authorization-secret records
/// cross this boundary; transfer payload blocks remain in native Rust I/O.
#[cfg_attr(feature = "uniffi-bindings", uniffi::export(callback_interface))]
pub trait FlowShareSecretProtector: Send + Sync {
    fn protect(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, FlowShareApiError>;
    fn unprotect(&self, protected: Vec<u8>) -> Result<Vec<u8>, FlowShareApiError>;
}

struct CallbackSecretProtector {
    callback: Box<dyn FlowShareSecretProtector>,
}

impl SecretProtector for CallbackSecretProtector {
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        catch_unwind(AssertUnwindSafe(|| {
            self.callback.protect(plaintext.to_vec())
        }))
        .map_err(|_| "platform-secret-protector-panicked".to_string())?
        .map_err(|error| format!("platform-secret-protector-failed:{error}"))
    }

    fn unprotect(&self, protected: &[u8]) -> Result<Vec<u8>, String> {
        catch_unwind(AssertUnwindSafe(|| {
            self.callback.unprotect(protected.to_vec())
        }))
        .map_err(|_| "platform-secret-protector-panicked".to_string())?
        .map_err(|error| format!("platform-secret-protector-failed:{error}"))
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct PrepareReceiveRequest {
    pub lifetime_ms: Option<u64>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct PrepareReceiveResult {
    pub receiver_bootstrap_id: String,
    pub receiver_bootstrap_package: String,
    pub certificate_fingerprint_sha256: String,
    pub expires_unix_ms: u64,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct PrepareSendRequest {
    /// Desktop uses a canonical path. Android will supply an owned native descriptor handle.
    pub source_handle: String,
    pub receiver_bootstrap_package: String,
    pub invitation_lifetime_ms: Option<u64>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct PrepareSendResult {
    pub transfer: FlowShareTransferStatus,
    pub invitation_package: String,
    /// Validated source metadata computed by the authoritative native engine.
    pub display_filename: String,
    pub file_size: u64,
    pub expected_sha256: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct ImportInvitationRequest {
    pub receiver_bootstrap_id: String,
    pub invitation_package: String,
    /// Desktop uses a directory path; Android adapters may resolve an opaque destination handle.
    pub destination_handle: String,
    pub retention_expires_unix_ms: Option<u64>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct AcceptTransferRequest {
    pub transfer_id: String,
    pub display_filename: String,
    pub file_size: u64,
    pub expected_sha256: String,
    pub overwrite: bool,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct StartTransferRequest {
    pub transfer_id: String,
    pub signaling_endpoint: String,
    /// Enables loopback candidates only for isolated local test harnesses.
    pub allow_loopback_test: bool,
    pub signaling_timeout_ms: Option<u64>,
    pub connectivity_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct TransferControlRequest {
    pub transfer_id: String,
    pub direction: FlowShareDirection,
    pub retain_partial: bool,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct ResumeSenderRequest {
    pub transfer_id: String,
    pub receiver_bootstrap_package: String,
    /// Android reopens its persisted SAF URI and supplies a fresh registered
    /// descriptor token after process death. Desktop leaves this unset.
    pub source_handle: Option<String>,
    pub expected_checkpoint_generation: Option<u64>,
    pub signaling_endpoint: String,
    pub allow_loopback_test: bool,
    pub signaling_timeout_ms: Option<u64>,
    pub connectivity_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct ResumeReceiverRequest {
    pub transfer_id: String,
    pub receiver_bootstrap_id: String,
    pub destination_handle: String,
    pub expected_checkpoint_generation: Option<u64>,
    pub signaling_endpoint: String,
    pub allow_loopback_test: bool,
    pub signaling_timeout_ms: Option<u64>,
    pub connectivity_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct TransferLookupRequest {
    pub transfer_id: String,
    pub direction: FlowShareDirection,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct RecoverTransfersRequest {
    pub destination_handles: Vec<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct RecoverableTransfer {
    pub transfer_id: String,
    pub direction: FlowShareDirection,
    pub total_bytes: u64,
    pub completed_bytes: u64,
    pub checkpoint_generation: u64,
    pub source_or_destination_handle: String,
    pub source_available: bool,
    pub checkpoint_authenticated: bool,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct RecoveryResult {
    pub resumable: Vec<RecoverableTransfer>,
}

#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Object))]
pub struct FlowShareEngine {
    local: FlowShareCapabilities,
    initialized: AtomicBool,
    shutdown: AtomicBool,
    runtime: Mutex<Option<Runtime>>,
    owned: Mutex<HashSet<(String, FlowShareDirection)>>,
    source_handles: Mutex<HashSet<String>>,
    listeners: Arc<RwLock<Option<Arc<dyn FlowShareEventListener>>>>,
    watchers: Mutex<HashMap<(String, FlowShareDirection), CancellationToken>>,
    sequence: Arc<std::sync::atomic::AtomicU64>,
}

impl Drop for FlowShareEngine {
    fn drop(&mut self) {
        if let Ok(watchers) = self.watchers.get_mut() {
            for cancellation in watchers.values() {
                cancellation.cancel();
            }
            watchers.clear();
        }
        if let Ok(mut listener) = self.listeners.write() {
            *listener = None;
        }
        if let Ok(runtime) = self.runtime.get_mut() {
            if let Some(runtime) = runtime.take() {
                runtime.shutdown_background();
            }
        }
        if let Ok(handles) = self.source_handles.get_mut() {
            for token in handles.drain() {
                let _ = crate::platform_handles::release_source_descriptor(&token);
            }
        }
    }
}

impl FlowShareEngine {
    fn require_running(&self) -> Result<(), FlowShareApiError> {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(FlowShareApiError::EngineShutdown);
        }
        if !self.initialized.load(Ordering::Acquire) {
            return Err(FlowShareApiError::EngineNotInitialized);
        }
        Ok(())
    }

    async fn run<T, F>(&self, future: F) -> Result<T, FlowShareApiError>
    where
        T: Send + 'static,
        F: std::future::Future<Output = Result<T, String>> + Send + 'static,
    {
        let handle = self
            .runtime
            .lock()
            .map_err(|_| FlowShareApiError::Internal)?
            .as_ref()
            .map(Runtime::handle)
            .cloned()
            .ok_or(FlowShareApiError::EngineShutdown)?;
        handle
            .spawn(future)
            .await
            .map_err(|_| FlowShareApiError::Internal)?
            .map_err(|error| api_error(&error))
    }

    fn remember(&self, transfer_id: &str, direction: FlowShareDirection) {
        if let Ok(mut owned) = self.owned.lock() {
            owned.insert((transfer_id.to_string(), direction));
        }
    }

    fn emit(&self, status: FlowShareTransferStatus) {
        emit_to_listener(&self.listeners, &self.sequence, status);
    }

    fn watch(&self, transfer_id: String, direction: FlowShareDirection) {
        let cancellation = CancellationToken::new();
        if let Ok(mut watchers) = self.watchers.lock() {
            if let Some(previous) =
                watchers.insert((transfer_id.clone(), direction), cancellation.clone())
            {
                previous.cancel();
            }
        }
        let listeners = Arc::clone(&self.listeners);
        let sequence = Arc::clone(&self.sequence);
        let handle = self
            .runtime
            .lock()
            .ok()
            .and_then(|runtime| runtime.as_ref().map(Runtime::handle).cloned());
        if let Some(handle) = handle {
            handle.spawn(async move {
                let mut last: Option<(FlowShareTransferState, u64)> = None;
                loop {
                    tokio::select! {
                        _ = cancellation.cancelled() => break,
                        _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                    }
                    let status = status_for_direction(&transfer_id, direction).await;
                    match status {
                        Ok(status) => {
                            let current = (status.state, status.bytes_transferred);
                            if last != Some(current) {
                                let terminal = status.state.terminal();
                                if status.state == FlowShareTransferState::Transferring
                                    && last.is_some_and(|previous| {
                                        previous.0 == FlowShareTransferState::Connecting
                                    })
                                {
                                    let mut connected = status.clone();
                                    connected.state = FlowShareTransferState::Connected;
                                    emit_to_listener(&listeners, &sequence, connected);
                                }
                                if status.state == FlowShareTransferState::Completed
                                    && !last.is_some_and(|previous| {
                                        previous.0 == FlowShareTransferState::Verifying
                                    })
                                {
                                    let mut verifying = status.clone();
                                    verifying.state = FlowShareTransferState::Verifying;
                                    emit_to_listener(&listeners, &sequence, verifying);
                                }
                                emit_to_listener(&listeners, &sequence, status);
                                last = Some(current);
                                if terminal {
                                    break;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    }
}

#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
impl FlowShareEngine {
    #[cfg_attr(feature = "uniffi-bindings", uniffi::constructor)]
    pub fn new(local: FlowShareCapabilities) -> Arc<Self> {
        let runtime = Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("flowshare-core")
            .enable_all()
            .build()
            .expect("FlowShare runtime initialization failed");
        Arc::new(Self {
            local,
            initialized: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
            runtime: Mutex::new(Some(runtime)),
            owned: Mutex::new(HashSet::new()),
            source_handles: Mutex::new(HashSet::new()),
            listeners: Arc::new(RwLock::new(None)),
            watchers: Mutex::new(HashMap::new()),
            sequence: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    pub fn initialize(&self) -> Result<bool, FlowShareApiError> {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(FlowShareApiError::EngineShutdown);
        }
        Ok(!self.initialized.swap(true, Ordering::AcqRel))
    }

    /// Configures an application-owned checkpoint root before initialization.
    /// Android supplies its internal no-backup directory; Desktop may keep the
    /// established OS data-directory default.
    pub fn configure_state_root(&self, path: String) -> Result<bool, FlowShareApiError> {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(FlowShareApiError::EngineShutdown);
        }
        if self.initialized.load(Ordering::Acquire) {
            return Err(FlowShareApiError::InvalidRequest);
        }
        crate::platform_handles::configure_state_root(path).map_err(|error| api_error(&error))
    }

    /// Installs the process-wide OS-backed protector. Returns `true` when this
    /// call installed it and `false` when the process already had one.
    pub fn set_secret_protector(
        &self,
        protector: Box<dyn FlowShareSecretProtector>,
    ) -> Result<bool, FlowShareApiError> {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(FlowShareApiError::EngineShutdown);
        }
        Ok(secret_store::install_secret_protector(Arc::new(
            CallbackSecretProtector {
                callback: protector,
            },
        )))
    }

    /// Takes ownership of a duplicated Android file descriptor and returns a
    /// process-local opaque token accepted by `prepare_send` and `resume_sender`.
    pub fn register_source_descriptor(
        &self,
        descriptor: i32,
        display_name: String,
    ) -> Result<String, FlowShareApiError> {
        self.require_running()?;
        let token =
            crate::platform_handles::register_owned_source_descriptor(descriptor, display_name)
                .map_err(|error| api_error(&error))?;
        self.source_handles
            .lock()
            .map_err(|_| FlowShareApiError::Internal)?
            .insert(token.clone());
        Ok(token)
    }

    pub fn release_source_descriptor(&self, token: String) -> Result<bool, FlowShareApiError> {
        let removed = self
            .source_handles
            .lock()
            .map_err(|_| FlowShareApiError::Internal)?
            .remove(&token);
        if !removed {
            return Ok(false);
        }
        crate::platform_handles::release_source_descriptor(&token)
            .map_err(|error| api_error(&error))
    }

    pub async fn shutdown(&self) -> Result<(), FlowShareApiError> {
        if self.shutdown.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.initialized.store(false, Ordering::Release);
        if let Ok(watchers) = self.watchers.lock() {
            for cancellation in watchers.values() {
                cancellation.cancel();
            }
        }
        self.clear_event_listener();
        let owned = self
            .owned
            .lock()
            .map(|owned| owned.clone())
            .unwrap_or_default();
        let _ = self
            .run(async move {
                for (transfer_id, direction) in &owned {
                    let request = cross_device::CancelSplitTransferRequest {
                        transfer_id: transfer_id.clone(),
                        retain_partial: Some(true),
                    };
                    match direction {
                        FlowShareDirection::Send => {
                            let _ =
                                cross_device::flowshare_native_cancel_outgoing_transfer(request)
                                    .await;
                        }
                        FlowShareDirection::Receive => {
                            let _ =
                                cross_device::flowshare_native_cancel_incoming_transfer(request)
                                    .await;
                        }
                    }
                }
                let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
                loop {
                    let mut active = false;
                    for (transfer_id, direction) in &owned {
                        let request = cross_device::SplitTransferIdRequest {
                            transfer_id: transfer_id.clone(),
                        };
                        active |= match direction {
                            FlowShareDirection::Send => {
                                cross_device::flowshare_native_get_outgoing_transfer(request)
                                    .await
                                    .is_ok_and(|snapshot| snapshot.runtime_active)
                            }
                            FlowShareDirection::Receive => {
                                cross_device::flowshare_native_get_incoming_transfer(request)
                                    .await
                                    .is_ok_and(|snapshot| snapshot.runtime_active)
                            }
                        };
                    }
                    if !active || tokio::time::Instant::now() >= deadline {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Ok(())
            })
            .await;
        if let Ok(mut runtime) = self.runtime.lock() {
            if let Some(runtime) = runtime.take() {
                runtime.shutdown_background();
            }
        }
        if let Ok(mut handles) = self.source_handles.lock() {
            for token in handles.drain() {
                let _ = crate::platform_handles::release_source_descriptor(&token);
            }
        }
        Ok(())
    }

    pub fn local_capabilities(&self) -> FlowShareCapabilities {
        self.local.clone()
    }

    pub fn negotiate(&self, peer: FlowShareCapabilities) -> NegotiatedCapabilities {
        negotiate(&self.local, &peer)
    }

    pub fn set_event_listener(&self, listener: Box<dyn FlowShareEventListener>) {
        if let Ok(mut current) = self.listeners.write() {
            *current = Some(Arc::from(listener));
        }
    }

    pub fn clear_event_listener(&self) {
        if let Ok(mut current) = self.listeners.write() {
            *current = None;
        }
    }

    pub async fn prepare_receive(
        &self,
        request: PrepareReceiveRequest,
    ) -> Result<PrepareReceiveResult, FlowShareApiError> {
        self.require_running()?;
        let result = self
            .run(cross_device::flowshare_native_prepare_incoming_receiver(
                Some(cross_device::PrepareIncomingReceiverRequest {
                    lifetime_ms: request.lifetime_ms,
                }),
            ))
            .await?;
        Ok(PrepareReceiveResult {
            receiver_bootstrap_id: result.receiver_bootstrap_id,
            receiver_bootstrap_package: result.receiver_bootstrap_package,
            certificate_fingerprint_sha256: result.certificate_fingerprint_sha256,
            expires_unix_ms: result.expires_unix_ms,
        })
    }

    pub async fn prepare_send(
        &self,
        request: PrepareSendRequest,
    ) -> Result<PrepareSendResult, FlowShareApiError> {
        self.require_running()?;
        let result = self
            .run(cross_device::flowshare_native_create_outgoing_transfer(
                cross_device::CreateOutgoingTransferRequest {
                    source_path: request.source_handle,
                    receiver_bootstrap_package: request.receiver_bootstrap_package,
                    authorization_delivery_mode:
                        cross_device::NativeAuthorizationDeliveryMode::ManualPackage,
                    candidate_privacy_policy: Some(CandidatePrivacyPolicy::LanFirst),
                    invitation_lifetime_ms: request.invitation_lifetime_ms,
                },
            ))
            .await?;
        let display_filename = result.transfer.display_filename.clone();
        let file_size = result.transfer.file_size;
        let expected_sha256 = result.transfer.expected_sha256.clone();
        let status = outgoing_status(result.transfer);
        self.remember(&status.transfer_id, FlowShareDirection::Send);
        self.emit(status.clone());
        Ok(PrepareSendResult {
            transfer: status,
            invitation_package: result.invitation_package,
            display_filename,
            file_size,
            expected_sha256,
        })
    }

    pub async fn import_invitation(
        &self,
        request: ImportInvitationRequest,
    ) -> Result<FlowShareTransferStatus, FlowShareApiError> {
        self.require_running()?;
        let result = self
            .run(cross_device::flowshare_native_import_incoming_invitation(
                cross_device::ImportIncomingInvitationRequest {
                    receiver_bootstrap_id: request.receiver_bootstrap_id,
                    invitation_package: request.invitation_package,
                    destination_directory: request.destination_handle,
                    retention_expires_unix_ms: request.retention_expires_unix_ms,
                },
            ))
            .await?;
        let status = incoming_status(result.transfer);
        self.remember(&status.transfer_id, FlowShareDirection::Receive);
        self.emit(status.clone());
        Ok(status)
    }

    pub async fn accept_transfer(
        &self,
        request: AcceptTransferRequest,
    ) -> Result<FlowShareTransferStatus, FlowShareApiError> {
        self.require_running()?;
        let result = self
            .run(cross_device::flowshare_native_accept_incoming_transfer(
                cross_device::AcceptIncomingTransferRequest {
                    transfer_id: request.transfer_id,
                    display_filename: request.display_filename,
                    file_size: request.file_size,
                    expected_sha256: request.expected_sha256,
                    overwrite: Some(request.overwrite),
                },
            ))
            .await?;
        let status = incoming_status(result);
        self.emit(status.clone());
        Ok(status)
    }

    pub async fn reject_transfer(
        &self,
        request: TransferLookupRequest,
    ) -> Result<FlowShareTransferStatus, FlowShareApiError> {
        self.require_running()?;
        if request.direction != FlowShareDirection::Receive {
            return Err(FlowShareApiError::InvalidRequest);
        }
        let result = self
            .run(cross_device::flowshare_native_reject_incoming_transfer(
                cross_device::SplitTransferIdRequest {
                    transfer_id: request.transfer_id,
                },
            ))
            .await?;
        let status = incoming_status(result);
        self.emit(status.clone());
        Ok(status)
    }

    pub async fn start_sender(
        &self,
        request: StartTransferRequest,
    ) -> Result<FlowShareTransferStatus, FlowShareApiError> {
        self.require_running()?;
        let result = self
            .run(cross_device::flowshare_native_start_outgoing_transfer(
                start_request(request),
            ))
            .await?;
        let status = outgoing_status(result);
        self.emit(status.clone());
        self.watch(status.transfer_id.clone(), FlowShareDirection::Send);
        Ok(status)
    }

    pub async fn start_receiver(
        &self,
        request: StartTransferRequest,
    ) -> Result<FlowShareTransferStatus, FlowShareApiError> {
        self.require_running()?;
        let result = self
            .run(cross_device::flowshare_native_start_incoming_transfer(
                start_request(request),
            ))
            .await?;
        let status = incoming_status(result);
        self.emit(status.clone());
        self.watch(status.transfer_id.clone(), FlowShareDirection::Receive);
        Ok(status)
    }

    pub async fn pause(
        &self,
        request: TransferControlRequest,
    ) -> Result<FlowShareTransferStatus, FlowShareApiError> {
        self.require_running()?;
        let id = cross_device::SplitTransferIdRequest {
            transfer_id: request.transfer_id,
        };
        let status = match request.direction {
            FlowShareDirection::Send => outgoing_status(
                self.run(cross_device::flowshare_native_pause_outgoing_transfer(id))
                    .await?,
            ),
            FlowShareDirection::Receive => incoming_status(
                self.run(cross_device::flowshare_native_pause_incoming_transfer(id))
                    .await?,
            ),
        };
        self.emit(status.clone());
        Ok(status)
    }

    pub async fn cancel(
        &self,
        request: TransferControlRequest,
    ) -> Result<FlowShareTransferStatus, FlowShareApiError> {
        self.require_running()?;
        let direction = request.direction;
        let cancel = cross_device::CancelSplitTransferRequest {
            transfer_id: request.transfer_id,
            retain_partial: Some(request.retain_partial),
        };
        let status = match direction {
            FlowShareDirection::Send => outgoing_status(
                self.run(cross_device::flowshare_native_cancel_outgoing_transfer(
                    cancel,
                ))
                .await?,
            ),
            FlowShareDirection::Receive => incoming_status(
                self.run(cross_device::flowshare_native_cancel_incoming_transfer(
                    cancel,
                ))
                .await?,
            ),
        };
        if let Ok(watchers) = self.watchers.lock() {
            if let Some(watcher) = watchers.get(&(status.transfer_id.clone(), direction)) {
                watcher.cancel();
            }
        }
        self.emit(status.clone());
        Ok(status)
    }

    pub async fn resume_sender(
        &self,
        request: ResumeSenderRequest,
    ) -> Result<FlowShareTransferStatus, FlowShareApiError> {
        self.require_running()?;
        let result = self
            .run(cross_device::flowshare_native_resume_outgoing_transfer(
                cross_device::ResumeOutgoingTransferRequest {
                    transfer_id: request.transfer_id,
                    receiver_bootstrap_package: request.receiver_bootstrap_package,
                    source_handle: request.source_handle,
                    expected_checkpoint_generation: request.expected_checkpoint_generation,
                    signaling_endpoint: request.signaling_endpoint,
                    gathering: gathering_options(request.allow_loopback_test),
                    signaling_timeout_ms: request.signaling_timeout_ms,
                    connectivity_timeout_ms: request.connectivity_timeout_ms,
                },
            ))
            .await?;
        let status = outgoing_status(result);
        self.remember(&status.transfer_id, FlowShareDirection::Send);
        self.emit(status.clone());
        self.watch(status.transfer_id.clone(), FlowShareDirection::Send);
        Ok(status)
    }

    pub async fn resume_receiver(
        &self,
        request: ResumeReceiverRequest,
    ) -> Result<FlowShareTransferStatus, FlowShareApiError> {
        self.require_running()?;
        let result = self
            .run(cross_device::flowshare_native_resume_incoming_transfer(
                cross_device::ResumeIncomingTransferRequest {
                    transfer_id: request.transfer_id,
                    receiver_bootstrap_id: request.receiver_bootstrap_id,
                    destination_directory: request.destination_handle,
                    expected_checkpoint_generation: request.expected_checkpoint_generation,
                    signaling_endpoint: request.signaling_endpoint,
                    gathering: gathering_options(request.allow_loopback_test),
                    signaling_timeout_ms: request.signaling_timeout_ms,
                    connectivity_timeout_ms: request.connectivity_timeout_ms,
                },
            ))
            .await?;
        let status = incoming_status(result);
        self.remember(&status.transfer_id, FlowShareDirection::Receive);
        self.emit(status.clone());
        self.watch(status.transfer_id.clone(), FlowShareDirection::Receive);
        Ok(status)
    }

    pub async fn get_transfer_status(
        &self,
        request: TransferLookupRequest,
    ) -> Result<FlowShareTransferStatus, FlowShareApiError> {
        self.require_running()?;
        self.run(async move {
            status_for_direction(&request.transfer_id, request.direction)
                .await
                .map_err(|error| error.to_string())
        })
        .await
    }

    pub async fn list_transfers(&self) -> Result<Vec<FlowShareTransferStatus>, FlowShareApiError> {
        self.require_running()?;
        let owned = self
            .owned
            .lock()
            .map(|owned| owned.clone())
            .unwrap_or_default();
        self.run(async move {
            let mut statuses = Vec::new();
            for snapshot in cross_device::list_outgoing_transfers().await {
                if owned.contains(&(snapshot.transfer_id.clone(), FlowShareDirection::Send)) {
                    statuses.push(outgoing_status(snapshot));
                }
            }
            for snapshot in cross_device::list_incoming_transfers().await {
                if owned.contains(&(snapshot.transfer_id.clone(), FlowShareDirection::Receive)) {
                    statuses.push(incoming_status(snapshot));
                }
            }
            Ok(statuses)
        })
        .await
    }

    pub async fn recover_transfers(
        &self,
        request: RecoverTransfersRequest,
    ) -> Result<RecoveryResult, FlowShareApiError> {
        self.require_running()?;
        self.run(async move {
            let mut resumable = Vec::new();
            for item in cross_device::flowshare_native_scan_outgoing_resumable_transfers().await? {
                resumable.push(RecoverableTransfer {
                    transfer_id: item.transfer_id,
                    direction: FlowShareDirection::Send,
                    total_bytes: item.file_size,
                    completed_bytes: item.peer_completed_bytes,
                    checkpoint_generation: item.checkpoint_generation,
                    source_or_destination_handle: item.source_path,
                    source_available: item.source_identity_matches,
                    checkpoint_authenticated: item.protected_state_authenticated,
                });
            }
            if !request.destination_handles.is_empty() {
                for item in cross_device::flowshare_native_scan_incoming_resumable_transfers(
                    cross_device::ScanIncomingResumableRequest {
                        destination_directories: request.destination_handles,
                    },
                )
                .await?
                {
                    resumable.push(RecoverableTransfer {
                        transfer_id: item.transfer_id,
                        direction: FlowShareDirection::Receive,
                        total_bytes: item.file_size,
                        completed_bytes: item.completed_bytes,
                        checkpoint_generation: item.checkpoint_generation,
                        source_or_destination_handle: item.destination_directory,
                        source_available: item.part_file_present,
                        checkpoint_authenticated: item.checkpoint_authenticated
                            && item.block_hashes_authenticated,
                    });
                }
            }
            Ok(RecoveryResult { resumable })
        })
        .await
    }
}

fn start_request(request: StartTransferRequest) -> cross_device::StartSplitTransferRequest {
    cross_device::StartSplitTransferRequest {
        transfer_id: request.transfer_id,
        signaling_endpoint: request.signaling_endpoint,
        gathering: gathering_options(request.allow_loopback_test),
        signaling_timeout_ms: request.signaling_timeout_ms,
        connectivity_timeout_ms: request.connectivity_timeout_ms,
    }
}

fn gathering_options(
    allow_loopback_test: bool,
) -> Option<crate::connectivity::ConnectivityGatherOptions> {
    allow_loopback_test.then(|| crate::connectivity::ConnectivityGatherOptions {
        allow_loopback_test: Some(true),
        enable_stun: Some(false),
        expected_same_lan: Some(true),
        ..Default::default()
    })
}

async fn status_for_direction(
    transfer_id: &str,
    direction: FlowShareDirection,
) -> Result<FlowShareTransferStatus, FlowShareApiError> {
    let request = cross_device::SplitTransferIdRequest {
        transfer_id: transfer_id.to_string(),
    };
    match direction {
        FlowShareDirection::Send => cross_device::flowshare_native_get_outgoing_transfer(request)
            .await
            .map(outgoing_status)
            .map_err(|error| api_error(&error)),
        FlowShareDirection::Receive => {
            cross_device::flowshare_native_get_incoming_transfer(request)
                .await
                .map(incoming_status)
                .map_err(|error| api_error(&error))
        }
    }
}

fn outgoing_status(
    snapshot: cross_device::OutgoingNativeTransferSnapshot,
) -> FlowShareTransferStatus {
    let state = match snapshot.state {
        OutgoingNativeState::Created => FlowShareTransferState::Prepared,
        OutgoingNativeState::AwaitingReceiver | OutgoingNativeState::AuthorizationDelivering => {
            FlowShareTransferState::WaitingForPeer
        }
        OutgoingNativeState::GatheringCandidates | OutgoingNativeState::Connecting => {
            FlowShareTransferState::Connecting
        }
        OutgoingNativeState::Transferring => FlowShareTransferState::Transferring,
        OutgoingNativeState::Finalizing => FlowShareTransferState::Verifying,
        OutgoingNativeState::Paused => FlowShareTransferState::Paused,
        OutgoingNativeState::Completed => FlowShareTransferState::Completed,
        OutgoingNativeState::Cancelled => FlowShareTransferState::Cancelled,
        OutgoingNativeState::Failed => FlowShareTransferState::Failed,
    };
    let failure = snapshot
        .terminal_error
        .as_deref()
        .map(api_error)
        .map(failure_for_api_error);
    FlowShareTransferStatus {
        schema_version: 1,
        transfer_id: snapshot.transfer_id,
        direction: FlowShareDirection::Send,
        state,
        bytes_transferred: snapshot.bytes_sent,
        total_bytes: snapshot.file_size,
        bytes_per_second: snapshot
            .performance
            .as_ref()
            .map(|value| (value.average_mbps * 125_000.0).max(0.0) as u64)
            .unwrap_or(0),
        transport: snapshot
            .selected_path
            .or_else(|| snapshot.quic_session_id.map(|_| "quic-direct".into())),
        checkpoint_generation: snapshot.peer_checkpoint_generation.unwrap_or(0),
        runtime_active: snapshot.runtime_active,
        failure,
    }
}

fn incoming_status(
    snapshot: cross_device::IncomingNativeTransferSnapshot,
) -> FlowShareTransferStatus {
    let state = match snapshot.state {
        IncomingNativeState::InvitationImported => FlowShareTransferState::Incoming,
        IncomingNativeState::AwaitingAcceptance => FlowShareTransferState::AwaitingAcceptance,
        IncomingNativeState::Accepted => FlowShareTransferState::Prepared,
        IncomingNativeState::GatheringCandidates | IncomingNativeState::Connecting => {
            FlowShareTransferState::Connecting
        }
        IncomingNativeState::Receiving => FlowShareTransferState::Transferring,
        IncomingNativeState::Finalizing => FlowShareTransferState::Verifying,
        IncomingNativeState::Paused => FlowShareTransferState::Paused,
        IncomingNativeState::Completed => FlowShareTransferState::Completed,
        IncomingNativeState::Cancelled => FlowShareTransferState::Cancelled,
        IncomingNativeState::Declined => FlowShareTransferState::Rejected,
        IncomingNativeState::Failed => FlowShareTransferState::Failed,
    };
    let failure = snapshot
        .terminal_error
        .as_deref()
        .map(api_error)
        .map(failure_for_api_error);
    FlowShareTransferStatus {
        schema_version: 1,
        transfer_id: snapshot.transfer_id,
        direction: FlowShareDirection::Receive,
        state,
        bytes_transferred: snapshot.bytes_written,
        total_bytes: snapshot.expected_file_size.unwrap_or(0),
        bytes_per_second: snapshot
            .performance
            .as_ref()
            .map(|value| (value.average_mbps * 125_000.0).max(0.0) as u64)
            .unwrap_or(0),
        transport: snapshot
            .selected_path
            .or_else(|| snapshot.quic_session_id.map(|_| "quic-direct".into())),
        checkpoint_generation: snapshot.checkpoint_generation,
        runtime_active: snapshot.runtime_active,
        failure,
    }
}

fn event_kind(state: FlowShareTransferState, bytes: u64) -> FlowShareEventKind {
    match state {
        FlowShareTransferState::Prepared => FlowShareEventKind::TransferPrepared,
        FlowShareTransferState::Incoming | FlowShareTransferState::AwaitingAcceptance => {
            FlowShareEventKind::IncomingTransfer
        }
        FlowShareTransferState::WaitingForPeer => FlowShareEventKind::WaitingForPeer,
        FlowShareTransferState::Connecting => FlowShareEventKind::Connecting,
        FlowShareTransferState::Connected => FlowShareEventKind::Connected,
        FlowShareTransferState::Transferring if bytes == 0 => FlowShareEventKind::TransferStarted,
        FlowShareTransferState::Transferring => FlowShareEventKind::Progress,
        FlowShareTransferState::Paused => FlowShareEventKind::Paused,
        FlowShareTransferState::Resuming => FlowShareEventKind::Resuming,
        FlowShareTransferState::Verifying => FlowShareEventKind::Verifying,
        FlowShareTransferState::Completed => FlowShareEventKind::Completed,
        FlowShareTransferState::Cancelled => FlowShareEventKind::Cancelled,
        FlowShareTransferState::Rejected => FlowShareEventKind::Rejected,
        FlowShareTransferState::Failed => FlowShareEventKind::Failed,
    }
}

fn emit_to_listener(
    listeners: &RwLock<Option<Arc<dyn FlowShareEventListener>>>,
    sequence: &std::sync::atomic::AtomicU64,
    status: FlowShareTransferStatus,
) {
    let listener = listeners.read().ok().and_then(|listener| listener.clone());
    if let Some(listener) = listener {
        let event = FlowShareEvent {
            sequence: sequence.fetch_add(1, Ordering::AcqRel) + 1,
            kind: event_kind(status.state, status.bytes_transferred),
            status,
        };
        let _ = catch_unwind(AssertUnwindSafe(|| listener.on_event(event)));
    }
}

#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
pub fn classify_error(code: FlowShareErrorCode) -> FlowShareFailure {
    FlowShareFailure::classify(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capabilities(platform: DevicePlatform) -> FlowShareCapabilities {
        FlowShareCapabilities {
            schema_version: CAPABILITY_SCHEMA_VERSION,
            protocol_version: NATIVE_QUIC_PROTOCOL_VERSION,
            platform,
            native_quic: true,
            webrtc_direct: false,
            resume: true,
            completion_ack: true,
            sha256: true,
            lan_discovery: true,
            device_mode: true,
            max_file_size: 8 * 1024 * 1024 * 1024,
            app_version: "golden".into(),
        }
    }

    #[test]
    fn capability_negotiation_is_versioned_and_64_bit_safe() {
        let engine = FlowShareEngine::new(capabilities(DevicePlatform::Windows));
        let mut peer = capabilities(DevicePlatform::Android);
        peer.max_file_size = 4_294_967_297;
        let negotiated = engine.negotiate(peer);
        assert!(negotiated.compatible && negotiated.native_quic && negotiated.resume);
        assert_eq!(negotiated.max_file_size, 4_294_967_297);

        let mut future = capabilities(DevicePlatform::Android);
        future.protocol_version += 1;
        let rejected = engine.negotiate(future);
        assert_eq!(
            rejected.failure.unwrap().code,
            FlowShareErrorCode::ProtocolMismatch
        );
    }

    #[test]
    fn stable_errors_expose_retry_and_fallback_policy() {
        let native = FlowShareFailure::classify(FlowShareErrorCode::QuicConnectFailed);
        assert!(native.retryable && native.fallback_eligible);
        let authorization = FlowShareFailure::classify(FlowShareErrorCode::AuthorizationFailed);
        assert!(!authorization.retryable && !authorization.fallback_eligible);
    }

    #[test]
    fn initialize_is_idempotent_and_shutdown_is_terminal() {
        let engine = FlowShareEngine::new(capabilities(DevicePlatform::Windows));
        assert_eq!(engine.initialize(), Ok(true));
        assert_eq!(engine.initialize(), Ok(false));
    }

    #[test]
    fn logical_progress_remains_u64_safe_above_four_gib() {
        let status = FlowShareTransferStatus {
            schema_version: 1,
            transfer_id: "logical-large".into(),
            direction: FlowShareDirection::Send,
            state: FlowShareTransferState::Transferring,
            bytes_transferred: 4_294_967_297,
            total_bytes: 8_589_934_593,
            bytes_per_second: 0,
            transport: Some("quic-direct".into()),
            checkpoint_generation: 7,
            runtime_active: true,
            failure: None,
        };
        assert!(status.total_bytes > u32::MAX as u64);
        assert!(status.bytes_transferred > u32::MAX as u64);
    }

    #[test]
    fn successful_event_order_never_completes_before_verification() {
        let engine = FlowShareEngine::new(capabilities(DevicePlatform::Windows));
        let observed = Arc::new(Mutex::new(Vec::new()));
        struct SharedListener(Arc<Mutex<Vec<FlowShareEvent>>>);
        impl FlowShareEventListener for SharedListener {
            fn on_event(&self, event: FlowShareEvent) {
                self.0.lock().unwrap().push(event);
            }
        }
        engine.set_event_listener(Box::new(SharedListener(Arc::clone(&observed))));
        for (state, bytes) in [
            (FlowShareTransferState::Prepared, 0),
            (FlowShareTransferState::WaitingForPeer, 0),
            (FlowShareTransferState::Connecting, 0),
            (FlowShareTransferState::Connected, 0),
            (FlowShareTransferState::Transferring, 0),
            (FlowShareTransferState::Transferring, 1024),
            (FlowShareTransferState::Verifying, 1024),
            (FlowShareTransferState::Completed, 1024),
        ] {
            engine.emit(FlowShareTransferStatus {
                schema_version: 1,
                transfer_id: "event-order".into(),
                direction: FlowShareDirection::Send,
                state,
                bytes_transferred: bytes,
                total_bytes: 1024,
                bytes_per_second: 0,
                transport: Some("quic-direct".into()),
                checkpoint_generation: 0,
                runtime_active: !state.terminal(),
                failure: None,
            });
        }
        let events = observed.lock().unwrap();
        let kinds: Vec<_> = events.iter().map(|event| event.kind).collect();
        assert_eq!(
            kinds,
            vec![
                FlowShareEventKind::TransferPrepared,
                FlowShareEventKind::WaitingForPeer,
                FlowShareEventKind::Connecting,
                FlowShareEventKind::Connected,
                FlowShareEventKind::TransferStarted,
                FlowShareEventKind::Progress,
                FlowShareEventKind::Verifying,
                FlowShareEventKind::Completed,
            ]
        );
        assert!(events
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence));
    }

    #[tokio::test]
    async fn shutdown_is_idempotent_and_rejects_new_work() {
        let engine = FlowShareEngine::new(capabilities(DevicePlatform::Windows));
        assert!(engine.initialize().unwrap());
        engine.shutdown().await.unwrap();
        engine.shutdown().await.unwrap();
        assert_eq!(engine.initialize(), Err(FlowShareApiError::EngineShutdown));
        assert!(matches!(
            engine
                .prepare_receive(PrepareReceiveRequest { lifetime_ms: None })
                .await,
            Err(FlowShareApiError::EngineShutdown)
        ));
    }
}
