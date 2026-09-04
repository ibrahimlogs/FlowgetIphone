use super::{
    config::NativeQuicConfig,
    protocol::{CompletionManifest, RangeHeader, RangeLedger, RANGE_HEADER_BYTES},
    security::{create_ephemeral_identity, EphemeralIdentity},
};
use quinn::{ClientConfig, Endpoint, ServerConfig, VarInt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Instant, UNIX_EPOCH},
};
use tokio::{
    fs::{self, File, OpenOptions},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom},
};
use uuid::Uuid;

const DEFAULT_RECEIVER_BUFFER_COUNT: usize = 16;
const DEFAULT_PER_STREAM_WRITE_QUEUE: usize = 4;

pub(crate) fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

pub(crate) async fn checkpoint_record(
    record: &Arc<super::transfer_registry::TransferRecord>,
    source_identity: &super::resume::SourceIdentity,
    checkpoint_state: super::lifecycle::TransferState,
) -> Result<(), String> {
    {
        record.mutable.lock().await.active_checkpoint_tasks += 1;
    }
    let result = async {
        let (
            bitmap,
            block_hashes,
            expected_hash,
            generation,
            lifecycle_generation,
            checkpoint_time,
        ) = {
            let state = record.mutable.lock().await;
            (
                state.completed_bitmap.clone(),
                state.block_hashes.clone(),
                state.expected_sha256.ok_or("resume-state-invalid")?,
                state.checkpoint_generation + 1,
                state.lifecycle.generation,
                now_unix_ms(),
            )
        };
        let completed_bytes = super::resume::completed_bytes_for_bitmap(
            &bitmap,
            record.total_blocks,
            record.block_size,
            record.expected_file_size,
        )?;
        let transfer_id = *Uuid::parse_str(&record.transfer_id)
            .map_err(|e| e.to_string())?
            .as_bytes();
        let authorization = super::authorization::material_for_transfer(&transfer_id)?;
        let checkpoint_key = super::secure_protocol::derive_checkpoint_key(
            &authorization.master,
            &transfer_id,
            &authorization.invitation.body.invitation_id,
        )?;
        let part_identity_digest = super::resume::part_identity_digest(&record.part_path).await?;
        let metadata = super::resume::ResumeMetadata {
            format_version: super::resume::RESUME_FORMAT_VERSION,
            protocol_version: super::protocol::NATIVE_QUIC_PROTOCOL_VERSION,
            transfer_id,
            invitation_id: authorization.invitation.body.invitation_id,
            secret_version: 3,
            share_id: record.share_id.clone(),
            lifecycle_generation,
            checkpoint_generation: generation,
            checkpoint_state,
            previous_session_id: Some(super::secure_transport::parse_session_id(
                &record.mutable.lock().await.session_id,
            )?),
            source: source_identity.clone(),
            expected_sha256: expected_hash,
            final_filename: record
                .destination_path
                .file_name()
                .and_then(|v| v.to_str())
                .ok_or("resume-state-invalid")?
                .into(),
            part_filename: record
                .part_path
                .file_name()
                .and_then(|v| v.to_str())
                .ok_or("resume-state-invalid")?
                .into(),
            block_size: record.block_size,
            total_blocks: record.total_blocks,
            completed_bitmap: bitmap,
            completed_bytes,
            created_unix_ms: record.created_unix_ms,
            checkpoint_unix_ms: checkpoint_time,
            checkpoint_auth_micros: 0,
            retain_partial: true,
            block_hash_sidecar_digest: [0; 32],
            part_identity_digest,
            secure_state_digest: [0; 32],
            authentication_tag: [0; 32],
        };
        let mut block_manifest = super::block_hash::from_hashes(
            metadata.transfer_id,
            generation,
            record.expected_file_size,
            record.block_size,
            &block_hashes,
        )?;
        let block_auth_started = Instant::now();
        block_manifest.authenticate(
            authorization.invitation.body.invitation_id,
            part_identity_digest,
            &checkpoint_key,
        )?;
        let sidecar_digest = block_manifest.authenticated_digest()?;
        let mut checkpoint_auth_ms = block_auth_started.elapsed().as_secs_f64() * 1000.0;
        let sidecar_size = super::block_hash::write_atomic_authenticated(
            &record.resume_path,
            &block_manifest,
            &checkpoint_key,
            None,
        )
        .await?;
        let mut metadata = metadata;
        let metadata_auth_started = Instant::now();
        metadata.refresh_security(&checkpoint_key, sidecar_digest, part_identity_digest)?;
        checkpoint_auth_ms += metadata_auth_started.elapsed().as_secs_f64() * 1000.0;
        metadata.set_checkpoint_auth_duration(
            &checkpoint_key,
            (checkpoint_auth_ms * 1000.0).ceil() as u64,
        )?;
        super::resume::write_atomic_authenticated(&record.resume_path, &metadata, &checkpoint_key)
            .await?;
        super::authorization::mark_resumable(&transfer_id)?;
        let mut state = record.mutable.lock().await;
        state.checkpoint_generation = generation;
        state.last_checkpoint_unix_ms = Some(checkpoint_time);
        state.checkpoint_succeeded = true;
        state.resume_available = true;
        state.partial_retained = true;
        state.block_hash_sidecar_bytes = sidecar_size as u64;
        state.last_checkpoint_auth_ms = checkpoint_auth_ms;
        Ok(())
    }
    .await;
    {
        let mut state = record.mutable.lock().await;
        state.active_checkpoint_tasks = state.active_checkpoint_tasks.saturating_sub(1);
    }
    result
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeFileLoopbackRequest {
    pub source_path: Option<String>,
    pub source_mode: Option<String>,
    pub total_bytes: Option<u64>,
    pub destination_directory: String,
    pub stream_count: Option<u8>,
    pub block_bytes: Option<usize>,
    pub overwrite: Option<bool>,
    pub retain_partial: Option<bool>,
    pub sync_mode: Option<String>,
    pub receiver_buffer_count: Option<usize>,
    pub write_queue_capacity: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeFileTransferMetrics {
    event: &'static str,
    transfer_id: String,
    source_file_size: u64,
    payload_bytes: u64,
    wire_bytes: u64,
    stream_count: u8,
    block_bytes: usize,
    elapsed_seconds: f64,
    sender_mbps: f64,
    receiver_mbps: f64,
    disk_read_mbps: f64,
    disk_write_mbps: f64,
    hash_mbps: f64,
    preallocation_ms: f64,
    source_hash_ms: f64,
    receiver_hash_ms: f64,
    finalization_ms: f64,
    sync_data_ms: f64,
    sync_all_ms: f64,
    rename_ms: f64,
    peak_pooled_memory: u64,
    peak_pending_write_bytes: u64,
    rtt_ms: f64,
    lost_packets: u64,
    congestion_window_bytes: u64,
    mtu: u16,
    ranges_transferred: u32,
    integrity_result: String,
    final_path: String,
    likely_bottleneck: String,
    invitation_creation_ms: f64,
    protected_secret_store_ms: f64,
    secure_handshake_ms: f64,
    session_key_derivation_ms: f64,
    security_key_material_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileControl {
    transfer_id: [u8; 16],
    file_size: u64,
    stream_count: u8,
    expected_sha256: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileCompletionAck {
    transfer_id: [u8; 16],
    received_bytes: u64,
    sha256: [u8; 32],
    integrity_ok: bool,
}

#[derive(Debug)]
struct SourceIdentity {
    size: u64,
    modified_ms: Option<u128>,
    resume_identity: super::resume::SourceIdentity,
}

async fn source_identity(path: &Path) -> Result<SourceIdentity, String> {
    let metadata = fs::metadata(path)
        .await
        .map_err(|e| format!("source-unreadable: {e}"))?;
    if !metadata.is_file() {
        return Err("source-not-regular-file".into());
    }
    let modified_ms = metadata.modified().ok().and_then(|value| {
        value
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|value| value.as_millis())
    });
    Ok(SourceIdentity {
        size: metadata.len(),
        modified_ms,
        resume_identity: super::resume::capture_source_identity(path).await?,
    })
}

pub(crate) async fn sha256_file(
    path: &Path,
    block_bytes: usize,
) -> Result<([u8; 32], f64), String> {
    let started = Instant::now();
    let mut file = File::open(path).await.map_err(|e| e.to_string())?;
    let mut buffer = vec![0u8; block_bytes];
    let mut hash = Sha256::new();
    loop {
        let count = file.read(&mut buffer).await.map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok((hash.finalize().into(), started.elapsed().as_secs_f64()))
}

#[doc(hidden)]
pub async fn sha256_file_for_benchmark(
    path: &Path,
    block_bytes: usize,
) -> Result<([u8; 32], f64), String> {
    sha256_file(path, block_bytes).await
}

fn safe_name(source: &Path) -> Result<String, String> {
    let name = source
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("invalid-source-file-name")?;
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\']) {
        return Err("unsafe-source-file-name".into());
    }
    Ok(name.to_string())
}

fn duplicate_name(directory: &Path, name: &str, overwrite: bool) -> Result<PathBuf, String> {
    let requested = directory.join(name);
    if overwrite || !requested.exists() {
        return Ok(requested);
    }
    let path = Path::new(name);
    let stem = path.file_stem().and_then(|v| v.to_str()).unwrap_or("file");
    let extension = path.extension().and_then(|v| v.to_str());
    for index in 1..100_000u32 {
        let candidate = match extension {
            Some(ext) => directory.join(format!("{stem} ({index}).{ext}")),
            None => directory.join(format!("{stem} ({index})")),
        };
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err("destination-name-exhausted".into())
}

fn range_for(file_size: u64, streams: u8, index: u8) -> (u64, u64) {
    let base = file_size / streams as u64;
    let offset = base * index as u64;
    let length = if index + 1 == streams {
        file_size - offset
    } else {
        base
    };
    (offset, length)
}

fn deterministic_range_hash(file_size: u64, streams: u8, block_bytes: usize) -> [u8; 32] {
    let active = if file_size == 0 {
        0
    } else {
        streams.min(file_size.min(u8::MAX as u64) as u8)
    };
    let mut hash = Sha256::new();
    for index in 0..active {
        let (_, length) = range_for(file_size, active, index);
        let block = vec![index.wrapping_mul(37).wrapping_add(11); block_bytes];
        let mut remaining = length;
        while remaining != 0 {
            let count = remaining.min(block_bytes as u64) as usize;
            hash.update(&block[..count]);
            remaining -= count as u64;
        }
    }
    hash.finalize().into()
}

pub async fn flowshare_native_file_loopback(
    request: NativeFileLoopbackRequest,
) -> Result<NativeFileTransferMetrics, String> {
    if !cfg!(any(debug_assertions, test)) {
        return Err("Native file loopback is development-only.".into());
    }
    run_file_loopback(request).await
}

pub async fn run_file_loopback(
    request: NativeFileLoopbackRequest,
) -> Result<NativeFileTransferMetrics, String> {
    let memory_mode = request.source_mode.as_deref() == Some("memory");
    let source = if memory_mode {
        None
    } else {
        Some(
            fs::canonicalize(
                request
                    .source_path
                    .as_ref()
                    .ok_or("sourcePath is required")?,
            )
            .await
            .map_err(|e| format!("source-unreadable: {e}"))?,
        )
    };
    let destination_directory = fs::canonicalize(&request.destination_directory)
        .await
        .map_err(|e| format!("destination-unavailable: {e}"))?;
    if !fs::metadata(&destination_directory)
        .await
        .map_err(|e| e.to_string())?
        .is_dir()
    {
        return Err("destination-not-directory".into());
    }
    let initial_identity = if let Some(source) = source.as_deref() {
        source_identity(source).await?
    } else {
        SourceIdentity {
            size: request.total_bytes.unwrap_or(1024 * 1024 * 1024),
            modified_ms: None,
            resume_identity: super::resume::SourceIdentity {
                size: request.total_bytes.unwrap_or(1024 * 1024 * 1024),
                modified_unix_ms: None,
                platform_file_id: None,
                canonical_path: None,
            },
        }
    };
    let mut config = NativeQuicConfig::desktop(request.stream_count.unwrap_or(4))?;
    if let Some(block) = request.block_bytes {
        if !matches!(block, 1_048_576 | 2_097_152 | 4_194_304 | 8_388_608) {
            return Err("block size must be 1, 2, 4, or 8 MiB".into());
        }
        config.block_bytes = block;
    }
    let name = if let Some(source) = source.as_deref() {
        safe_name(source)?
    } else {
        "native-memory-payload.bin".into()
    };
    let final_path = duplicate_name(
        &destination_directory,
        &name,
        request.overwrite.unwrap_or(false),
    )?;
    let transfer_uuid = Uuid::new_v4();
    let transfer_id = *transfer_uuid.as_bytes();
    let part_path = final_path.with_file_name(format!(".{}.{}.part", name, transfer_uuid));
    let resume_path = part_path.with_extension("resume.current");
    let retain_partial = request.retain_partial.unwrap_or(true);
    let record = super::transfer_registry::register(super::transfer_registry::NewTransferRecord {
        transfer_id: transfer_uuid.to_string(),
        source_path: source.clone(),
        source_identity: Some(initial_identity.resume_identity.clone()),
        destination_path: final_path.clone(),
        part_path: part_path.clone(),
        resume_path: resume_path.clone(),
        expected_file_size: initial_identity.size,
        block_size: config.block_bytes as u64,
        retain_partial,
    })
    .await?;
    record
        .transition(super::lifecycle::TransferState::Preparing)
        .await?;
    let hash_started = Instant::now();
    let expected_hash = if let Some(source) = source.as_deref() {
        sha256_file(source, config.block_bytes).await?.0
    } else {
        deterministic_range_hash(
            initial_identity.size,
            config.stream_count,
            config.block_bytes,
        )
    };
    let source_hash_seconds = hash_started.elapsed().as_secs_f64();
    record.mutable.lock().await.expected_sha256 = Some(expected_hash);

    let preallocation_started = Instant::now();
    let part = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&part_path)
        .await
        .map_err(|e| format!("destination-create-failed: {e}"))?;
    part.set_len(initial_identity.size)
        .await
        .map_err(|e| format!("destination-preallocation-failed: {e}"))?;
    drop(part);
    let preallocation_seconds = preallocation_started.elapsed().as_secs_f64();

    let invitation_started = Instant::now();
    let identity = create_ephemeral_identity()?;
    let authorization = super::authorization::create_registered_invitation(
        transfer_id,
        identity.fingerprint_sha256_bytes,
        super::protocol::RESUME_REQUIRED_CAPABILITIES,
        super::secure_protocol::DEFAULT_INVITATION_LIFETIME_MS,
    )?;
    let invitation_creation_seconds = invitation_started.elapsed().as_secs_f64();
    let secret_store_started = Instant::now();
    if let Err(error) = super::secret_store::store(&resume_path, &authorization).await {
        let _ = fs::remove_file(&part_path).await;
        return Err(error);
    }
    let protected_secret_store_seconds = secret_store_started.elapsed().as_secs_f64();

    let result = transfer_file(
        source.as_deref(),
        &part_path,
        &final_path,
        &config,
        transfer_id,
        initial_identity.size,
        initial_identity.modified_ms,
        expected_hash,
        source_hash_seconds,
        preallocation_seconds,
        request.sync_mode.as_deref().unwrap_or("all"),
        request
            .receiver_buffer_count
            .unwrap_or(DEFAULT_RECEIVER_BUFFER_COUNT),
        request
            .write_queue_capacity
            .unwrap_or(DEFAULT_PER_STREAM_WRITE_QUEUE),
        record.clone(),
        identity,
        invitation_creation_seconds,
        protected_secret_store_seconds,
    )
    .await;
    if result.is_err() {
        let stop_reason = record.stop_reason().await;
        let checkpoint_state = match stop_reason {
            Some(super::transfer_registry::StopReason::Pause) => {
                Some(super::lifecycle::TransferState::Paused)
            }
            Some(super::transfer_registry::StopReason::CancelRetain) => {
                Some(super::lifecycle::TransferState::Cancelled)
            }
            Some(super::transfer_registry::StopReason::Disconnect) => {
                Some(super::lifecycle::TransferState::PausedByDisconnect)
            }
            Some(super::transfer_registry::StopReason::CancelDelete) => None,
            None if retain_partial => Some(super::lifecycle::TransferState::RecoverableFailure),
            None => None,
        };
        if let Some(state) = checkpoint_state {
            if let Err(error) =
                checkpoint_record(&record, &initial_identity.resume_identity, state).await
            {
                record.mutable.lock().await.terminal_error = Some(error);
            }
            let _ = record.transition(state).await;
        } else if stop_reason == Some(super::transfer_registry::StopReason::CancelDelete) {
            let _ = fs::remove_file(&part_path).await;
            let _ = super::resume::remove_generations(&record.resume_path).await;
            let _ = super::block_hash::remove_generations(&record.resume_path).await;
            let _ = super::secret_store::delete(&record.resume_path).await;
            let _ = super::authorization::revoke(&transfer_id);
            let _ = record
                .transition(super::lifecycle::TransferState::Cancelled)
                .await;
        } else {
            let mut mutable = record.mutable.lock().await;
            mutable.terminal_error = result.as_ref().err().cloned();
            let _ = mutable
                .lifecycle
                .transition(super::lifecycle::TransferState::Failed, now_unix_ms());
        }
    }
    record.reset_terminal_resources().await;
    result
}

#[allow(clippy::too_many_arguments)]
async fn transfer_file(
    source: Option<&Path>,
    part_path: &Path,
    final_path: &Path,
    config: &NativeQuicConfig,
    transfer_id: [u8; 16],
    file_size: u64,
    source_modified_ms: Option<u128>,
    expected_hash: [u8; 32],
    source_hash_seconds: f64,
    preallocation_seconds: f64,
    sync_mode: &str,
    receiver_buffer_count: usize,
    write_queue_capacity: usize,
    record: Arc<super::transfer_registry::TransferRecord>,
    identity: EphemeralIdentity,
    invitation_creation_seconds: f64,
    protected_secret_store_seconds: f64,
) -> Result<NativeFileTransferMetrics, String> {
    if !matches!(sync_mode, "none" | "data" | "all") {
        return Err("sync mode must be none, data, or all".into());
    }
    if !matches!(receiver_buffer_count, 8 | 16 | 32) {
        return Err("receiver buffer count must be 8, 16, or 32".into());
    }
    if !matches!(write_queue_capacity, 2 | 4 | 8 | 16) {
        return Err("write queue capacity must be 2, 4, 8, or 16".into());
    }
    let cancellation = record.cancellation_token().await;
    record
        .transition(super::lifecycle::TransferState::Connecting)
        .await?;
    let data_streams = if file_size == 0 {
        0
    } else {
        config.stream_count.min(file_size.min(u8::MAX as u64) as u8)
    };
    let certificate_fingerprint = identity.fingerprint_sha256_bytes;
    let authorization = super::authorization::material_for_transfer(&transfer_id)?;
    let invitation_id = authorization.invitation.body.invitation_id;
    let session_id =
        super::secure_transport::parse_session_id(&record.mutable.lock().await.session_id)?;
    let security_capabilities = super::protocol::RESUME_REQUIRED_CAPABILITIES;
    let transfer_commitment = super::secure_protocol::transfer_commitment(
        file_size,
        &expected_hash,
        config.block_bytes as u64,
        file_size.div_ceil(config.block_bytes as u64),
        security_capabilities,
    );
    let mut server_config = ServerConfig::with_single_cert(
        vec![identity.certificate.clone()],
        identity.private_key.into(),
    )
    .map_err(|e| e.to_string())?;
    server_config.transport_config(config.transport()?);
    let server = Endpoint::server(
        server_config,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .map_err(|e| e.to_string())?;
    let server_addr = server.local_addr().map_err(|e| e.to_string())?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(identity.certificate).map_err(|e| e.to_string())?;
    let mut client_config =
        ClientConfig::with_root_certificates(Arc::new(roots)).map_err(|e| e.to_string())?;
    client_config.transport_config(config.transport()?);
    let mut client = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .map_err(|e| e.to_string())?;
    client.set_default_client_config(client_config);

    let receiver_part = part_path.to_path_buf();
    let receiver_final = final_path.to_path_buf();
    let receiver_block = config.block_bytes;
    let receiver_sync_mode = sync_mode.to_string();
    let receiver_record = record.clone();
    let receiver_cancellation = cancellation.clone();
    let receiver = tokio::spawn(async move {
        let connection = server
            .accept()
            .await
            .ok_or("receiver-endpoint-closed")?
            .await
            .map_err(|e| e.to_string())?;
        let (mut ack_send, mut control_recv) = super::secure_transport::accept_control_stream(
            &connection,
            transfer_id,
            invitation_id,
            session_id,
            0,
        )
        .await?;
        let mut security = super::secure_transport::authenticate_server(
            &connection,
            &mut ack_send,
            &mut control_recv,
            transfer_id,
            invitation_id,
            session_id,
            certificate_fingerprint,
            super::secure_protocol::SecureSessionMode::NewTransfer,
            0,
            [0; 32],
            transfer_commitment,
            super::secure_protocol::session_lineage_digest(None),
            security_capabilities,
        )
        .await?;
        let control_len = control_recv.read_u32().await.map_err(|e| e.to_string())? as usize;
        if control_len > 8192 {
            return Err("control-frame-too-large".into());
        }
        let mut control_bytes = vec![0u8; control_len];
        control_recv
            .read_exact(&mut control_bytes)
            .await
            .map_err(|e| e.to_string())?;
        let control_payload = security.control.open(
            super::secure_protocol::MESSAGE_TRANSFER_METADATA,
            &control_bytes,
        )?;
        let control: FileControl =
            serde_json::from_slice(&control_payload).map_err(|_| "authentication-failed")?;
        if control.transfer_id != transfer_id
            || control.file_size != file_size
            || control.stream_count != data_streams
            || control.expected_sha256 != expected_hash
        {
            return Err("wrong-transfer-control".into());
        }
        let write_started = Instant::now();
        let (free_tx, free_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(receiver_buffer_count);
        for _ in 0..receiver_buffer_count {
            free_tx
                .send(vec![0u8; receiver_block])
                .await
                .map_err(|_| "buffer-pool-init-failed")?;
        }
        let free_rx = Arc::new(tokio::sync::Mutex::new(free_rx));
        let mut tasks = Vec::new();
        for _ in 0..control.stream_count {
            let mut stream = connection.accept_uni().await.map_err(|e| e.to_string())?;
            let output = receiver_part.clone();
            let pool_take = free_rx.clone();
            let pool_return = free_tx.clone();
            let task_record = receiver_record.clone();
            let task_cancellation = receiver_cancellation.clone();
            tasks.push(tokio::spawn(async move {
                task_record.mutable.lock().await.active_receiver_streams += 1;
                let mut encoded = [0u8; RANGE_HEADER_BYTES];
                stream
                    .read_exact(&mut encoded)
                    .await
                    .map_err(|e| e.to_string())?;
                let header = RangeHeader::decode(&encoded).map_err(|e| e.to_string())?;
                header
                    .validate(&transfer_id, file_size)
                    .map_err(|e| e.to_string())?;
                let (write_tx, mut write_rx) =
                    tokio::sync::mpsc::channel::<(u64, usize, Vec<u8>)>(write_queue_capacity);
                let writer_pool = pool_return.clone();
                let writer_record = task_record.clone();
                let writer = tokio::spawn(async move {
                    writer_record.mutable.lock().await.active_writers += 1;
                    let mut file = OpenOptions::new()
                        .write(true)
                        .open(output)
                        .await
                        .map_err(|e| e.to_string())?;
                    let mut expected_offset = None;
                    let mut written = 0u64;
                    while let Some((offset, valid, buffer)) = write_rx.recv().await {
                        {
                            let mut state = writer_record.mutable.lock().await;
                            state.queued_writes = state.queued_writes.saturating_sub(1);
                        }
                        if expected_offset != Some(offset) {
                            file.seek(SeekFrom::Start(offset))
                                .await
                                .map_err(|e| e.to_string())?;
                        }
                        file.write_all(&buffer[..valid])
                            .await
                            .map_err(|e| format!("destination-write-failed: {e}"))?;
                        {
                            let mut state = writer_record.mutable.lock().await;
                            state.bytes_written += valid as u64;
                            state.session_bytes_written += valid as u64;
                            if offset % writer_record.block_size == 0 {
                                let block = offset / writer_record.block_size;
                                if block < writer_record.total_blocks {
                                    let expected_length = (writer_record.expected_file_size
                                        - offset)
                                        .min(writer_record.block_size);
                                    let byte = (block / 8) as usize;
                                    let mask = 1u8 << (block % 8);
                                    if valid as u64 == expected_length {
                                        if state.completed_bitmap[byte] & mask == 0 {
                                            state.completed_bitmap[byte] |= mask;
                                            state.completed_blocks += 1;
                                        }
                                        state.block_hashes[block as usize] =
                                            Some(Sha256::digest(&buffer[..valid]).into());
                                    }
                                }
                            }
                        }
                        written += valid as u64;
                        expected_offset = Some(offset + valid as u64);
                        writer_pool
                            .send(buffer)
                            .await
                            .map_err(|_| "buffer-pool-return-failed".to_string())?;
                        let mut state = writer_record.mutable.lock().await;
                        state.checked_out_buffers = state.checked_out_buffers.saturating_sub(1);
                    }
                    file.flush().await.map_err(|e| e.to_string())?;
                    writer_record.mutable.lock().await.active_writers -= 1;
                    Ok::<u64, String>(written)
                });
                let mut remaining = header.length;
                let mut block_offset = header.offset;
                let mut cancelled = false;
                while remaining > 0 {
                    if task_cancellation.is_cancelled() {
                        cancelled = true;
                        break;
                    }
                    let target = remaining.min(receiver_block as u64) as usize;
                    let mut buffer = pool_take
                        .lock()
                        .await
                        .recv()
                        .await
                        .ok_or("buffer-pool-exhausted")?;
                    task_record.mutable.lock().await.checked_out_buffers += 1;
                    let mut filled = 0usize;
                    while filled < target {
                        let count = stream
                            .read(&mut buffer[filled..target])
                            .await
                            .map_err(|e| e.to_string())?
                            .ok_or("range-unexpected-eof")?;
                        if count == 0 {
                            return Err("range-short-read".into());
                        }
                        filled += count;
                    }
                    write_tx
                        .send((block_offset, filled, buffer))
                        .await
                        .map_err(|_| "receiver-writer-stopped".to_string())?;
                    {
                        let mut state = task_record.mutable.lock().await;
                        state.queued_writes += 1;
                        state.bytes_received += filled as u64;
                        state.session_bytes_received += filled as u64;
                    }
                    block_offset += filled as u64;
                    remaining -= filled as u64;
                }
                if !cancelled
                    && stream
                        .read_chunk(1, true)
                        .await
                        .map_err(|e| e.to_string())?
                        .is_some()
                {
                    return Err("range-declared-length-mismatch".into());
                }
                drop(write_tx);
                let written = writer.await.map_err(|e| e.to_string())??;
                if cancelled {
                    return Err("native-file-transfer-cancelled".into());
                }
                if written != header.length {
                    return Err("destination-short-write".into());
                }
                {
                    let mut state = task_record.mutable.lock().await;
                    state.active_receiver_streams = state.active_receiver_streams.saturating_sub(1);
                }
                Ok::<RangeHeader, String>(header)
            }));
        }
        let mut ledger = RangeLedger::default();
        let mut task_error = None;
        for task in tasks {
            match task.await.map_err(|e| e.to_string())? {
                Ok(header) => {
                    if let Err(error) = ledger
                        .record(&header, header.length)
                        .map_err(|e| e.to_string())
                    {
                        task_error.get_or_insert(error);
                    }
                }
                Err(error) => {
                    task_error.get_or_insert(error);
                }
            }
        }
        if let Some(error) = task_error {
            return Err(error);
        }
        let write_seconds = write_started.elapsed().as_secs_f64();
        let manifest_len = control_recv.read_u32().await.map_err(|e| e.to_string())? as usize;
        if manifest_len > 4096 {
            return Err("completion-frame-too-large".into());
        }
        let mut manifest_bytes = vec![0u8; manifest_len];
        control_recv
            .read_exact(&mut manifest_bytes)
            .await
            .map_err(|e| e.to_string())?;
        let manifest_payload = security.control.open(
            super::secure_protocol::MESSAGE_COMPLETION_MANIFEST,
            &manifest_bytes,
        )?;
        let manifest: CompletionManifest =
            serde_json::from_slice(&manifest_payload).map_err(|_| "authentication-failed")?;
        if manifest.transfer_id != transfer_id || manifest.sha256 != Some(expected_hash) {
            return Err("completion-manifest-mismatch".into());
        }
        ledger
            .finalize(&manifest, file_size)
            .map_err(|e| e.to_string())?;
        if receiver_cancellation.is_cancelled() {
            return Err("native-file-transfer-cancelled".into());
        }
        receiver_record
            .transition(super::lifecycle::TransferState::Validating)
            .await?;
        receiver_record.mutable.lock().await.finalization_owned = true;
        receiver_record
            .transition(super::lifecycle::TransferState::Synchronizing)
            .await?;
        let canonical = OpenOptions::new()
            .write(true)
            .open(&receiver_part)
            .await
            .map_err(|e| e.to_string())?;
        let mut sync_data_seconds = 0.0;
        let mut sync_all_seconds = 0.0;
        if receiver_sync_mode == "data" {
            let started = Instant::now();
            canonical.sync_data().await.map_err(|e| e.to_string())?;
            sync_data_seconds = started.elapsed().as_secs_f64();
        } else if receiver_sync_mode == "all" {
            let started = Instant::now();
            canonical.sync_all().await.map_err(|e| e.to_string())?;
            sync_all_seconds = started.elapsed().as_secs_f64();
        }
        drop(canonical);
        let (actual_hash, receiver_hash_seconds) =
            sha256_file(&receiver_part, receiver_block).await?;
        if actual_hash != expected_hash {
            return Err("integrity-mismatch".into());
        }
        if receiver_cancellation.is_cancelled() {
            return Err("native-file-transfer-cancelled".into());
        }
        receiver_record
            .transition(super::lifecycle::TransferState::Finalizing)
            .await?;
        let rename_started = Instant::now();
        fs::rename(&receiver_part, &receiver_final)
            .await
            .map_err(|e| format!("atomic-finalization-failed: {e}"))?;
        receiver_record
            .transition(super::lifecycle::TransferState::Completed)
            .await?;
        let mut cleanup_warnings = Vec::new();
        if let Err(error) = super::resume::remove_generations(&receiver_record.resume_path).await {
            cleanup_warnings.push(error);
        }
        if let Err(error) =
            super::block_hash::remove_generations(&receiver_record.resume_path).await
        {
            cleanup_warnings.push(error);
        }
        if let Err(error) = super::secret_store::delete(&receiver_record.resume_path).await {
            cleanup_warnings.push(error);
        }
        if let Err(error) = super::authorization::consume(&transfer_id) {
            cleanup_warnings.push(error);
        }
        {
            let mut state = receiver_record.mutable.lock().await;
            state.finalization_owned = false;
            state.resume_available = false;
            state.partial_retained = false;
            state.cleanup_warnings = cleanup_warnings;
        }
        let rename_seconds = rename_started.elapsed().as_secs_f64();
        let finalization_seconds = sync_data_seconds + sync_all_seconds + rename_seconds;
        let ack_payload = serde_json::to_vec(&FileCompletionAck {
            transfer_id,
            received_bytes: file_size,
            sha256: actual_hash,
            integrity_ok: true,
        })
        .map_err(|e| e.to_string())?;
        let ack = security
            .control
            .seal(super::secure_protocol::MESSAGE_COMPLETION_ACK, &ack_payload)?;
        ack_send
            .write_u32(ack.len() as u32)
            .await
            .map_err(|e| e.to_string())?;
        ack_send.write_all(&ack).await.map_err(|e| e.to_string())?;
        ack_send.finish().map_err(|e| e.to_string())?;
        // Keep the endpoint alive long enough for the final ACK and FIN to be
        // observed by the client before dropping the loopback server.
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        Ok::<(f64, f64, f64, f64, f64, f64), String>((
            write_seconds,
            receiver_hash_seconds,
            finalization_seconds.max(0.0),
            sync_data_seconds,
            sync_all_seconds,
            rename_seconds,
        ))
    });

    let connection = client
        .connect(server_addr, "flowshare-native.local")
        .map_err(|e| e.to_string())?
        .await
        .map_err(|e| e.to_string())?;
    let (mut control_send, mut ack_recv) = connection.open_bi().await.map_err(|e| e.to_string())?;
    let handshake_started = Instant::now();
    let prepared = super::authorization::prepare_client_handshake(
        transfer_id,
        session_id,
        super::secure_protocol::SecureSessionMode::NewTransfer,
        0,
        [0; 32],
        transfer_commitment,
        super::secure_protocol::session_lineage_digest(None),
        certificate_fingerprint,
        security_capabilities,
    )?;
    let mut security = super::secure_transport::authenticate_client(
        &connection,
        &mut control_send,
        &mut ack_recv,
        prepared,
    )
    .await?;
    let session_key_derivation_ms = security.key_derivation_ms;
    let secure_handshake_seconds = handshake_started.elapsed().as_secs_f64();
    record
        .transition(super::lifecycle::TransferState::Transferring)
        .await?;
    let control = serde_json::to_vec(&FileControl {
        transfer_id,
        file_size,
        stream_count: data_streams,
        expected_sha256: expected_hash,
    })
    .map_err(|e| e.to_string())?;
    let control = security
        .control
        .seal(super::secure_protocol::MESSAGE_TRANSFER_METADATA, &control)?;
    control_send
        .write_u32(control.len() as u32)
        .await
        .map_err(|e| e.to_string())?;
    control_send
        .write_all(&control)
        .await
        .map_err(|e| e.to_string())?;
    let transfer_started = Instant::now();
    let mut tasks = Vec::new();
    for index in 0..data_streams {
        let mut stream = match connection.open_uni().await {
            Ok(stream) => stream,
            Err(error) => {
                connection.close(VarInt::from_u32(0x1ff), b"stream-open-failed");
                let _ = receiver.await;
                return Err(error.to_string());
            }
        };
        let task_record = record.clone();
        let task_cancellation = cancellation.clone();
        let input = source.map(Path::to_path_buf);
        let block_bytes = config.block_bytes;
        let (offset, length) = range_for(file_size, data_streams, index);
        let header = RangeHeader {
            transfer_id,
            range_id: index as u32,
            offset,
            length,
            flags: 0,
        };
        tasks.push(tokio::spawn(async move {
            {
                let mut state = task_record.mutable.lock().await;
                state.active_sender_streams += 1;
                if input.is_some() {
                    state.active_readers += 1;
                }
            }
            stream
                .write_all(&header.encode())
                .await
                .map_err(|e| e.to_string())?;
            let mut file = if let Some(input) = input {
                let mut file = File::open(input).await.map_err(|e| e.to_string())?;
                file.seek(SeekFrom::Start(offset))
                    .await
                    .map_err(|e| e.to_string())?;
                Some(file)
            } else {
                None
            };
            let mut buffer = vec![index.wrapping_mul(37).wrapping_add(11); block_bytes];
            let mut remaining = length;
            while remaining > 0 {
                if task_cancellation.is_cancelled() {
                    return Err("native-file-transfer-cancelled".into());
                }
                let wanted = remaining.min(block_bytes as u64) as usize;
                if let Some(file) = file.as_mut() {
                    file.read_exact(&mut buffer[..wanted])
                        .await
                        .map_err(|_| "source-short-read".to_string())?;
                    let mut state = task_record.mutable.lock().await;
                    state.bytes_read += wanted as u64;
                    state.session_bytes_read += wanted as u64;
                }
                stream
                    .write_all(&buffer[..wanted])
                    .await
                    .map_err(|e| e.to_string())?;
                let mut state = task_record.mutable.lock().await;
                state.bytes_sent += wanted as u64;
                state.session_bytes_sent += wanted as u64;
                remaining -= wanted as u64;
            }
            stream.finish().map_err(|e| e.to_string())?;
            {
                let mut state = task_record.mutable.lock().await;
                state.active_sender_streams = state.active_sender_streams.saturating_sub(1);
                if file.is_some() {
                    state.active_readers = state.active_readers.saturating_sub(1);
                }
            }
            Ok::<u64, String>(length)
        }));
    }
    let mut sent = 0u64;
    let mut sender_error = None;
    for task in tasks {
        match task.await.map_err(|e| e.to_string())? {
            Ok(bytes) => sent += bytes,
            Err(error) => {
                sender_error.get_or_insert(error);
            }
        }
    }
    if let Some(error) = sender_error {
        connection.close(VarInt::from_u32(0x101), b"native-transfer-stopped");
        let _ = receiver.await;
        return Err(error);
    }
    let manifest = serde_json::to_vec(&CompletionManifest {
        version: super::protocol::NATIVE_QUIC_PROTOCOL_VERSION,
        transfer_id,
        expected_bytes: file_size,
        expected_ranges: data_streams as u32,
        sha256: Some(expected_hash),
    })
    .map_err(|e| e.to_string())?;
    let manifest = security.control.seal(
        super::secure_protocol::MESSAGE_COMPLETION_MANIFEST,
        &manifest,
    )?;
    control_send
        .write_u32(manifest.len() as u32)
        .await
        .map_err(|e| e.to_string())?;
    control_send
        .write_all(&manifest)
        .await
        .map_err(|e| e.to_string())?;
    control_send.finish().map_err(|e| e.to_string())?;
    let ack_result = async {
        let length = ack_recv.read_u32().await.map_err(|e| e.to_string())? as usize;
        if length > 8192 {
            return Err("completion-frame-too-large".into());
        }
        let mut envelope = vec![0u8; length];
        ack_recv
            .read_exact(&mut envelope)
            .await
            .map_err(|e| e.to_string())?;
        let payload = security
            .control
            .open(super::secure_protocol::MESSAGE_COMPLETION_ACK, &envelope)?;
        serde_json::from_slice::<FileCompletionAck>(&payload)
            .map_err(|_| "authentication-failed".to_string())
    }
    .await;
    let receiver_result = receiver.await.map_err(|e| e.to_string())?;
    let (
        write_seconds,
        receiver_hash_seconds,
        finalization_seconds,
        sync_data_seconds,
        sync_all_seconds,
        rename_seconds,
    ) = receiver_result?;
    let ack = ack_result.map_err(|e| format!("final-ack-read-failed: {e}"))?;
    let elapsed = transfer_started.elapsed().as_secs_f64().max(0.000_001);
    if let Some(source) = source {
        let current = source_identity(source).await?;
        if current.size != file_size || current.modified_ms != source_modified_ms {
            return Err("source-file-changed".into());
        }
    }
    if sent != file_size
        || ack.transfer_id != transfer_id
        || ack.received_bytes != file_size
        || ack.sha256 != expected_hash
        || !ack.integrity_ok
    {
        return Err("integrity-mismatch".into());
    }
    let stats = connection.stats();
    let mb = file_size as f64 / 1024.0 / 1024.0;
    let throughput = mb / elapsed;
    let disk_read = mb / elapsed;
    let disk_write = mb / write_seconds.max(0.000_001);
    let hash_rate = mb / receiver_hash_seconds.max(0.000_001);
    let likely = if finalization_seconds / elapsed >= 0.25 {
        "finalization-limited"
    } else {
        "inconclusive"
    };
    let result = NativeFileTransferMetrics {
        event: "native-quic-file-result",
        transfer_id: Uuid::from_bytes(transfer_id).to_string(),
        source_file_size: file_size,
        payload_bytes: sent,
        wire_bytes: stats.udp_tx.bytes,
        stream_count: config.stream_count,
        block_bytes: config.block_bytes,
        elapsed_seconds: elapsed,
        sender_mbps: throughput,
        receiver_mbps: throughput,
        disk_read_mbps: disk_read,
        disk_write_mbps: disk_write,
        hash_mbps: hash_rate,
        preallocation_ms: preallocation_seconds * 1000.0,
        source_hash_ms: source_hash_seconds * 1000.0,
        receiver_hash_ms: receiver_hash_seconds * 1000.0,
        finalization_ms: finalization_seconds * 1000.0,
        sync_data_ms: sync_data_seconds * 1000.0,
        sync_all_ms: sync_all_seconds * 1000.0,
        rename_ms: rename_seconds * 1000.0,
        peak_pooled_memory: (config.block_bytes
            * (config.buffer_pool_blocks + receiver_buffer_count))
            as u64,
        peak_pending_write_bytes: (config.block_bytes
            * config.stream_count as usize
            * write_queue_capacity) as u64,
        rtt_ms: stats.path.rtt.as_secs_f64() * 1000.0,
        lost_packets: stats.path.lost_packets,
        congestion_window_bytes: stats.path.cwnd,
        mtu: stats.path.current_mtu,
        ranges_transferred: data_streams as u32,
        integrity_result: "passed".into(),
        final_path: final_path.display().to_string(),
        likely_bottleneck: likely.into(),
        invitation_creation_ms: invitation_creation_seconds * 1000.0,
        protected_secret_store_ms: protected_secret_store_seconds * 1000.0,
        secure_handshake_ms: secure_handshake_seconds * 1000.0,
        session_key_derivation_ms,
        security_key_material_bytes: 32 + (5 * 32),
    };
    for event in [
        "native-quic-file-sender-summary",
        "native-quic-file-receiver-summary",
        "native-quic-file-result",
    ] {
        let mut value = serde_json::to_value(&result).map_err(|e| e.to_string())?;
        value["event"] = event.into();
        println!("[FlowShareNativePerf] {value}");
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_directory(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("flowget-native-{label}-{}", Uuid::new_v4()))
    }

    #[tokio::test]
    async fn secure_transfer_authenticates_before_payload_and_preserves_hash() {
        let root = test_directory("small");
        let destination = root.join("destination");
        fs::create_dir_all(&destination).await.unwrap();
        let source = root.join("source.bin");
        let content = vec![0x5au8; 3 * 1024 * 1024 + 17];
        fs::write(&source, &content).await.unwrap();
        let result = run_file_loopback(NativeFileLoopbackRequest {
            source_path: Some(source.display().to_string()),
            source_mode: None,
            total_bytes: None,
            destination_directory: destination.display().to_string(),
            stream_count: Some(4),
            block_bytes: Some(1024 * 1024),
            overwrite: Some(false),
            retain_partial: Some(true),
            sync_mode: Some("all".into()),
            receiver_buffer_count: None,
            write_queue_capacity: None,
        })
        .await
        .unwrap();
        assert_eq!(result.integrity_result, "passed");
        assert!(result.invitation_creation_ms > 0.0);
        assert!(result.protected_secret_store_ms > 0.0);
        assert!(result.secure_handshake_ms > 0.0);
        assert_eq!(fs::read(&result.final_path).await.unwrap(), content);
        assert!(!Path::new(&result.final_path)
            .with_extension("part")
            .exists());
        let record = super::super::transfer_registry::lookup(&result.transfer_id)
            .await
            .unwrap();
        assert!(!super::super::secret_store::secret_path(&record.resume_path).exists());
        let transfer_id = *Uuid::parse_str(&result.transfer_id).unwrap().as_bytes();
        assert_eq!(
            super::super::authorization::material_for_transfer(&transfer_id).unwrap_err(),
            "resume-authorization-failed"
        );
        let _ = fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn transfers_empty_file() {
        let root = test_directory("empty");
        let destination = root.join("destination");
        fs::create_dir_all(&destination).await.unwrap();
        let source = root.join("empty.bin");
        fs::write(&source, []).await.unwrap();
        let result = run_file_loopback(NativeFileLoopbackRequest {
            source_path: Some(source.display().to_string()),
            source_mode: None,
            total_bytes: None,
            destination_directory: destination.display().to_string(),
            stream_count: Some(4),
            block_bytes: None,
            overwrite: Some(false),
            retain_partial: Some(true),
            sync_mode: Some("all".into()),
            receiver_buffer_count: None,
            write_queue_capacity: None,
        })
        .await
        .unwrap();
        assert_eq!(fs::metadata(result.final_path).await.unwrap().len(), 0);
        let _ = fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn live_transfer_can_be_cancelled_through_registry() {
        let root = test_directory("live-cancel");
        fs::create_dir_all(&root).await.unwrap();
        let expected_final = root.join("native-memory-payload.bin");
        let root_marker = root.file_name().unwrap().to_string_lossy().into_owned();
        let request = NativeFileLoopbackRequest {
            source_path: None,
            source_mode: Some("memory".into()),
            total_bytes: Some(256 * 1024 * 1024),
            destination_directory: root.display().to_string(),
            stream_count: Some(4),
            block_bytes: Some(2 * 1024 * 1024),
            overwrite: Some(false),
            retain_partial: Some(false),
            sync_mode: Some("none".into()),
            receiver_buffer_count: Some(16),
            write_queue_capacity: Some(4),
        };
        let transfer = tokio::spawn(run_file_loopback(request));
        let transfer_id = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let snapshots = super::super::transfer_registry::flowshare_native_list_transfers()
                    .await
                    .unwrap();
                if let Some(value) = snapshots.into_iter().find(|value| {
                    value.expected_file_size == 256 * 1024 * 1024
                        && value.destination_path.contains(&root_marker)
                        && value
                            .destination_path
                            .ends_with("native-memory-payload.bin")
                }) {
                    break value.transfer_id;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let accepted = super::super::transfer_registry::flowshare_native_cancel_transfer(
            super::super::transfer_registry::CancelTransferRequest {
                transfer_id: transfer_id.clone(),
                retain_partial: Some(false),
                expected_generation: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            accepted.state,
            super::super::lifecycle::TransferState::Cancelling
        );
        assert!(transfer.await.unwrap().is_err());
        let final_state = super::super::transfer_registry::flowshare_native_get_transfer(
            super::super::transfer_registry::TransferIdRequest { transfer_id },
        )
        .await
        .unwrap();
        assert_eq!(
            final_state.state,
            super::super::lifecycle::TransferState::Cancelled
        );
        assert!(!expected_final.exists());
        assert!(!Path::new(&final_state.part_path).exists());
        assert!(
            !super::super::secret_store::secret_path(Path::new(&final_state.resume_path)).exists()
        );
        assert_eq!(
            super::super::resume_transfer::start_resume_transfer(
                super::super::resume_transfer::NativeResumeTransferRequest {
                    resume_metadata_path: final_state.resume_path.clone(),
                    source_path: String::new(),
                    destination_directory: root.display().to_string(),
                    expected_checkpoint_generation: final_state.checkpoint_generation,
                    verification_mode: None,
                    faults: None,
                },
            )
            .await
            .unwrap_err(),
            "invitation-revoked"
        );
        let _ = fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn live_transfer_can_pause_and_checkpoint() {
        let root = test_directory("live-pause");
        fs::create_dir_all(&root).await.unwrap();
        let expected_final = root.join("native-memory-payload.bin");
        let root_marker = root.file_name().unwrap().to_string_lossy().into_owned();
        let transfer = tokio::spawn(run_file_loopback(NativeFileLoopbackRequest {
            source_path: None,
            source_mode: Some("memory".into()),
            total_bytes: Some(256 * 1024 * 1024),
            destination_directory: root.display().to_string(),
            stream_count: Some(4),
            block_bytes: Some(2 * 1024 * 1024),
            overwrite: Some(false),
            retain_partial: Some(true),
            sync_mode: Some("none".into()),
            receiver_buffer_count: Some(16),
            write_queue_capacity: Some(4),
        }));
        let active = tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                let snapshots = super::super::transfer_registry::flowshare_native_list_transfers()
                    .await
                    .unwrap();
                if let Some(value) = snapshots.into_iter().find(|value| {
                    value.expected_file_size == 256 * 1024 * 1024
                        && value.destination_path.contains(&root_marker)
                        && value
                            .destination_path
                            .ends_with("native-memory-payload.bin")
                        && value.state == super::super::lifecycle::TransferState::Transferring
                        && value.bytes_written >= 64 * 1024 * 1024
                }) {
                    break value;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let accepted = super::super::transfer_registry::flowshare_native_pause_transfer(
            super::super::transfer_registry::PauseTransferRequest {
                transfer_id: active.transfer_id.clone(),
                expected_generation: Some(active.state_generation),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            accepted.state,
            super::super::lifecycle::TransferState::Pausing
        );
        assert!(transfer.await.unwrap().is_err());
        let paused = super::super::transfer_registry::flowshare_native_get_transfer(
            super::super::transfer_registry::TransferIdRequest {
                transfer_id: active.transfer_id,
            },
        )
        .await
        .unwrap();
        assert_eq!(paused.state, super::super::lifecycle::TransferState::Paused);
        assert_eq!(paused.active_writers, 0);
        assert_eq!(paused.checked_out_buffers, 0);
        assert_eq!(paused.queued_writes, 0);
        assert!(Path::new(&paused.part_path).exists());
        assert!(Path::new(&paused.resume_path).exists());
        assert!(paused.checkpoint_generation > 0);
        let checkpoint = super::super::resume::read_checkpoint(Path::new(&paused.resume_path))
            .await
            .unwrap();
        assert_eq!(checkpoint.completed_bytes, paused.bytes_written);
        assert_eq!(
            checkpoint
                .completed_bitmap
                .iter()
                .map(|value| value.count_ones() as u64)
                .sum::<u64>(),
            paused.completed_blocks
        );
        assert!(checkpoint.completed_bytes > 0);
        assert!(!expected_final.exists());
        let _ = fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    #[ignore = "run explicitly with FLOWGET_NATIVE_FILE_SOURCE and FLOWGET_NATIVE_FILE_DEST"]
    async fn native_file_release_benchmark() {
        let source = std::env::var("FLOWGET_NATIVE_FILE_SOURCE").ok();
        let source_mode = std::env::var("FLOWGET_NATIVE_FILE_SOURCE_MODE").ok();
        let total_bytes = std::env::var("FLOWGET_NATIVE_FILE_BYTES")
            .ok()
            .and_then(|value| value.parse().ok());
        let destination = std::env::var("FLOWGET_NATIVE_FILE_DEST").unwrap();
        let block_bytes = std::env::var("FLOWGET_NATIVE_FILE_BLOCK_BYTES")
            .ok()
            .and_then(|value| value.parse().ok());
        let sync_mode =
            std::env::var("FLOWGET_NATIVE_FILE_SYNC_MODE").unwrap_or_else(|_| "all".into());
        let receiver_buffer_count = std::env::var("FLOWGET_NATIVE_RECEIVER_BUFFERS")
            .ok()
            .and_then(|value| value.parse().ok());
        let write_queue_capacity = std::env::var("FLOWGET_NATIVE_WRITE_QUEUE")
            .ok()
            .and_then(|value| value.parse().ok());
        let result = run_file_loopback(NativeFileLoopbackRequest {
            source_path: source,
            source_mode,
            total_bytes,
            destination_directory: destination,
            stream_count: Some(4),
            block_bytes,
            overwrite: Some(false),
            retain_partial: Some(true),
            sync_mode: Some(sync_mode),
            receiver_buffer_count,
            write_queue_capacity,
        })
        .await
        .unwrap();
        assert_eq!(result.integrity_result, "passed");
    }
}
