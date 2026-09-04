use super::{
    block_hash,
    config::NativeQuicConfig,
    file_transfer::{checkpoint_record, sha256_file},
    lifecycle::TransferState,
    protocol::{
        missing_block_ranges, validate_missing_ranges, MissingBlockRange, RangeHeader,
        ResumeAccept, ResumeBinding, ResumeCompletionAck, ResumeCompletionManifest,
        ResumeControlMessage, ResumeOffer, ResumeState, NATIVE_QUIC_PROTOCOL_VERSION,
        RANGE_HEADER_BYTES, RESUME_REQUIRED_CAPABILITIES,
    },
    resume::{self, InvalidCheckpointCandidate, ResumeMetadata, SourceIdentity},
    security::create_ephemeral_identity,
    transfer_registry::{self, StopReason, TransferRecord},
};
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream, ServerConfig, VarInt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex},
    time::Instant,
};
use tokio::{
    fs::{self, File, OpenOptions},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom},
};

const RECEIVER_BUFFER_COUNT: usize = 16;
const WRITE_QUEUE_CAPACITY: usize = 4;
const MAX_CONTROL_FRAME_BYTES: usize = 64 * 1024 * 1024;
const CLOSE_PAUSE: u32 = 0x100;
const CLOSE_CANCEL: u32 = 0x101;
const CLOSE_DISCONNECT: u32 = 0x102;
const CLOSE_FAILURE: u32 = 0x1ff;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ResumeVerificationMode {
    #[default]
    Full,
    Sample,
    MetadataOnly,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeResumeFaults {
    pub disconnect_after_bytes: Option<u64>,
    pub pause_after_resumed_bytes: Option<u64>,
    pub cancel_after_resumed_bytes: Option<u64>,
    pub corrupt_completed_block_index: Option<u64>,
    pub delete_block_hash_index: Option<u64>,
    pub corrupt_block_hash_index: Option<u64>,
    pub fail_resume_offer: Option<bool>,
    pub fail_resume_accept: Option<bool>,
    pub fail_resume_checkpoint: Option<bool>,
    pub fail_during_missing_range_transfer: Option<bool>,
    pub fail_before_final_hash: Option<bool>,
    pub fail_before_final_rename: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeResumeTransferRequest {
    pub resume_metadata_path: String,
    pub source_path: String,
    pub destination_directory: String,
    pub expected_checkpoint_generation: u64,
    pub verification_mode: Option<ResumeVerificationMode>,
    pub faults: Option<NativeResumeFaults>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeResumeStartResponse {
    pub transfer_id: String,
    pub session_id: String,
    pub state: TransferState,
    pub checkpoint_generation: u64,
    pub selected_checkpoint_path: String,
    pub selected_checkpoint_generation: u64,
    pub recovered_from_pending: bool,
    pub recovered_from_previous: bool,
    pub invalid_candidates: Vec<InvalidCheckpointCandidate>,
    pub selected_block_hash_path: Option<String>,
    pub block_hash_encoded_size: usize,
    pub invalid_block_hash_candidates: Vec<InvalidCheckpointCandidate>,
    pub verification_mode: ResumeVerificationMode,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct VerificationReport {
    blocks_marked_complete: u64,
    blocks_verified: u64,
    blocks_valid: u64,
    blocks_invalid: u64,
    blocks_missing_hash: u64,
    bytes_reused: u64,
    bytes_invalidated: u64,
    verification_duration_ms: f64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeResumeFinalSummary {
    event: &'static str,
    transfer_id: String,
    session_id: String,
    state: TransferState,
    total_bytes: u64,
    total_blocks: u64,
    checkpoint_generation: u64,
    verification_mode: ResumeVerificationMode,
    verification: VerificationReport,
    verified_completed_blocks: u64,
    missing_blocks: u64,
    missing_range_count: u64,
    bytes_reusable: u64,
    bytes_remaining: u64,
    blocks_skipped: u64,
    bytes_skipped: u64,
    blocks_scheduled: u64,
    bytes_scheduled: u64,
    blocks_retransmitted: u64,
    bytes_retransmitted: u64,
    session_bytes_read: u64,
    session_bytes_sent: u64,
    session_bytes_received: u64,
    session_bytes_written: u64,
    elapsed_seconds: f64,
    final_sha256_passed: bool,
    final_ack_received: bool,
    new_quinn_session: bool,
    block_hash_encoded_size: u64,
    secure_handshake_ms: f64,
    session_key_derivation_ms: f64,
    secure_resume_negotiation_ms: f64,
    checkpoint_auth_ms: f64,
    security_key_material_bytes: u64,
    cleanup_warnings: Vec<String>,
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct ResumePaths {
    source: PathBuf,
    destination_directory: PathBuf,
    final_path: PathBuf,
    part_path: PathBuf,
    resume_current: PathBuf,
    source_identity: SourceIdentity,
}

pub async fn flowshare_native_resume_transfer(
    request: NativeResumeTransferRequest,
) -> Result<NativeResumeStartResponse, String> {
    if !cfg!(any(debug_assertions, test)) {
        return Err("Native QUIC resume is development-only.".into());
    }
    start_resume_transfer(request).await
}

pub async fn start_resume_transfer(
    request: NativeResumeTransferRequest,
) -> Result<NativeResumeStartResponse, String> {
    let requested_path = PathBuf::from(&request.resume_metadata_path);
    if let Some(existing) = transfer_registry::lookup_by_resume_path(&requested_path).await {
        let snapshot = existing.snapshot().await;
        if let Ok(transfer_id) = uuid::Uuid::parse_str(&snapshot.transfer_id) {
            if let Err(error) = super::authorization::material_for_transfer(transfer_id.as_bytes())
            {
                if error == "invitation-revoked" {
                    return Err(error);
                }
            }
        }
        if snapshot.state == TransferState::Completed {
            return Err("resume-transfer-completed".into());
        }
        if snapshot.runtime_active || snapshot.resume_owned || snapshot.finalization_owned {
            return Err("resume-already-active".into());
        }
        if snapshot.cleanup_in_progress || snapshot.state == TransferState::Cancelling {
            return Err("resume-cleanup-in-progress".into());
        }
    }
    // The DPAPI-protected transfer secret is loaded before any persisted
    // checkpoint field is trusted. Version-2 checksum-only checkpoints are
    // therefore rejected by the authenticated loader.
    let protected = super::secret_store::load(&requested_path).await?;
    let protected_transfer_id = protected.material.invitation.body.transfer_id;
    super::authorization::restore_persisted(protected.material.clone())?;
    let checkpoint_key = super::secure_protocol::derive_checkpoint_key(
        &protected.material.master,
        &protected_transfer_id,
        &protected.material.invitation.body.invitation_id,
    )?;
    let selection = resume::load_highest_valid_authenticated(
        &requested_path,
        &checkpoint_key,
        &protected_transfer_id,
        &protected.material.invitation.body.invitation_id,
    )
    .await?;
    if selection.metadata.checkpoint_generation != request.expected_checkpoint_generation {
        return Err("resume-stale-generation".into());
    }
    let transfer_id = uuid::Uuid::from_bytes(selection.metadata.transfer_id).to_string();
    if let Some(existing) = transfer_registry::lookup(&transfer_id).await {
        let snapshot = existing.snapshot().await;
        if snapshot.state == TransferState::Completed {
            return Err("resume-transfer-completed".into());
        }
        if snapshot.runtime_active || snapshot.resume_owned || snapshot.finalization_owned {
            return Err("resume-already-active".into());
        }
        if snapshot.cleanup_in_progress || snapshot.state == TransferState::Cancelling {
            return Err("resume-cleanup-in-progress".into());
        }
    }
    let paths = validate_paths(&request, &selection.metadata, &requested_path).await?;
    let block_selection = block_hash::load_for_generation_authenticated(
        &paths.resume_current,
        &selection.metadata.transfer_id,
        &selection.metadata.invitation_id,
        selection.metadata.checkpoint_generation,
        &selection.metadata.part_identity_digest,
        &selection.metadata.block_hash_sidecar_digest,
        &checkpoint_key,
    )
    .await;
    if block_selection.manifest.is_none() {
        return Err(if block_selection.invalid_candidates.is_empty() {
            "block-hash-sidecar-missing".into()
        } else {
            "checkpoint-authentication-failed".into()
        });
    }
    let claim = transfer_registry::claim_resume(
        &selection.metadata,
        paths.source.clone(),
        paths.final_path.clone(),
        paths.part_path.clone(),
        paths.resume_current.clone(),
    )
    .await?;
    let verification_mode = request.verification_mode.unwrap_or_default();
    let response = NativeResumeStartResponse {
        transfer_id: transfer_id.clone(),
        session_id: claim.session_id.clone(),
        state: TransferState::Resuming,
        checkpoint_generation: selection.metadata.checkpoint_generation,
        selected_checkpoint_path: selection.selected_path.display().to_string(),
        selected_checkpoint_generation: selection.metadata.checkpoint_generation,
        recovered_from_pending: selection.recovered_from_pending,
        recovered_from_previous: selection.recovered_from_previous,
        invalid_candidates: selection.invalid_candidates.clone(),
        selected_block_hash_path: block_selection
            .selected_path
            .as_ref()
            .map(|path| path.display().to_string()),
        block_hash_encoded_size: block_selection.encoded_size,
        invalid_block_hash_candidates: block_selection.invalid_candidates.clone(),
        verification_mode,
    };
    let record = claim.record.clone();
    let metadata = selection.metadata;
    let faults = request.faults.unwrap_or_default();
    let (start_tx, start_rx) = tokio::sync::oneshot::channel::<()>();
    let task_record = record.clone();
    let task = tokio::spawn(async move {
        let _ = start_rx.await;
        let result = run_resumed_transfer(
            task_record.clone(),
            metadata,
            paths,
            verification_mode,
            faults,
        )
        .await;
        finish_resumed_task(task_record, result).await;
    });
    transfer_registry::set_task_abort(&record, task.abort_handle()).await;
    let _ = start_tx.send(());
    println!(
        "[FlowShareNativeResume] {}",
        serde_json::to_string(&response).map_err(|e| e.to_string())?
    );
    Ok(response)
}

async fn validate_paths(
    request: &NativeResumeTransferRequest,
    metadata: &ResumeMetadata,
    requested_resume_path: &Path,
) -> Result<ResumePaths, String> {
    metadata.validate_shape()?;
    let source = fs::canonicalize(&request.source_path)
        .await
        .map_err(|_| "resume-source-missing")?;
    let source_identity = resume::capture_source_identity(&source).await?;
    validate_source_identity(&metadata.source, &source_identity)?;

    let destination_directory = fs::canonicalize(&request.destination_directory)
        .await
        .map_err(|_| "resume-destination-missing")?;
    if !fs::metadata(&destination_directory)
        .await
        .map_err(|_| "resume-destination-missing")?
        .is_dir()
    {
        return Err("resume-destination-missing".into());
    }
    let resume_current = resume::generation_paths(requested_resume_path).current;
    let resume_parent = resume_current.parent().ok_or("resume-checkpoint-invalid")?;
    let resume_parent = fs::canonicalize(resume_parent)
        .await
        .map_err(|_| "resume-checkpoint-invalid")?;
    if !paths_compatible(&resume_parent, &destination_directory) {
        return Err("resume-checkpoint-invalid".into());
    }
    let final_path = destination_directory.join(&metadata.final_filename);
    let part_path = destination_directory.join(&metadata.part_filename);
    if fs::try_exists(&final_path)
        .await
        .map_err(|_| "resume-destination-conflict")?
    {
        return Err("resume-destination-conflict".into());
    }
    let part_metadata = fs::metadata(&part_path)
        .await
        .map_err(|_| "resume-part-missing")?;
    if !part_metadata.is_file() {
        return Err("resume-part-missing".into());
    }
    if part_metadata.len() != metadata.source.size {
        return Err("resume-part-size-mismatch".into());
    }
    if resume::part_identity_digest(&part_path).await? != metadata.part_identity_digest {
        return Err("resume-state-mismatch".into());
    }
    if metadata.total_blocks != metadata.source.size.div_ceil(metadata.block_size)
        || metadata.total_blocks > u32::MAX as u64
    {
        return Err("resume-block-layout-invalid".into());
    }
    Ok(ResumePaths {
        source,
        destination_directory,
        final_path,
        part_path,
        resume_current,
        source_identity,
    })
}

fn validate_source_identity(
    expected: &SourceIdentity,
    actual: &SourceIdentity,
) -> Result<(), String> {
    if actual.size != expected.size {
        return Err("resume-source-size-mismatch".into());
    }
    if expected.modified_unix_ms.is_some() && actual.modified_unix_ms != expected.modified_unix_ms {
        return Err("resume-source-time-mismatch".into());
    }
    if expected.platform_file_id.is_some() && actual.platform_file_id != expected.platform_file_id {
        return Err("resume-source-identity-mismatch".into());
    }
    if let (Some(expected), Some(actual)) = (&expected.canonical_path, &actual.canonical_path) {
        if !paths_compatible(Path::new(expected), Path::new(actual)) {
            return Err("resume-source-replaced".into());
        }
    }
    Ok(())
}

fn paths_compatible(left: &Path, right: &Path) -> bool {
    if cfg!(windows) {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    } else {
        left == right
    }
}

struct ResumeExecutionResult {
    summary: NativeResumeFinalSummary,
}

async fn run_resumed_transfer(
    record: Arc<TransferRecord>,
    mut metadata: ResumeMetadata,
    paths: ResumePaths,
    verification_mode: ResumeVerificationMode,
    faults: NativeResumeFaults,
) -> Result<ResumeExecutionResult, String> {
    let started = Instant::now();
    validate_source_identity(
        &metadata.source,
        &resume::capture_source_identity(&paths.source).await?,
    )?;
    let source_hash = sha256_file(&paths.source, metadata.block_size as usize)
        .await?
        .0;
    if source_hash != metadata.expected_sha256 {
        return Err("resume-source-changed".into());
    }
    validate_destination_runtime(&metadata, &paths).await?;

    let authorization = super::authorization::material_for_transfer(&metadata.transfer_id)?;
    let checkpoint_key = super::secure_protocol::derive_checkpoint_key(
        &authorization.master,
        &metadata.transfer_id,
        &metadata.invitation_id,
    )?;
    metadata.verify_security(&checkpoint_key)?;
    let sidecar = block_hash::load_for_generation_authenticated(
        &paths.resume_current,
        &metadata.transfer_id,
        &metadata.invitation_id,
        metadata.checkpoint_generation,
        &metadata.part_identity_digest,
        &metadata.block_hash_sidecar_digest,
        &checkpoint_key,
    )
    .await;
    let mut hashes = vec![None; metadata.total_blocks as usize];
    if let Some(manifest) = sidecar.manifest {
        for entry in manifest.entries {
            hashes[entry.block_index as usize] = Some(entry.digest);
        }
    } else {
        return Err("checkpoint-authentication-failed".into());
    }
    apply_preverification_faults(&paths.part_path, &metadata, &mut hashes, &faults).await?;
    let (verification, repaired) = verify_completed_blocks(
        &record,
        &paths.part_path,
        &mut metadata,
        &mut hashes,
        verification_mode,
    )
    .await?;
    {
        let mut state = record.mutable.lock().await;
        state.completed_bitmap = metadata.completed_bitmap.clone();
        state.completed_blocks = metadata.completed_blocks();
        state.block_hashes = hashes;
        state.bytes_reused = metadata.completed_bytes;
        state.blocks_reused = metadata.completed_blocks();
        state.bytes_skipped = metadata.completed_bytes;
        state.blocks_skipped = metadata.completed_blocks();
        state.bytes_remaining = metadata.source.size - metadata.completed_bytes;
        state.blocks_remaining = metadata.total_blocks - metadata.completed_blocks();
        state.bytes_retransmitted = verification.bytes_invalidated;
        state.blocks_retransmitted = verification.blocks_invalid + verification.blocks_missing_hash;
        state.bytes_scheduled = state.bytes_remaining;
        state.blocks_scheduled = state.blocks_remaining;
        state.resume_verification_progress = 1.0;
        state.block_hash_sidecar_bytes = sidecar.encoded_size as u64;
    }
    if repaired {
        if faults.fail_resume_checkpoint.unwrap_or(false) {
            return Err("fault-injected-resume-checkpoint".into());
        }
        checkpoint_record(
            &record,
            &paths.source_identity,
            TransferState::RecoverableFailure,
        )
        .await?;
        metadata.checkpoint_generation = record.mutable.lock().await.checkpoint_generation;
        metadata.lifecycle_generation = record.mutable.lock().await.lifecycle.generation;
        metadata = resume::load_highest_valid_authenticated(
            &paths.resume_current,
            &checkpoint_key,
            &metadata.transfer_id,
            &metadata.invitation_id,
        )
        .await?
        .metadata;
    }
    let completed_bitmap = record.mutable.lock().await.completed_bitmap.clone();
    let missing_ranges = missing_block_ranges(&completed_bitmap, metadata.total_blocks)
        .map_err(|e| e.to_string())?;
    let missing_blocks = validate_missing_ranges(&missing_ranges, metadata.total_blocks)
        .map_err(|e| e.to_string())?;
    let bytes_remaining = bytes_for_ranges(
        &missing_ranges,
        metadata.block_size,
        metadata.source.size,
        metadata.total_blocks,
    )?;
    let checkpoint_generation = record.mutable.lock().await.checkpoint_generation;
    let session_id = record.mutable.lock().await.session_id.clone();
    let binding = ResumeBinding {
        version: NATIVE_QUIC_PROTOCOL_VERSION,
        transfer_id: metadata.transfer_id,
        session_id: session_id.clone(),
        checkpoint_generation,
        file_size: metadata.source.size,
        block_size: metadata.block_size,
        total_blocks: metadata.total_blocks,
        expected_sha256: metadata.expected_sha256,
        state_digest: metadata.secure_state_digest,
        capabilities: RESUME_REQUIRED_CAPABILITIES,
    };
    binding.validate().map_err(|e| e.to_string())?;
    let transport = execute_new_quinn_session(
        record.clone(),
        &paths,
        &metadata,
        binding,
        missing_ranges.clone(),
        faults,
    )
    .await?;
    let snapshot = record.snapshot().await;
    let summary = NativeResumeFinalSummary {
        event: "native-quic-resume-summary",
        transfer_id: record.transfer_id.clone(),
        session_id,
        state: snapshot.state,
        total_bytes: metadata.source.size,
        total_blocks: metadata.total_blocks,
        checkpoint_generation: snapshot.checkpoint_generation,
        verification_mode,
        verification,
        verified_completed_blocks: metadata.total_blocks - missing_blocks,
        missing_blocks,
        missing_range_count: missing_ranges.len() as u64,
        bytes_reusable: metadata.source.size - bytes_remaining,
        bytes_remaining,
        blocks_skipped: snapshot.blocks_skipped,
        bytes_skipped: snapshot.bytes_skipped,
        blocks_scheduled: snapshot.blocks_scheduled,
        bytes_scheduled: snapshot.bytes_scheduled,
        blocks_retransmitted: snapshot.blocks_retransmitted,
        bytes_retransmitted: snapshot.bytes_retransmitted,
        session_bytes_read: snapshot.session_bytes_read,
        session_bytes_sent: snapshot.session_bytes_sent,
        session_bytes_received: snapshot.session_bytes_received,
        session_bytes_written: snapshot.session_bytes_written,
        elapsed_seconds: started.elapsed().as_secs_f64(),
        final_sha256_passed: transport.final_sha256_passed,
        final_ack_received: transport.final_ack_received,
        new_quinn_session: true,
        block_hash_encoded_size: snapshot.block_hash_sidecar_bytes,
        secure_handshake_ms: transport.secure_handshake_ms,
        session_key_derivation_ms: transport.session_key_derivation_ms,
        secure_resume_negotiation_ms: transport.secure_resume_negotiation_ms,
        checkpoint_auth_ms: snapshot.last_checkpoint_auth_ms,
        security_key_material_bytes: 32 + (5 * 32),
        cleanup_warnings: snapshot.cleanup_warnings,
        error: None,
    };
    Ok(ResumeExecutionResult { summary })
}

async fn validate_destination_runtime(
    metadata: &ResumeMetadata,
    paths: &ResumePaths,
) -> Result<(), String> {
    if !fs::metadata(&paths.destination_directory)
        .await
        .map_err(|_| "resume-destination-missing")?
        .is_dir()
    {
        return Err("resume-destination-missing".into());
    }
    if fs::try_exists(&paths.final_path)
        .await
        .map_err(|_| "resume-destination-conflict")?
    {
        return Err("resume-destination-conflict".into());
    }
    let part = fs::metadata(&paths.part_path)
        .await
        .map_err(|_| "resume-part-missing")?;
    if !part.is_file() || part.len() != metadata.source.size {
        return Err("resume-part-size-mismatch".into());
    }
    Ok(())
}

async fn apply_preverification_faults(
    part_path: &Path,
    metadata: &ResumeMetadata,
    hashes: &mut [Option<[u8; 32]>],
    faults: &NativeResumeFaults,
) -> Result<(), String> {
    if let Some(block) = faults.corrupt_completed_block_index {
        if block >= metadata.total_blocks || !metadata.is_complete(block) {
            return Err("fault-block-index-not-completed".into());
        }
        let mut part = OpenOptions::new()
            .write(true)
            .open(part_path)
            .await
            .map_err(|e| e.to_string())?;
        part.seek(SeekFrom::Start(block * metadata.block_size))
            .await
            .map_err(|e| e.to_string())?;
        part.write_all(&[0xa5]).await.map_err(|e| e.to_string())?;
        part.flush().await.map_err(|e| e.to_string())?;
    }
    if let Some(block) = faults.delete_block_hash_index {
        if let Some(slot) = hashes.get_mut(block as usize) {
            *slot = None;
        }
    }
    if let Some(block) = faults.corrupt_block_hash_index {
        if let Some(Some(hash)) = hashes.get_mut(block as usize) {
            hash[0] ^= 0xff;
        }
    }
    Ok(())
}

async fn verify_completed_blocks(
    record: &Arc<TransferRecord>,
    part_path: &Path,
    metadata: &mut ResumeMetadata,
    hashes: &mut [Option<[u8; 32]>],
    mode: ResumeVerificationMode,
) -> Result<(VerificationReport, bool), String> {
    let started = Instant::now();
    let mut report = VerificationReport {
        blocks_marked_complete: metadata.completed_blocks(),
        ..Default::default()
    };
    let mut repaired = false;
    let mut part = File::open(part_path)
        .await
        .map_err(|_| "resume-part-missing")?;
    let sample_stride = metadata.total_blocks.div_ceil(64).max(1);
    let mut buffer = vec![0u8; metadata.block_size as usize];
    for block in 0..metadata.total_blocks {
        if !metadata.is_complete(block) {
            continue;
        }
        let length = resume::block_length(
            block,
            metadata.block_size,
            metadata.source.size,
            metadata.total_blocks,
        )?;
        let Some(expected_hash) = hashes[block as usize] else {
            metadata.clear_complete(block)?;
            report.blocks_missing_hash += 1;
            report.bytes_invalidated += length;
            repaired = true;
            continue;
        };
        let should_verify = match mode {
            ResumeVerificationMode::Full => true,
            ResumeVerificationMode::Sample => {
                block == 0 || block + 1 == metadata.total_blocks || block % sample_stride == 0
            }
            ResumeVerificationMode::MetadataOnly => false,
        };
        if should_verify {
            part.seek(SeekFrom::Start(block * metadata.block_size))
                .await
                .map_err(|e| e.to_string())?;
            part.read_exact(&mut buffer[..length as usize])
                .await
                .map_err(|_| "resume-part-size-mismatch")?;
            report.blocks_verified += 1;
            if <[u8; 32]>::from(Sha256::digest(&buffer[..length as usize])) != expected_hash {
                metadata.clear_complete(block)?;
                hashes[block as usize] = None;
                report.blocks_invalid += 1;
                report.bytes_invalidated += length;
                repaired = true;
                continue;
            }
        }
        report.blocks_valid += 1;
        report.bytes_reused += length;
        record.mutable.lock().await.resume_verification_progress =
            (block + 1) as f64 / metadata.total_blocks.max(1) as f64;
    }
    report.verification_duration_ms = started.elapsed().as_secs_f64() * 1000.0;
    Ok((report, repaired))
}

fn bytes_for_ranges(
    ranges: &[MissingBlockRange],
    block_size: u64,
    file_size: u64,
    total_blocks: u64,
) -> Result<u64, String> {
    let mut bytes = 0u64;
    for range in ranges {
        for block in range.start_block..range.start_block + range.block_count {
            bytes = bytes
                .checked_add(resume::block_length(
                    block,
                    block_size,
                    file_size,
                    total_blocks,
                )?)
                .ok_or("resume-block-layout-invalid")?;
        }
    }
    Ok(bytes)
}

#[derive(Debug)]
struct TransportResult {
    final_sha256_passed: bool,
    final_ack_received: bool,
    secure_handshake_ms: f64,
    session_key_derivation_ms: f64,
    secure_resume_negotiation_ms: f64,
}

#[allow(clippy::too_many_arguments)]
async fn execute_new_quinn_session(
    record: Arc<TransferRecord>,
    paths: &ResumePaths,
    metadata: &ResumeMetadata,
    binding: ResumeBinding,
    missing_ranges: Vec<MissingBlockRange>,
    faults: NativeResumeFaults,
) -> Result<TransportResult, String> {
    record.transition(TransferState::Connecting).await?;
    let config = NativeQuicConfig::desktop(4)?;
    if config.block_bytes as u64 != metadata.block_size {
        return Err("resume-block-layout-invalid".into());
    }
    let cancellation = record.cancellation_token().await;
    let identity = create_ephemeral_identity()?;
    let certificate_fingerprint = identity.fingerprint_sha256_bytes;
    let authorization = super::authorization::material_for_transfer(&metadata.transfer_id)?;
    if authorization.invitation.body.invitation_id != metadata.invitation_id {
        return Err("resume-authorization-failed".into());
    }
    let invitation_id = metadata.invitation_id;
    let session_id = super::secure_transport::parse_session_id(&binding.session_id)?;
    let transfer_commitment = super::secure_protocol::transfer_commitment(
        binding.file_size,
        &binding.expected_sha256,
        binding.block_size,
        binding.total_blocks,
        binding.capabilities,
    );
    let previous_session_digest =
        super::secure_protocol::session_lineage_digest(metadata.previous_session_id.as_ref());
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

    let receiver_record = record.clone();
    let receiver_binding = binding.clone();
    let receiver_ranges = missing_ranges.clone();
    let receiver_part = paths.part_path.clone();
    let receiver_final = paths.final_path.clone();
    let receiver_resume = paths.resume_current.clone();
    let receiver_cancellation = cancellation.clone();
    let receiver_faults = faults.clone();
    let receiver = tokio::spawn(async move {
        run_resume_receiver(
            server,
            receiver_record,
            receiver_part,
            receiver_final,
            receiver_resume,
            receiver_binding,
            receiver_ranges,
            receiver_cancellation,
            receiver_faults,
            invitation_id,
            session_id,
            certificate_fingerprint,
            transfer_commitment,
            previous_session_digest,
        )
        .await
    });

    let connection = client
        .connect(server_addr, "flowshare-native.local")
        .map_err(|e| e.to_string())?
        .await
        .map_err(|e| e.to_string())?;
    let (mut control_send, mut control_recv) =
        connection.open_bi().await.map_err(|e| e.to_string())?;
    let handshake_started = Instant::now();
    let prepared = super::authorization::prepare_client_handshake(
        metadata.transfer_id,
        session_id,
        super::secure_protocol::SecureSessionMode::Resume,
        binding.checkpoint_generation,
        binding.state_digest,
        transfer_commitment,
        previous_session_digest,
        certificate_fingerprint,
        binding.capabilities,
    )?;
    let mut security = super::secure_transport::authenticate_client(
        &connection,
        &mut control_send,
        &mut control_recv,
        prepared,
    )
    .await?;
    let session_key_derivation_ms = security.key_derivation_ms;
    let secure_handshake_ms = handshake_started.elapsed().as_secs_f64() * 1000.0;
    if faults.fail_resume_offer.unwrap_or(false) {
        connection.close(VarInt::from_u32(CLOSE_FAILURE), b"fault-resume-offer");
        let _ = receiver.await;
        return Err("fault-injected-resume-offer".into());
    }
    write_control(
        &mut control_send,
        &mut security.control,
        &ResumeControlMessage::Offer(ResumeOffer {
            binding: binding.clone(),
        }),
    )
    .await?;
    let state = match read_control(
        &mut control_recv,
        &mut security.control,
        super::secure_protocol::MESSAGE_RESUME_STATE,
    )
    .await?
    {
        ResumeControlMessage::State(state) => state,
        ResumeControlMessage::Reject(reject) => {
            return Err(format!("resume-rejected:{}", reject.code));
        }
        _ => return Err("resume-protocol-unexpected-message".into()),
    };
    state
        .binding
        .validate_matches(&binding)
        .map_err(|e| e.to_string())?;
    validate_missing_ranges(&state.missing_ranges, binding.total_blocks)
        .map_err(|e| e.to_string())?;
    if state.missing_ranges != missing_ranges {
        return Err("resume-missing-state-mismatch".into());
    }
    if faults.fail_resume_accept.unwrap_or(false) {
        connection.close(VarInt::from_u32(CLOSE_FAILURE), b"fault-resume-accept");
        let _ = receiver.await;
        return Err("fault-injected-resume-accept".into());
    }
    let missing_blocks = validate_missing_ranges(&missing_ranges, binding.total_blocks)
        .map_err(|e| e.to_string())?;
    let worker_count = if missing_blocks == 0 {
        0
    } else {
        4u8.min(missing_blocks as u8)
    };
    write_control(
        &mut control_send,
        &mut security.control,
        &ResumeControlMessage::Accept(ResumeAccept {
            binding: binding.clone(),
            missing_range_count: missing_ranges.len() as u64,
            stream_count: worker_count,
        }),
    )
    .await?;
    let secure_resume_negotiation_ms = handshake_started.elapsed().as_secs_f64() * 1000.0;
    record.transition(TransferState::Transferring).await?;

    let scheduler = Arc::new(StdMutex::new(MissingScheduler::new(&missing_ranges)));
    let mut send_tasks = Vec::new();
    for _ in 0..worker_count {
        let stream = connection.open_uni().await.map_err(|e| e.to_string())?;
        send_tasks.push(tokio::spawn(run_sender_worker(
            stream,
            paths.source.clone(),
            record.clone(),
            binding.clone(),
            scheduler.clone(),
            cancellation.clone(),
            faults.clone(),
        )));
    }
    let mut sender_error = None;
    for task in send_tasks {
        match task.await.map_err(|e| e.to_string())? {
            Ok(()) => {}
            Err(error) => {
                sender_error.get_or_insert(error);
            }
        }
    }
    if let Some(error) = sender_error {
        close_for_stop(&connection, record.stop_reason().await);
        let _ = receiver.await;
        return Err(error);
    }
    if cancellation.is_cancelled() {
        close_for_stop(&connection, record.stop_reason().await);
        let _ = receiver.await;
        return Err("native-file-transfer-cancelled".into());
    }
    let session = record.snapshot().await;
    write_control(
        &mut control_send,
        &mut security.control,
        &ResumeControlMessage::CompletionManifest(ResumeCompletionManifest {
            binding: binding.clone(),
            transferred_blocks: session.blocks_scheduled,
            transferred_bytes: session.session_bytes_sent,
            final_sha256: binding.expected_sha256,
        }),
    )
    .await?;
    let ack_result = read_control(
        &mut control_recv,
        &mut security.control,
        super::secure_protocol::MESSAGE_COMPLETION_ACK,
    )
    .await;
    let receiver_result = receiver.await.map_err(|e| e.to_string())?;
    receiver_result?;
    let ack = match ack_result? {
        ResumeControlMessage::CompletionAck(ack) => ack,
        ResumeControlMessage::Reject(reject) => {
            return Err(format!("resume-rejected:{}", reject.code));
        }
        _ => return Err("resume-protocol-unexpected-message".into()),
    };
    ack.binding
        .validate_matches(&binding)
        .map_err(|e| e.to_string())?;
    if !ack.integrity_ok
        || ack.final_sha256 != binding.expected_sha256
        || ack.complete_blocks != binding.total_blocks
    {
        return Err("resume-completion-ack-invalid".into());
    }
    control_send.finish().map_err(|e| e.to_string())?;
    connection.close(VarInt::from_u32(0), b"completed");
    client.wait_idle().await;
    Ok(TransportResult {
        final_sha256_passed: true,
        final_ack_received: true,
        secure_handshake_ms,
        session_key_derivation_ms,
        secure_resume_negotiation_ms,
    })
}

fn close_for_stop(connection: &quinn::Connection, reason: Option<StopReason>) {
    let (code, text): (u32, &[u8]) = match reason {
        Some(StopReason::Pause) => (CLOSE_PAUSE, b"pause"),
        Some(StopReason::CancelDelete | StopReason::CancelRetain) => (CLOSE_CANCEL, b"cancel"),
        Some(StopReason::Disconnect) => (CLOSE_DISCONNECT, b"disconnect"),
        None => (CLOSE_FAILURE, b"failure"),
    };
    connection.close(VarInt::from_u32(code), text);
}

struct MissingScheduler {
    ranges: VecDeque<(u64, u64)>,
}

impl MissingScheduler {
    fn new(ranges: &[MissingBlockRange]) -> Self {
        Self {
            ranges: ranges
                .iter()
                .map(|range| (range.start_block, range.start_block + range.block_count))
                .collect(),
        }
    }

    fn next(&mut self) -> Option<u64> {
        let (next, end) = self.ranges.front_mut()?;
        let block = *next;
        *next += 1;
        if *next == *end {
            self.ranges.pop_front();
        }
        Some(block)
    }
}

async fn run_sender_worker(
    mut stream: SendStream,
    source_path: PathBuf,
    record: Arc<TransferRecord>,
    binding: ResumeBinding,
    scheduler: Arc<StdMutex<MissingScheduler>>,
    cancellation: tokio_util::sync::CancellationToken,
    faults: NativeResumeFaults,
) -> Result<(), String> {
    {
        let mut state = record.mutable.lock().await;
        state.active_sender_streams += 1;
        state.active_readers += 1;
    }
    let result = async {
        let mut source = File::open(source_path)
            .await
            .map_err(|_| "resume-source-missing")?;
        let mut buffer = vec![0u8; binding.block_size as usize];
        loop {
            if cancellation.is_cancelled() {
                return Err("native-file-transfer-cancelled".into());
            }
            let block = scheduler
                .lock()
                .map_err(|_| "resume-scheduler-poisoned")?
                .next();
            let Some(block) = block else { break };
            let offset = block * binding.block_size;
            let length = (binding.file_size - offset).min(binding.block_size);
            source
                .seek(SeekFrom::Start(offset))
                .await
                .map_err(|e| e.to_string())?;
            source
                .read_exact(&mut buffer[..length as usize])
                .await
                .map_err(|_| "resume-source-short-read")?;
            {
                let mut state = record.mutable.lock().await;
                state.bytes_read += length;
                state.session_bytes_read += length;
            }
            stream.write_u8(1).await.map_err(|e| e.to_string())?;
            stream
                .write_all(
                    &RangeHeader {
                        transfer_id: binding.transfer_id,
                        range_id: block as u32,
                        offset,
                        length,
                        flags: 1,
                    }
                    .encode(),
                )
                .await
                .map_err(|e| e.to_string())?;
            stream
                .write_all(&buffer[..length as usize])
                .await
                .map_err(|e| e.to_string())?;
            let sent = {
                let mut state = record.mutable.lock().await;
                state.bytes_sent += length;
                state.session_bytes_sent += length;
                state.session_bytes_sent
            };
            if faults.fail_during_missing_range_transfer.unwrap_or(false)
                && sent >= binding.block_size
            {
                return Err("fault-injected-missing-range-transfer".into());
            }
        }
        stream.write_u8(0).await.map_err(|e| e.to_string())?;
        stream.finish().map_err(|e| e.to_string())?;
        Ok(())
    }
    .await;
    {
        let mut state = record.mutable.lock().await;
        state.active_sender_streams = state.active_sender_streams.saturating_sub(1);
        state.active_readers = state.active_readers.saturating_sub(1);
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn run_resume_receiver(
    server: Endpoint,
    record: Arc<TransferRecord>,
    part_path: PathBuf,
    final_path: PathBuf,
    resume_path: PathBuf,
    binding: ResumeBinding,
    missing_ranges: Vec<MissingBlockRange>,
    cancellation: tokio_util::sync::CancellationToken,
    faults: NativeResumeFaults,
    invitation_id: [u8; 16],
    session_id: [u8; 16],
    certificate_fingerprint: [u8; 32],
    transfer_commitment: [u8; 32],
    previous_session_digest: [u8; 32],
) -> Result<(), String> {
    let connection = server
        .accept()
        .await
        .ok_or("receiver-endpoint-closed")?
        .await
        .map_err(|e| e.to_string())?;
    let (mut control_send, mut control_recv) = super::secure_transport::accept_control_stream(
        &connection,
        binding.transfer_id,
        invitation_id,
        session_id,
        binding.checkpoint_generation,
    )
    .await?;
    let mut security = super::secure_transport::authenticate_server(
        &connection,
        &mut control_send,
        &mut control_recv,
        binding.transfer_id,
        invitation_id,
        session_id,
        certificate_fingerprint,
        super::secure_protocol::SecureSessionMode::Resume,
        binding.checkpoint_generation,
        binding.state_digest,
        transfer_commitment,
        previous_session_digest,
        binding.capabilities,
    )
    .await?;
    let offer = match read_control(
        &mut control_recv,
        &mut security.control,
        super::secure_protocol::MESSAGE_RESUME_OFFER,
    )
    .await?
    {
        ResumeControlMessage::Offer(offer) => offer,
        _ => return Err("resume-protocol-unexpected-message".into()),
    };
    offer
        .binding
        .validate_matches(&binding)
        .map_err(|e| e.to_string())?;
    write_control(
        &mut control_send,
        &mut security.control,
        &ResumeControlMessage::State(ResumeState {
            binding: binding.clone(),
            missing_ranges: missing_ranges.clone(),
        }),
    )
    .await?;
    let accept = match read_control(
        &mut control_recv,
        &mut security.control,
        super::secure_protocol::MESSAGE_RESUME_ACCEPT,
    )
    .await?
    {
        ResumeControlMessage::Accept(accept) => accept,
        _ => return Err("resume-protocol-unexpected-message".into()),
    };
    accept
        .binding
        .validate_matches(&binding)
        .map_err(|e| e.to_string())?;
    if accept.missing_range_count != missing_ranges.len() as u64
        || !matches!(accept.stream_count, 0..=4)
    {
        return Err("resume-accept-invalid".into());
    }
    let missing_blocks = validate_missing_ranges(&missing_ranges, binding.total_blocks)
        .map_err(|e| e.to_string())?;
    if (missing_blocks == 0) != (accept.stream_count == 0) {
        return Err("resume-accept-invalid".into());
    }

    let (free_tx, free_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(RECEIVER_BUFFER_COUNT);
    for _ in 0..RECEIVER_BUFFER_COUNT {
        free_tx
            .send(vec![0u8; binding.block_size as usize])
            .await
            .map_err(|_| "buffer-pool-init-failed")?;
    }
    let free_rx = Arc::new(tokio::sync::Mutex::new(free_rx));
    let claimed = Arc::new(tokio::sync::Mutex::new(vec![
        0u8;
        binding.total_blocks.div_ceil(8)
            as usize
    ]));
    let completed = record.mutable.lock().await.completed_bitmap.clone();
    let mut receiver_tasks = Vec::new();
    for _ in 0..accept.stream_count {
        let stream = connection.accept_uni().await.map_err(|e| e.to_string())?;
        receiver_tasks.push(tokio::spawn(run_receiver_stream(
            stream,
            part_path.clone(),
            record.clone(),
            binding.clone(),
            completed.clone(),
            claimed.clone(),
            free_rx.clone(),
            free_tx.clone(),
            cancellation.clone(),
            faults.clone(),
        )));
    }
    let mut receiver_error = None;
    for task in receiver_tasks {
        match task.await.map_err(|e| e.to_string())? {
            Ok(()) => {}
            Err(error) => {
                receiver_error.get_or_insert(error);
            }
        }
    }
    if let Some(error) = receiver_error {
        return Err(error);
    }
    if cancellation.is_cancelled() {
        return Err("native-file-transfer-cancelled".into());
    }
    let manifest = match read_control(
        &mut control_recv,
        &mut security.control,
        super::secure_protocol::MESSAGE_COMPLETION_MANIFEST,
    )
    .await?
    {
        ResumeControlMessage::CompletionManifest(manifest) => manifest,
        _ => return Err("resume-protocol-unexpected-message".into()),
    };
    manifest
        .binding
        .validate_matches(&binding)
        .map_err(|e| e.to_string())?;
    let snapshot = record.snapshot().await;
    if manifest.transferred_blocks != missing_blocks
        || manifest.transferred_bytes != snapshot.session_bytes_received
        || manifest.final_sha256 != binding.expected_sha256
    {
        return Err("resume-completion-manifest-invalid".into());
    }
    validate_exact_coverage(&record, &binding).await?;
    if snapshot.active_writers != 0
        || snapshot.active_receiver_streams != 0
        || snapshot.checked_out_buffers != 0
        || snapshot.queued_writes != 0
    {
        return Err("resume-resource-drain-incomplete".into());
    }
    record.transition(TransferState::Validating).await?;
    record.mutable.lock().await.finalization_owned = true;
    if faults.fail_before_final_hash.unwrap_or(false) {
        return Err("fault-injected-before-final-hash".into());
    }
    let actual_hash = sha256_file(&part_path, binding.block_size as usize)
        .await?
        .0;
    if actual_hash != binding.expected_sha256 {
        return Err("integrity-mismatch".into());
    }
    record.transition(TransferState::Synchronizing).await?;
    let part = OpenOptions::new()
        .write(true)
        .open(&part_path)
        .await
        .map_err(|e| e.to_string())?;
    part.sync_all().await.map_err(|e| e.to_string())?;
    drop(part);
    if cancellation.is_cancelled() {
        return Err("native-file-transfer-cancelled".into());
    }
    record.transition(TransferState::Finalizing).await?;
    if faults.fail_before_final_rename.unwrap_or(false) {
        return Err("fault-injected-before-final-rename".into());
    }
    fs::rename(&part_path, &final_path)
        .await
        .map_err(|e| format!("atomic-finalization-failed: {e}"))?;
    write_control(
        &mut control_send,
        &mut security.control,
        &ResumeControlMessage::CompletionAck(ResumeCompletionAck {
            binding: binding.clone(),
            complete_blocks: snapshot.total_blocks,
            received_bytes: snapshot.session_bytes_received,
            integrity_ok: true,
            final_sha256: actual_hash,
            cleanup_warnings: Vec::new(),
        }),
    )
    .await?;
    record.transition(TransferState::Completed).await?;
    let mut cleanup_warnings = Vec::new();
    if let Err(error) = resume::remove_generations(&resume_path).await {
        cleanup_warnings.push(error);
    }
    if let Err(error) = block_hash::remove_generations(&resume_path).await {
        cleanup_warnings.push(error);
    }
    if let Err(error) = super::secret_store::delete(&resume_path).await {
        cleanup_warnings.push(error);
    }
    if let Err(error) = super::authorization::consume(&binding.transfer_id) {
        cleanup_warnings.push(error);
    }
    {
        let mut state = record.mutable.lock().await;
        state.finalization_owned = false;
        state.resume_available = false;
        state.partial_retained = false;
        state.cleanup_warnings = cleanup_warnings;
    }
    control_send.finish().map_err(|e| e.to_string())?;
    // Keep the loopback endpoint alive until the peer can consume the final
    // completion ACK and stream FIN. Dropping the server immediately can make
    // Quinn report `ConnectionLost` even though rename already succeeded.
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_receiver_stream(
    mut stream: RecvStream,
    part_path: PathBuf,
    record: Arc<TransferRecord>,
    binding: ResumeBinding,
    completed: Vec<u8>,
    claimed: Arc<tokio::sync::Mutex<Vec<u8>>>,
    free_rx: Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
    free_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    cancellation: tokio_util::sync::CancellationToken,
    faults: NativeResumeFaults,
) -> Result<(), String> {
    record.mutable.lock().await.active_receiver_streams += 1;
    let (write_tx, mut write_rx) =
        tokio::sync::mpsc::channel::<(u64, u64, usize, Vec<u8>)>(WRITE_QUEUE_CAPACITY);
    let writer_record = record.clone();
    let writer_pool = free_tx.clone();
    let writer_cancellation = cancellation.clone();
    let writer_faults = faults.clone();
    let writer = tokio::spawn(async move {
        writer_record.mutable.lock().await.active_writers += 1;
        let result = async {
            let mut file = OpenOptions::new()
                .write(true)
                .open(part_path)
                .await
                .map_err(|e| e.to_string())?;
            while let Some((block, offset, valid, buffer)) = write_rx.recv().await {
                {
                    let mut state = writer_record.mutable.lock().await;
                    state.queued_writes = state.queued_writes.saturating_sub(1);
                }
                file.seek(SeekFrom::Start(offset))
                    .await
                    .map_err(|e| e.to_string())?;
                file.write_all(&buffer[..valid])
                    .await
                    .map_err(|e| format!("destination-write-failed: {e}"))?;
                let session_written = {
                    let mut state = writer_record.mutable.lock().await;
                    let byte = (block / 8) as usize;
                    let mask = 1u8 << (block % 8);
                    if state.completed_bitmap[byte] & mask != 0 {
                        return Err("resume-duplicate-completed-block".to_string());
                    }
                    state.completed_bitmap[byte] |= mask;
                    state.completed_blocks += 1;
                    state.block_hashes[block as usize] =
                        Some(Sha256::digest(&buffer[..valid]).into());
                    state.bytes_written += valid as u64;
                    state.session_bytes_written += valid as u64;
                    state.bytes_remaining = state.bytes_remaining.saturating_sub(valid as u64);
                    state.blocks_remaining = state.blocks_remaining.saturating_sub(1);
                    state.session_bytes_written
                };
                writer_pool
                    .send(buffer)
                    .await
                    .map_err(|_| "buffer-pool-return-failed".to_string())?;
                {
                    let mut state = writer_record.mutable.lock().await;
                    state.checked_out_buffers = state.checked_out_buffers.saturating_sub(1);
                }
                maybe_trigger_fault_stop(&writer_record, session_written, &writer_faults).await?;
                if writer_cancellation.is_cancelled() {
                    break;
                }
            }
            file.flush().await.map_err(|e| e.to_string())?;
            Ok::<(), String>(())
        }
        .await;
        {
            let mut state = writer_record.mutable.lock().await;
            state.active_writers = state.active_writers.saturating_sub(1);
        }
        result
    });
    let receive_result = async {
        loop {
            if cancellation.is_cancelled() {
                return Err("native-file-transfer-cancelled".into());
            }
            let marker = stream.read_u8().await.map_err(|e| e.to_string())?;
            if marker == 0 {
                break;
            }
            if marker != 1 {
                return Err("resume-data-frame-invalid".into());
            }
            let mut encoded = [0u8; RANGE_HEADER_BYTES];
            stream
                .read_exact(&mut encoded)
                .await
                .map_err(|e| e.to_string())?;
            let header = RangeHeader::decode(&encoded).map_err(|e| e.to_string())?;
            header
                .validate(&binding.transfer_id, binding.file_size)
                .map_err(|e| e.to_string())?;
            if header.flags != 1
                || header.offset % binding.block_size != 0
                || header.range_id as u64 != header.offset / binding.block_size
            {
                return Err("resume-data-block-invalid".into());
            }
            let block = header.range_id as u64;
            let expected_length = (binding.file_size - header.offset).min(binding.block_size);
            if header.length != expected_length
                || completed[(block / 8) as usize] & (1 << (block % 8)) != 0
            {
                return Err("resume-data-block-invalid".into());
            }
            {
                let mut claimed = claimed.lock().await;
                let byte = (block / 8) as usize;
                let mask = 1u8 << (block % 8);
                if claimed[byte] & mask != 0 {
                    return Err("resume-duplicate-block-ownership".into());
                }
                claimed[byte] |= mask;
            }
            let mut buffer = free_rx
                .lock()
                .await
                .recv()
                .await
                .ok_or("buffer-pool-exhausted")?;
            record.mutable.lock().await.checked_out_buffers += 1;
            stream
                .read_exact(&mut buffer[..header.length as usize])
                .await
                .map_err(|_| "resume-range-short-read")?;
            write_tx
                .send((block, header.offset, header.length as usize, buffer))
                .await
                .map_err(|_| "receiver-writer-stopped")?;
            {
                let mut state = record.mutable.lock().await;
                state.queued_writes += 1;
                state.bytes_received += header.length;
                state.session_bytes_received += header.length;
            }
        }
        Ok::<(), String>(())
    }
    .await;
    drop(write_tx);
    let writer_result = writer.await.map_err(|e| e.to_string())?;
    {
        let mut state = record.mutable.lock().await;
        state.active_receiver_streams = state.active_receiver_streams.saturating_sub(1);
    }
    receive_result?;
    writer_result
}

async fn maybe_trigger_fault_stop(
    record: &Arc<TransferRecord>,
    session_written: u64,
    faults: &NativeResumeFaults,
) -> Result<(), String> {
    let requested = if faults
        .pause_after_resumed_bytes
        .is_some_and(|threshold| session_written >= threshold)
    {
        Some(StopReason::Pause)
    } else if faults
        .cancel_after_resumed_bytes
        .is_some_and(|threshold| session_written >= threshold)
    {
        Some(StopReason::CancelDelete)
    } else if faults
        .disconnect_after_bytes
        .is_some_and(|threshold| session_written >= threshold)
    {
        Some(StopReason::Disconnect)
    } else {
        None
    };
    let Some(reason) = requested else {
        return Ok(());
    };
    let mut state = record.mutable.lock().await;
    if state.stop_reason.is_some() {
        return Ok(());
    }
    match reason {
        StopReason::Pause => state
            .lifecycle
            .transition(TransferState::Pausing, transfer_registry::now_ms())?,
        StopReason::CancelDelete | StopReason::CancelRetain => state
            .lifecycle
            .transition(TransferState::Cancelling, transfer_registry::now_ms())?,
        StopReason::Disconnect => {}
    }
    state.stop_reason = Some(reason);
    state.cancellation.cancel();
    Ok(())
}

async fn validate_exact_coverage(
    record: &Arc<TransferRecord>,
    binding: &ResumeBinding,
) -> Result<(), String> {
    let state = record.mutable.lock().await;
    if state.completed_blocks != binding.total_blocks {
        return Err("resume-coverage-incomplete".into());
    }
    let bytes = resume::completed_bytes_for_bitmap(
        &state.completed_bitmap,
        binding.total_blocks,
        binding.block_size,
        binding.file_size,
    )?;
    if bytes != binding.file_size {
        return Err("resume-coverage-incomplete".into());
    }
    for block in 0..binding.total_blocks {
        if state.completed_bitmap[(block / 8) as usize] & (1 << (block % 8)) == 0 {
            return Err("resume-coverage-incomplete".into());
        }
    }
    Ok(())
}

async fn write_control(
    stream: &mut SendStream,
    security: &mut super::secure_protocol::SecureControlChannel,
    message: &ResumeControlMessage,
) -> Result<(), String> {
    let payload = serde_json::to_vec(message).map_err(|e| e.to_string())?;
    if payload.len() > MAX_CONTROL_FRAME_BYTES {
        return Err("resume-control-frame-too-large".into());
    }
    let message_type = resume_control_message_type(message);
    let envelope = security.seal(message_type, &payload)?;
    stream
        .write_u32(envelope.len() as u32)
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(&envelope).await.map_err(|e| e.to_string())
}

fn resume_control_message_type(message: &ResumeControlMessage) -> u16 {
    match message {
        ResumeControlMessage::Offer(_) => super::secure_protocol::MESSAGE_RESUME_OFFER,
        ResumeControlMessage::State(_) => super::secure_protocol::MESSAGE_RESUME_STATE,
        ResumeControlMessage::Accept(_) => super::secure_protocol::MESSAGE_RESUME_ACCEPT,
        ResumeControlMessage::Reject(_) => super::secure_protocol::MESSAGE_RESUME_REJECT,
        ResumeControlMessage::CompletionManifest(_) => {
            super::secure_protocol::MESSAGE_COMPLETION_MANIFEST
        }
        ResumeControlMessage::CompletionAck(_) => super::secure_protocol::MESSAGE_COMPLETION_ACK,
    }
}

async fn read_control(
    stream: &mut RecvStream,
    security: &mut super::secure_protocol::SecureControlChannel,
    expected_message_type: u16,
) -> Result<ResumeControlMessage, String> {
    let length = stream.read_u32().await.map_err(|e| e.to_string())? as usize;
    if length > MAX_CONTROL_FRAME_BYTES {
        return Err("resume-control-frame-too-large".into());
    }
    let mut envelope = vec![0u8; length];
    stream
        .read_exact(&mut envelope)
        .await
        .map_err(|e| e.to_string())?;
    let payload = security.open(expected_message_type, &envelope)?;
    let message: ResumeControlMessage =
        serde_json::from_slice(&payload).map_err(|_| "authentication-failed")?;
    if resume_control_message_type(&message) != expected_message_type {
        return Err("authentication-failed".into());
    }
    Ok(message)
}

async fn finish_resumed_task(
    record: Arc<TransferRecord>,
    result: Result<ResumeExecutionResult, String>,
) {
    match result {
        Ok(result) => {
            println!(
                "[FlowShareNativeResume] {}",
                serde_json::to_string(&result.summary).unwrap_or_else(|_| {
                    "{\"event\":\"native-quic-resume-summary-encode-failed\"}".into()
                })
            );
        }
        Err(error) => {
            if error == "integrity-mismatch" {
                let mut state = record.mutable.lock().await;
                state.completed_bitmap.fill(0);
                state.block_hashes.fill(None);
                state.completed_blocks = 0;
                state.bytes_reused = 0;
                state.blocks_reused = 0;
                state.bytes_remaining = record.expected_file_size;
                state.blocks_remaining = record.total_blocks;
            }
            let snapshot = record.snapshot().await;
            if snapshot.state != TransferState::Completed {
                let reason = record.stop_reason().await;
                let target = match reason {
                    Some(StopReason::Pause) => TransferState::Paused,
                    Some(StopReason::CancelRetain) => TransferState::Cancelled,
                    Some(StopReason::CancelDelete) => TransferState::Cancelled,
                    Some(StopReason::Disconnect) => TransferState::PausedByDisconnect,
                    None => TransferState::RecoverableFailure,
                };
                let retain = !matches!(reason, Some(StopReason::CancelDelete));
                if retain {
                    let preserve_existing = reason.is_none()
                        && (error.starts_with("resume-source-")
                            || error.starts_with("resume-part-")
                            || error.starts_with("resume-destination-")
                            || error == "fault-injected-resume-checkpoint");
                    let checkpoint_result = if preserve_existing {
                        Ok(())
                    } else {
                        let identity = record.source_identity.clone();
                        if let Some(identity) = identity {
                            checkpoint_record(&record, &identity, target).await
                        } else {
                            Err("resume-source-missing".into())
                        }
                    };
                    if let Err(checkpoint_error) = checkpoint_result {
                        let mut state = record.mutable.lock().await;
                        state.terminal_error = Some(format!("{error}; {checkpoint_error}"));
                        let _ = state
                            .lifecycle
                            .transition(TransferState::Failed, transfer_registry::now_ms());
                    } else {
                        if let Ok(transfer_id) = uuid::Uuid::parse_str(&record.transfer_id) {
                            let _ = super::authorization::mark_resumable(transfer_id.as_bytes());
                        }
                        let _ = record.transition(target).await;
                    }
                } else {
                    let _ = transfer_registry::remove_if_present(&record.part_path).await;
                    let _ = resume::remove_generations(&record.resume_path).await;
                    let _ = block_hash::remove_generations(&record.resume_path).await;
                    let _ = super::secret_store::delete(&record.resume_path).await;
                    if let Ok(transfer_id) = uuid::Uuid::parse_str(&record.transfer_id) {
                        let _ = super::authorization::revoke(transfer_id.as_bytes());
                    }
                    let _ = record.transition(TransferState::Cancelled).await;
                    let mut state = record.mutable.lock().await;
                    state.partial_retained = false;
                    state.resume_available = false;
                }
                record.mutable.lock().await.terminal_error = Some(error.clone());
            }
            let snapshot = record.snapshot().await;
            let summary = NativeResumeFinalSummary {
                event: "native-quic-resume-summary",
                transfer_id: record.transfer_id.clone(),
                session_id: snapshot.session_id.clone(),
                state: snapshot.state,
                total_bytes: snapshot.expected_file_size,
                total_blocks: snapshot.total_blocks,
                checkpoint_generation: snapshot.checkpoint_generation,
                verification_mode: ResumeVerificationMode::Full,
                verification: VerificationReport::default(),
                verified_completed_blocks: snapshot.blocks_reused,
                missing_blocks: snapshot.blocks_remaining,
                missing_range_count: 0,
                bytes_reusable: snapshot.bytes_reused,
                bytes_remaining: snapshot.bytes_remaining,
                blocks_skipped: snapshot.blocks_skipped,
                bytes_skipped: snapshot.bytes_skipped,
                blocks_scheduled: snapshot.blocks_scheduled,
                bytes_scheduled: snapshot.bytes_scheduled,
                blocks_retransmitted: snapshot.blocks_retransmitted,
                bytes_retransmitted: snapshot.bytes_retransmitted,
                session_bytes_read: snapshot.session_bytes_read,
                session_bytes_sent: snapshot.session_bytes_sent,
                session_bytes_received: snapshot.session_bytes_received,
                session_bytes_written: snapshot.session_bytes_written,
                elapsed_seconds: 0.0,
                final_sha256_passed: false,
                final_ack_received: false,
                new_quinn_session: true,
                block_hash_encoded_size: snapshot.block_hash_sidecar_bytes,
                secure_handshake_ms: 0.0,
                session_key_derivation_ms: 0.0,
                secure_resume_negotiation_ms: 0.0,
                checkpoint_auth_ms: snapshot.last_checkpoint_auth_ms,
                security_key_material_bytes: 32 + (5 * 32),
                cleanup_warnings: snapshot.cleanup_warnings,
                error: Some(error),
            };
            println!(
                "[FlowShareNativeResume] {}",
                serde_json::to_string(&summary).unwrap_or_else(|_| {
                    "{\"event\":\"native-quic-resume-summary-encode-failed\"}".into()
                })
            );
        }
    }
    record.reset_terminal_resources().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        file_transfer::{run_file_loopback, NativeFileLoopbackRequest},
        transfer_registry::{
            flowshare_native_cancel_transfer, flowshare_native_get_transfer,
            flowshare_native_list_transfers, flowshare_native_pause_transfer,
            CancelTransferRequest, PauseTransferRequest, TransferIdRequest, TransferSnapshot,
        },
    };
    use std::time::Duration;
    use uuid::Uuid;

    struct PausedFixture {
        root: PathBuf,
        destination: PathBuf,
        source: PathBuf,
        paused: TransferSnapshot,
        original_session_id: String,
    }

    async fn write_pattern_file(path: &Path, bytes: u64) {
        let mut file = File::create(path).await.unwrap();
        let block_bytes = 2 * 1024 * 1024usize;
        let mut buffer = vec![0u8; block_bytes];
        let mut written = 0u64;
        let mut block = 0u64;
        while written < bytes {
            for (index, byte) in buffer.iter_mut().enumerate() {
                *byte = (block as u8)
                    .wrapping_mul(29)
                    .wrapping_add(index as u8)
                    .wrapping_add(7);
            }
            let count = (bytes - written).min(block_bytes as u64) as usize;
            file.write_all(&buffer[..count]).await.unwrap();
            written += count as u64;
            block += 1;
        }
        file.sync_all().await.unwrap();
    }

    async fn wait_for_snapshot<F>(root_marker: &str, predicate: F) -> TransferSnapshot
    where
        F: Fn(&TransferSnapshot) -> bool,
    {
        tokio::time::timeout(Duration::from_secs(120), async {
            loop {
                let snapshots = flowshare_native_list_transfers().await.unwrap();
                if let Some(snapshot) = snapshots
                    .into_iter()
                    .find(|value| value.destination_path.contains(root_marker) && predicate(value))
                {
                    return snapshot;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap()
    }

    async fn create_paused_fixture(bytes: u64, pause_after: u64, label: &str) -> PausedFixture {
        let root = std::env::temp_dir().join(format!("flowget-resume-{label}-{}", Uuid::new_v4()));
        let destination = root.join("destination");
        fs::create_dir_all(&destination).await.unwrap();
        let source = root.join("source.bin");
        write_pattern_file(&source, bytes).await;
        let marker = root.file_name().unwrap().to_string_lossy().into_owned();
        let transfer = tokio::spawn(run_file_loopback(NativeFileLoopbackRequest {
            source_path: Some(source.display().to_string()),
            source_mode: None,
            total_bytes: None,
            destination_directory: destination.display().to_string(),
            stream_count: Some(4),
            block_bytes: Some(2 * 1024 * 1024),
            overwrite: Some(false),
            retain_partial: Some(true),
            sync_mode: Some("all".into()),
            receiver_buffer_count: Some(16),
            write_queue_capacity: Some(4),
        }));
        let active = wait_for_snapshot(&marker, |value| {
            value.state == TransferState::Transferring && value.bytes_written >= pause_after
        })
        .await;
        let original_session_id = active.session_id.clone();
        flowshare_native_pause_transfer(PauseTransferRequest {
            transfer_id: active.transfer_id.clone(),
            expected_generation: Some(active.state_generation),
        })
        .await
        .unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(60), transfer)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        let paused = wait_for_snapshot(&marker, |value| value.state == TransferState::Paused).await;
        assert!(paused.bytes_written >= pause_after);
        assert!(paused.resume_available);
        assert!(paused.checkpoint_succeeded);
        assert_eq!(paused.active_readers, 0);
        assert_eq!(paused.active_writers, 0);
        assert_eq!(paused.active_sender_streams, 0);
        assert_eq!(paused.active_receiver_streams, 0);
        assert_eq!(paused.active_checkpoint_tasks, 0);
        assert_eq!(paused.checked_out_buffers, 0);
        assert_eq!(paused.queued_writes, 0);
        PausedFixture {
            root,
            destination,
            source,
            paused,
            original_session_id,
        }
    }

    async fn wait_for_transfer_state(
        transfer_id: &str,
        expected: TransferState,
    ) -> TransferSnapshot {
        tokio::time::timeout(Duration::from_secs(120), async {
            loop {
                let snapshot = flowshare_native_get_transfer(TransferIdRequest {
                    transfer_id: transfer_id.to_string(),
                })
                .await
                .unwrap();
                if snapshot.state == expected && !snapshot.runtime_active {
                    assert_eq!(snapshot.active_readers, 0);
                    assert_eq!(snapshot.active_writers, 0);
                    assert_eq!(snapshot.active_sender_streams, 0);
                    assert_eq!(snapshot.active_receiver_streams, 0);
                    assert_eq!(snapshot.active_checkpoint_tasks, 0);
                    assert_eq!(snapshot.checked_out_buffers, 0);
                    assert_eq!(snapshot.queued_writes, 0);
                    return snapshot;
                }
                if matches!(
                    snapshot.state,
                    TransferState::Failed | TransferState::RecoverableFailure
                ) && snapshot.state != expected
                {
                    panic!("resume failed: {snapshot:?}");
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap()
    }

    async fn wait_for_session_progress(transfer_id: &str, minimum_bytes: u64) -> TransferSnapshot {
        tokio::time::timeout(Duration::from_secs(120), async {
            loop {
                let snapshot = flowshare_native_get_transfer(TransferIdRequest {
                    transfer_id: transfer_id.to_string(),
                })
                .await
                .unwrap();
                if snapshot.state == TransferState::Transferring
                    && snapshot.session_bytes_written >= minimum_bytes
                {
                    return snapshot;
                }
                if matches!(
                    snapshot.state,
                    TransferState::Completed
                        | TransferState::Failed
                        | TransferState::RecoverableFailure
                ) {
                    panic!("transfer ended before requested progress: {snapshot:?}");
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn secure_operational_restart_resume_uses_new_session_and_skips_valid_blocks() {
        let fixture =
            create_paused_fixture(256 * 1024 * 1024, 64 * 1024 * 1024, "restart-basic").await;
        let transfer_id = fixture.paused.transfer_id.clone();
        let resume_path = fixture.paused.resume_path.clone();
        let checkpoint_generation = fixture.paused.checkpoint_generation;
        transfer_registry::remove_for_test(&transfer_id).await;
        let response = start_resume_transfer(NativeResumeTransferRequest {
            resume_metadata_path: resume_path.clone(),
            source_path: fixture.source.display().to_string(),
            destination_directory: fixture.destination.display().to_string(),
            expected_checkpoint_generation: checkpoint_generation,
            verification_mode: Some(ResumeVerificationMode::Full),
            faults: None,
        })
        .await
        .unwrap();
        assert_ne!(response.session_id, fixture.original_session_id);
        let simultaneous = start_resume_transfer(NativeResumeTransferRequest {
            resume_metadata_path: resume_path.clone(),
            source_path: fixture.source.display().to_string(),
            destination_directory: fixture.destination.display().to_string(),
            expected_checkpoint_generation: checkpoint_generation,
            verification_mode: Some(ResumeVerificationMode::Full),
            faults: None,
        })
        .await
        .unwrap_err();
        assert_eq!(simultaneous, "resume-already-active");
        let completed = wait_for_transfer_state(&transfer_id, TransferState::Completed).await;
        assert_eq!(completed.session_id, response.session_id);
        assert!(completed.blocks_skipped > 0);
        assert!(completed.bytes_skipped > 0);
        assert!(completed.session_bytes_sent < completed.expected_file_size);
        assert_eq!(completed.bytes_written, completed.expected_file_size);
        assert_eq!(completed.active_readers, 0);
        assert_eq!(completed.active_writers, 0);
        assert_eq!(completed.active_sender_streams, 0);
        assert_eq!(completed.active_receiver_streams, 0);
        assert_eq!(completed.active_checkpoint_tasks, 0);
        assert_eq!(completed.checked_out_buffers, 0);
        assert_eq!(completed.queued_writes, 0);
        let final_hash = sha256_file(Path::new(&completed.destination_path), 2 * 1024 * 1024)
            .await
            .unwrap()
            .0;
        let source_hash = sha256_file(&fixture.source, 2 * 1024 * 1024)
            .await
            .unwrap()
            .0;
        assert_eq!(final_hash, source_hash);
        let generations = resume::generation_paths(Path::new(&resume_path));
        assert!(!generations.current.exists());
        assert!(!generations.previous.exists());
        assert!(!generations.pending.exists());
        let block_generations = block_hash::block_generation_paths(Path::new(&resume_path));
        assert!(!block_generations.current.exists());
        assert!(!block_generations.previous.exists());
        assert!(!block_generations.pending.exists());
        let _ = fs::remove_dir_all(fixture.root).await;
    }

    async fn first_completed_block(resume_path: &str) -> u64 {
        let checkpoint = resume::read_checkpoint(Path::new(resume_path))
            .await
            .unwrap();
        (0..checkpoint.total_blocks)
            .find(|block| checkpoint.is_complete(*block))
            .expect("paused transfer must have a completed block")
    }

    async fn assert_final_matches_source(fixture: &PausedFixture, completed: &TransferSnapshot) {
        let final_hash = sha256_file(Path::new(&completed.destination_path), 2 * 1024 * 1024)
            .await
            .unwrap()
            .0;
        let source_hash = sha256_file(&fixture.source, 2 * 1024 * 1024)
            .await
            .unwrap()
            .0;
        assert_eq!(final_hash, source_hash);
    }

    #[tokio::test]
    async fn corrupted_completed_block_is_invalidated_and_retransmitted() {
        let fixture =
            create_paused_fixture(64 * 1024 * 1024, 16 * 1024 * 1024, "corrupt-block").await;
        let block = first_completed_block(&fixture.paused.resume_path).await;
        let transfer_id = fixture.paused.transfer_id.clone();
        transfer_registry::remove_for_test(&transfer_id).await;
        start_resume_transfer(NativeResumeTransferRequest {
            resume_metadata_path: fixture.paused.resume_path.clone(),
            source_path: fixture.source.display().to_string(),
            destination_directory: fixture.destination.display().to_string(),
            expected_checkpoint_generation: fixture.paused.checkpoint_generation,
            verification_mode: Some(ResumeVerificationMode::Full),
            faults: Some(NativeResumeFaults {
                corrupt_completed_block_index: Some(block),
                ..Default::default()
            }),
        })
        .await
        .unwrap();
        let completed = wait_for_transfer_state(&transfer_id, TransferState::Completed).await;
        assert!(completed.blocks_retransmitted >= 1);
        assert!(completed.bytes_retransmitted >= 2 * 1024 * 1024);
        assert!(completed.blocks_skipped > 0);
        assert_final_matches_source(&fixture, &completed).await;
        let _ = fs::remove_dir_all(fixture.root).await;
    }

    #[tokio::test]
    async fn missing_completed_block_hash_causes_conservative_retransmission() {
        let fixture =
            create_paused_fixture(64 * 1024 * 1024, 16 * 1024 * 1024, "missing-hash").await;
        let block = first_completed_block(&fixture.paused.resume_path).await;
        let transfer_id = fixture.paused.transfer_id.clone();
        transfer_registry::remove_for_test(&transfer_id).await;
        start_resume_transfer(NativeResumeTransferRequest {
            resume_metadata_path: fixture.paused.resume_path.clone(),
            source_path: fixture.source.display().to_string(),
            destination_directory: fixture.destination.display().to_string(),
            expected_checkpoint_generation: fixture.paused.checkpoint_generation,
            verification_mode: Some(ResumeVerificationMode::Full),
            faults: Some(NativeResumeFaults {
                delete_block_hash_index: Some(block),
                ..Default::default()
            }),
        })
        .await
        .unwrap();
        let completed = wait_for_transfer_state(&transfer_id, TransferState::Completed).await;
        assert!(completed.blocks_retransmitted >= 1);
        assert!(completed.bytes_retransmitted >= 2 * 1024 * 1024);
        assert_final_matches_source(&fixture, &completed).await;
        let _ = fs::remove_dir_all(fixture.root).await;
    }

    #[tokio::test]
    async fn multiple_pause_resume_cycles_increase_checkpoint_generation() {
        let fixture =
            create_paused_fixture(64 * 1024 * 1024, 16 * 1024 * 1024, "multi-cycle").await;
        let transfer_id = fixture.paused.transfer_id.clone();
        let first_generation = fixture.paused.checkpoint_generation;
        transfer_registry::remove_for_test(&transfer_id).await;
        let first_resume = start_resume_transfer(NativeResumeTransferRequest {
            resume_metadata_path: fixture.paused.resume_path.clone(),
            source_path: fixture.source.display().to_string(),
            destination_directory: fixture.destination.display().to_string(),
            expected_checkpoint_generation: first_generation,
            verification_mode: Some(ResumeVerificationMode::Full),
            faults: None,
        })
        .await
        .unwrap();
        let active = wait_for_session_progress(&transfer_id, 8 * 1024 * 1024).await;
        flowshare_native_pause_transfer(PauseTransferRequest {
            transfer_id: transfer_id.clone(),
            expected_generation: Some(active.state_generation),
        })
        .await
        .unwrap();
        let paused_again = wait_for_transfer_state(&transfer_id, TransferState::Paused).await;
        assert!(paused_again.checkpoint_generation > first_generation);
        assert!(paused_again.session_bytes_written >= 8 * 1024 * 1024);
        let stale = start_resume_transfer(NativeResumeTransferRequest {
            resume_metadata_path: fixture.paused.resume_path.clone(),
            source_path: fixture.source.display().to_string(),
            destination_directory: fixture.destination.display().to_string(),
            expected_checkpoint_generation: first_generation,
            verification_mode: Some(ResumeVerificationMode::Full),
            faults: None,
        })
        .await
        .unwrap_err();
        assert_eq!(stale, "resume-stale-generation");
        let second_resume = start_resume_transfer(NativeResumeTransferRequest {
            resume_metadata_path: fixture.paused.resume_path.clone(),
            source_path: fixture.source.display().to_string(),
            destination_directory: fixture.destination.display().to_string(),
            expected_checkpoint_generation: paused_again.checkpoint_generation,
            verification_mode: Some(ResumeVerificationMode::Full),
            faults: None,
        })
        .await
        .unwrap();
        assert_ne!(first_resume.session_id, second_resume.session_id);
        let completed = wait_for_transfer_state(&transfer_id, TransferState::Completed).await;
        assert!(completed.blocks_skipped > paused_again.blocks_skipped);
        assert_final_matches_source(&fixture, &completed).await;
        let _ = fs::remove_dir_all(fixture.root).await;
    }

    #[tokio::test]
    async fn retained_cancellation_checkpoints_and_resumes_to_completion() {
        let fixture =
            create_paused_fixture(96 * 1024 * 1024, 16 * 1024 * 1024, "retained-cancel").await;
        let transfer_id = fixture.paused.transfer_id.clone();
        let initial_generation = fixture.paused.checkpoint_generation;
        transfer_registry::remove_for_test(&transfer_id).await;
        start_resume_transfer(NativeResumeTransferRequest {
            resume_metadata_path: fixture.paused.resume_path.clone(),
            source_path: fixture.source.display().to_string(),
            destination_directory: fixture.destination.display().to_string(),
            expected_checkpoint_generation: initial_generation,
            verification_mode: Some(ResumeVerificationMode::Full),
            faults: None,
        })
        .await
        .unwrap();
        let active = wait_for_session_progress(&transfer_id, 8 * 1024 * 1024).await;
        let stale = flowshare_native_cancel_transfer(CancelTransferRequest {
            transfer_id: transfer_id.clone(),
            retain_partial: Some(true),
            expected_generation: Some(active.state_generation.saturating_sub(1)),
        })
        .await
        .unwrap_err();
        assert_eq!(stale, "native-transfer-stale-generation");
        flowshare_native_cancel_transfer(CancelTransferRequest {
            transfer_id: transfer_id.clone(),
            retain_partial: Some(true),
            expected_generation: Some(active.state_generation),
        })
        .await
        .unwrap();
        let cancelled = wait_for_transfer_state(&transfer_id, TransferState::Cancelled).await;
        assert!(cancelled.partial_retained);
        assert!(cancelled.checkpoint_succeeded);
        assert!(cancelled.resume_available);
        assert!(cancelled.checkpoint_generation > initial_generation);
        assert!(Path::new(&cancelled.part_path).exists());
        assert!(Path::new(&cancelled.resume_path).exists());
        transfer_registry::remove_for_test(&transfer_id).await;
        start_resume_transfer(NativeResumeTransferRequest {
            resume_metadata_path: cancelled.resume_path.clone(),
            source_path: fixture.source.display().to_string(),
            destination_directory: fixture.destination.display().to_string(),
            expected_checkpoint_generation: cancelled.checkpoint_generation,
            verification_mode: Some(ResumeVerificationMode::Full),
            faults: None,
        })
        .await
        .unwrap();
        let completed = wait_for_transfer_state(&transfer_id, TransferState::Completed).await;
        assert_final_matches_source(&fixture, &completed).await;
        let _ = fs::remove_dir_all(fixture.root).await;
    }

    #[tokio::test]
    async fn unexpected_disconnect_checkpoints_and_resumes_with_another_new_session() {
        let fixture = create_paused_fixture(96 * 1024 * 1024, 16 * 1024 * 1024, "disconnect").await;
        let transfer_id = fixture.paused.transfer_id.clone();
        let initial_generation = fixture.paused.checkpoint_generation;
        transfer_registry::remove_for_test(&transfer_id).await;
        let first_resume = start_resume_transfer(NativeResumeTransferRequest {
            resume_metadata_path: fixture.paused.resume_path.clone(),
            source_path: fixture.source.display().to_string(),
            destination_directory: fixture.destination.display().to_string(),
            expected_checkpoint_generation: initial_generation,
            verification_mode: Some(ResumeVerificationMode::Full),
            faults: None,
        })
        .await
        .unwrap();
        let _active = wait_for_session_progress(&transfer_id, 8 * 1024 * 1024).await;
        let record = transfer_registry::lookup(&transfer_id).await.unwrap();
        transfer_registry::request_disconnect(&record)
            .await
            .unwrap();
        let disconnected =
            wait_for_transfer_state(&transfer_id, TransferState::PausedByDisconnect).await;
        assert!(disconnected.resume_available);
        assert!(disconnected.checkpoint_succeeded);
        assert!(disconnected.checkpoint_generation > initial_generation);
        let second_resume = start_resume_transfer(NativeResumeTransferRequest {
            resume_metadata_path: disconnected.resume_path.clone(),
            source_path: fixture.source.display().to_string(),
            destination_directory: fixture.destination.display().to_string(),
            expected_checkpoint_generation: disconnected.checkpoint_generation,
            verification_mode: Some(ResumeVerificationMode::Full),
            faults: None,
        })
        .await
        .unwrap();
        assert_ne!(first_resume.session_id, second_resume.session_id);
        let completed = wait_for_transfer_state(&transfer_id, TransferState::Completed).await;
        assert_final_matches_source(&fixture, &completed).await;
        let _ = fs::remove_dir_all(fixture.root).await;
    }

    #[tokio::test]
    async fn resume_preflight_rejects_stale_changed_missing_and_unsupported_inputs() {
        let fixture = create_paused_fixture(64 * 1024 * 1024, 16 * 1024 * 1024, "rejections").await;
        let base_request = || NativeResumeTransferRequest {
            resume_metadata_path: fixture.paused.resume_path.clone(),
            source_path: fixture.source.display().to_string(),
            destination_directory: fixture.destination.display().to_string(),
            expected_checkpoint_generation: fixture.paused.checkpoint_generation,
            verification_mode: Some(ResumeVerificationMode::Full),
            faults: None,
        };
        let mut stale = base_request();
        stale.expected_checkpoint_generation += 1;
        assert_eq!(
            start_resume_transfer(stale).await.unwrap_err(),
            "resume-stale-generation"
        );

        let replacement = fixture.root.join("replacement.bin");
        write_pattern_file(&replacement, fixture.paused.expected_file_size).await;
        let mut wrong_source = base_request();
        wrong_source.source_path = replacement.display().to_string();
        assert!(matches!(
            start_resume_transfer(wrong_source)
                .await
                .unwrap_err()
                .as_str(),
            "resume-source-time-mismatch"
                | "resume-source-identity-mismatch"
                | "resume-source-replaced"
        ));

        let part = PathBuf::from(&fixture.paused.part_path);
        let part_backup = part.with_extension("part.test-backup");
        fs::rename(&part, &part_backup).await.unwrap();
        assert_eq!(
            start_resume_transfer(base_request()).await.unwrap_err(),
            "resume-part-missing"
        );
        fs::rename(&part_backup, &part).await.unwrap();
        fs::rename(&part, &part_backup).await.unwrap();
        let replacement_part = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&part)
            .await
            .unwrap();
        replacement_part
            .set_len(fixture.paused.expected_file_size)
            .await
            .unwrap();
        drop(replacement_part);
        assert_eq!(
            start_resume_transfer(base_request()).await.unwrap_err(),
            "resume-state-mismatch"
        );
        fs::remove_file(&part).await.unwrap();
        fs::rename(&part_backup, &part).await.unwrap();
        let part_file = OpenOptions::new().write(true).open(&part).await.unwrap();
        part_file
            .set_len(fixture.paused.expected_file_size - 1)
            .await
            .unwrap();
        assert_eq!(
            start_resume_transfer(base_request()).await.unwrap_err(),
            "resume-part-size-mismatch"
        );
        part_file
            .set_len(fixture.paused.expected_file_size)
            .await
            .unwrap();
        drop(part_file);

        let checkpoint_path = PathBuf::from(&fixture.paused.resume_path);
        let original = fs::read(&checkpoint_path).await.unwrap();
        fs::write(&checkpoint_path, b"corrupt-checkpoint")
            .await
            .unwrap();
        assert_eq!(
            start_resume_transfer(base_request()).await.unwrap_err(),
            "resume-checkpoint-invalid"
        );
        fs::write(&checkpoint_path, &original).await.unwrap();

        let mut unsupported = resume::read_checkpoint(&checkpoint_path).await.unwrap();
        unsupported.protocol_version = u16::MAX;
        let unsupported_bytes = resume::encode_framed(
            &resume::RESUME_MAGIC,
            &unsupported,
            "resume-metadata-too-large",
        )
        .unwrap();
        fs::write(&checkpoint_path, unsupported_bytes)
            .await
            .unwrap();
        assert_eq!(
            start_resume_transfer(base_request()).await.unwrap_err(),
            "resume-protocol-version-unsupported"
        );
        fs::write(&checkpoint_path, original).await.unwrap();
        let _ = fs::remove_dir_all(fixture.root).await;
    }

    #[tokio::test]
    async fn completed_registry_record_rejects_stale_resume_artifacts() {
        let root = std::env::temp_dir().join(format!("flowget-completed-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).await.unwrap();
        let resume_path = root.join("completed.resume.current");
        let record = transfer_registry::register(transfer_registry::NewTransferRecord {
            transfer_id: Uuid::new_v4().to_string(),
            source_path: Some(root.join("source")),
            source_identity: None,
            destination_path: root.join("final"),
            part_path: root.join("part"),
            resume_path: resume_path.clone(),
            expected_file_size: 1,
            block_size: 1,
            retain_partial: true,
        })
        .await
        .unwrap();
        for state in [
            TransferState::Preparing,
            TransferState::Connecting,
            TransferState::Transferring,
            TransferState::Validating,
            TransferState::Synchronizing,
            TransferState::Finalizing,
            TransferState::Completed,
        ] {
            record.transition(state).await.unwrap();
        }
        record.reset_terminal_resources().await;
        let error = start_resume_transfer(NativeResumeTransferRequest {
            resume_metadata_path: resume_path.display().to_string(),
            source_path: root.join("source").display().to_string(),
            destination_directory: root.display().to_string(),
            expected_checkpoint_generation: 1,
            verification_mode: None,
            faults: None,
        })
        .await
        .unwrap_err();
        assert_eq!(error, "resume-transfer-completed");
        let _ = fs::remove_dir_all(root).await;
    }
}
