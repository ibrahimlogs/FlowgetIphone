use super::{
    lifecycle::{Lifecycle, TransferState},
    resume::ResumeMetadata,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{sync::Mutex, task::AbortHandle};
use tokio_util::sync::CancellationToken;

static REGISTRY: LazyLock<Mutex<HashMap<String, Arc<TransferRecord>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    Pause,
    CancelDelete,
    CancelRetain,
    Disconnect,
}

#[derive(Debug)]
pub struct TransferRecord {
    pub transfer_id: String,
    pub share_id: Option<String>,
    pub source_path: Option<PathBuf>,
    pub source_identity: Option<super::resume::SourceIdentity>,
    pub destination_path: PathBuf,
    pub part_path: PathBuf,
    pub resume_path: PathBuf,
    pub expected_file_size: u64,
    pub block_size: u64,
    pub total_blocks: u64,
    pub retain_partial: bool,
    pub created_unix_ms: u64,
    pub mutable: Mutex<TransferMutable>,
}

#[derive(Debug)]
pub struct TransferMutable {
    pub session_id: String,
    pub lifecycle: Lifecycle,
    pub cancellation: CancellationToken,
    pub stop_reason: Option<StopReason>,
    pub runtime_active: bool,
    pub resume_owned: bool,
    pub finalization_owned: bool,
    pub cleanup_in_progress: bool,
    pub task_abort: Option<AbortHandle>,
    pub bytes_read: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub bytes_written: u64,
    pub session_bytes_read: u64,
    pub session_bytes_sent: u64,
    pub session_bytes_received: u64,
    pub session_bytes_written: u64,
    pub bytes_reused: u64,
    pub blocks_reused: u64,
    pub bytes_remaining: u64,
    pub blocks_remaining: u64,
    pub bytes_skipped: u64,
    pub blocks_skipped: u64,
    pub bytes_scheduled: u64,
    pub blocks_scheduled: u64,
    pub bytes_retransmitted: u64,
    pub blocks_retransmitted: u64,
    pub resume_verification_progress: f64,
    pub completed_blocks: u64,
    pub active_readers: u32,
    pub active_writers: u32,
    pub active_sender_streams: u32,
    pub active_receiver_streams: u32,
    pub active_checkpoint_tasks: u32,
    pub checked_out_buffers: u32,
    pub queued_writes: u32,
    pub checkpoint_generation: u64,
    pub last_checkpoint_unix_ms: Option<u64>,
    pub terminal_error: Option<String>,
    pub completed_bitmap: Vec<u8>,
    pub block_hashes: Vec<Option<[u8; 32]>>,
    pub expected_sha256: Option<[u8; 32]>,
    pub partial_retained: bool,
    pub checkpoint_succeeded: bool,
    pub resume_available: bool,
    pub block_hash_sidecar_bytes: u64,
    pub last_checkpoint_auth_ms: f64,
    pub cleanup_warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct NewTransferRecord {
    pub transfer_id: String,
    pub source_path: Option<PathBuf>,
    pub source_identity: Option<super::resume::SourceIdentity>,
    pub destination_path: PathBuf,
    pub part_path: PathBuf,
    pub resume_path: PathBuf,
    pub expected_file_size: u64,
    pub block_size: u64,
    pub retain_partial: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferSnapshot {
    pub transfer_id: String,
    pub share_id: Option<String>,
    pub session_id: String,
    pub state: TransferState,
    pub state_generation: u64,
    pub source_path: Option<String>,
    pub destination_path: String,
    pub part_path: String,
    pub resume_path: String,
    pub expected_file_size: u64,
    pub block_size: u64,
    pub total_blocks: u64,
    pub retain_partial: bool,
    pub runtime_active: bool,
    pub resume_owned: bool,
    pub finalization_owned: bool,
    pub cleanup_in_progress: bool,
    pub bytes_read: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub bytes_written: u64,
    pub session_bytes_read: u64,
    pub session_bytes_sent: u64,
    pub session_bytes_received: u64,
    pub session_bytes_written: u64,
    pub bytes_reused: u64,
    pub blocks_reused: u64,
    pub bytes_remaining: u64,
    pub blocks_remaining: u64,
    pub bytes_skipped: u64,
    pub blocks_skipped: u64,
    pub bytes_scheduled: u64,
    pub blocks_scheduled: u64,
    pub bytes_retransmitted: u64,
    pub blocks_retransmitted: u64,
    pub resume_verification_progress: f64,
    pub completed_blocks: u64,
    pub active_readers: u32,
    pub active_writers: u32,
    pub active_sender_streams: u32,
    pub active_receiver_streams: u32,
    pub active_checkpoint_tasks: u32,
    pub checked_out_buffers: u32,
    pub queued_writes: u32,
    pub checkpoint_generation: u64,
    pub terminal_error: Option<String>,
    pub partial_retained: bool,
    pub checkpoint_succeeded: bool,
    pub resume_available: bool,
    pub block_hash_sidecar_bytes: u64,
    pub last_checkpoint_auth_ms: f64,
    pub cleanup_warnings: Vec<String>,
}

impl TransferRecord {
    pub async fn snapshot(&self) -> TransferSnapshot {
        let value = self.mutable.lock().await;
        TransferSnapshot {
            transfer_id: self.transfer_id.clone(),
            share_id: self.share_id.clone(),
            session_id: value.session_id.clone(),
            state: value.lifecycle.state,
            state_generation: value.lifecycle.generation,
            source_path: self.source_path.as_ref().map(|v| v.display().to_string()),
            destination_path: self.destination_path.display().to_string(),
            part_path: self.part_path.display().to_string(),
            resume_path: self.resume_path.display().to_string(),
            expected_file_size: self.expected_file_size,
            block_size: self.block_size,
            total_blocks: self.total_blocks,
            retain_partial: self.retain_partial,
            runtime_active: value.runtime_active,
            resume_owned: value.resume_owned,
            finalization_owned: value.finalization_owned,
            cleanup_in_progress: value.cleanup_in_progress,
            bytes_read: value.bytes_read,
            bytes_sent: value.bytes_sent,
            bytes_received: value.bytes_received,
            bytes_written: value.bytes_written,
            session_bytes_read: value.session_bytes_read,
            session_bytes_sent: value.session_bytes_sent,
            session_bytes_received: value.session_bytes_received,
            session_bytes_written: value.session_bytes_written,
            bytes_reused: value.bytes_reused,
            blocks_reused: value.blocks_reused,
            bytes_remaining: value.bytes_remaining,
            blocks_remaining: value.blocks_remaining,
            bytes_skipped: value.bytes_skipped,
            blocks_skipped: value.blocks_skipped,
            bytes_scheduled: value.bytes_scheduled,
            blocks_scheduled: value.blocks_scheduled,
            bytes_retransmitted: value.bytes_retransmitted,
            blocks_retransmitted: value.blocks_retransmitted,
            resume_verification_progress: value.resume_verification_progress,
            completed_blocks: value.completed_blocks,
            active_readers: value.active_readers,
            active_writers: value.active_writers,
            active_sender_streams: value.active_sender_streams,
            active_receiver_streams: value.active_receiver_streams,
            active_checkpoint_tasks: value.active_checkpoint_tasks,
            checked_out_buffers: value.checked_out_buffers,
            queued_writes: value.queued_writes,
            checkpoint_generation: value.checkpoint_generation,
            terminal_error: value.terminal_error.clone(),
            partial_retained: value.partial_retained,
            checkpoint_succeeded: value.checkpoint_succeeded,
            resume_available: value.resume_available,
            block_hash_sidecar_bytes: value.block_hash_sidecar_bytes,
            last_checkpoint_auth_ms: value.last_checkpoint_auth_ms,
            cleanup_warnings: value.cleanup_warnings.clone(),
        }
    }

    pub async fn transition(&self, next: TransferState) -> Result<(), String> {
        self.mutable
            .lock()
            .await
            .lifecycle
            .transition(next, now_ms())
    }

    pub async fn cancellation_token(&self) -> CancellationToken {
        self.mutable.lock().await.cancellation.clone()
    }

    pub async fn stop_reason(&self) -> Option<StopReason> {
        self.mutable.lock().await.stop_reason
    }

    pub async fn reset_terminal_resources(&self) {
        let mut value = self.mutable.lock().await;
        value.active_readers = 0;
        value.active_writers = 0;
        value.active_sender_streams = 0;
        value.active_receiver_streams = 0;
        value.active_checkpoint_tasks = 0;
        value.checked_out_buffers = 0;
        value.queued_writes = 0;
        value.runtime_active = false;
        value.resume_owned = false;
        value.finalization_owned = false;
        value.task_abort = None;
    }
}

fn fresh_mutable(total_blocks: u64) -> TransferMutable {
    TransferMutable {
        session_id: uuid::Uuid::new_v4().to_string(),
        lifecycle: Lifecycle::new(now_ms()),
        cancellation: CancellationToken::new(),
        stop_reason: None,
        runtime_active: true,
        resume_owned: false,
        finalization_owned: false,
        cleanup_in_progress: false,
        task_abort: None,
        bytes_read: 0,
        bytes_sent: 0,
        bytes_received: 0,
        bytes_written: 0,
        session_bytes_read: 0,
        session_bytes_sent: 0,
        session_bytes_received: 0,
        session_bytes_written: 0,
        bytes_reused: 0,
        blocks_reused: 0,
        bytes_remaining: 0,
        blocks_remaining: 0,
        bytes_skipped: 0,
        blocks_skipped: 0,
        bytes_scheduled: 0,
        blocks_scheduled: 0,
        bytes_retransmitted: 0,
        blocks_retransmitted: 0,
        resume_verification_progress: 0.0,
        completed_blocks: 0,
        active_readers: 0,
        active_writers: 0,
        active_sender_streams: 0,
        active_receiver_streams: 0,
        active_checkpoint_tasks: 0,
        checked_out_buffers: 0,
        queued_writes: 0,
        checkpoint_generation: 0,
        last_checkpoint_unix_ms: None,
        terminal_error: None,
        completed_bitmap: vec![0; total_blocks.div_ceil(8) as usize],
        block_hashes: vec![None; total_blocks as usize],
        expected_sha256: None,
        partial_retained: false,
        checkpoint_succeeded: false,
        resume_available: false,
        block_hash_sidecar_bytes: 0,
        last_checkpoint_auth_ms: 0.0,
        cleanup_warnings: Vec::new(),
    }
}

pub async fn register(input: NewTransferRecord) -> Result<Arc<TransferRecord>, String> {
    if input.block_size == 0 {
        return Err("native-transfer-block-size-invalid".into());
    }
    let mut registry = REGISTRY.lock().await;
    if registry.contains_key(&input.transfer_id) {
        return Err("native-transfer-id-already-active".into());
    }
    let total_blocks = input.expected_file_size.div_ceil(input.block_size);
    let record = Arc::new(TransferRecord {
        transfer_id: input.transfer_id.clone(),
        share_id: None,
        source_path: input.source_path,
        source_identity: input.source_identity,
        destination_path: input.destination_path,
        part_path: input.part_path,
        resume_path: input.resume_path,
        expected_file_size: input.expected_file_size,
        block_size: input.block_size,
        total_blocks,
        retain_partial: input.retain_partial,
        created_unix_ms: now_ms(),
        mutable: Mutex::new(fresh_mutable(total_blocks)),
    });
    registry.insert(input.transfer_id, record.clone());
    Ok(record)
}

pub struct ResumeClaim {
    pub record: Arc<TransferRecord>,
    pub session_id: String,
}

pub async fn claim_resume(
    metadata: &ResumeMetadata,
    source_path: PathBuf,
    destination_path: PathBuf,
    part_path: PathBuf,
    resume_path: PathBuf,
) -> Result<ResumeClaim, String> {
    let transfer_id = uuid::Uuid::from_bytes(metadata.transfer_id).to_string();
    let mut registry = REGISTRY.lock().await;
    let record = if let Some(record) = registry.get(&transfer_id).cloned() {
        if record.source_path.as_deref() != Some(source_path.as_path())
            || record.source_identity.as_ref() != Some(&metadata.source)
            || record.destination_path != destination_path
            || record.part_path != part_path
            || record.expected_file_size != metadata.source.size
            || record.block_size != metadata.block_size
        {
            return Err("resume-checkpoint-invalid".into());
        }
        record
    } else {
        let total_blocks = metadata.total_blocks;
        let mut mutable = fresh_mutable(total_blocks);
        mutable.runtime_active = false;
        mutable.lifecycle = Lifecycle {
            state: metadata.checkpoint_state,
            generation: metadata.lifecycle_generation,
            last_state_change_unix_ms: metadata.checkpoint_unix_ms,
        };
        mutable.checkpoint_generation = metadata.checkpoint_generation;
        mutable.last_checkpoint_auth_ms = metadata.checkpoint_auth_micros as f64 / 1000.0;
        mutable.completed_bitmap = metadata.completed_bitmap.clone();
        mutable.completed_blocks = metadata.completed_blocks();
        mutable.bytes_written = metadata.completed_bytes;
        mutable.expected_sha256 = Some(metadata.expected_sha256);
        mutable.resume_available = true;
        mutable.partial_retained = true;
        let record = Arc::new(TransferRecord {
            transfer_id: transfer_id.clone(),
            share_id: metadata.share_id.clone(),
            source_path: Some(source_path),
            source_identity: Some(metadata.source.clone()),
            destination_path,
            part_path,
            resume_path,
            expected_file_size: metadata.source.size,
            block_size: metadata.block_size,
            total_blocks,
            retain_partial: metadata.retain_partial,
            created_unix_ms: metadata.created_unix_ms,
            mutable: Mutex::new(mutable),
        });
        registry.insert(transfer_id.clone(), record.clone());
        record
    };
    drop(registry);

    let mut value = record.mutable.lock().await;
    if value.lifecycle.state == TransferState::Completed {
        return Err("resume-transfer-completed".into());
    }
    if value.cleanup_in_progress || value.lifecycle.state == TransferState::Cancelling {
        return Err("resume-cleanup-in-progress".into());
    }
    if value.runtime_active || value.resume_owned || value.finalization_owned {
        return Err("resume-already-active".into());
    }
    if value.checkpoint_generation > metadata.checkpoint_generation {
        return Err("resume-stale-generation".into());
    }
    if !matches!(
        value.lifecycle.state,
        TransferState::Paused
            | TransferState::PausedByDisconnect
            | TransferState::RecoverableFailure
            | TransferState::Cancelled
    ) {
        return Err("resume-invalid-state".into());
    }
    value
        .lifecycle
        .transition(TransferState::Resuming, now_ms())?;
    value.session_id = uuid::Uuid::new_v4().to_string();
    value.cancellation = CancellationToken::new();
    value.stop_reason = None;
    value.runtime_active = true;
    value.resume_owned = true;
    value.finalization_owned = false;
    value.cleanup_in_progress = false;
    value.session_bytes_read = 0;
    value.session_bytes_sent = 0;
    value.session_bytes_received = 0;
    value.session_bytes_written = 0;
    value.bytes_reused = metadata.completed_bytes;
    value.blocks_reused = metadata.completed_blocks();
    value.bytes_remaining = metadata.source.size - metadata.completed_bytes;
    value.blocks_remaining = metadata.total_blocks - metadata.completed_blocks();
    value.bytes_skipped = metadata.completed_bytes;
    value.blocks_skipped = metadata.completed_blocks();
    value.bytes_scheduled = value.bytes_remaining;
    value.blocks_scheduled = value.blocks_remaining;
    value.bytes_retransmitted = 0;
    value.blocks_retransmitted = 0;
    value.resume_verification_progress = 0.0;
    value.completed_bitmap = metadata.completed_bitmap.clone();
    value.completed_blocks = metadata.completed_blocks();
    value.expected_sha256 = Some(metadata.expected_sha256);
    value.checkpoint_generation = metadata.checkpoint_generation;
    value.terminal_error = None;
    value.checkpoint_succeeded = false;
    value.cleanup_warnings.clear();
    let session_id = value.session_id.clone();
    drop(value);
    Ok(ResumeClaim { record, session_id })
}

pub async fn lookup(transfer_id: &str) -> Option<Arc<TransferRecord>> {
    REGISTRY.lock().await.get(transfer_id).cloned()
}

pub async fn lookup_by_resume_path(path: &Path) -> Option<Arc<TransferRecord>> {
    let requested = super::resume::generation_paths(path).current;
    REGISTRY
        .lock()
        .await
        .values()
        .find(|record| record.resume_path == requested)
        .cloned()
}

pub async fn set_task_abort(record: &Arc<TransferRecord>, abort: AbortHandle) {
    record.mutable.lock().await.task_abort = Some(abort);
}

#[cfg(test)]
pub async fn remove_for_test(transfer_id: &str) {
    REGISTRY.lock().await.remove(transfer_id);
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferIdRequest {
    pub transfer_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PauseTransferRequest {
    pub transfer_id: String,
    pub expected_generation: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelTransferRequest {
    pub transfer_id: String,
    pub retain_partial: Option<bool>,
    pub expected_generation: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscardResult {
    transfer_id: String,
    part_removed: bool,
    resume_artifacts_removed: Vec<String>,
    block_hash_artifacts_removed: Vec<String>,
}

pub async fn flowshare_native_list_transfers() -> Result<Vec<TransferSnapshot>, String> {
    if !cfg!(any(debug_assertions, test)) {
        return Err("Native transfer registry is development-only.".into());
    }
    let records: Vec<_> = REGISTRY.lock().await.values().cloned().collect();
    let mut output = Vec::with_capacity(records.len());
    for record in records {
        output.push(record.snapshot().await);
    }
    Ok(output)
}

pub async fn flowshare_native_get_transfer(
    request: TransferIdRequest,
) -> Result<TransferSnapshot, String> {
    if !cfg!(any(debug_assertions, test)) {
        return Err("Native transfer registry is development-only.".into());
    }
    Ok(lookup(&request.transfer_id)
        .await
        .ok_or("native-transfer-not-found")?
        .snapshot()
        .await)
}

pub async fn flowshare_native_cancel_transfer(
    request: CancelTransferRequest,
) -> Result<TransferSnapshot, String> {
    if !cfg!(any(debug_assertions, test)) {
        return Err("Native transfer cancellation is development-only.".into());
    }
    let record = lookup(&request.transfer_id)
        .await
        .ok_or("native-transfer-not-found")?;
    let retain = request.retain_partial.unwrap_or(record.retain_partial);
    let (inactive_cleanup, already_terminal) = {
        let mut value = record.mutable.lock().await;
        if request
            .expected_generation
            .is_some_and(|generation| generation != value.lifecycle.generation)
        {
            return Err("native-transfer-stale-generation".into());
        }
        if matches!(
            value.lifecycle.state,
            TransferState::Completed | TransferState::Cancelled
        ) {
            (false, true)
        } else {
            if value.cleanup_in_progress {
                return Err("resume-cleanup-in-progress".into());
            }
            value
                .lifecycle
                .transition(TransferState::Cancelling, now_ms())?;
            value.stop_reason = Some(if retain {
                StopReason::CancelRetain
            } else {
                StopReason::CancelDelete
            });
            if value.runtime_active {
                value.cancellation.cancel();
                (false, false)
            } else {
                value.cleanup_in_progress = !retain;
                (true, false)
            }
        }
    };
    if already_terminal {
        return Ok(record.snapshot().await);
    }
    if inactive_cleanup {
        if !retain {
            let _ = remove_if_present(&record.part_path).await?;
            let _ = super::resume::remove_generations(&record.resume_path).await?;
            let _ = super::block_hash::remove_generations(&record.resume_path).await?;
            let _ = super::secret_store::delete(&record.resume_path).await?;
            if let Ok(transfer_id) = uuid::Uuid::parse_str(&record.transfer_id) {
                let _ = super::authorization::revoke(transfer_id.as_bytes());
            }
        }
        let mut value = record.mutable.lock().await;
        value.cleanup_in_progress = false;
        value.partial_retained = retain;
        value.resume_available = retain;
        value
            .lifecycle
            .transition(TransferState::Cancelled, now_ms())?;
    }
    Ok(record.snapshot().await)
}

pub async fn flowshare_native_pause_transfer(
    request: PauseTransferRequest,
) -> Result<TransferSnapshot, String> {
    if !cfg!(any(debug_assertions, test)) {
        return Err("Native transfer pause is development-only.".into());
    }
    let record = lookup(&request.transfer_id)
        .await
        .ok_or("native-transfer-not-found")?;
    {
        let mut value = record.mutable.lock().await;
        if request
            .expected_generation
            .is_some_and(|generation| generation != value.lifecycle.generation)
        {
            return Err("native-transfer-stale-generation".into());
        }
        if matches!(
            value.lifecycle.state,
            TransferState::Paused | TransferState::PausedByDisconnect
        ) {
            drop(value);
            return Ok(record.snapshot().await);
        }
        if !value.runtime_active {
            return Err("resume-invalid-state".into());
        }
        value
            .lifecycle
            .transition(TransferState::Pausing, now_ms())?;
        value.stop_reason = Some(StopReason::Pause);
        value.cancellation.cancel();
    }
    Ok(record.snapshot().await)
}

pub async fn request_disconnect(record: &Arc<TransferRecord>) -> Result<(), String> {
    let mut value = record.mutable.lock().await;
    if !value.runtime_active {
        return Err("resume-invalid-state".into());
    }
    value.stop_reason = Some(StopReason::Disconnect);
    value.cancellation.cancel();
    Ok(())
}

pub async fn flowshare_native_discard_partial(
    request: TransferIdRequest,
) -> Result<DiscardResult, String> {
    if !cfg!(any(debug_assertions, test)) {
        return Err("Native partial discard is development-only.".into());
    }
    let record = lookup(&request.transfer_id)
        .await
        .ok_or("native-transfer-not-found")?;
    let state = record.mutable.lock().await.lifecycle.state;
    if !matches!(
        state,
        TransferState::Paused
            | TransferState::PausedByDisconnect
            | TransferState::Cancelled
            | TransferState::RecoverableFailure
            | TransferState::Failed
    ) {
        return Err("native-transfer-must-be-paused-or-cancelled".into());
    }
    let part_removed = remove_if_present(&record.part_path).await?;
    let resume_artifacts_removed = super::resume::remove_generations(&record.resume_path).await?;
    let block_hash_artifacts_removed =
        super::block_hash::remove_generations(&record.resume_path).await?;
    let _ = super::secret_store::delete(&record.resume_path).await?;
    if let Ok(transfer_id) = uuid::Uuid::parse_str(&record.transfer_id) {
        let _ = super::authorization::revoke(transfer_id.as_bytes());
    }
    {
        let mut value = record.mutable.lock().await;
        value.resume_available = false;
        value.partial_retained = false;
    }
    Ok(DiscardResult {
        transfer_id: record.transfer_id.clone(),
        part_removed,
        resume_artifacts_removed,
        block_hash_artifacts_removed,
    })
}

pub(crate) async fn remove_if_present(path: &Path) -> Result<bool, String> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("native-partial-cleanup-failed: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancellation_is_idempotent_and_terminal() {
        let id = uuid::Uuid::new_v4().to_string();
        let record = register(NewTransferRecord {
            transfer_id: id.clone(),
            source_path: None,
            source_identity: None,
            destination_path: "final".into(),
            part_path: "part".into(),
            resume_path: "resume".into(),
            expected_file_size: 10,
            block_size: 2,
            retain_partial: true,
        })
        .await
        .unwrap();
        record.transition(TransferState::Preparing).await.unwrap();
        record.transition(TransferState::Connecting).await.unwrap();
        record
            .transition(TransferState::Transferring)
            .await
            .unwrap();
        let generation = record.snapshot().await.state_generation;
        let first = flowshare_native_cancel_transfer(CancelTransferRequest {
            transfer_id: id.clone(),
            retain_partial: Some(true),
            expected_generation: Some(generation),
        })
        .await
        .unwrap();
        let second = flowshare_native_cancel_transfer(CancelTransferRequest {
            transfer_id: id,
            retain_partial: Some(true),
            expected_generation: None,
        })
        .await
        .unwrap();
        assert_eq!(first.state, TransferState::Cancelling);
        assert_eq!(second.state, TransferState::Cancelling);
        assert!(record.cancellation_token().await.is_cancelled());
    }
}
