use super::lifecycle::TransferState;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::{fs, io::AsyncWriteExt};

pub const RESUME_MAGIC: [u8; 8] = *b"FQRESUME";
pub const RESUME_FORMAT_VERSION: u16 = 3;
pub const MAX_CHECKPOINT_FRAME_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceIdentity {
    pub size: u64,
    pub modified_unix_ms: Option<u64>,
    pub platform_file_id: Option<String>,
    pub canonical_path: Option<String>,
}

pub async fn capture_source_identity(path: &Path) -> Result<SourceIdentity, String> {
    #[cfg(unix)]
    if path.to_string_lossy().starts_with("/proc/self/fd/") {
        return capture_descriptor_source_identity(path).await;
    }
    let canonical = fs::canonicalize(path)
        .await
        .map_err(|_| "resume-source-missing")?;
    let metadata = fs::metadata(&canonical)
        .await
        .map_err(|_| "resume-source-missing")?;
    if !metadata.is_file() {
        return Err("resume-source-replaced".into());
    }
    let modified_unix_ms = metadata.modified().ok().and_then(|value| {
        value
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|duration| duration.as_millis().try_into().ok())
    });
    Ok(SourceIdentity {
        size: metadata.len(),
        modified_unix_ms,
        platform_file_id: platform_file_id(&canonical, &metadata),
        canonical_path: Some(canonical.display().to_string()),
    })
}

/// Captures identity for an already-open platform descriptor without resolving
/// the Linux `/proc/self/fd` magic link into a provider-private path.
pub async fn capture_descriptor_source_identity(path: &Path) -> Result<SourceIdentity, String> {
    let metadata = fs::metadata(path)
        .await
        .map_err(|_| "resume-source-missing")?;
    if !metadata.is_file() {
        return Err("resume-source-replaced".into());
    }
    let modified_unix_ms = metadata.modified().ok().and_then(|value| {
        value
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|duration| duration.as_millis().try_into().ok())
    });
    Ok(SourceIdentity {
        size: metadata.len(),
        modified_unix_ms,
        platform_file_id: platform_file_id(path, &metadata),
        canonical_path: None,
    })
}

#[cfg(unix)]
fn platform_file_id(_path: &Path, metadata: &std::fs::Metadata) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    Some(format!("{}:{}", metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn platform_file_id(_path: &Path, _metadata: &std::fs::Metadata) -> Option<String> {
    None
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResumeMetadata {
    pub format_version: u16,
    pub protocol_version: u16,
    pub transfer_id: [u8; 16],
    pub invitation_id: [u8; 16],
    pub secret_version: u16,
    pub share_id: Option<String>,
    pub lifecycle_generation: u64,
    pub checkpoint_generation: u64,
    pub checkpoint_state: TransferState,
    pub previous_session_id: Option<[u8; 16]>,
    pub source: SourceIdentity,
    pub expected_sha256: [u8; 32],
    pub final_filename: String,
    pub part_filename: String,
    pub block_size: u64,
    pub total_blocks: u64,
    pub completed_bitmap: Vec<u8>,
    pub completed_bytes: u64,
    pub created_unix_ms: u64,
    pub checkpoint_unix_ms: u64,
    pub checkpoint_auth_micros: u64,
    pub retain_partial: bool,
    pub block_hash_sidecar_digest: [u8; 32],
    pub part_identity_digest: [u8; 32],
    pub secure_state_digest: [u8; 32],
    pub authentication_tag: [u8; 32],
}

impl ResumeMetadata {
    pub fn validate_shape(&self) -> Result<(), String> {
        if self.format_version != RESUME_FORMAT_VERSION {
            return Err("resume-version-unsupported".into());
        }
        if self.protocol_version != super::protocol::NATIVE_QUIC_PROTOCOL_VERSION {
            return Err("resume-protocol-version-unsupported".into());
        }
        if self.secret_version != 3
            || self.final_filename.len() > 1024
            || self.part_filename.len() > 1024
            || self
                .share_id
                .as_ref()
                .is_some_and(|value| value.len() > 4096)
            || self
                .source
                .canonical_path
                .as_ref()
                .is_some_and(|value| value.len() > 32 * 1024)
            || self
                .source
                .platform_file_id
                .as_ref()
                .is_some_and(|value| value.len() > 4096)
            || self.checkpoint_auth_micros > 60_000_000
        {
            return Err("resume-checkpoint-invalid".into());
        }
        if self.final_filename.is_empty()
            || self.part_filename.is_empty()
            || self.final_filename.contains(['/', '\\'])
            || self.part_filename.contains(['/', '\\'])
        {
            return Err("resume-checkpoint-invalid".into());
        }
        if !matches!(
            self.checkpoint_state,
            TransferState::Paused
                | TransferState::PausedByDisconnect
                | TransferState::RecoverableFailure
                | TransferState::Cancelled
        ) {
            return Err("resume-invalid-state".into());
        }
        if self.block_size == 0 || self.total_blocks != self.source.size.div_ceil(self.block_size) {
            return Err("resume-block-layout-invalid".into());
        }
        let expected_bitmap = self.total_blocks.div_ceil(8) as usize;
        if self.completed_bitmap.len() != expected_bitmap {
            return Err("resume-block-layout-invalid".into());
        }
        let bytes = completed_bytes_for_bitmap(
            &self.completed_bitmap,
            self.total_blocks,
            self.block_size,
            self.source.size,
        )?;
        if bytes != self.completed_bytes {
            return Err("resume-checkpoint-invalid".into());
        }
        validate_unused_bitmap_bits(&self.completed_bitmap, self.total_blocks)?;
        Ok(())
    }

    pub fn canonical_security_payload(&self) -> Result<Vec<u8>, String> {
        self.validate_shape()?;
        let mut output = Vec::new();
        output.extend_from_slice(b"flowshare/native/v3/resume-checkpoint");
        output.extend_from_slice(&self.format_version.to_be_bytes());
        output.extend_from_slice(&self.protocol_version.to_be_bytes());
        output.extend_from_slice(&self.transfer_id);
        output.extend_from_slice(&self.invitation_id);
        output.extend_from_slice(&self.secret_version.to_be_bytes());
        append_optional_string(&mut output, self.share_id.as_deref())?;
        output.extend_from_slice(&self.lifecycle_generation.to_be_bytes());
        output.extend_from_slice(&self.checkpoint_generation.to_be_bytes());
        output.push(transfer_state_code(self.checkpoint_state));
        match self.previous_session_id {
            Some(value) => {
                output.push(1);
                output.extend_from_slice(&value);
            }
            None => output.push(0),
        }
        append_source_identity(&mut output, &self.source)?;
        output.extend_from_slice(&self.expected_sha256);
        append_string(&mut output, &self.final_filename)?;
        append_string(&mut output, &self.part_filename)?;
        output.extend_from_slice(&self.block_size.to_be_bytes());
        output.extend_from_slice(&self.total_blocks.to_be_bytes());
        append_bytes(&mut output, &self.completed_bitmap)?;
        output.extend_from_slice(&self.completed_bytes.to_be_bytes());
        output.extend_from_slice(&self.created_unix_ms.to_be_bytes());
        output.extend_from_slice(&self.checkpoint_unix_ms.to_be_bytes());
        output.extend_from_slice(&self.checkpoint_auth_micros.to_be_bytes());
        output.push(u8::from(self.retain_partial));
        output.extend_from_slice(&self.block_hash_sidecar_digest);
        output.extend_from_slice(&self.part_identity_digest);
        output.extend_from_slice(&self.secure_state_digest);
        Ok(output)
    }

    pub fn refresh_security(
        &mut self,
        checkpoint_key: &[u8; 32],
        block_hash_sidecar_digest: [u8; 32],
        part_identity_digest: [u8; 32],
    ) -> Result<(), String> {
        self.block_hash_sidecar_digest = block_hash_sidecar_digest;
        self.part_identity_digest = part_identity_digest;
        self.secure_state_digest = super::secure_protocol::secure_resume_state_digest(
            &self.transfer_id,
            self.checkpoint_generation,
            self.source.size,
            self.block_size,
            self.total_blocks,
            &self.completed_bitmap,
            self.completed_bytes,
            &self.block_hash_sidecar_digest,
            &self.expected_sha256,
            &self.part_identity_digest,
        );
        self.authentication_tag = super::secure_protocol::checkpoint_mac(
            checkpoint_key,
            &self.canonical_security_payload()?,
        )?;
        Ok(())
    }

    pub fn set_checkpoint_auth_duration(
        &mut self,
        checkpoint_key: &[u8; 32],
        duration_micros: u64,
    ) -> Result<(), String> {
        if duration_micros > 60_000_000 {
            return Err("resume-checkpoint-invalid".into());
        }
        self.checkpoint_auth_micros = duration_micros;
        self.authentication_tag = super::secure_protocol::checkpoint_mac(
            checkpoint_key,
            &self.canonical_security_payload()?,
        )?;
        Ok(())
    }

    pub fn verify_security(&self, checkpoint_key: &[u8; 32]) -> Result<(), String> {
        let expected_state = super::secure_protocol::secure_resume_state_digest(
            &self.transfer_id,
            self.checkpoint_generation,
            self.source.size,
            self.block_size,
            self.total_blocks,
            &self.completed_bitmap,
            self.completed_bytes,
            &self.block_hash_sidecar_digest,
            &self.expected_sha256,
            &self.part_identity_digest,
        );
        if expected_state != self.secure_state_digest {
            return Err("resume-state-mismatch".into());
        }
        super::secure_protocol::verify_checkpoint_mac(
            checkpoint_key,
            &self.canonical_security_payload()?,
            &self.authentication_tag,
        )
    }

    pub fn is_complete(&self, block: u64) -> bool {
        bitmap_is_complete(&self.completed_bitmap, self.total_blocks, block)
    }

    pub fn set_complete(&mut self, block: u64) -> Result<(), String> {
        if block >= self.total_blocks {
            return Err("resume-block-layout-invalid".into());
        }
        if !self.is_complete(block) {
            self.completed_bitmap[(block / 8) as usize] |= 1 << (block % 8);
            self.completed_bytes +=
                block_length(block, self.block_size, self.source.size, self.total_blocks)?;
        }
        Ok(())
    }

    pub fn clear_complete(&mut self, block: u64) -> Result<bool, String> {
        if block >= self.total_blocks {
            return Err("resume-block-layout-invalid".into());
        }
        if !self.is_complete(block) {
            return Ok(false);
        }
        self.completed_bitmap[(block / 8) as usize] &= !(1 << (block % 8));
        self.completed_bytes -=
            block_length(block, self.block_size, self.source.size, self.total_blocks)?;
        Ok(true)
    }

    pub fn completed_blocks(&self) -> u64 {
        self.completed_bitmap
            .iter()
            .map(|value| value.count_ones() as u64)
            .sum()
    }
}

fn transfer_state_code(value: TransferState) -> u8 {
    match value {
        TransferState::Created => 1,
        TransferState::Preparing => 2,
        TransferState::Connecting => 3,
        TransferState::Transferring => 4,
        TransferState::Pausing => 5,
        TransferState::Paused => 6,
        TransferState::PausedByDisconnect => 7,
        TransferState::Resuming => 8,
        TransferState::Cancelling => 9,
        TransferState::Cancelled => 10,
        TransferState::Validating => 11,
        TransferState::Synchronizing => 12,
        TransferState::Finalizing => 13,
        TransferState::Completed => 14,
        TransferState::RecoverableFailure => 15,
        TransferState::Failed => 16,
    }
}

fn append_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    let length: u32 = value
        .len()
        .try_into()
        .map_err(|_| "resume-checkpoint-invalid")?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn append_string(output: &mut Vec<u8>, value: &str) -> Result<(), String> {
    append_bytes(output, value.as_bytes())
}

fn append_optional_string(output: &mut Vec<u8>, value: Option<&str>) -> Result<(), String> {
    match value {
        Some(value) => {
            output.push(1);
            append_string(output, value)
        }
        None => {
            output.push(0);
            Ok(())
        }
    }
}

fn append_source_identity(output: &mut Vec<u8>, value: &SourceIdentity) -> Result<(), String> {
    output.extend_from_slice(&value.size.to_be_bytes());
    match value.modified_unix_ms {
        Some(modified) => {
            output.push(1);
            output.extend_from_slice(&modified.to_be_bytes());
        }
        None => output.push(0),
    }
    append_optional_string(output, value.platform_file_id.as_deref())?;
    append_optional_string(output, value.canonical_path.as_deref())
}

pub fn source_identity_digest(value: &SourceIdentity) -> Result<[u8; 32], String> {
    let mut payload = b"flowshare/native/v3/file-identity".to_vec();
    append_source_identity(&mut payload, value)?;
    Ok(Sha256::digest(payload).into())
}

pub async fn part_identity_digest(path: &Path) -> Result<[u8; 32], String> {
    source_identity_digest(&capture_source_identity(path).await?)
}

pub fn bitmap_is_complete(bitmap: &[u8], total_blocks: u64, block: u64) -> bool {
    block < total_blocks && bitmap[(block / 8) as usize] & (1 << (block % 8)) != 0
}

pub fn block_length(
    block: u64,
    block_size: u64,
    file_size: u64,
    total_blocks: u64,
) -> Result<u64, String> {
    if block >= total_blocks || block_size == 0 {
        return Err("resume-block-layout-invalid".into());
    }
    let offset = block
        .checked_mul(block_size)
        .ok_or("resume-block-layout-invalid")?;
    Ok((file_size - offset).min(block_size))
}

pub fn completed_bytes_for_bitmap(
    bitmap: &[u8],
    total_blocks: u64,
    block_size: u64,
    file_size: u64,
) -> Result<u64, String> {
    if bitmap.len() != total_blocks.div_ceil(8) as usize {
        return Err("resume-block-layout-invalid".into());
    }
    let mut bytes = 0u64;
    for block in 0..total_blocks {
        if bitmap_is_complete(bitmap, total_blocks, block) {
            bytes = bytes
                .checked_add(block_length(block, block_size, file_size, total_blocks)?)
                .ok_or("resume-block-layout-invalid")?;
        }
    }
    Ok(bytes)
}

fn validate_unused_bitmap_bits(bitmap: &[u8], total_blocks: u64) -> Result<(), String> {
    if let Some(last) = bitmap.last() {
        let used_bits = (total_blocks % 8) as u8;
        if used_bits != 0 && last & (!0u8 << used_bits) != 0 {
            return Err("resume-block-layout-invalid".into());
        }
    }
    Ok(())
}

pub(crate) fn encode(metadata: &ResumeMetadata) -> Result<Vec<u8>, String> {
    metadata.validate_shape()?;
    encode_framed(&RESUME_MAGIC, metadata, "resume-metadata-too-large")
}

pub(crate) fn decode(input: &[u8]) -> Result<ResumeMetadata, String> {
    let value: ResumeMetadata = decode_framed(&RESUME_MAGIC, input, "resume-metadata-corrupt")?;
    value.validate_shape()?;
    Ok(value)
}

#[doc(hidden)]
pub fn encode_framed<T: Serialize>(
    magic: &[u8; 8],
    value: &T,
    too_large: &'static str,
) -> Result<Vec<u8>, String> {
    let payload = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    let length: u32 = payload.len().try_into().map_err(|_| too_large)?;
    let mut output = Vec::with_capacity(8 + 4 + payload.len() + 32);
    output.extend_from_slice(magic);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(&payload);
    output.extend_from_slice(&Sha256::digest(&output));
    Ok(output)
}

pub(crate) fn decode_framed<T: for<'de> Deserialize<'de>>(
    magic: &[u8; 8],
    input: &[u8],
    corrupt: &'static str,
) -> Result<T, String> {
    if input.len() < 44 || input.len() > MAX_CHECKPOINT_FRAME_BYTES || input[..8] != *magic {
        return Err(corrupt.into());
    }
    let length = u32::from_be_bytes(input[8..12].try_into().unwrap()) as usize;
    let authenticated_end = 12usize.checked_add(length).ok_or(corrupt)?;
    let total = authenticated_end.checked_add(32).ok_or(corrupt)?;
    if input.len() != total {
        return Err(corrupt.into());
    }
    let expected = Sha256::digest(&input[..authenticated_end]);
    if expected.as_slice() != &input[authenticated_end..] {
        return Err(corrupt.into());
    }
    serde_json::from_slice(&input[12..authenticated_end]).map_err(|_| corrupt.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointFault {
    AfterPendingCreation,
    AfterPendingWrite,
    AfterPendingSync,
    AfterPendingValidation,
    AfterCurrentBackup,
    BeforeCurrentPromotion,
    AfterCurrentPromotion,
    BeforePreviousCleanup,
}

#[derive(Debug, Clone)]
pub struct GenerationPaths {
    pub current: PathBuf,
    pub previous: PathBuf,
    pub pending: PathBuf,
}

pub fn generation_paths(requested: &Path) -> GenerationPaths {
    let filename = requested
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("transfer.resume.current");
    let base = [".current", ".previous", ".pending"]
        .iter()
        .find_map(|suffix| filename.strip_suffix(suffix))
        .unwrap_or(filename);
    let explicit_generation = base != filename;
    let current = if explicit_generation {
        requested.with_file_name(format!("{base}.current"))
    } else {
        requested.to_path_buf()
    };
    let previous = if explicit_generation {
        requested.with_file_name(format!("{base}.previous"))
    } else {
        requested.with_file_name(format!("{filename}.previous"))
    };
    let pending = if explicit_generation {
        requested.with_file_name(format!("{base}.pending"))
    } else {
        requested.with_file_name(format!("{filename}.pending"))
    };
    GenerationPaths {
        current,
        previous,
        pending,
    }
}

pub async fn write_atomic(path: &Path, metadata: &ResumeMetadata) -> Result<(), String> {
    write_with_fault(path, metadata, None).await
}

pub async fn write_atomic_authenticated(
    path: &Path,
    metadata: &ResumeMetadata,
    checkpoint_key: &[u8; 32],
) -> Result<(), String> {
    let bytes = encode(metadata)?;
    promote_bytes(
        &generation_paths(path),
        &bytes,
        |candidate| {
            let value = decode(candidate)?;
            value.verify_security(checkpoint_key)
        },
        None,
        "resume",
    )
    .await
}

pub async fn write_with_fault(
    path: &Path,
    metadata: &ResumeMetadata,
    fault: Option<CheckpointFault>,
) -> Result<(), String> {
    let bytes = encode(metadata)?;
    promote_bytes(
        &generation_paths(path),
        &bytes,
        |candidate| decode(candidate).map(|_| ()),
        fault,
        "resume",
    )
    .await
}

pub(crate) async fn promote_bytes<F>(
    paths: &GenerationPaths,
    bytes: &[u8],
    validate: F,
    fault: Option<CheckpointFault>,
    label: &str,
) -> Result<(), String>
where
    F: Fn(&[u8]) -> Result<(), String>,
{
    let pending_valid = match fs::read(&paths.pending).await {
        Ok(existing) => validate(&existing).is_ok(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(format!("{label}-checkpoint-pending-read-failed: {error}")),
    };
    let current_valid_before_write = match fs::read(&paths.current).await {
        Ok(existing) => validate(&existing).is_ok(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(format!("{label}-checkpoint-current-read-failed: {error}")),
    };
    if pending_valid && !current_valid_before_write {
        remove_if_exists(&paths.current).await?;
        fs::rename(&paths.pending, &paths.current)
            .await
            .map_err(|e| format!("{label}-checkpoint-pending-recovery-failed: {e}"))?;
    } else {
        remove_if_exists(&paths.pending).await?;
    }
    let mut pending = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&paths.pending)
        .await
        .map_err(|e| format!("{label}-checkpoint-create-failed: {e}"))?;
    inject(fault, CheckpointFault::AfterPendingCreation)?;
    pending
        .write_all(bytes)
        .await
        .map_err(|e| format!("{label}-checkpoint-write-failed: {e}"))?;
    inject(fault, CheckpointFault::AfterPendingWrite)?;
    pending
        .sync_all()
        .await
        .map_err(|e| format!("{label}-checkpoint-sync-failed: {e}"))?;
    inject(fault, CheckpointFault::AfterPendingSync)?;
    drop(pending);
    let pending_bytes = fs::read(&paths.pending)
        .await
        .map_err(|e| format!("{label}-checkpoint-validation-failed: {e}"))?;
    validate(&pending_bytes)?;
    inject(fault, CheckpointFault::AfterPendingValidation)?;

    let current_valid = match fs::read(&paths.current).await {
        Ok(current) => validate(&current).is_ok(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(format!("{label}-checkpoint-current-read-failed: {error}")),
    };
    if current_valid {
        remove_if_exists(&paths.previous).await?;
        fs::rename(&paths.current, &paths.previous)
            .await
            .map_err(|e| format!("{label}-checkpoint-backup-failed: {e}"))?;
    } else {
        remove_if_exists(&paths.current).await?;
    }
    inject(fault, CheckpointFault::AfterCurrentBackup)?;
    inject(fault, CheckpointFault::BeforeCurrentPromotion)?;
    fs::rename(&paths.pending, &paths.current)
        .await
        .map_err(|e| format!("{label}-checkpoint-promotion-failed: {e}"))?;
    inject(fault, CheckpointFault::AfterCurrentPromotion)?;
    let promoted = fs::read(&paths.current)
        .await
        .map_err(|e| format!("{label}-checkpoint-current-read-failed: {e}"))?;
    validate(&promoted)?;
    inject(fault, CheckpointFault::BeforePreviousCleanup)?;
    // The immediately preceding valid generation is intentionally retained.
    Ok(())
}

fn inject(actual: Option<CheckpointFault>, expected: CheckpointFault) -> Result<(), String> {
    if actual == Some(expected) {
        Err(format!("resume-checkpoint-fault:{expected:?}"))
    } else {
        Ok(())
    }
}

async fn remove_if_exists(path: &Path) -> Result<bool, String> {
    match fs::remove_file(path).await {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("resume-checkpoint-cleanup-failed: {error}")),
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvalidCheckpointCandidate {
    pub path: String,
    pub error: String,
}

#[derive(Debug, Clone)]
pub struct CheckpointSelection {
    pub metadata: ResumeMetadata,
    pub selected_path: PathBuf,
    pub recovered_from_pending: bool,
    pub recovered_from_previous: bool,
    pub invalid_candidates: Vec<InvalidCheckpointCandidate>,
}

pub async fn load_highest_valid(path: &Path) -> Result<CheckpointSelection, String> {
    let paths = generation_paths(path);
    let candidates = [
        (&paths.current, 3u8, false, false),
        (&paths.pending, 2u8, true, false),
        (&paths.previous, 1u8, false, true),
    ];
    let mut valid = Vec::new();
    let mut invalid = Vec::new();
    for (candidate, priority, pending, previous) in candidates {
        match fs::read(candidate).await {
            Ok(bytes) => match decode(&bytes) {
                Ok(metadata) => valid.push((
                    metadata.checkpoint_generation,
                    priority,
                    metadata,
                    candidate.clone(),
                    pending,
                    previous,
                )),
                Err(error) => invalid.push(InvalidCheckpointCandidate {
                    path: candidate.display().to_string(),
                    error,
                }),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => invalid.push(InvalidCheckpointCandidate {
                path: candidate.display().to_string(),
                error: format!("resume-checkpoint-read-failed: {error}"),
            }),
        }
    }
    valid.sort_by_key(|(generation, priority, _, _, _, _)| (*generation, *priority));
    let (_, _, metadata, selected_path, recovered_from_pending, recovered_from_previous) =
        match valid.pop() {
            Some(selected) => selected,
            None if invalid.is_empty() => return Err("resume-checkpoint-missing".into()),
            None if invalid.len() == 1
                && matches!(
                    invalid[0].error.as_str(),
                    "resume-version-unsupported" | "resume-protocol-version-unsupported"
                ) =>
            {
                return Err(invalid[0].error.clone());
            }
            None => return Err("resume-checkpoint-invalid".into()),
        };
    Ok(CheckpointSelection {
        metadata,
        selected_path,
        recovered_from_pending,
        recovered_from_previous,
        invalid_candidates: invalid,
    })
}

pub async fn load_highest_valid_authenticated(
    path: &Path,
    checkpoint_key: &[u8; 32],
    expected_transfer_id: &[u8; 16],
    expected_invitation_id: &[u8; 16],
) -> Result<CheckpointSelection, String> {
    let paths = generation_paths(path);
    let candidates = [
        (&paths.current, 3u8, false, false),
        (&paths.pending, 2u8, true, false),
        (&paths.previous, 1u8, false, true),
    ];
    let mut valid = Vec::new();
    let mut invalid = Vec::new();
    for (candidate, priority, pending, previous) in candidates {
        match fs::read(candidate).await {
            Ok(bytes) => {
                let verified = decode(&bytes).and_then(|metadata| {
                    if &metadata.transfer_id != expected_transfer_id
                        || &metadata.invitation_id != expected_invitation_id
                    {
                        return Err("checkpoint-authentication-failed".into());
                    }
                    metadata.verify_security(checkpoint_key)?;
                    Ok(metadata)
                });
                match verified {
                    Ok(metadata) => valid.push((
                        metadata.checkpoint_generation,
                        priority,
                        metadata,
                        candidate.clone(),
                        pending,
                        previous,
                    )),
                    Err(error) => invalid.push(InvalidCheckpointCandidate {
                        path: candidate.display().to_string(),
                        error,
                    }),
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => invalid.push(InvalidCheckpointCandidate {
                path: candidate.display().to_string(),
                error: "resume-checkpoint-read-failed".into(),
            }),
        }
    }
    valid.sort_by_key(|(generation, priority, _, _, _, _)| (*generation, *priority));
    let (_, _, metadata, selected_path, recovered_from_pending, recovered_from_previous) =
        match valid.pop() {
            Some(selected) => selected,
            None if invalid.is_empty() => return Err("resume-checkpoint-missing".into()),
            None if invalid.iter().any(|value| {
                matches!(
                    value.error.as_str(),
                    "checkpoint-authentication-failed" | "resume-state-mismatch"
                )
            }) =>
            {
                return Err("checkpoint-authentication-failed".into())
            }
            None if invalid.len() == 1
                && matches!(
                    invalid[0].error.as_str(),
                    "resume-version-unsupported" | "resume-protocol-version-unsupported"
                ) =>
            {
                return Err(invalid[0].error.clone())
            }
            None => return Err("resume-checkpoint-invalid".into()),
        };
    Ok(CheckpointSelection {
        metadata,
        selected_path,
        recovered_from_pending,
        recovered_from_previous,
        invalid_candidates: invalid,
    })
}

pub async fn read_and_validate(
    path: &Path,
    source: &Path,
    part: &Path,
) -> Result<ResumeMetadata, String> {
    let value = load_highest_valid(path).await?.metadata;
    let source_metadata = fs::metadata(source)
        .await
        .map_err(|_| "resume-source-missing")?;
    if !source_metadata.is_file() {
        return Err("resume-source-replaced".into());
    }
    if source_metadata.len() != value.source.size {
        return Err("resume-source-size-mismatch".into());
    }
    let part_metadata = fs::metadata(part)
        .await
        .map_err(|_| "resume-part-missing")?;
    if !part_metadata.is_file() || part_metadata.len() != value.source.size {
        return Err("resume-part-size-mismatch".into());
    }
    Ok(value)
}

pub async fn read_checkpoint(path: &Path) -> Result<ResumeMetadata, String> {
    decode(
        &fs::read(path)
            .await
            .map_err(|_| "resume-metadata-corrupt")?,
    )
}

pub async fn remove_generations(path: &Path) -> Result<Vec<String>, String> {
    let paths = generation_paths(path);
    let mut removed = Vec::new();
    for candidate in [paths.current, paths.previous, paths.pending] {
        if remove_if_exists(&candidate).await? {
            removed.push(candidate.display().to_string());
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn metadata(size: u64, generation: u64) -> ResumeMetadata {
        let blocks = size.div_ceil(2 * 1024 * 1024);
        ResumeMetadata {
            format_version: RESUME_FORMAT_VERSION,
            protocol_version: super::super::protocol::NATIVE_QUIC_PROTOCOL_VERSION,
            transfer_id: *Uuid::new_v4().as_bytes(),
            invitation_id: [1; 16],
            secret_version: 3,
            share_id: None,
            lifecycle_generation: 4,
            checkpoint_generation: generation,
            checkpoint_state: TransferState::Paused,
            previous_session_id: None,
            source: SourceIdentity {
                size,
                modified_unix_ms: None,
                platform_file_id: None,
                canonical_path: None,
            },
            expected_sha256: [3; 32],
            final_filename: "file.bin".into(),
            part_filename: ".file.part".into(),
            block_size: 2 * 1024 * 1024,
            total_blocks: blocks,
            completed_bitmap: vec![0; blocks.div_ceil(8) as usize],
            completed_bytes: 0,
            created_unix_ms: 1,
            checkpoint_unix_ms: 2,
            checkpoint_auth_micros: 0,
            retain_partial: true,
            block_hash_sidecar_digest: [4; 32],
            part_identity_digest: [5; 32],
            secure_state_digest: [6; 32],
            authentication_tag: [7; 32],
        }
    }

    #[test]
    fn compact_bitmap_round_trip_and_corruption_detection() {
        let mut value = metadata(5 * 1024 * 1024, 1);
        value.set_complete(0).unwrap();
        value.set_complete(2).unwrap();
        let bytes = encode(&value).unwrap();
        assert_eq!(decode(&bytes).unwrap(), value);
        let mut corrupt = bytes;
        corrupt[20] ^= 1;
        assert_eq!(decode(&corrupt).unwrap_err(), "resume-metadata-corrupt");
    }

    #[test]
    fn checksum_valid_but_mac_invalid_checkpoint_is_rejected() {
        let key = [9; 32];
        let mut value = metadata(5 * 1024 * 1024, 3);
        value.refresh_security(&key, [4; 32], [5; 32]).unwrap();
        value.verify_security(&key).unwrap();

        let mut mac_tampered = value.clone();
        mac_tampered.checkpoint_unix_ms += 1;
        let checksum_valid = decode(&encode(&mac_tampered).unwrap()).unwrap();
        assert_eq!(
            checksum_valid.verify_security(&key).unwrap_err(),
            "checkpoint-authentication-failed"
        );

        let mut state_tampered = value.clone();
        state_tampered.expected_sha256[0] ^= 1;
        let checksum_valid = decode(&encode(&state_tampered).unwrap()).unwrap();
        assert_eq!(
            checksum_valid.verify_security(&key).unwrap_err(),
            "resume-state-mismatch"
        );

        let mut bitmap_tampered = value.clone();
        bitmap_tampered.set_complete(0).unwrap();
        let checksum_valid = decode(&encode(&bitmap_tampered).unwrap()).unwrap();
        assert_eq!(
            checksum_valid.verify_security(&key).unwrap_err(),
            "resume-state-mismatch"
        );

        let mut digest_tampered = value.clone();
        digest_tampered.secure_state_digest[0] ^= 1;
        let checksum_valid = decode(&encode(&digest_tampered).unwrap()).unwrap();
        assert_eq!(
            checksum_valid.verify_security(&key).unwrap_err(),
            "resume-state-mismatch"
        );

        let mut part_tampered = value;
        part_tampered.part_identity_digest[0] ^= 1;
        let checksum_valid = decode(&encode(&part_tampered).unwrap()).unwrap();
        assert_eq!(
            checksum_valid.verify_security(&key).unwrap_err(),
            "resume-state-mismatch"
        );
    }

    #[test]
    fn checkpoint_decoder_rejects_random_truncated_and_oversized_frames() {
        let valid = encode(&metadata(1024, 1)).unwrap();
        for length in 0..valid.len() {
            assert!(decode(&valid[..length]).is_err());
        }
        let mut state = 0x1234_5678_9abc_def0u64;
        for length in 0..1024usize {
            let mut input = vec![0u8; length];
            for byte in &mut input {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                *byte = (state >> 32) as u8;
            }
            let _ = decode(&input);
        }
        assert!(decode_framed::<ResumeMetadata>(
            &RESUME_MAGIC,
            &vec![0; MAX_CHECKPOINT_FRAME_BYTES + 1],
            "resume-metadata-corrupt",
        )
        .is_err());
    }

    #[tokio::test]
    async fn highest_valid_generation_survives_corrupt_newer_candidate() {
        let root = std::env::temp_dir().join(format!("flowget-resume-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).await.unwrap();
        let current = root.join("transfer.resume.current");
        write_atomic(&current, &metadata(1024, 1)).await.unwrap();
        write_atomic(&current, &metadata(1024, 2)).await.unwrap();
        fs::write(generation_paths(&current).pending, b"corrupt")
            .await
            .unwrap();
        let selection = load_highest_valid(&current).await.unwrap();
        assert_eq!(selection.metadata.checkpoint_generation, 2);
        assert_eq!(selection.invalid_candidates.len(), 1);
        let _ = fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn valid_pending_is_recovered_and_current_wins_identical_generation() {
        let root = std::env::temp_dir().join(format!("flowget-resume-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).await.unwrap();
        let current = root.join("transfer.resume.current");
        let generation_one = metadata(1024, 1);
        write_atomic(&current, &generation_one).await.unwrap();
        let mut generation_two = generation_one.clone();
        generation_two.checkpoint_generation = 2;
        generation_two.checkpoint_unix_ms = 3;
        let paths = generation_paths(&current);
        fs::write(&paths.pending, encode(&generation_two).unwrap())
            .await
            .unwrap();
        let pending = load_highest_valid(&current).await.unwrap();
        assert_eq!(pending.metadata.checkpoint_generation, 2);
        assert!(pending.recovered_from_pending);

        fs::write(&paths.current, encode(&generation_two).unwrap())
            .await
            .unwrap();
        let tied = load_highest_valid(&current).await.unwrap();
        assert_eq!(tied.selected_path, paths.current);
        assert!(!tied.recovered_from_pending);
        let _ = fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn promotion_faults_leave_an_older_valid_generation_loadable() {
        let stages = [
            CheckpointFault::AfterPendingCreation,
            CheckpointFault::AfterPendingWrite,
            CheckpointFault::AfterPendingSync,
            CheckpointFault::AfterPendingValidation,
            CheckpointFault::AfterCurrentBackup,
            CheckpointFault::BeforeCurrentPromotion,
            CheckpointFault::AfterCurrentPromotion,
            CheckpointFault::BeforePreviousCleanup,
        ];
        for stage in stages {
            let root = std::env::temp_dir().join(format!("flowget-resume-{}", Uuid::new_v4()));
            fs::create_dir_all(&root).await.unwrap();
            let current = root.join("transfer.resume.current");
            write_atomic(&current, &metadata(1024, 1)).await.unwrap();
            assert!(write_with_fault(&current, &metadata(1024, 2), Some(stage))
                .await
                .is_err());
            let recovered = load_highest_valid(&current).await.unwrap();
            assert!(matches!(recovered.metadata.checkpoint_generation, 1 | 2));
            let _ = fs::remove_dir_all(root).await;
        }
    }

    #[tokio::test]
    async fn checkpoint_validates_source_and_part() {
        let root = std::env::temp_dir().join(format!("flowget-resume-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).await.unwrap();
        let source = root.join("source");
        let part = root.join("part");
        let resume = root.join("transfer.resume.current");
        fs::write(&source, vec![1; 1024]).await.unwrap();
        fs::write(&part, vec![1; 1024]).await.unwrap();
        let value = metadata(1024, 1);
        write_atomic(&resume, &value).await.unwrap();
        assert_eq!(
            read_and_validate(&resume, &source, &part).await.unwrap(),
            value
        );
        fs::remove_file(&part).await.unwrap();
        assert_eq!(
            read_and_validate(&resume, &source, &part)
                .await
                .unwrap_err(),
            "resume-part-missing"
        );
        let _ = fs::remove_dir_all(root).await;
    }
}
