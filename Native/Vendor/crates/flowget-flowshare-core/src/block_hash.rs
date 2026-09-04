use super::resume::{self, CheckpointFault, GenerationPaths, InvalidCheckpointCandidate};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};
use tokio::fs;

pub const BLOCK_HASH_MAGIC: [u8; 8] = *b"FQBLOCKS";
pub const BLOCK_HASH_FORMAT_VERSION: u16 = 2;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BlockHashEntry {
    pub block_index: u64,
    pub absolute_offset: u64,
    pub valid_length: u64,
    pub digest: [u8; 32],
    pub checkpoint_generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BlockHashManifest {
    pub format_version: u16,
    pub protocol_version: u16,
    pub transfer_id: [u8; 16],
    pub invitation_id: [u8; 16],
    pub checkpoint_generation: u64,
    pub file_size: u64,
    pub block_size: u64,
    pub total_blocks: u64,
    pub part_identity_digest: [u8; 32],
    pub entries: Vec<BlockHashEntry>,
    pub authentication_tag: [u8; 32],
}

impl BlockHashManifest {
    pub fn validate(&self) -> Result<(), String> {
        if self.format_version != BLOCK_HASH_FORMAT_VERSION {
            return Err("block-hash-version-unsupported".into());
        }
        if self.protocol_version != super::protocol::NATIVE_QUIC_PROTOCOL_VERSION {
            return Err("block-hash-protocol-version-unsupported".into());
        }
        if self.block_size == 0 || self.total_blocks != self.file_size.div_ceil(self.block_size) {
            return Err("block-hash-layout-invalid".into());
        }
        if self.entries.len() > self.total_blocks as usize {
            return Err("block-hash-layout-invalid".into());
        }
        let mut seen = BTreeSet::new();
        let mut previous = None;
        for entry in &self.entries {
            if entry.checkpoint_generation != self.checkpoint_generation
                || entry.block_index >= self.total_blocks
                || !seen.insert(entry.block_index)
            {
                return Err("block-hash-layout-invalid".into());
            }
            if previous.is_some_and(|value| entry.block_index <= value) {
                return Err("block-hash-layout-invalid".into());
            }
            previous = Some(entry.block_index);
            let expected_offset = entry
                .block_index
                .checked_mul(self.block_size)
                .ok_or("block-hash-layout-invalid")?;
            let expected_length = (self.file_size - expected_offset).min(self.block_size);
            if entry.absolute_offset != expected_offset || entry.valid_length != expected_length {
                return Err("block-hash-layout-invalid".into());
            }
        }
        Ok(())
    }

    pub fn canonical_security_payload(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let entry_count: u32 = self
            .entries
            .len()
            .try_into()
            .map_err(|_| "block-hash-layout-invalid")?;
        let mut output = b"flowshare/native/v3/block-hash-sidecar".to_vec();
        output.extend_from_slice(&self.format_version.to_be_bytes());
        output.extend_from_slice(&self.protocol_version.to_be_bytes());
        output.extend_from_slice(&self.transfer_id);
        output.extend_from_slice(&self.invitation_id);
        output.extend_from_slice(&self.checkpoint_generation.to_be_bytes());
        output.extend_from_slice(&self.file_size.to_be_bytes());
        output.extend_from_slice(&self.block_size.to_be_bytes());
        output.extend_from_slice(&self.total_blocks.to_be_bytes());
        output.extend_from_slice(&self.part_identity_digest);
        output.extend_from_slice(&entry_count.to_be_bytes());
        for entry in &self.entries {
            output.extend_from_slice(&entry.block_index.to_be_bytes());
            output.extend_from_slice(&entry.absolute_offset.to_be_bytes());
            output.extend_from_slice(&entry.valid_length.to_be_bytes());
            output.extend_from_slice(&entry.digest);
            output.extend_from_slice(&entry.checkpoint_generation.to_be_bytes());
        }
        Ok(output)
    }

    pub fn authenticate(
        &mut self,
        invitation_id: [u8; 16],
        part_identity_digest: [u8; 32],
        checkpoint_key: &[u8; 32],
    ) -> Result<(), String> {
        self.invitation_id = invitation_id;
        self.part_identity_digest = part_identity_digest;
        self.authentication_tag = super::secure_protocol::checkpoint_mac(
            checkpoint_key,
            &self.canonical_security_payload()?,
        )?;
        Ok(())
    }

    pub fn verify_security(
        &self,
        checkpoint_key: &[u8; 32],
        expected_invitation_id: &[u8; 16],
        expected_part_identity_digest: &[u8; 32],
    ) -> Result<(), String> {
        if &self.invitation_id != expected_invitation_id
            || &self.part_identity_digest != expected_part_identity_digest
        {
            return Err("checkpoint-authentication-failed".into());
        }
        super::secure_protocol::verify_checkpoint_mac(
            checkpoint_key,
            &self.canonical_security_payload()?,
            &self.authentication_tag,
        )
    }

    pub fn authenticated_digest(&self) -> Result<[u8; 32], String> {
        let mut payload = self.canonical_security_payload()?;
        payload.extend_from_slice(&self.authentication_tag);
        Ok(sha2::Sha256::digest(payload).into())
    }

    pub fn encoded_size(&self) -> Result<usize, String> {
        Ok(encode(self)?.len())
    }

    pub fn hash_for(&self, block: u64) -> Option<[u8; 32]> {
        self.entries
            .iter()
            .find(|entry| entry.block_index == block)
            .map(|entry| entry.digest)
    }
}

pub fn from_hashes(
    transfer_id: [u8; 16],
    checkpoint_generation: u64,
    file_size: u64,
    block_size: u64,
    hashes: &[Option<[u8; 32]>],
) -> Result<BlockHashManifest, String> {
    let total_blocks = file_size.div_ceil(block_size);
    if hashes.len() != total_blocks as usize {
        return Err("block-hash-layout-invalid".into());
    }
    let entries = hashes
        .iter()
        .enumerate()
        .filter_map(|(index, digest)| {
            digest.map(|digest| {
                let block_index = index as u64;
                let absolute_offset = block_index * block_size;
                BlockHashEntry {
                    block_index,
                    absolute_offset,
                    valid_length: (file_size - absolute_offset).min(block_size),
                    digest,
                    checkpoint_generation,
                }
            })
        })
        .collect();
    let value = BlockHashManifest {
        format_version: BLOCK_HASH_FORMAT_VERSION,
        protocol_version: super::protocol::NATIVE_QUIC_PROTOCOL_VERSION,
        transfer_id,
        invitation_id: [0; 16],
        checkpoint_generation,
        file_size,
        block_size,
        total_blocks,
        part_identity_digest: [0; 32],
        entries,
        authentication_tag: [0; 32],
    };
    value.validate()?;
    Ok(value)
}

pub fn block_generation_paths(resume_path: &Path) -> GenerationPaths {
    let resume = resume::generation_paths(resume_path);
    let current_name = resume
        .current
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("transfer.resume.current");
    let block_name = if let Some(prefix) = current_name.strip_suffix(".resume.current") {
        format!("{prefix}.blocks.current")
    } else if let Some(prefix) = current_name.strip_suffix(".resume") {
        format!("{prefix}.blocks.current")
    } else if let Some(prefix) = current_name.strip_suffix(".current") {
        format!("{prefix}.blocks.current")
    } else {
        format!("{current_name}.blocks.current")
    };
    resume::generation_paths(&resume.current.with_file_name(block_name))
}

fn encode(value: &BlockHashManifest) -> Result<Vec<u8>, String> {
    value.validate()?;
    resume::encode_framed(&BLOCK_HASH_MAGIC, value, "block-hash-sidecar-too-large")
}

fn decode(input: &[u8]) -> Result<BlockHashManifest, String> {
    let value: BlockHashManifest =
        resume::decode_framed(&BLOCK_HASH_MAGIC, input, "block-hash-sidecar-corrupt")?;
    value.validate()?;
    Ok(value)
}

pub async fn write_atomic(
    resume_path: &Path,
    manifest: &BlockHashManifest,
    fault: Option<CheckpointFault>,
) -> Result<usize, String> {
    let bytes = encode(manifest)?;
    let size = bytes.len();
    resume::promote_bytes(
        &block_generation_paths(resume_path),
        &bytes,
        |candidate| decode(candidate).map(|_| ()),
        fault,
        "block-hash",
    )
    .await?;
    Ok(size)
}

pub async fn write_atomic_authenticated(
    resume_path: &Path,
    manifest: &BlockHashManifest,
    checkpoint_key: &[u8; 32],
    fault: Option<CheckpointFault>,
) -> Result<usize, String> {
    let bytes = encode(manifest)?;
    let size = bytes.len();
    let invitation_id = manifest.invitation_id;
    resume::promote_bytes(
        &block_generation_paths(resume_path),
        &bytes,
        |candidate| {
            let value = decode(candidate)?;
            let candidate_part_identity = value.part_identity_digest;
            value.verify_security(checkpoint_key, &invitation_id, &candidate_part_identity)
        },
        fault,
        "block-hash",
    )
    .await?;
    Ok(size)
}

#[derive(Debug, Clone)]
pub struct BlockHashSelection {
    pub manifest: Option<BlockHashManifest>,
    pub selected_path: Option<PathBuf>,
    pub encoded_size: usize,
    pub invalid_candidates: Vec<InvalidCheckpointCandidate>,
}

pub async fn load_for_generation(
    resume_path: &Path,
    transfer_id: &[u8; 16],
    generation: u64,
) -> BlockHashSelection {
    let paths = block_generation_paths(resume_path);
    let candidates = [
        (&paths.current, 3u8),
        (&paths.pending, 2u8),
        (&paths.previous, 1u8),
    ];
    let mut valid = Vec::new();
    let mut invalid_candidates = Vec::new();
    for (path, priority) in candidates {
        match fs::read(path).await {
            Ok(bytes) => match decode(&bytes) {
                Ok(manifest)
                    if &manifest.transfer_id == transfer_id
                        && manifest.checkpoint_generation == generation =>
                {
                    valid.push((priority, manifest, path.clone(), bytes.len()));
                }
                Ok(_) => invalid_candidates.push(InvalidCheckpointCandidate {
                    path: path.display().to_string(),
                    error: "block-hash-generation-mismatch".into(),
                }),
                Err(error) => invalid_candidates.push(InvalidCheckpointCandidate {
                    path: path.display().to_string(),
                    error,
                }),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => invalid_candidates.push(InvalidCheckpointCandidate {
                path: path.display().to_string(),
                error: format!("block-hash-sidecar-read-failed: {error}"),
            }),
        }
    }
    valid.sort_by_key(|(priority, _, _, _)| *priority);
    if let Some((_, manifest, selected_path, encoded_size)) = valid.pop() {
        BlockHashSelection {
            manifest: Some(manifest),
            selected_path: Some(selected_path),
            encoded_size,
            invalid_candidates,
        }
    } else {
        BlockHashSelection {
            manifest: None,
            selected_path: None,
            encoded_size: 0,
            invalid_candidates,
        }
    }
}

pub async fn load_for_generation_authenticated(
    resume_path: &Path,
    transfer_id: &[u8; 16],
    invitation_id: &[u8; 16],
    generation: u64,
    part_identity_digest: &[u8; 32],
    expected_sidecar_digest: &[u8; 32],
    checkpoint_key: &[u8; 32],
) -> BlockHashSelection {
    let paths = block_generation_paths(resume_path);
    let candidates = [
        (&paths.current, 3u8),
        (&paths.pending, 2u8),
        (&paths.previous, 1u8),
    ];
    let mut valid = Vec::new();
    let mut invalid_candidates = Vec::new();
    for (path, priority) in candidates {
        match fs::read(path).await {
            Ok(bytes) => {
                let verified = decode(&bytes).and_then(|manifest| {
                    if &manifest.transfer_id != transfer_id
                        || manifest.checkpoint_generation != generation
                    {
                        return Err("block-hash-generation-mismatch".into());
                    }
                    manifest.verify_security(
                        checkpoint_key,
                        invitation_id,
                        part_identity_digest,
                    )?;
                    if &manifest.authenticated_digest()? != expected_sidecar_digest {
                        return Err("checkpoint-authentication-failed".into());
                    }
                    Ok(manifest)
                });
                match verified {
                    Ok(manifest) => valid.push((priority, manifest, path.clone(), bytes.len())),
                    Err(error) => invalid_candidates.push(InvalidCheckpointCandidate {
                        path: path.display().to_string(),
                        error,
                    }),
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => invalid_candidates.push(InvalidCheckpointCandidate {
                path: path.display().to_string(),
                error: "block-hash-sidecar-read-failed".into(),
            }),
        }
    }
    valid.sort_by_key(|(priority, _, _, _)| *priority);
    if let Some((_, manifest, selected_path, encoded_size)) = valid.pop() {
        BlockHashSelection {
            manifest: Some(manifest),
            selected_path: Some(selected_path),
            encoded_size,
            invalid_candidates,
        }
    } else {
        BlockHashSelection {
            manifest: None,
            selected_path: None,
            encoded_size: 0,
            invalid_candidates,
        }
    }
}

pub async fn remove_generations(resume_path: &Path) -> Result<Vec<String>, String> {
    let paths = block_generation_paths(resume_path);
    let mut removed = Vec::new();
    for path in [paths.current, paths.previous, paths.pending] {
        match fs::remove_file(&path).await {
            Ok(()) => removed.push(path.display().to_string()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("block-hash-cleanup-failed: {error}")),
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn sidecar_round_trip_is_generation_bound_and_corruption_detected() {
        let root = std::env::temp_dir().join(format!("flowget-blocks-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).await.unwrap();
        let resume = root.join("transfer.resume.current");
        let transfer = *Uuid::new_v4().as_bytes();
        let manifest =
            from_hashes(transfer, 3, 5, 2, &[Some([1; 32]), None, Some([2; 32])]).unwrap();
        let encoded_size = write_atomic(&resume, &manifest, None).await.unwrap();
        let loaded = load_for_generation(&resume, &transfer, 3).await;
        assert_eq!(loaded.manifest.unwrap(), manifest);
        assert_eq!(loaded.encoded_size, encoded_size);
        let paths = block_generation_paths(&resume);
        let mut bytes = fs::read(&paths.current).await.unwrap();
        bytes[15] ^= 1;
        fs::write(&paths.current, bytes).await.unwrap();
        let corrupt = load_for_generation(&resume, &transfer, 3).await;
        assert!(corrupt.manifest.is_none());
        assert_eq!(corrupt.invalid_candidates.len(), 1);
        let _ = fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn checksum_valid_but_mac_invalid_sidecar_is_rejected() {
        let root = std::env::temp_dir().join(format!("flowget-blocks-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).await.unwrap();
        let resume = root.join("transfer.resume.current");
        let transfer = *Uuid::new_v4().as_bytes();
        let invitation = [4; 16];
        let part_identity = [5; 32];
        let key = [6; 32];
        let mut manifest =
            from_hashes(transfer, 3, 5, 2, &[Some([1; 32]), None, Some([2; 32])]).unwrap();
        manifest
            .authenticate(invitation, part_identity, &key)
            .unwrap();
        write_atomic_authenticated(&resume, &manifest, &key, None)
            .await
            .unwrap();
        let loaded = load_for_generation_authenticated(
            &resume,
            &transfer,
            &invitation,
            3,
            &part_identity,
            &manifest.authenticated_digest().unwrap(),
            &key,
        )
        .await;
        assert!(loaded.manifest.is_some());

        let mut tampered = manifest;
        tampered.entries[0].digest[0] ^= 1;
        fs::write(
            block_generation_paths(&resume).current,
            encode(&tampered).unwrap(),
        )
        .await
        .unwrap();
        let rejected = load_for_generation_authenticated(
            &resume,
            &transfer,
            &invitation,
            3,
            &part_identity,
            &tampered.authenticated_digest().unwrap(),
            &key,
        )
        .await;
        assert!(rejected.manifest.is_none());
        assert!(rejected
            .invalid_candidates
            .iter()
            .any(|value| value.error == "checkpoint-authentication-failed"));
        let _ = fs::remove_dir_all(root).await;
    }

    #[test]
    fn block_sidecar_decoder_rejects_random_and_truncated_frames() {
        let manifest =
            from_hashes([1; 16], 3, 5, 2, &[Some([1; 32]), None, Some([2; 32])]).unwrap();
        let valid = encode(&manifest).unwrap();
        for length in 0..valid.len() {
            assert!(decode(&valid[..length]).is_err());
        }
        let mut state = 0xa5a5_5a5a_dead_beefu64;
        for length in 0..1024usize {
            let mut input = vec![0u8; length];
            for byte in &mut input {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            let _ = decode(&input);
        }
    }
}
