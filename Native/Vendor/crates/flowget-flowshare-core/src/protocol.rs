use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const NATIVE_QUIC_PROTOCOL_VERSION: u16 = 3;
pub const RANGE_MAGIC: [u8; 4] = *b"FQRG";
pub const RANGE_HEADER_BYTES: usize = 4 + 2 + 16 + 4 + 8 + 8 + 2;
pub const RESUME_CAP_BLOCK_SHA256: u64 = 1 << 0;
pub const RESUME_CAP_MISSING_RANGES: u64 = 1 << 1;
pub const RESUME_CAP_NEW_SESSION: u64 = 1 << 2;
pub const RESUME_REQUIRED_CAPABILITIES: u64 =
    RESUME_CAP_BLOCK_SHA256 | RESUME_CAP_MISSING_RANGES | RESUME_CAP_NEW_SESSION;
pub const MAX_MISSING_RANGES: usize = 1_000_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MissingBlockRange {
    pub start_block: u64,
    pub block_count: u64,
}

pub fn missing_block_ranges(
    completed_bitmap: &[u8],
    total_blocks: u64,
) -> Result<Vec<MissingBlockRange>, ProtocolError> {
    if completed_bitmap.len() != total_blocks.div_ceil(8) as usize {
        return Err(ProtocolError::InvalidResumeState);
    }
    let mut output = Vec::new();
    let mut cursor = 0u64;
    while cursor < total_blocks {
        if completed_bitmap[(cursor / 8) as usize] & (1 << (cursor % 8)) != 0 {
            cursor += 1;
            continue;
        }
        let start = cursor;
        while cursor < total_blocks
            && completed_bitmap[(cursor / 8) as usize] & (1 << (cursor % 8)) == 0
        {
            cursor += 1;
        }
        output.push(MissingBlockRange {
            start_block: start,
            block_count: cursor - start,
        });
        if output.len() > MAX_MISSING_RANGES {
            return Err(ProtocolError::InvalidResumeState);
        }
    }
    Ok(output)
}

pub fn validate_missing_ranges(
    ranges: &[MissingBlockRange],
    total_blocks: u64,
) -> Result<u64, ProtocolError> {
    if ranges.len() > MAX_MISSING_RANGES {
        return Err(ProtocolError::InvalidResumeState);
    }
    let mut prior_end = 0u64;
    let mut missing = 0u64;
    for (index, range) in ranges.iter().enumerate() {
        let end = range
            .start_block
            .checked_add(range.block_count)
            .ok_or(ProtocolError::InvalidResumeState)?;
        if range.block_count == 0
            || end > total_blocks
            || (index != 0 && range.start_block <= prior_end)
        {
            return Err(ProtocolError::InvalidResumeState);
        }
        missing = missing
            .checked_add(range.block_count)
            .ok_or(ProtocolError::InvalidResumeState)?;
        prior_end = end;
    }
    Ok(missing)
}

pub fn resume_state_digest(total_blocks: u64, completed_bitmap: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(NATIVE_QUIC_PROTOCOL_VERSION.to_be_bytes());
    hash.update(total_blocks.to_be_bytes());
    hash.update(completed_bitmap);
    hash.finalize().into()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResumeBinding {
    pub version: u16,
    pub transfer_id: [u8; 16],
    pub session_id: String,
    pub checkpoint_generation: u64,
    pub file_size: u64,
    pub block_size: u64,
    pub total_blocks: u64,
    pub expected_sha256: [u8; 32],
    pub state_digest: [u8; 32],
    pub capabilities: u64,
}

impl ResumeBinding {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != NATIVE_QUIC_PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        if self.session_id.is_empty()
            || self.block_size == 0
            || self.total_blocks != self.file_size.div_ceil(self.block_size)
        {
            return Err(ProtocolError::InvalidResumeState);
        }
        if self.capabilities & RESUME_REQUIRED_CAPABILITIES != RESUME_REQUIRED_CAPABILITIES {
            return Err(ProtocolError::ResumeDowngrade);
        }
        Ok(())
    }

    pub fn validate_matches(&self, expected: &Self) -> Result<(), ProtocolError> {
        self.validate()?;
        expected.validate()?;
        if self.transfer_id != expected.transfer_id {
            return Err(ProtocolError::WrongTransfer);
        }
        if self.session_id != expected.session_id {
            return Err(ProtocolError::WrongSession);
        }
        if self.checkpoint_generation != expected.checkpoint_generation {
            return Err(ProtocolError::StaleCheckpoint);
        }
        if self.file_size != expected.file_size
            || self.block_size != expected.block_size
            || self.total_blocks != expected.total_blocks
            || self.expected_sha256 != expected.expected_sha256
            || self.state_digest != expected.state_digest
        {
            return Err(ProtocolError::ResumeMismatch);
        }
        if self.capabilities != expected.capabilities {
            return Err(ProtocolError::ResumeDowngrade);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResumeOffer {
    pub binding: ResumeBinding,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResumeState {
    pub binding: ResumeBinding,
    pub missing_ranges: Vec<MissingBlockRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResumeAccept {
    pub binding: ResumeBinding,
    pub missing_range_count: u64,
    pub stream_count: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResumeReject {
    pub version: u16,
    pub transfer_id: [u8; 16],
    pub session_id: String,
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResumeCompletionManifest {
    pub binding: ResumeBinding,
    pub transferred_blocks: u64,
    pub transferred_bytes: u64,
    pub final_sha256: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResumeCompletionAck {
    pub binding: ResumeBinding,
    pub complete_blocks: u64,
    pub received_bytes: u64,
    pub integrity_ok: bool,
    pub final_sha256: [u8; 32],
    pub cleanup_warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "payload", rename_all = "kebab-case")]
pub enum ResumeControlMessage {
    Offer(ResumeOffer),
    State(ResumeState),
    Accept(ResumeAccept),
    Reject(ResumeReject),
    CompletionManifest(ResumeCompletionManifest),
    CompletionAck(ResumeCompletionAck),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SessionControl {
    pub version: u16,
    pub share_id: String,
    pub transfer_id: [u8; 16],
    pub session_id: String,
    pub file_id: String,
    pub file_name: String,
    pub file_size: u64,
    pub modified_unix_ms: Option<u64>,
    pub stream_count: u8,
    pub range_bytes: u64,
    pub integrity_algorithm: String,
    pub capabilities: u64,
    pub resume_supported: bool,
    pub expires_unix_ms: u64,
}

impl SessionControl {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != NATIVE_QUIC_PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        if self.share_id.is_empty()
            || self.session_id.is_empty()
            || self.file_id.is_empty()
            || self.file_name.is_empty()
        {
            return Err(ProtocolError::Malformed("required session field is empty"));
        }
        if self.file_name.contains(['/', '\\']) || matches!(self.stream_count, 0 | 3 | 5..=u8::MAX)
        {
            return Err(ProtocolError::Malformed(
                "invalid file name or stream count",
            ));
        }
        if self.range_bytes == 0 {
            return Err(ProtocolError::Malformed("range size is zero"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeHeader {
    pub transfer_id: [u8; 16],
    pub range_id: u32,
    pub offset: u64,
    pub length: u64,
    pub flags: u16,
}

impl RangeHeader {
    pub fn encode(&self) -> [u8; RANGE_HEADER_BYTES] {
        let mut output = [0u8; RANGE_HEADER_BYTES];
        output[0..4].copy_from_slice(&RANGE_MAGIC);
        output[4..6].copy_from_slice(&NATIVE_QUIC_PROTOCOL_VERSION.to_be_bytes());
        output[6..22].copy_from_slice(&self.transfer_id);
        output[22..26].copy_from_slice(&self.range_id.to_be_bytes());
        output[26..34].copy_from_slice(&self.offset.to_be_bytes());
        output[34..42].copy_from_slice(&self.length.to_be_bytes());
        output[42..44].copy_from_slice(&self.flags.to_be_bytes());
        output
    }

    pub fn decode(input: &[u8]) -> Result<Self, ProtocolError> {
        if input.len() != RANGE_HEADER_BYTES {
            return Err(ProtocolError::Malformed("invalid range header length"));
        }
        if input[0..4] != RANGE_MAGIC {
            return Err(ProtocolError::Malformed("invalid range magic"));
        }
        let version = u16::from_be_bytes([input[4], input[5]]);
        if version != NATIVE_QUIC_PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }
        let mut transfer_id = [0u8; 16];
        transfer_id.copy_from_slice(&input[6..22]);
        Ok(Self {
            transfer_id,
            range_id: u32::from_be_bytes(input[22..26].try_into().unwrap()),
            offset: u64::from_be_bytes(input[26..34].try_into().unwrap()),
            length: u64::from_be_bytes(input[34..42].try_into().unwrap()),
            flags: u16::from_be_bytes(input[42..44].try_into().unwrap()),
        })
    }

    pub fn validate(
        &self,
        expected_transfer: &[u8; 16],
        file_size: u64,
    ) -> Result<(), ProtocolError> {
        if &self.transfer_id != expected_transfer {
            return Err(ProtocolError::WrongTransfer);
        }
        if self.length == 0
            || self
                .offset
                .checked_add(self.length)
                .is_none_or(|end| end > file_size)
        {
            return Err(ProtocolError::OutOfBounds);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompletionManifest {
    pub version: u16,
    pub transfer_id: [u8; 16],
    pub expected_bytes: u64,
    pub expected_ranges: u32,
    pub sha256: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompletionAck {
    pub version: u16,
    pub transfer_id: [u8; 16],
    pub received_bytes: u64,
    pub completed_ranges: Vec<u32>,
    pub missing_ranges: Vec<u32>,
    pub integrity_ok: bool,
}

#[derive(Debug, Default)]
pub struct RangeLedger {
    ranges: BTreeMap<u64, (u64, u32)>,
    received_bytes: u64,
    finalized: bool,
}

impl RangeLedger {
    pub fn record(
        &mut self,
        header: &RangeHeader,
        actual_length: u64,
    ) -> Result<(), ProtocolError> {
        if self.finalized {
            return Err(ProtocolError::PayloadAfterFinalization);
        }
        if actual_length != header.length {
            return Err(ProtocolError::LengthMismatch);
        }
        let end = header.offset + header.length;
        if let Some((&start, &(length, id))) = self.ranges.range(..=header.offset).next_back() {
            if start + length > header.offset {
                return if start == header.offset && length == header.length && id == header.range_id
                {
                    Err(ProtocolError::DuplicateRange)
                } else {
                    Err(ProtocolError::OverlappingRange)
                };
            }
        }
        if self.ranges.range(header.offset..end).next().is_some() {
            return Err(ProtocolError::OverlappingRange);
        }
        self.ranges
            .insert(header.offset, (header.length, header.range_id));
        self.received_bytes += header.length;
        Ok(())
    }

    pub fn finalize(
        &mut self,
        manifest: &CompletionManifest,
        file_size: u64,
    ) -> Result<(), ProtocolError> {
        if manifest.version != NATIVE_QUIC_PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(manifest.version));
        }
        if manifest.expected_bytes != file_size
            || self.received_bytes != file_size
            || self.ranges.len() != manifest.expected_ranges as usize
        {
            return Err(ProtocolError::IncompleteTransfer);
        }
        let mut cursor = 0u64;
        for (&offset, &(length, _)) in &self.ranges {
            if offset != cursor {
                return Err(ProtocolError::IncompleteTransfer);
            }
            cursor += length;
        }
        if cursor != file_size {
            return Err(ProtocolError::IncompleteTransfer);
        }
        self.finalized = true;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    Malformed(&'static str),
    UnsupportedVersion(u16),
    WrongTransfer,
    OutOfBounds,
    LengthMismatch,
    DuplicateRange,
    OverlappingRange,
    IncompleteTransfer,
    PayloadAfterFinalization,
    InvalidResumeState,
    WrongSession,
    StaleCheckpoint,
    ResumeMismatch,
    ResumeDowngrade,
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ProtocolError {}

#[cfg(test)]
mod tests {
    use super::*;
    fn header(id: u32, offset: u64, length: u64) -> RangeHeader {
        RangeHeader {
            transfer_id: [7; 16],
            range_id: id,
            offset,
            length,
            flags: 0,
        }
    }

    #[test]
    fn range_header_round_trip_and_rejections() {
        let value = header(9, u32::MAX as u64 + 20, 4096);
        assert_eq!(RangeHeader::decode(&value.encode()).unwrap(), value);
        assert!(matches!(
            RangeHeader::decode(&value.encode()[..20]),
            Err(ProtocolError::Malformed(_))
        ));
        assert!(matches!(
            value.validate(&[8; 16], u64::MAX),
            Err(ProtocolError::WrongTransfer)
        ));
        assert!(matches!(
            header(1, 90, 20).validate(&[7; 16], 100),
            Err(ProtocolError::OutOfBounds)
        ));
    }

    #[test]
    fn ledger_rejects_duplicates_overlaps_missing_and_payload_after_completion() {
        let mut ledger = RangeLedger::default();
        ledger.record(&header(0, 0, 50), 50).unwrap();
        assert_eq!(
            ledger.record(&header(0, 0, 50), 50),
            Err(ProtocolError::DuplicateRange)
        );
        assert_eq!(
            ledger.record(&header(1, 40, 20), 20),
            Err(ProtocolError::OverlappingRange)
        );
        let incomplete = CompletionManifest {
            version: NATIVE_QUIC_PROTOCOL_VERSION,
            transfer_id: [7; 16],
            expected_bytes: 100,
            expected_ranges: 2,
            sha256: None,
        };
        assert_eq!(
            ledger.finalize(&incomplete, 100),
            Err(ProtocolError::IncompleteTransfer)
        );
        ledger.record(&header(1, 50, 50), 50).unwrap();
        ledger.finalize(&incomplete, 100).unwrap();
        assert_eq!(
            ledger.record(&header(2, 100, 1), 1),
            Err(ProtocolError::PayloadAfterFinalization)
        );
    }

    #[test]
    fn ledger_rejects_declared_length_mismatch() {
        assert_eq!(
            RangeLedger::default().record(&header(0, 0, 10), 9),
            Err(ProtocolError::LengthMismatch)
        );
    }

    #[test]
    fn missing_ranges_are_compact_and_strictly_validated() {
        let bitmap = [0b0000_1111u8, 0b0000_0011];
        let ranges = missing_block_ranges(&bitmap, 12).unwrap();
        assert_eq!(
            ranges,
            vec![
                MissingBlockRange {
                    start_block: 4,
                    block_count: 4,
                },
                MissingBlockRange {
                    start_block: 10,
                    block_count: 2,
                }
            ]
        );
        assert_eq!(validate_missing_ranges(&ranges, 12).unwrap(), 6);
        assert!(validate_missing_ranges(
            &[
                MissingBlockRange {
                    start_block: 4,
                    block_count: 3,
                },
                MissingBlockRange {
                    start_block: 6,
                    block_count: 1,
                }
            ],
            12
        )
        .is_err());
    }

    #[test]
    fn randomized_missing_range_round_trips_are_bounded_and_exact() {
        let mut state = 0x6a09_e667_f3bc_c909u64;
        for total_blocks in 0..1024u64 {
            let mut bitmap = vec![0u8; total_blocks.div_ceil(8) as usize];
            for byte in &mut bitmap {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            if let Some(last) = bitmap.last_mut() {
                let used = total_blocks % 8;
                if used != 0 {
                    *last &= (1u8 << used) - 1;
                }
            }
            let expected_missing = (0..total_blocks)
                .filter(|block| bitmap[(*block / 8) as usize] & (1 << (*block % 8)) == 0)
                .count() as u64;
            let ranges = missing_block_ranges(&bitmap, total_blocks).unwrap();
            assert!(ranges.len() <= total_blocks as usize);
            assert_eq!(
                validate_missing_ranges(&ranges, total_blocks).unwrap(),
                expected_missing
            );
        }
    }

    #[test]
    fn resume_binding_rejects_stale_mismatched_and_downgraded_sessions() {
        let expected = ResumeBinding {
            version: NATIVE_QUIC_PROTOCOL_VERSION,
            transfer_id: [4; 16],
            session_id: "new-session".into(),
            checkpoint_generation: 7,
            file_size: 8 * 1024 * 1024,
            block_size: 2 * 1024 * 1024,
            total_blocks: 4,
            expected_sha256: [9; 32],
            state_digest: [3; 32],
            capabilities: RESUME_REQUIRED_CAPABILITIES,
        };
        expected.validate_matches(&expected).unwrap();
        let mut stale = expected.clone();
        stale.checkpoint_generation -= 1;
        assert_eq!(
            stale.validate_matches(&expected),
            Err(ProtocolError::StaleCheckpoint)
        );
        let mut wrong_hash = expected.clone();
        wrong_hash.expected_sha256[0] ^= 1;
        assert_eq!(
            wrong_hash.validate_matches(&expected),
            Err(ProtocolError::ResumeMismatch)
        );
        let mut downgraded = expected.clone();
        downgraded.capabilities &= !RESUME_CAP_BLOCK_SHA256;
        assert_eq!(
            downgraded.validate_matches(&expected),
            Err(ProtocolError::ResumeDowngrade)
        );
    }
}
