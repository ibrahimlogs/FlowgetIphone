use crate::{
    adapters::{LifecycleEventSink, PlatformFileAccess},
    lifecycle::TransferState,
    protocol::NATIVE_QUIC_PROTOCOL_VERSION,
};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRequest {
    pub transfer_id: String,
    pub source_handle: String,
    pub destination_handle: String,
    pub start_offset: u64,
    pub total_bytes: u64,
    pub block_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferReceipt {
    pub transfer_id: String,
    pub bytes_written: u64,
    pub sha256: [u8; 32],
    pub protocol_version: u16,
}

/// Adapter-driven transfer primitive used by mobile bindings and deterministic
/// tests. QUIC framing/authentication continues to use the frozen v3 modules.
pub async fn transfer_via_adapters<F: PlatformFileAccess, E: LifecycleEventSink>(
    files: &F,
    events: &E,
    request: &TransferRequest,
) -> Result<TransferReceipt, String> {
    if request.block_bytes == 0 || request.total_bytes < request.start_offset {
        return Err("flowshare-transfer-request-invalid".into());
    }
    events.state_changed(&request.transfer_id, TransferState::Transferring);
    let mut offset = request.start_offset;
    let mut hash = Sha256::new();
    while offset < request.total_bytes {
        let remaining = request.total_bytes - offset;
        let length = remaining.min(request.block_bytes as u64) as usize;
        let bytes = files
            .read_range(&request.source_handle, offset, length)
            .await?;
        if bytes.len() != length {
            return Err("flowshare-source-short-read".into());
        }
        files
            .write_range(&request.destination_handle, offset, &bytes)
            .await?;
        hash.update(&bytes);
        offset += bytes.len() as u64;
        events.progress(&request.transfer_id, offset, request.total_bytes);
    }
    files.sync(&request.destination_handle).await?;
    events.state_changed(&request.transfer_id, TransferState::Completed);
    Ok(TransferReceipt {
        transfer_id: request.transfer_id.clone(),
        bytes_written: offset - request.start_offset,
        sha256: hash.finalize().into(),
        protocol_version: NATIVE_QUIC_PROTOCOL_VERSION,
    })
}
