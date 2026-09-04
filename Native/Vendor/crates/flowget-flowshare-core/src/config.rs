use quinn::{TransportConfig, VarInt};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeQuicConfig {
    pub stream_count: u8,
    pub block_bytes: usize,
    pub connection_window_bytes: u64,
    pub stream_window_bytes: u64,
    pub send_window_bytes: u64,
    pub keep_alive_seconds: u64,
    pub buffer_pool_blocks: usize,
}

impl NativeQuicConfig {
    pub fn desktop(stream_count: u8) -> Result<Self, String> {
        if !matches!(stream_count, 1 | 2 | 4 | 8) {
            return Err("Native QUIC stream count must be 1, 2, 4, or 8.".into());
        }
        Ok(Self {
            stream_count,
            block_bytes: 2 * 1024 * 1024,
            connection_window_bytes: 256 * 1024 * 1024,
            stream_window_bytes: 64 * 1024 * 1024,
            send_window_bytes: 256 * 1024 * 1024,
            keep_alive_seconds: 10,
            buffer_pool_blocks: (stream_count as usize * 2).max(8),
        })
    }

    pub fn transport(&self) -> Result<Arc<TransportConfig>, String> {
        let mut transport = TransportConfig::default();
        transport
            .max_concurrent_bidi_streams(VarInt::from_u32(4))
            .max_concurrent_uni_streams(VarInt::from_u32(16))
            .receive_window(
                VarInt::from_u64(self.connection_window_bytes).map_err(|e| e.to_string())?,
            )
            .stream_receive_window(
                VarInt::from_u64(self.stream_window_bytes).map_err(|e| e.to_string())?,
            )
            .send_window(self.send_window_bytes)
            .keep_alive_interval(Some(Duration::from_secs(self.keep_alive_seconds)))
            .enable_segmentation_offload(true);
        Ok(Arc::new(transport))
    }
}
