use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeQuicMetrics {
    pub event: &'static str,
    pub benchmark_id: String,
    pub mode: String,
    pub payload_bytes: u64,
    pub wire_bytes: u64,
    pub elapsed_seconds: f64,
    pub sender_mbps: f64,
    pub receiver_mbps: f64,
    pub stream_count: u8,
    pub block_bytes: usize,
    pub rtt_ms: f64,
    pub congestion_window_bytes: u64,
    pub bytes_in_flight: Option<u64>,
    pub lost_packets: u64,
    pub lost_bytes: u64,
    pub retransmitted_bytes: Option<u64>,
    pub mtu: u16,
    pub send_flow_control_blocked_ms: Option<f64>,
    pub receive_flow_control_blocked_ms: Option<f64>,
    pub socket_send_buffer_bytes: Option<u64>,
    pub socket_receive_buffer_bytes: Option<u64>,
    pub cpu_percent: Option<f64>,
    pub memory_pool_bytes: u64,
    pub integrity_status: String,
    pub fingerprint_sha256: String,
    pub limitation: String,
}
