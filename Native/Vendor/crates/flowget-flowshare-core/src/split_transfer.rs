use super::{
    authorization,
    config::NativeQuicConfig,
    connectivity::NominatedPathContext,
    cross_device::{
        IncomingNativeState, IncomingNativeTransfer, LocalStopIntent, OutgoingNativeState,
        OutgoingNativeTransfer,
    },
    protocol::{CompletionManifest, RangeHeader, RangeLedger, RANGE_HEADER_BYTES},
    secure_protocol::{
        self, SecureControlChannel, SecureSessionMode, MESSAGE_COMPLETION_ACK,
        MESSAGE_COMPLETION_MANIFEST, MESSAGE_TRANSFER_CANCEL, MESSAGE_TRANSFER_CANCEL_ACK,
        MESSAGE_TRANSFER_METADATA, MESSAGE_TRANSFER_PAUSED, MESSAGE_TRANSFER_PAUSE_ACCEPT,
        MESSAGE_TRANSFER_PAUSE_REQUEST, MESSAGE_TRANSFER_STATUS, MESSAGE_TRANSFER_STATUS_QUERY,
    },
    signaling::NativeDeviceRole,
};
use quinn::{
    ClientConfig, Connection, ConnectionError, Endpoint, RecvStream, SendStream, ServerConfig,
    VarInt,
};
use rustls::RootCertStore;
use serde::{Deserialize, Serialize};
use sha2_compat::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    fs::{self, File, OpenOptions},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom},
    sync::{mpsc, Mutex},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub const FROZEN_STREAM_COUNT: u8 = 4;
pub const FROZEN_BLOCK_BYTES: usize = 2 * 1024 * 1024;
pub const FROZEN_RECEIVER_BUFFER_COUNT: usize = 16;
pub const FROZEN_WRITE_QUEUE_CAPACITY: usize = 4;

const MAX_CONTROL_FRAME_BYTES: usize = 64 * 1024;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const CLOSE_AUTHENTICATED_PEER_CANCELLED: u32 = 0x430;
const CLOSE_AUTHENTICATED_PEER_PAUSED: u32 = 0x431;

/// Observe the peer's FIN before dropping a receive stream.
///
/// Reading exactly the framed payload length is not sufficient: Quinn sends
/// STOP_SENDING when a RecvStream is dropped before EOF has been observed.
/// On higher-latency paths the FIN can arrive after the final payload byte,
/// which would otherwise make the sender report an interrupted transfer.
pub(crate) async fn require_stream_eof(stream: &mut RecvStream) -> Result<(), String> {
    match stream
        .read_chunk(1, true)
        .await
        .map_err(|_| "transfer-interrupted")?
    {
        None => Ok(()),
        Some(_) => Err("data-stream-trailing-bytes".into()),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SplitFileMetadata {
    transfer_id: [u8; 16],
    invitation_id: [u8; 16],
    display_filename: String,
    file_size: u64,
    block_bytes: u64,
    stream_count: u8,
    expected_sha256: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SplitCompletionAck {
    transfer_id: [u8; 16],
    received_bytes: u64,
    sha256: [u8; 32],
    integrity_ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CancellationControl {
    pub(crate) transfer_id: [u8; 16],
    pub(crate) retain_partial: bool,
    #[serde(default)]
    pub(crate) checkpoint_generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PauseControl {
    pub(crate) transfer_id: [u8; 16],
    pub(crate) request_id: [u8; 16],
    pub(crate) checkpoint_generation: u64,
    pub(crate) state_digest: [u8; 32],
    pub(crate) completed_bytes: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TransferStatusState {
    Transferring,
    Receiving,
    Paused,
    Cancelled,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TransferStatusQuery {
    pub(crate) transfer_id: [u8; 16],
    pub(crate) query_id: [u8; 16],
    pub(crate) session_id: [u8; 16],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TransferStatus {
    pub(crate) transfer_id: [u8; 16],
    pub(crate) query_id: [u8; 16],
    pub(crate) session_id: [u8; 16],
    pub(crate) session_lineage_digest: [u8; 32],
    pub(crate) state: TransferStatusState,
    pub(crate) final_file_completed: bool,
    pub(crate) checkpoint_generation: u64,
    pub(crate) state_digest: [u8; 32],
    pub(crate) completed_bytes: u64,
}

pub(crate) struct AuthenticatedFrame {
    pub(crate) message_type: u16,
    pub(crate) payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitTransferResult {
    pub transfer_id: String,
    pub role: &'static str,
    pub total_bytes: u64,
    pub payload_bytes: u64,
    pub bytes_skipped: u64,
    pub blocks_transferred: u64,
    pub blocks_skipped: u64,
    pub elapsed_seconds: f64,
    pub average_mbps: f64,
    pub rtt_ms: f64,
    pub lost_packets: u64,
    pub congestion_window_bytes: u64,
    pub mtu: u16,
    pub integrity_result: &'static str,
    pub signaling_file_payload_bytes: u64,
}

pub(crate) async fn receiver_server_config(
    record: &IncomingNativeTransfer,
) -> Result<ServerConfig, String> {
    let config = NativeQuicConfig::desktop(FROZEN_STREAM_COUNT)?;
    let identity = record.receiver_identity.lock().await;
    let identity = identity
        .as_ref()
        .ok_or("native-receiver-identity-unavailable")?;
    let mut server = ServerConfig::with_single_cert(
        vec![identity.certificate.clone()],
        identity.private_key.clone_key().into(),
    )
    .map_err(|_| "native-quic-server-config-failed")?;
    server.transport_config(config.transport()?);
    Ok(server)
}

pub(crate) fn sender_client_config(
    record: &OutgoingNativeTransfer,
) -> Result<ClientConfig, String> {
    let config = NativeQuicConfig::desktop(FROZEN_STREAM_COUNT)?;
    let mut roots = RootCertStore::empty();
    roots
        .add(record.receiver_certificate.clone())
        .map_err(|_| "native-quic-receiver-certificate-invalid")?;
    let mut client = ClientConfig::with_root_certificates(Arc::new(roots))
        .map_err(|_| "native-quic-client-config-failed")?;
    client.transport_config(config.transport()?);
    Ok(client)
}

pub(crate) async fn run_outgoing_transfer(
    record: Arc<OutgoingNativeTransfer>,
    endpoint: Endpoint,
    context: NominatedPathContext,
) -> Result<SplitTransferResult, String> {
    if context.role != NativeDeviceRole::Sender {
        return Err("native-connectivity-role-mismatch".into());
    }
    let transfer_id = parse_uuid(&record.transfer_id)?;
    let invitation_id = parse_uuid(&record.invitation_id)?;
    if context.transfer_id != transfer_id {
        return Err("native-connectivity-transfer-mismatch".into());
    }
    let config = NativeQuicConfig::desktop(FROZEN_STREAM_COUNT)?;
    let remote = context.pair.remote_socket_addr();
    let connection = tokio::time::timeout(
        CONNECTION_TIMEOUT,
        endpoint
            .connect(remote, "flowshare-native.local")
            .map_err(|_| "quic-connect-failed")?,
    )
    .await
    .map_err(|_| "quic-connect-failed".to_string())?
    .map_err(|_| "quic-connect-failed")?;
    let result = send_authenticated_file(
        record.clone(),
        connection.clone(),
        context.future_quic_session_id,
        transfer_id,
        invitation_id,
        &config,
    )
    .await;
    if result.is_err() {
        connection.close(VarInt::from_u32(0x401), b"native-outgoing-stopped");
    }
    endpoint.close(VarInt::from_u32(0), b"native-outgoing-finished");
    result
}

pub(crate) async fn run_incoming_transfer(
    record: Arc<IncomingNativeTransfer>,
    endpoint: Endpoint,
    context: NominatedPathContext,
) -> Result<SplitTransferResult, String> {
    if context.role != NativeDeviceRole::Receiver {
        return Err("native-connectivity-role-mismatch".into());
    }
    let transfer_id = parse_uuid(&record.transfer_id)?;
    let invitation_id = parse_uuid(&record.invitation_id)?;
    if context.transfer_id != transfer_id {
        return Err("native-connectivity-transfer-mismatch".into());
    }
    let deadline = Instant::now() + CONNECTION_TIMEOUT;
    let mut rejected = 0u8;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            endpoint.close(VarInt::from_u32(0x402), b"native-listener-timeout");
            return Err("quic-connect-failed".into());
        }
        let incoming = tokio::time::timeout(remaining, endpoint.accept())
            .await
            .map_err(|_| "quic-connect-failed".to_string())?
            .ok_or("quic-connect-failed")?;
        let connection = match incoming.await {
            Ok(connection) => connection,
            Err(_) => {
                rejected = rejected.saturating_add(1);
                if rejected >= 8 {
                    return Err("quic-connect-failed".into());
                }
                continue;
            }
        };
        match receive_authenticated_file(
            record.clone(),
            connection.clone(),
            context.future_quic_session_id,
            transfer_id,
            invitation_id,
        )
        .await
        {
            Ok(result) => {
                endpoint.close(VarInt::from_u32(0), b"native-incoming-finished");
                return Ok(result);
            }
            Err(error)
                if is_authorization_rejection(&error)
                    && rejected < 8
                    && Instant::now() < deadline =>
            {
                rejected = rejected.saturating_add(1);
                connection.close(VarInt::from_u32(0x403), b"unauthorized-native-session");
            }
            Err(error) => {
                let (code, reason): (u32, &[u8]) = match error.as_str() {
                    "native-transfer-cancelled" | "peer-cancelled" => {
                        (CLOSE_AUTHENTICATED_PEER_CANCELLED, b"authenticated-cancel")
                    }
                    "native-transfer-paused" => {
                        (CLOSE_AUTHENTICATED_PEER_PAUSED, b"authenticated-pause")
                    }
                    _ => (0x404, b"native-incoming-stopped"),
                };
                endpoint.close(VarInt::from_u32(code), reason);
                return Err(error);
            }
        }
    }
}

async fn send_authenticated_file(
    record: Arc<OutgoingNativeTransfer>,
    connection: Connection,
    session_id: [u8; 16],
    transfer_id: [u8; 16],
    invitation_id: [u8; 16],
    config: &NativeQuicConfig,
) -> Result<SplitTransferResult, String> {
    let started = Instant::now();
    let data_streams = active_streams(record.file_size, config.stream_count);
    let transfer_commitment = secure_protocol::transfer_commitment(
        record.file_size,
        &record.expected_sha256,
        config.block_bytes as u64,
        record.file_size.div_ceil(config.block_bytes as u64),
        super::protocol::RESUME_REQUIRED_CAPABILITIES,
    );
    let (control_send, mut peer_recv) = connection
        .open_bi()
        .await
        .map_err(|_| "secure-handshake-failed")?;
    let control_send = Arc::new(Mutex::new(control_send));
    let mut control_send_guard = control_send.lock().await;
    let prepared = authorization::prepare_client_handshake(
        transfer_id,
        session_id,
        SecureSessionMode::NewTransfer,
        0,
        [0; 32],
        transfer_commitment,
        secure_protocol::session_lineage_digest(None),
        record.receiver_certificate_fingerprint_sha256,
        super::protocol::RESUME_REQUIRED_CAPABILITIES,
    )?;
    let security = super::secure_transport::authenticate_client(
        &connection,
        &mut control_send_guard,
        &mut peer_recv,
        prepared,
    )
    .await
    .map_err(|_| "secure-handshake-failed")?;
    drop(control_send_guard);
    let channel = Arc::new(Mutex::new(security.control));
    let metadata = SplitFileMetadata {
        transfer_id,
        invitation_id,
        display_filename: record.display_filename.clone(),
        file_size: record.file_size,
        block_bytes: config.block_bytes as u64,
        stream_count: data_streams,
        expected_sha256: record.expected_sha256,
    };
    send_authenticated(
        &control_send,
        &channel,
        MESSAGE_TRANSFER_METADATA,
        &serde_json::to_vec(&metadata).map_err(|_| "transfer-metadata-invalid")?,
    )
    .await?;
    {
        let mut mutable = record.mutable.lock().await;
        if mutable.state != OutgoingNativeState::Cancelled
            && mutable.state != OutgoingNativeState::Paused
        {
            mutable.state = OutgoingNativeState::Transferring;
        }
    }
    let cancellation = record.mutable.lock().await.cancellation.clone();
    let peer_cancel = CancellationToken::new();
    let peer_pause = CancellationToken::new();
    let (frame_tx, mut frame_rx) = mpsc::channel(16);
    let reader = tokio::spawn(read_authenticated_frames(
        peer_recv,
        channel.clone(),
        frame_tx,
        &[
            MESSAGE_TRANSFER_CANCEL,
            MESSAGE_TRANSFER_CANCEL_ACK,
            MESSAGE_TRANSFER_PAUSE_REQUEST,
            MESSAGE_TRANSFER_PAUSE_ACCEPT,
            MESSAGE_TRANSFER_PAUSED,
            MESSAGE_COMPLETION_ACK,
            MESSAGE_TRANSFER_STATUS_QUERY,
            MESSAGE_TRANSFER_STATUS,
        ],
    ));
    let mut cancellation_monitor = spawn_cancellation_monitor_outgoing(
        record.clone(),
        control_send.clone(),
        channel.clone(),
        transfer_id,
    );
    let mut send_tasks = Vec::new();
    for index in 0..data_streams {
        let mut stream = connection
            .open_uni()
            .await
            .map_err(|_| "transfer-interrupted")?;
        let input = record.source_path.clone();
        let task_record = record.clone();
        let local_cancel = cancellation.clone();
        let remote_cancel = peer_cancel.clone();
        let remote_pause = peer_pause.clone();
        let block_bytes = config.block_bytes;
        let (offset, length) = range_for(record.file_size, data_streams, index);
        send_tasks.push(tokio::spawn(async move {
            let header = RangeHeader {
                transfer_id,
                range_id: index as u32,
                offset,
                length,
                flags: 0,
            };
            stream
                .write_all(&header.encode())
                .await
                .map_err(|_| "transfer-interrupted")?;
            let mut file = File::open(input).await.map_err(|_| "sender-read-failed")?;
            file.seek(SeekFrom::Start(offset))
                .await
                .map_err(|_| "sender-read-failed")?;
            let mut buffer = vec![0u8; block_bytes];
            let mut remaining = length;
            while remaining != 0 {
                if local_cancel.is_cancelled()
                    || remote_cancel.is_cancelled()
                    || remote_pause.is_cancelled()
                {
                    let _ = stream.reset(VarInt::from_u32(0x405));
                    return Err("native-transfer-cancelled".to_string());
                }
                let wanted = remaining.min(block_bytes as u64) as usize;
                file.read_exact(&mut buffer[..wanted])
                    .await
                    .map_err(|_| "sender-read-failed")?;
                stream
                    .write_all(&buffer[..wanted])
                    .await
                    .map_err(|_| "transfer-interrupted")?;
                task_record.mutable.lock().await.bytes_sent += wanted as u64;
                remaining -= wanted as u64;
            }
            stream.finish().map_err(|_| "transfer-interrupted")?;
            match stream.stopped().await.map_err(|_| "transfer-interrupted")? {
                None => {}
                Some(_) => return Err("transfer-interrupted".into()),
            }
            Ok::<u64, String>(length)
        }));
    }
    let mut send_join = Box::pin(join_byte_tasks(send_tasks));
    let mut peer_checkpoint = None;
    let sent = loop {
        tokio::select! {
            result = &mut send_join => {
                match result {
                    Ok(bytes) => break bytes,
                    Err(_error)
                        if cancellation.is_cancelled()
                            || peer_cancel.is_cancelled()
                            || peer_pause.is_cancelled() =>
                    {
                        let intent = record.mutable.lock().await.local_stop;
                        settle_local_stop_monitor(intent, &mut cancellation_monitor).await;
                        if outgoing_pause_requested(&record).await || peer_pause.is_cancelled() {
                            return finish_sender_pause(
                                &record,
                                &control_send,
                                &channel,
                                &mut frame_rx,
                                peer_checkpoint,
                                transfer_id,
                                session_id,
                            )
                            .await;
                        }
                        await_local_cancellation_ack(
                            intent,
                            &control_send,
                            &channel,
                            &mut frame_rx,
                            transfer_id,
                            session_id,
                        )
                        .await;
                        if peer_cancel.is_cancelled() {
                            linger_outgoing_status_queries(
                                &record,
                                &control_send,
                                &channel,
                                &mut frame_rx,
                                transfer_id,
                                session_id,
                            )
                            .await;
                        }
                        reader.abort();
                        return Err(cancellation_error_outgoing(&record).await);
                    }
                    Err(error) => {
                        if let Ok(Some(frame)) = tokio::time::timeout(
                            Duration::from_millis(1_000),
                            frame_rx.recv(),
                        )
                        .await
                        {
                            match frame.message_type {
                                MESSAGE_TRANSFER_CANCEL => {
                                    validate_cancellation(&frame.payload, transfer_id)?;
                                    record.mutable.lock().await.state = OutgoingNativeState::Cancelled;
                                    peer_cancel.cancel();
                                    let _ = send_authenticated(
                                        &control_send,
                                        &channel,
                                        MESSAGE_TRANSFER_CANCEL_ACK,
                                        &frame.payload,
                                    )
                                    .await;
                                    cancellation_monitor.abort();
                                    linger_outgoing_status_queries(
                                        &record,
                                        &control_send,
                                        &channel,
                                        &mut frame_rx,
                                        transfer_id,
                                        session_id,
                                    )
                                    .await;
                                    reader.abort();
                                    return Err("peer-cancelled".into());
                                }
                                MESSAGE_TRANSFER_PAUSE_REQUEST => {
                                    let pause = validate_pause(&frame.payload, transfer_id)?;
                                    record.mutable.lock().await.pause_request_id =
                                        Some(pause.request_id);
                                    peer_pause.cancel();
                                    send_authenticated(
                                        &control_send,
                                        &channel,
                                        MESSAGE_TRANSFER_PAUSE_ACCEPT,
                                        &frame.payload,
                                    )
                                    .await?;
                                    cancellation_monitor.abort();
                                    return finish_sender_pause(
                                        &record,
                                        &control_send,
                                        &channel,
                                        &mut frame_rx,
                                        None,
                                        transfer_id,
                                        session_id,
                                    )
                                    .await;
                                }
                                MESSAGE_TRANSFER_PAUSED => {
                                    let checkpoint = validate_pause(&frame.payload, transfer_id)?;
                                    peer_pause.cancel();
                                    cancellation_monitor.abort();
                                    return finish_sender_pause(
                                        &record,
                                        &control_send,
                                        &channel,
                                        &mut frame_rx,
                                        Some(checkpoint),
                                        transfer_id,
                                        session_id,
                                    )
                                    .await;
                                }
                                _ => {}
                            }
                        }
                        if let Some(error) = authenticated_peer_close_error(&connection) {
                            cancellation_monitor.abort();
                            reader.abort();
                            return Err(error.into());
                        }
                        let _ = tokio::time::timeout(
                            Duration::from_millis(1_200),
                            connection.closed(),
                        )
                        .await;
                        if let Some(error) = authenticated_peer_close_error(&connection) {
                            cancellation_monitor.abort();
                            reader.abort();
                            return Err(error.into());
                        }
                        return Err(error);
                    }
                }
            },
            frame = frame_rx.recv() => {
                let frame = frame.ok_or("transfer-interrupted")?;
                match frame.message_type {
                    MESSAGE_TRANSFER_CANCEL => {
                        validate_cancellation(&frame.payload, transfer_id)?;
                        record.mutable.lock().await.state = OutgoingNativeState::Cancelled;
                        peer_cancel.cancel();
                        send_authenticated(&control_send, &channel, MESSAGE_TRANSFER_CANCEL_ACK, &frame.payload).await?;
                    }
                    MESSAGE_TRANSFER_CANCEL_ACK => {
                        validate_cancellation(&frame.payload, transfer_id)?;
                        if matches!(
                            record.mutable.lock().await.local_stop,
                            Some(LocalStopIntent::Cancel { .. })
                        ) {
                            cancellation.cancel();
                        }
                    }
                    MESSAGE_TRANSFER_PAUSE_REQUEST => {
                        let pause = validate_pause(&frame.payload, transfer_id)?;
                        record.mutable.lock().await.pause_request_id = Some(pause.request_id);
                        peer_pause.cancel();
                        send_authenticated(&control_send, &channel, MESSAGE_TRANSFER_PAUSE_ACCEPT, &frame.payload).await?;
                        if pause.checkpoint_generation != 0 {
                            return Err("authenticated-control-state-invalid".into());
                        }
                    }
                    MESSAGE_TRANSFER_PAUSE_ACCEPT => {
                        let _ = validate_pause(&frame.payload, transfer_id)?;
                        if record.mutable.lock().await.local_stop == Some(LocalStopIntent::Pause) {
                            cancellation.cancel();
                        }
                    }
                    MESSAGE_TRANSFER_PAUSED => {
                        peer_checkpoint = Some(validate_pause(&frame.payload, transfer_id)?);
                        peer_pause.cancel();
                    }
                    MESSAGE_TRANSFER_STATUS_QUERY => {
                        respond_outgoing_status_query(
                            &record,
                            &control_send,
                            &channel,
                            &frame.payload,
                            transfer_id,
                            session_id,
                            secure_protocol::session_lineage_digest(None),
                        )
                        .await?;
                    }
                    _ => return Err("authenticated-control-state-invalid".into()),
                }
            }
        }
    };
    if cancellation.is_cancelled() || peer_cancel.is_cancelled() || peer_pause.is_cancelled() {
        let intent = record.mutable.lock().await.local_stop;
        settle_local_stop_monitor(intent, &mut cancellation_monitor).await;
        if outgoing_pause_requested(&record).await || peer_pause.is_cancelled() {
            return finish_sender_pause(
                &record,
                &control_send,
                &channel,
                &mut frame_rx,
                peer_checkpoint,
                transfer_id,
                session_id,
            )
            .await;
        }
        await_local_cancellation_ack(
            intent,
            &control_send,
            &channel,
            &mut frame_rx,
            transfer_id,
            session_id,
        )
        .await;
        if peer_cancel.is_cancelled() {
            linger_outgoing_status_queries(
                &record,
                &control_send,
                &channel,
                &mut frame_rx,
                transfer_id,
                session_id,
            )
            .await;
        }
        reader.abort();
        return Err(cancellation_error_outgoing(&record).await);
    }
    let current_identity = super::resume::capture_source_identity(&record.source_path).await?;
    if current_identity != record.source_identity {
        cancellation_monitor.abort();
        reader.abort();
        return Err("source-file-changed".into());
    }
    let manifest = CompletionManifest {
        version: super::protocol::NATIVE_QUIC_PROTOCOL_VERSION,
        transfer_id,
        expected_bytes: record.file_size,
        expected_ranges: data_streams as u32,
        sha256: Some(record.expected_sha256),
    };
    if let Err(error) = super::cross_device::claim_outgoing_finalization(&record).await {
        let intent = record.mutable.lock().await.local_stop;
        settle_local_stop_monitor(intent, &mut cancellation_monitor).await;
        if error == "native-transfer-paused" {
            return finish_sender_pause(
                &record,
                &control_send,
                &channel,
                &mut frame_rx,
                peer_checkpoint,
                transfer_id,
                session_id,
            )
            .await;
        }
        await_local_cancellation_ack(
            intent,
            &control_send,
            &channel,
            &mut frame_rx,
            transfer_id,
            session_id,
        )
        .await;
        reader.abort();
        return Err(error);
    }
    send_authenticated(
        &control_send,
        &channel,
        MESSAGE_COMPLETION_MANIFEST,
        &serde_json::to_vec(&manifest).map_err(|_| "completion-manifest-invalid")?,
    )
    .await?;
    let mut status_query_id = None;
    let completion_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let ack = loop {
        let remaining = completion_deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err("completed-ack-lost".into());
        }
        let wait = if status_query_id.is_some() {
            remaining
        } else {
            remaining.min(Duration::from_millis(500))
        };
        let frame = match tokio::time::timeout(wait, frame_rx.recv()).await {
            Ok(Some(frame)) => frame,
            Ok(None) => return Err("completed-ack-lost".into()),
            Err(_) if status_query_id.is_none() => {
                status_query_id = Some(
                    send_status_query(&control_send, &channel, transfer_id, session_id).await?,
                );
                continue;
            }
            Err(_) => return Err("completed-ack-lost".into()),
        };
        match frame.message_type {
            MESSAGE_COMPLETION_ACK => {
                break serde_json::from_slice::<SplitCompletionAck>(&frame.payload)
                    .map_err(|_| "completed-ack-invalid")?;
            }
            MESSAGE_TRANSFER_CANCEL => {
                validate_cancellation(&frame.payload, transfer_id)?;
                record.mutable.lock().await.state = OutgoingNativeState::Cancelled;
                send_authenticated(
                    &control_send,
                    &channel,
                    MESSAGE_TRANSFER_CANCEL_ACK,
                    &frame.payload,
                )
                .await?;
                return Err("peer-cancelled".into());
            }
            MESSAGE_TRANSFER_CANCEL_ACK => {
                validate_cancellation(&frame.payload, transfer_id)?;
                if matches!(
                    record.mutable.lock().await.local_stop,
                    Some(LocalStopIntent::Cancel { .. })
                ) {
                    return Err("native-transfer-cancelled".into());
                }
            }
            MESSAGE_TRANSFER_PAUSE_REQUEST => {
                let _ = validate_pause(&frame.payload, transfer_id)?;
                send_authenticated(
                    &control_send,
                    &channel,
                    MESSAGE_TRANSFER_PAUSE_ACCEPT,
                    &frame.payload,
                )
                .await?;
                return finish_sender_pause(
                    &record,
                    &control_send,
                    &channel,
                    &mut frame_rx,
                    None,
                    transfer_id,
                    session_id,
                )
                .await;
            }
            MESSAGE_TRANSFER_PAUSE_ACCEPT => {
                let _ = validate_pause(&frame.payload, transfer_id)?;
            }
            MESSAGE_TRANSFER_PAUSED => {
                return finish_sender_pause(
                    &record,
                    &control_send,
                    &channel,
                    &mut frame_rx,
                    Some(validate_pause(&frame.payload, transfer_id)?),
                    transfer_id,
                    session_id,
                )
                .await;
            }
            MESSAGE_TRANSFER_STATUS_QUERY => {
                respond_outgoing_status_query(
                    &record,
                    &control_send,
                    &channel,
                    &frame.payload,
                    transfer_id,
                    session_id,
                    secure_protocol::session_lineage_digest(None),
                )
                .await?;
            }
            MESSAGE_TRANSFER_STATUS => {
                let query_id = status_query_id.ok_or("authenticated-status-unexpected")?;
                let status = validate_transfer_status(
                    &frame.payload,
                    transfer_id,
                    query_id,
                    session_id,
                    secure_protocol::session_lineage_digest(None),
                )?;
                if status.state != TransferStatusState::Completed
                    || !status.final_file_completed
                    || status.completed_bytes != record.file_size
                {
                    status_query_id = None;
                    continue;
                }
                break SplitCompletionAck {
                    transfer_id,
                    received_bytes: status.completed_bytes,
                    sha256: record.expected_sha256,
                    integrity_ok: true,
                };
            }
            _ => return Err("authenticated-control-state-invalid".into()),
        }
    };
    cancellation_monitor.abort();
    reader.abort();
    if sent != record.file_size
        || ack.transfer_id != transfer_id
        || ack.received_bytes != record.file_size
        || ack.sha256 != record.expected_sha256
        || !ack.integrity_ok
    {
        return Err("integrity-mismatch".into());
    }
    let _ = authorization::consume(&transfer_id);
    let _ = super::secret_store::delete(&record.authorization_resume_path).await;
    let elapsed = started.elapsed().as_secs_f64().max(0.000_001);
    let stats = connection.stats();
    let result = SplitTransferResult {
        transfer_id: record.transfer_id.clone(),
        role: "sender",
        total_bytes: record.file_size,
        payload_bytes: sent,
        bytes_skipped: 0,
        blocks_transferred: record.file_size.div_ceil(config.block_bytes as u64),
        blocks_skipped: 0,
        elapsed_seconds: elapsed,
        average_mbps: sent as f64 / 1024.0 / 1024.0 / elapsed,
        rtt_ms: stats.path.rtt.as_secs_f64() * 1000.0,
        lost_packets: stats.path.lost_packets,
        congestion_window_bytes: stats.path.cwnd,
        mtu: stats.path.current_mtu,
        integrity_result: "passed",
        signaling_file_payload_bytes: 0,
    };
    println!(
        "[FlowShareNativeSplit] {}",
        serde_json::to_string(&result).unwrap_or_else(|_| "{}".into())
    );
    Ok(result)
}

async fn receive_authenticated_file(
    record: Arc<IncomingNativeTransfer>,
    connection: Connection,
    session_id: [u8; 16],
    transfer_id: [u8; 16],
    invitation_id: [u8; 16],
) -> Result<SplitTransferResult, String> {
    let started = Instant::now();
    let (mut peer_send, mut control_recv) = super::secure_transport::accept_control_stream(
        &connection,
        transfer_id,
        invitation_id,
        session_id,
        0,
    )
    .await?;
    let expected = {
        let mutable = record.mutable.lock().await;
        (
            mutable
                .accepted_filename
                .clone()
                .ok_or("receiver-acceptance-required")?,
            mutable
                .expected_file_size
                .ok_or("receiver-acceptance-required")?,
            mutable
                .expected_sha256
                .ok_or("receiver-acceptance-required")?,
            mutable
                .part_path
                .clone()
                .ok_or("receiver-acceptance-required")?,
            mutable
                .final_path
                .clone()
                .ok_or("receiver-acceptance-required")?,
        )
    };
    let transfer_commitment = secure_protocol::transfer_commitment(
        expected.1,
        &expected.2,
        FROZEN_BLOCK_BYTES as u64,
        expected.1.div_ceil(FROZEN_BLOCK_BYTES as u64),
        super::protocol::RESUME_REQUIRED_CAPABILITIES,
    );
    let security = super::secure_transport::authenticate_server(
        &connection,
        &mut peer_send,
        &mut control_recv,
        transfer_id,
        invitation_id,
        session_id,
        record.receiver_certificate_fingerprint_sha256,
        SecureSessionMode::NewTransfer,
        0,
        [0; 32],
        transfer_commitment,
        secure_protocol::session_lineage_digest(None),
        super::protocol::RESUME_REQUIRED_CAPABILITIES,
    )
    .await?;
    let channel = Arc::new(Mutex::new(security.control));
    let peer_send = Arc::new(Mutex::new(peer_send));
    let metadata_frame =
        read_one_authenticated(&mut control_recv, &channel, &[MESSAGE_TRANSFER_METADATA]).await?;
    let metadata: SplitFileMetadata =
        serde_json::from_slice(&metadata_frame.payload).map_err(|_| "transfer-metadata-invalid")?;
    let expected_streams = active_streams(expected.1, FROZEN_STREAM_COUNT);
    if metadata.transfer_id != transfer_id
        || metadata.invitation_id != invitation_id
        || metadata.display_filename != expected.0
        || metadata.file_size != expected.1
        || metadata.expected_sha256 != expected.2
        || metadata.block_bytes != FROZEN_BLOCK_BYTES as u64
        || metadata.stream_count != expected_streams
    {
        return Err("transfer-metadata-mismatch".into());
    }
    {
        let mut mutable = record.mutable.lock().await;
        if mutable.state != IncomingNativeState::Cancelled
            && mutable.state != IncomingNativeState::Paused
        {
            mutable.state = IncomingNativeState::Receiving;
        }
    }
    let cancellation = record.mutable.lock().await.cancellation.clone();
    let peer_cancel = CancellationToken::new();
    let peer_pause = CancellationToken::new();
    let (frame_tx, mut frame_rx) = mpsc::channel(16);
    let reader = tokio::spawn(read_authenticated_frames(
        control_recv,
        channel.clone(),
        frame_tx,
        &[
            MESSAGE_TRANSFER_CANCEL,
            MESSAGE_TRANSFER_CANCEL_ACK,
            MESSAGE_TRANSFER_PAUSE_REQUEST,
            MESSAGE_TRANSFER_PAUSE_ACCEPT,
            MESSAGE_TRANSFER_PAUSED,
            MESSAGE_COMPLETION_MANIFEST,
            MESSAGE_TRANSFER_STATUS_QUERY,
            MESSAGE_TRANSFER_STATUS,
        ],
    ));
    let mut cancellation_monitor = spawn_cancellation_monitor_incoming(
        record.clone(),
        peer_send.clone(),
        channel.clone(),
        transfer_id,
    );
    let (free_tx, free_rx) = mpsc::channel::<Vec<u8>>(FROZEN_RECEIVER_BUFFER_COUNT);
    for _ in 0..FROZEN_RECEIVER_BUFFER_COUNT {
        free_tx
            .send(vec![0u8; FROZEN_BLOCK_BYTES])
            .await
            .map_err(|_| "receiver-buffer-pool-failed")?;
    }
    let free_rx = Arc::new(Mutex::new(free_rx));
    let mut receive_tasks = Vec::new();
    for _ in 0..metadata.stream_count {
        let mut stream = connection
            .accept_uni()
            .await
            .map_err(|_| "transfer-interrupted")?;
        let output = expected.3.clone();
        let take_pool = free_rx.clone();
        let return_pool = free_tx.clone();
        let task_record = record.clone();
        let local_cancel = cancellation.clone();
        let remote_cancel = peer_cancel.clone();
        let remote_pause = peer_pause.clone();
        receive_tasks.push(tokio::spawn(async move {
            let mut encoded = [0u8; RANGE_HEADER_BYTES];
            stream
                .read_exact(&mut encoded)
                .await
                .map_err(|_| "transfer-interrupted")?;
            let header = RangeHeader::decode(&encoded).map_err(|_| "range-header-invalid")?;
            header
                .validate(&transfer_id, metadata.file_size)
                .map_err(|_| "range-header-invalid")?;
            let (write_tx, mut write_rx) =
                mpsc::channel::<(u64, usize, Vec<u8>)>(FROZEN_WRITE_QUEUE_CAPACITY);
            let writer_pool = return_pool.clone();
            let writer_record = task_record.clone();
            let writer = tokio::spawn(async move {
                let mut file = OpenOptions::new()
                    .write(true)
                    .open(output)
                    .await
                    .map_err(|_| "receiver-write-failed")?;
                let mut expected_offset = None;
                let mut written = 0u64;
                while let Some((offset, valid, buffer)) = write_rx.recv().await {
                    if expected_offset != Some(offset) {
                        file.seek(SeekFrom::Start(offset))
                            .await
                            .map_err(|_| "receiver-write-failed")?;
                    }
                    file.write_all(&buffer[..valid])
                        .await
                        .map_err(|_| "receiver-write-failed")?;
                    {
                        let mut mutable = writer_record.mutable.lock().await;
                        mutable.bytes_written += valid as u64;
                        mutable
                            .committed_intervals
                            .push((offset, offset + valid as u64));
                    }
                    written += valid as u64;
                    expected_offset = Some(offset + valid as u64);
                    writer_pool
                        .send(buffer)
                        .await
                        .map_err(|_| "receiver-buffer-pool-failed")?;
                }
                file.flush().await.map_err(|_| "receiver-write-failed")?;
                Ok::<u64, String>(written)
            });
            let mut remaining = header.length;
            let mut offset = header.offset;
            while remaining != 0 {
                if local_cancel.is_cancelled()
                    || remote_cancel.is_cancelled()
                    || remote_pause.is_cancelled()
                {
                    let _ = stream.stop(VarInt::from_u32(0x406));
                    break;
                }
                let wanted = remaining.min(FROZEN_BLOCK_BYTES as u64) as usize;
                let mut buffer = take_pool
                    .lock()
                    .await
                    .recv()
                    .await
                    .ok_or("receiver-buffer-pool-failed")?;
                stream
                    .read_exact(&mut buffer[..wanted])
                    .await
                    .map_err(|_| "transfer-interrupted")?;
                write_tx
                    .send((offset, wanted, buffer))
                    .await
                    .map_err(|_| "receiver-write-failed")?;
                task_record.mutable.lock().await.bytes_received += wanted as u64;
                offset += wanted as u64;
                remaining -= wanted as u64;
            }
            if remaining == 0 {
                require_stream_eof(&mut stream).await?;
            }
            drop(write_tx);
            let written = writer.await.map_err(|_| "receiver-write-failed")??;
            if local_cancel.is_cancelled()
                || remote_cancel.is_cancelled()
                || remote_pause.is_cancelled()
            {
                return Err("native-transfer-cancelled".into());
            }
            if written != header.length {
                return Err("receiver-short-write".into());
            }
            Ok::<RangeHeader, String>(header)
        }));
    }
    let mut receive_join = Box::pin(join_range_tasks(receive_tasks));
    let mut pending_manifest = None;
    let headers = loop {
        tokio::select! {
            result = &mut receive_join => {
                match result {
                    Ok(headers) => break headers,
                    Err(_error)
                        if cancellation.is_cancelled()
                            || peer_cancel.is_cancelled()
                            || peer_pause.is_cancelled() =>
                    {
                        let intent = record.mutable.lock().await.local_stop;
                        settle_local_stop_monitor(intent, &mut cancellation_monitor).await;
                        if incoming_pause_requested(&record).await || peer_pause.is_cancelled() {
                            return finish_receiver_pause(
                                &record,
                                &peer_send,
                                &channel,
                                &mut frame_rx,
                                transfer_id,
                                invitation_id,
                                session_id,
                            )
                            .await;
                        }
                        await_local_cancellation_ack(
                            intent,
                            &peer_send,
                            &channel,
                            &mut frame_rx,
                            transfer_id,
                            session_id,
                        )
                        .await;
                        if peer_cancel.is_cancelled() {
                            linger_incoming_status_queries(
                                &record,
                                &peer_send,
                                &channel,
                                &mut frame_rx,
                                transfer_id,
                                session_id,
                            )
                            .await;
                        }
                        reader.abort();
                        return Err(cancellation_error_incoming(&record, peer_cancel.is_cancelled()).await);
                    }
                    Err(error) => return Err(error),
                }
            },
            frame = frame_rx.recv() => {
                let frame = frame.ok_or("transfer-interrupted")?;
                match frame.message_type {
                    MESSAGE_TRANSFER_CANCEL => {
                        let control = validate_cancellation(&frame.payload, transfer_id)?;
                        {
                            let mut mutable = record.mutable.lock().await;
                            mutable.state = IncomingNativeState::Cancelled;
                            mutable.peer_cancel_retain_partial = Some(control.retain_partial);
                        }
                        peer_cancel.cancel();
                        send_authenticated(&peer_send, &channel, MESSAGE_TRANSFER_CANCEL_ACK, &frame.payload).await?;
                    }
                    MESSAGE_TRANSFER_CANCEL_ACK => {
                        validate_cancellation(&frame.payload, transfer_id)?;
                        if matches!(
                            record.mutable.lock().await.local_stop,
                            Some(LocalStopIntent::Cancel { .. })
                        ) {
                            cancellation.cancel();
                        }
                    }
                    MESSAGE_TRANSFER_PAUSE_REQUEST => {
                        let pause = validate_pause(&frame.payload, transfer_id)?;
                        record.mutable.lock().await.pause_request_id = Some(pause.request_id);
                        peer_pause.cancel();
                        send_authenticated(&peer_send, &channel, MESSAGE_TRANSFER_PAUSE_ACCEPT, &frame.payload).await?;
                    }
                    MESSAGE_TRANSFER_PAUSE_ACCEPT => {
                        let _ = validate_pause(&frame.payload, transfer_id)?;
                        if record.mutable.lock().await.local_stop == Some(LocalStopIntent::Pause) {
                            cancellation.cancel();
                        }
                    }
                    MESSAGE_TRANSFER_PAUSED => {
                        let _ = validate_pause(&frame.payload, transfer_id)?;
                    }
                    MESSAGE_COMPLETION_MANIFEST => pending_manifest = Some(frame.payload),
                    MESSAGE_TRANSFER_STATUS_QUERY => {
                        respond_incoming_status_query(
                            &record,
                            &peer_send,
                            &channel,
                            &frame.payload,
                            transfer_id,
                            session_id,
                            secure_protocol::session_lineage_digest(None),
                        )
                        .await?;
                    }
                    _ => return Err("authenticated-control-state-invalid".into()),
                }
            }
        }
    };
    if cancellation.is_cancelled() || peer_cancel.is_cancelled() || peer_pause.is_cancelled() {
        let intent = record.mutable.lock().await.local_stop;
        settle_local_stop_monitor(intent, &mut cancellation_monitor).await;
        if incoming_pause_requested(&record).await || peer_pause.is_cancelled() {
            return finish_receiver_pause(
                &record,
                &peer_send,
                &channel,
                &mut frame_rx,
                transfer_id,
                invitation_id,
                session_id,
            )
            .await;
        }
        await_local_cancellation_ack(
            intent,
            &peer_send,
            &channel,
            &mut frame_rx,
            transfer_id,
            session_id,
        )
        .await;
        if peer_cancel.is_cancelled() {
            linger_incoming_status_queries(
                &record,
                &peer_send,
                &channel,
                &mut frame_rx,
                transfer_id,
                session_id,
            )
            .await;
        }
        reader.abort();
        return Err(cancellation_error_incoming(&record, peer_cancel.is_cancelled()).await);
    }
    let manifest_payload = if let Some(value) = pending_manifest {
        value
    } else {
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(30), frame_rx.recv())
                .await
                .map_err(|_| "transfer-interrupted".to_string())?
                .ok_or("transfer-interrupted")?;
            match frame.message_type {
                MESSAGE_COMPLETION_MANIFEST => break frame.payload,
                MESSAGE_TRANSFER_CANCEL => {
                    let control = validate_cancellation(&frame.payload, transfer_id)?;
                    {
                        let mut mutable = record.mutable.lock().await;
                        mutable.state = IncomingNativeState::Cancelled;
                        mutable.peer_cancel_retain_partial = Some(control.retain_partial);
                    }
                    send_authenticated(
                        &peer_send,
                        &channel,
                        MESSAGE_TRANSFER_CANCEL_ACK,
                        &frame.payload,
                    )
                    .await?;
                    linger_incoming_status_queries(
                        &record,
                        &peer_send,
                        &channel,
                        &mut frame_rx,
                        transfer_id,
                        session_id,
                    )
                    .await;
                    return Err("peer-cancelled".into());
                }
                MESSAGE_TRANSFER_CANCEL_ACK => {
                    validate_cancellation(&frame.payload, transfer_id)?;
                    if matches!(
                        record.mutable.lock().await.local_stop,
                        Some(LocalStopIntent::Cancel { .. })
                    ) {
                        return Err("native-transfer-cancelled".into());
                    }
                }
                MESSAGE_TRANSFER_PAUSE_REQUEST => {
                    let pause = validate_pause(&frame.payload, transfer_id)?;
                    record.mutable.lock().await.pause_request_id = Some(pause.request_id);
                    send_authenticated(
                        &peer_send,
                        &channel,
                        MESSAGE_TRANSFER_PAUSE_ACCEPT,
                        &frame.payload,
                    )
                    .await?;
                    return finish_receiver_pause(
                        &record,
                        &peer_send,
                        &channel,
                        &mut frame_rx,
                        transfer_id,
                        invitation_id,
                        session_id,
                    )
                    .await;
                }
                MESSAGE_TRANSFER_PAUSE_ACCEPT | MESSAGE_TRANSFER_PAUSED => {
                    let _ = validate_pause(&frame.payload, transfer_id)?;
                }
                MESSAGE_TRANSFER_STATUS_QUERY => {
                    respond_incoming_status_query(
                        &record,
                        &peer_send,
                        &channel,
                        &frame.payload,
                        transfer_id,
                        session_id,
                        secure_protocol::session_lineage_digest(None),
                    )
                    .await?;
                }
                _ => return Err("authenticated-control-state-invalid".into()),
            }
        }
    };
    let manifest: CompletionManifest =
        serde_json::from_slice(&manifest_payload).map_err(|_| "completion-manifest-invalid")?;
    if manifest.transfer_id != transfer_id || manifest.sha256 != Some(expected.2) {
        return Err("completion-manifest-mismatch".into());
    }
    let mut ledger = RangeLedger::default();
    for header in headers {
        ledger
            .record(&header, header.length)
            .map_err(|_| "range-ledger-invalid")?;
    }
    ledger
        .finalize(&manifest, expected.1)
        .map_err(|_| "incomplete-transfer")?;
    if let Err(error) = super::cross_device::claim_incoming_finalization(&record).await {
        let intent = record.mutable.lock().await.local_stop;
        settle_local_stop_monitor(intent, &mut cancellation_monitor).await;
        if error == "native-transfer-paused" {
            return finish_receiver_pause(
                &record,
                &peer_send,
                &channel,
                &mut frame_rx,
                transfer_id,
                invitation_id,
                session_id,
            )
            .await;
        }
        await_local_cancellation_ack(
            intent,
            &peer_send,
            &channel,
            &mut frame_rx,
            transfer_id,
            session_id,
        )
        .await;
        reader.abort();
        return Err(error);
    }
    super::cross_device::reject_reparse_path(&expected.3).await?;
    let file = OpenOptions::new()
        .write(true)
        .open(&expected.3)
        .await
        .map_err(|_| "receiver-write-failed")?;
    file.sync_all().await.map_err(|_| "receiver-sync-failed")?;
    drop(file);
    let (actual_hash, _) =
        super::file_transfer::sha256_file(&expected.3, FROZEN_BLOCK_BYTES).await?;
    if actual_hash != expected.2 {
        return Err("integrity-mismatch".into());
    }
    if record.mutable.lock().await.cancellation.is_cancelled() {
        return Err("native-transfer-cancelled".into());
    }
    fs::rename(&expected.3, &expected.4)
        .await
        .map_err(|_| "atomic-finalization-failed")?;
    {
        let mut mutable = record.mutable.lock().await;
        mutable.state = IncomingNativeState::Completed;
        mutable.bytes_received = expected.1;
        mutable.bytes_written = expected.1;
        mutable.integrity_result = Some("passed".into());
    }
    let ack = SplitCompletionAck {
        transfer_id,
        received_bytes: expected.1,
        sha256: actual_hash,
        integrity_ok: true,
    };
    if !drop_completion_ack_for_test() {
        send_authenticated(
            &peer_send,
            &channel,
            MESSAGE_COMPLETION_ACK,
            &serde_json::to_vec(&ack).map_err(|_| "completion-ack-invalid")?,
        )
        .await?;
    }
    linger_incoming_status_queries(
        &record,
        &peer_send,
        &channel,
        &mut frame_rx,
        transfer_id,
        session_id,
    )
    .await;
    cancellation_monitor.abort();
    reader.abort();
    let resume_path = record.authorization_resume_path.lock().await.clone();
    let _ = authorization::consume(&transfer_id);
    let _ = super::secret_store::delete(&resume_path).await;
    let elapsed = started.elapsed().as_secs_f64().max(0.000_001);
    let stats = connection.stats();
    let result = SplitTransferResult {
        transfer_id: record.transfer_id.clone(),
        role: "receiver",
        total_bytes: expected.1,
        payload_bytes: expected.1,
        bytes_skipped: 0,
        blocks_transferred: expected.1.div_ceil(FROZEN_BLOCK_BYTES as u64),
        blocks_skipped: 0,
        elapsed_seconds: elapsed,
        average_mbps: expected.1 as f64 / 1024.0 / 1024.0 / elapsed,
        rtt_ms: stats.path.rtt.as_secs_f64() * 1000.0,
        lost_packets: stats.path.lost_packets,
        congestion_window_bytes: stats.path.cwnd,
        mtu: stats.path.current_mtu,
        integrity_result: "passed",
        signaling_file_payload_bytes: 0,
    };
    println!(
        "[FlowShareNativeSplit] {}",
        serde_json::to_string(&result).unwrap_or_else(|_| "{}".into())
    );
    Ok(result)
}

pub(crate) async fn send_authenticated(
    stream: &Arc<Mutex<SendStream>>,
    channel: &Arc<Mutex<SecureControlChannel>>,
    message_type: u16,
    payload: &[u8],
) -> Result<(), String> {
    let envelope = channel.lock().await.seal(message_type, payload)?;
    if envelope.len() > MAX_CONTROL_FRAME_BYTES {
        return Err("authenticated-control-frame-oversized".into());
    }
    let mut stream = stream.lock().await;
    stream
        .write_u32(envelope.len() as u32)
        .await
        .map_err(|_| "transfer-interrupted")?;
    stream
        .write_all(&envelope)
        .await
        .map_err(|_| "transfer-interrupted")?;
    stream
        .flush()
        .await
        .map_err(|_| "transfer-interrupted".to_string())
}

async fn read_one_authenticated(
    stream: &mut RecvStream,
    channel: &Arc<Mutex<SecureControlChannel>>,
    allowed: &'static [u16],
) -> Result<AuthenticatedFrame, String> {
    let length = stream
        .read_u32()
        .await
        .map_err(|_| "transfer-interrupted")? as usize;
    if length == 0 || length > MAX_CONTROL_FRAME_BYTES {
        return Err("authenticated-control-frame-oversized".into());
    }
    let mut envelope = vec![0u8; length];
    stream
        .read_exact(&mut envelope)
        .await
        .map_err(|_| "transfer-interrupted")?;
    let (message_type, payload) = channel.lock().await.open_one_of(allowed, &envelope)?;
    Ok(AuthenticatedFrame {
        message_type,
        payload,
    })
}

pub(crate) async fn read_authenticated_frames(
    mut stream: RecvStream,
    channel: Arc<Mutex<SecureControlChannel>>,
    sender: mpsc::Sender<AuthenticatedFrame>,
    allowed: &'static [u16],
) -> Result<(), String> {
    loop {
        let frame = read_one_authenticated(&mut stream, &channel, allowed).await?;
        sender
            .send(frame)
            .await
            .map_err(|_| "transfer-interrupted")?;
    }
}

pub(crate) async fn send_status_query(
    stream: &Arc<Mutex<SendStream>>,
    channel: &Arc<Mutex<SecureControlChannel>>,
    transfer_id: [u8; 16],
    session_id: [u8; 16],
) -> Result<[u8; 16], String> {
    let query_id = *Uuid::new_v4().as_bytes();
    let query = TransferStatusQuery {
        transfer_id,
        query_id,
        session_id,
    };
    send_authenticated(
        stream,
        channel,
        MESSAGE_TRANSFER_STATUS_QUERY,
        &serde_json::to_vec(&query).map_err(|_| "authenticated-status-invalid")?,
    )
    .await?;
    Ok(query_id)
}

pub(crate) fn validate_transfer_status(
    payload: &[u8],
    transfer_id: [u8; 16],
    query_id: [u8; 16],
    session_id: [u8; 16],
    session_lineage_digest: [u8; 32],
) -> Result<TransferStatus, String> {
    let status: TransferStatus =
        serde_json::from_slice(payload).map_err(|_| "authenticated-status-invalid")?;
    if status.transfer_id != transfer_id
        || status.query_id != query_id
        || status.session_id != session_id
        || status.session_lineage_digest != session_lineage_digest
        || status.query_id == [0; 16]
        || (status.final_file_completed && status.state != TransferStatusState::Completed)
        || (status.checkpoint_generation == 0 && status.state_digest != [0; 32])
    {
        return Err("authenticated-status-mismatch".into());
    }
    Ok(status)
}

fn parse_status_query(
    payload: &[u8],
    transfer_id: [u8; 16],
    session_id: [u8; 16],
) -> Result<TransferStatusQuery, String> {
    let query: TransferStatusQuery =
        serde_json::from_slice(payload).map_err(|_| "authenticated-status-invalid")?;
    if query.transfer_id != transfer_id
        || query.session_id != session_id
        || query.query_id == [0; 16]
    {
        return Err("authenticated-status-mismatch".into());
    }
    Ok(query)
}

pub(crate) async fn outgoing_status(
    record: &OutgoingNativeTransfer,
    query_id: [u8; 16],
    session_id: [u8; 16],
    session_lineage_digest: [u8; 32],
) -> TransferStatus {
    let mutable = record.mutable.lock().await;
    let state = match mutable.state {
        OutgoingNativeState::Transferring => TransferStatusState::Transferring,
        OutgoingNativeState::Paused
            if mutable.pause_request_id.is_none()
                && mutable
                    .peer_checkpoint_generation
                    .is_some_and(|value| value > 0)
                && mutable.peer_state_digest.is_some() =>
        {
            TransferStatusState::Paused
        }
        OutgoingNativeState::Paused => TransferStatusState::Transferring,
        OutgoingNativeState::Cancelled => TransferStatusState::Cancelled,
        OutgoingNativeState::Completed => TransferStatusState::Completed,
        OutgoingNativeState::Failed => TransferStatusState::Failed,
        _ => TransferStatusState::Transferring,
    };
    TransferStatus {
        transfer_id: parse_uuid(&record.transfer_id).unwrap_or([0; 16]),
        query_id,
        session_id,
        session_lineage_digest,
        state,
        final_file_completed: state == TransferStatusState::Completed
            && mutable.integrity_result.as_deref() == Some("passed"),
        checkpoint_generation: mutable.peer_checkpoint_generation.unwrap_or(0),
        state_digest: mutable.peer_state_digest.unwrap_or([0; 32]),
        completed_bytes: if state == TransferStatusState::Completed {
            record.file_size
        } else {
            mutable.peer_completed_bytes
        },
    }
}

pub(crate) async fn incoming_status(
    record: &IncomingNativeTransfer,
    query_id: [u8; 16],
    session_id: [u8; 16],
    session_lineage_digest: [u8; 32],
) -> TransferStatus {
    let mutable = record.mutable.lock().await;
    let state = match mutable.state {
        IncomingNativeState::Receiving => TransferStatusState::Receiving,
        IncomingNativeState::Paused
            if mutable.pause_request_id.is_none()
                && mutable.checkpoint_generation > 0
                && mutable.secure_state_digest.is_some() =>
        {
            TransferStatusState::Paused
        }
        IncomingNativeState::Paused => TransferStatusState::Receiving,
        IncomingNativeState::Cancelled | IncomingNativeState::Declined => {
            TransferStatusState::Cancelled
        }
        IncomingNativeState::Completed => TransferStatusState::Completed,
        IncomingNativeState::Failed => TransferStatusState::Failed,
        _ => TransferStatusState::Receiving,
    };
    TransferStatus {
        transfer_id: parse_uuid(&record.transfer_id).unwrap_or([0; 16]),
        query_id,
        session_id,
        session_lineage_digest,
        state,
        final_file_completed: state == TransferStatusState::Completed
            && mutable.integrity_result.as_deref() == Some("passed"),
        checkpoint_generation: mutable.checkpoint_generation,
        state_digest: mutable.secure_state_digest.unwrap_or([0; 32]),
        completed_bytes: if state == TransferStatusState::Completed {
            mutable.expected_file_size.unwrap_or(mutable.bytes_written)
        } else {
            mutable.completed_checkpoint_bytes
        },
    }
}

pub(crate) async fn respond_outgoing_status_query(
    record: &OutgoingNativeTransfer,
    stream: &Arc<Mutex<SendStream>>,
    channel: &Arc<Mutex<SecureControlChannel>>,
    payload: &[u8],
    transfer_id: [u8; 16],
    session_id: [u8; 16],
    session_lineage_digest: [u8; 32],
) -> Result<(), String> {
    let query = parse_status_query(payload, transfer_id, session_id)?;
    let status = outgoing_status(record, query.query_id, session_id, session_lineage_digest).await;
    send_authenticated(
        stream,
        channel,
        MESSAGE_TRANSFER_STATUS,
        &serde_json::to_vec(&status).map_err(|_| "authenticated-status-invalid")?,
    )
    .await
}

pub(crate) async fn respond_incoming_status_query(
    record: &IncomingNativeTransfer,
    stream: &Arc<Mutex<SendStream>>,
    channel: &Arc<Mutex<SecureControlChannel>>,
    payload: &[u8],
    transfer_id: [u8; 16],
    session_id: [u8; 16],
    session_lineage_digest: [u8; 32],
) -> Result<(), String> {
    let query = parse_status_query(payload, transfer_id, session_id)?;
    let status = incoming_status(record, query.query_id, session_id, session_lineage_digest).await;
    send_authenticated(
        stream,
        channel,
        MESSAGE_TRANSFER_STATUS,
        &serde_json::to_vec(&status).map_err(|_| "authenticated-status-invalid")?,
    )
    .await
}

async fn linger_incoming_status_queries(
    record: &IncomingNativeTransfer,
    stream: &Arc<Mutex<SendStream>>,
    channel: &Arc<Mutex<SecureControlChannel>>,
    frame_rx: &mut mpsc::Receiver<AuthenticatedFrame>,
    transfer_id: [u8; 16],
    session_id: [u8; 16],
) {
    let lineage = secure_protocol::session_lineage_digest(None);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while let Ok(Some(frame)) = tokio::time::timeout_at(deadline, frame_rx.recv()).await {
        if frame.message_type == MESSAGE_TRANSFER_STATUS_QUERY {
            let _ = respond_incoming_status_query(
                record,
                stream,
                channel,
                &frame.payload,
                transfer_id,
                session_id,
                lineage,
            )
            .await;
        }
    }
}

async fn linger_outgoing_status_queries(
    record: &OutgoingNativeTransfer,
    stream: &Arc<Mutex<SendStream>>,
    channel: &Arc<Mutex<SecureControlChannel>>,
    frame_rx: &mut mpsc::Receiver<AuthenticatedFrame>,
    transfer_id: [u8; 16],
    session_id: [u8; 16],
) {
    let lineage = secure_protocol::session_lineage_digest(None);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while let Ok(Some(frame)) = tokio::time::timeout_at(deadline, frame_rx.recv()).await {
        if frame.message_type == MESSAGE_TRANSFER_STATUS_QUERY {
            let _ = respond_outgoing_status_query(
                record,
                stream,
                channel,
                &frame.payload,
                transfer_id,
                session_id,
                lineage,
            )
            .await;
        }
    }
}

fn spawn_cancellation_monitor_outgoing(
    record: Arc<OutgoingNativeTransfer>,
    stream: Arc<Mutex<SendStream>>,
    channel: Arc<Mutex<SecureControlChannel>>,
    transfer_id: [u8; 16],
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let control_request = record.mutable.lock().await.control_request.clone();
        control_request.cancelled().await;
        let intent = record.mutable.lock().await.local_stop;
        if let Some(LocalStopIntent::Cancel { retain_partial }) = intent {
            let payload = serde_json::to_vec(&CancellationControl {
                transfer_id,
                retain_partial,
                checkpoint_generation: 0,
            })
            .unwrap_or_default();
            let result =
                send_authenticated(&stream, &channel, MESSAGE_TRANSFER_CANCEL, &payload).await;
            log_control_delivery("sender", "cancel", &result);
            if result.is_ok() {
                tokio::time::sleep(Duration::from_millis(500)).await;
                record.mutable.lock().await.cancellation.cancel();
            }
        } else if intent == Some(LocalStopIntent::Pause) {
            let request_id = record
                .mutable
                .lock()
                .await
                .pause_request_id
                .unwrap_or_else(|| *Uuid::new_v4().as_bytes());
            let payload = serde_json::to_vec(&PauseControl {
                transfer_id,
                request_id,
                checkpoint_generation: 0,
                state_digest: [0; 32],
                completed_bytes: 0,
            })
            .unwrap_or_default();
            let result =
                send_authenticated(&stream, &channel, MESSAGE_TRANSFER_PAUSE_REQUEST, &payload)
                    .await;
            log_control_delivery("sender", "pause-request", &result);
            if result.is_ok() {
                tokio::time::sleep(Duration::from_millis(500)).await;
                record.mutable.lock().await.cancellation.cancel();
            }
        }
    })
}

fn spawn_cancellation_monitor_incoming(
    record: Arc<IncomingNativeTransfer>,
    stream: Arc<Mutex<SendStream>>,
    channel: Arc<Mutex<SecureControlChannel>>,
    transfer_id: [u8; 16],
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let control_request = record.mutable.lock().await.control_request.clone();
        control_request.cancelled().await;
        let intent = record.mutable.lock().await.local_stop;
        if let Some(LocalStopIntent::Cancel { retain_partial }) = intent {
            let payload = serde_json::to_vec(&CancellationControl {
                transfer_id,
                retain_partial,
                checkpoint_generation: 0,
            })
            .unwrap_or_default();
            let result =
                send_authenticated(&stream, &channel, MESSAGE_TRANSFER_CANCEL, &payload).await;
            log_control_delivery("receiver", "cancel", &result);
            if result.is_ok() {
                tokio::time::sleep(Duration::from_millis(500)).await;
                record.mutable.lock().await.cancellation.cancel();
            }
        } else if intent == Some(LocalStopIntent::Pause) {
            let request_id = record
                .mutable
                .lock()
                .await
                .pause_request_id
                .unwrap_or_else(|| *Uuid::new_v4().as_bytes());
            let payload = serde_json::to_vec(&PauseControl {
                transfer_id,
                request_id,
                checkpoint_generation: 0,
                state_digest: [0; 32],
                completed_bytes: 0,
            })
            .unwrap_or_default();
            let result =
                send_authenticated(&stream, &channel, MESSAGE_TRANSFER_PAUSE_REQUEST, &payload)
                    .await;
            log_control_delivery("receiver", "pause-request", &result);
            if result.is_ok() {
                tokio::time::sleep(Duration::from_millis(500)).await;
                record.mutable.lock().await.cancellation.cancel();
            }
        }
    })
}

fn log_control_delivery(role: &str, control: &str, result: &Result<(), String>) {
    println!(
        "[FlowShareNativeControl] {}",
        serde_json::json!({
            "event": "authenticated-control-send",
            "role": role,
            "control": control,
            "written": result.is_ok(),
            "error": result.as_ref().err(),
        })
    );
}

pub(crate) fn validate_cancellation_at_generation(
    payload: &[u8],
    transfer_id: [u8; 16],
    checkpoint_generation: u64,
) -> Result<CancellationControl, String> {
    let control: CancellationControl =
        serde_json::from_slice(payload).map_err(|_| "authenticated-control-invalid")?;
    if control.transfer_id != transfer_id || control.checkpoint_generation != checkpoint_generation
    {
        return Err("authenticated-control-transfer-mismatch".into());
    }
    Ok(control)
}

fn validate_cancellation(
    payload: &[u8],
    transfer_id: [u8; 16],
) -> Result<CancellationControl, String> {
    validate_cancellation_at_generation(payload, transfer_id, 0)
}

async fn settle_local_stop_monitor(
    intent: Option<LocalStopIntent>,
    monitor: &mut tokio::task::JoinHandle<()>,
) {
    if intent.is_some() {
        if tokio::time::timeout(Duration::from_millis(1_000), &mut *monitor)
            .await
            .is_err()
        {
            monitor.abort();
        }
    } else {
        monitor.abort();
    }
}

async fn await_local_cancellation_ack(
    intent: Option<LocalStopIntent>,
    stream: &Arc<Mutex<SendStream>>,
    channel: &Arc<Mutex<SecureControlChannel>>,
    frame_rx: &mut mpsc::Receiver<AuthenticatedFrame>,
    transfer_id: [u8; 16],
    session_id: [u8; 16],
) {
    let Some(LocalStopIntent::Cancel { .. }) = intent else {
        return;
    };
    let wait_for_ack = async {
        while let Some(frame) = frame_rx.recv().await {
            match frame.message_type {
                MESSAGE_TRANSFER_CANCEL_ACK => {
                    validate_cancellation(&frame.payload, transfer_id)?;
                    return Ok(true);
                }
                MESSAGE_TRANSFER_CANCEL => {
                    validate_cancellation(&frame.payload, transfer_id)?;
                    let _ = send_authenticated(
                        stream,
                        channel,
                        MESSAGE_TRANSFER_CANCEL_ACK,
                        &frame.payload,
                    )
                    .await;
                    return Ok(true);
                }
                _ => {}
            }
        }
        Ok::<bool, String>(false)
    };
    if matches!(
        tokio::time::timeout(Duration::from_millis(400), wait_for_ack).await,
        Ok(Ok(true))
    ) {
        return;
    }
    let Ok(query_id) = send_status_query(stream, channel, transfer_id, session_id).await else {
        return;
    };
    let _ = tokio::time::timeout(Duration::from_millis(1_500), async {
        while let Some(frame) = frame_rx.recv().await {
            if frame.message_type == MESSAGE_TRANSFER_STATUS {
                let status = validate_transfer_status(
                    &frame.payload,
                    transfer_id,
                    query_id,
                    session_id,
                    secure_protocol::session_lineage_digest(None),
                )?;
                if status.state == TransferStatusState::Cancelled {
                    return Ok::<(), String>(());
                }
                return Err("authenticated-status-state-invalid".into());
            }
        }
        Err::<(), String>("authenticated-status-unavailable".into())
    })
    .await;
}

fn validate_pause(payload: &[u8], transfer_id: [u8; 16]) -> Result<PauseControl, String> {
    let control: PauseControl =
        serde_json::from_slice(payload).map_err(|_| "authenticated-control-invalid")?;
    if control.transfer_id != transfer_id || control.request_id == [0; 16] {
        return Err("authenticated-control-transfer-mismatch".into());
    }
    if control.checkpoint_generation == 0
        && (control.state_digest != [0; 32] || control.completed_bytes != 0)
    {
        return Err("authenticated-control-state-invalid".into());
    }
    Ok(control)
}

pub(crate) fn validate_pause_at_generation(
    payload: &[u8],
    transfer_id: [u8; 16],
    checkpoint_generation: u64,
    state_digest: [u8; 32],
) -> Result<PauseControl, String> {
    let control: PauseControl =
        serde_json::from_slice(payload).map_err(|_| "authenticated-control-invalid")?;
    if control.transfer_id != transfer_id
        || control.request_id == [0; 16]
        || control.checkpoint_generation != checkpoint_generation
        || control.state_digest != state_digest
    {
        return Err("authenticated-control-state-invalid".into());
    }
    Ok(control)
}

pub(crate) fn validate_paused_checkpoint_after(
    payload: &[u8],
    transfer_id: [u8; 16],
    checkpoint_generation: u64,
    file_size: u64,
) -> Result<PauseControl, String> {
    let control: PauseControl =
        serde_json::from_slice(payload).map_err(|_| "authenticated-control-invalid")?;
    if control.transfer_id != transfer_id
        || control.request_id == [0; 16]
        || control.checkpoint_generation <= checkpoint_generation
        || control.state_digest == [0; 32]
        || control.completed_bytes > file_size
    {
        return Err("authenticated-control-state-invalid".into());
    }
    Ok(control)
}

async fn outgoing_pause_requested(record: &OutgoingNativeTransfer) -> bool {
    record.mutable.lock().await.local_stop == Some(LocalStopIntent::Pause)
}

async fn finish_sender_pause(
    record: &OutgoingNativeTransfer,
    stream: &Arc<Mutex<SendStream>>,
    channel: &Arc<Mutex<SecureControlChannel>>,
    frame_rx: &mut mpsc::Receiver<AuthenticatedFrame>,
    pending: Option<PauseControl>,
    transfer_id: [u8; 16],
    session_id: [u8; 16],
) -> Result<SplitTransferResult, String> {
    let checkpoint = if let Some(checkpoint) = pending {
        checkpoint
    } else {
        let mut query_id = None;
        loop {
            let wait = if query_id.is_some() {
                Duration::from_secs(30)
            } else {
                Duration::from_millis(500)
            };
            let frame = match tokio::time::timeout(wait, frame_rx.recv()).await {
                Ok(Some(frame)) => frame,
                Ok(None) => return Err("peer-paused-state-lost".into()),
                Err(_) if query_id.is_none() => {
                    query_id =
                        Some(send_status_query(stream, channel, transfer_id, session_id).await?);
                    continue;
                }
                Err(_) => return Err("peer-paused-state-lost".into()),
            };
            match frame.message_type {
                MESSAGE_TRANSFER_PAUSED => break validate_pause(&frame.payload, transfer_id)?,
                MESSAGE_TRANSFER_PAUSE_REQUEST => {
                    let _ = validate_pause(&frame.payload, transfer_id)?;
                    send_authenticated(
                        stream,
                        channel,
                        MESSAGE_TRANSFER_PAUSE_ACCEPT,
                        &frame.payload,
                    )
                    .await?;
                }
                MESSAGE_TRANSFER_PAUSE_ACCEPT => {
                    let _ = validate_pause(&frame.payload, transfer_id)?;
                }
                MESSAGE_TRANSFER_CANCEL => {
                    validate_cancellation(&frame.payload, transfer_id)?;
                    send_authenticated(
                        stream,
                        channel,
                        MESSAGE_TRANSFER_CANCEL_ACK,
                        &frame.payload,
                    )
                    .await?;
                    return Err("peer-cancelled".into());
                }
                MESSAGE_TRANSFER_CANCEL_ACK => {
                    validate_cancellation(&frame.payload, transfer_id)?;
                }
                MESSAGE_TRANSFER_STATUS_QUERY => {
                    respond_outgoing_status_query(
                        record,
                        stream,
                        channel,
                        &frame.payload,
                        transfer_id,
                        session_id,
                        secure_protocol::session_lineage_digest(None),
                    )
                    .await?;
                }
                MESSAGE_TRANSFER_STATUS => {
                    let status = validate_transfer_status(
                        &frame.payload,
                        transfer_id,
                        query_id.ok_or("authenticated-status-unexpected")?,
                        session_id,
                        secure_protocol::session_lineage_digest(None),
                    )?;
                    if status.state != TransferStatusState::Paused
                        || status.checkpoint_generation == 0
                        || status.state_digest == [0; 32]
                    {
                        continue;
                    }
                    break PauseControl {
                        transfer_id,
                        request_id: record
                            .mutable
                            .lock()
                            .await
                            .pause_request_id
                            .unwrap_or_else(|| *Uuid::new_v4().as_bytes()),
                        checkpoint_generation: status.checkpoint_generation,
                        state_digest: status.state_digest,
                        completed_bytes: status.completed_bytes,
                    };
                }
                _ => return Err("authenticated-control-state-invalid".into()),
            }
        }
    };
    if checkpoint.checkpoint_generation == 0
        || checkpoint.state_digest == [0; 32]
        || checkpoint.completed_bytes > record.file_size
    {
        return Err("resume-state-mismatch".into());
    }
    {
        let mut mutable = record.mutable.lock().await;
        mutable.peer_checkpoint_generation = Some(checkpoint.checkpoint_generation);
        mutable.peer_state_digest = Some(checkpoint.state_digest);
        mutable.peer_completed_bytes = checkpoint.completed_bytes;
        mutable.pause_request_id = None;
    }
    authorization::mark_resumable(&transfer_id)?;
    let encoded =
        serde_json::to_vec(&checkpoint).map_err(|_| "authenticated-control-invalid".to_string())?;
    let _ = send_authenticated(stream, channel, MESSAGE_TRANSFER_PAUSED, &encoded).await;
    Err("native-transfer-paused".into())
}

async fn incoming_pause_requested(record: &IncomingNativeTransfer) -> bool {
    record.mutable.lock().await.local_stop == Some(LocalStopIntent::Pause)
}

async fn finish_receiver_pause(
    record: &IncomingNativeTransfer,
    stream: &Arc<Mutex<SendStream>>,
    channel: &Arc<Mutex<SecureControlChannel>>,
    frame_rx: &mut mpsc::Receiver<AuthenticatedFrame>,
    transfer_id: [u8; 16],
    invitation_id: [u8; 16],
    session_id: [u8; 16],
) -> Result<SplitTransferResult, String> {
    let checkpoint = checkpoint_incoming(record, transfer_id, invitation_id, session_id).await?;
    let payload =
        serde_json::to_vec(&checkpoint).map_err(|_| "authenticated-control-invalid".to_string())?;
    send_authenticated(stream, channel, MESSAGE_TRANSFER_PAUSED, &payload).await?;
    linger_incoming_status_queries(record, stream, channel, frame_rx, transfer_id, session_id)
        .await;
    Err("native-transfer-paused".into())
}

async fn checkpoint_incoming(
    record: &IncomingNativeTransfer,
    transfer_id: [u8; 16],
    invitation_id: [u8; 16],
    session_id: [u8; 16],
) -> Result<PauseControl, String> {
    let (
        part_path,
        final_filename,
        expected_file_size,
        expected_sha256,
        intervals,
        generation,
        request_id,
    ) = {
        let mutable = record.mutable.lock().await;
        (
            mutable.part_path.clone().ok_or("resume-state-mismatch")?,
            mutable
                .accepted_filename
                .clone()
                .ok_or("resume-state-mismatch")?,
            mutable.expected_file_size.ok_or("resume-state-mismatch")?,
            mutable.expected_sha256.ok_or("resume-state-mismatch")?,
            mutable.committed_intervals.clone(),
            mutable.checkpoint_generation.saturating_add(1),
            mutable
                .pause_request_id
                .unwrap_or_else(|| *Uuid::new_v4().as_bytes()),
        )
    };
    super::cross_device::reject_reparse_path(&part_path).await?;
    let canonical = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&part_path)
        .await
        .map_err(|_| "resume-part-missing")?;
    canonical
        .sync_all()
        .await
        .map_err(|_| "receiver-sync-failed")?;
    drop(canonical);
    let merged = merge_intervals(intervals);
    let total_blocks = expected_file_size.div_ceil(FROZEN_BLOCK_BYTES as u64);
    let mut bitmap = vec![0u8; total_blocks.div_ceil(8) as usize];
    let mut hashes = vec![None; total_blocks as usize];
    let mut completed_bytes = 0u64;
    let mut file = File::open(&part_path)
        .await
        .map_err(|_| "resume-part-missing")?;
    let mut buffer = vec![0u8; FROZEN_BLOCK_BYTES];
    for block in 0..total_blocks {
        let offset = block * FROZEN_BLOCK_BYTES as u64;
        let length = (expected_file_size - offset).min(FROZEN_BLOCK_BYTES as u64);
        if !range_fully_covered(&merged, offset, offset + length) {
            continue;
        }
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(|_| "resume-part-read-failed")?;
        file.read_exact(&mut buffer[..length as usize])
            .await
            .map_err(|_| "resume-part-read-failed")?;
        bitmap[(block / 8) as usize] |= 1 << (block % 8);
        hashes[block as usize] = Some(Sha256::digest(&buffer[..length as usize]).into());
        completed_bytes = completed_bytes.saturating_add(length);
    }
    let authorization = authorization::material_for_transfer(&transfer_id)?;
    let checkpoint_key = secure_protocol::derive_checkpoint_key(
        &authorization.master,
        &transfer_id,
        &invitation_id,
    )?;
    let part_identity_digest = super::resume::part_identity_digest(&part_path).await?;
    let resume_path = record.authorization_resume_path.lock().await.clone();
    let checkpoint_time = super::file_transfer::now_unix_ms();
    let mut metadata = super::resume::ResumeMetadata {
        format_version: super::resume::RESUME_FORMAT_VERSION,
        protocol_version: super::protocol::NATIVE_QUIC_PROTOCOL_VERSION,
        transfer_id,
        invitation_id,
        secret_version: 3,
        share_id: Some(record.transfer_id.clone()),
        lifecycle_generation: generation,
        checkpoint_generation: generation,
        checkpoint_state: super::lifecycle::TransferState::Paused,
        previous_session_id: Some(session_id),
        source: super::resume::SourceIdentity {
            size: expected_file_size,
            modified_unix_ms: None,
            platform_file_id: None,
            canonical_path: None,
        },
        expected_sha256,
        final_filename,
        part_filename: part_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or("resume-state-mismatch")?
            .to_string(),
        block_size: FROZEN_BLOCK_BYTES as u64,
        total_blocks,
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
    let mut manifest = super::block_hash::from_hashes(
        transfer_id,
        generation,
        expected_file_size,
        FROZEN_BLOCK_BYTES as u64,
        &hashes,
    )?;
    manifest.authenticate(invitation_id, part_identity_digest, &checkpoint_key)?;
    let sidecar_digest = manifest.authenticated_digest()?;
    super::block_hash::write_atomic_authenticated(&resume_path, &manifest, &checkpoint_key, None)
        .await?;
    metadata.refresh_security(&checkpoint_key, sidecar_digest, part_identity_digest)?;
    super::resume::write_atomic_authenticated(&resume_path, &metadata, &checkpoint_key).await?;
    authorization::mark_resumable(&transfer_id)?;
    {
        let mut mutable = record.mutable.lock().await;
        mutable.checkpoint_generation = generation;
        mutable.secure_state_digest = Some(metadata.secure_state_digest);
        mutable.completed_checkpoint_bytes = completed_bytes;
        mutable.state = IncomingNativeState::Paused;
        mutable.pause_request_id = None;
    }
    Ok(PauseControl {
        transfer_id,
        request_id,
        checkpoint_generation: generation,
        state_digest: metadata.secure_state_digest,
        completed_bytes,
    })
}

fn merge_intervals(mut intervals: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    intervals.retain(|(start, end)| start < end);
    intervals.sort_unstable_by_key(|value| value.0);
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(intervals.len());
    for (start, end) in intervals {
        if let Some(last) = merged.last_mut() {
            if start <= last.1 {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
}

fn range_fully_covered(intervals: &[(u64, u64)], start: u64, end: u64) -> bool {
    intervals
        .iter()
        .any(|(candidate_start, candidate_end)| *candidate_start <= start && *candidate_end >= end)
}

async fn cancellation_error_outgoing(record: &OutgoingNativeTransfer) -> String {
    match record.mutable.lock().await.local_stop {
        Some(LocalStopIntent::Pause) => "native-transfer-paused".into(),
        Some(LocalStopIntent::Cancel { .. }) => "native-transfer-cancelled".into(),
        None => "peer-cancelled".into(),
    }
}

async fn cancellation_error_incoming(
    record: &IncomingNativeTransfer,
    peer_cancelled: bool,
) -> String {
    if peer_cancelled && record.mutable.lock().await.local_stop.is_none() {
        return "peer-cancelled".into();
    }
    match record.mutable.lock().await.local_stop {
        Some(LocalStopIntent::Pause) => "native-transfer-paused".into(),
        Some(LocalStopIntent::Cancel { .. }) => "native-transfer-cancelled".into(),
        None => "peer-cancelled".into(),
    }
}

async fn join_byte_tasks(
    tasks: Vec<tokio::task::JoinHandle<Result<u64, String>>>,
) -> Result<u64, String> {
    let mut total = 0u64;
    let mut first_error = None;
    for task in tasks {
        match task.await.map_err(|_| "transfer-interrupted")? {
            Ok(bytes) => total = total.saturating_add(bytes),
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    first_error.map_or(Ok(total), Err)
}

async fn join_range_tasks(
    tasks: Vec<tokio::task::JoinHandle<Result<RangeHeader, String>>>,
) -> Result<Vec<RangeHeader>, String> {
    let mut headers = Vec::with_capacity(tasks.len());
    let mut first_error = None;
    for task in tasks {
        match task.await.map_err(|_| "transfer-interrupted")? {
            Ok(header) => headers.push(header),
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    first_error.map_or(Ok(headers), Err)
}

fn active_streams(file_size: u64, configured: u8) -> u8 {
    if file_size == 0 {
        0
    } else {
        configured.min(file_size.min(u8::MAX as u64) as u8)
    }
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

fn parse_uuid(value: &str) -> Result<[u8; 16], String> {
    Ok(*Uuid::parse_str(value)
        .map_err(|_| "native-transfer-id-invalid")?
        .as_bytes())
}

fn is_authorization_rejection(error: &str) -> bool {
    matches!(
        error,
        "authentication-required"
            | "authentication-failed"
            | "certificate-binding-failed"
            | "transcript-mismatch"
            | "unauthorized-data-stream"
            | "secure-handshake-failed"
    )
}

fn authenticated_peer_close_error(connection: &Connection) -> Option<&'static str> {
    match connection.close_reason()? {
        ConnectionError::ApplicationClosed(close)
            if close.error_code == VarInt::from_u32(CLOSE_AUTHENTICATED_PEER_CANCELLED) =>
        {
            Some("peer-cancelled")
        }
        ConnectionError::ApplicationClosed(close)
            if close.error_code == VarInt::from_u32(CLOSE_AUTHENTICATED_PEER_PAUSED) =>
        {
            Some("peer-paused")
        }
        _ => None,
    }
}

fn drop_completion_ack_for_test() -> bool {
    cfg!(debug_assertions)
        && std::env::var("FLOWGET_NATIVE_TEST_DROP_COMPLETION_ACK")
            .ok()
            .is_some_and(|value| value == "1")
}

pub(crate) fn selected_path_label(context: &NominatedPathContext) -> String {
    let remote = context.pair.remote_socket_addr();
    format!(
        "{}:{}->{}:{} ({:?}/{:?})",
        context.pair.local_candidate.address,
        context.pair.local_candidate.port,
        remote.ip(),
        remote.port(),
        context.pair.local_candidate.candidate_type,
        context.pair.remote_candidate.candidate_type,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::NativeQuicConfig, security::create_ephemeral_identity};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn eof_test_endpoints() -> (Endpoint, Endpoint, SocketAddr) {
        let identity = create_ephemeral_identity().unwrap();
        let config = NativeQuicConfig::desktop(1).unwrap();
        let certificate = identity.certificate.clone();
        let mut server_config =
            ServerConfig::with_single_cert(vec![certificate.clone()], identity.private_key.into())
                .unwrap();
        server_config.transport_config(config.transport().unwrap());
        let server = Endpoint::server(
            server_config,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(certificate).unwrap();
        let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
        client_config.transport_config(config.transport().unwrap());
        let mut client =
            Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        client.set_default_client_config(client_config);
        (server, client, address)
    }

    fn outgoing_status_record() -> OutgoingNativeTransfer {
        OutgoingNativeTransfer {
            transfer_id: Uuid::new_v4().to_string(),
            invitation_id: Uuid::new_v4().to_string(),
            source_path: std::path::PathBuf::from("source.bin"),
            source_identity: super::super::resume::SourceIdentity {
                size: 1_000,
                modified_unix_ms: None,
                platform_file_id: None,
                canonical_path: None,
            },
            display_filename: "source.bin".into(),
            file_size: 1_000,
            expected_sha256: [1; 32],
            receiver_certificate: rustls::pki_types::CertificateDer::from(Vec::new()),
            receiver_certificate_fingerprint_sha256: [2; 32],
            candidate_privacy_policy: super::super::candidates::CandidatePrivacyPolicy::LanFirst,
            authorization_resume_path: std::path::PathBuf::from("transfer.resume.current"),
            outgoing_state_path: std::path::PathBuf::from("outgoing-state.json"),
            previous_quic_session_id: None,
            expires_unix_ms: 1,
            created_unix_ms: 1,
            mutable: Mutex::new(super::super::cross_device::OutgoingMutable {
                state: OutgoingNativeState::Paused,
                control_request: CancellationToken::new(),
                cancellation: CancellationToken::new(),
                local_stop: Some(LocalStopIntent::Pause),
                pause_request_id: Some([7; 16]),
                task_abort: None,
                connectivity_session_id: None,
                quic_session_id: None,
                selected_path: None,
                bytes_sent: 900,
                bytes_skipped: 0,
                peer_checkpoint_generation: Some(1),
                peer_state_digest: Some([3; 32]),
                peer_completed_bytes: 400,
                integrity_result: None,
                performance: None,
                signaling_file_payload_bytes: 0,
                terminal_error: None,
            }),
        }
    }

    fn incoming_status_record() -> IncomingNativeTransfer {
        IncomingNativeTransfer {
            transfer_id: Uuid::new_v4().to_string(),
            invitation_id: Uuid::new_v4().to_string(),
            destination_directory: Mutex::new(std::path::PathBuf::from("destination")),
            artifact_directory: Mutex::new(std::path::PathBuf::from("artifact")),
            authorization_resume_path: Mutex::new(std::path::PathBuf::from(
                "transfer.resume.current",
            )),
            receiver_identity: Mutex::new(None),
            receiver_certificate_fingerprint_sha256: [2; 32],
            expires_unix_ms: 1,
            retention_expires_unix_ms: 2,
            created_unix_ms: 1,
            mutable: Mutex::new(super::super::cross_device::IncomingMutable {
                state: IncomingNativeState::Paused,
                control_request: CancellationToken::new(),
                cancellation: CancellationToken::new(),
                local_stop: Some(LocalStopIntent::Pause),
                peer_cancel_retain_partial: None,
                pause_request_id: Some([8; 16]),
                task_abort: None,
                connectivity_session_id: None,
                quic_session_id: None,
                selected_path: None,
                accepted_filename: Some("file.bin".into()),
                expected_file_size: Some(1_000),
                expected_sha256: Some([4; 32]),
                final_path: None,
                part_path: None,
                bytes_received: 900,
                bytes_written: 800,
                bytes_skipped: 0,
                committed_intervals: Vec::new(),
                checkpoint_generation: 1,
                secure_state_digest: Some([5; 32]),
                completed_checkpoint_bytes: 300,
                integrity_result: None,
                performance: None,
                signaling_file_payload_bytes: 0,
                terminal_error: None,
            }),
        }
    }

    #[tokio::test]
    async fn receiver_observes_delayed_fin_before_dropping_stream() {
        let (server, client, address) = eof_test_endpoints();
        let receiver = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            let mut stream = connection.accept_uni().await.unwrap();
            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"data");
            require_stream_eof(&mut stream).await
        });

        let connection = client
            .connect(address, "flowshare-native.local")
            .unwrap()
            .await
            .unwrap();
        let mut stream = connection.open_uni().await.unwrap();
        stream.write_all(b"data").await.unwrap();
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(
            !receiver.is_finished(),
            "receiver must wait for the QUIC FIN"
        );
        stream.finish().unwrap();
        assert_eq!(stream.stopped().await.unwrap(), None);
        receiver.await.unwrap().unwrap();
    }

    #[test]
    fn authenticated_status_binds_query_session_and_lineage() {
        let transfer_id = [1; 16];
        let query_id = [2; 16];
        let session_id = [3; 16];
        let lineage = [4; 32];
        let status = TransferStatus {
            transfer_id,
            query_id,
            session_id,
            session_lineage_digest: lineage,
            state: TransferStatusState::Completed,
            final_file_completed: true,
            checkpoint_generation: 2,
            state_digest: [5; 32],
            completed_bytes: 1024,
        };
        let encoded = serde_json::to_vec(&status).unwrap();
        assert_eq!(
            validate_transfer_status(&encoded, transfer_id, query_id, session_id, lineage)
                .unwrap()
                .state,
            TransferStatusState::Completed
        );
        assert!(
            validate_transfer_status(&encoded, transfer_id, [9; 16], session_id, lineage).is_err()
        );
        assert!(
            validate_transfer_status(&encoded, transfer_id, query_id, session_id, [9; 32]).is_err()
        );
    }

    #[test]
    fn resumed_controls_reject_stale_checkpoint_generation() {
        let transfer_id = [6; 16];
        let cancellation = serde_json::to_vec(&CancellationControl {
            transfer_id,
            retain_partial: false,
            checkpoint_generation: 4,
        })
        .unwrap();
        assert!(validate_cancellation_at_generation(&cancellation, transfer_id, 4).is_ok());
        assert!(validate_cancellation_at_generation(&cancellation, transfer_id, 3).is_err());

        let pause = serde_json::to_vec(&PauseControl {
            transfer_id,
            request_id: [7; 16],
            checkpoint_generation: 4,
            state_digest: [8; 32],
            completed_bytes: 100,
        })
        .unwrap();
        assert!(validate_pause_at_generation(&pause, transfer_id, 4, [8; 32]).is_ok());
        assert!(validate_pause_at_generation(&pause, transfer_id, 3, [8; 32]).is_err());
    }

    #[tokio::test]
    async fn status_exposes_only_committed_pause_and_durable_bytes() {
        let outgoing = outgoing_status_record();
        let provisional = outgoing_status(&outgoing, [1; 16], [2; 16], [3; 32]).await;
        assert_eq!(provisional.state, TransferStatusState::Transferring);
        assert_eq!(provisional.completed_bytes, 400);
        {
            let mut mutable = outgoing.mutable.lock().await;
            mutable.pause_request_id = None;
        }
        let committed = outgoing_status(&outgoing, [1; 16], [2; 16], [3; 32]).await;
        assert_eq!(committed.state, TransferStatusState::Paused);
        assert_eq!(committed.completed_bytes, 400);

        let incoming = incoming_status_record();
        let provisional = incoming_status(&incoming, [1; 16], [2; 16], [3; 32]).await;
        assert_eq!(provisional.state, TransferStatusState::Receiving);
        assert_eq!(provisional.completed_bytes, 300);
        incoming.mutable.lock().await.pause_request_id = None;
        let committed = incoming_status(&incoming, [1; 16], [2; 16], [3; 32]).await;
        assert_eq!(committed.state, TransferStatusState::Paused);
        assert_eq!(committed.completed_bytes, 300);
    }

    #[test]
    fn repeated_completion_status_is_idempotent_after_ack_loss() {
        let transfer_id = [1; 16];
        let query_id = [2; 16];
        let session_id = [3; 16];
        let lineage = [4; 32];
        let status = TransferStatus {
            transfer_id,
            query_id,
            session_id,
            session_lineage_digest: lineage,
            state: TransferStatusState::Completed,
            final_file_completed: true,
            checkpoint_generation: 2,
            state_digest: [5; 32],
            completed_bytes: 1_000,
        };
        let encoded = serde_json::to_vec(&status).unwrap();
        let first =
            validate_transfer_status(&encoded, transfer_id, query_id, session_id, lineage).unwrap();
        let repeated =
            validate_transfer_status(&encoded, transfer_id, query_id, session_id, lineage).unwrap();
        assert_eq!(first.state, repeated.state);
        assert_eq!(first.final_file_completed, repeated.final_file_completed);
        assert_eq!(first.completed_bytes, repeated.completed_bytes);
        assert_eq!(first.checkpoint_generation, repeated.checkpoint_generation);
        assert_eq!(first.state_digest, repeated.state_digest);
    }
}
