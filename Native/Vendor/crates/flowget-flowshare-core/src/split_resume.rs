use super::{
    authorization, block_hash,
    connectivity::NominatedPathContext,
    cross_device::{
        IncomingNativeState, IncomingNativeTransfer, LocalStopIntent, OutgoingNativeState,
        OutgoingNativeTransfer,
    },
    protocol::{
        missing_block_ranges, validate_missing_ranges, MissingBlockRange, RangeHeader,
        ResumeAccept, ResumeBinding, ResumeCompletionAck, ResumeCompletionManifest,
        ResumeControlMessage, ResumeOffer, ResumeState, NATIVE_QUIC_PROTOCOL_VERSION,
        RANGE_HEADER_BYTES, RESUME_REQUIRED_CAPABILITIES,
    },
    resume::{self, ResumeMetadata},
    secure_protocol::{
        self, SecureControlChannel, SecureSessionMode, MESSAGE_COMPLETION_ACK,
        MESSAGE_COMPLETION_MANIFEST, MESSAGE_TRANSFER_CANCEL, MESSAGE_TRANSFER_CANCEL_ACK,
        MESSAGE_TRANSFER_PAUSED, MESSAGE_TRANSFER_PAUSE_ACCEPT, MESSAGE_TRANSFER_PAUSE_REQUEST,
        MESSAGE_TRANSFER_STATUS, MESSAGE_TRANSFER_STATUS_QUERY,
    },
    signaling::NativeDeviceRole,
    split_transfer::{
        self, require_stream_eof, AuthenticatedFrame, CancellationControl, PauseControl,
        SplitTransferResult, TransferStatusState, FROZEN_BLOCK_BYTES, FROZEN_RECEIVER_BUFFER_COUNT,
        FROZEN_STREAM_COUNT, FROZEN_WRITE_QUEUE_CAPACITY,
    },
};
use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use sha2_compat::{Digest, Sha256};
use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};
use tokio::{
    fs::{self, File, OpenOptions},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom},
    sync::{mpsc, Mutex},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const MAX_RESUME_CONTROL_FRAME_BYTES: usize = 64 * 1024 * 1024;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const RESUME_RUNTIME_MESSAGES: &[u16] = &[
    MESSAGE_TRANSFER_CANCEL,
    MESSAGE_TRANSFER_CANCEL_ACK,
    MESSAGE_TRANSFER_PAUSE_REQUEST,
    MESSAGE_TRANSFER_PAUSE_ACCEPT,
    MESSAGE_TRANSFER_PAUSED,
    MESSAGE_COMPLETION_MANIFEST,
    MESSAGE_COMPLETION_ACK,
    MESSAGE_TRANSFER_STATUS_QUERY,
    MESSAGE_TRANSFER_STATUS,
];

#[derive(Debug, Clone)]
pub(crate) struct ValidatedIncomingCheckpoint {
    pub metadata: ResumeMetadata,
    pub hashes: Vec<Option<[u8; 32]>>,
    pub resume_path: PathBuf,
    pub part_path: PathBuf,
    pub final_path: PathBuf,
}

pub(crate) async fn validate_incoming_checkpoint(
    record: &IncomingNativeTransfer,
) -> Result<ValidatedIncomingCheckpoint, String> {
    let transfer_id = parse_uuid(&record.transfer_id)?;
    let invitation_id = parse_uuid(&record.invitation_id)?;
    let resume_path = record.authorization_resume_path.lock().await.clone();
    let protected = super::secret_store::load(&resume_path).await?;
    if protected.material.invitation.body.transfer_id != transfer_id
        || protected.material.invitation.body.invitation_id != invitation_id
    {
        return Err("resume-state-mismatch".into());
    }
    authorization::restore_persisted(protected.material.clone())?;
    let checkpoint_key = secure_protocol::derive_checkpoint_key(
        &protected.material.master,
        &transfer_id,
        &invitation_id,
    )?;
    let selected = resume::load_highest_valid_authenticated(
        &resume_path,
        &checkpoint_key,
        &transfer_id,
        &invitation_id,
    )
    .await?;
    let metadata = selected.metadata;
    metadata.validate_shape()?;
    if metadata.block_size != FROZEN_BLOCK_BYTES as u64
        || metadata.checkpoint_generation == 0
        || metadata.secure_state_digest == [0; 32]
    {
        return Err("resume-state-mismatch".into());
    }
    let expected = {
        let mutable = record.mutable.lock().await;
        (
            mutable.accepted_filename.clone(),
            mutable.expected_file_size,
            mutable.expected_sha256,
            mutable.part_path.clone(),
            mutable.final_path.clone(),
            mutable.checkpoint_generation,
            mutable.secure_state_digest,
            mutable.completed_checkpoint_bytes,
        )
    };
    if expected.0.as_deref() != Some(metadata.final_filename.as_str())
        || expected.1 != Some(metadata.source.size)
        || expected.2 != Some(metadata.expected_sha256)
        || expected.5 != metadata.checkpoint_generation
        || expected.6 != Some(metadata.secure_state_digest)
        || expected.7 != metadata.completed_bytes
    {
        return Err("resume-state-mismatch".into());
    }
    let part_path = expected.3.ok_or("resume-part-missing")?;
    let final_path = expected.4.ok_or("resume-state-mismatch")?;
    let part = fs::metadata(&part_path)
        .await
        .map_err(|_| "resume-part-missing")?;
    if !part.is_file() || part.len() != metadata.source.size {
        return Err("resume-part-size-mismatch".into());
    }
    if fs::try_exists(&final_path)
        .await
        .map_err(|_| "resume-destination-conflict")?
    {
        return Err("resume-destination-conflict".into());
    }
    if resume::part_identity_digest(&part_path).await? != metadata.part_identity_digest {
        return Err("resume-state-mismatch".into());
    }
    let sidecar = block_hash::load_for_generation_authenticated(
        &resume_path,
        &transfer_id,
        &invitation_id,
        metadata.checkpoint_generation,
        &metadata.part_identity_digest,
        &metadata.block_hash_sidecar_digest,
        &checkpoint_key,
    )
    .await;
    let manifest = sidecar.manifest.ok_or("checkpoint-authentication-failed")?;
    let mut hashes = vec![None; metadata.total_blocks as usize];
    for entry in manifest.entries {
        hashes[entry.block_index as usize] = Some(entry.digest);
    }
    verify_completed_blocks(&part_path, &metadata, &hashes).await?;
    Ok(ValidatedIncomingCheckpoint {
        metadata,
        hashes,
        resume_path,
        part_path,
        final_path,
    })
}

async fn verify_completed_blocks(
    part_path: &Path,
    metadata: &ResumeMetadata,
    hashes: &[Option<[u8; 32]>],
) -> Result<(), String> {
    let mut file = File::open(part_path)
        .await
        .map_err(|_| "resume-part-missing")?;
    let mut buffer = vec![0u8; metadata.block_size as usize];
    for block in 0..metadata.total_blocks {
        if !metadata.is_complete(block) {
            continue;
        }
        let expected = hashes
            .get(block as usize)
            .and_then(|value| *value)
            .ok_or("checkpoint-authentication-failed")?;
        let length = resume::block_length(
            block,
            metadata.block_size,
            metadata.source.size,
            metadata.total_blocks,
        )?;
        file.seek(SeekFrom::Start(block * metadata.block_size))
            .await
            .map_err(|_| "resume-part-read-failed")?;
        file.read_exact(&mut buffer[..length as usize])
            .await
            .map_err(|_| "resume-part-read-failed")?;
        let actual: [u8; 32] = Sha256::digest(&buffer[..length as usize]).into();
        if actual != expected {
            return Err("resume-state-mismatch".into());
        }
    }
    Ok(())
}

pub(crate) async fn run_outgoing_resume(
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
    let current_identity = resume::capture_source_identity(&record.source_path).await?;
    if current_identity != record.source_identity {
        return Err("source-file-changed".into());
    }
    let (actual_hash, _) =
        super::file_transfer::sha256_file(&record.source_path, FROZEN_BLOCK_BYTES).await?;
    if actual_hash != record.expected_sha256 {
        return Err("source-file-changed".into());
    }
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
    let result = send_missing_blocks(
        record,
        connection.clone(),
        context.future_quic_session_id,
        transfer_id,
        invitation_id,
    )
    .await;
    if result.is_err() {
        connection.close(VarInt::from_u32(0x421), b"native-resume-sender-stopped");
    }
    endpoint.close(VarInt::from_u32(0), b"native-resume-sender-finished");
    result
}

pub(crate) async fn run_incoming_resume(
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
    let checkpoint = validate_incoming_checkpoint(&record).await?;
    let deadline = Instant::now() + CONNECTION_TIMEOUT;
    let mut rejected = 0u8;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("quic-connect-failed".into());
        }
        let incoming = tokio::time::timeout(remaining, endpoint.accept())
            .await
            .map_err(|_| "quic-connect-failed".to_string())?
            .ok_or("quic-connect-failed")?;
        let connection = match incoming.await {
            Ok(value) => value,
            Err(_) if rejected < 8 => {
                rejected += 1;
                continue;
            }
            Err(_) => return Err("quic-connect-failed".into()),
        };
        match receive_missing_blocks(
            record.clone(),
            connection.clone(),
            context.future_quic_session_id,
            transfer_id,
            invitation_id,
            checkpoint.clone(),
        )
        .await
        {
            Ok(result) => {
                endpoint.close(VarInt::from_u32(0), b"native-resume-receiver-finished");
                return Ok(result);
            }
            Err(error)
                if is_authorization_rejection(&error)
                    && rejected < 8
                    && Instant::now() < deadline =>
            {
                rejected += 1;
                connection.close(VarInt::from_u32(0x422), b"unauthorized-resume-session");
            }
            Err(error) => {
                endpoint.close(VarInt::from_u32(0x423), b"native-resume-receiver-stopped");
                return Err(error);
            }
        }
    }
}

async fn send_missing_blocks(
    record: Arc<OutgoingNativeTransfer>,
    connection: Connection,
    session_id: [u8; 16],
    transfer_id: [u8; 16],
    invitation_id: [u8; 16],
) -> Result<SplitTransferResult, String> {
    let started = Instant::now();
    let material = authorization::material_for_transfer(&transfer_id)?;
    if material.invitation.body.invitation_id != invitation_id {
        return Err("resume-state-mismatch".into());
    }
    let (generation, state_digest, expected_skipped) = {
        let mutable = record.mutable.lock().await;
        (
            mutable
                .peer_checkpoint_generation
                .ok_or("resume-state-mismatch")?,
            mutable.peer_state_digest.ok_or("resume-state-mismatch")?,
            mutable.peer_completed_bytes,
        )
    };
    let binding = resume_binding(
        transfer_id,
        session_id,
        generation,
        record.file_size,
        record.expected_sha256,
        state_digest,
    )?;
    let previous_session = record
        .previous_quic_session_id
        .as_deref()
        .map(super::secure_transport::parse_session_id)
        .transpose()?;
    let transfer_commitment = secure_protocol::transfer_commitment(
        record.file_size,
        &record.expected_sha256,
        FROZEN_BLOCK_BYTES as u64,
        binding.total_blocks,
        RESUME_REQUIRED_CAPABILITIES,
    );
    let (mut control_send, mut control_recv) = connection
        .open_bi()
        .await
        .map_err(|_| "secure-handshake-failed")?;
    let prepared = authorization::prepare_client_handshake(
        transfer_id,
        session_id,
        SecureSessionMode::Resume,
        generation,
        state_digest,
        transfer_commitment,
        secure_protocol::session_lineage_digest(previous_session.as_ref()),
        record.receiver_certificate_fingerprint_sha256,
        RESUME_REQUIRED_CAPABILITIES,
    )?;
    let mut security = super::secure_transport::authenticate_client(
        &connection,
        &mut control_send,
        &mut control_recv,
        prepared,
    )
    .await
    .map_err(|_| "secure-handshake-failed")?;
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
        secure_protocol::MESSAGE_RESUME_STATE,
    )
    .await?
    {
        ResumeControlMessage::State(value) => value,
        ResumeControlMessage::Reject(value) => {
            return Err(format!("resume-rejected:{}", value.code));
        }
        _ => return Err("resume-protocol-unexpected-message".into()),
    };
    state
        .binding
        .validate_matches(&binding)
        .map_err(|_| "resume-state-mismatch")?;
    let missing_blocks = validate_missing_ranges(&state.missing_ranges, binding.total_blocks)
        .map_err(|_| "resume-state-mismatch")?;
    let missing_bytes = bytes_for_ranges(&state.missing_ranges, &binding)?;
    let bytes_skipped = binding.file_size.saturating_sub(missing_bytes);
    if bytes_skipped != expected_skipped {
        return Err("resume-state-mismatch".into());
    }
    let worker_count = if missing_blocks == 0 {
        0
    } else {
        FROZEN_STREAM_COUNT.min(missing_blocks as u8)
    };
    write_control(
        &mut control_send,
        &mut security.control,
        &ResumeControlMessage::Accept(ResumeAccept {
            binding: binding.clone(),
            missing_range_count: state.missing_ranges.len() as u64,
            stream_count: worker_count,
        }),
    )
    .await?;
    let control_send = Arc::new(Mutex::new(control_send));
    let channel = Arc::new(Mutex::new(security.control));
    let (frame_tx, mut frame_rx) = mpsc::channel(16);
    let reader = tokio::spawn(split_transfer::read_authenticated_frames(
        control_recv,
        channel.clone(),
        frame_tx,
        RESUME_RUNTIME_MESSAGES,
    ));
    {
        let mut mutable = record.mutable.lock().await;
        mutable.state = OutgoingNativeState::Transferring;
        mutable.bytes_skipped = bytes_skipped;
        mutable.bytes_sent = 0;
    }
    let cancellation = record.mutable.lock().await.cancellation.clone();
    let scheduler = Arc::new(StdMutex::new(MissingScheduler::new(&state.missing_ranges)));
    let mut tasks = Vec::new();
    for _ in 0..worker_count {
        let stream = connection
            .open_uni()
            .await
            .map_err(|_| "transfer-interrupted")?;
        tasks.push(tokio::spawn(sender_worker(
            stream,
            record.source_path.clone(),
            record.clone(),
            binding.clone(),
            scheduler.clone(),
            cancellation.clone(),
        )));
    }
    let ack = drive_resumed_sender(
        record.clone(),
        control_send.clone(),
        channel.clone(),
        &mut frame_rx,
        tasks,
        binding.clone(),
        missing_blocks,
        missing_bytes,
        previous_session,
    )
    .await?;
    reader.abort();
    let sent = record.mutable.lock().await.bytes_sent;
    ack.binding
        .validate_matches(&binding)
        .map_err(|_| "resume-state-mismatch")?;
    if !ack.integrity_ok
        || ack.final_sha256 != binding.expected_sha256
        || ack.complete_blocks != binding.total_blocks
    {
        return Err("integrity-mismatch".into());
    }
    control_send
        .lock()
        .await
        .finish()
        .map_err(|_| "completed-ack-lost")?;
    let _ = authorization::consume(&transfer_id);
    let _ = super::secret_store::delete(&record.authorization_resume_path).await;
    let stats = connection.stats();
    let elapsed = started.elapsed().as_secs_f64().max(0.000_001);
    let result = SplitTransferResult {
        transfer_id: record.transfer_id.clone(),
        role: "sender",
        total_bytes: binding.file_size,
        payload_bytes: sent,
        bytes_skipped,
        blocks_transferred: missing_blocks,
        blocks_skipped: binding.total_blocks - missing_blocks,
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
        "[FlowShareNativeSplitResume] {}",
        serde_json::to_string(&result).unwrap_or_else(|_| "{}".into())
    );
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
async fn drive_resumed_sender(
    record: Arc<OutgoingNativeTransfer>,
    stream: Arc<Mutex<SendStream>>,
    channel: Arc<Mutex<SecureControlChannel>>,
    frame_rx: &mut mpsc::Receiver<AuthenticatedFrame>,
    tasks: Vec<tokio::task::JoinHandle<Result<(), String>>>,
    binding: ResumeBinding,
    missing_blocks: u64,
    missing_bytes: u64,
    previous_session: Option<[u8; 16]>,
) -> Result<ResumeCompletionAck, String> {
    let cancellation = record.mutable.lock().await.cancellation.clone();
    let peer_cancel = CancellationToken::new();
    let peer_pause = CancellationToken::new();
    let lineage = secure_protocol::session_lineage_digest(previous_session.as_ref());
    let mut monitor = spawn_resume_control_outgoing(
        record.clone(),
        stream.clone(),
        channel.clone(),
        binding.clone(),
    );
    let mut pending_pause = None;
    let mut joined = Box::pin(join_resume_tasks(tasks));
    loop {
        tokio::select! {
            result = &mut joined => {
                if let Err(error) = result {
                    let local_stop_requested = record.mutable.lock().await.local_stop.is_some();
                    if !cancellation.is_cancelled()
                        && !peer_cancel.is_cancelled()
                        && !peer_pause.is_cancelled()
                        && !local_stop_requested
                    {
                        monitor.abort();
                        return Err(error);
                    }
                }
                break;
            }
            frame = frame_rx.recv() => {
                let frame = frame.ok_or("transfer-interrupted")?;
                match frame.message_type {
                    MESSAGE_TRANSFER_CANCEL => {
                        split_transfer::validate_cancellation_at_generation(&frame.payload, binding.transfer_id, binding.checkpoint_generation)?;
                        record.mutable.lock().await.state = OutgoingNativeState::Cancelled;
                        peer_cancel.cancel();
                        cancellation.cancel();
                        split_transfer::send_authenticated(&stream, &channel, MESSAGE_TRANSFER_CANCEL_ACK, &frame.payload).await?;
                    }
                    MESSAGE_TRANSFER_CANCEL_ACK => {
                        split_transfer::validate_cancellation_at_generation(&frame.payload, binding.transfer_id, binding.checkpoint_generation)?;
                        if matches!(record.mutable.lock().await.local_stop, Some(LocalStopIntent::Cancel { .. })) {
                            cancellation.cancel();
                        }
                    }
                    MESSAGE_TRANSFER_PAUSE_REQUEST => {
                        let pause = split_transfer::validate_pause_at_generation(
                            &frame.payload,
                            binding.transfer_id,
                            binding.checkpoint_generation,
                            binding.state_digest,
                        )?;
                        record.mutable.lock().await.pause_request_id = Some(pause.request_id);
                        peer_pause.cancel();
                        cancellation.cancel();
                        split_transfer::send_authenticated(&stream, &channel, MESSAGE_TRANSFER_PAUSE_ACCEPT, &frame.payload).await?;
                    }
                    MESSAGE_TRANSFER_PAUSE_ACCEPT => {
                        split_transfer::validate_pause_at_generation(
                            &frame.payload,
                            binding.transfer_id,
                            binding.checkpoint_generation,
                            binding.state_digest,
                        )?;
                        if record.mutable.lock().await.local_stop == Some(LocalStopIntent::Pause) {
                            cancellation.cancel();
                        }
                    }
                    MESSAGE_TRANSFER_PAUSED => {
                        pending_pause = Some(split_transfer::validate_paused_checkpoint_after(
                            &frame.payload,
                            binding.transfer_id,
                            binding.checkpoint_generation,
                            binding.file_size,
                        )?);
                        peer_pause.cancel();
                        cancellation.cancel();
                    }
                    MESSAGE_TRANSFER_STATUS_QUERY => {
                        split_transfer::respond_outgoing_status_query(
                            &record,
                            &stream,
                            &channel,
                            &frame.payload,
                            binding.transfer_id,
                            parse_uuid(&binding.session_id)?,
                            lineage,
                        ).await?;
                    }
                    _ => return Err("authenticated-control-state-invalid".into()),
                }
            }
        }
    }
    let local_stop = record.mutable.lock().await.local_stop;
    let stopped = cancellation.is_cancelled()
        || peer_cancel.is_cancelled()
        || peer_pause.is_cancelled()
        || local_stop.is_some();
    if stopped {
        settle_resume_monitor(&mut monitor).await;
    }
    if stopped {
        if local_stop == Some(LocalStopIntent::Pause) || peer_pause.is_cancelled() {
            return finish_resumed_sender_pause(
                &record,
                &stream,
                &channel,
                frame_rx,
                &binding,
                lineage,
                pending_pause,
            )
            .await;
        }
        reconcile_resumed_cancel(&stream, &channel, frame_rx, &binding, lineage).await;
        if peer_cancel.is_cancelled() {
            linger_resumed_outgoing_status(&record, &stream, &channel, frame_rx, &binding, lineage)
                .await;
            return Err("peer-cancelled".into());
        }
        return Err("native-transfer-cancelled".into());
    }
    let sent = record.mutable.lock().await.bytes_sent;
    if sent != missing_bytes {
        return Err("resume-transfer-interrupted".into());
    }
    if let Err(error) = super::cross_device::claim_outgoing_finalization(&record).await {
        settle_resume_monitor(&mut monitor).await;
        if error == "native-transfer-paused" {
            return finish_resumed_sender_pause(
                &record,
                &stream,
                &channel,
                frame_rx,
                &binding,
                lineage,
                pending_pause,
            )
            .await;
        }
        reconcile_resumed_cancel(&stream, &channel, frame_rx, &binding, lineage).await;
        return Err(error);
    }
    monitor.abort();
    send_resume_message(
        &stream,
        &channel,
        &ResumeControlMessage::CompletionManifest(ResumeCompletionManifest {
            binding: binding.clone(),
            transferred_blocks: missing_blocks,
            transferred_bytes: sent,
            final_sha256: binding.expected_sha256,
        }),
    )
    .await?;
    let mut query_id = None;
    let completion_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let remaining = completion_deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err("completed-ack-lost".into());
        }
        let wait = if query_id.is_some() {
            remaining
        } else {
            remaining.min(Duration::from_millis(500))
        };
        let frame = match tokio::time::timeout(wait, frame_rx.recv()).await {
            Ok(Some(frame)) => frame,
            Ok(None) => return Err("completed-ack-lost".into()),
            Err(_) if query_id.is_none() => {
                query_id = Some(
                    split_transfer::send_status_query(
                        &stream,
                        &channel,
                        binding.transfer_id,
                        parse_uuid(&binding.session_id)?,
                    )
                    .await?,
                );
                continue;
            }
            Err(_) => return Err("completed-ack-lost".into()),
        };
        match frame.message_type {
            MESSAGE_TRANSFER_CANCEL => {
                split_transfer::validate_cancellation_at_generation(
                    &frame.payload,
                    binding.transfer_id,
                    binding.checkpoint_generation,
                )?;
                record.mutable.lock().await.state = OutgoingNativeState::Cancelled;
                split_transfer::send_authenticated(
                    &stream,
                    &channel,
                    MESSAGE_TRANSFER_CANCEL_ACK,
                    &frame.payload,
                )
                .await?;
                linger_resumed_outgoing_status(
                    &record, &stream, &channel, frame_rx, &binding, lineage,
                )
                .await;
                return Err("peer-cancelled".into());
            }
            MESSAGE_TRANSFER_PAUSE_REQUEST => {
                let pause = split_transfer::validate_pause_at_generation(
                    &frame.payload,
                    binding.transfer_id,
                    binding.checkpoint_generation,
                    binding.state_digest,
                )?;
                record.mutable.lock().await.pause_request_id = Some(pause.request_id);
                split_transfer::send_authenticated(
                    &stream,
                    &channel,
                    MESSAGE_TRANSFER_PAUSE_ACCEPT,
                    &frame.payload,
                )
                .await?;
                return finish_resumed_sender_pause(
                    &record, &stream, &channel, frame_rx, &binding, lineage, None,
                )
                .await;
            }
            MESSAGE_TRANSFER_PAUSE_ACCEPT => {
                split_transfer::validate_pause_at_generation(
                    &frame.payload,
                    binding.transfer_id,
                    binding.checkpoint_generation,
                    binding.state_digest,
                )?;
                if record.mutable.lock().await.local_stop == Some(LocalStopIntent::Pause) {
                    return finish_resumed_sender_pause(
                        &record, &stream, &channel, frame_rx, &binding, lineage, None,
                    )
                    .await;
                }
            }
            MESSAGE_TRANSFER_PAUSED => {
                let checkpoint = split_transfer::validate_paused_checkpoint_after(
                    &frame.payload,
                    binding.transfer_id,
                    binding.checkpoint_generation,
                    binding.file_size,
                )?;
                return finish_resumed_sender_pause(
                    &record,
                    &stream,
                    &channel,
                    frame_rx,
                    &binding,
                    lineage,
                    Some(checkpoint),
                )
                .await;
            }
            MESSAGE_COMPLETION_ACK => {
                let message: ResumeControlMessage =
                    serde_json::from_slice(&frame.payload).map_err(|_| "resume-control-invalid")?;
                if let ResumeControlMessage::CompletionAck(ack) = message {
                    return Ok(ack);
                }
                return Err("resume-protocol-unexpected-message".into());
            }
            MESSAGE_TRANSFER_STATUS => {
                let status = split_transfer::validate_transfer_status(
                    &frame.payload,
                    binding.transfer_id,
                    query_id.ok_or("authenticated-status-unexpected")?,
                    parse_uuid(&binding.session_id)?,
                    lineage,
                )?;
                if status.state == TransferStatusState::Completed
                    && status.final_file_completed
                    && status.completed_bytes == binding.file_size
                {
                    return Ok(ResumeCompletionAck {
                        binding: binding.clone(),
                        complete_blocks: binding.total_blocks,
                        received_bytes: binding.file_size,
                        integrity_ok: true,
                        final_sha256: binding.expected_sha256,
                        cleanup_warnings: Vec::new(),
                    });
                }
                query_id = None;
            }
            MESSAGE_TRANSFER_STATUS_QUERY => {
                split_transfer::respond_outgoing_status_query(
                    &record,
                    &stream,
                    &channel,
                    &frame.payload,
                    binding.transfer_id,
                    parse_uuid(&binding.session_id)?,
                    lineage,
                )
                .await?;
            }
            _ => return Err("authenticated-control-state-invalid".into()),
        }
    }
}

async fn receive_missing_blocks(
    record: Arc<IncomingNativeTransfer>,
    connection: Connection,
    session_id: [u8; 16],
    transfer_id: [u8; 16],
    invitation_id: [u8; 16],
    checkpoint: ValidatedIncomingCheckpoint,
) -> Result<SplitTransferResult, String> {
    let started = Instant::now();
    let mut metadata = checkpoint.metadata;
    let binding = resume_binding(
        transfer_id,
        session_id,
        metadata.checkpoint_generation,
        metadata.source.size,
        metadata.expected_sha256,
        metadata.secure_state_digest,
    )?;
    let transfer_commitment = secure_protocol::transfer_commitment(
        binding.file_size,
        &binding.expected_sha256,
        binding.block_size,
        binding.total_blocks,
        binding.capabilities,
    );
    let (mut control_send, mut control_recv) = super::secure_transport::accept_control_stream(
        &connection,
        transfer_id,
        invitation_id,
        session_id,
        binding.checkpoint_generation,
    )
    .await?;
    let mut security = super::secure_transport::authenticate_server(
        &connection,
        &mut control_send,
        &mut control_recv,
        transfer_id,
        invitation_id,
        session_id,
        record.receiver_certificate_fingerprint_sha256,
        SecureSessionMode::Resume,
        binding.checkpoint_generation,
        binding.state_digest,
        transfer_commitment,
        secure_protocol::session_lineage_digest(metadata.previous_session_id.as_ref()),
        binding.capabilities,
    )
    .await?;
    let offer = match read_control(
        &mut control_recv,
        &mut security.control,
        secure_protocol::MESSAGE_RESUME_OFFER,
    )
    .await?
    {
        ResumeControlMessage::Offer(value) => value,
        _ => return Err("resume-protocol-unexpected-message".into()),
    };
    offer
        .binding
        .validate_matches(&binding)
        .map_err(|_| "resume-state-mismatch")?;
    let missing_ranges = missing_block_ranges(&metadata.completed_bitmap, metadata.total_blocks)
        .map_err(|_| "resume-state-mismatch")?;
    let missing_blocks = validate_missing_ranges(&missing_ranges, metadata.total_blocks)
        .map_err(|_| "resume-state-mismatch")?;
    let missing_bytes = bytes_for_ranges(&missing_ranges, &binding)?;
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
        secure_protocol::MESSAGE_RESUME_ACCEPT,
    )
    .await?
    {
        ResumeControlMessage::Accept(value) => value,
        _ => return Err("resume-protocol-unexpected-message".into()),
    };
    accept
        .binding
        .validate_matches(&binding)
        .map_err(|_| "resume-state-mismatch")?;
    let expected_streams = if missing_blocks == 0 {
        0
    } else {
        FROZEN_STREAM_COUNT.min(missing_blocks as u8)
    };
    if accept.missing_range_count != missing_ranges.len() as u64
        || accept.stream_count != expected_streams
    {
        return Err("resume-accept-invalid".into());
    }
    let control_send = Arc::new(Mutex::new(control_send));
    let channel = Arc::new(Mutex::new(security.control));
    let (frame_tx, mut frame_rx) = mpsc::channel(16);
    let reader = tokio::spawn(split_transfer::read_authenticated_frames(
        control_recv,
        channel.clone(),
        frame_tx,
        RESUME_RUNTIME_MESSAGES,
    ));
    let bytes_skipped = metadata.completed_bytes;
    {
        let mut mutable = record.mutable.lock().await;
        mutable.state = IncomingNativeState::Receiving;
        mutable.bytes_skipped = bytes_skipped;
        mutable.bytes_received = 0;
        mutable.bytes_written = 0;
    }
    let cancellation = record.mutable.lock().await.cancellation.clone();
    let completed = Arc::new(Mutex::new(metadata.completed_bitmap.clone()));
    let hashes = Arc::new(Mutex::new(checkpoint.hashes));
    let claimed = Arc::new(Mutex::new(vec![0u8; metadata.completed_bitmap.len()]));
    let (free_tx, free_rx) = mpsc::channel::<Vec<u8>>(FROZEN_RECEIVER_BUFFER_COUNT);
    for _ in 0..FROZEN_RECEIVER_BUFFER_COUNT {
        free_tx
            .send(vec![0u8; FROZEN_BLOCK_BYTES])
            .await
            .map_err(|_| "receiver-buffer-pool-failed")?;
    }
    let free_rx = Arc::new(Mutex::new(free_rx));
    let mut tasks = Vec::new();
    for _ in 0..accept.stream_count {
        let stream = connection
            .accept_uni()
            .await
            .map_err(|_| "transfer-interrupted")?;
        tasks.push(tokio::spawn(receiver_stream(
            stream,
            checkpoint.part_path.clone(),
            record.clone(),
            binding.clone(),
            metadata.completed_bitmap.clone(),
            completed.clone(),
            hashes.clone(),
            claimed.clone(),
            free_rx.clone(),
            free_tx.clone(),
            cancellation.clone(),
        )));
    }
    let manifest = drive_resumed_receiver(
        record.clone(),
        control_send.clone(),
        channel.clone(),
        &mut frame_rx,
        tasks,
        &binding,
        &mut metadata,
        &checkpoint.resume_path,
        &checkpoint.part_path,
        completed.clone(),
        hashes.clone(),
    )
    .await?;
    manifest
        .binding
        .validate_matches(&binding)
        .map_err(|_| "resume-state-mismatch")?;
    let received = record.mutable.lock().await.bytes_received;
    let written = record.mutable.lock().await.bytes_written;
    if manifest.transferred_blocks != missing_blocks
        || manifest.transferred_bytes != missing_bytes
        || received != missing_bytes
        || written != missing_bytes
        || manifest.final_sha256 != binding.expected_sha256
    {
        return Err("resume-completion-manifest-invalid".into());
    }
    validate_complete_bitmap(&completed.lock().await, binding.total_blocks)?;
    super::cross_device::reject_reparse_path(&checkpoint.part_path).await?;
    let file = OpenOptions::new()
        .write(true)
        .open(&checkpoint.part_path)
        .await
        .map_err(|_| "receiver-write-failed")?;
    file.sync_all().await.map_err(|_| "receiver-sync-failed")?;
    drop(file);
    let (actual_hash, _) =
        super::file_transfer::sha256_file(&checkpoint.part_path, FROZEN_BLOCK_BYTES).await?;
    if actual_hash != binding.expected_sha256 {
        return Err("integrity-mismatch".into());
    }
    if record.mutable.lock().await.cancellation.is_cancelled() {
        return Err("native-transfer-cancelled".into());
    }
    fs::rename(&checkpoint.part_path, &checkpoint.final_path)
        .await
        .map_err(|_| "atomic-finalization-failed")?;
    {
        let mut mutable = record.mutable.lock().await;
        mutable.state = IncomingNativeState::Completed;
        mutable.bytes_received = received;
        mutable.bytes_written = received;
        mutable.integrity_result = Some("passed".into());
    }
    if !drop_completion_ack_for_test() {
        send_resume_message(
            &control_send,
            &channel,
            &ResumeControlMessage::CompletionAck(ResumeCompletionAck {
                binding: binding.clone(),
                complete_blocks: binding.total_blocks,
                received_bytes: received,
                integrity_ok: true,
                final_sha256: actual_hash,
                cleanup_warnings: Vec::new(),
            }),
        )
        .await?;
    }
    linger_resumed_incoming_status(
        &record,
        &control_send,
        &channel,
        &mut frame_rx,
        &binding,
        secure_protocol::session_lineage_digest(metadata.previous_session_id.as_ref()),
    )
    .await;
    reader.abort();
    let _ = resume::remove_generations(&checkpoint.resume_path).await;
    let _ = block_hash::remove_generations(&checkpoint.resume_path).await;
    let _ = super::secret_store::delete(&checkpoint.resume_path).await;
    let _ = authorization::consume(&transfer_id);
    let stats = connection.stats();
    let elapsed = started.elapsed().as_secs_f64().max(0.000_001);
    let result = SplitTransferResult {
        transfer_id: record.transfer_id.clone(),
        role: "receiver",
        total_bytes: binding.file_size,
        payload_bytes: received,
        bytes_skipped,
        blocks_transferred: missing_blocks,
        blocks_skipped: binding.total_blocks - missing_blocks,
        elapsed_seconds: elapsed,
        average_mbps: received as f64 / 1024.0 / 1024.0 / elapsed,
        rtt_ms: stats.path.rtt.as_secs_f64() * 1000.0,
        lost_packets: stats.path.lost_packets,
        congestion_window_bytes: stats.path.cwnd,
        mtu: stats.path.current_mtu,
        integrity_result: "passed",
        signaling_file_payload_bytes: 0,
    };
    println!(
        "[FlowShareNativeSplitResume] {}",
        serde_json::to_string(&result).unwrap_or_else(|_| "{}".into())
    );
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
async fn drive_resumed_receiver(
    record: Arc<IncomingNativeTransfer>,
    stream: Arc<Mutex<SendStream>>,
    channel: Arc<Mutex<SecureControlChannel>>,
    frame_rx: &mut mpsc::Receiver<AuthenticatedFrame>,
    tasks: Vec<tokio::task::JoinHandle<Result<(), String>>>,
    binding: &ResumeBinding,
    metadata: &mut ResumeMetadata,
    resume_path: &Path,
    part_path: &Path,
    completed: Arc<Mutex<Vec<u8>>>,
    hashes: Arc<Mutex<Vec<Option<[u8; 32]>>>>,
) -> Result<ResumeCompletionManifest, String> {
    let cancellation = record.mutable.lock().await.cancellation.clone();
    let peer_cancel = CancellationToken::new();
    let peer_pause = CancellationToken::new();
    let lineage = secure_protocol::session_lineage_digest(metadata.previous_session_id.as_ref());
    let mut monitor = spawn_resume_control_incoming(
        record.clone(),
        stream.clone(),
        channel.clone(),
        binding.clone(),
    );
    let mut pending_manifest = None;
    let mut joined = Box::pin(join_resume_tasks(tasks));
    loop {
        tokio::select! {
            result = &mut joined => {
                if let Err(error) = result {
                    let local_stop_requested = record.mutable.lock().await.local_stop.is_some();
                    if !cancellation.is_cancelled()
                        && !peer_cancel.is_cancelled()
                        && !peer_pause.is_cancelled()
                        && !local_stop_requested
                    {
                        monitor.abort();
                        return Err(error);
                    }
                }
                break;
            }
            frame = frame_rx.recv() => {
                let frame = frame.ok_or("transfer-interrupted")?;
                match frame.message_type {
                    MESSAGE_TRANSFER_CANCEL => {
                        let control = split_transfer::validate_cancellation_at_generation(
                            &frame.payload,
                            binding.transfer_id,
                            binding.checkpoint_generation,
                        )?;
                        {
                            let mut mutable = record.mutable.lock().await;
                            mutable.state = IncomingNativeState::Cancelled;
                            mutable.peer_cancel_retain_partial = Some(control.retain_partial);
                        }
                        peer_cancel.cancel();
                        cancellation.cancel();
                        split_transfer::send_authenticated(&stream, &channel, MESSAGE_TRANSFER_CANCEL_ACK, &frame.payload).await?;
                    }
                    MESSAGE_TRANSFER_CANCEL_ACK => {
                        split_transfer::validate_cancellation_at_generation(&frame.payload, binding.transfer_id, binding.checkpoint_generation)?;
                        if matches!(record.mutable.lock().await.local_stop, Some(LocalStopIntent::Cancel { .. })) {
                            cancellation.cancel();
                        }
                    }
                    MESSAGE_TRANSFER_PAUSE_REQUEST => {
                        let pause = split_transfer::validate_pause_at_generation(
                            &frame.payload,
                            binding.transfer_id,
                            binding.checkpoint_generation,
                            binding.state_digest,
                        )?;
                        record.mutable.lock().await.pause_request_id = Some(pause.request_id);
                        peer_pause.cancel();
                        cancellation.cancel();
                        split_transfer::send_authenticated(&stream, &channel, MESSAGE_TRANSFER_PAUSE_ACCEPT, &frame.payload).await?;
                    }
                    MESSAGE_TRANSFER_PAUSE_ACCEPT => {
                        split_transfer::validate_pause_at_generation(
                            &frame.payload,
                            binding.transfer_id,
                            binding.checkpoint_generation,
                            binding.state_digest,
                        )?;
                        if record.mutable.lock().await.local_stop == Some(LocalStopIntent::Pause) {
                            cancellation.cancel();
                        }
                    }
                    MESSAGE_TRANSFER_PAUSED => {
                        split_transfer::validate_paused_checkpoint_after(
                            &frame.payload,
                            binding.transfer_id,
                            binding.checkpoint_generation,
                            binding.file_size,
                        )?;
                    }
                    MESSAGE_COMPLETION_MANIFEST => pending_manifest = Some(frame.payload),
                    MESSAGE_TRANSFER_STATUS_QUERY => {
                        split_transfer::respond_incoming_status_query(
                            &record,
                            &stream,
                            &channel,
                            &frame.payload,
                            binding.transfer_id,
                            parse_uuid(&binding.session_id)?,
                            lineage,
                        ).await?;
                    }
                    _ => return Err("authenticated-control-state-invalid".into()),
                }
            }
        }
    }
    let local_stop = record.mutable.lock().await.local_stop;
    let stopped = cancellation.is_cancelled()
        || peer_cancel.is_cancelled()
        || peer_pause.is_cancelled()
        || local_stop.is_some();
    if stopped {
        settle_resume_monitor(&mut monitor).await;
    }
    if stopped {
        if local_stop == Some(LocalStopIntent::Pause) || peer_pause.is_cancelled() {
            return finish_resumed_receiver_pause(
                &record,
                &stream,
                &channel,
                frame_rx,
                binding,
                metadata,
                resume_path,
                part_path,
                completed,
                hashes,
                lineage,
            )
            .await;
        }
        reconcile_resumed_cancel(&stream, &channel, frame_rx, binding, lineage).await;
        if peer_cancel.is_cancelled() {
            linger_resumed_incoming_status(&record, &stream, &channel, frame_rx, binding, lineage)
                .await;
            return Err("peer-cancelled".into());
        }
        return Err("native-transfer-cancelled".into());
    }
    if let Err(error) = super::cross_device::claim_incoming_finalization(&record).await {
        settle_resume_monitor(&mut monitor).await;
        if error == "native-transfer-paused" {
            return finish_resumed_receiver_pause(
                &record,
                &stream,
                &channel,
                frame_rx,
                binding,
                metadata,
                resume_path,
                part_path,
                completed,
                hashes,
                lineage,
            )
            .await;
        }
        reconcile_resumed_cancel(&stream, &channel, frame_rx, binding, lineage).await;
        return Err(error);
    }
    monitor.abort();
    let payload = if let Some(payload) = pending_manifest {
        payload
    } else {
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(30), frame_rx.recv())
                .await
                .map_err(|_| "transfer-interrupted".to_string())?
                .ok_or("transfer-interrupted")?;
            match frame.message_type {
                MESSAGE_COMPLETION_MANIFEST => break frame.payload,
                MESSAGE_TRANSFER_STATUS_QUERY => {
                    split_transfer::respond_incoming_status_query(
                        &record,
                        &stream,
                        &channel,
                        &frame.payload,
                        binding.transfer_id,
                        parse_uuid(&binding.session_id)?,
                        lineage,
                    )
                    .await?;
                }
                MESSAGE_TRANSFER_CANCEL => {
                    let control = split_transfer::validate_cancellation_at_generation(
                        &frame.payload,
                        binding.transfer_id,
                        binding.checkpoint_generation,
                    )?;
                    record.mutable.lock().await.peer_cancel_retain_partial =
                        Some(control.retain_partial);
                    split_transfer::send_authenticated(
                        &stream,
                        &channel,
                        MESSAGE_TRANSFER_CANCEL_ACK,
                        &frame.payload,
                    )
                    .await?;
                    return Err("peer-cancelled".into());
                }
                MESSAGE_TRANSFER_PAUSE_REQUEST => {
                    let pause = split_transfer::validate_pause_at_generation(
                        &frame.payload,
                        binding.transfer_id,
                        binding.checkpoint_generation,
                        binding.state_digest,
                    )?;
                    record.mutable.lock().await.pause_request_id = Some(pause.request_id);
                    split_transfer::send_authenticated(
                        &stream,
                        &channel,
                        MESSAGE_TRANSFER_PAUSE_ACCEPT,
                        &frame.payload,
                    )
                    .await?;
                    return finish_resumed_receiver_pause(
                        &record,
                        &stream,
                        &channel,
                        frame_rx,
                        binding,
                        metadata,
                        resume_path,
                        part_path,
                        completed,
                        hashes,
                        lineage,
                    )
                    .await;
                }
                _ => return Err("authenticated-control-state-invalid".into()),
            }
        }
    };
    match serde_json::from_slice::<ResumeControlMessage>(&payload)
        .map_err(|_| "resume-control-invalid")?
    {
        ResumeControlMessage::CompletionManifest(value) => Ok(value),
        _ => Err("resume-protocol-unexpected-message".into()),
    }
}

#[allow(clippy::too_many_arguments)]
async fn finish_resumed_receiver_pause(
    record: &IncomingNativeTransfer,
    stream: &Arc<Mutex<SendStream>>,
    channel: &Arc<Mutex<SecureControlChannel>>,
    frame_rx: &mut mpsc::Receiver<AuthenticatedFrame>,
    binding: &ResumeBinding,
    metadata: &mut ResumeMetadata,
    resume_path: &Path,
    part_path: &Path,
    completed: Arc<Mutex<Vec<u8>>>,
    hashes: Arc<Mutex<Vec<Option<[u8; 32]>>>>,
    lineage: [u8; 32],
) -> Result<ResumeCompletionManifest, String> {
    let checkpoint = checkpoint_resumed_incoming(
        record,
        metadata,
        resume_path,
        part_path,
        completed,
        hashes,
        parse_uuid(&binding.session_id)?,
    )
    .await?;
    split_transfer::send_authenticated(
        stream,
        channel,
        MESSAGE_TRANSFER_PAUSED,
        &serde_json::to_vec(&checkpoint).map_err(|_| "authenticated-control-invalid")?,
    )
    .await?;
    linger_resumed_incoming_status(record, stream, channel, frame_rx, binding, lineage).await;
    Err("native-transfer-paused".into())
}

fn spawn_resume_control_outgoing(
    record: Arc<OutgoingNativeTransfer>,
    stream: Arc<Mutex<SendStream>>,
    channel: Arc<Mutex<SecureControlChannel>>,
    binding: ResumeBinding,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let request = record.mutable.lock().await.control_request.clone();
        request.cancelled().await;
        let (intent, pause_request_id, completed_bytes) = {
            let mutable = record.mutable.lock().await;
            (
                mutable.local_stop,
                mutable.pause_request_id,
                mutable.peer_completed_bytes,
            )
        };
        let message = match intent {
            Some(LocalStopIntent::Cancel { retain_partial }) => (
                MESSAGE_TRANSFER_CANCEL,
                serde_json::to_vec(&CancellationControl {
                    transfer_id: binding.transfer_id,
                    retain_partial,
                    checkpoint_generation: binding.checkpoint_generation,
                }),
            ),
            Some(LocalStopIntent::Pause) => (
                MESSAGE_TRANSFER_PAUSE_REQUEST,
                serde_json::to_vec(&PauseControl {
                    transfer_id: binding.transfer_id,
                    request_id: pause_request_id.unwrap_or_else(|| *Uuid::new_v4().as_bytes()),
                    checkpoint_generation: binding.checkpoint_generation,
                    state_digest: binding.state_digest,
                    completed_bytes,
                }),
            ),
            None => return,
        };
        if let Ok(payload) = message.1 {
            let result =
                split_transfer::send_authenticated(&stream, &channel, message.0, &payload).await;
            log_resume_control("sender", message.0, &result);
            if result.is_ok() {
                record.mutable.lock().await.cancellation.cancel();
            }
        }
    })
}

fn spawn_resume_control_incoming(
    record: Arc<IncomingNativeTransfer>,
    stream: Arc<Mutex<SendStream>>,
    channel: Arc<Mutex<SecureControlChannel>>,
    binding: ResumeBinding,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let request = record.mutable.lock().await.control_request.clone();
        request.cancelled().await;
        let (intent, pause_request_id, completed_bytes) = {
            let mutable = record.mutable.lock().await;
            (
                mutable.local_stop,
                mutable.pause_request_id,
                mutable.completed_checkpoint_bytes,
            )
        };
        let message = match intent {
            Some(LocalStopIntent::Cancel { retain_partial }) => (
                MESSAGE_TRANSFER_CANCEL,
                serde_json::to_vec(&CancellationControl {
                    transfer_id: binding.transfer_id,
                    retain_partial,
                    checkpoint_generation: binding.checkpoint_generation,
                }),
            ),
            Some(LocalStopIntent::Pause) => (
                MESSAGE_TRANSFER_PAUSE_REQUEST,
                serde_json::to_vec(&PauseControl {
                    transfer_id: binding.transfer_id,
                    request_id: pause_request_id.unwrap_or_else(|| *Uuid::new_v4().as_bytes()),
                    checkpoint_generation: binding.checkpoint_generation,
                    state_digest: binding.state_digest,
                    completed_bytes,
                }),
            ),
            None => return,
        };
        if let Ok(payload) = message.1 {
            let result =
                split_transfer::send_authenticated(&stream, &channel, message.0, &payload).await;
            log_resume_control("receiver", message.0, &result);
            if result.is_ok() {
                record.mutable.lock().await.cancellation.cancel();
            }
        }
    })
}

fn log_resume_control(role: &str, message_type: u16, result: &Result<(), String>) {
    println!(
        "[FlowShareNativeControl] {}",
        serde_json::json!({
            "event": "authenticated-resume-control-send",
            "role": role,
            "messageType": message_type,
            "written": result.is_ok(),
            "error": result.as_ref().err(),
        })
    );
}

async fn settle_resume_monitor(monitor: &mut tokio::task::JoinHandle<()>) {
    if tokio::time::timeout(Duration::from_millis(900), &mut *monitor)
        .await
        .is_err()
    {
        monitor.abort();
    }
}

async fn send_resume_message(
    stream: &Arc<Mutex<SendStream>>,
    channel: &Arc<Mutex<SecureControlChannel>>,
    message: &ResumeControlMessage,
) -> Result<(), String> {
    split_transfer::send_authenticated(
        stream,
        channel,
        message_type(message),
        &serde_json::to_vec(message).map_err(|_| "resume-control-invalid")?,
    )
    .await
}

async fn reconcile_resumed_cancel(
    stream: &Arc<Mutex<SendStream>>,
    channel: &Arc<Mutex<SecureControlChannel>>,
    frame_rx: &mut mpsc::Receiver<AuthenticatedFrame>,
    binding: &ResumeBinding,
    lineage: [u8; 32],
) {
    let Ok(query_id) = split_transfer::send_status_query(
        stream,
        channel,
        binding.transfer_id,
        parse_uuid(&binding.session_id).unwrap_or([0; 16]),
    )
    .await
    else {
        return;
    };
    let _ = tokio::time::timeout(Duration::from_millis(1_500), async {
        while let Some(frame) = frame_rx.recv().await {
            if frame.message_type == MESSAGE_TRANSFER_STATUS {
                let status = split_transfer::validate_transfer_status(
                    &frame.payload,
                    binding.transfer_id,
                    query_id,
                    parse_uuid(&binding.session_id)?,
                    lineage,
                )?;
                return if status.state == TransferStatusState::Cancelled {
                    Ok::<(), String>(())
                } else {
                    Err("authenticated-status-state-invalid".into())
                };
            }
        }
        Err::<(), String>("authenticated-status-unavailable".into())
    })
    .await;
}

async fn finish_resumed_sender_pause(
    record: &OutgoingNativeTransfer,
    stream: &Arc<Mutex<SendStream>>,
    channel: &Arc<Mutex<SecureControlChannel>>,
    frame_rx: &mut mpsc::Receiver<AuthenticatedFrame>,
    binding: &ResumeBinding,
    lineage: [u8; 32],
    pending: Option<PauseControl>,
) -> Result<ResumeCompletionAck, String> {
    let checkpoint = if let Some(value) = pending {
        value
    } else {
        let query_id = split_transfer::send_status_query(
            stream,
            channel,
            binding.transfer_id,
            parse_uuid(&binding.session_id)?,
        )
        .await?;
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(30), frame_rx.recv())
                .await
                .map_err(|_| "peer-paused-state-lost".to_string())?
                .ok_or("peer-paused-state-lost")?;
            match frame.message_type {
                MESSAGE_TRANSFER_PAUSED => {
                    break split_transfer::validate_paused_checkpoint_after(
                        &frame.payload,
                        binding.transfer_id,
                        binding.checkpoint_generation,
                        binding.file_size,
                    )?
                }
                MESSAGE_TRANSFER_STATUS => {
                    let status = split_transfer::validate_transfer_status(
                        &frame.payload,
                        binding.transfer_id,
                        query_id,
                        parse_uuid(&binding.session_id)?,
                        lineage,
                    )?;
                    if status.state != TransferStatusState::Paused
                        || status.checkpoint_generation <= binding.checkpoint_generation
                        || status.state_digest == [0; 32]
                    {
                        continue;
                    }
                    break PauseControl {
                        transfer_id: binding.transfer_id,
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
                _ => {}
            }
        }
    };
    {
        let mut mutable = record.mutable.lock().await;
        mutable.state = OutgoingNativeState::Paused;
        mutable.peer_checkpoint_generation = Some(checkpoint.checkpoint_generation);
        mutable.peer_state_digest = Some(checkpoint.state_digest);
        mutable.peer_completed_bytes = checkpoint.completed_bytes;
        mutable.pause_request_id = None;
    }
    authorization::mark_resumable(&binding.transfer_id)?;
    let _ = split_transfer::send_authenticated(
        stream,
        channel,
        MESSAGE_TRANSFER_PAUSED,
        &serde_json::to_vec(&checkpoint).map_err(|_| "authenticated-control-invalid")?,
    )
    .await;
    Err("native-transfer-paused".into())
}

#[allow(clippy::too_many_arguments)]
async fn checkpoint_resumed_incoming(
    record: &IncomingNativeTransfer,
    metadata: &mut ResumeMetadata,
    resume_path: &Path,
    part_path: &Path,
    completed: Arc<Mutex<Vec<u8>>>,
    hashes: Arc<Mutex<Vec<Option<[u8; 32]>>>>,
    session_id: [u8; 16],
) -> Result<PauseControl, String> {
    super::cross_device::reject_reparse_path(part_path).await?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(part_path)
        .await
        .map_err(|_| "resume-part-missing")?;
    file.sync_all().await.map_err(|_| "receiver-sync-failed")?;
    drop(file);
    let bitmap = completed.lock().await.clone();
    let mut completed_bytes = 0u64;
    for block in 0..metadata.total_blocks {
        if bitmap[(block / 8) as usize] & (1 << (block % 8)) != 0 {
            completed_bytes = completed_bytes.saturating_add(resume::block_length(
                block,
                metadata.block_size,
                metadata.source.size,
                metadata.total_blocks,
            )?);
        }
    }
    let generation = metadata.checkpoint_generation.saturating_add(1);
    let material = authorization::material_for_transfer(&metadata.transfer_id)?;
    let checkpoint_key = secure_protocol::derive_checkpoint_key(
        &material.master,
        &metadata.transfer_id,
        &metadata.invitation_id,
    )?;
    let part_identity_digest = resume::part_identity_digest(part_path).await?;
    let mut manifest = block_hash::from_hashes(
        metadata.transfer_id,
        generation,
        metadata.source.size,
        metadata.block_size,
        &hashes.lock().await,
    )?;
    manifest.authenticate(
        metadata.invitation_id,
        part_identity_digest,
        &checkpoint_key,
    )?;
    let sidecar_digest = manifest.authenticated_digest()?;
    block_hash::write_atomic_authenticated(resume_path, &manifest, &checkpoint_key, None).await?;
    metadata.lifecycle_generation = generation;
    metadata.checkpoint_generation = generation;
    metadata.checkpoint_state = super::lifecycle::TransferState::Paused;
    metadata.previous_session_id = Some(session_id);
    metadata.completed_bitmap = bitmap;
    metadata.completed_bytes = completed_bytes;
    metadata.checkpoint_unix_ms = super::file_transfer::now_unix_ms();
    metadata.retain_partial = true;
    metadata.refresh_security(&checkpoint_key, sidecar_digest, part_identity_digest)?;
    resume::write_atomic_authenticated(resume_path, metadata, &checkpoint_key).await?;
    authorization::mark_resumable(&metadata.transfer_id)?;
    let request_id = record
        .mutable
        .lock()
        .await
        .pause_request_id
        .unwrap_or_else(|| *Uuid::new_v4().as_bytes());
    {
        let mut mutable = record.mutable.lock().await;
        mutable.state = IncomingNativeState::Paused;
        mutable.checkpoint_generation = generation;
        mutable.secure_state_digest = Some(metadata.secure_state_digest);
        mutable.completed_checkpoint_bytes = completed_bytes;
        mutable.pause_request_id = None;
    }
    Ok(PauseControl {
        transfer_id: metadata.transfer_id,
        request_id,
        checkpoint_generation: generation,
        state_digest: metadata.secure_state_digest,
        completed_bytes,
    })
}

async fn linger_resumed_outgoing_status(
    record: &OutgoingNativeTransfer,
    stream: &Arc<Mutex<SendStream>>,
    channel: &Arc<Mutex<SecureControlChannel>>,
    frame_rx: &mut mpsc::Receiver<AuthenticatedFrame>,
    binding: &ResumeBinding,
    lineage: [u8; 32],
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while let Ok(Some(frame)) = tokio::time::timeout_at(deadline, frame_rx.recv()).await {
        if frame.message_type == MESSAGE_TRANSFER_STATUS_QUERY {
            let _ = split_transfer::respond_outgoing_status_query(
                record,
                stream,
                channel,
                &frame.payload,
                binding.transfer_id,
                parse_uuid(&binding.session_id).unwrap_or([0; 16]),
                lineage,
            )
            .await;
        }
    }
}

async fn linger_resumed_incoming_status(
    record: &IncomingNativeTransfer,
    stream: &Arc<Mutex<SendStream>>,
    channel: &Arc<Mutex<SecureControlChannel>>,
    frame_rx: &mut mpsc::Receiver<AuthenticatedFrame>,
    binding: &ResumeBinding,
    lineage: [u8; 32],
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while let Ok(Some(frame)) = tokio::time::timeout_at(deadline, frame_rx.recv()).await {
        if frame.message_type == MESSAGE_TRANSFER_STATUS_QUERY {
            let _ = split_transfer::respond_incoming_status_query(
                record,
                stream,
                channel,
                &frame.payload,
                binding.transfer_id,
                parse_uuid(&binding.session_id).unwrap_or([0; 16]),
                lineage,
            )
            .await;
        }
    }
}

async fn join_resume_tasks(
    tasks: Vec<tokio::task::JoinHandle<Result<(), String>>>,
) -> Result<(), String> {
    let mut first_error = None;
    for task in tasks {
        match task.await.map_err(|_| "transfer-interrupted")? {
            Ok(()) => {}
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn drop_completion_ack_for_test() -> bool {
    cfg!(debug_assertions)
        && std::env::var("FLOWGET_NATIVE_TEST_DROP_COMPLETION_ACK")
            .ok()
            .is_some_and(|value| value == "1")
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

async fn sender_worker(
    mut stream: SendStream,
    source_path: PathBuf,
    record: Arc<OutgoingNativeTransfer>,
    binding: ResumeBinding,
    scheduler: Arc<StdMutex<MissingScheduler>>,
    cancellation: tokio_util::sync::CancellationToken,
) -> Result<(), String> {
    let mut source = File::open(source_path)
        .await
        .map_err(|_| "sender-read-failed")?;
    let mut buffer = vec![0u8; binding.block_size as usize];
    loop {
        if cancellation.is_cancelled() {
            return Err("native-transfer-cancelled".into());
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
            .map_err(|_| "sender-read-failed")?;
        source
            .read_exact(&mut buffer[..length as usize])
            .await
            .map_err(|_| "sender-read-failed")?;
        stream
            .write_u8(1)
            .await
            .map_err(|_| "transfer-interrupted")?;
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
            .map_err(|_| "transfer-interrupted")?;
        stream
            .write_all(&buffer[..length as usize])
            .await
            .map_err(|_| "transfer-interrupted")?;
        record.mutable.lock().await.bytes_sent += length;
    }
    stream
        .write_u8(0)
        .await
        .map_err(|_| "transfer-interrupted")?;
    stream
        .finish()
        .map_err(|_| "transfer-interrupted".to_string())?;
    match stream.stopped().await.map_err(|_| "transfer-interrupted")? {
        None => Ok(()),
        Some(_) => Err("transfer-interrupted".into()),
    }
}

#[allow(clippy::too_many_arguments)]
async fn receiver_stream(
    mut stream: RecvStream,
    part_path: PathBuf,
    record: Arc<IncomingNativeTransfer>,
    binding: ResumeBinding,
    initial_completed: Vec<u8>,
    completed: Arc<Mutex<Vec<u8>>>,
    hashes: Arc<Mutex<Vec<Option<[u8; 32]>>>>,
    claimed: Arc<Mutex<Vec<u8>>>,
    free_rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    free_tx: mpsc::Sender<Vec<u8>>,
    cancellation: tokio_util::sync::CancellationToken,
) -> Result<(), String> {
    let (write_tx, mut write_rx) =
        mpsc::channel::<(u64, u64, usize, Vec<u8>)>(FROZEN_WRITE_QUEUE_CAPACITY);
    let writer_record = record.clone();
    let writer_completed = completed.clone();
    let writer_hashes = hashes.clone();
    let writer_pool = free_tx.clone();
    let writer = tokio::spawn(async move {
        let mut file = OpenOptions::new()
            .write(true)
            .open(part_path)
            .await
            .map_err(|_| "receiver-write-failed")?;
        while let Some((block, offset, valid, buffer)) = write_rx.recv().await {
            file.seek(SeekFrom::Start(offset))
                .await
                .map_err(|_| "receiver-write-failed")?;
            file.write_all(&buffer[..valid])
                .await
                .map_err(|_| "receiver-write-failed")?;
            let digest: [u8; 32] = Sha256::digest(&buffer[..valid]).into();
            {
                let mut bitmap = writer_completed.lock().await;
                let byte = (block / 8) as usize;
                let mask = 1 << (block % 8);
                if bitmap[byte] & mask != 0 {
                    return Err("resume-duplicate-completed-block".to_string());
                }
                bitmap[byte] |= mask;
            }
            writer_hashes.lock().await[block as usize] = Some(digest);
            writer_record.mutable.lock().await.bytes_written += valid as u64;
            writer_pool
                .send(buffer)
                .await
                .map_err(|_| "receiver-buffer-pool-failed")?;
        }
        file.flush()
            .await
            .map_err(|_| "receiver-write-failed".to_string())
    });
    let receive_result = async {
        loop {
            if cancellation.is_cancelled() {
                return Err("native-transfer-cancelled".into());
            }
            let marker = stream.read_u8().await.map_err(|_| "transfer-interrupted")?;
            if marker == 0 {
                require_stream_eof(&mut stream).await?;
                break;
            }
            if marker != 1 {
                return Err("resume-data-frame-invalid".into());
            }
            let mut encoded = [0u8; RANGE_HEADER_BYTES];
            stream
                .read_exact(&mut encoded)
                .await
                .map_err(|_| "transfer-interrupted")?;
            let header = RangeHeader::decode(&encoded).map_err(|_| "resume-data-frame-invalid")?;
            header
                .validate(&binding.transfer_id, binding.file_size)
                .map_err(|_| "resume-data-block-invalid")?;
            if header.flags != 1
                || header.offset % binding.block_size != 0
                || header.range_id as u64 != header.offset / binding.block_size
            {
                return Err("resume-data-block-invalid".into());
            }
            let block = header.range_id as u64;
            if block >= binding.total_blocks {
                return Err("resume-data-block-invalid".into());
            }
            let expected_length = (binding.file_size - header.offset).min(binding.block_size);
            if header.length != expected_length
                || initial_completed[(block / 8) as usize] & (1 << (block % 8)) != 0
            {
                return Err("resume-data-block-invalid".into());
            }
            {
                let mut bitmap = claimed.lock().await;
                let byte = (block / 8) as usize;
                let mask = 1 << (block % 8);
                if bitmap[byte] & mask != 0 {
                    return Err("resume-duplicate-block-ownership".into());
                }
                bitmap[byte] |= mask;
            }
            let mut buffer = free_rx
                .lock()
                .await
                .recv()
                .await
                .ok_or("receiver-buffer-pool-failed")?;
            stream
                .read_exact(&mut buffer[..header.length as usize])
                .await
                .map_err(|_| "transfer-interrupted")?;
            write_tx
                .send((block, header.offset, header.length as usize, buffer))
                .await
                .map_err(|_| "receiver-write-failed")?;
            record.mutable.lock().await.bytes_received += header.length;
        }
        Ok::<(), String>(())
    }
    .await;
    drop(write_tx);
    let writer_result = writer.await.map_err(|_| "receiver-write-failed")?;
    receive_result?;
    writer_result
}

fn resume_binding(
    transfer_id: [u8; 16],
    session_id: [u8; 16],
    checkpoint_generation: u64,
    file_size: u64,
    expected_sha256: [u8; 32],
    state_digest: [u8; 32],
) -> Result<ResumeBinding, String> {
    let binding = ResumeBinding {
        version: NATIVE_QUIC_PROTOCOL_VERSION,
        transfer_id,
        session_id: uuid::Uuid::from_bytes(session_id).to_string(),
        checkpoint_generation,
        file_size,
        block_size: FROZEN_BLOCK_BYTES as u64,
        total_blocks: file_size.div_ceil(FROZEN_BLOCK_BYTES as u64),
        expected_sha256,
        state_digest,
        capabilities: RESUME_REQUIRED_CAPABILITIES,
    };
    binding.validate().map_err(|_| "resume-state-mismatch")?;
    Ok(binding)
}

fn bytes_for_ranges(ranges: &[MissingBlockRange], binding: &ResumeBinding) -> Result<u64, String> {
    let mut bytes = 0u64;
    for range in ranges {
        for block in range.start_block..range.start_block + range.block_count {
            bytes = bytes
                .checked_add(resume::block_length(
                    block,
                    binding.block_size,
                    binding.file_size,
                    binding.total_blocks,
                )?)
                .ok_or("resume-block-layout-invalid")?;
        }
    }
    Ok(bytes)
}

fn validate_complete_bitmap(bitmap: &[u8], total_blocks: u64) -> Result<(), String> {
    if bitmap.len() != total_blocks.div_ceil(8) as usize {
        return Err("resume-coverage-incomplete".into());
    }
    for block in 0..total_blocks {
        if bitmap[(block / 8) as usize] & (1 << (block % 8)) == 0 {
            return Err("resume-coverage-incomplete".into());
        }
    }
    Ok(())
}

async fn write_control(
    stream: &mut SendStream,
    channel: &mut SecureControlChannel,
    message: &ResumeControlMessage,
) -> Result<(), String> {
    let payload = serde_json::to_vec(message).map_err(|_| "resume-control-invalid")?;
    let message_type = message_type(message);
    let envelope = channel.seal(message_type, &payload)?;
    if envelope.len() > MAX_RESUME_CONTROL_FRAME_BYTES {
        return Err("resume-control-frame-too-large".into());
    }
    stream
        .write_u32(envelope.len() as u32)
        .await
        .map_err(|_| "transfer-interrupted")?;
    stream
        .write_all(&envelope)
        .await
        .map_err(|_| "transfer-interrupted".into())
}

async fn read_control(
    stream: &mut RecvStream,
    channel: &mut SecureControlChannel,
    expected: u16,
) -> Result<ResumeControlMessage, String> {
    let length = stream
        .read_u32()
        .await
        .map_err(|_| "transfer-interrupted")? as usize;
    if length == 0 || length > MAX_RESUME_CONTROL_FRAME_BYTES {
        return Err("resume-control-frame-too-large".into());
    }
    let mut envelope = vec![0u8; length];
    stream
        .read_exact(&mut envelope)
        .await
        .map_err(|_| "transfer-interrupted")?;
    let payload = channel.open(expected, &envelope)?;
    let message: ResumeControlMessage =
        serde_json::from_slice(&payload).map_err(|_| "authentication-failed")?;
    if message_type(&message) != expected {
        return Err("authentication-failed".into());
    }
    Ok(message)
}

fn message_type(message: &ResumeControlMessage) -> u16 {
    match message {
        ResumeControlMessage::Offer(_) => secure_protocol::MESSAGE_RESUME_OFFER,
        ResumeControlMessage::State(_) => secure_protocol::MESSAGE_RESUME_STATE,
        ResumeControlMessage::Accept(_) => secure_protocol::MESSAGE_RESUME_ACCEPT,
        ResumeControlMessage::Reject(_) => secure_protocol::MESSAGE_RESUME_REJECT,
        ResumeControlMessage::CompletionManifest(_) => secure_protocol::MESSAGE_COMPLETION_MANIFEST,
        ResumeControlMessage::CompletionAck(_) => secure_protocol::MESSAGE_COMPLETION_ACK,
    }
}

fn parse_uuid(value: &str) -> Result<[u8; 16], String> {
    Ok(*uuid::Uuid::parse_str(value)
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
            | "secure-handshake-failed"
            | "resume-state-mismatch"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_scheduler_never_repeats_or_fills_completed_gaps() {
        let ranges = vec![
            MissingBlockRange {
                start_block: 1,
                block_count: 2,
            },
            MissingBlockRange {
                start_block: 6,
                block_count: 1,
            },
        ];
        let mut scheduler = MissingScheduler::new(&ranges);
        assert_eq!(scheduler.next(), Some(1));
        assert_eq!(scheduler.next(), Some(2));
        assert_eq!(scheduler.next(), Some(6));
        assert_eq!(scheduler.next(), None);
    }

    #[test]
    fn range_byte_count_handles_partial_final_block() {
        let binding = resume_binding([1; 16], [2; 16], 1, 5_000_000, [3; 32], [4; 32]).unwrap();
        let ranges = vec![MissingBlockRange {
            start_block: 2,
            block_count: 1,
        }];
        assert_eq!(bytes_for_ranges(&ranges, &binding).unwrap(), 805_696);
    }
}
