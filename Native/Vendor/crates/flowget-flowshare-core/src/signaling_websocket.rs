use super::signaling::{
    adapt_envelope_for_existing_signaling, AuthenticatedSignalingEnvelope,
    NativeSignalingTransport, SignalingDeliveryAck, MAX_SIGNALING_ENVELOPE_BYTES,
};
use futures::{SinkExt, StreamExt};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use tokio_util::sync::CancellationToken;

const MAX_WEBSOCKET_MESSAGE_BYTES: usize = 128 * 1024;
const MAX_RECEIVED_ENVELOPES: usize = 128;
const MAX_RECONNECT_ATTEMPTS: u8 = 5;

type NativeSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum NativeWebSocketRole {
    Sender,
    Receiver,
}

#[derive(Debug, Clone)]
pub struct NativeWebSocketSignalingOptions {
    pub endpoint: String,
    pub share_id: String,
    pub role: NativeWebSocketRole,
    pub display_filename: Option<String>,
    pub file_size: Option<u64>,
    pub file_sha256: Option<String>,
    pub expires_at_rfc3339: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeWebSocketSignalingStatus {
    pub connected: bool,
    pub room_bound: bool,
    pub role: NativeWebSocketRole,
    pub share_id: String,
    pub receiver_id: Option<String>,
    pub reconnect_attempts: u8,
    pub queued_incoming_envelopes: usize,
    pub delivered_envelopes: u64,
    pub duplicate_deliveries_dropped: u64,
    pub file_payload_bytes_sent: u64,
    pub last_error: Option<String>,
}

enum OutboundCommand {
    Envelope {
        receiver_id: String,
        envelope: AuthenticatedSignalingEnvelope,
        completion: Option<oneshot::Sender<Result<SignalingDeliveryAck, String>>>,
    },
}

struct SharedState {
    status: NativeWebSocketSignalingStatus,
    incoming: VecDeque<AuthenticatedSignalingEnvelope>,
    seen: VecDeque<(u64, u64, super::signaling::NativeDeviceRole)>,
}

pub struct NativeWebSocketSignalingTransport {
    outbound: mpsc::Sender<OutboundCommand>,
    shared: Arc<StdMutex<SharedState>>,
    cancellation: CancellationToken,
}

impl std::fmt::Debug for NativeWebSocketSignalingTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeWebSocketSignalingTransport")
            .field("status", &self.status())
            .finish()
    }
}

impl NativeWebSocketSignalingTransport {
    pub async fn connect(options: NativeWebSocketSignalingOptions) -> Result<Self, String> {
        super::install_rustls_crypto_provider()?;
        validate_options(&options)?;
        let (socket, receiver_id) = establish(&options).await?;
        let (outbound, outbound_rx) = mpsc::channel(64);
        let cancellation = CancellationToken::new();
        let shared = Arc::new(StdMutex::new(SharedState {
            status: NativeWebSocketSignalingStatus {
                connected: true,
                room_bound: true,
                role: options.role.clone(),
                share_id: options.share_id.clone(),
                receiver_id,
                reconnect_attempts: 0,
                queued_incoming_envelopes: 0,
                delivered_envelopes: 0,
                duplicate_deliveries_dropped: 0,
                file_payload_bytes_sent: 0,
                last_error: None,
            },
            incoming: VecDeque::new(),
            seen: VecDeque::new(),
        }));
        tokio::spawn(run_actor(
            options,
            socket,
            outbound_rx,
            shared.clone(),
            cancellation.clone(),
        ));
        Ok(Self {
            outbound,
            shared,
            cancellation,
        })
    }

    pub fn status(&self) -> NativeWebSocketSignalingStatus {
        self.shared
            .lock()
            .map(|state| state.status.clone())
            .unwrap_or_else(|_| NativeWebSocketSignalingStatus {
                connected: false,
                room_bound: false,
                role: NativeWebSocketRole::Receiver,
                share_id: String::new(),
                receiver_id: None,
                reconnect_attempts: 0,
                queued_incoming_envelopes: 0,
                delivered_envelopes: 0,
                duplicate_deliveries_dropped: 0,
                file_payload_bytes_sent: 0,
                last_error: Some("native-signaling-state-unavailable".into()),
            })
    }

    pub async fn wait_for_receiver_id(&self, timeout: Duration) -> Result<String, String> {
        tokio::time::timeout(timeout, async {
            loop {
                let status = self.status();
                if status.connected && status.room_bound {
                    if let Some(receiver_id) = status.receiver_id.clone() {
                        return Ok(receiver_id);
                    }
                }
                if let Some(error) = terminal_actor_error(&status) {
                    return Err(error);
                }
                if self.cancellation.is_cancelled() {
                    return Err("native-signaling-cancelled".into());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .map_err(|_| "native-signaling-receiver-timeout".to_string())?
    }

    pub async fn send_and_wait_delivery(
        &self,
        receiver_id: &str,
        envelope: AuthenticatedSignalingEnvelope,
        timeout: Duration,
    ) -> Result<SignalingDeliveryAck, String> {
        let (sender, receiver) = oneshot::channel();
        self.outbound
            .send(OutboundCommand::Envelope {
                receiver_id: receiver_id.to_string(),
                envelope,
                completion: Some(sender),
            })
            .await
            .map_err(|_| "native-signaling-transport-unavailable")?;
        tokio::time::timeout(timeout, receiver)
            .await
            .map_err(|_| "native-signaling-delivery-timeout".to_string())?
            .map_err(|_| "native-signaling-transport-unavailable".to_string())?
    }

    /// Deliver an authenticated envelope to the receiver route that is active
    /// at the time of each attempt. Receiver routes are connection-scoped and
    /// may change after a WebSocket reconnect, so callers must not retain the
    /// route returned by the initial room join.
    pub async fn send_and_wait_delivery_current(
        &self,
        envelope: AuthenticatedSignalingEnvelope,
        timeout: Duration,
    ) -> Result<SignalingDeliveryAck, String> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut last_error = "native-signaling-receiver-route-unavailable".to_string();
        loop {
            if self.cancellation.is_cancelled() {
                return Err("native-signaling-cancelled".into());
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(format!(
                    "native-signaling-delivery-retry-exhausted: {last_error}"
                ));
            }
            let status = self.status();
            if let Some(error) = terminal_actor_error(&status) {
                return Err(error);
            }
            if status.connected && status.room_bound {
                if let Some(receiver_id) = status.receiver_id.as_deref() {
                    let attempt_timeout = remaining.min(Duration::from_secs(2));
                    match self
                        .send_and_wait_delivery(receiver_id, envelope.clone(), attempt_timeout)
                        .await
                    {
                        Ok(acknowledgment) => return Ok(acknowledgment),
                        Err(error) if delivery_error_retryable(&error) => {
                            last_error = error;
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                continue;
            }
            tokio::select! {
                _ = self.cancellation.cancelled() => {
                    return Err("native-signaling-cancelled".into());
                }
                _ = tokio::time::sleep(Duration::from_millis(25).min(remaining)) => {}
            }
        }
    }

    pub async fn receive_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<AuthenticatedSignalingEnvelope, String> {
        tokio::time::timeout(timeout, async {
            loop {
                if let Some(envelope) = self.receive("native", None)? {
                    return Ok(envelope);
                }
                let status = self.status();
                if let Some(error) = terminal_actor_error(&status) {
                    return Err(error);
                }
                if self.cancellation.is_cancelled() {
                    return Err("native-signaling-cancelled".into());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .map_err(|_| "native-signaling-receive-timeout".to_string())?
    }

    pub async fn shutdown(&self) {
        self.cancellation.cancel();
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

impl NativeSignalingTransport for NativeWebSocketSignalingTransport {
    fn send(
        &self,
        route: &str,
        envelope: &AuthenticatedSignalingEnvelope,
    ) -> Result<SignalingDeliveryAck, String> {
        validate_route(route)?;
        self.outbound
            .try_send(OutboundCommand::Envelope {
                receiver_id: route.to_string(),
                envelope: envelope.clone(),
                completion: None,
            })
            .map_err(|_| "native-signaling-queue-full")?;
        Ok(SignalingDeliveryAck {
            route: route.to_string(),
            sequence: envelope.sequence,
            accepted: true,
        })
    }

    fn receive(
        &self,
        _route: &str,
        after_sequence: Option<u64>,
    ) -> Result<Option<AuthenticatedSignalingEnvelope>, String> {
        let mut state = self
            .shared
            .lock()
            .map_err(|_| "native-signaling-state-unavailable")?;
        let position = state
            .incoming
            .iter()
            .position(|value| after_sequence.is_none_or(|after| value.sequence > after));
        let envelope = position.and_then(|position| state.incoming.remove(position));
        state.status.queued_incoming_envelopes = state.incoming.len();
        Ok(envelope)
    }

    fn reconnect(&self, _route: &str) -> Result<(), String> {
        if self.cancellation.is_cancelled() {
            Err("native-signaling-cancelled".into())
        } else {
            Ok(())
        }
    }

    fn cancel(&self, _route: &str) -> Result<(), String> {
        self.cancellation.cancel();
        Ok(())
    }
}

async fn run_actor(
    options: NativeWebSocketSignalingOptions,
    initial_socket: NativeSocket,
    mut outbound: mpsc::Receiver<OutboundCommand>,
    shared: Arc<StdMutex<SharedState>>,
    cancellation: CancellationToken,
) {
    let mut socket = Some(initial_socket);
    let mut reconnect_attempts = 0u8;
    while !cancellation.is_cancelled() {
        let Some(active) = socket.take() else {
            if reconnect_attempts >= MAX_RECONNECT_ATTEMPTS {
                update_error(&shared, "native-signaling-reconnect-exhausted");
                break;
            }
            reconnect_attempts += 1;
            update_reconnecting(&shared, reconnect_attempts);
            let delay = reconnect_delay(reconnect_attempts);
            tokio::select! {
                _ = cancellation.cancelled() => break,
                _ = tokio::time::sleep(delay) => {}
            }
            match establish(&options).await {
                Ok((new_socket, receiver_id)) => {
                    update_connected(&shared, receiver_id, reconnect_attempts);
                    socket = Some(new_socket);
                    continue;
                }
                Err(error) => {
                    update_error(&shared, &error);
                    continue;
                }
            }
        };
        match run_connected(&options, active, &mut outbound, &shared, &cancellation).await {
            Ok(()) => break,
            Err(error) => {
                update_error(&shared, &error);
                mark_disconnected(&shared);
                socket = None;
            }
        }
    }
    mark_disconnected(&shared);
}

async fn run_connected(
    options: &NativeWebSocketSignalingOptions,
    socket: NativeSocket,
    outbound: &mut mpsc::Receiver<OutboundCommand>,
    shared: &Arc<StdMutex<SharedState>>,
    cancellation: &CancellationToken,
) -> Result<(), String> {
    let (mut writer, mut reader) = socket.split();
    let mut pending_delivery: VecDeque<(
        u64,
        String,
        Option<oneshot::Sender<Result<SignalingDeliveryAck, String>>>,
    )> = VecDeque::new();
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => {
                let _ = writer.send(Message::Close(None)).await;
                return Ok(());
            }
            command = outbound.recv() => {
                let Some(OutboundCommand::Envelope { receiver_id, envelope, completion }) = command else {
                    return Ok(());
                };
                validate_route(&receiver_id)?;
                let message = adapt_envelope_for_existing_signaling(
                    &options.share_id,
                    &receiver_id,
                    &envelope,
                )?;
                let encoded = serde_json::to_string(&message)
                    .map_err(|_| "native-signaling-message-encode-failed")?;
                if encoded.len() > MAX_WEBSOCKET_MESSAGE_BYTES {
                    return Err("native-signaling-message-oversized".into());
                }
                writer
                    .send(Message::Text(encoded.into()))
                    .await
                    .map_err(|_| "native-signaling-send-failed")?;
                pending_delivery.push_back((envelope.sequence, receiver_id, completion));
            }
            message = reader.next() => {
                let message = message
                    .ok_or("native-signaling-disconnected")?
                    .map_err(|_| "native-signaling-receive-failed")?;
                match message {
                    Message::Text(text) => {
                        if text.len() > MAX_WEBSOCKET_MESSAGE_BYTES {
                            return Err("native-signaling-message-oversized".into());
                        }
                        let value: Value = serde_json::from_str(text.as_ref())
                            .map_err(|_| "native-signaling-message-malformed")?;
                        handle_incoming_value(options, value, shared, &mut pending_delivery)?;
                    }
                    Message::Binary(bytes) => {
                        if bytes.len() > MAX_WEBSOCKET_MESSAGE_BYTES {
                            return Err("native-signaling-message-oversized".into());
                        }
                        let value: Value = serde_json::from_slice(&bytes)
                            .map_err(|_| "native-signaling-message-malformed")?;
                        handle_incoming_value(options, value, shared, &mut pending_delivery)?;
                    }
                    Message::Ping(value) => {
                        writer.send(Message::Pong(value)).await
                            .map_err(|_| "native-signaling-send-failed")?;
                    }
                    Message::Close(_) => return Err("native-signaling-disconnected".into()),
                    _ => {}
                }
            }
        }
    }
}

fn handle_incoming_value(
    options: &NativeWebSocketSignalingOptions,
    value: Value,
    shared: &Arc<StdMutex<SharedState>>,
    pending_delivery: &mut VecDeque<(
        u64,
        String,
        Option<oneshot::Sender<Result<SignalingDeliveryAck, String>>>,
    )>,
) -> Result<(), String> {
    let message_type = value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match message_type {
        "receiver-joined" | "joined" => {
            let share_id = value
                .get("shareId")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let receiver_id = value
                .get("receiverId")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if share_id != options.share_id || validate_route(receiver_id).is_err() {
                return Err("native-signaling-route-mismatch".into());
            }
            if let Ok(mut state) = shared.lock() {
                state.status.receiver_id = Some(receiver_id.to_string());
            }
        }
        "native-connectivity-delivered-v1" => {
            let share_id = value
                .get("shareId")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let receiver_id = value
                .get("receiverId")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if share_id != options.share_id {
                return Err("native-signaling-route-mismatch".into());
            }
            if let Some((sequence, expected_receiver, completion)) = pending_delivery.pop_front() {
                if expected_receiver != receiver_id {
                    return Err("native-signaling-route-mismatch".into());
                }
                if let Some(completion) = completion {
                    let _ = completion.send(Ok(SignalingDeliveryAck {
                        route: receiver_id.to_string(),
                        sequence,
                        accepted: true,
                    }));
                }
                if let Ok(mut state) = shared.lock() {
                    state.status.delivered_envelopes =
                        state.status.delivered_envelopes.saturating_add(1);
                    state.status.last_error = None;
                }
            }
        }
        "native-connectivity-envelope-v1" => {
            let share_id = value
                .get("shareId")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let receiver_id = value
                .get("receiverId")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let encoded = value
                .get("envelope")
                .and_then(Value::as_str)
                .ok_or("native-signaling-message-malformed")?;
            if share_id != options.share_id || validate_route(receiver_id).is_err() {
                return Err("native-signaling-route-mismatch".into());
            }
            if encoded.len() > MAX_SIGNALING_ENVELOPE_BYTES * 2 {
                return Err("native-signaling-envelope-oversized".into());
            }
            let envelope = AuthenticatedSignalingEnvelope::decode(encoded)?;
            let key = (
                envelope.signaling_generation,
                envelope.sequence,
                envelope.sender_role,
            );
            let mut state = shared
                .lock()
                .map_err(|_| "native-signaling-state-unavailable")?;
            if state.seen.contains(&key) {
                state.status.duplicate_deliveries_dropped =
                    state.status.duplicate_deliveries_dropped.saturating_add(1);
                return Ok(());
            }
            if state.incoming.len() >= MAX_RECEIVED_ENVELOPES {
                return Err("native-signaling-incoming-queue-full".into());
            }
            state.seen.push_back(key);
            while state.seen.len() > MAX_RECEIVED_ENVELOPES * 2 {
                state.seen.pop_front();
            }
            state.incoming.push_back(envelope);
            state.status.queued_incoming_envelopes = state.incoming.len();
        }
        "error" => {
            let expected_receiver = pending_delivery
                .front()
                .map(|(_, receiver_id, _)| receiver_id.as_str());
            let error = parse_server_error(options, &value, expected_receiver)?;
            if let Some((_, _, completion)) = pending_delivery.pop_front() {
                if let Some(completion) = completion {
                    let _ = completion.send(Err(error.clone()));
                }
                if let Ok(mut state) = shared.lock() {
                    state.status.last_error = Some(error);
                }
            } else {
                return Err(error);
            }
        }
        _ => {}
    }
    Ok(())
}

async fn establish(
    options: &NativeWebSocketSignalingOptions,
) -> Result<(NativeSocket, Option<String>), String> {
    let (mut socket, _) =
        tokio::time::timeout(Duration::from_secs(10), connect_async(&options.endpoint))
            .await
            .map_err(|_| "native-signaling-connect-timeout".to_string())?
            .map_err(|_| "native-signaling-connect-failed")?;
    let registration = match options.role {
        NativeWebSocketRole::Sender => json!({
            "type": "register-share",
            "shareId": options.share_id,
            "protocolVersion": 2,
            "metadata": {
                "fileName": options.display_filename.as_deref().unwrap_or("native-transfer"),
                "fileSize": options.file_size.unwrap_or(1),
                "fileHash": options.file_sha256,
                "passwordProtected": false,
                "expiresAt": options.expires_at_rfc3339,
            }
        }),
        NativeWebSocketRole::Receiver => json!({
            "type": "join-share",
            "shareId": options.share_id,
            "protocolVersion": 2,
            "receiverKind": "flowget-app",
            "resumeOffset": 0,
            "resumeChunkIndex": 0,
        }),
    };
    let encoded = serde_json::to_string(&registration)
        .map_err(|_| "native-signaling-message-encode-failed")?;
    socket
        .send(Message::Text(encoded.into()))
        .await
        .map_err(|_| "native-signaling-send-failed")?;
    let receiver_id = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let message = socket
                .next()
                .await
                .ok_or_else(|| "native-signaling-disconnected".to_string())?
                .map_err(|_| "native-signaling-receive-failed".to_string())?;
            let Message::Text(text) = message else {
                continue;
            };
            if text.len() > MAX_WEBSOCKET_MESSAGE_BYTES {
                return Err("native-signaling-message-oversized".to_string());
            }
            let value: Value = serde_json::from_str(text.as_ref())
                .map_err(|_| "native-signaling-message-malformed".to_string())?;
            let message_type = value
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if message_type == "error" {
                return Err(parse_server_error(options, &value, None)?);
            }
            match options.role {
                NativeWebSocketRole::Sender
                    if matches!(message_type, "share-registered" | "registered") =>
                {
                    return Ok(None)
                }
                NativeWebSocketRole::Receiver if message_type == "joined" => {
                    let receiver_id = value
                        .get("receiverId")
                        .and_then(Value::as_str)
                        .ok_or_else(|| "native-signaling-route-mismatch".to_string())?;
                    validate_route(receiver_id)?;
                    return Ok(Some(receiver_id.to_string()));
                }
                _ => {}
            }
        }
    })
    .await
    .map_err(|_| "native-signaling-room-bind-timeout".to_string())??;
    Ok((socket, receiver_id))
}

fn validate_options(options: &NativeWebSocketSignalingOptions) -> Result<(), String> {
    if !matches!(options.endpoint.as_str(), value if value.starts_with("ws://") || value.starts_with("wss://"))
        || options.endpoint.len() > 2048
    {
        return Err("native-signaling-endpoint-invalid".into());
    }
    validate_route(&options.share_id)?;
    if options.role == NativeWebSocketRole::Sender {
        let filename = options
            .display_filename
            .as_deref()
            .ok_or("native-signaling-file-summary-required")?;
        if filename.is_empty() || filename.len() > 240 || options.file_size.unwrap_or(0) == 0 {
            return Err("native-signaling-file-summary-invalid".into());
        }
    }
    Ok(())
}

fn validate_route(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("native-signaling-route-invalid".into());
    }
    Ok(())
}

fn parse_server_error(
    options: &NativeWebSocketSignalingOptions,
    value: &Value,
    expected_receiver: Option<&str>,
) -> Result<String, String> {
    if let Some(share_id) = value.get("shareId").and_then(Value::as_str) {
        if share_id != options.share_id {
            return Err("native-signaling-route-mismatch".into());
        }
    }
    if let Some(receiver_id) = value.get("receiverId").and_then(Value::as_str) {
        validate_route(receiver_id)?;
        if expected_receiver.is_some_and(|expected| expected != receiver_id) {
            return Err("native-signaling-route-mismatch".into());
        }
    }
    let code = value
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or_default();
    Ok(match code {
        // Only server codes with stable, local semantics cross this trust
        // boundary. Never include an arbitrary server code or message in a
        // diagnostic string rendered by the desktop app.
        "native-signaling-disabled" => "native-signaling-disabled",
        "native-peer-offline" => "native-peer-offline",
        "native-route-unauthorized" => "native-route-unauthorized",
        "invalid-native-envelope" => "invalid-native-envelope",
        "share-offline-or-expired" => "share-offline-or-expired",
        "receiver-announcement-failed" => "receiver-announcement-failed",
        "invalid-native-capability" => "invalid-native-capability",
        "invalid-native-control" => "invalid-native-control",
        _ => "native-signaling-server-error",
    }
    .to_string())
}

fn reconnect_delay(attempt: u8) -> Duration {
    let base = 250u64.saturating_mul(1u64 << attempt.saturating_sub(1).min(4));
    let mut jitter = [0u8; 2];
    OsRng.fill_bytes(&mut jitter);
    Duration::from_millis((base + u16::from_be_bytes(jitter) as u64 % 201).min(5_000))
}

fn delivery_error_retryable(error: &str) -> bool {
    !matches!(
        error,
        "native-signaling-cancelled"
            | "native-signaling-disabled"
            | "native-route-unauthorized"
            | "invalid-native-envelope"
            | "invalid-native-capability"
            | "invalid-native-control"
            | "native-signaling-route-invalid"
            | "native-signaling-route-mismatch"
            | "native-signaling-message-malformed"
            | "native-signaling-message-oversized"
            | "native-signaling-envelope-oversized"
            | "native-signaling-state-unavailable"
    )
}

fn terminal_actor_error(status: &NativeWebSocketSignalingStatus) -> Option<String> {
    if !status.connected
        && matches!(
            status.last_error.as_deref(),
            Some("native-signaling-reconnect-exhausted" | "native-signaling-state-unavailable")
        )
    {
        return status.last_error.clone();
    }
    None
}

fn update_error(shared: &Arc<StdMutex<SharedState>>, error: &str) {
    if let Ok(mut state) = shared.lock() {
        state.status.last_error = Some(error.to_string());
    }
}

fn update_reconnecting(shared: &Arc<StdMutex<SharedState>>, attempts: u8) {
    if let Ok(mut state) = shared.lock() {
        state.status.connected = false;
        state.status.room_bound = false;
        state.status.reconnect_attempts = attempts;
    }
}

fn update_connected(
    shared: &Arc<StdMutex<SharedState>>,
    receiver_id: Option<String>,
    attempts: u8,
) {
    if let Ok(mut state) = shared.lock() {
        state.status.connected = true;
        state.status.room_bound = true;
        state.status.reconnect_attempts = attempts;
        if receiver_id.is_some() {
            state.status.receiver_id = receiver_id;
        }
        state.status.last_error = None;
    }
}

fn mark_disconnected(shared: &Arc<StdMutex<SharedState>>) {
    if let Ok(mut state) = shared.lock() {
        state.status.connected = false;
        state.status.room_bound = false;
        // A receiver route belongs to the WebSocket room binding. Receivers
        // receive a new route on reconnect, while senders learn the retained or
        // replacement route from the server's receiver replay.
        state.status.receiver_id = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authorization::{clear_for_test, create_registered_invitation},
        candidates::ManualCandidateInput,
        signaling::{ConnectivityAuthenticator, NativeDeviceRole, NativeSignalingPayload},
    };
    use std::net::SocketAddr;
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;
    use uuid::Uuid;

    fn signed_offer() -> AuthenticatedSignalingEnvelope {
        clear_for_test();
        let material =
            create_registered_invitation(*Uuid::new_v4().as_bytes(), [7; 32], 7, 60_000).unwrap();
        let authenticator = ConnectivityAuthenticator::from_authorization(
            &material,
            *Uuid::new_v4().as_bytes(),
            *Uuid::new_v4().as_bytes(),
            9,
            [7; 32],
        )
        .unwrap();
        let candidate = ManualCandidateInput {
            address: "198.51.100.10".parse().unwrap(),
            port: 45000,
            priority: None,
        }
        .into_candidate(
            1,
            super::super::secure_protocol::now_unix_ms() + 60_000,
            false,
        )
        .unwrap();
        authenticator
            .sign(
                NativeDeviceRole::Sender,
                1,
                super::super::secure_protocol::now_unix_ms() + 60_000,
                0,
                NativeSignalingPayload::NativeConnectivityOffer {
                    candidates: vec![candidate],
                },
            )
            .unwrap()
    }

    #[test]
    fn stable_server_error_codes_are_allowlisted_and_route_bound() {
        let share_id = Uuid::new_v4().to_string();
        let receiver_id = Uuid::new_v4().to_string();
        let options = NativeWebSocketSignalingOptions {
            endpoint: "wss://share.example.test/ws".into(),
            share_id: share_id.clone(),
            role: NativeWebSocketRole::Sender,
            display_filename: Some("test.bin".into()),
            file_size: Some(1),
            file_sha256: Some("00".repeat(32)),
            expires_at_rfc3339: None,
        };
        for code in [
            "native-signaling-disabled",
            "native-peer-offline",
            "native-route-unauthorized",
            "invalid-native-envelope",
        ] {
            let value = json!({
                "type": "error",
                "code": code,
                "shareId": share_id,
                "receiverId": receiver_id,
                "message": "untrusted server detail",
            });
            assert_eq!(
                parse_server_error(&options, &value, Some(&receiver_id)).unwrap(),
                code
            );
        }
        let unknown = json!({
            "type": "error",
            "code": "attacker-controlled: diagnostic-injection",
            "shareId": share_id,
            "receiverId": receiver_id,
            "message": "must not be rendered",
        });
        assert_eq!(
            parse_server_error(&options, &unknown, Some(&receiver_id)).unwrap(),
            "native-signaling-server-error"
        );
        let wrong_share = json!({
            "type": "error",
            "code": "native-peer-offline",
            "shareId": Uuid::new_v4().to_string(),
            "receiverId": receiver_id,
        });
        assert_eq!(
            parse_server_error(&options, &wrong_share, Some(&receiver_id)).unwrap_err(),
            "native-signaling-route-mismatch"
        );
    }

    async fn spawn_two_client_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (sender_tcp, _) = listener.accept().await.unwrap();
            let mut sender = accept_async(sender_tcp).await.unwrap();
            let registration = sender.next().await.unwrap().unwrap();
            let Message::Text(registration) = registration else {
                panic!()
            };
            let registration: Value = serde_json::from_str(registration.as_ref()).unwrap();
            let share_id = registration["shareId"].as_str().unwrap().to_string();
            sender
                .send(Message::Text(
                    json!({"type":"registered","shareId":share_id})
                        .to_string()
                        .into(),
                ))
                .await
                .unwrap();

            let (receiver_tcp, _) = listener.accept().await.unwrap();
            let mut receiver = accept_async(receiver_tcp).await.unwrap();
            let _join = receiver.next().await.unwrap().unwrap();
            let receiver_id = "receiver-test-route";
            receiver
                .send(Message::Text(
                    json!({"type":"joined","shareId":share_id,"receiverId":receiver_id})
                        .to_string()
                        .into(),
                ))
                .await
                .unwrap();
            sender
                .send(Message::Text(
                    json!({"type":"receiver-joined","shareId":share_id,"receiverId":receiver_id})
                        .to_string()
                        .into(),
                ))
                .await
                .unwrap();

            let outbound = sender.next().await.unwrap().unwrap();
            let Message::Text(outbound) = outbound else {
                panic!()
            };
            let outbound: Value = serde_json::from_str(outbound.as_ref()).unwrap();
            receiver
                .send(Message::Text(outbound.to_string().into()))
                .await
                .unwrap();
            receiver
                .send(Message::Text(outbound.to_string().into()))
                .await
                .unwrap();
            sender
                .send(Message::Text(
                    json!({"type":"native-connectivity-delivered-v1","shareId":share_id,"receiverId":receiver_id})
                        .to_string()
                        .into(),
                ))
                .await
                .unwrap();
        });
        (address, task)
    }

    #[tokio::test]
    async fn two_clients_bind_room_and_forward_only_opaque_envelope() {
        std::env::set_var("FLOWGET_NATIVE_CONNECTIVITY_SIGNALING", "1");
        let (address, server) = spawn_two_client_server().await;
        let endpoint = format!("ws://{address}");
        let share_id = Uuid::new_v4().to_string();
        let sender = NativeWebSocketSignalingTransport::connect(NativeWebSocketSignalingOptions {
            endpoint: endpoint.clone(),
            share_id: share_id.clone(),
            role: NativeWebSocketRole::Sender,
            display_filename: Some("test.bin".into()),
            file_size: Some(64),
            file_sha256: Some("00".repeat(32)),
            expires_at_rfc3339: None,
        })
        .await
        .unwrap();
        let receiver =
            NativeWebSocketSignalingTransport::connect(NativeWebSocketSignalingOptions {
                endpoint,
                share_id,
                role: NativeWebSocketRole::Receiver,
                display_filename: None,
                file_size: None,
                file_sha256: None,
                expires_at_rfc3339: None,
            })
            .await
            .unwrap();
        let receiver_id = sender
            .wait_for_receiver_id(Duration::from_secs(2))
            .await
            .unwrap();
        let envelope = signed_offer();
        let ack = sender
            .send_and_wait_delivery(&receiver_id, envelope.clone(), Duration::from_secs(2))
            .await
            .unwrap();
        assert!(ack.accepted);
        assert_eq!(
            receiver
                .receive_with_timeout(Duration::from_secs(2))
                .await
                .unwrap(),
            envelope
        );
        assert_eq!(sender.status().file_payload_bytes_sent, 0);
        assert_eq!(receiver.status().file_payload_bytes_sent, 0);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if receiver.status().duplicate_deliveries_dropped == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        sender.shutdown().await;
        receiver.shutdown().await;
        server.await.unwrap();
        std::env::remove_var("FLOWGET_NATIVE_CONNECTIVITY_SIGNALING");
    }

    #[tokio::test]
    async fn bounded_actor_reconnects_and_rebinds_the_room() {
        std::env::set_var("FLOWGET_NATIVE_CONNECTIVITY_SIGNALING", "1");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for attempt in 0..2 {
                let (tcp, _) = listener.accept().await.unwrap();
                let mut socket = accept_async(tcp).await.unwrap();
                let registration = socket.next().await.unwrap().unwrap();
                let Message::Text(registration) = registration else {
                    panic!()
                };
                let registration: Value = serde_json::from_str(registration.as_ref()).unwrap();
                let share_id = registration["shareId"].as_str().unwrap();
                socket
                    .send(Message::Text(
                        json!({"type":"registered","shareId":share_id})
                            .to_string()
                            .into(),
                    ))
                    .await
                    .unwrap();
                if attempt == 0 {
                    socket.send(Message::Close(None)).await.unwrap();
                } else {
                    let _ = socket.next().await;
                }
            }
        });
        let transport =
            NativeWebSocketSignalingTransport::connect(NativeWebSocketSignalingOptions {
                endpoint,
                share_id: Uuid::new_v4().to_string(),
                role: NativeWebSocketRole::Sender,
                display_filename: Some("reconnect.bin".into()),
                file_size: Some(1),
                file_sha256: Some("00".repeat(32)),
                expires_at_rfc3339: None,
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                let status = transport.status();
                if status.connected && status.room_bound && status.reconnect_attempts == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        transport.shutdown().await;
        server.await.unwrap();
        std::env::remove_var("FLOWGET_NATIVE_CONNECTIVITY_SIGNALING");
    }

    #[tokio::test]
    async fn terminal_actor_failure_short_circuits_waiters() {
        let (outbound, _outbound_rx) = mpsc::channel(1);
        let shared = Arc::new(StdMutex::new(SharedState {
            status: NativeWebSocketSignalingStatus {
                connected: false,
                room_bound: false,
                role: NativeWebSocketRole::Sender,
                share_id: Uuid::new_v4().to_string(),
                receiver_id: None,
                reconnect_attempts: MAX_RECONNECT_ATTEMPTS,
                queued_incoming_envelopes: 0,
                delivered_envelopes: 0,
                duplicate_deliveries_dropped: 0,
                file_payload_bytes_sent: 0,
                last_error: Some("native-signaling-reconnect-exhausted".into()),
            },
            incoming: VecDeque::new(),
            seen: VecDeque::new(),
        }));
        let transport = NativeWebSocketSignalingTransport {
            outbound,
            shared,
            cancellation: CancellationToken::new(),
        };

        let receiver_error = tokio::time::timeout(
            Duration::from_millis(100),
            transport.wait_for_receiver_id(Duration::from_secs(30)),
        )
        .await
        .expect("terminal state must not wait for the public timeout")
        .unwrap_err();
        assert_eq!(receiver_error, "native-signaling-reconnect-exhausted");

        let receive_error = tokio::time::timeout(
            Duration::from_millis(100),
            transport.receive_with_timeout(Duration::from_secs(30)),
        )
        .await
        .expect("terminal state must not wait for the public timeout")
        .unwrap_err();
        assert_eq!(receive_error, "native-signaling-reconnect-exhausted");
    }

    #[tokio::test]
    async fn delivery_retry_uses_the_receiver_route_from_the_reconnected_room() {
        let (outbound, mut outbound_rx) = mpsc::channel(4);
        let share_id = Uuid::new_v4().to_string();
        let old_receiver = Uuid::new_v4().to_string();
        let new_receiver = Uuid::new_v4().to_string();
        let shared = Arc::new(StdMutex::new(SharedState {
            status: NativeWebSocketSignalingStatus {
                connected: true,
                room_bound: true,
                role: NativeWebSocketRole::Sender,
                share_id,
                receiver_id: Some(old_receiver.clone()),
                reconnect_attempts: 0,
                queued_incoming_envelopes: 0,
                delivered_envelopes: 0,
                duplicate_deliveries_dropped: 0,
                file_payload_bytes_sent: 0,
                last_error: None,
            },
            incoming: VecDeque::new(),
            seen: VecDeque::new(),
        }));
        let transport = NativeWebSocketSignalingTransport {
            outbound,
            shared: shared.clone(),
            cancellation: CancellationToken::new(),
        };
        let server_shared = shared.clone();
        let expected_new_receiver = new_receiver.clone();
        let server = tokio::spawn(async move {
            let Some(OutboundCommand::Envelope {
                receiver_id,
                completion,
                ..
            }) = outbound_rx.recv().await
            else {
                panic!("first delivery command missing");
            };
            assert_eq!(receiver_id, old_receiver);
            mark_disconnected(&server_shared);
            let _ = completion
                .expect("delivery completion missing")
                .send(Err("native-signaling-transport-unavailable".into()));
            tokio::time::sleep(Duration::from_millis(40)).await;
            update_connected(&server_shared, Some(expected_new_receiver.clone()), 1);

            let Some(OutboundCommand::Envelope {
                receiver_id,
                envelope,
                completion,
            }) = outbound_rx.recv().await
            else {
                panic!("retried delivery command missing");
            };
            assert_eq!(receiver_id, expected_new_receiver);
            let _ = completion
                .expect("retried delivery completion missing")
                .send(Ok(SignalingDeliveryAck {
                    route: receiver_id,
                    sequence: envelope.sequence,
                    accepted: true,
                }));
        });

        let envelope = signed_offer();
        let acknowledgment = transport
            .send_and_wait_delivery_current(envelope.clone(), Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(acknowledgment.route, new_receiver);
        assert_eq!(acknowledgment.sequence, envelope.sequence);
        assert!(acknowledgment.accepted);
        server.await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires access to production FlowShare WSS signaling"]
    async fn production_wss_binds_and_routes_native_envelope() {
        let endpoint = std::env::var("FLOWGET_NATIVE_WSS_TEST_ENDPOINT")
            .unwrap_or_else(|_| "wss://share.flowget.xyz/ws".into());
        let share_id = Uuid::new_v4().to_string();
        let sender = NativeWebSocketSignalingTransport::connect(NativeWebSocketSignalingOptions {
            endpoint: endpoint.clone(),
            share_id: share_id.clone(),
            role: NativeWebSocketRole::Sender,
            display_filename: Some("wss-smoke-test.bin".into()),
            file_size: Some(1),
            file_sha256: Some("00".repeat(32)),
            expires_at_rfc3339: None,
        })
        .await
        .unwrap();
        let receiver =
            NativeWebSocketSignalingTransport::connect(NativeWebSocketSignalingOptions {
                endpoint,
                share_id,
                role: NativeWebSocketRole::Receiver,
                display_filename: None,
                file_size: None,
                file_sha256: None,
                expires_at_rfc3339: None,
            })
            .await
            .unwrap();
        let receiver_id = sender
            .wait_for_receiver_id(Duration::from_secs(10))
            .await
            .unwrap();
        let envelope = signed_offer();
        let acknowledgment = sender
            .send_and_wait_delivery(&receiver_id, envelope.clone(), Duration::from_secs(10))
            .await
            .unwrap();
        assert!(acknowledgment.accepted);
        assert_eq!(
            receiver
                .receive_with_timeout(Duration::from_secs(10))
                .await
                .unwrap(),
            envelope
        );
        assert_eq!(sender.status().file_payload_bytes_sent, 0);
        assert_eq!(receiver.status().file_payload_bytes_sent, 0);
        receiver.shutdown().await;
        sender.shutdown().await;
    }
}
