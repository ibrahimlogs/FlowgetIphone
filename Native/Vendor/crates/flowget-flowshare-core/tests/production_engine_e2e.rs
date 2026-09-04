use flowget_flowshare_core::{
    cross_platform::{
        AcceptTransferRequest, FlowShareCapabilities, FlowShareDirection, FlowShareEngine,
        FlowShareTransferState, ImportInvitationRequest, PrepareReceiveRequest, PrepareSendRequest,
        StartTransferRequest, TransferLookupRequest, CAPABILITY_SCHEMA_VERSION,
    },
    device_protocol::DevicePlatform,
    protocol::NATIVE_QUIC_PROTOCOL_VERSION,
    secret_store::{install_secret_protector, SecretProtector},
};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{net::TcpListener, time::Instant};
use tokio_tungstenite::{accept_async, tungstenite::Message, WebSocketStream};
use uuid::Uuid;

struct TestSecretProtector;

impl SecretProtector for TestSecretProtector {
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        Ok(plaintext.iter().map(|byte| byte ^ 0xa5).collect())
    }

    fn unprotect(&self, protected: &[u8]) -> Result<Vec<u8>, String> {
        Ok(protected.iter().map(|byte| byte ^ 0xa5).collect())
    }
}

fn capabilities(platform: DevicePlatform) -> FlowShareCapabilities {
    FlowShareCapabilities {
        schema_version: CAPABILITY_SCHEMA_VERSION,
        protocol_version: NATIVE_QUIC_PROTOCOL_VERSION,
        platform,
        native_quic: true,
        webrtc_direct: false,
        resume: true,
        completion_ack: true,
        sha256: true,
        lan_discovery: true,
        device_mode: true,
        max_file_size: u64::MAX,
        app_version: "production-engine-e2e".into(),
    }
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn registered_socket(
    listener: &TcpListener,
) -> (String, String, WebSocketStream<tokio::net::TcpStream>) {
    let (tcp, _) = listener.accept().await.unwrap();
    let mut socket = accept_async(tcp).await.unwrap();
    let Message::Text(registration) = socket.next().await.unwrap().unwrap() else {
        panic!("registration must be text")
    };
    let registration: Value = serde_json::from_str(registration.as_ref()).unwrap();
    (
        registration["type"].as_str().unwrap().to_string(),
        registration["shareId"].as_str().unwrap().to_string(),
        socket,
    )
}

async fn spawn_signaling_broker() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let first = registered_socket(&listener).await;
        let second = registered_socket(&listener).await;
        assert_eq!(first.1, second.1);
        let share_id = first.1.clone();
        let (mut sender, mut receiver) = match (first.0.as_str(), second.0.as_str()) {
            ("register-share", "join-share") => (first.2, second.2),
            ("join-share", "register-share") => (second.2, first.2),
            roles => panic!("unexpected signaling roles: {roles:?}"),
        };
        let receiver_id = "core-e2e-receiver";
        sender
            .send(Message::Text(
                json!({"type":"registered","shareId":share_id})
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
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

        loop {
            tokio::select! {
                message = sender.next() => {
                    let Some(Ok(Message::Text(text))) = message else { break };
                    let value: Value = serde_json::from_str(text.as_ref()).unwrap();
                    if value["type"] == "native-connectivity-envelope-v1" {
                        receiver.send(Message::Text(text)).await.unwrap();
                        sender.send(Message::Text(json!({
                            "type":"native-connectivity-delivered-v1",
                            "shareId":share_id,
                            "receiverId":receiver_id,
                        }).to_string().into())).await.unwrap();
                    }
                }
                message = receiver.next() => {
                    let Some(Ok(Message::Text(text))) = message else { break };
                    let value: Value = serde_json::from_str(text.as_ref()).unwrap();
                    if value["type"] == "native-connectivity-envelope-v1" {
                        sender.send(Message::Text(text)).await.unwrap();
                        receiver.send(Message::Text(json!({
                            "type":"native-connectivity-delivered-v1",
                            "shareId":share_id,
                            "receiverId":receiver_id,
                        }).to_string().into())).await.unwrap();
                    }
                }
            }
        }
    });
    (endpoint, task)
}

async fn wait_for_terminal(
    engine: &FlowShareEngine,
    transfer_id: &str,
    direction: FlowShareDirection,
) -> flowget_flowshare_core::cross_platform::FlowShareTransferStatus {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let status = engine
            .get_transfer_status(TransferLookupRequest {
                transfer_id: transfer_id.into(),
                direction,
            })
            .await
            .unwrap();
        if matches!(
            status.state,
            FlowShareTransferState::Completed
                | FlowShareTransferState::Cancelled
                | FlowShareTransferState::Failed
        ) {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "transfer timed out in {:?}",
            status.state
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn run_two_engine_transfer(payload_bytes: usize) {
    let _ = install_secret_protector(Arc::new(TestSecretProtector));
    let root = std::env::temp_dir().join(format!("flowshare-core-e2e-{}", Uuid::new_v4()));
    let source_dir = root.join("source");
    let destination_dir = root.join("destination");
    tokio::fs::create_dir_all(&source_dir).await.unwrap();
    tokio::fs::create_dir_all(&destination_dir).await.unwrap();
    let source = source_dir.join("payload.bin");
    let payload: Vec<u8> = (0..payload_bytes)
        .map(|index| ((index * 31 + 17) % 251) as u8)
        .collect();
    tokio::fs::write(&source, &payload).await.unwrap();
    let expected_hash = hex(Sha256::digest(&payload));

    let sender = FlowShareEngine::new(capabilities(DevicePlatform::Windows));
    let receiver = FlowShareEngine::new(capabilities(DevicePlatform::Android));
    assert!(sender.initialize().unwrap());
    assert!(receiver.initialize().unwrap());

    let bootstrap = receiver
        .prepare_receive(PrepareReceiveRequest {
            lifetime_ms: Some(120_000),
        })
        .await
        .unwrap();
    let prepared = sender
        .prepare_send(PrepareSendRequest {
            source_handle: source.display().to_string(),
            receiver_bootstrap_package: bootstrap.receiver_bootstrap_package,
            invitation_lifetime_ms: Some(120_000),
        })
        .await
        .unwrap();
    let transfer_id = prepared.transfer.transfer_id.clone();
    receiver
        .import_invitation(ImportInvitationRequest {
            receiver_bootstrap_id: bootstrap.receiver_bootstrap_id,
            invitation_package: prepared.invitation_package,
            destination_handle: destination_dir.display().to_string(),
            retention_expires_unix_ms: None,
        })
        .await
        .unwrap();
    receiver
        .accept_transfer(AcceptTransferRequest {
            transfer_id: transfer_id.clone(),
            display_filename: "payload.bin".into(),
            file_size: payload.len() as u64,
            expected_sha256: expected_hash.clone(),
            overwrite: false,
        })
        .await
        .unwrap();

    let (endpoint, broker) = spawn_signaling_broker().await;
    let start = || StartTransferRequest {
        transfer_id: transfer_id.clone(),
        signaling_endpoint: endpoint.clone(),
        allow_loopback_test: true,
        signaling_timeout_ms: Some(10_000),
        connectivity_timeout_ms: Some(10_000),
    };
    sender.start_sender(start()).await.unwrap();
    receiver.start_receiver(start()).await.unwrap();

    let (sender_state, receiver_state) = tokio::join!(
        wait_for_terminal(&sender, &transfer_id, FlowShareDirection::Send),
        wait_for_terminal(&receiver, &transfer_id, FlowShareDirection::Receive),
    );
    if sender_state.state != FlowShareTransferState::Completed
        || receiver_state.state != FlowShareTransferState::Completed
    {
        let raw_sender =
            flowget_flowshare_core::cross_device::flowshare_native_get_outgoing_transfer(
                flowget_flowshare_core::cross_device::SplitTransferIdRequest {
                    transfer_id: transfer_id.clone(),
                },
            )
            .await
            .unwrap();
        let raw_receiver =
            flowget_flowshare_core::cross_device::flowshare_native_get_incoming_transfer(
                flowget_flowshare_core::cross_device::SplitTransferIdRequest {
                    transfer_id: transfer_id.clone(),
                },
            )
            .await
            .unwrap();
        eprintln!("sender terminal error: {:?}", raw_sender.terminal_error);
        eprintln!("receiver terminal error: {:?}", raw_receiver.terminal_error);
    }
    assert_eq!(
        sender_state.state,
        FlowShareTransferState::Completed,
        "{sender_state:?}"
    );
    assert_eq!(
        receiver_state.state,
        FlowShareTransferState::Completed,
        "{receiver_state:?}"
    );
    let completed = destination_dir.join("payload.bin");
    let received = tokio::fs::read(completed).await.unwrap();
    assert_eq!(hex(Sha256::digest(&received)), expected_hash);
    assert_eq!(received, payload);

    sender.shutdown().await.unwrap();
    receiver.shutdown().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(3), broker).await;
    let _ = tokio::fs::remove_dir_all(PathBuf::from(root)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial(flowshare_production_engine)]
async fn two_engine_instances_transfer_over_real_local_quic_and_verify_hash() {
    std::env::set_var("FLOWGET_NATIVE_CONNECTIVITY_SIGNALING", "1");
    run_two_engine_transfer(6 * 1024 * 1024 + 137).await;
    std::env::remove_var("FLOWGET_NATIVE_CONNECTIVITY_SIGNALING");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(flowshare_production_engine)]
async fn simultaneous_engine_pairs_keep_registries_and_quic_paths_isolated() {
    std::env::set_var("FLOWGET_NATIVE_CONNECTIVITY_SIGNALING", "1");
    tokio::join!(
        run_two_engine_transfer(3 * 1024 * 1024 + 19),
        run_two_engine_transfer(4 * 1024 * 1024 + 23),
    );
    std::env::remove_var("FLOWGET_NATIVE_CONNECTIVITY_SIGNALING");
}
