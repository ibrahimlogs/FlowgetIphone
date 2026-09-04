use quinn::{ClientConfig, Endpoint, EndpointConfig, ServerConfig, TokioRuntime};
use serde::Serialize;
use socket2::SockRef;
use std::{net::UdpSocket, sync::Arc};

/// Quinn uses the OS UDP queues in addition to its QUIC flow-control windows.
/// Windows defaults both queues to 64 KiB, which is too small for a sustained
/// high-bandwidth Internet path and can collapse congestion control when the
/// runtime cannot drain a short burst immediately.
pub const QUINN_UDP_SOCKET_BUFFER_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuinnSocketHandoffDiagnostic {
    pub prepared_local_endpoint: String,
    pub quinn_local_endpoint: String,
    pub same_local_port: bool,
    pub socket_rebound: bool,
    pub requested_udp_buffer_bytes: usize,
    pub udp_send_buffer_bytes: usize,
    pub udp_receive_buffer_bytes: usize,
    pub udp_send_buffer_tuned: bool,
    pub udp_receive_buffer_tuned: bool,
}

pub fn server_endpoint_from_prepared_socket(
    socket: UdpSocket,
    server_config: ServerConfig,
) -> Result<(Endpoint, QuinnSocketHandoffDiagnostic), String> {
    endpoint_from_prepared_socket(socket, Some(server_config), None)
}

pub fn client_endpoint_from_prepared_socket(
    socket: UdpSocket,
    client_config: ClientConfig,
) -> Result<(Endpoint, QuinnSocketHandoffDiagnostic), String> {
    endpoint_from_prepared_socket(socket, None, Some(client_config))
}

fn endpoint_from_prepared_socket(
    socket: UdpSocket,
    server_config: Option<ServerConfig>,
    client_config: Option<ClientConfig>,
) -> Result<(Endpoint, QuinnSocketHandoffDiagnostic), String> {
    let prepared = socket
        .local_addr()
        .map_err(|_| "native-quic-prepared-socket-invalid")?;
    let socket_ref = SockRef::from(&socket);
    let udp_send_buffer_tuned = socket_ref
        .set_send_buffer_size(QUINN_UDP_SOCKET_BUFFER_BYTES)
        .is_ok();
    let udp_receive_buffer_tuned = socket_ref
        .set_recv_buffer_size(QUINN_UDP_SOCKET_BUFFER_BYTES)
        .is_ok();
    let udp_send_buffer_bytes = socket_ref.send_buffer_size().unwrap_or(0);
    let udp_receive_buffer_bytes = socket_ref.recv_buffer_size().unwrap_or(0);
    socket
        .set_nonblocking(true)
        .map_err(|_| "native-quic-prepared-socket-invalid")?;
    let mut endpoint = Endpoint::new(
        EndpointConfig::default(),
        server_config,
        socket,
        Arc::new(TokioRuntime),
    )
    .map_err(|error| format!("native-quic-socket-handoff-failed: {error}"))?;
    if let Some(client_config) = client_config {
        endpoint.set_default_client_config(client_config);
    }
    let quinn = endpoint
        .local_addr()
        .map_err(|_| "native-quic-socket-handoff-failed")?;
    let diagnostic = QuinnSocketHandoffDiagnostic {
        prepared_local_endpoint: prepared.to_string(),
        quinn_local_endpoint: quinn.to_string(),
        same_local_port: prepared.port() == quinn.port(),
        socket_rebound: prepared != quinn,
        requested_udp_buffer_bytes: QUINN_UDP_SOCKET_BUFFER_BYTES,
        udp_send_buffer_bytes,
        udp_receive_buffer_bytes,
        udp_send_buffer_tuned,
        udp_receive_buffer_tuned,
    };
    if !diagnostic.same_local_port {
        endpoint.close(0u32.into(), b"prepared-port-changed");
        return Err("native-quic-prepared-port-changed".into());
    }
    Ok((endpoint, diagnostic))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authorization::{clear_for_test, create_registered_invitation, prepare_client_handshake},
        config::NativeQuicConfig,
        secure_protocol::{session_lineage_digest, transfer_commitment, SecureSessionMode},
        secure_transport::{accept_control_stream, authenticate_client, authenticate_server},
        security::create_ephemeral_identity,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use uuid::Uuid;

    #[tokio::test]
    #[serial_test::serial(flowshare_authorization)]
    async fn prepared_udp_ports_survive_quinn_and_secure_v3_handshake() {
        clear_for_test();
        let config = NativeQuicConfig::desktop(4).unwrap();
        let identity = create_ephemeral_identity().unwrap();
        let certificate = identity.certificate.clone();
        let fingerprint = identity.fingerprint_sha256_bytes;
        let transfer_id = *Uuid::new_v4().as_bytes();
        let session_id = *Uuid::new_v4().as_bytes();
        let authorization =
            create_registered_invitation(transfer_id, fingerprint, 7, 60_000).unwrap();
        let invitation_id = authorization.invitation.body.invitation_id;
        let commitment = transfer_commitment(64, &[3; 32], 2 * 1024 * 1024, 1, 7);

        let server_socket =
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        let client_socket =
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        let server_address = server_socket.local_addr().unwrap();
        let client_address = client_socket.local_addr().unwrap();

        // Exercise the prepared sockets before Quinn adopts clones of the same
        // OS sockets, matching the STUN/probe-to-QUIC ownership strategy.
        let probe_server_socket = server_socket.try_clone().unwrap();
        let probe_client_socket = client_socket.try_clone().unwrap();
        probe_server_socket.set_nonblocking(true).unwrap();
        probe_client_socket.set_nonblocking(true).unwrap();
        let probe_server = tokio::net::UdpSocket::from_std(probe_server_socket).unwrap();
        let probe_client = tokio::net::UdpSocket::from_std(probe_client_socket).unwrap();
        probe_client
            .send_to(b"probe", server_address)
            .await
            .unwrap();
        let mut probe = [0u8; 8];
        let (length, source) = probe_server.recv_from(&mut probe).await.unwrap();
        assert_eq!(&probe[..length], b"probe");
        assert_eq!(source, client_address);
        drop(probe_server);
        drop(probe_client);

        let mut server_config =
            ServerConfig::with_single_cert(vec![certificate.clone()], identity.private_key.into())
                .unwrap();
        server_config.transport_config(config.transport().unwrap());
        let (server, server_handoff) =
            server_endpoint_from_prepared_socket(server_socket, server_config).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
        client_config.transport_config(config.transport().unwrap());
        let (client, client_handoff) =
            client_endpoint_from_prepared_socket(client_socket, client_config).unwrap();
        assert!(server_handoff.same_local_port);
        assert!(client_handoff.same_local_port);
        assert!(!server_handoff.socket_rebound);
        assert_eq!(
            server_handoff.requested_udp_buffer_bytes,
            QUINN_UDP_SOCKET_BUFFER_BYTES
        );
        assert!(server_handoff.udp_send_buffer_bytes > 0);
        assert!(server_handoff.udp_receive_buffer_bytes > 0);
        #[cfg(windows)]
        {
            assert!(server_handoff.udp_send_buffer_tuned);
            assert!(server_handoff.udp_receive_buffer_tuned);
            assert!(server_handoff.udp_send_buffer_bytes >= QUINN_UDP_SOCKET_BUFFER_BYTES);
            assert!(server_handoff.udp_receive_buffer_bytes >= QUINN_UDP_SOCKET_BUFFER_BYTES);
        }

        let receiver = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut receive) =
                accept_control_stream(&connection, transfer_id, invitation_id, session_id, 0)
                    .await
                    .unwrap();
            let result = authenticate_server(
                &connection,
                &mut send,
                &mut receive,
                transfer_id,
                invitation_id,
                session_id,
                fingerprint,
                SecureSessionMode::NewTransfer,
                0,
                [0; 32],
                commitment,
                session_lineage_digest(None),
                7,
            )
            .await
            .map(|session| session.audit_identifier);
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            result
        });
        let connection = client
            .connect(server_address, "flowshare-native.local")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut receive) = connection.open_bi().await.unwrap();
        let prepared = prepare_client_handshake(
            transfer_id,
            session_id,
            SecureSessionMode::NewTransfer,
            0,
            [0; 32],
            commitment,
            session_lineage_digest(None),
            fingerprint,
            7,
        )
        .unwrap();
        let client_result = authenticate_client(&connection, &mut send, &mut receive, prepared)
            .await
            .map(|session| session.audit_identifier);
        let receiver_result = receiver.await.unwrap();
        assert_eq!(client_result, receiver_result);
        assert!(
            client_result.is_ok(),
            "secure v3 handshake failed: {client_result:?}"
        );
        assert_eq!(client.local_addr().unwrap().port(), client_address.port());
    }
}
