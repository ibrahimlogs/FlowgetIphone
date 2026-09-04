use super::{
    authorization::{self, PreparedClientHandshake},
    secure_protocol::{
        client_answer_challenge, client_finish_handshake, development_handshake_timeout_ms,
        server_finish_handshake, SecureControlChannel, SecureHandshakeMessage, SecureSessionMode,
        MAX_HANDSHAKE_BYTES,
    },
    security::peer_certificate_fingerprint,
};
use quinn::{Connection, RecvStream, SendStream, VarInt};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

pub const CLOSE_AUTHENTICATION_REQUIRED: u32 = 0x300;
pub const CLOSE_AUTHENTICATION_FAILED: u32 = 0x301;
pub const CLOSE_UNAUTHORIZED_DATA_STREAM: u32 = 0x302;

pub struct AuthenticatedSession {
    pub control: SecureControlChannel,
    pub audit_identifier: String,
    pub key_derivation_ms: f64,
}

pub async fn accept_control_stream(
    connection: &Connection,
    transfer_id: [u8; 16],
    invitation_id: [u8; 16],
    session_id: [u8; 16],
    checkpoint_generation: u64,
) -> Result<(SendStream, RecvStream), String> {
    tokio::select! {
        result = connection.accept_bi() => result.map_err(|_| "authentication-required".into()),
        early = connection.accept_uni() => {
            match early {
                Ok(mut stream) => {
                    let _ = stream.stop(VarInt::from_u32(CLOSE_UNAUTHORIZED_DATA_STREAM));
                    reject_early_stream(connection, transfer_id, invitation_id, session_id, checkpoint_generation);
                    Err("unauthorized-data-stream".into())
                }
                Err(_) => Err("authentication-required".into()),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn authenticate_server(
    connection: &Connection,
    send: &mut SendStream,
    receive: &mut RecvStream,
    expected_transfer_id: [u8; 16],
    expected_invitation_id: [u8; 16],
    expected_session_id: [u8; 16],
    actual_certificate_fingerprint: [u8; 32],
    expected_mode: SecureSessionMode,
    expected_checkpoint_generation: u64,
    expected_state_digest: [u8; 32],
    expected_transfer_commitment: [u8; 32],
    expected_previous_session_digest: [u8; 32],
    expected_capabilities: u64,
) -> Result<AuthenticatedSession, String> {
    let message = read_handshake_guarded(
        connection,
        receive,
        expected_transfer_id,
        expected_invitation_id,
        expected_session_id,
        expected_checkpoint_generation,
    )
    .await?;
    let offer = match message {
        SecureHandshakeMessage::Offer(value) => value,
        _ => return reject(connection, "authentication-required"),
    };
    if offer.authorization.body.transfer_id != expected_transfer_id
        || offer.authorization.body.invitation_id != expected_invitation_id
    {
        return reject(connection, "authentication-failed");
    }
    let expires = offer.authorization.body.expires_unix_ms;
    let claim = match authorization::begin_server_claim(
        &offer,
        actual_certificate_fingerprint,
        expected_session_id,
        expected_mode,
        expected_checkpoint_generation,
        expected_state_digest,
        expected_transfer_commitment,
        expected_previous_session_digest,
        expected_capabilities,
    ) {
        Ok(value) => value,
        Err(error) => return reject(connection, &error),
    };
    let handle = claim.handle.clone();
    if let Err(error) =
        write_handshake(send, &SecureHandshakeMessage::Challenge(claim.challenge)).await
    {
        authorization::abort_claim(&handle, false, &error);
        return reject(connection, &error);
    }
    let response = match read_handshake_guarded(
        connection,
        receive,
        expected_transfer_id,
        expected_invitation_id,
        expected_session_id,
        expected_checkpoint_generation,
    )
    .await
    {
        Ok(SecureHandshakeMessage::Response(value)) => value,
        Ok(_) => {
            authorization::abort_claim(&handle, false, "transcript-mismatch");
            return reject(connection, "transcript-mismatch");
        }
        Err(error) => {
            authorization::abort_claim(&handle, false, &error);
            return Err(error);
        }
    };
    let (keys, accept) = match server_finish_handshake(claim.state, &response) {
        Ok(value) => value,
        Err(error) => {
            authorization::abort_claim(&handle, false, &error);
            return reject(connection, &error);
        }
    };
    let audit_identifier = keys.audit_identifier();
    let key_derivation_ms = keys.key_derivation_ms();
    if let Err(error) = write_handshake(send, &SecureHandshakeMessage::Accept(accept)).await {
        authorization::abort_claim(&handle, false, &error);
        return reject(connection, &error);
    }
    if let Err(error) = authorization::complete_claim(&handle, audit_identifier.clone()) {
        authorization::abort_claim(&handle, false, &error);
        return reject(connection, &error);
    }
    Ok(AuthenticatedSession {
        control: SecureControlChannel::new(
            expected_transfer_id,
            expected_session_id,
            expires,
            keys,
        ),
        audit_identifier,
        key_derivation_ms,
    })
}

pub async fn authenticate_client(
    connection: &Connection,
    send: &mut SendStream,
    receive: &mut RecvStream,
    prepared: PreparedClientHandshake,
) -> Result<AuthenticatedSession, String> {
    let expected_certificate = prepared
        .offer
        .authorization
        .body
        .server_certificate_fingerprint;
    if peer_certificate_fingerprint(connection)? != expected_certificate {
        return reject(connection, "certificate-binding-failed");
    }
    let transfer_id = prepared.offer.authorization.body.transfer_id;
    let session_id = prepared.offer.authorization.body.session_id;
    let expires = prepared.authorization_expires_unix_ms;
    write_handshake(send, &SecureHandshakeMessage::Offer(prepared.offer)).await?;
    let challenge = match read_handshake(receive).await? {
        SecureHandshakeMessage::Challenge(value) => value,
        SecureHandshakeMessage::Reject { code: _ } => return Err("authentication-failed".into()),
        _ => return Err("transcript-mismatch".into()),
    };
    let (pending, response) = client_answer_challenge(prepared.state, &challenge)?;
    write_handshake(send, &SecureHandshakeMessage::Response(response)).await?;
    let accept = match read_handshake(receive).await? {
        SecureHandshakeMessage::Accept(value) => value,
        SecureHandshakeMessage::Reject { code: _ } => return Err("authentication-failed".into()),
        _ => return Err("transcript-mismatch".into()),
    };
    let keys = client_finish_handshake(pending, &accept)?;
    let audit_identifier = keys.audit_identifier();
    let key_derivation_ms = keys.key_derivation_ms();
    Ok(AuthenticatedSession {
        control: SecureControlChannel::new(transfer_id, session_id, expires, keys),
        audit_identifier,
        key_derivation_ms,
    })
}

async fn write_handshake(
    stream: &mut SendStream,
    message: &SecureHandshakeMessage,
) -> Result<(), String> {
    let payload = message.encode()?;
    let write = async {
        stream
            .write_u32(payload.len() as u32)
            .await
            .map_err(|_| "authentication-failed")?;
        stream
            .write_all(&payload)
            .await
            .map_err(|_| "authentication-failed".to_string())
    };
    tokio::time::timeout(
        Duration::from_millis(development_handshake_timeout_ms()),
        write,
    )
    .await
    .map_err(|_| "handshake-timeout".to_string())?
}

async fn read_handshake(stream: &mut RecvStream) -> Result<SecureHandshakeMessage, String> {
    read_handshake_with_timeout(
        stream,
        Duration::from_millis(development_handshake_timeout_ms()),
    )
    .await
}

async fn read_handshake_with_timeout(
    stream: &mut RecvStream,
    timeout: Duration,
) -> Result<SecureHandshakeMessage, String> {
    let read = async {
        let length = stream
            .read_u32()
            .await
            .map_err(|_| "authentication-failed")? as usize;
        if length > MAX_HANDSHAKE_BYTES {
            return Err("authentication-failed".into());
        }
        let mut payload = vec![0u8; length];
        stream
            .read_exact(&mut payload)
            .await
            .map_err(|_| "authentication-failed")?;
        SecureHandshakeMessage::decode(&payload)
    };
    tokio::time::timeout(timeout, read)
        .await
        .map_err(|_| "handshake-timeout".to_string())?
}

async fn read_handshake_guarded(
    connection: &Connection,
    receive: &mut RecvStream,
    transfer_id: [u8; 16],
    invitation_id: [u8; 16],
    session_id: [u8; 16],
    checkpoint_generation: u64,
) -> Result<SecureHandshakeMessage, String> {
    tokio::select! {
        result = read_handshake(receive) => result,
        early = connection.accept_uni() => {
            match early {
                Ok(mut stream) => {
                    let _ = stream.stop(VarInt::from_u32(CLOSE_UNAUTHORIZED_DATA_STREAM));
                    reject_early_stream(connection, transfer_id, invitation_id, session_id, checkpoint_generation);
                    Err("unauthorized-data-stream".into())
                }
                Err(_) => Err("authentication-failed".into()),
            }
        }
        extra = connection.accept_bi() => {
            match extra {
                Ok((mut send, mut receive)) => {
                    let _ = send.reset(VarInt::from_u32(CLOSE_UNAUTHORIZED_DATA_STREAM));
                    let _ = receive.stop(VarInt::from_u32(CLOSE_UNAUTHORIZED_DATA_STREAM));
                    reject_early_stream(connection, transfer_id, invitation_id, session_id, checkpoint_generation);
                    Err("unauthorized-data-stream".into())
                }
                Err(_) => Err("authentication-failed".into()),
            }
        }
    }
}

fn reject_early_stream(
    connection: &Connection,
    transfer_id: [u8; 16],
    invitation_id: [u8; 16],
    session_id: [u8; 16],
    checkpoint_generation: u64,
) {
    connection.close(
        VarInt::from_u32(CLOSE_UNAUTHORIZED_DATA_STREAM),
        b"unauthorized-data-stream",
    );
    authorization::record_security_rejection(
        "native-auth-session-rejected",
        transfer_id,
        invitation_id,
        Some(session_id),
        "unauthorized-data-stream",
        Some(checkpoint_generation),
    );
}

fn reject<T>(connection: &Connection, code: &str) -> Result<T, String> {
    let application_code = if code == "authentication-required" {
        CLOSE_AUTHENTICATION_REQUIRED
    } else {
        CLOSE_AUTHENTICATION_FAILED
    };
    connection.close(VarInt::from_u32(application_code), code.as_bytes());
    Err(code.to_string())
}

pub fn parse_session_id(value: &str) -> Result<[u8; 16], String> {
    Ok(*Uuid::parse_str(value)
        .map_err(|_| "authentication-failed")?
        .as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::NativeQuicConfig, security::create_ephemeral_identity};
    use quinn::{ClientConfig, Endpoint, ServerConfig};
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
    };

    fn endpoints(identity: crate::security::EphemeralIdentity) -> (Endpoint, Endpoint, SocketAddr) {
        let config = NativeQuicConfig::desktop(4).unwrap();
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
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
        client_config.transport_config(config.transport().unwrap());
        let mut client =
            Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        client.set_default_client_config(client_config);
        (server, client, address)
    }

    #[tokio::test]
    #[serial_test::serial(flowshare_authorization)]
    async fn payload_stream_before_authentication_is_reset_and_connection_closed() {
        let identity = create_ephemeral_identity().unwrap();
        let (server, client, address) = endpoints(identity);

        let receiver = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            accept_control_stream(&connection, [1; 16], [2; 16], [3; 16], 0).await
        });
        let connection = client
            .connect(address, "flowshare-native.local")
            .unwrap()
            .await
            .unwrap();
        let mut early = connection.open_uni().await.unwrap();
        let _ = early.write_all(b"unauthorized-payload").await;
        let error = receiver.await.unwrap().unwrap_err();
        assert_eq!(error, "unauthorized-data-stream");
        let closed = connection.closed().await;
        assert!(closed.to_string().contains("unauthorized-data-stream"));
    }

    #[tokio::test]
    #[serial_test::serial(flowshare_authorization)]
    async fn silent_peer_hits_monotonic_handshake_timeout() {
        let identity = create_ephemeral_identity().unwrap();
        let (server, client, address) = endpoints(identity);
        let receiver = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            let (_send, mut receive) = connection.accept_bi().await.unwrap();
            read_handshake_with_timeout(&mut receive, Duration::from_millis(10)).await
        });
        let connection = client
            .connect(address, "flowshare-native.local")
            .unwrap()
            .await
            .unwrap();
        let (mut send, _receive) = connection.open_bi().await.unwrap();
        send.write_all(&[0]).await.unwrap();
        assert_eq!(receiver.await.unwrap().unwrap_err(), "handshake-timeout");
    }

    #[tokio::test]
    #[serial_test::serial(flowshare_authorization)]
    async fn forged_psk_offer_is_rejected_before_metadata_or_payload() {
        use crate::{
            authorization,
            protocol::RESUME_REQUIRED_CAPABILITIES,
            secure_protocol::{session_lineage_digest, transfer_commitment, SecureSessionMode},
        };
        authorization::clear_for_test();
        let identity = create_ephemeral_identity().unwrap();
        let certificate = identity.fingerprint_sha256_bytes;
        let (server, client, address) = endpoints(identity);
        let transfer = *Uuid::new_v4().as_bytes();
        let session = *Uuid::new_v4().as_bytes();
        let capabilities = RESUME_REQUIRED_CAPABILITIES;
        let commitment = transfer_commitment(10, &[3; 32], 2, 5, capabilities);
        let material = authorization::create_registered_invitation(
            transfer,
            certificate,
            capabilities,
            60_000,
        )
        .unwrap();
        let mut prepared = authorization::prepare_client_handshake(
            transfer,
            session,
            SecureSessionMode::NewTransfer,
            0,
            [0; 32],
            commitment,
            session_lineage_digest(None),
            certificate,
            capabilities,
        )
        .unwrap();
        prepared.offer.proof[0] ^= 1;
        let invitation_id = material.invitation.body.invitation_id;
        let receiver = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut receive) =
                match accept_control_stream(&connection, transfer, invitation_id, session, 0).await
                {
                    Ok(value) => value,
                    Err(error) => return error,
                };
            authenticate_server(
                &connection,
                &mut send,
                &mut receive,
                transfer,
                invitation_id,
                session,
                certificate,
                SecureSessionMode::NewTransfer,
                0,
                [0; 32],
                commitment,
                session_lineage_digest(None),
                capabilities,
            )
            .await
            .err()
            .unwrap()
        });
        let connection = client
            .connect(address, "flowshare-native.local")
            .unwrap()
            .await
            .unwrap();
        let (mut send, _receive) = connection.open_bi().await.unwrap();
        write_handshake(&mut send, &SecureHandshakeMessage::Offer(prepared.offer))
            .await
            .unwrap();
        assert_eq!(receiver.await.unwrap(), "authentication-failed");
    }

    #[tokio::test]
    #[serial_test::serial(flowshare_authorization)]
    async fn live_certificate_substitution_is_rejected_before_offer() {
        use crate::{
            authorization,
            protocol::RESUME_REQUIRED_CAPABILITIES,
            secure_protocol::{session_lineage_digest, transfer_commitment, SecureSessionMode},
        };
        authorization::clear_for_test();
        let substituted_identity = create_ephemeral_identity().unwrap();
        let substituted_certificate = substituted_identity.fingerprint_sha256_bytes;
        let (server, client, address) = endpoints(substituted_identity);
        let expected_certificate = [7; 32];
        let transfer = *Uuid::new_v4().as_bytes();
        let session = *Uuid::new_v4().as_bytes();
        let capabilities = RESUME_REQUIRED_CAPABILITIES;
        let commitment = transfer_commitment(10, &[3; 32], 2, 5, capabilities);
        let material = authorization::create_registered_invitation(
            transfer,
            expected_certificate,
            capabilities,
            60_000,
        )
        .unwrap();
        let prepared = authorization::prepare_client_handshake(
            transfer,
            session,
            SecureSessionMode::NewTransfer,
            0,
            [0; 32],
            commitment,
            session_lineage_digest(None),
            expected_certificate,
            capabilities,
        )
        .unwrap();
        let invitation_id = material.invitation.body.invitation_id;
        let receiver = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut receive) =
                match accept_control_stream(&connection, transfer, invitation_id, session, 0).await
                {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
            authenticate_server(
                &connection,
                &mut send,
                &mut receive,
                transfer,
                invitation_id,
                session,
                substituted_certificate,
                SecureSessionMode::NewTransfer,
                0,
                [0; 32],
                commitment,
                session_lineage_digest(None),
                capabilities,
            )
            .await
        });
        let connection = client
            .connect(address, "flowshare-native.local")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut receive) = connection.open_bi().await.unwrap();
        assert_eq!(
            authenticate_client(&connection, &mut send, &mut receive, prepared)
                .await
                .err()
                .unwrap(),
            "certificate-binding-failed"
        );
        assert!(receiver.await.unwrap().is_err());
    }
}
