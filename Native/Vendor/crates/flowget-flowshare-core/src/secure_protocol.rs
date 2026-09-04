use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2_compat::{Digest, Sha256};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvitationDeliveryModel {
    PreSharedOneTimeSecret,
    DeviceAuthenticated,
}

/// Extension point for a future account/device identity service. The current
/// development path deliberately implements only the pre-shared one-time
/// secret model and never invents a persistent application signing key.
pub trait DeviceInvitationVerifier: Send + Sync {
    fn verify_device_invitation(
        &self,
        canonical_invitation: &[u8],
        detached_signature: &[u8],
        sender_identity_digest: &[u8; 32],
    ) -> Result<(), String>;
}

pub const SECURE_PROTOCOL_VERSION: u16 = 3;
pub const INVITATION_MAGIC: [u8; 8] = *b"FQINV003";
pub const HANDSHAKE_MAGIC: [u8; 8] = *b"FQHSK003";
pub const CONTROL_MAGIC: [u8; 8] = *b"FQMAC003";
pub const MAX_INVITATION_BYTES: usize = 4096;
pub const MAX_HANDSHAKE_BYTES: usize = 16 * 1024;
pub const MAX_AUTHENTICATED_CONTROL_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_INVITATION_LIFETIME_MS: u64 = 15 * 60 * 1000;
pub const DEFAULT_RESUME_AUTH_LIFETIME_MS: u64 = 10 * 60 * 1000;
pub const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 15 * 1000;
pub const MAX_INVITATION_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;
pub const MAX_SESSION_AUTH_LIFETIME_MS: u64 = 60 * 60 * 1000;
pub const MAX_HANDSHAKE_TIMEOUT_MS: u64 = 60 * 1000;
pub const ALLOWED_CLOCK_SKEW_MS: u64 = 30 * 1000;

pub const MESSAGE_TRANSFER_METADATA: u16 = 1;
pub const MESSAGE_RESUME_OFFER: u16 = 2;
pub const MESSAGE_RESUME_STATE: u16 = 3;
pub const MESSAGE_RESUME_ACCEPT: u16 = 4;
pub const MESSAGE_RESUME_REJECT: u16 = 5;
pub const MESSAGE_COMPLETION_MANIFEST: u16 = 6;
pub const MESSAGE_COMPLETION_ACK: u16 = 7;
pub const MESSAGE_PROTOCOL_ERROR: u16 = 8;
pub const MESSAGE_TRANSFER_CANCEL: u16 = 9;
pub const MESSAGE_TRANSFER_CANCEL_ACK: u16 = 10;
pub const MESSAGE_TRANSFER_PAUSE_REQUEST: u16 = 11;
pub const MESSAGE_TRANSFER_PAUSE_ACCEPT: u16 = 12;
pub const MESSAGE_TRANSFER_PAUSE_REJECT: u16 = 13;
pub const MESSAGE_TRANSFER_PAUSED: u16 = 14;
pub const MESSAGE_TRANSFER_STATUS_QUERY: u16 = 15;
pub const MESSAGE_TRANSFER_STATUS: u16 = 16;

const SENDER_ROLE: &[u8] = b"flowshare-native-sender";
const RECEIVER_ROLE: &[u8] = b"flowshare-native-receiver";
const LABEL_INVITATION: &[u8] = b"flowshare/native/v3/invitation";
const LABEL_AUTHORIZATION: &[u8] = b"flowshare/native/v3/authorization";
const LABEL_CONTROL: &[u8] = b"flowshare/native/v3/control";
const LABEL_RESUME: &[u8] = b"flowshare/native/v3/resume";
const LABEL_COMPLETION: &[u8] = b"flowshare/native/v3/completion";
const LABEL_CHECKPOINT: &[u8] = b"flowshare/native/v3/checkpoint";
const LABEL_EXPORTER: &[u8] = b"flowshare/native/v3/exporter";

#[derive(Clone)]
pub struct TransferMasterSecret(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for TransferMasterSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TransferMasterSecret([REDACTED])")
    }
}

impl TransferMasterSecret {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(Zeroizing::new(bytes))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Exposes key bytes only to a platform secure-storage adapter.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransferDirection {
    SenderToReceiver = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SecureSessionMode {
    NewTransfer = 1,
    Resume = 2,
}

impl SecureSessionMode {
    fn decode(value: u8) -> Result<Self, String> {
        match value {
            1 => Ok(Self::NewTransfer),
            2 => Ok(Self::Resume),
            _ => Err("authentication-failed".into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationBody {
    pub invitation_id: [u8; 16],
    pub transfer_id: [u8; 16],
    pub server_certificate_fingerprint: [u8; 32],
    pub capability_digest: [u8; 32],
    pub created_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub nonce: [u8; 32],
    pub allowed_file_count: u32,
    pub maximum_claim_count: u32,
    pub direction: TransferDirection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureInvitation {
    pub version: u16,
    pub body: InvitationBody,
    authorization_proof: [u8; 32],
}

impl SecureInvitation {
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = CanonicalWriter::new();
        writer.fixed(&INVITATION_MAGIC);
        writer.u16(self.version);
        self.body.write_canonical(&mut writer);
        writer.fixed(&self.authorization_proof);
        writer.finish()
    }

    pub fn decode(input: &[u8]) -> Result<Self, String> {
        if input.len() > MAX_INVITATION_BYTES {
            return Err("authentication-failed".into());
        }
        let mut reader = CanonicalReader::new(input);
        if reader.fixed::<8>()? != INVITATION_MAGIC {
            return Err("authentication-failed".into());
        }
        let version = reader.u16()?;
        if version != SECURE_PROTOCOL_VERSION {
            return Err("protocol-downgrade-rejected".into());
        }
        let body = InvitationBody::read_canonical(&mut reader)?;
        let authorization_proof = reader.fixed::<32>()?;
        reader.finish()?;
        Ok(Self {
            version,
            body,
            authorization_proof,
        })
    }

    pub fn verify(&self, master: &TransferMasterSecret, now_unix_ms: u64) -> Result<(), String> {
        if self.version != SECURE_PROTOCOL_VERSION {
            return Err("protocol-downgrade-rejected".into());
        }
        validate_expiration(
            self.body.created_unix_ms,
            self.body.expires_unix_ms,
            now_unix_ms,
        )?;
        if self.body.expires_unix_ms - self.body.created_unix_ms > MAX_INVITATION_LIFETIME_MS {
            return Err("authentication-failed".into());
        }
        self.verify_proof(master)
    }

    pub fn verify_proof(&self, master: &TransferMasterSecret) -> Result<(), String> {
        if self.version != SECURE_PROTOCOL_VERSION
            || self.body.allowed_file_count != 1
            || self.body.maximum_claim_count != 1
            || self.body.direction != TransferDirection::SenderToReceiver
        {
            return Err("authentication-failed".into());
        }
        let expected_key = Zeroizing::new(derive_labeled_key(
            master.expose(),
            LABEL_INVITATION,
            &self.body.digest(),
        )?);
        verify_mac(
            &*expected_key,
            &self.body.canonical_bytes(),
            &self.authorization_proof,
        )
        .map_err(|_| "authentication-failed".into())
    }

    pub fn proof_redacted(&self) -> &'static str {
        "[REDACTED]"
    }
}

impl InvitationBody {
    fn write_canonical(&self, writer: &mut CanonicalWriter) {
        writer.fixed(&self.invitation_id);
        writer.fixed(&self.transfer_id);
        writer.fixed(&self.server_certificate_fingerprint);
        writer.fixed(&self.capability_digest);
        writer.u64(self.created_unix_ms);
        writer.u64(self.expires_unix_ms);
        writer.fixed(&self.nonce);
        writer.u32(self.allowed_file_count);
        writer.u32(self.maximum_claim_count);
        writer.u8(self.direction as u8);
    }

    fn read_canonical(reader: &mut CanonicalReader<'_>) -> Result<Self, String> {
        let invitation_id = reader.fixed::<16>()?;
        let transfer_id = reader.fixed::<16>()?;
        let server_certificate_fingerprint = reader.fixed::<32>()?;
        let capability_digest = reader.fixed::<32>()?;
        let created_unix_ms = reader.u64()?;
        let expires_unix_ms = reader.u64()?;
        let nonce = reader.fixed::<32>()?;
        let allowed_file_count = reader.u32()?;
        let maximum_claim_count = reader.u32()?;
        let direction = match reader.u8()? {
            1 => TransferDirection::SenderToReceiver,
            _ => return Err("authentication-failed".into()),
        };
        Ok(Self {
            invitation_id,
            transfer_id,
            server_certificate_fingerprint,
            capability_digest,
            created_unix_ms,
            expires_unix_ms,
            nonce,
            allowed_file_count,
            maximum_claim_count,
            direction,
        })
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut writer = CanonicalWriter::new();
        self.write_canonical(&mut writer);
        writer.finish()
    }

    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }
}

pub fn create_invitation(
    transfer_id: [u8; 16],
    server_certificate_fingerprint: [u8; 32],
    capability_digest: [u8; 32],
    lifetime_ms: u64,
) -> Result<(SecureInvitation, TransferMasterSecret), String> {
    let master = TransferMasterSecret::generate();
    create_invitation_with_master(
        transfer_id,
        server_certificate_fingerprint,
        capability_digest,
        lifetime_ms,
        master,
    )
}

pub fn create_invitation_with_master(
    transfer_id: [u8; 16],
    server_certificate_fingerprint: [u8; 32],
    capability_digest: [u8; 32],
    lifetime_ms: u64,
    master: TransferMasterSecret,
) -> Result<(SecureInvitation, TransferMasterSecret), String> {
    if lifetime_ms == 0 || lifetime_ms > MAX_INVITATION_LIFETIME_MS {
        return Err("invitation-expired".into());
    }
    let created_unix_ms = now_unix_ms();
    let body = InvitationBody {
        invitation_id: random16(),
        transfer_id,
        server_certificate_fingerprint,
        capability_digest,
        created_unix_ms,
        expires_unix_ms: created_unix_ms
            .checked_add(lifetime_ms)
            .ok_or("invitation-expired")?,
        nonce: random32(),
        allowed_file_count: 1,
        maximum_claim_count: 1,
        direction: TransferDirection::SenderToReceiver,
    };
    let key = Zeroizing::new(derive_labeled_key(
        master.expose(),
        LABEL_INVITATION,
        &body.digest(),
    )?);
    let invitation = SecureInvitation {
        version: SECURE_PROTOCOL_VERSION,
        authorization_proof: calculate_mac(&*key, &body.canonical_bytes())?,
        body,
    };
    Ok((invitation, master))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAuthorizationBody {
    pub authorization_id: [u8; 16],
    pub invitation_id: [u8; 16],
    pub transfer_id: [u8; 16],
    pub session_id: [u8; 16],
    pub mode: SecureSessionMode,
    pub checkpoint_generation: u64,
    pub verified_state_digest: [u8; 32],
    pub transfer_commitment: [u8; 32],
    pub previous_session_digest: [u8; 32],
    pub sender_ephemeral_public_key: [u8; 32],
    pub server_certificate_fingerprint: [u8; 32],
    pub negotiated_capabilities: u64,
    pub created_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub nonce: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAuthorization {
    pub version: u16,
    pub body: SessionAuthorizationBody,
    proof: [u8; 32],
}

impl SessionAuthorizationBody {
    fn write_canonical(&self, writer: &mut CanonicalWriter) {
        writer.fixed(&self.authorization_id);
        writer.fixed(&self.invitation_id);
        writer.fixed(&self.transfer_id);
        writer.fixed(&self.session_id);
        writer.u8(self.mode as u8);
        writer.u64(self.checkpoint_generation);
        writer.fixed(&self.verified_state_digest);
        writer.fixed(&self.transfer_commitment);
        writer.fixed(&self.previous_session_digest);
        writer.fixed(&self.sender_ephemeral_public_key);
        writer.fixed(&self.server_certificate_fingerprint);
        writer.u64(self.negotiated_capabilities);
        writer.u64(self.created_unix_ms);
        writer.u64(self.expires_unix_ms);
        writer.fixed(&self.nonce);
    }

    fn read_canonical(reader: &mut CanonicalReader<'_>) -> Result<Self, String> {
        Ok(Self {
            authorization_id: reader.fixed()?,
            invitation_id: reader.fixed()?,
            transfer_id: reader.fixed()?,
            session_id: reader.fixed()?,
            mode: SecureSessionMode::decode(reader.u8()?)?,
            checkpoint_generation: reader.u64()?,
            verified_state_digest: reader.fixed()?,
            transfer_commitment: reader.fixed()?,
            previous_session_digest: reader.fixed()?,
            sender_ephemeral_public_key: reader.fixed()?,
            server_certificate_fingerprint: reader.fixed()?,
            negotiated_capabilities: reader.u64()?,
            created_unix_ms: reader.u64()?,
            expires_unix_ms: reader.u64()?,
            nonce: reader.fixed()?,
        })
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut writer = CanonicalWriter::new();
        self.write_canonical(&mut writer);
        writer.finish()
    }

    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }
}

impl SessionAuthorization {
    fn write_canonical(&self, writer: &mut CanonicalWriter) {
        writer.u16(self.version);
        self.body.write_canonical(writer);
        writer.fixed(&self.proof);
    }

    fn read_canonical(reader: &mut CanonicalReader<'_>) -> Result<Self, String> {
        let version = reader.u16()?;
        if version != SECURE_PROTOCOL_VERSION {
            return Err("protocol-downgrade-rejected".into());
        }
        Ok(Self {
            version,
            body: SessionAuthorizationBody::read_canonical(reader)?,
            proof: reader.fixed()?,
        })
    }

    pub fn verify(
        &self,
        master: &TransferMasterSecret,
        invitation: &SecureInvitation,
        now_unix_ms: u64,
    ) -> Result<[u8; 32], String> {
        match self.body.mode {
            SecureSessionMode::NewTransfer => invitation.verify(master, now_unix_ms)?,
            SecureSessionMode::Resume => invitation.verify_proof(master)?,
        }
        if self.version != SECURE_PROTOCOL_VERSION
            || self.body.invitation_id != invitation.body.invitation_id
            || self.body.transfer_id != invitation.body.transfer_id
            || (self.body.mode == SecureSessionMode::NewTransfer
                && self.body.server_certificate_fingerprint
                    != invitation.body.server_certificate_fingerprint)
        {
            return Err("authentication-failed".into());
        }
        validate_expiration(
            self.body.created_unix_ms,
            self.body.expires_unix_ms,
            now_unix_ms,
        )
        .map_err(|error| {
            if error == "invitation-expired" {
                "session-expired".to_string()
            } else {
                error
            }
        })?;
        if self.body.expires_unix_ms - self.body.created_unix_ms > MAX_SESSION_AUTH_LIFETIME_MS {
            return Err("authentication-failed".into());
        }
        let key = Zeroizing::new(authorization_key(master, &self.body)?);
        verify_mac(&*key, &self.body.canonical_bytes(), &self.proof)
            .map_err(|_| "authentication-failed".to_string())?;
        Ok(*key)
    }
}

pub struct EphemeralAgreement {
    secret: StaticSecret,
    pub public_key: [u8; 32],
}

impl std::fmt::Debug for EphemeralAgreement {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EphemeralAgreement")
            .field("secret", &"[REDACTED]")
            .field("public_key", &hex(&self.public_key))
            .finish()
    }
}

impl EphemeralAgreement {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret).to_bytes();
        Self { secret, public_key }
    }

    fn agree(&self, remote: &[u8; 32]) -> Result<[u8; 32], String> {
        let shared = self
            .secret
            .diffie_hellman(&PublicKey::from(*remote))
            .to_bytes();
        if bool::from(shared.ct_eq(&[0u8; 32])) {
            return Err("authentication-failed".into());
        }
        Ok(shared)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn create_session_authorization(
    master: &TransferMasterSecret,
    invitation: &SecureInvitation,
    session_id: [u8; 16],
    mode: SecureSessionMode,
    checkpoint_generation: u64,
    verified_state_digest: [u8; 32],
    transfer_commitment: [u8; 32],
    previous_session_digest: [u8; 32],
    sender_ephemeral_public_key: [u8; 32],
    server_certificate_fingerprint: [u8; 32],
    negotiated_capabilities: u64,
    lifetime_ms: u64,
) -> Result<SessionAuthorization, String> {
    match mode {
        SecureSessionMode::NewTransfer => invitation.verify(master, now_unix_ms())?,
        SecureSessionMode::Resume => invitation.verify_proof(master)?,
    }
    if (mode == SecureSessionMode::NewTransfer
        && server_certificate_fingerprint != invitation.body.server_certificate_fingerprint)
        || lifetime_ms == 0
        || lifetime_ms > MAX_SESSION_AUTH_LIFETIME_MS
    {
        return Err("certificate-binding-failed".into());
    }
    let created_unix_ms = now_unix_ms();
    let body = SessionAuthorizationBody {
        authorization_id: random16(),
        invitation_id: invitation.body.invitation_id,
        transfer_id: invitation.body.transfer_id,
        session_id,
        mode,
        checkpoint_generation,
        verified_state_digest,
        transfer_commitment,
        previous_session_digest,
        sender_ephemeral_public_key,
        server_certificate_fingerprint,
        negotiated_capabilities,
        created_unix_ms,
        expires_unix_ms: created_unix_ms
            .checked_add(lifetime_ms)
            .ok_or("session-expired")?,
        nonce: random32(),
    };
    let key = Zeroizing::new(authorization_key(master, &body)?);
    Ok(SessionAuthorization {
        version: SECURE_PROTOCOL_VERSION,
        proof: calculate_mac(&*key, &body.canonical_bytes())?,
        body,
    })
}

fn authorization_key(
    master: &TransferMasterSecret,
    body: &SessionAuthorizationBody,
) -> Result<[u8; 32], String> {
    let mut context = CanonicalWriter::new();
    context.fixed(&body.invitation_id);
    context.fixed(&body.transfer_id);
    context.fixed(&body.session_id);
    context.fixed(&body.authorization_id);
    context.u8(body.mode as u8);
    context.u64(body.checkpoint_generation);
    context.fixed(&body.verified_state_digest);
    context.fixed(&body.server_certificate_fingerprint);
    context.u64(body.expires_unix_ms);
    derive_labeled_key(master.expose(), LABEL_AUTHORIZATION, &context.finish())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureSessionOffer {
    pub authorization: SessionAuthorization,
    pub sender_nonce: [u8; 32],
    pub proof: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureSessionChallenge {
    pub receiver_ephemeral_public_key: [u8; 32],
    pub receiver_nonce: [u8; 32],
    pub server_certificate_fingerprint: [u8; 32],
    pub offer_digest: [u8; 32],
    pub proof: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureSessionResponse {
    pub transcript_hash: [u8; 32],
    pub role: [u8; 32],
    pub proof: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureSessionAccept {
    pub transcript_hash: [u8; 32],
    pub role: [u8; 32],
    pub exporter_id: [u8; 16],
    pub proof: [u8; 32],
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecureHandshakeMessage {
    Offer(SecureSessionOffer),
    Challenge(SecureSessionChallenge),
    Response(SecureSessionResponse),
    Accept(SecureSessionAccept),
    Reject { code: u16 },
}

impl SecureHandshakeMessage {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut writer = CanonicalWriter::new();
        writer.fixed(&HANDSHAKE_MAGIC);
        writer.u16(SECURE_PROTOCOL_VERSION);
        match self {
            Self::Offer(value) => {
                writer.u8(1);
                value.authorization.write_canonical(&mut writer);
                writer.fixed(&value.sender_nonce);
                writer.fixed(&value.proof);
            }
            Self::Challenge(value) => {
                writer.u8(2);
                writer.fixed(&value.receiver_ephemeral_public_key);
                writer.fixed(&value.receiver_nonce);
                writer.fixed(&value.server_certificate_fingerprint);
                writer.fixed(&value.offer_digest);
                writer.fixed(&value.proof);
            }
            Self::Response(value) => {
                writer.u8(3);
                writer.fixed(&value.transcript_hash);
                writer.fixed(&value.role);
                writer.fixed(&value.proof);
            }
            Self::Accept(value) => {
                writer.u8(4);
                writer.fixed(&value.transcript_hash);
                writer.fixed(&value.role);
                writer.fixed(&value.exporter_id);
                writer.fixed(&value.proof);
            }
            Self::Reject { code } => {
                writer.u8(5);
                writer.u16(*code);
            }
        }
        let output = writer.finish();
        if output.len() > MAX_HANDSHAKE_BYTES {
            return Err("authentication-failed".into());
        }
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> Result<Self, String> {
        if input.len() > MAX_HANDSHAKE_BYTES {
            return Err("authentication-failed".into());
        }
        let mut reader = CanonicalReader::new(input);
        if reader.fixed::<8>()? != HANDSHAKE_MAGIC {
            return Err("authentication-required".into());
        }
        if reader.u16()? != SECURE_PROTOCOL_VERSION {
            return Err("protocol-downgrade-rejected".into());
        }
        let message = match reader.u8()? {
            1 => Self::Offer(SecureSessionOffer {
                authorization: SessionAuthorization::read_canonical(&mut reader)?,
                sender_nonce: reader.fixed()?,
                proof: reader.fixed()?,
            }),
            2 => Self::Challenge(SecureSessionChallenge {
                receiver_ephemeral_public_key: reader.fixed()?,
                receiver_nonce: reader.fixed()?,
                server_certificate_fingerprint: reader.fixed()?,
                offer_digest: reader.fixed()?,
                proof: reader.fixed()?,
            }),
            3 => Self::Response(SecureSessionResponse {
                transcript_hash: reader.fixed()?,
                role: reader.fixed()?,
                proof: reader.fixed()?,
            }),
            4 => Self::Accept(SecureSessionAccept {
                transcript_hash: reader.fixed()?,
                role: reader.fixed()?,
                exporter_id: reader.fixed()?,
                proof: reader.fixed()?,
            }),
            5 => Self::Reject {
                code: reader.u16()?,
            },
            _ => return Err("authentication-failed".into()),
        };
        reader.finish()?;
        Ok(message)
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    control: [u8; 32],
    resume: [u8; 32],
    completion: [u8; 32],
    checkpoint: [u8; 32],
    exporter: [u8; 32],
    key_derivation_nanos: u64,
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionKeys")
            .field("key_material", &"[REDACTED]")
            .field("audit_identifier", &self.audit_identifier())
            .finish()
    }
}

impl SessionKeys {
    pub fn audit_identifier(&self) -> String {
        hex(&Sha256::digest(self.exporter)[..16])
    }

    pub fn key_derivation_ms(&self) -> f64 {
        self.key_derivation_nanos as f64 / 1_000_000.0
    }

    fn key_for_message(&self, message_type: u16) -> Result<&[u8; 32], String> {
        match message_type {
            MESSAGE_TRANSFER_METADATA
            | MESSAGE_PROTOCOL_ERROR
            | MESSAGE_TRANSFER_CANCEL
            | MESSAGE_TRANSFER_CANCEL_ACK
            | MESSAGE_TRANSFER_PAUSE_REQUEST
            | MESSAGE_TRANSFER_PAUSE_ACCEPT
            | MESSAGE_TRANSFER_PAUSE_REJECT
            | MESSAGE_TRANSFER_PAUSED
            | MESSAGE_TRANSFER_STATUS_QUERY
            | MESSAGE_TRANSFER_STATUS => Ok(&self.control),
            MESSAGE_RESUME_OFFER
            | MESSAGE_RESUME_STATE
            | MESSAGE_RESUME_ACCEPT
            | MESSAGE_RESUME_REJECT => Ok(&self.resume),
            MESSAGE_COMPLETION_MANIFEST | MESSAGE_COMPLETION_ACK => Ok(&self.completion),
            _ => Err("authentication-failed".into()),
        }
    }
}

pub struct ClientHandshakeState {
    authorization_key: Zeroizing<[u8; 32]>,
    agreement: EphemeralAgreement,
    offer: SecureSessionOffer,
}

pub struct ClientHandshakePending {
    keys: SessionKeys,
    transcript_hash: [u8; 32],
}

#[derive(Debug)]
pub struct ServerHandshakeState {
    transcript_hash: [u8; 32],
    keys: SessionKeys,
}

pub fn client_begin_handshake(
    master: &TransferMasterSecret,
    invitation: &SecureInvitation,
    authorization: SessionAuthorization,
    agreement: EphemeralAgreement,
    sender_nonce: Option<[u8; 32]>,
) -> Result<(ClientHandshakeState, SecureSessionOffer), String> {
    if agreement.public_key != authorization.body.sender_ephemeral_public_key {
        return Err("transcript-mismatch".into());
    }
    let authorization_key = authorization.verify(master, invitation, now_unix_ms())?;
    let mut offer = SecureSessionOffer {
        authorization,
        sender_nonce: sender_nonce.unwrap_or_else(random32),
        proof: [0; 32],
    };
    offer.proof = calculate_mac(&authorization_key, &offer.canonical_body())?;
    let state = ClientHandshakeState {
        authorization_key: Zeroizing::new(authorization_key),
        agreement,
        offer: offer.clone(),
    };
    Ok((state, offer))
}

pub fn server_accept_offer(
    master: &TransferMasterSecret,
    invitation: &SecureInvitation,
    offer: &SecureSessionOffer,
    actual_server_certificate_fingerprint: [u8; 32],
    receiver_nonce: Option<[u8; 32]>,
) -> Result<(ServerHandshakeState, SecureSessionChallenge), String> {
    let authorization_key = Zeroizing::new(offer.authorization.verify(
        master,
        invitation,
        now_unix_ms(),
    )?);
    verify_mac(&*authorization_key, &offer.canonical_body(), &offer.proof)
        .map_err(|_| "authentication-failed".to_string())?;
    if actual_server_certificate_fingerprint
        != offer.authorization.body.server_certificate_fingerprint
        || (offer.authorization.body.mode == SecureSessionMode::NewTransfer
            && actual_server_certificate_fingerprint
                != invitation.body.server_certificate_fingerprint)
    {
        return Err("certificate-binding-failed".into());
    }
    let agreement = EphemeralAgreement::generate();
    let mut challenge = SecureSessionChallenge {
        receiver_ephemeral_public_key: agreement.public_key,
        receiver_nonce: receiver_nonce.unwrap_or_else(random32),
        server_certificate_fingerprint: actual_server_certificate_fingerprint,
        offer_digest: offer.digest(),
        proof: [0; 32],
    };
    challenge.proof = calculate_mac(&*authorization_key, &challenge.canonical_body())?;
    let transcript_hash = transcript_hash(offer, &challenge);
    let shared = agreement.agree(&offer.authorization.body.sender_ephemeral_public_key)?;
    let keys = derive_session_keys(&shared, &authorization_key, &transcript_hash)?;
    let state = ServerHandshakeState {
        transcript_hash,
        keys,
    };
    Ok((state, challenge))
}

pub fn client_answer_challenge(
    state: ClientHandshakeState,
    challenge: &SecureSessionChallenge,
) -> Result<(ClientHandshakePending, SecureSessionResponse), String> {
    verify_mac(
        &*state.authorization_key,
        &challenge.canonical_body(),
        &challenge.proof,
    )
    .map_err(|_| "authentication-failed".to_string())?;
    if challenge.offer_digest != state.offer.digest()
        || challenge.server_certificate_fingerprint
            != state
                .offer
                .authorization
                .body
                .server_certificate_fingerprint
    {
        return Err("transcript-mismatch".into());
    }
    let transcript_hash = transcript_hash(&state.offer, challenge);
    let shared = state
        .agreement
        .agree(&challenge.receiver_ephemeral_public_key)?;
    let keys = derive_session_keys(&shared, &state.authorization_key, &transcript_hash)?;
    let role = role_digest(SENDER_ROLE);
    let proof = calculate_mac(&keys.control, &response_mac_input(&transcript_hash, &role))?;
    Ok((
        ClientHandshakePending {
            keys,
            transcript_hash,
        },
        SecureSessionResponse {
            transcript_hash,
            role,
            proof,
        },
    ))
}

pub fn server_finish_handshake(
    state: ServerHandshakeState,
    response: &SecureSessionResponse,
) -> Result<(SessionKeys, SecureSessionAccept), String> {
    if response.transcript_hash != state.transcript_hash
        || response.role != role_digest(SENDER_ROLE)
    {
        return Err("transcript-mismatch".into());
    }
    verify_mac(
        &state.keys.control,
        &response_mac_input(&response.transcript_hash, &response.role),
        &response.proof,
    )
    .map_err(|_| "authentication-failed".to_string())?;
    let role = role_digest(RECEIVER_ROLE);
    let exporter_id = exporter_id(&state.keys.exporter);
    let proof = calculate_mac(
        &state.keys.control,
        &accept_mac_input(&state.transcript_hash, &role, &exporter_id),
    )?;
    let keys = state.keys.clone();
    Ok((
        keys,
        SecureSessionAccept {
            transcript_hash: state.transcript_hash,
            role,
            exporter_id,
            proof,
        },
    ))
}

pub fn client_finish_handshake(
    pending: ClientHandshakePending,
    accept: &SecureSessionAccept,
) -> Result<SessionKeys, String> {
    if accept.transcript_hash != pending.transcript_hash
        || accept.role != role_digest(RECEIVER_ROLE)
        || accept.exporter_id != exporter_id(&pending.keys.exporter)
    {
        return Err("transcript-mismatch".into());
    }
    verify_mac(
        &pending.keys.control,
        &accept_mac_input(&accept.transcript_hash, &accept.role, &accept.exporter_id),
        &accept.proof,
    )
    .map_err(|_| "authentication-failed".to_string())?;
    Ok(pending.keys)
}

impl SecureSessionOffer {
    fn canonical_body(&self) -> Vec<u8> {
        let mut writer = CanonicalWriter::new();
        writer.u16(SECURE_PROTOCOL_VERSION);
        writer.bytes(&self.authorization.body.canonical_bytes());
        writer.fixed(&self.authorization.proof);
        writer.fixed(&self.sender_nonce);
        writer.fixed(&role_digest(SENDER_ROLE));
        writer.finish()
    }

    fn digest(&self) -> [u8; 32] {
        let mut writer = CanonicalWriter::new();
        writer.bytes(&self.canonical_body());
        writer.fixed(&self.proof);
        Sha256::digest(writer.finish()).into()
    }
}

impl SecureSessionChallenge {
    fn canonical_body(&self) -> Vec<u8> {
        let mut writer = CanonicalWriter::new();
        writer.u16(SECURE_PROTOCOL_VERSION);
        writer.fixed(&self.receiver_ephemeral_public_key);
        writer.fixed(&self.receiver_nonce);
        writer.fixed(&self.server_certificate_fingerprint);
        writer.fixed(&self.offer_digest);
        writer.fixed(&role_digest(RECEIVER_ROLE));
        writer.finish()
    }
}

fn transcript_hash(offer: &SecureSessionOffer, challenge: &SecureSessionChallenge) -> [u8; 32] {
    let mut writer = CanonicalWriter::new();
    writer.bytes(b"flowshare/native/v3/transcript");
    writer.bytes(&offer.canonical_body());
    writer.fixed(&offer.proof);
    writer.bytes(&challenge.canonical_body());
    writer.fixed(&challenge.proof);
    Sha256::digest(writer.finish()).into()
}

fn derive_session_keys(
    shared_secret: &[u8; 32],
    authorization_key: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> Result<SessionKeys, String> {
    let started = Instant::now();
    let mut salt_input = CanonicalWriter::new();
    salt_input.fixed(authorization_key);
    salt_input.fixed(transcript_hash);
    let salt = Sha256::digest(salt_input.finish());
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let control = expand_key(&hkdf, LABEL_CONTROL, transcript_hash)?;
    let resume = expand_key(&hkdf, LABEL_RESUME, transcript_hash)?;
    let completion = expand_key(&hkdf, LABEL_COMPLETION, transcript_hash)?;
    let checkpoint = expand_key(&hkdf, LABEL_CHECKPOINT, transcript_hash)?;
    let exporter = expand_key(&hkdf, LABEL_EXPORTER, transcript_hash)?;
    let key_derivation_nanos = started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
    Ok(SessionKeys {
        control,
        resume,
        completion,
        checkpoint,
        exporter,
        key_derivation_nanos,
    })
}

fn expand_key(
    hkdf: &Hkdf<Sha256>,
    label: &[u8],
    transcript_hash: &[u8; 32],
) -> Result<[u8; 32], String> {
    let mut info = CanonicalWriter::new();
    info.bytes(label);
    info.fixed(transcript_hash);
    let mut output = [0u8; 32];
    hkdf.expand(&info.finish(), &mut output)
        .map_err(|_| "authentication-failed")?;
    Ok(output)
}

pub fn derive_checkpoint_key(
    master: &TransferMasterSecret,
    transfer_id: &[u8; 16],
    invitation_id: &[u8; 16],
) -> Result<[u8; 32], String> {
    let mut context = CanonicalWriter::new();
    context.fixed(transfer_id);
    context.fixed(invitation_id);
    derive_labeled_key(master.expose(), LABEL_CHECKPOINT, &context.finish())
}

fn derive_labeled_key(input_key: &[u8], label: &[u8], context: &[u8]) -> Result<[u8; 32], String> {
    let hkdf = Hkdf::<Sha256>::new(None, input_key);
    let mut info = CanonicalWriter::new();
    info.bytes(label);
    info.bytes(context);
    let mut output = [0u8; 32];
    hkdf.expand(&info.finish(), &mut output)
        .map_err(|_| "authentication-failed")?;
    Ok(output)
}

#[derive(Debug)]
pub struct SecureControlChannel {
    transfer_id: [u8; 16],
    session_id: [u8; 16],
    send_sequence: u64,
    receive_sequence: u64,
    expires_unix_ms: u64,
    keys: SessionKeys,
}

impl SecureControlChannel {
    pub fn new(
        transfer_id: [u8; 16],
        session_id: [u8; 16],
        expires_unix_ms: u64,
        keys: SessionKeys,
    ) -> Self {
        Self {
            transfer_id,
            session_id,
            send_sequence: 0,
            receive_sequence: 0,
            expires_unix_ms,
            keys,
        }
    }

    pub fn seal(&mut self, message_type: u16, payload: &[u8]) -> Result<Vec<u8>, String> {
        if payload.len() > MAX_AUTHENTICATED_CONTROL_BYTES {
            return Err("authentication-failed".into());
        }
        if now_unix_ms() > self.expires_unix_ms.saturating_add(ALLOWED_CLOCK_SKEW_MS) {
            return Err("session-expired".into());
        }
        let sequence = self.send_sequence;
        self.send_sequence = self
            .send_sequence
            .checked_add(1)
            .ok_or("control-replay-detected")?;
        let mut writer = CanonicalWriter::new();
        writer.fixed(&CONTROL_MAGIC);
        writer.u16(SECURE_PROTOCOL_VERSION);
        writer.u16(message_type);
        writer.u64(sequence);
        writer.fixed(&self.session_id);
        writer.fixed(&self.transfer_id);
        writer.bytes(payload);
        let mut output = writer.finish();
        let tag = calculate_mac(self.keys.key_for_message(message_type)?, &output)?;
        output.extend_from_slice(&tag);
        Ok(output)
    }

    pub fn open(&mut self, expected_message_type: u16, input: &[u8]) -> Result<Vec<u8>, String> {
        if input.len() > MAX_AUTHENTICATED_CONTROL_BYTES + 96 || input.len() < 86 {
            return Err("authentication-failed".into());
        }
        let (authenticated, tag) = input.split_at(input.len() - 32);
        let mut reader = CanonicalReader::new(authenticated);
        if reader.fixed::<8>()? != CONTROL_MAGIC {
            return Err("authentication-failed".into());
        }
        if reader.u16()? != SECURE_PROTOCOL_VERSION {
            return Err("protocol-downgrade-rejected".into());
        }
        let message_type = reader.u16()?;
        if message_type != expected_message_type {
            return Err("authentication-failed".into());
        }
        let sequence = reader.u64()?;
        if sequence != self.receive_sequence {
            return Err("control-replay-detected".into());
        }
        if reader.fixed::<16>()? != self.session_id {
            return Err("authentication-failed".into());
        }
        if reader.fixed::<16>()? != self.transfer_id {
            return Err("authentication-failed".into());
        }
        let payload = reader.bytes(MAX_AUTHENTICATED_CONTROL_BYTES)?.to_vec();
        reader.finish()?;
        verify_mac(self.keys.key_for_message(message_type)?, authenticated, tag)
            .map_err(|_| "invalid-control-mac".to_string())?;
        if now_unix_ms() > self.expires_unix_ms.saturating_add(ALLOWED_CLOCK_SKEW_MS) {
            return Err("session-expired".into());
        }
        self.receive_sequence = self
            .receive_sequence
            .checked_add(1)
            .ok_or("control-replay-detected")?;
        Ok(payload)
    }

    pub fn open_one_of(
        &mut self,
        allowed_message_types: &[u16],
        input: &[u8],
    ) -> Result<(u16, Vec<u8>), String> {
        if input.len() < 12 {
            return Err("authentication-failed".into());
        }
        if input[0..8] != CONTROL_MAGIC
            || u16::from_be_bytes([input[8], input[9]]) != SECURE_PROTOCOL_VERSION
        {
            return Err("authentication-failed".into());
        }
        let message_type = u16::from_be_bytes([input[10], input[11]]);
        if !allowed_message_types.contains(&message_type) {
            return Err("authentication-failed".into());
        }
        let payload = self.open(message_type, input)?;
        Ok((message_type, payload))
    }

    pub fn audit_identifier(&self) -> String {
        self.keys.audit_identifier()
    }
}

pub fn transfer_commitment(
    file_size: u64,
    expected_sha256: &[u8; 32],
    block_size: u64,
    total_blocks: u64,
    capabilities: u64,
) -> [u8; 32] {
    let mut writer = CanonicalWriter::new();
    writer.bytes(b"flowshare/native/v3/transfer-commitment");
    writer.u64(file_size);
    writer.fixed(expected_sha256);
    writer.u64(block_size);
    writer.u64(total_blocks);
    writer.u64(capabilities);
    Sha256::digest(writer.finish()).into()
}

#[allow(clippy::too_many_arguments)]
pub fn secure_resume_state_digest(
    transfer_id: &[u8; 16],
    checkpoint_generation: u64,
    source_size: u64,
    block_size: u64,
    total_blocks: u64,
    completed_bitmap: &[u8],
    completed_bytes: u64,
    block_hash_sidecar_digest: &[u8; 32],
    expected_sha256: &[u8; 32],
    part_identity_digest: &[u8; 32],
) -> [u8; 32] {
    let mut writer = CanonicalWriter::new();
    writer.bytes(b"flowshare/native/v3/resume-state");
    writer.fixed(transfer_id);
    writer.u64(checkpoint_generation);
    writer.u64(source_size);
    writer.u64(block_size);
    writer.u64(total_blocks);
    writer.bytes(completed_bitmap);
    writer.u64(completed_bytes);
    writer.fixed(block_hash_sidecar_digest);
    writer.fixed(expected_sha256);
    writer.fixed(part_identity_digest);
    Sha256::digest(writer.finish()).into()
}

pub fn checkpoint_mac(key: &[u8; 32], canonical_payload: &[u8]) -> Result<[u8; 32], String> {
    calculate_mac(key, canonical_payload)
}

pub fn verify_checkpoint_mac(
    key: &[u8; 32],
    canonical_payload: &[u8],
    tag: &[u8; 32],
) -> Result<(), String> {
    verify_mac(key, canonical_payload, tag).map_err(|_| "checkpoint-authentication-failed".into())
}

fn response_mac_input(transcript_hash: &[u8; 32], role: &[u8; 32]) -> Vec<u8> {
    let mut writer = CanonicalWriter::new();
    writer.bytes(b"flowshare/native/v3/response");
    writer.fixed(transcript_hash);
    writer.fixed(role);
    writer.finish()
}

fn accept_mac_input(
    transcript_hash: &[u8; 32],
    role: &[u8; 32],
    exporter_id: &[u8; 16],
) -> Vec<u8> {
    let mut writer = CanonicalWriter::new();
    writer.bytes(b"flowshare/native/v3/accept");
    writer.fixed(transcript_hash);
    writer.fixed(role);
    writer.fixed(exporter_id);
    writer.finish()
}

fn role_digest(role: &[u8]) -> [u8; 32] {
    Sha256::digest(role).into()
}

fn exporter_id(exporter: &[u8; 32]) -> [u8; 16] {
    Sha256::digest(exporter)[..16].try_into().unwrap()
}

fn calculate_mac(key: &[u8], message: &[u8]) -> Result<[u8; 32], String> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| "authentication-failed")?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().into())
}

fn verify_mac(key: &[u8], message: &[u8], tag: &[u8]) -> Result<(), ()> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| ())?;
    mac.update(message);
    mac.verify_slice(tag).map_err(|_| ())
}

fn validate_expiration(created: u64, expires: u64, now: u64) -> Result<(), String> {
    if expires <= created || now > expires.saturating_add(ALLOWED_CLOCK_SKEW_MS) {
        return Err("invitation-expired".into());
    }
    if created > now.saturating_add(ALLOWED_CLOCK_SKEW_MS) {
        return Err("authentication-failed".into());
    }
    Ok(())
}

pub fn capability_digest(capabilities: u64) -> [u8; 32] {
    let mut writer = CanonicalWriter::new();
    writer.bytes(b"flowshare/native/v3/capabilities");
    writer.u64(capabilities);
    Sha256::digest(writer.finish()).into()
}

pub fn session_lineage_digest(session_id: Option<&[u8; 16]>) -> [u8; 32] {
    let mut writer = CanonicalWriter::new();
    writer.bytes(b"flowshare/native/v3/session-lineage");
    if let Some(session_id) = session_id {
        writer.u8(1);
        writer.fixed(session_id);
    } else {
        writer.u8(0);
    }
    Sha256::digest(writer.finish()).into()
}

pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

pub fn development_handshake_timeout_ms() -> u64 {
    development_duration(
        "FLOWGET_NATIVE_HANDSHAKE_TIMEOUT_MS",
        DEFAULT_HANDSHAKE_TIMEOUT_MS,
        1_000,
        MAX_HANDSHAKE_TIMEOUT_MS,
    )
}

pub fn development_resume_authorization_lifetime_ms() -> u64 {
    development_duration(
        "FLOWGET_NATIVE_RESUME_AUTH_LIFETIME_MS",
        DEFAULT_RESUME_AUTH_LIFETIME_MS,
        60_000,
        MAX_SESSION_AUTH_LIFETIME_MS,
    )
}

fn development_duration(name: &str, default: u64, minimum: u64, maximum: u64) -> u64 {
    if !cfg!(any(debug_assertions, test)) {
        return default;
    }
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (minimum..=maximum).contains(value))
        .unwrap_or(default)
}

fn random16() -> [u8; 16] {
    let mut output = [0u8; 16];
    OsRng.fill_bytes(&mut output);
    output
}

fn random32() -> [u8; 32] {
    let mut output = [0u8; 32];
    OsRng.fill_bytes(&mut output);
    output
}

pub fn hex(input: &[u8]) -> String {
    input.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn decode_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.is_ascii() {
        return Err("authentication-failed".into());
    }
    let mut output = [0u8; 32];
    for (index, slot) in output.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "authentication-failed")?;
    }
    Ok(output)
}

#[derive(Default)]
struct CanonicalWriter {
    bytes: Vec<u8>,
}

impl CanonicalWriter {
    fn new() -> Self {
        Self::default()
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn fixed(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn bytes(&mut self, value: &[u8]) {
        self.u32(value.len().try_into().unwrap_or(u32::MAX));
        self.bytes.extend_from_slice(value);
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct CanonicalReader<'a> {
    input: &'a [u8],
    cursor: usize,
}

impl<'a> CanonicalReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, cursor: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or("authentication-failed")?;
        if end > self.input.len() {
            return Err("authentication-failed".into());
        }
        let output = &self.input[self.cursor..end];
        self.cursor = end;
        Ok(output)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], String> {
        self.take(N)?
            .try_into()
            .map_err(|_| "authentication-failed".into())
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], String> {
        let length = u32::from_be_bytes(self.fixed()?) as usize;
        if length > maximum {
            return Err("authentication-failed".into());
        }
        self.take(length)
    }

    fn finish(&self) -> Result<(), String> {
        if self.cursor == self.input.len() {
            Ok(())
        } else {
            Err("authentication-failed".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_invitation() -> (SecureInvitation, TransferMasterSecret) {
        create_invitation_with_master(
            [1; 16],
            [2; 32],
            capability_digest(7),
            DEFAULT_INVITATION_LIFETIME_MS,
            TransferMasterSecret::from_bytes([3; 32]),
        )
        .unwrap()
    }

    fn complete_handshake() -> (SessionKeys, SessionKeys, SessionAuthorization) {
        let (invitation, master) = test_invitation();
        let client_agreement = EphemeralAgreement::generate();
        let authorization = create_session_authorization(
            &master,
            &invitation,
            [4; 16],
            SecureSessionMode::NewTransfer,
            0,
            [0; 32],
            [5; 32],
            session_lineage_digest(None),
            client_agreement.public_key,
            [2; 32],
            7,
            DEFAULT_RESUME_AUTH_LIFETIME_MS,
        )
        .unwrap();
        let (client_state, offer) = client_begin_handshake(
            &master,
            &invitation,
            authorization.clone(),
            client_agreement,
            Some([6; 32]),
        )
        .unwrap();
        let (server_state, challenge) =
            server_accept_offer(&master, &invitation, &offer, [2; 32], Some([7; 32])).unwrap();
        let (pending, response) = client_answer_challenge(client_state, &challenge).unwrap();
        let (server_keys, accept) = server_finish_handshake(server_state, &response).unwrap();
        let client_keys = client_finish_handshake(pending, &accept).unwrap();
        (client_keys, server_keys, authorization)
    }

    #[test]
    fn invitation_round_trip_and_tampering_rejection() {
        let (invitation, master) = test_invitation();
        let encoded = invitation.encode();
        assert_eq!(SecureInvitation::decode(&encoded).unwrap(), invitation);
        invitation.verify(&master, now_unix_ms()).unwrap();
        let mut tampered = encoded;
        tampered[30] ^= 1;
        let tampered = SecureInvitation::decode(&tampered).unwrap();
        assert_eq!(
            tampered.verify(&master, now_unix_ms()).unwrap_err(),
            "authentication-failed"
        );
    }

    #[test]
    fn authenticated_handshake_derives_matching_domain_separated_keys() {
        let (client, server, _) = complete_handshake();
        assert_eq!(client.control, server.control);
        assert_eq!(client.resume, server.resume);
        assert_eq!(client.completion, server.completion);
        assert_eq!(client.checkpoint, server.checkpoint);
        assert_ne!(client.control, client.resume);
        assert_ne!(client.resume, client.completion);
        assert_ne!(client.completion, client.checkpoint);
        assert_eq!(client.audit_identifier(), server.audit_identifier());
    }

    #[test]
    fn wrong_secret_certificate_and_transcript_are_rejected() {
        let (invitation, master) = test_invitation();
        assert_eq!(
            invitation
                .verify(&TransferMasterSecret::from_bytes([9; 32]), now_unix_ms())
                .unwrap_err(),
            "authentication-failed"
        );
        let agreement = EphemeralAgreement::generate();
        let authorization = create_session_authorization(
            &master,
            &invitation,
            [4; 16],
            SecureSessionMode::NewTransfer,
            0,
            [0; 32],
            [5; 32],
            [0; 32],
            agreement.public_key,
            [2; 32],
            7,
            60_000,
        )
        .unwrap();
        let (_, offer) = client_begin_handshake(
            &master,
            &invitation,
            authorization,
            agreement,
            Some([6; 32]),
        )
        .unwrap();
        assert_eq!(
            server_accept_offer(&master, &invitation, &offer, [8; 32], None).unwrap_err(),
            "certificate-binding-failed"
        );
    }

    #[test]
    fn control_envelope_rejects_mac_replay_sequence_and_identity_attacks() {
        let (client_keys, server_keys, authorization) = complete_handshake();
        let expires = authorization.body.expires_unix_ms;
        let mut sender = SecureControlChannel::new([1; 16], [4; 16], expires, client_keys);
        let mut wrong_type =
            SecureControlChannel::new([1; 16], [4; 16], expires, server_keys.clone());
        let mut receiver = SecureControlChannel::new([1; 16], [4; 16], expires, server_keys);
        let envelope = sender.seal(MESSAGE_TRANSFER_METADATA, b"metadata").unwrap();
        assert_eq!(
            wrong_type
                .open(MESSAGE_COMPLETION_ACK, &envelope)
                .unwrap_err(),
            "authentication-failed"
        );
        assert_eq!(
            receiver.open(MESSAGE_TRANSFER_METADATA, &envelope).unwrap(),
            b"metadata"
        );
        assert_eq!(
            receiver
                .open(MESSAGE_TRANSFER_METADATA, &envelope)
                .unwrap_err(),
            "control-replay-detected"
        );
        let mut tampered = sender.seal(MESSAGE_TRANSFER_METADATA, b"next").unwrap();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(
            receiver
                .open(MESSAGE_TRANSFER_METADATA, &tampered)
                .unwrap_err(),
            "invalid-control-mac"
        );

        let mut sender = SecureControlChannel::new([1; 16], [4; 16], expires, sender.keys.clone());
        let mut receiver =
            SecureControlChannel::new([1; 16], [4; 16], expires, receiver.keys.clone());
        let envelope = sender
            .seal(MESSAGE_TRANSFER_CANCEL, b"authenticated-cancel")
            .unwrap();
        let (message_type, payload) = receiver
            .open_one_of(
                &[MESSAGE_TRANSFER_PAUSE_REQUEST, MESSAGE_TRANSFER_CANCEL],
                &envelope,
            )
            .unwrap();
        assert_eq!(message_type, MESSAGE_TRANSFER_CANCEL);
        assert_eq!(payload, b"authenticated-cancel");
    }

    #[test]
    fn invitation_parser_rejects_truncation_trailing_and_oversized_input() {
        let (invitation, _) = test_invitation();
        let encoded = invitation.encode();
        for length in 0..encoded.len() {
            assert!(SecureInvitation::decode(&encoded[..length]).is_err());
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(SecureInvitation::decode(&trailing).is_err());
        assert!(SecureInvitation::decode(&vec![0; MAX_INVITATION_BYTES + 1]).is_err());
        let mut downgraded = invitation.encode();
        downgraded[9] = SECURE_PROTOCOL_VERSION.saturating_sub(1) as u8;
        assert_eq!(
            SecureInvitation::decode(&downgraded).unwrap_err(),
            "protocol-downgrade-rejected"
        );
    }

    #[test]
    fn random_invitations_and_ephemeral_keys_are_unique() {
        let mut invitation_ids = std::collections::BTreeSet::new();
        let mut public_keys = std::collections::BTreeSet::new();
        for index in 0..128u8 {
            let (invitation, _) =
                create_invitation([index; 16], [2; 32], capability_digest(7), 60_000).unwrap();
            assert!(invitation_ids.insert(invitation.body.invitation_id));
            assert!(public_keys.insert(EphemeralAgreement::generate().public_key));
        }
    }

    #[test]
    fn deterministic_cryptographic_vectors_are_stable() {
        let body = InvitationBody {
            invitation_id: [1; 16],
            transfer_id: [2; 16],
            server_certificate_fingerprint: [3; 32],
            capability_digest: [4; 32],
            created_unix_ms: 1_000,
            expires_unix_ms: 2_000,
            nonce: [5; 32],
            allowed_file_count: 1,
            maximum_claim_count: 1,
            direction: TransferDirection::SenderToReceiver,
        };
        let master = TransferMasterSecret::from_bytes([6; 32]);
        let key = derive_labeled_key(master.expose(), LABEL_INVITATION, &body.digest()).unwrap();
        let invitation = SecureInvitation {
            version: SECURE_PROTOCOL_VERSION,
            authorization_proof: calculate_mac(&key, &body.canonical_bytes()).unwrap(),
            body,
        };
        assert_eq!(
            hex(&invitation.body.digest()),
            "ca072627c95a8527f5ab66c5e47bf8f34cb630cf8e91de81deb35bc6346e1312"
        );
        assert_eq!(
            hex(&invitation.authorization_proof),
            "f25cbc08fe24f536d825a98e9e8cdc72c2e9d8615f2fe89fb0a398208a1ded25"
        );
        assert_eq!(
            hex(&invitation.encode()),
            "4651494e56303033000301010101010101010101010101010101020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303040404040404040404040404040404040404040404040404040404040404040400000000000003e800000000000007d00505050505050505050505050505050505050505050505050505050505050505000000010000000101f25cbc08fe24f536d825a98e9e8cdc72c2e9d8615f2fe89fb0a398208a1ded25"
        );

        let authorization = SessionAuthorization {
            version: SECURE_PROTOCOL_VERSION,
            body: SessionAuthorizationBody {
                authorization_id: [7; 16],
                invitation_id: [8; 16],
                transfer_id: [9; 16],
                session_id: [10; 16],
                mode: SecureSessionMode::Resume,
                checkpoint_generation: 11,
                verified_state_digest: [12; 32],
                transfer_commitment: [13; 32],
                previous_session_digest: [14; 32],
                sender_ephemeral_public_key: [15; 32],
                server_certificate_fingerprint: [16; 32],
                negotiated_capabilities: 17,
                created_unix_ms: 18,
                expires_unix_ms: 19,
                nonce: [20; 32],
            },
            proof: [21; 32],
        };
        let offer = SecureSessionOffer {
            authorization,
            sender_nonce: [22; 32],
            proof: [23; 32],
        };
        let challenge = SecureSessionChallenge {
            receiver_ephemeral_public_key: [24; 32],
            receiver_nonce: [25; 32],
            server_certificate_fingerprint: [26; 32],
            offer_digest: offer.digest(),
            proof: [27; 32],
        };
        assert_eq!(
            hex(&transcript_hash(&offer, &challenge)),
            "eeb10a6f6ed545e617270da302a86ac104515a7ed8aaf49cc564f2f56b82579f"
        );

        let keys = derive_session_keys(&[7; 32], &[8; 32], &[9; 32]).unwrap();
        assert_eq!(
            hex(&keys.control),
            "930ef71a47ab4f4f214c7cf96d078613c157c51bd22a8cc238f3558e39ab840f"
        );
        assert_eq!(
            hex(&keys.resume),
            "70b76bd9dae1df4cb7fec4a2ba818b56c751fcaaca390beaaf7738cc4d8364e2"
        );
        assert_eq!(
            hex(&keys.completion),
            "0543ea26d73e53e5f07c76f1bd433976cfe8ec66b4ca6752d67216eb5cbb429e"
        );
        assert_eq!(
            hex(&keys.checkpoint),
            "96c1f9eb45b91e91c2cb5d51716bae435e91585884478ea40c9d10e3a2ad5194"
        );

        let state = secure_resume_state_digest(
            &[2; 16],
            7,
            10,
            2,
            5,
            &[0x15],
            6,
            &[8; 32],
            &[9; 32],
            &[10; 32],
        );
        assert_eq!(
            hex(&state),
            "74c8da3c8c79e782b90d694f4aac3327a05e4cc4b94308d27b5d5086d94097da"
        );

        let vector_keys = SessionKeys {
            control: [11; 32],
            resume: [12; 32],
            completion: [13; 32],
            checkpoint: [14; 32],
            exporter: [15; 32],
            key_derivation_nanos: 0,
        };
        let mut channel = SecureControlChannel::new([2; 16], [1; 16], u64::MAX, vector_keys);
        assert_eq!(
            hex(&channel.seal(MESSAGE_TRANSFER_METADATA, b"metadata").unwrap()),
            "46514d41433030330003000100000000000000000101010101010101010101010101010102020202020202020202020202020202000000086d657461646174618a5fa9f708a8847837e93347335b9fc158da0c84b2b5fe1527e60d2291cf75de"
        );
    }

    #[test]
    fn handshake_binary_parser_round_trips_and_rejects_malformed_frames() {
        let (invitation, master) = test_invitation();
        let agreement = EphemeralAgreement::generate();
        let authorization = create_session_authorization(
            &master,
            &invitation,
            [4; 16],
            SecureSessionMode::NewTransfer,
            0,
            [0; 32],
            [5; 32],
            session_lineage_digest(None),
            agreement.public_key,
            [2; 32],
            7,
            60_000,
        )
        .unwrap();
        let (_, offer) = client_begin_handshake(
            &master,
            &invitation,
            authorization,
            agreement,
            Some([6; 32]),
        )
        .unwrap();
        let message = SecureHandshakeMessage::Offer(offer);
        let encoded = message.encode().unwrap();
        assert_eq!(SecureHandshakeMessage::decode(&encoded).unwrap(), message);
        for length in 0..encoded.len() {
            assert!(SecureHandshakeMessage::decode(&encoded[..length]).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(SecureHandshakeMessage::decode(&trailing).is_err());
        let mut downgraded = encoded;
        downgraded[9] = 2;
        assert_eq!(
            SecureHandshakeMessage::decode(&downgraded).unwrap_err(),
            "protocol-downgrade-rejected"
        );
    }

    #[test]
    fn handshake_and_control_identity_tampering_is_rejected() {
        let (invitation, master) = test_invitation();
        let agreement = EphemeralAgreement::generate();
        let authorization = create_session_authorization(
            &master,
            &invitation,
            [4; 16],
            SecureSessionMode::NewTransfer,
            0,
            [0; 32],
            [5; 32],
            session_lineage_digest(None),
            agreement.public_key,
            [2; 32],
            7,
            60_000,
        )
        .unwrap();
        let (_, offer) = client_begin_handshake(
            &master,
            &invitation,
            authorization,
            agreement,
            Some([6; 32]),
        )
        .unwrap();
        let mut modified_nonce = offer.clone();
        modified_nonce.sender_nonce[0] ^= 1;
        assert_eq!(
            server_accept_offer(&master, &invitation, &modified_nonce, [2; 32], None).unwrap_err(),
            "authentication-failed"
        );
        let mut modified_ephemeral = offer.clone();
        modified_ephemeral
            .authorization
            .body
            .sender_ephemeral_public_key[0] ^= 1;
        assert_eq!(
            server_accept_offer(&master, &invitation, &modified_ephemeral, [2; 32], None)
                .unwrap_err(),
            "authentication-failed"
        );
        let mut modified_capability = offer;
        modified_capability
            .authorization
            .body
            .negotiated_capabilities ^= 1;
        assert_eq!(
            server_accept_offer(&master, &invitation, &modified_capability, [2; 32], None)
                .unwrap_err(),
            "authentication-failed"
        );

        let (client_keys, server_keys, authorization) = complete_handshake();
        let envelope = SecureControlChannel::new(
            [1; 16],
            [4; 16],
            authorization.body.expires_unix_ms,
            client_keys,
        )
        .seal(MESSAGE_TRANSFER_METADATA, b"metadata")
        .unwrap();
        let mut wrong_transfer = SecureControlChannel::new(
            [9; 16],
            [4; 16],
            authorization.body.expires_unix_ms,
            server_keys.clone(),
        );
        assert_eq!(
            wrong_transfer
                .open(MESSAGE_TRANSFER_METADATA, &envelope)
                .unwrap_err(),
            "authentication-failed"
        );
        let mut wrong_session = SecureControlChannel::new(
            [1; 16],
            [8; 16],
            authorization.body.expires_unix_ms,
            server_keys,
        );
        assert_eq!(
            wrong_session
                .open(MESSAGE_TRANSFER_METADATA, &envelope)
                .unwrap_err(),
            "authentication-failed"
        );
        assert!(wrong_session
            .open(
                MESSAGE_TRANSFER_METADATA,
                &vec![0; MAX_AUTHENTICATED_CONTROL_BYTES + 97],
            )
            .is_err());
    }

    #[test]
    fn sender_receiver_role_swap_is_rejected() {
        let (invitation, master) = test_invitation();
        let agreement = EphemeralAgreement::generate();
        let authorization = create_session_authorization(
            &master,
            &invitation,
            [4; 16],
            SecureSessionMode::NewTransfer,
            0,
            [0; 32],
            [5; 32],
            session_lineage_digest(None),
            agreement.public_key,
            [2; 32],
            7,
            60_000,
        )
        .unwrap();
        let (client, offer) =
            client_begin_handshake(&master, &invitation, authorization, agreement, None).unwrap();
        let (server, challenge) =
            server_accept_offer(&master, &invitation, &offer, [2; 32], None).unwrap();
        let (_, mut response) = client_answer_challenge(client, &challenge).unwrap();
        response.role = role_digest(RECEIVER_ROLE);
        assert_eq!(
            server_finish_handshake(server, &response).unwrap_err(),
            "transcript-mismatch"
        );
    }

    #[test]
    fn expired_and_future_dated_invitations_are_rejected() {
        let (invitation, master) = test_invitation();
        assert_eq!(
            invitation
                .verify(
                    &master,
                    invitation
                        .body
                        .expires_unix_ms
                        .saturating_add(ALLOWED_CLOCK_SKEW_MS + 1),
                )
                .unwrap_err(),
            "invitation-expired"
        );
        assert_eq!(
            invitation
                .verify(
                    &master,
                    invitation
                        .body
                        .created_unix_ms
                        .saturating_sub(ALLOWED_CLOCK_SKEW_MS + 1),
                )
                .unwrap_err(),
            "authentication-failed"
        );
        assert_eq!(
            create_invitation([1; 16], [2; 32], [3; 32], MAX_INVITATION_LIFETIME_MS + 1)
                .unwrap_err(),
            "invitation-expired"
        );
    }

    #[test]
    fn bounded_security_parsers_survive_randomized_malformed_inputs() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for length in 0..2048usize {
            let mut input = vec![0u8; length];
            for byte in &mut input {
                state ^= state << 7;
                state ^= state >> 9;
                state ^= state << 8;
                *byte = state as u8;
            }
            let _ = SecureInvitation::decode(&input);
            let _ = SecureHandshakeMessage::decode(&input);
            let keys = SessionKeys {
                control: [1; 32],
                resume: [2; 32],
                completion: [3; 32],
                checkpoint: [4; 32],
                exporter: [5; 32],
                key_derivation_nanos: 0,
            };
            let mut channel = SecureControlChannel::new([1; 16], [2; 16], u64::MAX, keys);
            let _ = channel.open(MESSAGE_TRANSFER_METADATA, &input);
        }
    }
}
