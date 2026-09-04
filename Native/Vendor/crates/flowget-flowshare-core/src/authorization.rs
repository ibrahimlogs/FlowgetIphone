use super::secure_protocol::{
    capability_digest, client_begin_handshake, create_invitation, create_session_authorization,
    hex, now_unix_ms, server_accept_offer, ClientHandshakeState, EphemeralAgreement,
    SecureInvitation, SecureSessionChallenge, SecureSessionMode, SecureSessionOffer,
    ServerHandshakeState, TransferMasterSecret, DEFAULT_INVITATION_LIFETIME_MS,
    SECURE_PROTOCOL_VERSION,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    sync::{LazyLock, Mutex},
};
use subtle::ConstantTimeEq;
use uuid::Uuid;

const MAX_SECURITY_EVENTS: usize = 1024;

static AUTHORIZATIONS: LazyLock<Mutex<HashMap<[u8; 16], AuthorizationRecord>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static SECURITY_EVENTS: LazyLock<Mutex<VecDeque<SecurityEvent>>> =
    LazyLock::new(|| Mutex::new(VecDeque::new()));

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum InvitationState {
    Available,
    Claiming,
    Claimed,
    Active,
    Consumed,
    Expired,
    Revoked,
}

struct AuthorizationRecord {
    invitation: SecureInvitation,
    master: TransferMasterSecret,
    state: InvitationState,
    active_session_id: Option<[u8; 16]>,
    last_session_id: Option<[u8; 16]>,
    used_authorization_ids: BTreeSet<[u8; 16]>,
    used_session_ids: BTreeSet<[u8; 16]>,
    normal_claim_completed: bool,
}

#[derive(Debug, Clone, Copy)]
enum AuthorizationInstallOutcome {
    Inserted,
    Existing(InvitationState),
}

#[derive(Debug, Clone, Copy)]
pub struct PersistedAuthorizationRestoreLease {
    invitation_id: [u8; 16],
    inserted: bool,
}

#[derive(Debug, Clone)]
pub struct AuthorizationMaterial {
    pub invitation: SecureInvitation,
    pub master: TransferMasterSecret,
}

pub struct PreparedClientHandshake {
    pub state: ClientHandshakeState,
    pub offer: SecureSessionOffer,
    pub authorization_expires_unix_ms: u64,
}

pub struct ServerClaim {
    pub state: ServerHandshakeState,
    pub challenge: SecureSessionChallenge,
    pub handle: ClaimHandle,
}

#[derive(Debug, Clone)]
pub struct ClaimHandle {
    invitation_id: [u8; 16],
    authorization_id: [u8; 16],
    session_id: [u8; 16],
    mode: SecureSessionMode,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityEvent {
    pub event: &'static str,
    pub transfer_id: String,
    pub invitation_id: String,
    pub session_id: Option<String>,
    pub protocol_version: u16,
    pub reason_code: Option<String>,
    pub timestamp_unix_ms: u64,
    pub checkpoint_generation: Option<u64>,
    pub transcript_identifier: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecureInvitationInspection {
    pub invitation_id: String,
    pub transfer_id: String,
    pub state: InvitationState,
    pub created_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub protocol_version: u16,
    pub certificate_fingerprint_sha256: String,
    pub capability_digest_sha256: String,
    pub allowed_file_count: u32,
    pub maximum_claim_count: u32,
    pub delivery_model: &'static str,
    pub active_session_id: Option<String>,
    pub last_session_id: Option<String>,
    pub authorization_secret: &'static str,
    pub authentication_tags: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateSecureInvitationRequest {
    pub transfer_id: String,
    pub certificate_fingerprint_sha256: String,
    pub capabilities: Option<u64>,
    pub lifetime_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSecureInvitationResponse {
    #[serde(flatten)]
    pub inspection: SecureInvitationInspection,
    pub encoded_invitation: String,
    pub secret_delivery_model: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InspectSecureInvitationRequest {
    pub invitation_id: Option<String>,
    pub transfer_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevokeAuthorizationRequest {
    pub transfer_id: String,
    pub retain_partial: Option<bool>,
    pub stop_active_session: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeAuthorizationResponse {
    pub transfer_id: String,
    pub invitation_id: String,
    pub state: InvitationState,
    pub active_session_stop_requested: bool,
    pub protected_secret_removed: bool,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListSecurityEventsRequest {
    pub transfer_id: Option<String>,
    pub limit: Option<usize>,
}

fn lock_authorizations(
) -> Result<std::sync::MutexGuard<'static, HashMap<[u8; 16], AuthorizationRecord>>, String> {
    AUTHORIZATIONS
        .lock()
        .map_err(|_| "native-auth-registry-unavailable".into())
}

fn push_event(event: SecurityEvent) {
    if let Ok(mut events) = SECURITY_EVENTS.lock() {
        if events.len() == MAX_SECURITY_EVENTS {
            events.pop_front();
        }
        events.push_back(event);
    }
}

fn event(
    name: &'static str,
    invitation: &SecureInvitation,
    session_id: Option<[u8; 16]>,
    reason: Option<&str>,
    generation: Option<u64>,
    transcript_identifier: Option<String>,
) {
    push_event(SecurityEvent {
        event: name,
        transfer_id: Uuid::from_bytes(invitation.body.transfer_id).to_string(),
        invitation_id: Uuid::from_bytes(invitation.body.invitation_id).to_string(),
        session_id: session_id.map(|value| Uuid::from_bytes(value).to_string()),
        protocol_version: SECURE_PROTOCOL_VERSION,
        reason_code: reason.map(str::to_string),
        timestamp_unix_ms: now_unix_ms(),
        checkpoint_generation: generation,
        transcript_identifier,
    });
}

pub fn record_security_rejection(
    name: &'static str,
    transfer_id: [u8; 16],
    invitation_id: [u8; 16],
    session_id: Option<[u8; 16]>,
    reason: &str,
    generation: Option<u64>,
) {
    push_event(SecurityEvent {
        event: name,
        transfer_id: Uuid::from_bytes(transfer_id).to_string(),
        invitation_id: Uuid::from_bytes(invitation_id).to_string(),
        session_id: session_id.map(|value| Uuid::from_bytes(value).to_string()),
        protocol_version: SECURE_PROTOCOL_VERSION,
        reason_code: Some(reason.to_string()),
        timestamp_unix_ms: now_unix_ms(),
        checkpoint_generation: generation,
        transcript_identifier: None,
    });
}

fn refresh_expiration(record: &mut AuthorizationRecord) {
    if record.state == InvitationState::Available
        && now_unix_ms()
            > record
                .invitation
                .body
                .expires_unix_ms
                .saturating_add(super::secure_protocol::ALLOWED_CLOCK_SKEW_MS)
    {
        record.state = InvitationState::Expired;
        record.active_session_id = None;
    }
}

pub fn create_registered_invitation(
    transfer_id: [u8; 16],
    certificate_fingerprint: [u8; 32],
    capabilities: u64,
    lifetime_ms: u64,
) -> Result<AuthorizationMaterial, String> {
    let (invitation, master) = create_invitation(
        transfer_id,
        certificate_fingerprint,
        capability_digest(capabilities),
        lifetime_ms,
    )?;
    install(
        invitation.clone(),
        master.clone(),
        InvitationState::Available,
    )?;
    event(
        "native-auth-invitation-created",
        &invitation,
        None,
        None,
        None,
        None,
    );
    Ok(AuthorizationMaterial { invitation, master })
}

fn install(
    invitation: SecureInvitation,
    master: TransferMasterSecret,
    state: InvitationState,
) -> Result<AuthorizationInstallOutcome, String> {
    if state == InvitationState::Available {
        invitation.verify(&master, now_unix_ms())?;
    } else {
        invitation.verify_proof(&master)?;
    }
    let mut records = lock_authorizations()?;
    if let Some(existing) = records.get(&invitation.body.invitation_id) {
        if existing.invitation == invitation
            && bool::from(existing.master.expose().ct_eq(master.expose()))
        {
            return Ok(AuthorizationInstallOutcome::Existing(existing.state));
        }
        return Err("authentication-failed".into());
    }
    if records
        .values()
        .any(|value| value.invitation.body.transfer_id == invitation.body.transfer_id)
    {
        return Err("native-auth-transfer-already-registered".into());
    }
    records.insert(
        invitation.body.invitation_id,
        AuthorizationRecord {
            invitation,
            master,
            state,
            active_session_id: None,
            last_session_id: None,
            used_authorization_ids: BTreeSet::new(),
            used_session_ids: BTreeSet::new(),
            normal_claim_completed: state != InvitationState::Available,
        },
    );
    Ok(AuthorizationInstallOutcome::Inserted)
}

pub fn restore_persisted(material: AuthorizationMaterial) -> Result<(), String> {
    install(
        material.invitation,
        material.master,
        InvitationState::Claimed,
    )
    .map(|_| ())
}

pub fn restore_persisted_leased(
    material: AuthorizationMaterial,
) -> Result<PersistedAuthorizationRestoreLease, String> {
    let invitation_id = material.invitation.body.invitation_id;
    let outcome = install(
        material.invitation,
        material.master,
        InvitationState::Claimed,
    )?;
    match outcome {
        AuthorizationInstallOutcome::Inserted => Ok(PersistedAuthorizationRestoreLease {
            invitation_id,
            inserted: true,
        }),
        AuthorizationInstallOutcome::Existing(InvitationState::Consumed) => {
            Err("resume-authorization-failed".into())
        }
        AuthorizationInstallOutcome::Existing(InvitationState::Revoked) => {
            Err("invitation-revoked".into())
        }
        AuthorizationInstallOutcome::Existing(InvitationState::Expired) => {
            Err("invitation-expired".into())
        }
        AuthorizationInstallOutcome::Existing(_) => Ok(PersistedAuthorizationRestoreLease {
            invitation_id,
            inserted: false,
        }),
    }
}

pub fn rollback_persisted_restore(lease: PersistedAuthorizationRestoreLease) {
    if !lease.inserted {
        return;
    }
    let Ok(mut records) = lock_authorizations() else {
        return;
    };
    let removable = records.get(&lease.invitation_id).is_some_and(|record| {
        record.state == InvitationState::Claimed
            && record.active_session_id.is_none()
            && record.last_session_id.is_none()
            && record.used_authorization_ids.is_empty()
            && record.used_session_ids.is_empty()
    });
    if removable {
        records.remove(&lease.invitation_id);
    }
}

pub fn install_imported_available(material: AuthorizationMaterial) -> Result<(), String> {
    install(
        material.invitation,
        material.master,
        InvitationState::Available,
    )
    .map(|_| ())
}

pub fn material_for_transfer(transfer_id: &[u8; 16]) -> Result<AuthorizationMaterial, String> {
    let mut records = lock_authorizations()?;
    let record = records
        .values_mut()
        .find(|value| &value.invitation.body.transfer_id == transfer_id)
        .ok_or("resume-authorization-failed")?;
    refresh_expiration(record);
    if matches!(
        record.state,
        InvitationState::Revoked | InvitationState::Consumed | InvitationState::Expired
    ) {
        return Err(match record.state {
            InvitationState::Revoked => "invitation-revoked",
            InvitationState::Expired => "invitation-expired",
            _ => "resume-authorization-failed",
        }
        .into());
    }
    Ok(AuthorizationMaterial {
        invitation: record.invitation.clone(),
        master: record.master.clone(),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_client_handshake(
    transfer_id: [u8; 16],
    session_id: [u8; 16],
    mode: SecureSessionMode,
    checkpoint_generation: u64,
    verified_state_digest: [u8; 32],
    transfer_commitment: [u8; 32],
    previous_session_digest: [u8; 32],
    certificate_fingerprint: [u8; 32],
    capabilities: u64,
) -> Result<PreparedClientHandshake, String> {
    let material = material_for_transfer(&transfer_id)?;
    let agreement = EphemeralAgreement::generate();
    let authorization = create_session_authorization(
        &material.master,
        &material.invitation,
        session_id,
        mode,
        checkpoint_generation,
        verified_state_digest,
        transfer_commitment,
        previous_session_digest,
        agreement.public_key,
        certificate_fingerprint,
        capabilities,
        super::secure_protocol::development_resume_authorization_lifetime_ms(),
    )?;
    let expires = authorization.body.expires_unix_ms;
    let (state, offer) = client_begin_handshake(
        &material.master,
        &material.invitation,
        authorization,
        agreement,
        None,
    )?;
    Ok(PreparedClientHandshake {
        state,
        offer,
        authorization_expires_unix_ms: expires,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn begin_server_claim(
    offer: &SecureSessionOffer,
    actual_certificate_fingerprint: [u8; 32],
    expected_session_id: [u8; 16],
    expected_mode: SecureSessionMode,
    expected_checkpoint_generation: u64,
    expected_state_digest: [u8; 32],
    expected_transfer_commitment: [u8; 32],
    expected_previous_session_digest: [u8; 32],
    expected_capabilities: u64,
) -> Result<ServerClaim, String> {
    let invitation_id = offer.authorization.body.invitation_id;
    let session_id = offer.authorization.body.session_id;
    let authorization_id = offer.authorization.body.authorization_id;
    let mut records = lock_authorizations()?;
    let record = records
        .get_mut(&invitation_id)
        .ok_or("authentication-failed")?;
    refresh_expiration(record);
    event(
        "native-auth-claim-attempted",
        &record.invitation,
        Some(session_id),
        None,
        Some(expected_checkpoint_generation),
        None,
    );

    let verified = server_accept_offer(
        &record.master,
        &record.invitation,
        offer,
        actual_certificate_fingerprint,
        None,
    );
    let (state, challenge) = match verified {
        Ok(value) => value,
        Err(error) => {
            let event_name = if error == "certificate-binding-failed" {
                "native-auth-certificate-rejected"
            } else {
                "native-auth-session-rejected"
            };
            event(
                event_name,
                &record.invitation,
                Some(session_id),
                Some(&error),
                Some(expected_checkpoint_generation),
                None,
            );
            return Err(error);
        }
    };

    if offer.authorization.body.session_id != expected_session_id
        || offer.authorization.body.mode != expected_mode
        || offer.authorization.body.checkpoint_generation != expected_checkpoint_generation
        || offer.authorization.body.verified_state_digest != expected_state_digest
        || offer.authorization.body.transfer_commitment != expected_transfer_commitment
        || offer.authorization.body.previous_session_digest != expected_previous_session_digest
        || offer.authorization.body.negotiated_capabilities != expected_capabilities
        || record.invitation.body.capability_digest != capability_digest(expected_capabilities)
    {
        event(
            "native-auth-session-rejected",
            &record.invitation,
            Some(session_id),
            Some("transcript-mismatch"),
            Some(expected_checkpoint_generation),
            None,
        );
        return Err("transcript-mismatch".into());
    }
    if record.used_authorization_ids.contains(&authorization_id)
        || record.used_session_ids.contains(&session_id)
    {
        event(
            "native-auth-replay-rejected",
            &record.invitation,
            Some(session_id),
            Some("control-replay-detected"),
            Some(expected_checkpoint_generation),
            None,
        );
        return Err("control-replay-detected".into());
    }
    let allowed = match expected_mode {
        SecureSessionMode::NewTransfer => {
            record.state == InvitationState::Available && !record.normal_claim_completed
        }
        SecureSessionMode::Resume => record.state == InvitationState::Claimed,
    };
    if !allowed {
        let reason = match record.state {
            InvitationState::Expired => "invitation-expired",
            InvitationState::Revoked => "invitation-revoked",
            InvitationState::Consumed => "resume-authorization-failed",
            _ => "invitation-already-claimed",
        };
        event(
            "native-auth-claim-rejected",
            &record.invitation,
            Some(session_id),
            Some(reason),
            Some(expected_checkpoint_generation),
            None,
        );
        return Err(reason.into());
    }
    record.state = InvitationState::Claiming;
    record.active_session_id = Some(session_id);
    // Reservation is permanent even if the rest of this handshake fails. A
    // retry must mint a fresh authorization and fresh session identifier.
    record.used_authorization_ids.insert(authorization_id);
    record.used_session_ids.insert(session_id);
    event(
        "native-auth-claim-accepted",
        &record.invitation,
        Some(session_id),
        None,
        Some(expected_checkpoint_generation),
        None,
    );
    Ok(ServerClaim {
        state,
        challenge,
        handle: ClaimHandle {
            invitation_id,
            authorization_id,
            session_id,
            mode: expected_mode,
        },
    })
}

pub fn complete_claim(handle: &ClaimHandle, transcript_identifier: String) -> Result<(), String> {
    let mut records = lock_authorizations()?;
    let record = records
        .get_mut(&handle.invitation_id)
        .ok_or("authentication-failed")?;
    if record.state != InvitationState::Claiming
        || record.active_session_id != Some(handle.session_id)
        || !record
            .used_authorization_ids
            .contains(&handle.authorization_id)
    {
        return Err("authentication-failed".into());
    }
    record.state = InvitationState::Active;
    record.last_session_id = Some(handle.session_id);
    if handle.mode == SecureSessionMode::NewTransfer {
        record.normal_claim_completed = true;
    }
    event(
        if handle.mode == SecureSessionMode::Resume {
            "native-auth-resume-established"
        } else {
            "native-auth-session-established"
        },
        &record.invitation,
        Some(handle.session_id),
        None,
        None,
        Some(transcript_identifier),
    );
    Ok(())
}

pub fn abort_claim(handle: &ClaimHandle, sensitive_activity: bool, reason: &str) {
    if let Ok(mut records) = lock_authorizations() {
        if let Some(record) = records.get_mut(&handle.invitation_id) {
            if record.active_session_id == Some(handle.session_id) {
                record.active_session_id = None;
                record.state = if handle.mode == SecureSessionMode::NewTransfer
                    && !record.normal_claim_completed
                    && !sensitive_activity
                {
                    InvitationState::Available
                } else {
                    InvitationState::Claimed
                };
                event(
                    if handle.mode == SecureSessionMode::Resume {
                        "native-auth-resume-rejected"
                    } else {
                        "native-auth-session-rejected"
                    },
                    &record.invitation,
                    Some(handle.session_id),
                    Some(reason),
                    None,
                    None,
                );
            }
        }
    }
}

pub fn mark_resumable(transfer_id: &[u8; 16]) -> Result<(), String> {
    let mut records = lock_authorizations()?;
    let record = records
        .values_mut()
        .find(|value| &value.invitation.body.transfer_id == transfer_id)
        .ok_or("resume-authorization-failed")?;
    if matches!(
        record.state,
        InvitationState::Active | InvitationState::Available
    ) {
        record.state = InvitationState::Claimed;
        record.active_session_id = None;
        record.normal_claim_completed = true;
    }
    Ok(())
}

pub fn consume(transfer_id: &[u8; 16]) -> Result<(), String> {
    let mut records = lock_authorizations()?;
    let record = records
        .values_mut()
        .find(|value| &value.invitation.body.transfer_id == transfer_id)
        .ok_or("resume-authorization-failed")?;
    record.state = InvitationState::Consumed;
    record.active_session_id = None;
    Ok(())
}

pub fn revoke(transfer_id: &[u8; 16]) -> Result<[u8; 16], String> {
    let mut records = lock_authorizations()?;
    let record = records
        .values_mut()
        .find(|value| &value.invitation.body.transfer_id == transfer_id)
        .ok_or("native-auth-invitation-not-found")?;
    record.state = InvitationState::Revoked;
    record.active_session_id = None;
    event(
        "native-auth-authorization-revoked",
        &record.invitation,
        None,
        Some("invitation-revoked"),
        None,
        None,
    );
    Ok(record.invitation.body.invitation_id)
}

fn inspect_record(record: &mut AuthorizationRecord) -> SecureInvitationInspection {
    refresh_expiration(record);
    SecureInvitationInspection {
        invitation_id: Uuid::from_bytes(record.invitation.body.invitation_id).to_string(),
        transfer_id: Uuid::from_bytes(record.invitation.body.transfer_id).to_string(),
        state: record.state,
        created_unix_ms: record.invitation.body.created_unix_ms,
        expires_unix_ms: record.invitation.body.expires_unix_ms,
        protocol_version: SECURE_PROTOCOL_VERSION,
        certificate_fingerprint_sha256: hex(&record.invitation.body.server_certificate_fingerprint),
        capability_digest_sha256: hex(&record.invitation.body.capability_digest),
        allowed_file_count: record.invitation.body.allowed_file_count,
        maximum_claim_count: record.invitation.body.maximum_claim_count,
        delivery_model: "pre-shared-one-time-secret",
        active_session_id: record
            .active_session_id
            .map(|value| Uuid::from_bytes(value).to_string()),
        last_session_id: record
            .last_session_id
            .map(|value| Uuid::from_bytes(value).to_string()),
        authorization_secret: "[REDACTED]",
        authentication_tags: "[REDACTED]",
    }
}

pub fn flowshare_native_create_secure_invitation(
    request: CreateSecureInvitationRequest,
) -> Result<CreateSecureInvitationResponse, String> {
    if !cfg!(any(debug_assertions, test)) {
        return Err("Native secure invitations are development-only.".into());
    }
    let transfer_id = *Uuid::parse_str(&request.transfer_id)
        .map_err(|_| "native-auth-transfer-id-invalid")?
        .as_bytes();
    let certificate =
        super::secure_protocol::decode_hex_32(&request.certificate_fingerprint_sha256)?;
    let material = create_registered_invitation(
        transfer_id,
        certificate,
        request.capabilities.unwrap_or(0),
        request
            .lifetime_ms
            .unwrap_or(DEFAULT_INVITATION_LIFETIME_MS),
    )?;
    let mut records = lock_authorizations()?;
    let inspection = inspect_record(
        records
            .get_mut(&material.invitation.body.invitation_id)
            .ok_or("native-auth-invitation-not-found")?,
    );
    Ok(CreateSecureInvitationResponse {
        inspection,
        encoded_invitation: URL_SAFE_NO_PAD.encode(material.invitation.encode()),
        secret_delivery_model: "internal-development-authorized-operation",
    })
}

pub fn flowshare_native_inspect_secure_invitation(
    request: InspectSecureInvitationRequest,
) -> Result<SecureInvitationInspection, String> {
    if !cfg!(any(debug_assertions, test)) {
        return Err("Native secure invitation inspection is development-only.".into());
    }
    let invitation = request
        .invitation_id
        .as_deref()
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|_| "native-auth-invitation-id-invalid")?
        .map(|value| *value.as_bytes());
    let transfer = request
        .transfer_id
        .as_deref()
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|_| "native-auth-transfer-id-invalid")?
        .map(|value| *value.as_bytes());
    if invitation.is_none() == transfer.is_none() {
        return Err("provide-exactly-one-invitation-or-transfer-id".into());
    }
    let mut records = lock_authorizations()?;
    let record = records
        .values_mut()
        .find(|record| {
            invitation.is_some_and(|value| value == record.invitation.body.invitation_id)
                || transfer.is_some_and(|value| value == record.invitation.body.transfer_id)
        })
        .ok_or("native-auth-invitation-not-found")?;
    Ok(inspect_record(record))
}

// Desktop-specific registry and protected-storage cleanup is implemented by the
// desktop adapter; the core owns the revocation state machine itself.
#[cfg(any())]
pub async fn flowshare_native_revoke_authorization(
    request: RevokeAuthorizationRequest,
) -> Result<RevokeAuthorizationResponse, String> {
    if !cfg!(any(debug_assertions, test)) {
        return Err("Native authorization revocation is development-only.".into());
    }
    let transfer_uuid =
        Uuid::parse_str(&request.transfer_id).map_err(|_| "native-auth-transfer-id-invalid")?;
    let transfer_id = *transfer_uuid.as_bytes();
    let retain_partial = request.retain_partial.unwrap_or(true);
    let stop_active_session = request.stop_active_session.unwrap_or(true);
    let record = super::transfer_registry::lookup(&request.transfer_id).await;
    let snapshot = if let Some(record) = record.as_ref() {
        Some(record.snapshot().await)
    } else {
        None
    };
    if snapshot
        .as_ref()
        .is_some_and(|value| value.runtime_active && !stop_active_session && !retain_partial)
    {
        return Err("revocation-delete-requires-stop-active-session".into());
    }
    let invitation_id = revoke(&transfer_id)?;
    let mut stop_requested = false;
    let mut secret_removed = false;
    if let Some(record) = record {
        secret_removed = super::secret_store::delete(&record.resume_path).await?;
        {
            let mut state = record.mutable.lock().await;
            state.resume_available = false;
            if !retain_partial {
                state.partial_retained = false;
            }
        }
        let snapshot = snapshot.ok_or("native-transfer-not-found")?;
        if snapshot.runtime_active && stop_active_session {
            super::transfer_registry::flowshare_native_cancel_transfer(
                super::transfer_registry::CancelTransferRequest {
                    transfer_id: request.transfer_id.clone(),
                    retain_partial: Some(retain_partial),
                    expected_generation: None,
                },
            )
            .await?;
            stop_requested = true;
        } else if !snapshot.runtime_active && !retain_partial {
            if matches!(
                snapshot.state,
                super::lifecycle::TransferState::Paused
                    | super::lifecycle::TransferState::PausedByDisconnect
                    | super::lifecycle::TransferState::Cancelled
                    | super::lifecycle::TransferState::RecoverableFailure
                    | super::lifecycle::TransferState::Failed
            ) {
                super::transfer_registry::flowshare_native_discard_partial(
                    super::transfer_registry::TransferIdRequest {
                        transfer_id: request.transfer_id.clone(),
                    },
                )
                .await?;
            } else if snapshot.state != super::lifecycle::TransferState::Completed {
                super::transfer_registry::flowshare_native_cancel_transfer(
                    super::transfer_registry::CancelTransferRequest {
                        transfer_id: request.transfer_id.clone(),
                        retain_partial: Some(false),
                        expected_generation: None,
                    },
                )
                .await?;
            }
        }
    }
    Ok(RevokeAuthorizationResponse {
        transfer_id: transfer_uuid.to_string(),
        invitation_id: Uuid::from_bytes(invitation_id).to_string(),
        state: InvitationState::Revoked,
        active_session_stop_requested: stop_requested,
        protected_secret_removed: secret_removed,
    })
}

pub fn flowshare_native_list_security_events(
    request: Option<ListSecurityEventsRequest>,
) -> Result<Vec<SecurityEvent>, String> {
    if !cfg!(any(debug_assertions, test)) {
        return Err("Native security events are development-only.".into());
    }
    let request = request.unwrap_or_default();
    let limit = request.limit.unwrap_or(200).min(MAX_SECURITY_EVENTS);
    let events = SECURITY_EVENTS
        .lock()
        .map_err(|_| "native-auth-event-log-unavailable")?;
    Ok(events
        .iter()
        .rev()
        .filter(|event| {
            request
                .transfer_id
                .as_ref()
                .is_none_or(|value| value == &event.transfer_id)
        })
        .take(limit)
        .cloned()
        .collect())
}

#[doc(hidden)]
pub fn clear_for_test() {
    if let Ok(mut records) = AUTHORIZATIONS.lock() {
        records.clear();
    }
    if let Ok(mut events) = SECURITY_EVENTS.lock() {
        events.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_protocol::{session_lineage_digest, transfer_commitment};

    fn setup() -> ([u8; 16], [u8; 32]) {
        clear_for_test();
        let transfer = *Uuid::new_v4().as_bytes();
        let certificate = [2; 32];
        create_registered_invitation(transfer, certificate, 7, 60_000).unwrap();
        (transfer, certificate)
    }

    #[test]
    #[serial_test::serial(flowshare_authorization)]
    fn simultaneous_claim_allows_exactly_one_receiver() {
        let (transfer, certificate) = setup();
        let session = *Uuid::new_v4().as_bytes();
        let commitment = transfer_commitment(10, &[3; 32], 2, 5, 7);
        let prepared = prepare_client_handshake(
            transfer,
            session,
            SecureSessionMode::NewTransfer,
            0,
            [0; 32],
            commitment,
            session_lineage_digest(None),
            certificate,
            7,
        )
        .unwrap();
        let offer = std::sync::Arc::new(prepared.offer);
        let mut threads = Vec::new();
        for _ in 0..8 {
            let offer = offer.clone();
            threads.push(std::thread::spawn(move || {
                begin_server_claim(
                    &offer,
                    certificate,
                    session,
                    SecureSessionMode::NewTransfer,
                    0,
                    [0; 32],
                    commitment,
                    session_lineage_digest(None),
                    7,
                )
                .map(|claim| claim.handle)
            }));
        }
        let results: Vec<_> = threads
            .into_iter()
            .map(|value| value.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|value| value.is_ok()).count(), 1);
        assert!(results.iter().filter(|value| value.is_err()).all(|value| {
            matches!(
                value.as_ref().unwrap_err().as_str(),
                "control-replay-detected" | "invitation-already-claimed"
            )
        }));
    }

    #[test]
    #[serial_test::serial(flowshare_authorization)]
    fn invitation_command_never_returns_shared_secret() {
        clear_for_test();
        let response = flowshare_native_create_secure_invitation(CreateSecureInvitationRequest {
            transfer_id: Uuid::new_v4().to_string(),
            certificate_fingerprint_sha256: hex(&[4; 32]),
            capabilities: Some(7),
            lifetime_ms: Some(60_000),
        })
        .unwrap();
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("[REDACTED]"));
        assert!(!json.contains(&URL_SAFE_NO_PAD.encode([0u8; 32])));
    }

    #[test]
    #[serial_test::serial(flowshare_authorization)]
    fn revocation_and_resume_authorization_replay_are_rejected() {
        let (transfer, certificate) = setup();
        let normal_session = *Uuid::new_v4().as_bytes();
        let commitment = transfer_commitment(10, &[3; 32], 2, 5, 7);
        let normal = prepare_client_handshake(
            transfer,
            normal_session,
            SecureSessionMode::NewTransfer,
            0,
            [0; 32],
            commitment,
            session_lineage_digest(None),
            certificate,
            7,
        )
        .unwrap();
        let normal_claim = begin_server_claim(
            &normal.offer,
            certificate,
            normal_session,
            SecureSessionMode::NewTransfer,
            0,
            [0; 32],
            commitment,
            session_lineage_digest(None),
            7,
        )
        .unwrap();
        abort_claim(&normal_claim.handle, true, "disconnect");

        let resume_session = *Uuid::new_v4().as_bytes();
        let resume_certificate = [8; 32];
        let state_digest = [9; 32];
        let resume = prepare_client_handshake(
            transfer,
            resume_session,
            SecureSessionMode::Resume,
            3,
            state_digest,
            commitment,
            session_lineage_digest(Some(&normal_session)),
            resume_certificate,
            7,
        )
        .unwrap();
        assert_eq!(
            begin_server_claim(
                &resume.offer,
                certificate,
                resume_session,
                SecureSessionMode::Resume,
                3,
                state_digest,
                commitment,
                session_lineage_digest(Some(&normal_session)),
                7,
            )
            .err()
            .unwrap(),
            "certificate-binding-failed"
        );
        let claim = begin_server_claim(
            &resume.offer,
            resume_certificate,
            resume_session,
            SecureSessionMode::Resume,
            3,
            state_digest,
            commitment,
            session_lineage_digest(Some(&normal_session)),
            7,
        )
        .unwrap();
        abort_claim(&claim.handle, true, "disconnect");
        assert_eq!(
            begin_server_claim(
                &resume.offer,
                resume_certificate,
                resume_session,
                SecureSessionMode::Resume,
                3,
                state_digest,
                commitment,
                session_lineage_digest(Some(&normal_session)),
                7,
            )
            .err()
            .unwrap(),
            "control-replay-detected"
        );

        revoke(&transfer).unwrap();
        assert_eq!(
            material_for_transfer(&transfer).unwrap_err(),
            "invitation-revoked"
        );
    }

    #[cfg(any())]
    #[tokio::test]
    #[serial_test::serial(flowshare_authorization)]
    async fn revocation_honors_delete_choice_for_inactive_paused_transfer() {
        clear_for_test();
        let transfer_uuid = Uuid::new_v4();
        let transfer = *transfer_uuid.as_bytes();
        let material = create_registered_invitation(transfer, [2; 32], 7, 60_000).unwrap();
        let root = std::env::temp_dir().join(format!("flowget-revoke-{transfer_uuid}"));
        tokio::fs::create_dir_all(&root).await.unwrap();
        let part = root.join("file.part");
        let resume = root.join("file.resume.current");
        let blocks = crate::flowshare_native::block_hash::block_generation_paths(&resume).current;
        tokio::fs::write(&part, [1u8; 4]).await.unwrap();
        tokio::fs::write(&resume, b"checkpoint").await.unwrap();
        tokio::fs::write(&blocks, b"sidecar").await.unwrap();
        crate::flowshare_native::secret_store::store(&resume, &material)
            .await
            .unwrap();
        let record = crate::flowshare_native::transfer_registry::register(
            crate::flowshare_native::transfer_registry::NewTransferRecord {
                transfer_id: transfer_uuid.to_string(),
                source_path: None,
                source_identity: None,
                destination_path: root.join("file.bin"),
                part_path: part.clone(),
                resume_path: resume.clone(),
                expected_file_size: 4,
                block_size: 2,
                retain_partial: true,
            },
        )
        .await
        .unwrap();
        for state in [
            crate::flowshare_native::lifecycle::TransferState::Preparing,
            crate::flowshare_native::lifecycle::TransferState::Connecting,
            crate::flowshare_native::lifecycle::TransferState::Transferring,
            crate::flowshare_native::lifecycle::TransferState::Pausing,
            crate::flowshare_native::lifecycle::TransferState::Paused,
        ] {
            record.transition(state).await.unwrap();
        }
        {
            let mut state = record.mutable.lock().await;
            state.runtime_active = false;
            state.partial_retained = true;
            state.resume_available = true;
        }

        let result = flowshare_native_revoke_authorization(RevokeAuthorizationRequest {
            transfer_id: transfer_uuid.to_string(),
            retain_partial: Some(false),
            stop_active_session: Some(false),
        })
        .await
        .unwrap();
        assert_eq!(result.state, InvitationState::Revoked);
        assert!(result.protected_secret_removed);
        assert!(!result.active_session_stop_requested);
        assert!(!part.exists());
        assert!(!resume.exists());
        assert!(!blocks.exists());
        assert!(!crate::flowshare_native::secret_store::secret_path(&resume).exists());
        let snapshot = record.snapshot().await;
        assert!(!snapshot.partial_retained);
        assert!(!snapshot.resume_available);

        crate::flowshare_native::transfer_registry::remove_for_test(&transfer_uuid.to_string())
            .await;
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[test]
    #[serial_test::serial(flowshare_authorization)]
    fn persisted_restore_lease_rolls_back_only_untouched_insertions() {
        clear_for_test();
        let transfer = *Uuid::new_v4().as_bytes();
        let (invitation, master) =
            create_invitation(transfer, [4; 32], capability_digest(7), 60_000).unwrap();
        let material = AuthorizationMaterial { invitation, master };

        let lease = restore_persisted_leased(material.clone()).unwrap();
        assert!(material_for_transfer(&transfer).is_ok());
        rollback_persisted_restore(lease);
        assert_eq!(
            material_for_transfer(&transfer).unwrap_err(),
            "resume-authorization-failed"
        );

        let consumed_lease = restore_persisted_leased(material.clone()).unwrap();
        consume(&transfer).unwrap();
        rollback_persisted_restore(consumed_lease);
        assert_eq!(
            material_for_transfer(&transfer).unwrap_err(),
            "resume-authorization-failed"
        );
        assert_eq!(
            restore_persisted_leased(material).unwrap_err(),
            "resume-authorization-failed"
        );
        clear_for_test();
    }
}
