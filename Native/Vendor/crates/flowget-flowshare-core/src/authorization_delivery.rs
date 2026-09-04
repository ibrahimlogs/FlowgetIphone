use super::{
    authorization::AuthorizationMaterial,
    secure_protocol::{
        now_unix_ms, SecureInvitation, TransferMasterSecret, ALLOWED_CLOCK_SKEW_MS,
        SECURE_PROTOCOL_VERSION,
    },
    security::{create_ephemeral_identity, EphemeralIdentity},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand_core::{OsRng, RngCore};
use rustls::pki_types::CertificateDer;
use serde::Serialize;
use sha2_compat::{Digest, Sha256};
use std::time::Duration;
use uuid::Uuid;
use zeroize::Zeroizing;

const BOOTSTRAP_MAGIC: [u8; 16] = *b"FQNATIVEBOOT0004";
const INVITATION_PACKAGE_MAGIC: [u8; 16] = *b"FQNATIVEINVITE04";
const BOOTSTRAP_FORMAT_VERSION: u16 = 1;
pub const AUTHORIZATION_DELIVERY_VERSION: u16 = 4;
const MANUAL_PACKAGE_FLAG: u16 = 1;
const SENDER_ROLE: u8 = 1;
const RECEIVER_ROLE: u8 = 2;
const MAX_BOOTSTRAP_BYTES: usize = 8 * 1024;
const MAX_INVITATION_PACKAGE_BYTES: usize = 8 * 1024;
const MAX_CERTIFICATE_BYTES: usize = 4 * 1024;
const MAX_MANUAL_PACKAGE_LIFETIME_MS: u64 = 15 * 60 * 1000;

pub const MANUAL_PACKAGE_POSSESSION_WARNING: &str =
    "Possession of this high-entropy one-time package authorizes one FlowShare native transfer. Share it only with the intended receiver.";

pub struct PreparedReceiverBootstrap {
    pub bootstrap_id: [u8; 16],
    pub encoded_package: String,
    pub certificate_fingerprint_sha256: [u8; 32],
    pub expires_unix_ms: u64,
    pub identity: EphemeralIdentity,
}

#[derive(Debug, Clone)]
pub struct DecodedReceiverBootstrap {
    pub bootstrap_id: [u8; 16],
    pub certificate: CertificateDer<'static>,
    pub certificate_fingerprint_sha256: [u8; 32],
    pub created_unix_ms: u64,
    pub expires_unix_ms: u64,
}

#[derive(Clone)]
pub struct DecodedManualInvitationPackage {
    pub material: AuthorizationMaterial,
    pub package_digest_sha256: [u8; 32],
    pub created_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub receiver_certificate_fingerprint_sha256: [u8; 32],
}

impl std::fmt::Debug for DecodedManualInvitationPackage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DecodedManualInvitationPackage")
            .field(
                "transfer_id",
                &Uuid::from_bytes(self.material.invitation.body.transfer_id),
            )
            .field(
                "invitation_id",
                &Uuid::from_bytes(self.material.invitation.body.invitation_id),
            )
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManualInvitationPackageInspection {
    pub format: &'static str,
    pub authorization_delivery_version: u16,
    pub secure_protocol_version: u16,
    pub transfer_id: String,
    pub invitation_id: String,
    pub expires_unix_ms: u64,
    pub receiver_certificate_fingerprint_sha256: String,
    pub possession_warning: &'static str,
    pub contains_high_entropy_one_time_secret: bool,
    pub contains_path_or_filename: bool,
}

pub fn prepare_receiver_bootstrap(lifetime: Duration) -> Result<PreparedReceiverBootstrap, String> {
    let lifetime_ms = lifetime
        .as_millis()
        .try_into()
        .map_err(|_| "native-receiver-bootstrap-lifetime-invalid")?;
    if lifetime_ms == 0 || lifetime_ms > MAX_MANUAL_PACKAGE_LIFETIME_MS {
        return Err("native-receiver-bootstrap-lifetime-invalid".into());
    }
    let identity = create_ephemeral_identity()?;
    let bootstrap_id = *Uuid::new_v4().as_bytes();
    let created_unix_ms = now_unix_ms();
    let expires_unix_ms = created_unix_ms
        .checked_add(lifetime_ms)
        .ok_or("native-receiver-bootstrap-lifetime-invalid")?;
    let certificate = identity.certificate.as_ref();
    if certificate.is_empty() || certificate.len() > MAX_CERTIFICATE_BYTES {
        return Err("native-receiver-bootstrap-certificate-invalid".into());
    }
    let mut package = Vec::with_capacity(128 + certificate.len());
    package.extend_from_slice(&BOOTSTRAP_MAGIC);
    package.extend_from_slice(&BOOTSTRAP_FORMAT_VERSION.to_be_bytes());
    package.extend_from_slice(&SECURE_PROTOCOL_VERSION.to_be_bytes());
    package.extend_from_slice(&bootstrap_id);
    package.extend_from_slice(&created_unix_ms.to_be_bytes());
    package.extend_from_slice(&expires_unix_ms.to_be_bytes());
    package.extend_from_slice(&identity.fingerprint_sha256_bytes);
    package.extend_from_slice(&(certificate.len() as u16).to_be_bytes());
    package.extend_from_slice(certificate);
    package.extend_from_slice(&random_32());
    append_checksum(&mut package);
    if package.len() > MAX_BOOTSTRAP_BYTES {
        return Err("native-receiver-bootstrap-oversized".into());
    }
    Ok(PreparedReceiverBootstrap {
        bootstrap_id,
        encoded_package: URL_SAFE_NO_PAD.encode(package),
        certificate_fingerprint_sha256: identity.fingerprint_sha256_bytes,
        expires_unix_ms,
        identity,
    })
}

pub fn decode_receiver_bootstrap(
    encoded: &str,
    now: u64,
) -> Result<DecodedReceiverBootstrap, String> {
    let bytes = decode_bounded(encoded, MAX_BOOTSTRAP_BYTES, "native-receiver-bootstrap")?;
    let authenticated = verify_checksum(&bytes, "native-receiver-bootstrap-invalid")?;
    let mut reader = Reader::new(authenticated);
    if reader.take_array::<16>()? != BOOTSTRAP_MAGIC
        || reader.u16()? != BOOTSTRAP_FORMAT_VERSION
        || reader.u16()? != SECURE_PROTOCOL_VERSION
    {
        return Err("native-receiver-bootstrap-version-unsupported".into());
    }
    let bootstrap_id = reader.take_array::<16>()?;
    let created_unix_ms = reader.u64()?;
    let expires_unix_ms = reader.u64()?;
    let certificate_fingerprint_sha256 = reader.take_array::<32>()?;
    let certificate_length = reader.u16()? as usize;
    if certificate_length == 0 || certificate_length > MAX_CERTIFICATE_BYTES {
        return Err("native-receiver-bootstrap-certificate-invalid".into());
    }
    let certificate = CertificateDer::from(reader.take(certificate_length)?.to_vec());
    let _nonce = reader.take_array::<32>()?;
    reader.finish()?;
    validate_time_window(created_unix_ms, expires_unix_ms, now)?;
    if Sha256::digest(certificate.as_ref()).as_slice() != certificate_fingerprint_sha256 {
        return Err("native-receiver-bootstrap-certificate-invalid".into());
    }
    Ok(DecodedReceiverBootstrap {
        bootstrap_id,
        certificate,
        certificate_fingerprint_sha256,
        created_unix_ms,
        expires_unix_ms,
    })
}

pub fn export_manual_invitation_package(
    material: &AuthorizationMaterial,
    lifetime: Duration,
) -> Result<(String, ManualInvitationPackageInspection), String> {
    let lifetime_ms: u64 = lifetime
        .as_millis()
        .try_into()
        .map_err(|_| "native-manual-package-lifetime-invalid")?;
    if lifetime_ms == 0 || lifetime_ms > MAX_MANUAL_PACKAGE_LIFETIME_MS {
        return Err("native-manual-package-lifetime-invalid".into());
    }
    let created_unix_ms = now_unix_ms();
    let expires_unix_ms = created_unix_ms
        .checked_add(lifetime_ms)
        .ok_or("native-manual-package-lifetime-invalid")?
        .min(material.invitation.body.expires_unix_ms);
    material
        .invitation
        .verify(&material.master, created_unix_ms)?;
    let invitation = material.invitation.encode();
    let mut package = Zeroizing::new(Vec::with_capacity(256 + invitation.len()));
    package.extend_from_slice(&INVITATION_PACKAGE_MAGIC);
    package.extend_from_slice(&AUTHORIZATION_DELIVERY_VERSION.to_be_bytes());
    package.extend_from_slice(&MANUAL_PACKAGE_FLAG.to_be_bytes());
    package.extend_from_slice(&SECURE_PROTOCOL_VERSION.to_be_bytes());
    package.extend_from_slice(&created_unix_ms.to_be_bytes());
    package.extend_from_slice(&expires_unix_ms.to_be_bytes());
    package.push(SENDER_ROLE);
    package.push(RECEIVER_ROLE);
    package.extend_from_slice(&material.invitation.body.invitation_id);
    package.extend_from_slice(&material.invitation.body.transfer_id);
    package.extend_from_slice(&material.invitation.body.server_certificate_fingerprint);
    package.extend_from_slice(&material.invitation.body.capability_digest);
    package.extend_from_slice(&random_32());
    package.extend_from_slice(&(invitation.len() as u32).to_be_bytes());
    package.extend_from_slice(&invitation);
    package.extend_from_slice(material.master.expose());
    append_checksum(&mut package);
    if package.len() > MAX_INVITATION_PACKAGE_BYTES {
        return Err("native-manual-package-oversized".into());
    }
    let inspection = inspect_manual_package(material, expires_unix_ms);
    Ok((URL_SAFE_NO_PAD.encode(&*package), inspection))
}

pub fn decode_manual_invitation_package(
    encoded: &str,
    expected_receiver_certificate: Option<[u8; 32]>,
    now: u64,
) -> Result<DecodedManualInvitationPackage, String> {
    let bytes = Zeroizing::new(decode_bounded(
        encoded,
        MAX_INVITATION_PACKAGE_BYTES,
        "native-manual-package",
    )?);
    let package_digest_sha256: [u8; 32] = Sha256::digest(&*bytes).into();
    let authenticated = verify_checksum(&bytes, "native-manual-package-invalid")?;
    let mut reader = Reader::new(authenticated);
    if reader.take_array::<16>()? != INVITATION_PACKAGE_MAGIC
        || reader.u16()? != AUTHORIZATION_DELIVERY_VERSION
    {
        return Err("native-manual-package-version-unsupported".into());
    }
    if reader.u16()? != MANUAL_PACKAGE_FLAG || reader.u16()? != SECURE_PROTOCOL_VERSION {
        return Err("native-manual-package-flags-invalid".into());
    }
    let created_unix_ms = reader.u64()?;
    let expires_unix_ms = reader.u64()?;
    if reader.u8()? != SENDER_ROLE || reader.u8()? != RECEIVER_ROLE {
        return Err("native-manual-package-role-invalid".into());
    }
    let invitation_id = reader.take_array::<16>()?;
    let transfer_id = reader.take_array::<16>()?;
    let receiver_certificate_fingerprint_sha256 = reader.take_array::<32>()?;
    let capability_digest = reader.take_array::<32>()?;
    let _package_nonce = reader.take_array::<32>()?;
    let invitation_length = reader.u32()? as usize;
    if invitation_length == 0 || invitation_length > super::secure_protocol::MAX_INVITATION_BYTES {
        return Err("native-manual-package-invitation-invalid".into());
    }
    let invitation = SecureInvitation::decode(reader.take(invitation_length)?)?;
    let master = TransferMasterSecret::from_bytes(reader.take_array::<32>()?);
    reader.finish()?;
    validate_time_window(created_unix_ms, expires_unix_ms, now)?;
    if invitation.body.invitation_id != invitation_id
        || invitation.body.transfer_id != transfer_id
        || invitation.body.server_certificate_fingerprint != receiver_certificate_fingerprint_sha256
        || invitation.body.capability_digest != capability_digest
        || invitation.body.expires_unix_ms < expires_unix_ms
    {
        return Err("native-manual-package-binding-invalid".into());
    }
    if expected_receiver_certificate
        .is_some_and(|expected| expected != receiver_certificate_fingerprint_sha256)
    {
        return Err("native-manual-package-receiver-mismatch".into());
    }
    invitation.verify(&master, now)?;
    Ok(DecodedManualInvitationPackage {
        material: AuthorizationMaterial { invitation, master },
        package_digest_sha256,
        created_unix_ms,
        expires_unix_ms,
        receiver_certificate_fingerprint_sha256,
    })
}

pub fn inspect_manual_package(
    material: &AuthorizationMaterial,
    expires_unix_ms: u64,
) -> ManualInvitationPackageInspection {
    ManualInvitationPackageInspection {
        format: "FQNATIVEINVITE04",
        authorization_delivery_version: AUTHORIZATION_DELIVERY_VERSION,
        secure_protocol_version: SECURE_PROTOCOL_VERSION,
        transfer_id: Uuid::from_bytes(material.invitation.body.transfer_id).to_string(),
        invitation_id: Uuid::from_bytes(material.invitation.body.invitation_id).to_string(),
        expires_unix_ms,
        receiver_certificate_fingerprint_sha256: hex(&material
            .invitation
            .body
            .server_certificate_fingerprint),
        possession_warning: MANUAL_PACKAGE_POSSESSION_WARNING,
        contains_high_entropy_one_time_secret: true,
        contains_path_or_filename: false,
    }
}

fn validate_time_window(created: u64, expires: u64, now: u64) -> Result<(), String> {
    if expires <= created
        || expires.saturating_sub(created) > MAX_MANUAL_PACKAGE_LIFETIME_MS
        || created > now.saturating_add(ALLOWED_CLOCK_SKEW_MS)
        || expires.saturating_add(ALLOWED_CLOCK_SKEW_MS) < now
    {
        return Err("native-authorization-package-expired".into());
    }
    Ok(())
}

fn decode_bounded(encoded: &str, maximum: usize, prefix: &str) -> Result<Vec<u8>, String> {
    if encoded.is_empty() || encoded.len() > maximum.saturating_mul(2) {
        return Err(format!("{prefix}-oversized"));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| format!("{prefix}-malformed"))?;
    if decoded.is_empty() || decoded.len() > maximum {
        return Err(format!("{prefix}-oversized"));
    }
    Ok(decoded)
}

fn append_checksum(bytes: &mut Vec<u8>) {
    let checksum = Sha256::digest(&*bytes);
    bytes.extend_from_slice(&checksum);
}

fn verify_checksum<'a>(bytes: &'a [u8], error: &str) -> Result<&'a [u8], String> {
    if bytes.len() < 32 {
        return Err(error.into());
    }
    let (body, checksum) = bytes.split_at(bytes.len() - 32);
    if Sha256::digest(body).as_slice() != checksum {
        return Err(error.into());
    }
    Ok(body)
}

fn random_32() -> [u8; 32] {
    let mut value = [0u8; 32];
    OsRng.fill_bytes(&mut value);
    value
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or("native-authorization-package-invalid")?;
        if end > self.bytes.len() {
            return Err("native-authorization-package-invalid".into());
        }
        let value = &self.bytes[self.cursor..end];
        self.cursor = end;
        Ok(value)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        self.take(N)?
            .try_into()
            .map_err(|_| "native-authorization-package-invalid".into())
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_be_bytes(self.take_array()?))
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.take_array()?))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_be_bytes(self.take_array()?))
    }

    fn finish(self) -> Result<(), String> {
        if self.cursor != self.bytes.len() {
            return Err("native-authorization-package-trailing-bytes".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{authorization, protocol::RESUME_REQUIRED_CAPABILITIES};

    fn fixture() -> (PreparedReceiverBootstrap, AuthorizationMaterial) {
        authorization::clear_for_test();
        let bootstrap = prepare_receiver_bootstrap(Duration::from_secs(60)).unwrap();
        let material = authorization::create_registered_invitation(
            *Uuid::new_v4().as_bytes(),
            bootstrap.certificate_fingerprint_sha256,
            RESUME_REQUIRED_CAPABILITIES,
            60_000,
        )
        .unwrap();
        (bootstrap, material)
    }

    #[test]
    #[serial_test::serial(flowshare_authorization)]
    fn receiver_bootstrap_round_trip_binds_certificate() {
        let bootstrap = prepare_receiver_bootstrap(Duration::from_secs(60)).unwrap();
        assert_eq!(bootstrap.bootstrap_id[6] >> 4, 4);
        assert_eq!(bootstrap.bootstrap_id[8] & 0xc0, 0x80);
        let decoded = decode_receiver_bootstrap(&bootstrap.encoded_package, now_unix_ms()).unwrap();
        assert_eq!(decoded.bootstrap_id, bootstrap.bootstrap_id);
        assert_eq!(
            decoded.certificate_fingerprint_sha256,
            bootstrap.certificate_fingerprint_sha256
        );
    }

    #[test]
    #[serial_test::serial(flowshare_authorization)]
    fn manual_package_round_trip_is_bound_and_path_free() {
        let (bootstrap, material) = fixture();
        let (encoded, inspection) =
            export_manual_invitation_package(&material, Duration::from_secs(60)).unwrap();
        assert!(!encoded.contains('\\'));
        assert!(!encoded.contains('/'));
        assert!(!inspection.contains_path_or_filename);
        let decoded = decode_manual_invitation_package(
            &encoded,
            Some(bootstrap.certificate_fingerprint_sha256),
            now_unix_ms(),
        )
        .unwrap();
        assert_eq!(
            decoded.material.invitation.body.transfer_id,
            material.invitation.body.transfer_id
        );
        assert_eq!(decoded.material.master.expose(), material.master.expose());
    }

    #[test]
    #[serial_test::serial(flowshare_authorization)]
    fn manual_package_rejects_tamper_wrong_receiver_and_trailing_bytes() {
        let (bootstrap, material) = fixture();
        let (encoded, _) =
            export_manual_invitation_package(&material, Duration::from_secs(60)).unwrap();
        let mut bytes = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
        bytes[40] ^= 1;
        assert!(decode_manual_invitation_package(
            &URL_SAFE_NO_PAD.encode(&bytes),
            Some(bootstrap.certificate_fingerprint_sha256),
            now_unix_ms()
        )
        .is_err());
        assert!(decode_manual_invitation_package(&encoded, Some([9; 32]), now_unix_ms()).is_err());
        let mut trailing = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
        trailing.extend_from_slice(b"extra");
        assert!(decode_manual_invitation_package(
            &URL_SAFE_NO_PAD.encode(trailing),
            Some(bootstrap.certificate_fingerprint_sha256),
            now_unix_ms()
        )
        .is_err());
    }

    #[test]
    #[serial_test::serial(flowshare_authorization)]
    fn manual_package_rejects_expiration_and_oversize() {
        let (bootstrap, material) = fixture();
        let (encoded, _) =
            export_manual_invitation_package(&material, Duration::from_millis(1)).unwrap();
        assert!(decode_manual_invitation_package(
            &encoded,
            Some(bootstrap.certificate_fingerprint_sha256),
            now_unix_ms() + ALLOWED_CLOCK_SKEW_MS + 10
        )
        .is_err());
        assert!(decode_manual_invitation_package(
            &"a".repeat(MAX_INVITATION_PACKAGE_BYTES * 2 + 1),
            None,
            now_unix_ms()
        )
        .is_err());
    }
}
