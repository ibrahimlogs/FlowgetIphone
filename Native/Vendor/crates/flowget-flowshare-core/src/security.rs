use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};

pub struct EphemeralIdentity {
    pub certificate: CertificateDer<'static>,
    pub private_key: PrivatePkcs8KeyDer<'static>,
    pub fingerprint_sha256: String,
    pub fingerprint_sha256_bytes: [u8; 32],
}

pub fn create_ephemeral_identity() -> Result<EphemeralIdentity, String> {
    let certified = generate_simple_self_signed(vec!["flowshare-native.local".into()])
        .map_err(|e| e.to_string())?;
    let certificate = certified.cert.der().clone();
    let private_key = PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());
    let fingerprint_sha256_bytes: [u8; 32] = Sha256::digest(certificate.as_ref()).into();
    let fingerprint_sha256 = fingerprint_sha256_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(EphemeralIdentity {
        certificate,
        private_key,
        fingerprint_sha256,
        fingerprint_sha256_bytes,
    })
}

pub fn peer_certificate_fingerprint(connection: &quinn::Connection) -> Result<[u8; 32], String> {
    let identity = connection
        .peer_identity()
        .ok_or("certificate-binding-failed")?;
    let certificates = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| "certificate-binding-failed")?;
    let certificate = certificates.first().ok_or("certificate-binding-failed")?;
    Ok(Sha256::digest(certificate.as_ref()).into())
}
