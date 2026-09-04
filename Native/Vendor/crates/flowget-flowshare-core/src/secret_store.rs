use super::{
    authorization::AuthorizationMaterial,
    secure_protocol::{now_unix_ms, SecureInvitation, TransferMasterSecret},
};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
};
use zeroize::Zeroizing;

const PROTECTED_MAGIC: [u8; 8] = *b"FQDPA003";
const PLAINTEXT_MAGIC: [u8; 8] = *b"FQSEC003";
const SECRET_FORMAT_VERSION: u16 = 3;
const MAX_SECRET_RECORD_BYTES: usize = 64 * 1024;
const TRANSFER_SECRET_LIFETIME_MS: u64 = 30 * 24 * 60 * 60 * 1000;

#[derive(Debug, Clone)]
pub struct LoadedSecret {
    pub material: AuthorizationMaterial,
    pub created_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub secret_version: u16,
}

/// Platform-owned encryption boundary for resumable-transfer authorization secrets.
///
/// Implementations must use OS-backed secure storage (DPAPI on Windows, Android
/// Keystore on Android). File payload bytes never cross this interface.
pub trait SecretProtector: Send + Sync {
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, String>;
    fn unprotect(&self, protected: &[u8]) -> Result<Vec<u8>, String>;
}

static SECRET_PROTECTOR: OnceLock<Arc<dyn SecretProtector>> = OnceLock::new();

/// Installs the process-wide platform protector. The first installation wins so
/// active transfers cannot have their protection domain swapped underneath them.
pub fn install_secret_protector(protector: Arc<dyn SecretProtector>) -> bool {
    SECRET_PROTECTOR.set(protector).is_ok()
}

fn protect_secret(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    if let Some(protector) = SECRET_PROTECTOR.get() {
        return protector
            .protect(plaintext)
            .map_err(|_| "protected-secret-write-failed".into());
    }
    #[cfg(test)]
    {
        let mut output = b"INSECURE-TEST-ONLY\0".to_vec();
        output.extend(plaintext.iter().map(|byte| byte ^ 0xa5));
        return Ok(output);
    }
    #[cfg(not(test))]
    Err("os-protected-secret-store-unavailable".into())
}

fn unprotect_secret(protected: &[u8]) -> Result<Vec<u8>, String> {
    if let Some(protector) = SECRET_PROTECTOR.get() {
        return protector
            .unprotect(protected)
            .map_err(|_| "protected-secret-unavailable".into());
    }
    #[cfg(test)]
    {
        return protected
            .strip_prefix(b"INSECURE-TEST-ONLY\0")
            .map(|ciphertext| ciphertext.iter().map(|byte| byte ^ 0xa5).collect())
            .ok_or_else(|| "protected-secret-unavailable".into());
    }
    #[cfg(not(test))]
    Err("os-protected-secret-store-unavailable".into())
}

pub fn secret_path(resume_path: &Path) -> PathBuf {
    super::resume::generation_paths(resume_path)
        .current
        .with_extension("secret.dpapi")
}

fn encode_plaintext(
    material: &AuthorizationMaterial,
    created_unix_ms: u64,
    expires_unix_ms: u64,
) -> Result<Vec<u8>, String> {
    let invitation = material.invitation.encode();
    let invitation_length: u32 = invitation
        .len()
        .try_into()
        .map_err(|_| "protected-secret-write-failed")?;
    let mut output = Vec::with_capacity(8 + 2 + 16 + 16 + 8 + 8 + 4 + invitation.len() + 32 + 32);
    output.extend_from_slice(&PLAINTEXT_MAGIC);
    output.extend_from_slice(&SECRET_FORMAT_VERSION.to_be_bytes());
    output.extend_from_slice(&material.invitation.body.transfer_id);
    output.extend_from_slice(&material.invitation.body.invitation_id);
    output.extend_from_slice(&created_unix_ms.to_be_bytes());
    output.extend_from_slice(&expires_unix_ms.to_be_bytes());
    output.extend_from_slice(&invitation_length.to_be_bytes());
    output.extend_from_slice(&invitation);
    output.extend_from_slice(material.master.expose());
    let checksum = Sha256::digest(&output);
    output.extend_from_slice(&checksum);
    Ok(output)
}

fn decode_plaintext(input: &[u8]) -> Result<LoadedSecret, String> {
    if input.len() < 8 + 2 + 16 + 16 + 8 + 8 + 4 + 32 + 32 || input.len() > MAX_SECRET_RECORD_BYTES
    {
        return Err("protected-secret-invalid".into());
    }
    let (authenticated, checksum) = input.split_at(input.len() - 32);
    if Sha256::digest(authenticated).as_slice() != checksum {
        return Err("protected-secret-invalid".into());
    }
    let mut cursor = 0usize;
    let mut take = |length: usize| -> Result<&[u8], String> {
        let end = cursor
            .checked_add(length)
            .ok_or("protected-secret-invalid")?;
        if end > authenticated.len() {
            return Err("protected-secret-invalid".into());
        }
        let value = &authenticated[cursor..end];
        cursor = end;
        Ok(value)
    };
    if take(8)? != PLAINTEXT_MAGIC {
        return Err("protected-secret-invalid".into());
    }
    let version = u16::from_be_bytes(take(2)?.try_into().unwrap());
    if version != SECRET_FORMAT_VERSION {
        return Err("protected-secret-version-unsupported".into());
    }
    let transfer_id: [u8; 16] = take(16)?.try_into().unwrap();
    let invitation_id: [u8; 16] = take(16)?.try_into().unwrap();
    let created_unix_ms = u64::from_be_bytes(take(8)?.try_into().unwrap());
    let expires_unix_ms = u64::from_be_bytes(take(8)?.try_into().unwrap());
    let invitation_length = u32::from_be_bytes(take(4)?.try_into().unwrap()) as usize;
    let invitation = SecureInvitation::decode(take(invitation_length)?)?;
    let master = TransferMasterSecret::from_bytes(take(32)?.try_into().unwrap());
    if cursor != authenticated.len()
        || invitation.body.transfer_id != transfer_id
        || invitation.body.invitation_id != invitation_id
        || expires_unix_ms <= created_unix_ms
    {
        return Err("protected-secret-invalid".into());
    }
    if now_unix_ms() > expires_unix_ms {
        return Err("protected-secret-expired".into());
    }
    invitation.verify_proof(&master)?;
    Ok(LoadedSecret {
        material: AuthorizationMaterial { invitation, master },
        created_unix_ms,
        expires_unix_ms,
        secret_version: version,
    })
}

fn encode_protected(protected: &[u8]) -> Result<Vec<u8>, String> {
    let length: u32 = protected
        .len()
        .try_into()
        .map_err(|_| "protected-secret-write-failed")?;
    let mut output = Vec::with_capacity(8 + 4 + protected.len() + 32);
    output.extend_from_slice(&PROTECTED_MAGIC);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(protected);
    let checksum = Sha256::digest(&output);
    output.extend_from_slice(&checksum);
    Ok(output)
}

fn decode_protected(input: &[u8]) -> Result<&[u8], String> {
    if input.len() < 44 || input.len() > MAX_SECRET_RECORD_BYTES || input[..8] != PROTECTED_MAGIC {
        return Err("protected-secret-invalid".into());
    }
    let length = u32::from_be_bytes(input[8..12].try_into().unwrap()) as usize;
    let end = 12usize
        .checked_add(length)
        .ok_or("protected-secret-invalid")?;
    if end.checked_add(32) != Some(input.len())
        || Sha256::digest(&input[..end]).as_slice() != &input[end..]
    {
        return Err("protected-secret-invalid".into());
    }
    Ok(&input[12..end])
}

pub async fn store(
    resume_path: &Path,
    material: &AuthorizationMaterial,
) -> Result<PathBuf, String> {
    let path = secret_path(resume_path);
    super::cross_device::reject_reparse_if_present(&path).await?;
    if let Ok(existing) = load(resume_path).await {
        if existing.material.invitation.body.transfer_id == material.invitation.body.transfer_id
            && existing.material.invitation.body.invitation_id
                == material.invitation.body.invitation_id
        {
            return Ok(path);
        }
        return Err("protected-secret-conflict".into());
    }
    let parent = path.parent().ok_or("protected-secret-write-failed")?;
    fs::create_dir_all(parent)
        .await
        .map_err(|_| "protected-secret-write-failed")?;
    let created = now_unix_ms();
    let expires = created
        .checked_add(TRANSFER_SECRET_LIFETIME_MS)
        .ok_or("protected-secret-write-failed")?;
    let plaintext = Zeroizing::new(encode_plaintext(material, created, expires)?);
    let protected = protect_secret(&plaintext)?;
    let encoded = encode_protected(&protected)?;
    let pending = path.with_extension("secret.dpapi.pending");
    super::cross_device::reject_reparse_if_present(&pending).await?;
    let _ = fs::remove_file(&pending).await;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&pending)
        .await
        .map_err(|_| "protected-secret-write-failed")?;
    file.write_all(&encoded)
        .await
        .map_err(|_| "protected-secret-write-failed")?;
    file.sync_all()
        .await
        .map_err(|_| "protected-secret-write-failed")?;
    drop(file);
    if fs::try_exists(&path)
        .await
        .map_err(|_| "protected-secret-write-failed")?
    {
        fs::remove_file(&path)
            .await
            .map_err(|_| "protected-secret-write-failed")?;
    }
    fs::rename(&pending, &path)
        .await
        .map_err(|_| "protected-secret-write-failed")?;
    let loaded = load(resume_path).await?;
    if loaded.material.invitation.body.invitation_id != material.invitation.body.invitation_id {
        return Err("protected-secret-write-failed".into());
    }
    Ok(path)
}

pub async fn load(resume_path: &Path) -> Result<LoadedSecret, String> {
    let path = secret_path(resume_path);
    super::cross_device::reject_reparse_if_present(&path).await?;
    let bytes = fs::read(path).await.map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            "protected-secret-unavailable".to_string()
        } else {
            "protected-secret-read-failed".to_string()
        }
    })?;
    let protected = decode_protected(&bytes)?;
    let plaintext = Zeroizing::new(unprotect_secret(protected)?);
    decode_plaintext(&plaintext)
}

pub async fn load_and_restore(
    resume_path: &Path,
    expected_transfer_id: &[u8; 16],
) -> Result<LoadedSecret, String> {
    let loaded = load(resume_path).await?;
    if &loaded.material.invitation.body.transfer_id != expected_transfer_id {
        return Err("protected-secret-transfer-mismatch".into());
    }
    super::authorization::restore_persisted(loaded.material.clone())?;
    Ok(loaded)
}

pub async fn delete(resume_path: &Path) -> Result<bool, String> {
    let path = secret_path(resume_path);
    let pending = path.with_extension("secret.dpapi.pending");
    super::cross_device::reject_reparse_if_present(&path).await?;
    super::cross_device::reject_reparse_if_present(&pending).await?;
    let _ = fs::remove_file(pending).await;
    match fs::remove_file(path).await {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err("protected-secret-cleanup-failed".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::{clear_for_test, create_registered_invitation};
    use uuid::Uuid;

    #[tokio::test]
    async fn protected_store_round_trip_and_corruption_rejection() {
        clear_for_test();
        let root = std::env::temp_dir().join(format!("flowget-secret-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).await.unwrap();
        let resume = root.join("transfer.resume.current");
        let transfer = *Uuid::new_v4().as_bytes();
        let material = create_registered_invitation(transfer, [2; 32], 7, 60_000).unwrap();
        store(&resume, &material).await.unwrap();
        let path = secret_path(&resume);
        let bytes = fs::read(&path).await.unwrap();
        assert!(!bytes
            .windows(32)
            .any(|window| window == material.master.expose()));
        let loaded = load_and_restore(&resume, &transfer).await.unwrap();
        assert_eq!(
            loaded.material.invitation.body.invitation_id,
            material.invitation.body.invitation_id
        );
        let mut corrupt = bytes;
        corrupt[16] ^= 1;
        fs::write(&path, corrupt).await.unwrap();
        assert_eq!(load(&resume).await.unwrap_err(), "protected-secret-invalid");
        let _ = fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn deleted_secret_is_explicitly_unavailable() {
        let root = std::env::temp_dir().join(format!("flowget-secret-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).await.unwrap();
        let resume = root.join("transfer.resume.current");
        assert_eq!(
            load(&resume).await.unwrap_err(),
            "protected-secret-unavailable"
        );
        let _ = fs::remove_dir_all(root).await;
    }
}
