//! Process-local ownership for platform file descriptors registered through UniFFI.
//!
//! Android detaches a duplicate `ParcelFileDescriptor` and transfers that duplicate
//! to this module. Rust owns and closes it. The original descriptor remains owned
//! by Kotlin. Tokens are process-local and never appear on the wire.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, LazyLock, Mutex, OnceLock},
};
#[cfg(unix)]
use uuid::Uuid;

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[derive(Debug)]
pub struct RegisteredSource {
    #[cfg(unix)]
    descriptor: OwnedFd,
    display_name: String,
}

impl RegisteredSource {
    #[cfg(unix)]
    pub fn io_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.descriptor.as_raw_fd()))
    }

    #[cfg(not(unix))]
    pub fn io_path(&self) -> PathBuf {
        PathBuf::new()
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

static SOURCES: LazyLock<Mutex<HashMap<String, Arc<RegisteredSource>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static STATE_ROOT: OnceLock<PathBuf> = OnceLock::new();

pub fn configure_state_root(path: String) -> Result<bool, String> {
    let requested = PathBuf::from(path);
    if !requested.is_absolute() {
        return Err("platform-state-root-invalid".into());
    }
    std::fs::create_dir_all(&requested).map_err(|_| "platform-state-root-unavailable")?;
    let canonical =
        std::fs::canonicalize(requested).map_err(|_| "platform-state-root-unavailable")?;
    if let Some(current) = STATE_ROOT.get() {
        return if current == &canonical {
            Ok(false)
        } else {
            Err("platform-state-root-already-configured".into())
        };
    }
    STATE_ROOT
        .set(canonical)
        .map(|_| true)
        .map_err(|_| "platform-state-root-already-configured".into())
}

pub fn state_root() -> Result<PathBuf, String> {
    if let Some(root) = STATE_ROOT.get() {
        return Ok(root.clone());
    }
    dirs::data_local_dir().ok_or_else(|| "platform-state-root-unavailable".into())
}

/// Takes ownership of an already-duplicated descriptor and returns an opaque token.
#[cfg(unix)]
pub fn register_owned_source_descriptor(
    descriptor: i32,
    display_name: String,
) -> Result<String, String> {
    if descriptor < 0 {
        return Err("platform-source-descriptor-invalid".into());
    }
    let display_name = validate_display_name(display_name)?;
    // SAF contract: Kotlin called `detachFd`, transferring exclusive ownership
    // of this duplicate to Rust. `OwnedFd` closes it exactly once.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let source = Arc::new(RegisteredSource {
        descriptor,
        display_name,
    });
    let metadata = std::fs::metadata(source.io_path())
        .map_err(|_| "platform-source-descriptor-unavailable")?;
    if !metadata.is_file() {
        return Err("platform-source-descriptor-unavailable".into());
    }
    let token = format!("android-fd:{}", Uuid::new_v4());
    SOURCES
        .lock()
        .map_err(|_| "platform-source-registry-unavailable")?
        .insert(token.clone(), source);
    Ok(token)
}

#[cfg(not(unix))]
pub fn register_owned_source_descriptor(
    _descriptor: i32,
    _display_name: String,
) -> Result<String, String> {
    Err("platform-source-descriptor-unsupported".into())
}

pub fn resolve_registered_source(token: &str) -> Result<Arc<RegisteredSource>, String> {
    if !token.starts_with("android-fd:") {
        return Err("platform-source-token-invalid".into());
    }
    SOURCES
        .lock()
        .map_err(|_| "platform-source-registry-unavailable")?
        .get(token)
        .cloned()
        .ok_or_else(|| "platform-source-descriptor-unavailable".into())
}

pub fn release_source_descriptor(token: &str) -> Result<bool, String> {
    Ok(SOURCES
        .lock()
        .map_err(|_| "platform-source-registry-unavailable")?
        .remove(token)
        .is_some())
}

pub fn is_registered_source_token(value: &str) -> bool {
    value.starts_with("android-fd:")
}

#[cfg_attr(not(unix), allow(dead_code))]
fn validate_display_name(value: String) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 255
        || value == "."
        || value == ".."
        || value.contains(['/', '\\'])
        || value.chars().any(char::is_control)
    {
        return Err("platform-source-display-name-invalid".into());
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::validate_display_name;

    #[test]
    fn display_name_rejects_paths_and_control_characters() {
        assert!(validate_display_name("movie.webm".into()).is_ok());
        for invalid in ["../movie", "folder/movie", "folder\\movie", "bad\nname", ""] {
            assert!(validate_display_name(invalid.into()).is_err());
        }
    }
}
