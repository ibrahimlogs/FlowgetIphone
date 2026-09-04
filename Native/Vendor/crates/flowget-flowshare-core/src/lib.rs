//! Authoritative, platform-neutral FlowShare engine foundation.
//!
//! Wire protocol v3 is frozen. UI, Tauri, WebView, Windows credential APIs,
//! Android framework APIs, and platform path policy belong in adapters.

pub mod adapters;
pub mod authorization;
pub mod authorization_delivery;
pub mod block_hash;
pub mod candidates;
pub mod config;
pub mod connectivity;
pub mod connectivity_diagnostics;
pub mod cross_device;
pub mod cross_platform;
pub mod device_protocol;
pub mod engine;
pub mod ffi;
pub mod file_transfer;
pub mod hole_punch;
pub mod lifecycle;
pub mod metrics;
pub mod path_selection;
pub mod platform_handles;
pub mod port_mapping;
pub mod protocol;
pub mod quinn_connectivity;
pub mod resume;
pub mod resume_transfer;
pub mod secret_store;
pub mod secure_protocol;
pub mod secure_transport;
pub mod security;
pub mod signaling;
pub mod signaling_websocket;
pub mod split_resume;
pub mod split_transfer;
pub mod stun;
pub mod transfer_registry;

pub const CORE_API_VERSION: u16 = 1;

/// Installs the process-wide rustls provider used by QUIC and WSS signaling.
pub fn install_rustls_crypto_provider() -> Result<(), String> {
    use rustls::crypto::CryptoProvider;

    if CryptoProvider::get_default().is_some() {
        return Ok(());
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    CryptoProvider::get_default()
        .is_some()
        .then_some(())
        .ok_or_else(|| "native-tls-crypto-provider-unavailable".into())
}

#[cfg(feature = "uniffi-bindings")]
uniffi::setup_scaffolding!();
