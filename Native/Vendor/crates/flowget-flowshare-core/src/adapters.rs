use crate::{device_protocol::DevicePlatform, lifecycle::TransferState};
use std::{future::Future, pin::Pin};

pub type AdapterFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMetadata {
    pub size: u64,
    pub modified_unix_ms: Option<u64>,
    pub stable_identity: Option<Vec<u8>>,
}

/// Platform path/URI access. Android implementations may use ContentResolver;
/// Desktop implementations may use ordinary filesystem handles.
pub trait PlatformFileAccess: Send + Sync {
    fn metadata<'a>(&'a self, handle: &'a str) -> AdapterFuture<'a, Result<FileMetadata, String>>;
    fn read_range<'a>(
        &'a self,
        handle: &'a str,
        offset: u64,
        length: usize,
    ) -> AdapterFuture<'a, Result<Vec<u8>, String>>;
    fn write_range<'a>(
        &'a self,
        handle: &'a str,
        offset: u64,
        bytes: &'a [u8],
    ) -> AdapterFuture<'a, Result<(), String>>;
    fn sync<'a>(&'a self, handle: &'a str) -> AdapterFuture<'a, Result<(), String>>;
}

pub trait SecureStorage: Send + Sync {
    fn store<'a>(&'a self, key: &'a str, secret: &'a [u8])
        -> AdapterFuture<'a, Result<(), String>>;
    fn load<'a>(&'a self, key: &'a str) -> AdapterFuture<'a, Result<Option<Vec<u8>>, String>>;
    fn delete<'a>(&'a self, key: &'a str) -> AdapterFuture<'a, Result<(), String>>;
}

pub trait NetworkReachability: Send + Sync {
    fn is_network_available(&self) -> bool;
    fn is_metered(&self) -> Option<bool>;
}

pub trait SignalingTransport: Send + Sync {
    fn send<'a>(&'a self, message: &'a [u8]) -> AdapterFuture<'a, Result<(), String>>;
    fn receive<'a>(&'a self) -> AdapterFuture<'a, Result<Vec<u8>, String>>;
}

pub trait DeviceIdentityProvider: Send + Sync {
    fn stable_device_id(&self) -> Result<String, String>;
    fn display_name(&self) -> Result<String, String>;
    fn platform(&self) -> DevicePlatform;
}

pub trait LifecycleEventSink: Send + Sync {
    fn state_changed(&self, transfer_id: &str, state: TransferState);
    fn progress(&self, transfer_id: &str, completed_bytes: u64, total_bytes: u64);
    fn security_event(&self, transfer_id: &str, code: &str);
}

pub trait ConnectivityAdapter: Send + Sync {
    fn bind_udp<'a>(
        &'a self,
        preferred_port: Option<u16>,
    ) -> AdapterFuture<'a, Result<String, String>>;
    fn local_addresses<'a>(&'a self) -> AdapterFuture<'a, Result<Vec<String>, String>>;
}
