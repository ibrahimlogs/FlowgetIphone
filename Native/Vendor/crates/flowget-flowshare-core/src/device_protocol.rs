use serde::{Deserialize, Serialize};

pub const DEVICE_PROTOCOL_VERSION: u16 = 1;
pub const DEVICE_SESSION_MAX_LIFETIME_SECONDS: u64 = 30 * 24 * 60 * 60;
pub const DEVICE_PRESENCE_HEARTBEAT_SECONDS: u64 = 25;
pub const DEVICE_OFFLINE_COMMAND_TTL_SECONDS: u64 = 24 * 60 * 60;
pub const MAX_DEVICE_COMMAND_BYTES: usize = 16 * 1024;
pub const MAX_DEVICE_FILE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const LAN_SERVICE_TYPE: &str = "_flowget._udp.local.";
pub const LAN_TXT_VERSION_KEY: &str = "v";
pub const LAN_TXT_DEVICE_KEY: &str = "device";
pub const LAN_TXT_PLATFORM_KEY: &str = "platform";
pub const LAN_TXT_CAPABILITY_KEY: &str = "caps";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
pub enum DevicePlatform {
    Windows,
    Macos,
    Android,
    Ios,
    Unknown,
}

impl DevicePlatform {
    pub fn entitlement_audience(self) -> Option<&'static str> {
        match self {
            Self::Windows | Self::Macos => Some("flowget-desktop"),
            Self::Android => Some("flowget-android"),
            Self::Ios | Self::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceCapabilities {
    pub send_file: bool,
    pub receive_file: bool,
    pub receive_url: bool,
    pub lan_direct: bool,
    pub global_direct: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DevicePresence {
    pub device_id: String,
    pub display_name: String,
    pub platform: DevicePlatform,
    pub capabilities: DeviceCapabilities,
    pub online: bool,
    pub last_seen_unix_ms: u64,
    pub receiver_bootstrap: Option<DeviceReceiverBootstrap>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceReceiverBootstrap {
    pub receiver_bootstrap_id: String,
    pub receiver_bootstrap_package: String,
    pub expires_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum DeviceCommandPayload {
    SendUrl {
        url: String,
    },
    SendFile {
        native_transfer_id: String,
        invitation_package: String,
        file_name: String,
        file_size: u64,
        file_sha256: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceCommand {
    pub protocol_version: u16,
    pub command_id: String,
    pub source_device_id: String,
    pub target_device_id: String,
    pub created_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub payload: DeviceCommandPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceCommandAck {
    pub command_id: String,
    pub target_device_id: String,
    pub status: DeviceCommandStatus,
    pub detail_code: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceCommandStatus {
    Accepted,
    Rejected,
    Completed,
    Failed,
    Duplicate,
    Expired,
}
