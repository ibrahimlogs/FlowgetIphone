use crate::{
    device_protocol::{DEVICE_PROTOCOL_VERSION, LAN_SERVICE_TYPE},
    protocol::NATIVE_QUIC_PROTOCOL_VERSION,
    CORE_API_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct CoreContract {
    pub core_api_version: u16,
    pub native_quic_protocol_version: u16,
    pub device_protocol_version: u16,
    pub lan_service_type: String,
}

#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
pub fn flowshare_core_contract() -> CoreContract {
    CoreContract {
        core_api_version: CORE_API_VERSION,
        native_quic_protocol_version: NATIVE_QUIC_PROTOCOL_VERSION,
        device_protocol_version: DEVICE_PROTOCOL_VERSION,
        lan_service_type: LAN_SERVICE_TYPE.into(),
    }
}

#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
pub fn validate_completed_bitmap(bitmap: Vec<u8>, total_blocks: u64, block: u64) -> bool {
    crate::resume::bitmap_is_complete(&bitmap, total_blocks, block)
}
