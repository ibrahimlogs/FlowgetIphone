use super::candidates::{foundation, NativeAddressFamily, NativeCandidate, NativeCandidateType};
use crab_nat::{InternetProtocol, PortMapping, PortMappingOptions, PortMappingType, TimeoutConfig};
use igd_next::{PortMappingProtocol, SearchOptions};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU16,
    sync::Arc,
    time::Duration,
};
use tokio::{sync::Mutex, task::JoinHandle};
use tokio_util::sync::CancellationToken;

const DEFAULT_MAPPING_LEASE_SECONDS: u32 = 120;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum NativePortMappingProtocol {
    UpnpIgd,
    Pcp,
    NatPmp,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortMappingAttemptDiagnostic {
    pub protocol: NativePortMappingProtocol,
    pub internal_endpoint: String,
    pub external_endpoint: Option<String>,
    pub lease_duration_seconds: u32,
    pub created: bool,
    pub renewal_status: String,
    pub removal_result: Option<String>,
    pub error: Option<String>,
}

pub struct ActivePortMapping {
    pub candidate: NativeCandidate,
    pub diagnostic: Arc<Mutex<PortMappingAttemptDiagnostic>>,
    cancellation: CancellationToken,
    task: JoinHandle<()>,
}

impl std::fmt::Debug for ActivePortMapping {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActivePortMapping")
            .field("candidate", &self.candidate)
            .field("task", &"active")
            .finish()
    }
}

impl ActivePortMapping {
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    pub async fn diagnostic_snapshot(&self) -> PortMappingAttemptDiagnostic {
        self.diagnostic.lock().await.clone()
    }

    pub async fn shutdown(mut self) -> PortMappingAttemptDiagnostic {
        self.cancellation.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(3), &mut self.task).await;
        self.diagnostic.lock().await.clone()
    }
}

impl Drop for ActivePortMapping {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortMappingDevelopmentOptions {
    pub enabled: bool,
    pub protocols: Option<Vec<NativePortMappingProtocol>>,
    pub lease_duration_seconds: Option<u32>,
}

impl Default for PortMappingDevelopmentOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            protocols: None,
            lease_duration_seconds: None,
        }
    }
}

#[derive(Debug)]
pub struct PortMappingStartResult {
    pub attempts: Vec<PortMappingAttemptDiagnostic>,
    pub active: Option<ActivePortMapping>,
}

pub async fn start_optional_port_mapping(
    internal_port: u16,
    generation: u32,
    expires_unix_ms: u64,
    options: &PortMappingDevelopmentOptions,
    parent_cancellation: &CancellationToken,
) -> Result<PortMappingStartResult, String> {
    if !options.enabled {
        return Ok(PortMappingStartResult {
            attempts: Vec::new(),
            active: None,
        });
    }
    if !cfg!(debug_assertions) {
        return Err("native-port-mapping-development-only".into());
    }
    let internal_port = NonZeroU16::new(internal_port).ok_or("native-port-mapping-port-invalid")?;
    let lease_seconds = options
        .lease_duration_seconds
        .unwrap_or(DEFAULT_MAPPING_LEASE_SECONDS)
        .clamp(60, 600);
    let protocols = options.protocols.clone().unwrap_or_else(|| {
        vec![
            NativePortMappingProtocol::UpnpIgd,
            NativePortMappingProtocol::Pcp,
            NativePortMappingProtocol::NatPmp,
        ]
    });
    if protocols.len() > 3 {
        return Err("native-port-mapping-protocol-set-invalid".into());
    }
    let (gateway, client) = mapping_route()?;
    let internal_endpoint = SocketAddr::new(client, internal_port.get());
    let mut attempts = Vec::new();
    for protocol in protocols {
        if parent_cancellation.is_cancelled() {
            return Err("native-connectivity-cancelled".into());
        }
        let result = match protocol {
            NativePortMappingProtocol::UpnpIgd => {
                start_upnp_mapping(
                    internal_endpoint,
                    generation,
                    expires_unix_ms,
                    lease_seconds,
                    parent_cancellation,
                )
                .await
            }
            NativePortMappingProtocol::Pcp => {
                start_crab_mapping(
                    gateway,
                    client,
                    internal_port,
                    generation,
                    expires_unix_ms,
                    lease_seconds,
                    false,
                    parent_cancellation,
                )
                .await
            }
            NativePortMappingProtocol::NatPmp => {
                start_crab_mapping(
                    gateway,
                    client,
                    internal_port,
                    generation,
                    expires_unix_ms,
                    lease_seconds,
                    true,
                    parent_cancellation,
                )
                .await
            }
        };
        match result {
            Ok(active) => {
                attempts.push(active.diagnostic_snapshot().await);
                return Ok(PortMappingStartResult {
                    attempts,
                    active: Some(active),
                });
            }
            Err(error) => attempts.push(PortMappingAttemptDiagnostic {
                protocol,
                internal_endpoint: internal_endpoint.to_string(),
                external_endpoint: None,
                lease_duration_seconds: lease_seconds,
                created: false,
                renewal_status: "not-created".into(),
                removal_result: None,
                error: Some(error),
            }),
        }
    }
    Ok(PortMappingStartResult {
        attempts,
        active: None,
    })
}

async fn start_upnp_mapping(
    internal_endpoint: SocketAddr,
    generation: u32,
    expires_unix_ms: u64,
    lease_seconds: u32,
    parent_cancellation: &CancellationToken,
) -> Result<ActivePortMapping, String> {
    let search = SearchOptions {
        bind_addr: SocketAddr::new(internal_endpoint.ip(), 0),
        timeout: Some(Duration::from_secs(3)),
        single_search_timeout: Some(Duration::from_secs(2)),
        ..Default::default()
    };
    let gateway = tokio::select! {
        _ = parent_cancellation.cancelled() => return Err("native-connectivity-cancelled".into()),
        result = igd_next::aio::tokio::search_gateway(search) => {
            result.map_err(|error| format!("native-upnp-gateway-not-found: {error}"))?
        }
    };
    let external_ip = gateway
        .get_external_ip()
        .await
        .map_err(|error| format!("native-upnp-external-address-failed: {error}"))?;
    let external_port = gateway
        .add_any_port(
            PortMappingProtocol::UDP,
            internal_endpoint,
            lease_seconds,
            "FlowShare native development session",
        )
        .await
        .map_err(|error| format!("native-upnp-mapping-failed: {error}"))?;
    let external_endpoint = SocketAddr::new(external_ip, external_port);
    let diagnostic = Arc::new(Mutex::new(PortMappingAttemptDiagnostic {
        protocol: NativePortMappingProtocol::UpnpIgd,
        internal_endpoint: internal_endpoint.to_string(),
        external_endpoint: Some(external_endpoint.to_string()),
        lease_duration_seconds: lease_seconds,
        created: true,
        renewal_status: "active".into(),
        removal_result: None,
        error: None,
    }));
    let cancellation = parent_cancellation.child_token();
    let task_cancellation = cancellation.clone();
    let task_diagnostic = diagnostic.clone();
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = task_cancellation.cancelled() => {
                    let result = gateway
                        .remove_port(PortMappingProtocol::UDP, external_port)
                        .await;
                    let mut diagnostic = task_diagnostic.lock().await;
                    diagnostic.removal_result = Some(match result {
                        Ok(()) => "removed".into(),
                        Err(error) => format!("removal-unconfirmed: {error}"),
                    });
                    diagnostic.renewal_status = "stopped".into();
                    break;
                }
                _ = tokio::time::sleep(Duration::from_secs((lease_seconds / 2).max(30) as u64)) => {
                    let result = gateway
                        .add_port(
                            PortMappingProtocol::UDP,
                            external_port,
                            internal_endpoint,
                            lease_seconds,
                            "FlowShare native development session",
                        )
                        .await;
                    let mut diagnostic = task_diagnostic.lock().await;
                    match result {
                        Ok(()) => diagnostic.renewal_status = "renewed".into(),
                        Err(error) => {
                            diagnostic.renewal_status = "renewal-failed".into();
                            diagnostic.error = Some(error.to_string());
                            break;
                        }
                    }
                }
            }
        }
    });
    let network_identifier = "upnp-igd".to_string();
    let candidate = NativeCandidate::new(
        NativeCandidateType::Mapped,
        external_ip,
        external_port,
        network_identifier.clone(),
        350_000,
        foundation(
            NativeCandidateType::Mapped,
            &network_identifier,
            NativeAddressFamily::for_ip(external_ip),
        ),
        Some(internal_endpoint),
        generation,
        expires_unix_ms,
    )?;
    Ok(ActivePortMapping {
        candidate,
        diagnostic,
        cancellation,
        task,
    })
}

#[allow(clippy::too_many_arguments)]
async fn start_crab_mapping(
    gateway: IpAddr,
    client: IpAddr,
    internal_port: NonZeroU16,
    generation: u32,
    expires_unix_ms: u64,
    lease_seconds: u32,
    nat_pmp_only: bool,
    parent_cancellation: &CancellationToken,
) -> Result<ActivePortMapping, String> {
    let timeout = TimeoutConfig {
        initial_timeout: Duration::from_millis(400),
        max_retries: 2,
        max_retry_timeout: Some(Duration::from_secs(2)),
    };
    let options = PortMappingOptions {
        external_port: Some(internal_port),
        lifetime_seconds: Some(lease_seconds),
        timeout_config: Some(timeout),
    };
    let mut mapping = if nat_pmp_only {
        crab_nat::natpmp::port_mapping(gateway, InternetProtocol::Udp, internal_port, options)
            .await
            .map_err(|error| format!("native-nat-pmp-mapping-failed: {error}"))?
    } else {
        let mapping = PortMapping::new(
            gateway,
            client,
            InternetProtocol::Udp,
            internal_port,
            options,
        )
        .await
        .map_err(|error| format!("native-pcp-mapping-failed: {error}"))?;
        if !matches!(mapping.mapping_type(), PortMappingType::Pcp { .. }) {
            let _ = mapping.try_drop().await;
            return Err("native-pcp-unavailable".into());
        }
        mapping
    };
    let protocol = match mapping.mapping_type() {
        PortMappingType::Pcp { .. } => NativePortMappingProtocol::Pcp,
        PortMappingType::NatPmp => NativePortMappingProtocol::NatPmp,
    };
    let external_ip = match mapping.mapping_type() {
        PortMappingType::Pcp { external_ip, .. } => external_ip,
        PortMappingType::NatPmp => IpAddr::V4(
            crab_nat::natpmp::external_address(gateway, Some(timeout))
                .await
                .map_err(|error| format!("native-nat-pmp-external-address-failed: {error}"))?,
        ),
    };
    let external_port = mapping.external_port().get();
    let internal_endpoint = SocketAddr::new(client, internal_port.get());
    let external_endpoint = SocketAddr::new(external_ip, external_port);
    let diagnostic = Arc::new(Mutex::new(PortMappingAttemptDiagnostic {
        protocol,
        internal_endpoint: internal_endpoint.to_string(),
        external_endpoint: Some(external_endpoint.to_string()),
        lease_duration_seconds: mapping.lifetime(),
        created: true,
        renewal_status: "active".into(),
        removal_result: None,
        error: None,
    }));
    let cancellation = parent_cancellation.child_token();
    let task_cancellation = cancellation.clone();
    let task_diagnostic = diagnostic.clone();
    let task = tokio::spawn(async move {
        loop {
            let renew_after = Duration::from_secs((mapping.lifetime().max(60) / 2) as u64);
            tokio::select! {
                _ = task_cancellation.cancelled() => {
                    let result = mapping.try_drop().await;
                    let mut diagnostic = task_diagnostic.lock().await;
                    diagnostic.removal_result = Some(match result {
                        Ok(()) => "removed".into(),
                        Err((error, _mapping)) => format!("removal-unconfirmed: {error}"),
                    });
                    diagnostic.renewal_status = "stopped".into();
                    break;
                }
                _ = tokio::time::sleep(renew_after) => {
                    let result = mapping.renew().await;
                    let mut diagnostic = task_diagnostic.lock().await;
                    match result {
                        Ok(()) => diagnostic.renewal_status = "renewed".into(),
                        Err(error) => {
                            diagnostic.renewal_status = "renewal-failed".into();
                            diagnostic.error = Some(error.to_string());
                            break;
                        }
                    }
                }
            }
        }
    });
    let network_identifier = match protocol {
        NativePortMappingProtocol::Pcp => "pcp",
        NativePortMappingProtocol::NatPmp => "nat-pmp",
        NativePortMappingProtocol::UpnpIgd => unreachable!(),
    }
    .to_string();
    let candidate = NativeCandidate::new(
        NativeCandidateType::Mapped,
        external_ip,
        external_port,
        network_identifier.clone(),
        350_000,
        foundation(
            NativeCandidateType::Mapped,
            &network_identifier,
            NativeAddressFamily::Ipv4,
        ),
        Some(internal_endpoint),
        generation,
        expires_unix_ms,
    )?;
    Ok(ActivePortMapping {
        candidate,
        diagnostic,
        cancellation,
        task,
    })
}

fn mapping_route() -> Result<(IpAddr, IpAddr), String> {
    let interface = netdev::interface::get_default_interface()
        .map_err(|_| "native-port-mapping-default-route-unavailable")?;
    let client = interface
        .ipv4_addrs()
        .into_iter()
        .find(|address| !address.is_loopback() && !address.is_unspecified())
        .map(IpAddr::V4)
        .ok_or("native-port-mapping-client-address-unavailable")?;
    let gateway = interface
        .gateway
        .and_then(|gateway| gateway.ipv4.into_iter().next())
        .map(IpAddr::V4)
        .ok_or("native-port-mapping-gateway-unavailable")?;
    Ok((gateway, client))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mapping_is_disabled_by_default_without_network_access() {
        let result = start_optional_port_mapping(
            45000,
            1,
            u64::MAX - 31_000,
            &PortMappingDevelopmentOptions::default(),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(result.attempts.is_empty());
        assert!(result.active.is_none());
    }
}
