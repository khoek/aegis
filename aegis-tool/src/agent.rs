#[cfg(target_os = "linux")]
use crate::config::AgentBirdConfig;
#[cfg(target_os = "linux")]
use aegis_dto::protocol::{AegisNetworkMemberInternalAddresses, AegisNetworkWireGuardConfig};
#[cfg(any(target_os = "macos", test))]
mod babel;
#[cfg(all(test, target_os = "linux"))]
mod egress_kernel_tests;
#[cfg(target_os = "macos")]
pub(crate) mod macos;
mod tunnel;
#[cfg(any(target_os = "macos", test))]
mod vxlan;

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::CStr,
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU16,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use aegis_dto::{
    AegisHostMode, DEFAULT_AEGIS_NETWORK, HostAlias, HostAliases, HostId,
    protocol::{
        AegisAgentHealth, AegisAgentStatus, AegisDirectClientCertRequest,
        AegisDirectClientCertResponse, AegisDirectGateway, AegisDirectGatewayConfig,
        AegisDirectGatewayPublishRequest, AegisDirectGatewayReport, AegisDirectPeerObservation,
        AegisDirectSatellite, AegisDirectTargetListResponse, AegisDirectWireGuard,
        AegisEgressConfig, AegisEgressEnableRequest, AegisEgressHost, AegisEgressIdentityRequest,
        AegisEgressInventory, AegisEgressOutcome, AegisEgressPolicy, AegisEgressResult,
        AegisEgressStatus, AegisHostMessage, AegisHostMessageLevel, AegisHostReportRequest,
        AegisMeshConfig, AegisNetworkConfig, AegisNetworkMember, AegisPrincipalGrant,
        AegisPutNetworkMemberRequest, AegisPutNetworkMemberWireGuard, aegis_user_cert_principal,
    },
    sshd_install_dropin_contents,
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use axum::{
    Json, Router,
    extract::{ConnectInfo, State, connect_info::Connected},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
    routing::{get, post},
    serve::IncomingStream,
};
use capulus::managed::{
    ActivatedListeners, ManagedAgent, ManagementServer, ManagementServerOptions, ReleaseSource,
    ResolvedRelease, VersionTarget,
};
#[cfg(target_os = "linux")]
use futures_util::StreamExt;
#[cfg(target_os = "linux")]
use rtnetlink::{
    MulticastGroup, new_multicast_connection,
    packet_core::NetlinkPayload,
    packet_route::{
        AddressFamily, RouteNetlinkMessage,
        link::{LinkAttribute, LinkMessage, State as LinkState},
        route::{RouteAddress, RouteAttribute, RouteMessage},
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssh_key::{Certificate, HashAlg, PublicKey, certificate::CertType};
use tokio::net::UnixListener;

use crate::ssh_service::{
    active as sshd_is_active, reload as reload_sshd, validate as validate_sshd,
};

use crate::{
    agent_credentials::AgentCredentials,
    api::{ApiClient, ApiClientError},
    cli::{AgentArgs, AgentMode},
    command::{require_success, require_success_with_input, run_capture},
    config::{
        AgentConfig, AgentHostConfig, CachedHost as InventoryHost, CachedInventory, CachedNetwork,
        ResolvedNetwork, load_cached_inventory_for_endpoint as load_cached_inventory_file,
        persist_agent_config, persist_inventory as persist_inventory_file,
    },
    egress_probe::{CandidateProbe, CommittedProbe},
    metadata::gce_wireguard_endpoint_ips,
    redeploy_version::RedeployVersion,
    wireguard_endpoint::{
        preferred_wireguard_endpoint_ip_with_ipv6_support, system_supports_public_ipv6,
        wireguard_endpoint_ipv4,
    },
};

const AEGIS_AGENT_BASE_PATH: &str = "/aegis-agent";
const AEGIS_AGENT_HEALTH_ROUTE: &str = "/health";
const AEGIS_AGENT_REFRESH_ROUTE: &str = "/refresh";
pub(crate) const AEGIS_AGENT_REFRESH_PATH: &str = "/aegis-agent/refresh";
const AEGIS_AGENT_REFRESH_CREDENTIALS_ROUTE: &str = "/refresh-credentials";
pub(crate) const AEGIS_AGENT_REFRESH_CREDENTIALS_PATH: &str = "/aegis-agent/refresh-credentials";
const AEGIS_AGENT_PRINCIPAL_GRANTS_ROUTE: &str = "/principal-grants";
pub(crate) const AEGIS_AGENT_PRINCIPAL_GRANTS_PATH: &str = "/aegis-agent/principal-grants";
const AEGIS_AGENT_STATUS_ROUTE: &str = "/status";
pub(crate) const AEGIS_AGENT_STATUS_PATH: &str = "/aegis-agent/status";
const AEGIS_AGENT_VERSION_ROUTE: &str = "/version";
pub(crate) const AEGIS_AGENT_VERSION_PATH: &str = "/aegis-agent/version";
const AEGIS_AGENT_REISSUE_TOKEN_ROUTE: &str = "/reissue-token";
pub(crate) const AEGIS_AGENT_REISSUE_TOKEN_PATH: &str = "/aegis-agent/reissue-token";
const AEGIS_AGENT_DIRECT_TARGETS_ROUTE: &str = "/direct/targets";
pub(crate) const AEGIS_AGENT_DIRECT_TARGETS_PATH: &str = "/aegis-agent/direct/targets";
const AEGIS_AGENT_DIRECT_CLIENT_CERT_ROUTE: &str = "/direct/client-cert";
pub(crate) const AEGIS_AGENT_DIRECT_CLIENT_CERT_PATH: &str = "/aegis-agent/direct/client-cert";
const AEGIS_AGENT_EGRESS_ROUTE: &str = "/egress";
pub(crate) const AEGIS_AGENT_EGRESS_PATH: &str = "/aegis-agent/egress";
const BIRD3_APT_SOURCE_PATH: &str = "/etc/apt/sources.list.d/cznic-bird3.sources";
const BIRD3_APT_KEYRING_PATH: &str = "/usr/share/keyrings/cznic-labs-bird3.gpg";
const BIRD3_APT_REPOSITORY: &str = "https://pkg.labs.nic.cz/bird3";
pub(crate) const BABEL_OVERLAY_PREFIX: &str = "agx";
pub(crate) const BABEL_VXLAN_PORT: &str = "4789";
const BABEL_TRANSIT_IPV4_BASE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 0);
const BABEL_TRANSIT_IPV6_BASE: Ipv6Addr = Ipv6Addr::new(0xfd75, 0xffff, 0, 0, 0, 0, 0, 0);
const AEGIS_WIREGUARD_DIR: &str = aegis_dto::layout::WIREGUARD_DIRECTORY;
const AEGIS_WIREGUARD_UNIT_TEMPLATE_PATH: &str =
    aegis_dto::layout::WIREGUARD_SYSTEMD_UNIT_TEMPLATE_PATH;
const AEGIS_WIREGUARD_UNIT_PREFIX: &str = aegis_dto::layout::WIREGUARD_SYSTEMD_UNIT_PREFIX;

const NORMAL_POLL_INTERVAL: Duration = Duration::from_secs(60);
#[cfg(target_os = "linux")]
const UNDERLAY_EVENT_DEBOUNCE: Duration = Duration::from_millis(500);
#[cfg(target_os = "linux")]
const UNDERLAY_EVENT_MAX_DEBOUNCE: Duration = Duration::from_secs(2);
const UNDERLAY_MONITOR_RETRY_INTERVAL: Duration = Duration::from_secs(30);
#[cfg(target_os = "linux")]
const UNDERLAY_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const NSS_QUERY_TIMEOUT: Duration = Duration::from_secs(10);
const BABEL_ROUTE_READY_TIMEOUT: Duration = Duration::from_secs(20);
const BABEL_ROUTE_READY_POLL_INTERVAL: Duration = Duration::from_millis(500);
const BABEL_ROUTE_READY_STABLE_POLLS: u8 = 2;
const BABEL_PROTOCOL_NAME: &str = "babel_mesh";
#[cfg(target_os = "linux")]
const BABEL_STATUS_COMMAND_TIMEOUT: &str = "3s";
const APPLIED_CONFIG_DIRECTORY: &str = aegis_dto::layout::APPLIED_CONFIG_DIRECTORY;
#[cfg(target_os = "linux")]
const BIRD_APPLIED_CONFIG_NAME: &str = "bird";
const SSHD_APPLIED_CONFIG_NAME: &str = "sshd";
const WIREGUARD_UNIT_APPLIED_CONFIG_NAME: &str = "wireguard-systemd-unit";
const EGRESS_NFTABLES_APPLIED_CONFIG_NAME: &str = "egress-nftables";
// A private rt_protocol value, additionally scoped to the dedicated egress interface and pools.
const EGRESS_ROUTE_PROTOCOL: u8 = 186;
const EGRESS_ROUTE_METRIC: u16 = 5;
const EGRESS_COMMAND_TIMEOUT: &str = "10s";
const MANAGED_CONFIG_HEADER: &str =
    "# THIS FILE IS AUTOMATICALLY GENERATED BY aegis.\n# ALL MODIFICATIONS WILL BE LOST.\n\n";
const WG_QUICK_INTERFACE_FIELDS: [&str; 9] = [
    "address",
    "dns",
    "mtu",
    "table",
    "preup",
    "postup",
    "predown",
    "postdown",
    "saveconfig",
];

#[derive(Debug, Serialize)]
struct AgentVersionResponse {
    version: &'static str,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct AgentBabelStatus {
    pub(crate) ready: bool,
    pub(crate) ready_unix: Option<u64>,
    pub(crate) latest_route_update: Option<String>,
    pub(crate) learned_route_count: usize,
    pub(crate) stable_polls: u8,
    pub(crate) last_error: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum AgentTunnelStatus {
    #[default]
    Unknown,
    Unsupported,
    Disabled,
    Enabled {
        via: String,
    },
    Reconciling {
        active_via: Option<String>,
        desired_via: Option<String>,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct AgentStatusResponse {
    pub(crate) ready: bool,
    pub(crate) boot_id: String,
    pub(crate) reconciled_since_boot: bool,
    pub(crate) applied_aliases: Option<HostAliases>,
    pub(crate) first_reconcile_unix: Option<u64>,
    pub(crate) last_reconcile_unix: Option<u64>,
    #[serde(default)]
    pub(crate) last_reconcile_warning: Option<String>,
    pub(crate) last_reconcile_error: Option<String>,
    pub(crate) babel: AgentBabelStatus,
    pub(crate) tunnel: AgentTunnelStatus,
}

#[derive(Clone, Debug)]
struct AgentPeerCredentials {
    uid: Option<u32>,
}

impl AgentPeerCredentials {
    fn require_root(&self) -> Result<()> {
        if self.uid != Some(0) {
            return Err(AgentForbidden("TLS provisioning requires local root".into()).into());
        }
        Ok(())
    }
}

impl Connected<IncomingStream<'_, UnixListener>> for AgentPeerCredentials {
    fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
        let cred = stream.io().peer_cred().ok();
        Self {
            uid: cred.as_ref().map(|cred| cred.uid()),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct PrincipalGrantMutationRequest {
    user_id: String,
}

#[derive(Clone, Debug, Deserialize)]
struct AgentTokenReissueRequest {
    refresh_token: String,
}

#[derive(Debug, Serialize)]
struct PrincipalGrantResponse {
    login_principal: String,
    grants: Vec<AegisPrincipalGrant>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DirectAccountState {
    account: String,
    satellite_slug: String,
}

#[derive(Debug)]
struct AgentForbidden(String);

impl std::fmt::Display for AgentForbidden {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for AgentForbidden {}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct WireGuardConfig {
    interface: String,
    config_path: PathBuf,
    private_key_path: PathBuf,
    public_key_path: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AppliedConfigStatus {
    Current,
    Stale,
    Uninitialized,
}

#[derive(Debug)]
struct AppliedConfig {
    path: PathBuf,
    digest: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct WireGuardRuntimeConfig {
    interface: BTreeMap<String, Vec<String>>,
    peers: BTreeMap<String, BTreeMap<String, Vec<String>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WireGuardListenPort {
    Automatic,
    Fixed(NonZeroU16),
}

impl WireGuardListenPort {
    fn for_listener(endpoint_port: u16, accepts_connections: bool) -> Result<Self> {
        let port = NonZeroU16::new(endpoint_port)
            .ok_or_else(|| anyhow!("WireGuard endpoint port must be nonzero"))?;
        Ok(if accepts_connections {
            Self::Fixed(port)
        } else {
            Self::Automatic
        })
    }

    fn config_port(self) -> u16 {
        match self {
            Self::Automatic => 0,
            Self::Fixed(port) => port.get(),
        }
    }

    fn applied_config(self, path: &Path, live_port: u16) -> AppliedConfig {
        AppliedConfig::at_path(
            path.to_owned(),
            &[self.config_port().to_be_bytes(), live_port.to_be_bytes()].concat(),
        )
    }

    fn needs_activation(self, status: AppliedConfigStatus, live_port: u16) -> bool {
        match self {
            Self::Automatic => live_port == 0 || status != AppliedConfigStatus::Current,
            Self::Fixed(port) => live_port != port.get(),
        }
    }
}

impl WireGuardRuntimeConfig {
    fn listen_port(&self) -> Result<u16> {
        let Some(values) = self.interface.get("listenport") else {
            return Ok(0);
        };
        ensure!(
            values.len() == 1,
            "WireGuard must contain at most one ListenPort"
        );
        values[0].parse().context("invalid WireGuard ListenPort")
    }

    fn listen_port_policy(&self) -> Result<WireGuardListenPort> {
        Ok(match NonZeroU16::new(self.listen_port()?) {
            Some(port) => WireGuardListenPort::Fixed(port),
            None => WireGuardListenPort::Automatic,
        })
    }

    fn set_listen_port(&mut self, port: NonZeroU16) {
        self.interface
            .insert("listenport".to_string(), vec![port.to_string()]);
    }

    fn contents(&self) -> String {
        let mut content = String::from("[Interface]\n");
        for (key, values) in &self.interface {
            for value in values {
                content.push_str(&format!("{key} = {value}\n"));
            }
        }
        for peer in self.peers.values() {
            content.push_str("\n[Peer]\n");
            for (key, values) in peer {
                if key == "allowedips" {
                    content.push_str(&format!("{key} = {}\n", values.join(",")));
                } else {
                    for value in values {
                        content.push_str(&format!("{key} = {value}\n"));
                    }
                }
            }
        }
        content
    }

    fn matches(&self, live: &Self) -> Result<bool> {
        let mut desired = self.clone();
        let mut live = live.clone();
        for fields in [&mut desired.interface, &mut live.interface] {
            if let Some(values) = fields.get_mut("privatekey") {
                for value in values {
                    *value = crate::wireguard_keys::canonical_private_key_for_comparison(value);
                }
            }
        }
        if self.listen_port_policy()? == WireGuardListenPort::Automatic {
            let Some(port) = NonZeroU16::new(live.listen_port()?) else {
                return Ok(false);
            };
            desired.set_listen_port(port);
        }
        if desired.interface != live.interface || desired.peers.keys().ne(live.peers.keys()) {
            return Ok(false);
        }
        for (public_key, desired_peer) in &desired.peers {
            let mut live_peer = live.peers[public_key].clone();
            if !desired_peer.contains_key("endpoint") {
                live_peer.remove("endpoint");
            }
            if *desired_peer != live_peer {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

struct WireGuardRuntime<'a> {
    interface: &'a str,
    desired: WireGuardRuntimeConfig,
    policy: WireGuardListenPort,
    port_state_path: PathBuf,
}

impl<'a> WireGuardRuntime<'a> {
    fn parse(interface: &'a str, desired: &str) -> Result<Self> {
        let desired = parse_wireguard_runtime_config(&strip_wg_quick_fields(desired)?)?;
        let policy = desired.listen_port_policy()?;
        Ok(Self {
            interface,
            desired,
            policy,
            port_state_path: Path::new(APPLIED_CONFIG_DIRECTORY)
                .join(format!("wireguard-{interface}-listen-port.sha256")),
        })
    }

    fn applied_port(&self, port: u16) -> AppliedConfig {
        self.policy.applied_config(&self.port_state_path, port)
    }

    fn read(&self) -> Result<WireGuardRuntimeConfig> {
        let output =
            run_capture(bounded_egress_command("/usr/bin/wg").args(["showconf", self.interface]))?;
        ensure!(
            output.status.success(),
            "failed to inspect WireGuard runtime for `{}`: {}",
            self.interface,
            output.stderr.trim(),
        );
        parse_wireguard_runtime_config(&output.stdout)
    }

    fn verify_port(&self, live: &WireGuardRuntimeConfig) -> Result<NonZeroU16> {
        let port = NonZeroU16::new(live.listen_port()?)
            .ok_or_else(|| anyhow!("WireGuard `{}` has no listening port", self.interface))?;
        if let WireGuardListenPort::Fixed(expected) = self.policy {
            ensure!(
                port == expected,
                "WireGuard `{}` listens on UDP {port}, expected {expected}; port policy remains pending",
                self.interface,
            );
        }
        Ok(port)
    }

    fn record_start(&self) -> Result<()> {
        let port = self.verify_port(&self.read()?)?;
        self.applied_port(port.get()).mark()?;
        eprintln!(
            "aegis-agent WireGuard `{}` started on UDP {port} ({:?} listen-port policy)",
            self.interface, self.policy,
        );
        Ok(())
    }

    fn reconcile(&self) -> Result<()> {
        let policy = self.policy;
        let mut live = self.read()?;
        let previous_port = live.listen_port()?;
        let applied = self.applied_port(previous_port);
        let status = applied.status()?;
        let activation_required = policy.needs_activation(status, previous_port);
        if activation_required {
            applied.mark_pending()?;
            require_success(
                &format!("apply WireGuard listen-port policy for `{}`", self.interface),
                bounded_egress_command("/usr/bin/wg").args([
                    "set",
                    self.interface,
                    "listen-port",
                    &policy.config_port().to_string(),
                ]),
            )
            .with_context(|| {
                format!(
                    "WireGuard `{}` listen-port policy remains pending; previous observed port was UDP {previous_port}",
                    self.interface,
                )
            })?;
            live = self.read()?;
        }
        let port = self.verify_port(&live)?;
        if activation_required || status != AppliedConfigStatus::Current {
            eprintln!(
                "aegis-agent WireGuard `{}` applied {policy:?} listen-port policy: UDP {previous_port} -> {port}",
                self.interface,
            );
            self.applied_port(port.get()).mark().with_context(|| {
                format!(
                    "WireGuard `{}` is listening on UDP {port}, but recording its applied port policy failed",
                    self.interface,
                )
            })?;
        }

        let mut desired = self.desired.clone();
        if policy == WireGuardListenPort::Automatic {
            // syncconf resets an omitted/zero ListenPort. Preserve the selected runtime port.
            desired.set_listen_port(port);
        }
        if !desired.matches(&live)? {
            require_success_with_input(
                "synchronize live WireGuard configuration",
                bounded_egress_command("/usr/bin/wg").args([
                    "syncconf",
                    self.interface,
                    "/dev/stdin",
                ]),
                desired.contents().as_bytes(),
            )
            .with_context(|| {
                format!(
                    "WireGuard `{}` port policy was applied on UDP {port}; peer synchronization failed",
                    self.interface,
                )
            })?;
            ensure!(
                desired.matches(&self.read()?)?,
                "WireGuard `{}` runtime does not match after synchronization",
                self.interface,
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct WireGuardEndpointPeer {
    host_id: HostId,
    alias: HostAlias,
    interface: String,
    public_key: String,
    endpoint: SocketAddr,
    probe: Option<SocketAddr>,
}

#[derive(Debug, Default)]
struct DataPlaneSummary {
    required_babel_routes: BTreeSet<IpAddr>,
    endpoint_peers: Vec<WireGuardEndpointPeer>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct BabelRouteSnapshot {
    routes: BTreeSet<IpAddr>,
    latest_route_update: Option<String>,
    last_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(target_os = "linux")]
enum UnderlayChange {
    Link(String),
    Route { network: IpAddr, prefix: u8 },
}

#[cfg(target_os = "linux")]
impl UnderlayChange {
    fn description(&self) -> String {
        match self {
            Self::Link(interface) => format!("link `{interface}` became usable"),
            Self::Route { network, prefix } => format!("route `{network}/{prefix}` appeared"),
        }
    }
}

#[derive(Debug)]
struct HostCertificatePrincipals {
    required: BTreeSet<String>,
    exact: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct NetworkAgentConfig {
    mode: AgentMode,
    #[serde(default)]
    managed_mesh: bool,
    #[serde(default)]
    managed_ssh: bool,
    wireguard: WireGuardConfig,
}

#[derive(Default)]
struct RuntimeState {
    boot_id: String,
    first_reconcile_unix: Option<u64>,
    last_reconcile_unix: Option<u64>,
    last_reconcile_completed: Option<Instant>,
    last_reconcile_warning: Option<String>,
    last_reconcile_error: Option<String>,
    applied_aliases: Option<HostAliases>,
    required_babel_routes: BTreeSet<IpAddr>,
    babel: AgentBabelStatus,
    tunnel: AgentTunnelStatus,
}

impl RuntimeState {
    fn status(&self) -> AgentStatusResponse {
        let reconciled_since_boot = self.first_reconcile_unix.is_some();
        AgentStatusResponse {
            ready: reconciled_since_boot && self.last_reconcile_error.is_none() && self.babel.ready,
            boot_id: self.boot_id.clone(),
            reconciled_since_boot,
            applied_aliases: self.applied_aliases.clone(),
            first_reconcile_unix: self.first_reconcile_unix,
            last_reconcile_unix: self.last_reconcile_unix,
            last_reconcile_warning: self.last_reconcile_warning.clone(),
            last_reconcile_error: self.last_reconcile_error.clone(),
            babel: self.babel.clone(),
            tunnel: self.tunnel.clone(),
        }
    }

    fn record_reconcile_success(
        &mut self,
        completed_unix: u64,
        warning: Option<String>,
        babel: AgentBabelStatus,
        required_babel_routes: BTreeSet<IpAddr>,
        applied_aliases: HostAliases,
    ) {
        if self.first_reconcile_unix.is_none() {
            self.first_reconcile_unix = Some(completed_unix);
        }
        self.last_reconcile_completed = Some(Instant::now());
        self.last_reconcile_unix = Some(completed_unix);
        self.last_reconcile_warning = warning;
        self.last_reconcile_error = None;
        self.applied_aliases = Some(applied_aliases);
        self.required_babel_routes = required_babel_routes;
        self.babel = babel;
    }

    fn record_babel_observation(&mut self, snapshot: BabelRouteSnapshot) {
        if self.first_reconcile_unix.is_none() {
            return;
        }
        let complete = babel_routes_complete(&snapshot, &self.required_babel_routes);
        let stable_polls = if complete {
            self.babel
                .stable_polls
                .saturating_add(1)
                .min(BABEL_ROUTE_READY_STABLE_POLLS)
        } else {
            0
        };
        let was_ready = self.babel.ready;
        let ready_unix = self.babel.ready_unix;
        self.babel = babel_status_from_snapshot(
            &snapshot,
            &self.required_babel_routes,
            stable_polls,
            ready_unix,
        );
        if self.babel.ready && !was_ready {
            self.babel.ready_unix = Some(now_unix());
        }
    }

    fn record_reconcile_error(&mut self, message: String) {
        self.last_reconcile_completed = Some(Instant::now());
        self.last_reconcile_warning = None;
        self.last_reconcile_error = Some(message);
        self.babel.ready = false;
    }

    fn coalesced_reconcile_result(&self, requested_at: Instant) -> Option<Result<()>> {
        self.last_reconcile_completed
            .filter(|completed_at| *completed_at >= requested_at)
            .map(|_| {
                self.last_reconcile_error
                    .as_ref()
                    .map(|error| Err(anyhow!(error.clone())))
                    .unwrap_or(Ok(()))
            })
    }
}

struct AppState {
    platform: aegis_dto::platform::HostPlatform,
    config: AgentConfig,
    api: ApiClient,
    config_path: PathBuf,
    credentials: Mutex<AgentCredentials>,
    reconcile_lock: Mutex<()>,
    data_plane_lock: Mutex<()>,
    egress_lock: Mutex<()>,
    tunnel_operations: Mutex<Vec<Arc<crate::tunnel_operation::Operation>>>,
    endpoint_recovery_peers: Mutex<Vec<WireGuardEndpointPeer>>,
    direct_targets: DirectTargetCache,
    runtime: Mutex<RuntimeState>,
}

#[derive(Default)]
struct DirectTargetCache(Mutex<BTreeMap<String, AegisDirectTargetListResponse>>);

impl DirectTargetCache {
    fn get_or_fetch(
        &self,
        slug: &str,
        fetch: impl FnOnce() -> Result<AegisDirectTargetListResponse>,
    ) -> Result<AegisDirectTargetListResponse> {
        if let Some(targets) = self.0.lock().expect("direct targets lock").get(slug) {
            return Ok(targets.clone());
        }
        let targets = fetch()?;
        self.insert(slug, targets.clone());
        Ok(targets)
    }

    fn insert(&self, slug: &str, targets: AegisDirectTargetListResponse) {
        self.0
            .lock()
            .expect("direct targets lock")
            .insert(slug.to_string(), targets);
    }
}

impl AgentConfig {
    fn agent_network_config(
        &self,
        network_config: &AegisNetworkConfig,
        local: &InventoryHost,
    ) -> NetworkAgentConfig {
        NetworkAgentConfig {
            mode: match local.mode {
                AegisHostMode::Leaf => AgentMode::Leaf,
                AegisHostMode::Hub => AgentMode::Hub,
            },
            managed_mesh: network_config.mesh.is_some(),
            managed_ssh: network_config.managed_ssh,
            wireguard: managed_wireguard_config(&network_config.wireguard.interface),
        }
    }
}

#[derive(Debug)]
struct AgentHttpError(anyhow::Error);

impl IntoResponse for AgentHttpError {
    fn into_response(self) -> Response {
        if let Some(error) = self
            .0
            .downcast_ref::<aegis_dto::platform::UnsupportedCapability>()
        {
            return (StatusCode::CONFLICT, error.to_string()).into_response();
        }
        if let Some(error) = self.0.downcast_ref::<AgentForbidden>() {
            return (StatusCode::FORBIDDEN, error.to_string()).into_response();
        }
        if let Some(ApiClientError::Status { status, message }) = self.0.downcast_ref() {
            let message = if message.is_empty() {
                format!("aegis API request failed with {status}")
            } else {
                format!("aegis API request failed with {status}: {message}")
            };
            return (*status, message).into_response();
        }

        (
            StatusCode::INTERNAL_SERVER_ERROR,
            agent_http_error_message(&self.0),
        )
            .into_response()
    }
}

fn agent_http_error_message(error: &anyhow::Error) -> String {
    format!("aegis-agent request failed: {error:#}")
}

pub fn run(args: &AgentArgs) -> Result<i32> {
    #[cfg(unix)]
    if unsafe { libc::geteuid() } != 0 {
        bail!("aegis-agent must run as root");
    }
    let listeners = (!args.once)
        .then(|| ActivatedListeners::from_environment(&["application", "capulus"]))
        .transpose()
        .context("failed to adopt the aegis application and Capulus sockets")?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build aegis-agent tokio runtime")?
        .block_on(run_async(args, listeners))
}

async fn run_async(args: &AgentArgs, listeners: Option<ActivatedListeners>) -> Result<i32> {
    let platform = crate::platform::detect()?;
    let config = load_config(&args.config)?;
    config.routing.validate_platform(platform)?;
    let api = ApiClient::new_agent_control(&config.api_base)?;
    crate::config::AgentContext {
        api_base: config.api_base.clone(),
        host_id: config.host.host_id,
    }
    .persist()?;
    let agent_refresh_token = config.auth.refresh_token.clone();
    let state = Arc::new(AppState {
        platform,
        config,
        api,
        config_path: args.config.clone(),
        credentials: Mutex::new(AgentCredentials::new(agent_refresh_token)),
        reconcile_lock: Mutex::new(()),
        data_plane_lock: Mutex::new(()),
        egress_lock: Mutex::new(()),
        tunnel_operations: Mutex::new(Vec::new()),
        endpoint_recovery_peers: Mutex::new(Vec::new()),
        direct_targets: DirectTargetCache::default(),
        runtime: Mutex::new(RuntimeState {
            boot_id: crate::platform::boot_id()?,
            ..Default::default()
        }),
    });

    if args.once {
        let result = run_blocking({
            let state = Arc::clone(&state);
            move || reconcile_and_update_status(&state)
        })
        .await;
        #[cfg(target_os = "macos")]
        run_blocking(macos::shutdown)
            .await
            .context("one-shot native mesh cleanup failed; ownership journals retained")?;
        result?;
        return Ok(0);
    }

    let mut listeners = listeners.expect("non-once agent startup adopts service listeners");
    let application_listener = listeners.take_tokio("application")?;
    let management_listener = listeners.take_tokio("capulus")?;
    if !listeners.is_empty() {
        bail!("aegis-agent retained an unexpected service listener");
    }
    let management = Arc::new(ManagedAgent::new(
        Arc::new(crate::managed::product()?),
        Arc::new(AegisReleaseSource),
    )?);
    let management_server = ManagementServer::new(
        management_listener,
        management,
        ManagementServerOptions::default(),
    )?;
    let reconcile_task = tokio::spawn(reconcile_loop(Arc::clone(&state)));
    let underlay_monitor_task = tokio::spawn(underlay_monitor_loop(Arc::clone(&state)));
    let app = agent_app(state);
    let result = tokio::select! {
        result = axum::serve(
            application_listener,
            app.into_make_service_with_connect_info::<AgentPeerCredentials>(),
        ) => result.context("failed to serve the aegis application API"),
        result = management_server.run() => result.context("failed to serve the aegis Capulus API"),
        result = shutdown_signal() => result,
    };
    reconcile_task.abort();
    underlay_monitor_task.abort();
    #[cfg(target_os = "macos")]
    run_blocking(macos::shutdown).await?;
    result?;
    Ok(0)
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! { signal = tokio::signal::ctrl_c() => signal?, _ = terminate.recv() => {} }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        std::future::pending().await
    }
}

struct AegisReleaseSource;

impl ReleaseSource for AegisReleaseSource {
    async fn resolve(&self, target: VersionTarget) -> Result<ResolvedRelease> {
        tokio::task::spawn_blocking(move || resolve_managed_release(target))
            .await
            .context("aegis release-resolution task panicked")?
    }
}

fn resolve_managed_release(target: VersionTarget) -> Result<ResolvedRelease> {
    let version = match target {
        VersionTarget::Latest => crate::release::latest_version()?,
        VersionTarget::Exact(version) => RedeployVersion::explicit(&version)?.semver().clone(),
    };
    let release = ResolvedRelease {
        version,
        registry: capulus::managed::CargoRegistry::CratesIo,
    };
    release.validate()?;
    Ok(release)
}

fn agent_app(state: Arc<AppState>) -> Router {
    let routes = Router::new()
        .route(AEGIS_AGENT_HEALTH_ROUTE, get(get_health))
        .route(AEGIS_AGENT_REFRESH_ROUTE, post(post_refresh))
        .route(
            AEGIS_AGENT_REFRESH_CREDENTIALS_ROUTE,
            post(post_refresh_credentials),
        )
        .route(
            AEGIS_AGENT_PRINCIPAL_GRANTS_ROUTE,
            get(get_principal_grants)
                .post(post_principal_grant)
                .delete(delete_principal_grant),
        )
        .route(AEGIS_AGENT_STATUS_ROUTE, get(get_status))
        .route(AEGIS_AGENT_VERSION_ROUTE, get(get_version))
        .route(AEGIS_AGENT_REISSUE_TOKEN_ROUTE, post(post_reissue_token))
        .route(
            "/tls/certs/{label}",
            axum::routing::put(put_tls_certificate),
        )
        .route(AEGIS_AGENT_DIRECT_TARGETS_ROUTE, get(get_direct_targets))
        .route(
            AEGIS_AGENT_DIRECT_CLIENT_CERT_ROUTE,
            post(post_direct_client_cert),
        )
        .route(AEGIS_AGENT_EGRESS_ROUTE, get(get_local_egress))
        .route("/egress/operation", post(tunnel::start))
        .route(
            "/egress/operation/{id}",
            get(tunnel::poll).delete(tunnel::cancel),
        )
        .with_state(state);
    Router::new().nest(AEGIS_AGENT_BASE_PATH, routes)
}

async fn reconcile_loop(state: Arc<AppState>) {
    loop {
        if let Err(error) = run_blocking({
            let state = Arc::clone(&state);
            move || reconcile_and_update_status(&state)
        })
        .await
        {
            eprintln!("aegis-agent reconcile failed: {error:#}");
        }
        tokio::time::sleep(NORMAL_POLL_INTERVAL).await;
    }
}

#[cfg(target_os = "macos")]
use macos::{current_babel_route_snapshot, monitor_underlay_events};

async fn underlay_monitor_loop(state: Arc<AppState>) {
    loop {
        if let Err(error) = monitor_underlay_events(Arc::clone(&state)).await {
            eprintln!(
                "aegis-agent underlay monitor failed; retrying in {}s: {error:#}",
                UNDERLAY_MONITOR_RETRY_INTERVAL.as_secs()
            );
            tokio::time::sleep(UNDERLAY_MONITOR_RETRY_INTERVAL).await;
        }
    }
}

#[cfg(target_os = "linux")]
async fn monitor_underlay_events(state: Arc<AppState>) -> Result<()> {
    let (connection, _handle, mut messages) = new_multicast_connection(&[
        MulticastGroup::Link,
        MulticastGroup::Ipv4Route,
        MulticastGroup::Ipv6Route,
    ])
    .context("failed to subscribe to kernel link and route events")?;
    let connection_task = tokio::spawn(connection);
    eprintln!("aegis-agent underlay monitor is watching kernel link and route events");

    while let Some((message, _)) = messages.next().await {
        let peers = state.endpoint_recovery_peers.lock().expect("lock").clone();
        let Some(change) = relevant_underlay_change(&message.payload, &peers) else {
            continue;
        };
        let mut changes = BTreeSet::from([change]);
        let debounce_started = Instant::now();
        loop {
            tokio::time::sleep(UNDERLAY_EVENT_DEBOUNCE).await;
            let mut saw_relevant_change = false;
            while let Ok((message, _)) = messages.try_recv() {
                if let Some(change) = relevant_underlay_change(&message.payload, &peers) {
                    saw_relevant_change = true;
                    changes.insert(change);
                }
            }
            if !saw_relevant_change || debounce_started.elapsed() >= UNDERLAY_EVENT_MAX_DEBOUNCE {
                break;
            }
        }
        recover_wireguard_after_underlay_change(Arc::clone(&state), changes).await?;
    }

    connection_task
        .await
        .context("kernel route-netlink connection task failed")?;
    bail!("kernel route-netlink event stream ended")
}

#[cfg(target_os = "linux")]
fn relevant_underlay_change(
    payload: &NetlinkPayload<RouteNetlinkMessage>,
    peers: &[WireGuardEndpointPeer],
) -> Option<UnderlayChange> {
    if peers.is_empty() {
        return None;
    }
    match payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(route)) => {
            let (network, prefix) = route_network(route)?;
            peers
                .iter()
                .any(|peer| ip_in_subnet(network, prefix, peer.endpoint.ip()))
                .then_some(UnderlayChange::Route { network, prefix })
        }
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)) => {
            let interface = usable_link_name(link)?;
            is_physical_underlay_interface(interface)
                .then(|| UnderlayChange::Link(interface.to_string()))
        }
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn route_network(route: &RouteMessage) -> Option<(IpAddr, u8)> {
    let prefix = route.header.destination_prefix_length;
    match route.header.address_family {
        AddressFamily::Inet if prefix <= 32 => {
            if prefix == 0 {
                return Some((IpAddr::V4(Ipv4Addr::UNSPECIFIED), prefix));
            }
            route
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    RouteAttribute::Destination(RouteAddress::Inet(network)) => {
                        Some((IpAddr::V4(*network), prefix))
                    }
                    _ => None,
                })
        }
        AddressFamily::Inet6 if prefix <= 128 => {
            if prefix == 0 {
                return Some((IpAddr::V6(Ipv6Addr::UNSPECIFIED), prefix));
            }
            route
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    RouteAttribute::Destination(RouteAddress::Inet6(network)) => {
                        Some((IpAddr::V6(*network), prefix))
                    }
                    _ => None,
                })
        }
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn ip_in_subnet(network: IpAddr, prefix: u8, address: IpAddr) -> bool {
    match (network, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) => ipv4_in_subnet((network, prefix), address),
        (IpAddr::V6(network), IpAddr::V6(address)) => ipv6_in_subnet((network, prefix), address),
        _ => false,
    }
}

#[cfg(target_os = "linux")]
fn usable_link_name(link: &LinkMessage) -> Option<&str> {
    if !link.attributes.iter().any(|attribute| {
        matches!(
            attribute,
            LinkAttribute::Carrier(1)
                | LinkAttribute::OperState(LinkState::Up | LinkState::Dormant)
        )
    }) {
        return None;
    }
    link.attributes
        .iter()
        .find_map(|attribute| match attribute {
            LinkAttribute::IfName(interface) => Some(interface.as_str()),
            _ => None,
        })
}

#[cfg(target_os = "linux")]
fn is_physical_underlay_interface(interface: &str) -> bool {
    interface != "lo"
        && !interface.starts_with(BABEL_OVERLAY_PREFIX)
        && !interface.starts_with("wg-")
        && Path::new("/sys/class/net")
            .join(interface)
            .join("device")
            .exists()
}

#[cfg(target_os = "linux")]
struct EndpointRebindReport {
    peers: Vec<WireGuardEndpointPeer>,
    failures: Vec<String>,
}

#[cfg(target_os = "linux")]
async fn recover_wireguard_after_underlay_change(
    state: Arc<AppState>,
    changes: BTreeSet<UnderlayChange>,
) -> Result<()> {
    let started = Instant::now();
    let report = run_blocking(move || rebind_wireguard_endpoints(&state)).await?;
    if report.peers.is_empty() {
        return Ok(());
    }

    let probe_results = futures_util::future::join_all(report.peers.iter().filter_map(|peer| {
        let address = peer.probe?;
        let peer_label = format!("{}@{}", peer.alias, peer.interface);
        Some(async move {
            let outcome = tokio::time::timeout(
                UNDERLAY_PROBE_TIMEOUT,
                tokio::net::TcpStream::connect(address),
            )
            .await;
            let error = match outcome {
                Ok(Ok(_)) => None,
                Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => None,
                Ok(Err(error)) => Some(error.to_string()),
                Err(_) => Some(format!(
                    "timed out after {}s",
                    UNDERLAY_PROBE_TIMEOUT.as_secs()
                )),
            };
            (peer_label, address, error)
        })
    }))
    .await;

    let mut failures = report.failures;
    let probes_reached = probe_results
        .iter()
        .filter(|(_, _, error)| error.is_none())
        .count();
    for (peer, address, error) in &probe_results {
        if let Some(error) = error {
            failures.push(format!("probe {peer} ({address}): {error}"));
        }
    }
    let changes = changes
        .iter()
        .map(UnderlayChange::description)
        .collect::<Vec<_>>()
        .join(", ");
    let peers = report
        .peers
        .iter()
        .map(|peer| format!("{}@{}={}", peer.alias, peer.interface, peer.endpoint))
        .collect::<Vec<_>>()
        .join(", ");
    let elapsed_ms = started.elapsed().as_millis();
    if failures.is_empty() {
        eprintln!(
            "aegis-agent WireGuard underlay recovery after {changes}: refreshed {peers}; direct probes {probes_reached}/{} reached in {elapsed_ms}ms",
            probe_results.len()
        );
    } else {
        eprintln!(
            "aegis-agent WireGuard underlay recovery after {changes} was incomplete: refreshed {peers}; direct probes {probes_reached}/{} reached in {elapsed_ms}ms; {}",
            probe_results.len(),
            failures.join("; ")
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn rebind_wireguard_endpoints(state: &AppState) -> Result<EndpointRebindReport> {
    let _guard = state.data_plane_lock.lock().expect("lock");
    let peers = state.endpoint_recovery_peers.lock().expect("lock").clone();
    let mut failures = Vec::new();
    for peer in &peers {
        let endpoint = peer.endpoint.to_string();
        let result = require_success(
            &format!("refresh WireGuard endpoint for `{}`", peer.alias),
            Command::new("wg").args([
                "set",
                &peer.interface,
                "peer",
                &peer.public_key,
                "endpoint",
                &endpoint,
            ]),
        );
        if let Err(error) = result {
            failures.push(format!("{}@{}: {error:#}", peer.alias, peer.interface));
        }
    }
    Ok(EndpointRebindReport { peers, failures })
}

async fn run_blocking<T, F>(task: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(task)
        .await
        .context("aegis-agent blocking task panicked")?
}

async fn get_health() -> &'static str {
    "OK"
}

async fn get_version() -> Json<AgentVersionResponse> {
    Json(AgentVersionResponse {
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn get_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<AgentStatusResponse>, AgentHttpError> {
    run_blocking(move || {
        let required_routes = state
            .runtime
            .lock()
            .expect("lock")
            .required_babel_routes
            .clone();
        let snapshot = (!required_routes.is_empty()).then(current_babel_route_snapshot);
        let mut runtime = state.runtime.lock().expect("lock");
        if let Some(snapshot) = snapshot {
            runtime.record_babel_observation(snapshot);
        }
        let mut status = runtime.status();
        drop(runtime);
        if let Some(alert) = state.credentials.lock().expect("lock").alert() {
            status.ready = false;
            status.last_reconcile_error = Some(alert.value);
        }
        Ok(Json(status))
    })
    .await
    .map_err(AgentHttpError)
}

async fn post_refresh(State(state): State<Arc<AppState>>) -> Result<StatusCode, AgentHttpError> {
    run_blocking(move || reconcile_and_update_status(&state))
        .await
        .map_err(AgentHttpError)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn post_refresh_credentials(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<AgentPeerCredentials>,
) -> Result<StatusCode, AgentHttpError> {
    run_blocking(move || {
        login_principal_from_peer(&peer)?;
        refresh_credentials_for_login_principal(&state)?;
        Ok(StatusCode::NO_CONTENT)
    })
    .await
    .map_err(AgentHttpError)
}

async fn get_principal_grants(
    ConnectInfo(peer): ConnectInfo<AgentPeerCredentials>,
) -> Result<Json<PrincipalGrantResponse>, AgentHttpError> {
    run_blocking(move || {
        let login_principal = login_principal_from_peer(&peer)?;
        let grants = crate::principal_grants::PrincipalGrantStore::load()?
            .grants
            .into_iter()
            .filter(|grant| grant.login_principal == login_principal)
            .collect();
        Ok(PrincipalGrantResponse {
            login_principal,
            grants,
        })
    })
    .await
    .map(Json)
    .map_err(AgentHttpError)
}

async fn post_principal_grant(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<AgentPeerCredentials>,
    Json(request): Json<PrincipalGrantMutationRequest>,
) -> Result<Json<PrincipalGrantResponse>, AgentHttpError> {
    mutate_principal_grants(state, peer, request.user_id, PrincipalGrantMutation::Allow).await
}

async fn delete_principal_grant(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<AgentPeerCredentials>,
    Json(request): Json<PrincipalGrantMutationRequest>,
) -> Result<Json<PrincipalGrantResponse>, AgentHttpError> {
    mutate_principal_grants(state, peer, request.user_id, PrincipalGrantMutation::Revoke).await
}

async fn get_direct_targets(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<AgentPeerCredentials>,
) -> Result<Json<AegisDirectTargetListResponse>, AgentHttpError> {
    run_blocking(move || {
        let satellite = direct_account_from_peer(&peer)?;
        state
            .direct_targets
            .get_or_fetch(&satellite.satellite_slug, || {
                fetch_direct_targets(&state, &satellite.satellite_slug)
            })
    })
    .await
    .map(Json)
    .map_err(AgentHttpError)
}

fn fetch_direct_targets(state: &AppState, slug: &str) -> Result<AegisDirectTargetListResponse> {
    let token = access_token(state)?;
    match state.api.get_satellite_targets(&token, slug) {
        Ok(targets) => Ok(targets),
        Err(error) if error.is_unauthorized() => state
            .api
            .get_satellite_targets(&force_access_token_refresh(state)?, slug)
            .map_err(Into::into),
        Err(error) => Err(error.into()),
    }
}

fn refresh_direct_targets(state: &AppState, plan: &DirectGatewayPlan, warnings: &mut Vec<String>) {
    let satellites = match plan {
        DirectGatewayPlan::Configuring(inventory) | DirectGatewayPlan::Ready(inventory) => {
            &inventory.satellites[..]
        }
        DirectGatewayPlan::Disabled { .. } | DirectGatewayPlan::Unsupported => &[],
        DirectGatewayPlan::Preserve => return,
    };
    state
        .direct_targets
        .0
        .lock()
        .expect("direct targets lock")
        .retain(|slug, _| satellites.iter().any(|satellite| &satellite.slug == slug));
    // This is menu data only. Issuing a client certificate always rechecks the
    // satellite and its current grants at the API.
    for satellite in satellites {
        match fetch_direct_targets(state, &satellite.slug) {
            Ok(targets) => state.direct_targets.insert(&satellite.slug, targets),
            Err(error) => warnings.push(format!(
                "failed to refresh SSH targets for satellite `{}`: {error:#}",
                satellite.slug
            )),
        }
    }
}

async fn post_direct_client_cert(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<AgentPeerCredentials>,
    Json(request): Json<AegisDirectClientCertRequest>,
) -> Result<Json<AegisDirectClientCertResponse>, AgentHttpError> {
    run_blocking(move || {
        let satellite = direct_account_from_peer(&peer)?;
        let api = state.api.clone();
        let token = access_token(&state)?;
        match api.request_satellite_client_cert(&token, &satellite.satellite_slug, &request) {
            Ok(certificate) => Ok(certificate),
            Err(error) if error.is_unauthorized() => api
                .request_satellite_client_cert(
                    &force_access_token_refresh(&state)?,
                    &satellite.satellite_slug,
                    &request,
                )
                .map_err(Into::into),
            Err(error) => Err(error.into()),
        }
    })
    .await
    .map(Json)
    .map_err(AgentHttpError)
}

async fn get_local_egress(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<AgentPeerCredentials>,
    headers: HeaderMap,
) -> Result<Json<crate::tunnel_operation::Status>, AgentHttpError> {
    state
        .platform
        .require(aegis_dto::platform::Capability::InternetTunnel)
        .map_err(AgentHttpError)?;
    let bearer = forwarded_user_bearer(&headers).map_err(AgentHttpError)?;
    run_blocking(move || {
        let response = state
            .api
            .get_egress_status(&bearer, &state.config.host.host_id);
        let (central, central_error) = match response {
            Ok(status) => (Some(status), None),
            Err(error) if error.is_unauthorized() => return Err(error.into()),
            Err(error) => (None, Some(error.to_string())),
        };
        let aliases = load_cached_inventory(&state)
            .map(|cache| {
                cache
                    .hosts
                    .into_iter()
                    .map(|(id, host)| (id, host.aliases.primary().to_string()))
                    .collect()
            })
            .unwrap_or_default();
        Ok(crate::tunnel_operation::Status {
            source: state.config.host.host_id,
            central,
            central_error,
            aliases,
            local: state.runtime.lock().expect("runtime").tunnel.clone(),
            operation: state
                .tunnel_operations
                .lock()
                .expect("operation")
                .iter()
                .rev()
                .find(|op| peer.uid == Some(0) || peer.uid == Some(op.owner))
                .map(|op| op.snapshot()),
            recovery_pending: Path::new(tunnel::JOURNAL).exists(),
        })
    })
    .await
    .map(Json)
    .map_err(AgentHttpError)
}

fn forwarded_user_bearer(headers: &HeaderMap) -> Result<String> {
    let value = headers
        .get(AUTHORIZATION)
        .ok_or_else(|| anyhow!("missing Authorization header"))?
        .to_str()
        .context("Authorization header is not valid text")?;
    let (scheme, token) = value
        .split_once(' ')
        .ok_or_else(|| anyhow!("invalid Authorization header"))?;
    if !scheme.eq_ignore_ascii_case("Bearer") || token.trim().is_empty() {
        bail!("invalid Authorization header");
    }
    Ok(token.trim().to_string())
}

#[derive(Clone, Copy)]
enum PrincipalGrantMutation {
    Allow,
    Revoke,
}

async fn mutate_principal_grants(
    state: Arc<AppState>,
    peer: AgentPeerCredentials,
    user_id: String,
    mutation: PrincipalGrantMutation,
) -> Result<Json<PrincipalGrantResponse>, AgentHttpError> {
    run_blocking(move || {
        let login_principal = login_principal_from_peer(&peer)?;
        let user_id = crate::principal_grants::validate_user_id(&user_id)?;
        let grant = AegisPrincipalGrant {
            login_principal: login_principal.clone(),
            user_id,
        };
        let mut store = crate::principal_grants::PrincipalGrantStore::load()?;
        match mutation {
            PrincipalGrantMutation::Allow => {
                store.allow(&grant.login_principal, &grant.user_id)?;
            }
            PrincipalGrantMutation::Revoke => {
                store.revoke(&grant.login_principal, &grant.user_id)?;
            }
        }
        let store = store.commit_validated_with(
            |grants| {
                let token = access_token(&state)?;
                let mut report = host_report_request(&state)?;
                report.principal_grants = grants.to_vec();
                Ok(state
                    .api
                    .report_host(&token, &state.config.host.host_id, &report)?
                    .principal_grants)
            },
            crate::principal_grants::PrincipalGrantStore::persist,
        )?;
        reconcile_and_update_status_forced(&state)?;
        let grants = store
            .grants
            .into_iter()
            .filter(|grant| grant.login_principal == login_principal)
            .collect();
        Ok(PrincipalGrantResponse {
            login_principal,
            grants,
        })
    })
    .await
    .map(Json)
    .map_err(AgentHttpError)
}

async fn post_reissue_token(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AgentTokenReissueRequest>,
) -> Result<StatusCode, AgentHttpError> {
    run_blocking(move || {
        let refresh_token = request.refresh_token.trim();
        if refresh_token.is_empty() {
            bail!("agent refresh token must not be empty");
        }
        {
            let mut credentials = state.credentials.lock().expect("lock");
            let access = state
                .api
                .exchange_agent_refresh_token(refresh_token, crate::config::now_unix())?;
            if access.host_id != state.config.host.host_id {
                bail!(
                    "agent token is for host `{}`, but local config is for `{}`",
                    access.host_id,
                    state.config.host.host_id
                );
            }
            credentials.accept(access, |token| persist_agent_refresh_token(&state, token));
        }
        if let Err(error) = reconcile_and_update_status_forced(&state) {
            eprintln!("aegis-agent reconcile after token reissue failed: {error:#}");
        }
        Ok(StatusCode::NO_CONTENT)
    })
    .await
    .map_err(AgentHttpError)
}

async fn put_tls_certificate(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<AgentPeerCredentials>,
    axum::extract::Path(label): axum::extract::Path<String>,
    public_key: String,
) -> Result<String, AgentHttpError> {
    peer.require_root().map_err(AgentHttpError)?;
    run_blocking(move || {
        let token = access_token(&state)?;
        match state.api.issue_tls_certificate(&token, &label, &public_key) {
            Err(ApiClientError::Status {
                status: StatusCode::UNAUTHORIZED,
                ..
            }) => state
                .api
                .issue_tls_certificate(&force_access_token_refresh(&state)?, &label, &public_key)
                .map_err(Into::into),
            result => result.map_err(Into::into),
        }
    })
    .await
    .map_err(AgentHttpError)
}

fn refresh_credentials_for_login_principal(state: &AppState) -> Result<()> {
    reconcile_and_update_status_forced(state)?;
    Ok(())
}

fn load_config(path: &Path) -> Result<AgentConfig> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    AgentConfig::parse_toml(&raw).with_context(|| format!("failed to load {}", path.display()))
}

fn login_principal_from_peer(peer: &AgentPeerCredentials) -> Result<String> {
    let uid = peer
        .uid
        .ok_or_else(|| anyhow!("agent socket peer credentials did not include a uid"))?;
    username_for_uid(uid).with_context(|| {
        format!("failed to resolve agent socket peer uid {uid} to a local login principal")
    })
}

fn direct_account_from_peer(peer: &AgentPeerCredentials) -> Result<DirectAccountState> {
    let account = login_principal_from_peer(peer)?;
    if !valid_direct_account(&account) {
        return Err(AgentForbidden(
            "direct-session credentials are available only to paired satellite accounts"
                .to_string(),
        )
        .into());
    }
    let path = Path::new(aegis_dto::layout::DIRECT_STATE_DIRECTORY).join(format!("{account}.json"));
    let raw = fs::read_to_string(&path).map_err(|error| {
        AgentForbidden(format!(
            "paired satellite account `{account}` has no managed identity: {error}"
        ))
    })?;
    let state = serde_json::from_str::<DirectAccountState>(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    if state.account != account {
        bail!(
            "direct account state {} names `{}` instead of `{account}`",
            path.display(),
            state.account
        );
    }
    Ok(state)
}

fn valid_direct_account(account: &str) -> bool {
    account.strip_prefix("aegis-d-").is_some_and(|suffix| {
        suffix.len() == 24
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn username_for_uid(uid: u32) -> Result<String> {
    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    let buffer_len = passwd_buffer_len();
    let mut buffer = vec![0u8; buffer_len];
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            pwd.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 {
        bail!("getpwuid_r failed with errno {rc}");
    }
    if result.is_null() {
        bail!("no passwd entry for uid {uid}");
    }
    let pwd = unsafe { pwd.assume_init() };
    let name = unsafe { CStr::from_ptr(pwd.pw_name) }
        .to_str()
        .context("passwd username is not UTF-8")?;
    crate::principal_grants::validate_login_principal(name)?;
    Ok(name.to_string())
}

fn passwd_buffer_len() -> usize {
    let value = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    if value > 0 { value as usize } else { 16 * 1024 }
}

#[derive(Debug, Clone)]
struct ReconcileSummary {
    required_babel_routes: BTreeSet<IpAddr>,
    applied_aliases: HostAliases,
    warning: Option<String>,
}

struct ControlPlaneSummary {
    inventory: CachedInventory,
    direct_gateway: DirectGatewayPlan,
    reported_wireguard_peers: BTreeSet<String>,
    warning: Option<String>,
}

struct FetchedInventory {
    inventory: CachedInventory,
    reported_wireguard_peers: BTreeSet<String>,
}

#[derive(Debug)]
struct DirectGatewayState {
    config: AegisDirectGatewayConfig,
    gateway: AegisDirectGateway,
    direct_client_ca_public_key: String,
    satellites: Vec<AegisDirectSatellite>,
}

#[derive(Debug)]
enum DirectGatewayPlan {
    Unsupported,
    Configuring(DirectGatewayState),
    Ready(DirectGatewayState),
    Disabled {
        config: AegisDirectGatewayConfig,
        remove_published: bool,
    },
    Preserve,
}

fn reconcile_and_update_status(state: &AppState) -> Result<Option<String>> {
    reconcile_and_update_status_inner(state, true)
}

fn reconcile_and_update_status_forced(state: &AppState) -> Result<Option<String>> {
    reconcile_and_update_status_inner(state, false)
}

fn reconcile_and_update_status_inner(
    state: &AppState,
    allow_coalescing: bool,
) -> Result<Option<String>> {
    let requested_at = Instant::now();
    let _guard = state.reconcile_lock.lock().expect("lock");
    if allow_coalescing {
        let coalesced = {
            let runtime = state.runtime.lock().expect("lock");
            runtime
                .coalesced_reconcile_result(requested_at)
                .map(|result| (result, runtime.last_reconcile_warning.clone()))
        };
        if let Some((result, warning)) = coalesced {
            result?;
            return Ok(warning);
        }
    }

    let result = match reconcile(state) {
        Ok(summary) => {
            let babel = poll_babel_readiness(&summary.required_babel_routes);
            let warning = summary.warning.clone();
            state
                .runtime
                .lock()
                .expect("lock")
                .record_reconcile_success(
                    now_unix(),
                    warning.clone(),
                    babel,
                    summary.required_babel_routes,
                    summary.applied_aliases,
                );
            Ok(warning)
        }
        Err(error) => {
            state
                .runtime
                .lock()
                .expect("lock")
                .record_reconcile_error(format!("{error:#}"));
            Err(error)
        }
    };
    // Publish the result of this reconciliation, including local service failures.
    // A cached access token still lets a storage-impaired agent publish its alert.
    let reported = (|| -> Result<()> {
        let token = access_token(state)?;
        let report = host_report_request(state)?;
        publish_host_report(state, &token, &report)
    })();
    if let Err(error) = reported {
        eprintln!("aegis-agent failed to publish current health: {error:#}");
    }
    result
}

fn reconcile(state: &AppState) -> Result<ReconcileSummary> {
    if state
        .platform
        .supports(aegis_dto::platform::Capability::InternetTunnel)
    {
        ensure_managed_service_running(
            aegis_dto::layout::EGRESS_RESOLVED_DROPIN_PATH,
            "systemd-resolved.service",
        )?;
    }
    let (inventory, direct_gateway, reported_wireguard_peers, warning) =
        match reconcile_control_plane(state) {
            Ok(summary) => (
                summary.inventory,
                summary.direct_gateway,
                Some(summary.reported_wireguard_peers),
                summary.warning,
            ),
            Err(error) => {
                let warning = format!(
                    "aegis control-plane sync failed; reconciled local data plane from cached host inventory: {error:#}"
                );
                eprintln!("{warning}");
                (
                    load_cached_inventory(state)?,
                    DirectGatewayPlan::Preserve,
                    None,
                    Some(warning),
                )
            }
        };
    crate::apparmor::ensure_wireguard_access()?;
    let data_plane = {
        let _guard = state.data_plane_lock.lock().expect("lock");
        let data_plane = reconcile_data_plane(state, &inventory)?;
        if state
            .platform
            .supports(aegis_dto::platform::Capability::DirectGateway)
        {
            reconcile_direct_gateway(&direct_gateway)?;
        }
        // Start the loader only after reconciliation has persisted the desired rules
        // and unit. A previously failed loader must not prevent its own repair.
        if state
            .platform
            .supports(aegis_dto::platform::Capability::InternetTunnel)
        {
            ensure_egress_services_running()?;
        }
        if state
            .platform
            .supports(aegis_dto::platform::Capability::SshLockdown)
        {
            crate::app::lockdown::reconcile_enabled()?;
        }
        *state.endpoint_recovery_peers.lock().expect("lock") = data_plane.endpoint_peers.clone();
        data_plane
    };
    publish_direct_gateway_ready(state, &direct_gateway)?;
    if state
        .platform
        .supports(aegis_dto::platform::Capability::InternetTunnel)
    {
        reconcile_egress_plane(state)?;
    } else {
        state.runtime.lock().expect("runtime").tunnel = AgentTunnelStatus::Unsupported;
    }
    if let Some(reported_wireguard_peers) = reported_wireguard_peers {
        publish_host_report_after_peer_change(state, &reported_wireguard_peers)?;
    }
    Ok(ReconcileSummary {
        required_babel_routes: data_plane.required_babel_routes,
        applied_aliases: inventory
            .hosts
            .get(&state.config.host.host_id)
            .map(|host| host.aliases.clone())
            .ok_or_else(|| anyhow!("host inventory does not contain the local host"))?,
        warning,
    })
}

fn reconcile_control_plane(state: &AppState) -> Result<ControlPlaneSummary> {
    let mut warnings = Vec::new();
    let fetched = fetch_inventory(state)?;
    let mut inventory = fetched.inventory;
    let mut reported_wireguard_peers = fetched.reported_wireguard_peers;
    let direct_gateway = match fetch_direct_gateway_plan(state, &inventory) {
        Ok(direct_gateway) => direct_gateway,
        Err(error) => {
            warnings.push(format!(
                "failed to fetch direct-gateway inventory; preserving the current direct gateway: {error:#}"
            ));
            DirectGatewayPlan::Preserve
        }
    };
    refresh_direct_targets(state, &direct_gateway, &mut warnings);
    record_inventory_cache_result(&mut warnings, persist_inventory(state, &inventory));
    for network in local_network_names(state, &inventory) {
        let update_result = sync_network_member_from_inventory(state, &network, &inventory);
        let needs_refresh = match update_result {
            Ok(needs_refresh) => needs_refresh,
            Err(error) => {
                warnings.push(format!(
                    "failed to publish local host state for network `{network}`: {error:#}"
                ));
                false
            }
        };
        if !needs_refresh {
            continue;
        }
        match fetch_inventory(state) {
            Ok(updated) => {
                inventory = updated.inventory;
                reported_wireguard_peers = updated.reported_wireguard_peers;
                record_inventory_cache_result(&mut warnings, persist_inventory(state, &inventory));
            }
            Err(error) => warnings.push(format!(
                "failed to refresh host inventory after publishing network `{network}` membership: {error:#}"
            )),
        }
    }
    if managed_ssh_enabled(state, &inventory)
        && let Err(error) = sync_local_ssh(state, &inventory, &direct_gateway)
    {
        warnings.push(format!("failed to sync managed SSH assets: {error:#}"));
    }
    Ok(ControlPlaneSummary {
        inventory,
        direct_gateway,
        reported_wireguard_peers,
        warning: warnings_to_option(warnings),
    })
}

fn sync_network_member_from_inventory(
    state: &AppState,
    network: &str,
    inventory: &CachedInventory,
) -> Result<bool> {
    let cached_network = inventory
        .resolve_network(network)?
        .ok_or_else(|| anyhow!("control-plane inventory is missing network `{network}`"))?;
    let local = local_network_member(state, &cached_network, network)?;
    let config = state
        .config
        .agent_network_config(&cached_network.config, local);
    sync_network_member(state, network, &config)
}

fn managed_ssh_enabled(state: &AppState, inventory: &CachedInventory) -> bool {
    local_network_names(state, inventory).iter().any(|network| {
        inventory
            .resolve_network(network)
            .ok()
            .flatten()
            .is_some_and(|cached_network| {
                local_network_member(state, &cached_network, network)
                    .map(|local| {
                        state
                            .config
                            .agent_network_config(&cached_network.config, local)
                            .managed_ssh
                    })
                    .unwrap_or(false)
            })
    })
}

fn record_inventory_cache_result(warnings: &mut Vec<String>, result: Result<()>) {
    if let Err(error) = result {
        warnings.push(format!("failed to persist host inventory cache: {error:#}"));
    }
}

fn warnings_to_option(warnings: Vec<String>) -> Option<String> {
    (!warnings.is_empty()).then(|| warnings.join("; "))
}

fn reconcile_data_plane(state: &AppState, inventory: &CachedInventory) -> Result<DataPlaneSummary> {
    let local_networks = local_network_names(state, inventory);
    #[cfg(target_os = "macos")]
    macos::retain_networks(&local_networks)?;
    if local_networks.is_empty() {
        bail!(
            "local host `{}` is not a member of any published aegis network",
            state.config.host.host_id
        );
    }

    let mut summary = DataPlaneSummary::default();
    for network in local_networks {
        let cached_network = inventory
            .resolve_network(&network)?
            .ok_or_else(|| anyhow!("cached data-plane inventory is missing network `{network}`"))?;
        let local = local_network_member(state, &cached_network, &network)?;
        let config = state
            .config
            .agent_network_config(&cached_network.config, local);
        let network_summary = reconcile_network(state, &network, &config, &cached_network)?;
        summary
            .required_babel_routes
            .extend(network_summary.required_babel_routes);
        summary
            .endpoint_peers
            .extend(network_summary.endpoint_peers);
    }
    summary.endpoint_peers.sort();
    summary.endpoint_peers.dedup();
    Ok(summary)
}

fn reconcile_network(
    state: &AppState,
    network: &str,
    config: &NetworkAgentConfig,
    inventory: &ResolvedNetwork,
) -> Result<DataPlaneSummary> {
    let local = inventory
        .hosts
        .iter()
        .find(|host| host.host_id == state.config.host.host_id)
        .cloned()
        .ok_or_else(|| {
            anyhow!(
                "local host `{}` is missing from the `{network}` network inventory",
                state.config.host.host_id
            )
        })?;
    ensure!(
        local.platform == state.platform,
        "enrolled platform differs from the running host; repair the host identity explicitly"
    );
    state.platform.require_role(local.mode)?;
    let local_wireguard = local.wireguard.as_ref().ok_or_else(|| {
        anyhow!(
            "local host `{}` is missing a WireGuard identity in network `{network}`",
            local.alias()
        )
    })?;
    ensure_local_wireguard_public_key(&config.wireguard, &local_wireguard.public_key)?;
    let peers = select_peers(config.mode, &inventory.hosts, &local.host_id);
    let required_babel_routes = config
        .managed_mesh
        .then(|| required_babel_backbone_routes(&peers))
        .transpose()?
        .unwrap_or_default();
    // Managed meshes reserve the IPv4 underlay's smaller encapsulation overhead for
    // VXLAN and egress. Non-mesh networks can continue to prefer native IPv6.
    let ipv4_endpoint_required = config.managed_mesh;
    let public_ipv6_available = !ipv4_endpoint_required && system_supports_public_ipv6()?;
    let endpoint_peers = peers
        .iter()
        .filter_map(|peer| {
            wireguard_endpoint_peer(
                &config.wireguard.interface,
                inventory.config.wireguard.endpoint_port,
                peer,
                public_ipv6_available,
                ipv4_endpoint_required,
            )
        })
        .collect();
    #[cfg(target_os = "macos")]
    {
        macos::reconcile(macos::NetworkOptions {
            network,
            config,
            inventory,
            local: &local,
            peers: &peers,
        })?;
        Ok(DataPlaneSummary {
            required_babel_routes,
            endpoint_peers,
        })
    }
    #[cfg(target_os = "linux")]
    {
        enable_mesh_ipv6(&config.wireguard.interface, false)?;
        apply_wireguard_config(
            &config.wireguard,
            &inventory.config.wireguard,
            &local,
            &peers,
            public_ipv6_available,
            ipv4_endpoint_required,
        )?;
        enable_mesh_ipv6(&config.wireguard.interface, true)?;
        if !config.managed_mesh {
            return Ok(DataPlaneSummary {
                endpoint_peers,
                ..DataPlaneSummary::default()
            });
        }
        let mesh = inventory.config.mesh.clone().ok_or_else(|| {
            anyhow!("network `{network}` has managed mesh enabled but no mesh config")
        })?;
        configure_loopback_internal_addresses(&mesh, local.internal.as_ref())?;
        let babel_overlay_changes = reconcile_babel_overlays(
            &config.wireguard.interface,
            &local.host_id,
            &local_wireguard.ipv4,
            &peers,
            mesh.overlay_mtu,
        )?;
        configure_mesh_sysctls(config.mode, &config.wireguard.interface)?;
        apply_bird_config(
            state.config.routing.bird()?,
            &mesh,
            &local,
            config.mode,
            &babel_overlay_changes,
        )?;
        Ok(DataPlaneSummary {
            required_babel_routes,
            endpoint_peers,
        })
    }
}

fn local_network_names(state: &AppState, inventory: &CachedInventory) -> Vec<String> {
    inventory
        .networks
        .iter()
        .filter(|(_, network)| network.members.contains_key(&state.config.host.host_id))
        .map(|(name, _)| name.clone())
        .collect()
}

fn local_network_member<'a>(
    state: &AppState,
    inventory: &'a ResolvedNetwork,
    network: &str,
) -> Result<&'a InventoryHost> {
    inventory
        .hosts
        .iter()
        .find(|host| host.host_id == state.config.host.host_id)
        .ok_or_else(|| {
            anyhow!(
                "local host `{}` is missing from the `{network}` network inventory",
                state.config.host.host_id
            )
        })
}

fn required_babel_backbone_routes(peers: &[&InventoryHost]) -> Result<BTreeSet<IpAddr>> {
    let mut routes = BTreeSet::new();
    for peer in peers
        .iter()
        .filter(|peer| !peer.pending && peer.mode == AegisHostMode::Hub)
    {
        let internal = peer.internal.as_ref().ok_or_else(|| {
            anyhow!(
                "Babel backbone peer `{}` has no internal mesh addresses",
                peer.alias()
            )
        })?;
        for address in [&internal.ipv4, &internal.ipv6] {
            routes.insert(address.parse::<IpAddr>().with_context(|| {
                format!(
                    "Babel backbone peer `{}` has invalid internal address `{address}`",
                    peer.alias()
                )
            })?);
        }
    }
    Ok(routes)
}

fn poll_babel_readiness(required_routes: &BTreeSet<IpAddr>) -> AgentBabelStatus {
    if required_routes.is_empty() {
        return AgentBabelStatus {
            ready: true,
            ready_unix: Some(now_unix()),
            stable_polls: BABEL_ROUTE_READY_STABLE_POLLS,
            ..AgentBabelStatus::default()
        };
    }

    let deadline = Instant::now() + BABEL_ROUTE_READY_TIMEOUT;
    let mut stable_polls = 0u8;
    loop {
        let snapshot = current_babel_route_snapshot();
        stable_polls = if babel_routes_complete(&snapshot, required_routes) {
            stable_polls
                .saturating_add(1)
                .min(BABEL_ROUTE_READY_STABLE_POLLS)
        } else {
            0
        };
        let mut status = babel_status_from_snapshot(&snapshot, required_routes, stable_polls, None);
        if status.ready {
            status.ready_unix = Some(now_unix());
            return status;
        }
        if Instant::now() >= deadline {
            if status.last_error.is_none() {
                status.last_error = Some(format!(
                    "Babel backbone routes did not become ready within {}s",
                    BABEL_ROUTE_READY_TIMEOUT.as_secs()
                ));
            }
            return status;
        }
        thread::sleep(BABEL_ROUTE_READY_POLL_INTERVAL);
    }
}

#[cfg(target_os = "linux")]
fn current_babel_route_snapshot() -> BabelRouteSnapshot {
    let mut command = Command::new("/usr/bin/timeout");
    command.args([
        "--signal=KILL",
        BABEL_STATUS_COMMAND_TIMEOUT,
        "birdc",
        "-r",
        &format!("show route protocol {BABEL_PROTOCOL_NAME} all"),
    ]);
    match run_capture(&mut command) {
        Ok(output) if output.status.success() => parse_babel_route_snapshot(&output.stdout),
        Ok(output) => BabelRouteSnapshot {
            last_error: Some(command_output_error(&output)),
            ..BabelRouteSnapshot::default()
        },
        Err(error) => BabelRouteSnapshot {
            last_error: Some(error.to_string()),
            ..BabelRouteSnapshot::default()
        },
    }
}

#[cfg(target_os = "linux")]
fn parse_babel_route_snapshot(output: &str) -> BabelRouteSnapshot {
    let mut latest_route_update = None::<String>;
    let mut routes = BTreeSet::new();
    for line in output.lines() {
        let Some((route, route_update)) = babel_route(line) else {
            continue;
        };
        routes.insert(route);
        if latest_route_update
            .as_deref()
            .is_none_or(|latest| route_update > latest)
        {
            latest_route_update = Some(route_update.to_string());
        }
    }
    BabelRouteSnapshot {
        routes,
        latest_route_update,
        last_error: None,
    }
}

#[cfg(target_os = "linux")]
fn babel_route(line: &str) -> Option<(IpAddr, &str)> {
    let route_update = babel_route_update(line)?;
    let prefix = line.split_ascii_whitespace().next()?;
    let (address, prefix_length) = prefix.split_once('/')?;
    let address = address.parse::<IpAddr>().ok()?;
    let prefix_length = prefix_length.parse::<u8>().ok()?;
    if prefix_length != if address.is_ipv4() { 32 } else { 128 } {
        return None;
    }
    Some((address, route_update))
}

fn babel_routes_complete(
    snapshot: &BabelRouteSnapshot,
    required_routes: &BTreeSet<IpAddr>,
) -> bool {
    snapshot.last_error.is_none() && required_routes.is_subset(&snapshot.routes)
}

fn babel_status_from_snapshot(
    snapshot: &BabelRouteSnapshot,
    required_routes: &BTreeSet<IpAddr>,
    stable_polls: u8,
    ready_unix: Option<u64>,
) -> AgentBabelStatus {
    let missing_routes = required_routes
        .difference(&snapshot.routes)
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let complete = snapshot.last_error.is_none() && missing_routes.is_empty();
    AgentBabelStatus {
        ready: complete && stable_polls >= BABEL_ROUTE_READY_STABLE_POLLS,
        ready_unix,
        latest_route_update: snapshot.latest_route_update.clone(),
        learned_route_count: snapshot.routes.len(),
        stable_polls,
        last_error: snapshot.last_error.clone().or_else(|| {
            (!missing_routes.is_empty()).then(|| {
                format!(
                    "Babel is missing required backbone routes: {}",
                    missing_routes.join(", ")
                )
            })
        }),
    }
}

#[cfg(target_os = "linux")]
fn babel_route_update(line: &str) -> Option<&str> {
    let marker = format!("[{BABEL_PROTOCOL_NAME} ");
    let raw = line.split_once(&marker)?.1.split_once(']')?.0.trim();
    if raw.len() >= "YYYY-MM-DD HH:MM:SS.mmm".len() {
        let route_update = &raw[.."YYYY-MM-DD HH:MM:SS.mmm".len()];
        if route_update_matches_iso_long_ms(route_update) {
            return Some(route_update);
        }
    }
    (!raw.is_empty()).then_some(raw)
}

#[cfg(target_os = "linux")]
fn route_update_matches_iso_long_ms(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 23
        && bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && bytes[10] == b' '
        && bytes[11..13].iter().all(u8::is_ascii_digit)
        && bytes[13] == b':'
        && bytes[14..16].iter().all(u8::is_ascii_digit)
        && bytes[16] == b':'
        && bytes[17..19].iter().all(u8::is_ascii_digit)
        && bytes[19] == b'.'
        && bytes[20..23].iter().all(u8::is_ascii_digit)
}

fn command_output_error(output: &crate::command::CommandOutput) -> String {
    let stderr = output.stderr.trim();
    if !stderr.is_empty() {
        return stderr.lines().next().unwrap_or(stderr).to_string();
    }
    let stdout = output.stdout.trim();
    if !stdout.is_empty() {
        return stdout.lines().next().unwrap_or(stdout).to_string();
    }
    format!(
        "birdc exited with status {}",
        output.status.code().unwrap_or(1)
    )
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn fetch_inventory(state: &AppState) -> Result<FetchedInventory> {
    let token = access_token(state)?;
    let api = state.api.clone();
    let report = host_report_request(state)?;
    let reported_wireguard_peers = wireguard_peer_keys(&report.direct_gateway);
    publish_host_report(state, &token, &report)?;
    let hosts = api.get_hosts(&token)?.hosts;
    let mut networks = BTreeMap::new();
    for (name, config) in api.get_networks(&token)?.networks {
        let members = api.get_network_members(&token, &name)?.members;
        networks.insert(name, CachedNetwork { config, members });
    }
    let default_network = networks
        .get(DEFAULT_AEGIS_NETWORK)
        .ok_or_else(|| anyhow!("aegis API has no `{DEFAULT_AEGIS_NETWORK}` network"))?;
    default_network.config.mesh.as_ref().ok_or_else(|| {
        anyhow!("`{DEFAULT_AEGIS_NETWORK}` network does not publish a managed mesh")
    })?;
    Ok(FetchedInventory {
        inventory: CachedInventory {
            api_base: state.config.api_base.clone(),
            hosts,
            networks,
        },
        reported_wireguard_peers,
    })
}

fn publish_host_report_after_peer_change(
    state: &AppState,
    reported_wireguard_peers: &BTreeSet<String>,
) -> Result<()> {
    let report = host_report_request(state)?;
    if wireguard_peer_keys(&report.direct_gateway) == *reported_wireguard_peers {
        return Ok(());
    }
    let token = access_token(state)?;
    publish_host_report(state, &token, &report)
}

fn publish_host_report(
    state: &AppState,
    token: &str,
    report: &AegisHostReportRequest,
) -> Result<()> {
    let response = state
        .api
        .report_host(token, &state.config.host.host_id, report)?;
    let mut store = crate::principal_grants::PrincipalGrantStore::load()?;
    if store.reconcile(response.principal_grants)? {
        store.persist()?;
    }
    Ok(())
}

fn wireguard_peer_keys(report: &AegisDirectGatewayReport) -> BTreeSet<String> {
    report
        .peers
        .iter()
        .map(|peer| peer.public_key.clone())
        .collect()
}

fn fetch_direct_gateway_plan(
    state: &AppState,
    inventory: &CachedInventory,
) -> Result<DirectGatewayPlan> {
    if !state
        .platform
        .supports(aegis_dto::platform::Capability::DirectGateway)
    {
        return Ok(DirectGatewayPlan::Unsupported);
    }
    let token = access_token(state)?;
    let api = state.api.clone();
    let direct = api.get_direct_gateway_inventory(&token, &state.config.host.host_id)?;
    let config = AegisDirectGatewayConfig {
        interface: direct.config.interface,
        endpoint_port: direct.config.endpoint_port,
        mtu: direct.config.mtu,
        fwmark: direct.config.fwmark,
        subnet_ipv4: direct.config.subnet_ipv4,
        subnet_ipv6: direct.config.subnet_ipv6,
        full_tunnel_dns: direct.config.full_tunnel_dns,
    };
    if !direct.enabled {
        return Ok(DirectGatewayPlan::Disabled {
            config,
            remove_published: direct.published.is_some(),
        });
    }
    let wireguard = managed_wireguard_config(&config.interface);
    ensure_wireguard_keypair(&wireguard)?;
    let public_key = aegis_dto::normalize_wireguard_key(
        &fs::read_to_string(&wireguard.public_key_path)
            .with_context(|| format!("failed to read {}", wireguard.public_key_path.display()))?,
    )
    .with_context(|| {
        format!(
            "invalid WireGuard public key at {}",
            wireguard.public_key_path.display()
        )
    })?;
    let endpoints = local_public_endpoint_ips(state, inventory);
    if endpoints.is_empty() {
        let alias = inventory
            .hosts
            .get(&state.config.host.host_id)
            .map(|host| host.aliases.primary().to_string())
            .unwrap_or_else(|| state.config.host.host_id.to_string());
        bail!(
            "no public direct-gateway endpoint was detected on `{}`",
            alias
        );
    }
    let aliases = inventory
        .hosts
        .get(&state.config.host.host_id)
        .map(|host| host.aliases.clone())
        .ok_or_else(|| anyhow!("host inventory does not contain the local host"))?;
    let pool = config.address_pool();
    let gateway = AegisDirectGateway {
        host_id: state.config.host.host_id,
        aliases,
        wireguard: AegisDirectWireGuard {
            public_key,
            ipv4: aegis_dto::wireguard_ipv4_for_host_id(&pool, 1)
                .map_err(|error| anyhow!(error))?,
            ipv6: aegis_dto::wireguard_ipv6_for_host_id(&pool, 1)
                .map_err(|error| anyhow!(error))?,
            endpoints,
        },
        updated_unix: direct
            .published
            .as_ref()
            .map(|gateway| gateway.updated_unix)
            .unwrap_or_default(),
    };
    let configuring = direct.published.as_ref().is_none_or(|published| {
        published.host_id != gateway.host_id
            || published.aliases != gateway.aliases
            || published.wireguard.public_key != gateway.wireguard.public_key
            || published.wireguard.ipv4 != gateway.wireguard.ipv4
            || published.wireguard.ipv6 != gateway.wireguard.ipv6
            || published.wireguard.endpoints != gateway.wireguard.endpoints
    });
    let inventory = DirectGatewayState {
        config,
        gateway,
        direct_client_ca_public_key: direct.direct_client_ca_public_key,
        satellites: direct
            .satellites
            .into_iter()
            .map(|satellite| AegisDirectSatellite {
                slug: satellite.slug,
                account: satellite.account,
                ssh_principal: satellite.ssh_principal,
                wireguard: AegisDirectWireGuard {
                    public_key: satellite.wireguard.public_key,
                    ipv4: satellite.wireguard.ipv4,
                    ipv6: satellite.wireguard.ipv6,
                    endpoints: satellite.wireguard.endpoints,
                },
            })
            .collect(),
    };
    if configuring {
        Ok(DirectGatewayPlan::Configuring(inventory))
    } else {
        Ok(DirectGatewayPlan::Ready(inventory))
    }
}

fn fetch_egress_plane(state: &AppState) -> Result<AegisEgressInventory> {
    let token = access_token(state)?;
    let api = state.api.clone();
    let mut inventory = api.get_egress_inventory(&token)?;
    let wireguard = managed_wireguard_config(&inventory.config.interface);
    ensure_wireguard_keypair(&wireguard)?;
    let public_key = aegis_dto::normalize_wireguard_key(
        &fs::read_to_string(&wireguard.public_key_path)
            .with_context(|| format!("failed to read {}", wireguard.public_key_path.display()))?,
    )
    .with_context(|| {
        format!(
            "invalid WireGuard public key at {}",
            wireguard.public_key_path.display()
        )
    })?;
    let published_key = inventory
        .hosts
        .get(&state.config.host.host_id)
        .map(|host| host.public_key.as_str());
    if published_key != Some(public_key.as_str()) {
        api.put_egress_identity(
            &token,
            &state.config.host.host_id,
            &AegisEgressIdentityRequest { public_key },
        )?;
        inventory = api.get_egress_inventory(&token)?;
    }
    let local = inventory
        .hosts
        .get(&state.config.host.host_id)
        .ok_or_else(|| {
            anyhow!(
                "egress inventory does not contain local host `{}` after identity publication",
                state.config.host.host_id
            )
        })?;
    ensure_local_wireguard_public_key(&wireguard, &local.public_key)?;
    Ok(inventory)
}

fn local_public_endpoint_ips(state: &AppState, inventory: &CachedInventory) -> Vec<String> {
    let mut endpoints = crate::metadata::gce_wireguard_endpoint_ips();
    if let Some(host) = inventory.hosts.get(&state.config.host.host_id) {
        endpoints.extend(
            [
                host.report.observed_public_ips.ipv6.as_ref(),
                host.report.observed_public_ips.ipv4.as_ref(),
            ]
            .into_iter()
            .flatten()
            .map(|observed| observed.ip.clone()),
        );
    }
    for network in inventory.networks.values() {
        if let Some(member) = network.members.get(&state.config.host.host_id)
            && let Some(wireguard) = member.wireguard.as_ref()
        {
            endpoints.extend(wireguard.endpoints.iter().cloned());
        }
    }
    endpoints.retain(|endpoint| endpoint.parse::<IpAddr>().is_ok());
    endpoints.sort();
    endpoints.dedup();
    endpoints
}

fn host_report_request(state: &AppState) -> Result<AegisHostReportRequest> {
    let mut runtime = state.runtime.lock().expect("lock").status();
    let lockdown = if state
        .platform
        .supports(aegis_dto::platform::Capability::SshLockdown)
    {
        crate::app::lockdown::host_report()
    } else {
        crate::app::lockdown::HostReport {
            enabled: false,
            warning: None,
        }
    };
    let mut messages = local_host_messages(state.platform);
    if let Some(alert) = state.credentials.lock().expect("lock").alert() {
        runtime.last_reconcile_error = Some(alert.value.clone());
        messages.push(alert);
    }
    messages.extend(lockdown.warning);
    Ok(AegisHostReportRequest {
        messages,
        agent: AegisAgentStatus {
            version: env!("CARGO_PKG_VERSION").to_string(),
            health: AegisAgentHealth {
                boot_id: runtime.boot_id,
                reconciled_since_boot: runtime.reconciled_since_boot,
                applied_aliases: runtime.applied_aliases,
                last_reconcile_unix: runtime.last_reconcile_unix,
                last_reconcile_warning: runtime.last_reconcile_warning,
                last_reconcile_error: runtime.last_reconcile_error,
            },
            reported_unix: now_unix() as i64,
        },
        principal_grants: crate::principal_grants::PrincipalGrantStore::load()?.grants,
        ssh_lockdown_enabled: lockdown.enabled,
        direct_gateway: if state
            .platform
            .supports(aegis_dto::platform::Capability::DirectGateway)
        {
            live_wireguard_peer_report()?
        } else {
            AegisDirectGatewayReport {
                observed_unix: now_unix() as i64,
                peers: Vec::new(),
            }
        },
    })
}

fn live_wireguard_peer_report() -> Result<AegisDirectGatewayReport> {
    let output = Command::new("wg")
        .args(["show", "all", "latest-handshakes"])
        .output()
        .context("failed to inspect live WireGuard peer handshakes")?;
    if !output.status.success() {
        bail!(
            "failed to inspect live WireGuard peer handshakes: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(AegisDirectGatewayReport {
        observed_unix: now_unix() as i64,
        peers: parse_live_wireguard_handshakes(&String::from_utf8_lossy(&output.stdout))?,
    })
}

fn parse_live_wireguard_handshakes(raw: &str) -> Result<Vec<AegisDirectPeerObservation>> {
    let mut handshakes = BTreeMap::<String, Option<i64>>::new();
    for line in raw.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let (public_key, timestamp) = match fields.as_slice() {
            [public_key, timestamp] | [_, public_key, timestamp] => (*public_key, *timestamp),
            _ => bail!("unexpected `wg show all latest-handshakes` line: {line}"),
        };
        let public_key = aegis_dto::normalize_wireguard_key(public_key)
            .context("live WireGuard peer has an invalid public key")?;
        let timestamp = timestamp
            .parse::<i64>()
            .with_context(|| format!("invalid WireGuard handshake timestamp `{timestamp}`"))?;
        let timestamp = (timestamp > 0).then_some(timestamp);
        handshakes
            .entry(public_key)
            .and_modify(|current| *current = (*current).max(timestamp))
            .or_insert(timestamp);
    }
    Ok(handshakes
        .into_iter()
        .map(
            |(public_key, latest_handshake_unix)| AegisDirectPeerObservation {
                public_key,
                latest_handshake_unix,
            },
        )
        .collect())
}

fn load_cached_inventory(state: &AppState) -> Result<CachedInventory> {
    if let Some(path) = &state.config.cache_path {
        return load_cached_inventory_file(path, &state.config.api_base)?
            .ok_or_else(|| anyhow!("failed to read {}", path.display()));
    }

    bail!("aegis-agent cache is unavailable")
}

fn persist_inventory(state: &AppState, inventory: &CachedInventory) -> Result<()> {
    if let Some(path) = &state.config.cache_path {
        persist_inventory_file(path, inventory)?;
    }
    Ok(())
}

fn access_token(state: &AppState) -> Result<String> {
    access_token_with_refresh(state, false)
}

fn force_access_token_refresh(state: &AppState) -> Result<String> {
    access_token_with_refresh(state, true)
}

fn access_token_with_refresh(state: &AppState, force_refresh: bool) -> Result<String> {
    let now = crate::config::now_unix();
    crate::tunnel_operation::lock(&state.credentials)?.access_token(
        now,
        force_refresh,
        |refresh_token| {
            let access = state.api.exchange_agent_refresh_token(refresh_token, now)?;
            ensure!(
                access.host_id == state.config.host.host_id,
                "agent token is for host `{}`, but local config is for `{}`",
                access.host_id,
                state.config.host.host_id
            );
            Ok(access)
        },
        |token| persist_agent_refresh_token(state, token),
    )
}

fn persist_agent_refresh_token(state: &AppState, refresh_token: &str) -> Result<()> {
    let raw = fs::read_to_string(&state.config_path)
        .with_context(|| format!("failed to read {}", state.config_path.display()))?;
    let mut config = AgentConfig::parse_toml(&raw)
        .with_context(|| format!("failed to load {}", state.config_path.display()))?;
    if config.host.host_id != state.config.host.host_id {
        bail!("the persisted aegis-agent config changed host identity");
    }
    config.auth.refresh_token = refresh_token.to_string();
    persist_agent_config(&state.config_path, &config)?;
    Ok(())
}

fn sync_network_member(
    state: &AppState,
    network: &str,
    config: &NetworkAgentConfig,
) -> Result<bool> {
    ensure_wireguard_keypair(&config.wireguard)?;
    let token = access_token(state)?;
    let api = state.api.clone();
    let desired = desired_network_member_put_request(config)?;
    let needs_update = api
        .get_network_members(&token, network)?
        .members
        .into_iter()
        .find(|(host_id, _)| host_id == &state.config.host.host_id)
        .map(|(_, current)| network_member_needs_update(&current, &desired, config.managed_mesh))
        .unwrap_or(true);
    if needs_update {
        api.put_network_member(&token, network, &state.config.host.host_id, &desired)?;
    }
    Ok(needs_update)
}

fn sync_local_ssh(
    state: &AppState,
    inventory: &CachedInventory,
    direct_gateway: &DirectGatewayPlan,
) -> Result<()> {
    if state.config.host.port.is_none() {
        return disable_local_ssh(&state.config.host);
    }

    let network_name = DEFAULT_AEGIS_NETWORK;
    let network = inventory
        .resolve_network(network_name)?
        .filter(|network| network.config.managed_ssh)
        .ok_or_else(|| anyhow!("`{network_name}` is not a managed-SSH Aegis network"))?;
    let local = network
        .hosts
        .iter()
        .find(|host| host.host_id == state.config.host.host_id)
        .ok_or_else(|| {
            anyhow!(
                "local host `{}` is not a member of managed-SSH network `{network_name}`",
                state.config.host.host_id
            )
        })?;
    let api = state.api.clone();
    let client_ca = api.get_client_ca_public_key()?;
    let server_ca = api.get_server_ca_public_key()?;
    let host_public_key = fs::read_to_string(&state.config.host.host_public_key_path)
        .with_context(|| {
            format!(
                "failed to read {}",
                state.config.host.host_public_key_path.display()
            )
        })?;
    let key_id = format!("host:{network_name}:{}", state.config.host.host_id);
    let principals = host_certificate_principals(
        &state.config.host.host_id,
        &local.aliases,
        &network.config,
        local,
        direct_gateway,
    )?;
    let server_certificate = match reusable_host_certificate(
        &state.config.host.host_certificate_path,
        &host_public_key,
        &server_ca.public_key,
        &key_id,
        &principals,
        now_unix(),
    )? {
        Some(certificate) => certificate,
        None => {
            let token = access_token(state)?;
            api.request_network_member_server_cert(
                &token,
                network_name,
                &state.config.host.host_id,
            )?
            .certificate
        }
    };
    let mut client_ca_public_keys = vec![client_ca.public_key];
    let direct_client_ca = match direct_gateway {
        DirectGatewayPlan::Configuring(state) | DirectGatewayPlan::Ready(state) => {
            Some(state.direct_client_ca_public_key.clone())
        }
        DirectGatewayPlan::Preserve => {
            read_optional_trimmed_text(Path::new(aegis_dto::layout::DIRECT_CLIENT_CA_PATH))?
        }
        DirectGatewayPlan::Disabled { .. } | DirectGatewayPlan::Unsupported => None,
    };
    if let Some(direct_client_ca) = direct_client_ca {
        client_ca_public_keys.push(direct_client_ca);
    }
    apply_host_ssh(
        &state.config.host,
        &client_ca_public_keys.join("\n"),
        &server_certificate,
        &crate::principal_grants::PrincipalGrantStore::load()?.grants,
    )
}

fn host_certificate_principals(
    host_id: &HostId,
    aliases: &HostAliases,
    network: &AegisNetworkConfig,
    local: &InventoryHost,
    direct_gateway: &DirectGatewayPlan,
) -> Result<HostCertificatePrincipals> {
    let ssh = local.ssh.as_ref().ok_or_else(|| {
        anyhow!("local host `{host_id}` has no managed SSH identity in the inventory")
    })?;
    let mut required = ssh
        .internal_principals
        .iter()
        .chain(&ssh.external_principals)
        .cloned()
        .collect::<BTreeSet<_>>();
    required.extend(aliases.iter().map(ToString::to_string));
    if let Some(suffix) = network
        .host_dns_suffix
        .as_deref()
        .map(str::trim)
        .filter(|suffix| !suffix.is_empty())
    {
        required.extend(
            aliases
                .iter()
                .map(|alias| format!("{alias}.{}", suffix.trim_start_matches('.'))),
        );
    }
    match direct_gateway {
        DirectGatewayPlan::Configuring(inventory) | DirectGatewayPlan::Ready(inventory) => {
            required.insert(inventory.gateway.wireguard.ipv4.clone());
            required.insert(inventory.gateway.wireguard.ipv6.clone());
        }
        DirectGatewayPlan::Disabled { .. } | DirectGatewayPlan::Unsupported => {}
        DirectGatewayPlan::Preserve => {
            return Ok(HostCertificatePrincipals {
                required,
                exact: false,
            });
        }
    }
    Ok(HostCertificatePrincipals {
        required,
        exact: true,
    })
}

fn reusable_host_certificate(
    path: &Path,
    host_public_key: &str,
    server_ca_public_key: &str,
    key_id: &str,
    principals: &HostCertificatePrincipals,
    now_unix: u64,
) -> Result<Option<String>> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    let Ok(certificate) = Certificate::from_openssh(&raw) else {
        return Ok(None);
    };
    let host_public_key = PublicKey::from_openssh(host_public_key)
        .context("managed SSH host public key is invalid")?;
    let server_ca_public_key = PublicKey::from_openssh(server_ca_public_key)
        .context("Aegis SSH server CA public key is invalid")?;
    let server_ca_fingerprint = server_ca_public_key.fingerprint(HashAlg::Sha256);
    let actual_principals = certificate
        .valid_principals()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let lifetime = certificate
        .valid_before()
        .saturating_sub(certificate.valid_after());
    let renewal_unix = certificate
        .valid_after()
        .saturating_add(lifetime.saturating_mul(2) / 3);
    let principals_match = if principals.exact {
        actual_principals == principals.required
    } else {
        principals.required.is_subset(&actual_principals)
    };
    if certificate.cert_type() != CertType::Host
        || certificate.key_id() != key_id
        || certificate.public_key() != host_public_key.key_data()
        || certificate.signature_key() != server_ca_public_key.key_data()
        || !principals_match
        || !certificate.critical_options().is_empty()
        || !certificate.extensions().is_empty()
        || now_unix >= renewal_unix
        || certificate
            .validate_at(now_unix, [&server_ca_fingerprint])
            .is_err()
    {
        return Ok(None);
    }
    Ok(Some(raw.trim().to_string()))
}

fn desired_network_member_put_request(
    config: &NetworkAgentConfig,
) -> Result<AegisPutNetworkMemberRequest> {
    let wireguard_public_key =
        fs::read_to_string(&config.wireguard.public_key_path).with_context(|| {
            format!(
                "failed to read {}",
                config.wireguard.public_key_path.display()
            )
        })?;
    Ok(AegisPutNetworkMemberRequest {
        mode: match config.mode {
            AgentMode::Hub => AegisHostMode::Hub,
            AgentMode::Leaf => AegisHostMode::Leaf,
        },
        wireguard: Some(AegisPutNetworkMemberWireGuard {
            public_key: wireguard_public_key.trim().to_string(),
            ipv4: None,
            ipv6: None,
            endpoints: if config.mode == AgentMode::Hub {
                gce_wireguard_endpoint_ips()
            } else {
                Vec::new()
            },
        }),
        pending: false,
    })
}

fn network_member_needs_update(
    current: &AegisNetworkMember,
    desired: &AegisPutNetworkMemberRequest,
    managed_mesh: bool,
) -> bool {
    current.mode != desired.mode
        || current.pending
        || current
            .wireguard
            .as_ref()
            .map(|wireguard| wireguard.public_key.as_str())
            != desired
                .wireguard
                .as_ref()
                .map(|wireguard| wireguard.public_key.as_str())
        || current
            .wireguard
            .as_ref()
            .map(|wireguard| wireguard.endpoints.as_slice())
            .unwrap_or(&[])
            != desired
                .wireguard
                .as_ref()
                .map(|wireguard| wireguard.endpoints.as_slice())
                .unwrap_or(&[])
        || current.wireguard.is_none()
        || (managed_mesh && current.internal.is_none())
}

fn local_host_messages(platform: aegis_dto::platform::HostPlatform) -> Vec<AegisHostMessage> {
    if platform.operating_system == aegis_dto::platform::OperatingSystem::Ubuntu {
        bird3_apt_source_message().into_iter().collect()
    } else {
        Vec::new()
    }
}

fn bird3_apt_source_message() -> Option<AegisHostMessage> {
    let architecture = match native_dpkg_architecture() {
        Ok(architecture) => architecture,
        Err(error) => {
            return Some(host_warning_message(format!(
                "Bird3 apt source could not be checked because dpkg architecture detection failed: {error}"
            )));
        }
    };
    for (path, label) in [
        (BIRD3_APT_SOURCE_PATH, "apt source"),
        (BIRD3_APT_KEYRING_PATH, "repository keyring"),
    ] {
        if let Some(message) = bird3_repository_file_message(path, label) {
            return Some(message);
        }
    }
    let source = match fs::read_to_string(BIRD3_APT_SOURCE_PATH) {
        Ok(source) => source,
        Err(error) => {
            return Some(host_warning_message(format!(
                "Bird3 apt source at {BIRD3_APT_SOURCE_PATH} could not be inspected: {error}"
            )));
        }
    };
    let blocks = bird3_source_blocks(&source);
    if matches!(blocks.as_slice(), [block] if bird3_source_block_is_managed(block, &architecture)) {
        return None;
    }
    Some(host_warning_message(format!(
        "Bird3 apt source is misconfigured; {BIRD3_APT_SOURCE_PATH} must use {BIRD3_APT_REPOSITORY} with Architectures: {architecture} and Signed-By: {BIRD3_APT_KEYRING_PATH}. Run `aegis advanced redeploy` to reinstall it."
    )))
}

fn bird3_repository_file_message(path: &str, label: &str) -> Option<AegisHostMessage> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Some(host_warning_message(format!(
                "Bird3 {label} is missing at {path}; run `aegis advanced redeploy` to reinstall it."
            )));
        }
        Err(error) => {
            return Some(host_warning_message(format!(
                "Bird3 {label} at {path} could not be inspected: {error}"
            )));
        }
    };
    let mode = metadata.mode() & 0o7777;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || mode != 0o644
    {
        return Some(host_warning_message(format!(
            "Bird3 {label} at {path} must be a root-owned regular file with mode 0644 (found uid {}, gid {}, mode {mode:04o}); run `aegis advanced redeploy` to reinstall it.",
            metadata.uid(),
            metadata.gid(),
        )));
    }
    None
}

fn host_warning_message(value: String) -> AegisHostMessage {
    AegisHostMessage {
        level: AegisHostMessageLevel::Warning,
        value,
    }
}

fn bird3_source_blocks(source: &str) -> Vec<BTreeMap<String, String>> {
    let mut blocks = Vec::new();
    let mut block: BTreeMap<String, String> = BTreeMap::new();
    let mut current_field: Option<String> = None;
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if !block.is_empty() {
                blocks.push(block);
                block = BTreeMap::new();
                current_field = None;
            }
            continue;
        }
        if trimmed.starts_with('#') {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(field) = current_field.as_ref() {
                block.entry(field.clone()).and_modify(|value: &mut String| {
                    value.push(' ');
                    value.push_str(trimmed);
                });
            }
            continue;
        }
        let Some((field, value)) = trimmed.split_once(':') else {
            block.insert(String::new(), String::new());
            current_field = None;
            continue;
        };
        let field = field.trim().to_ascii_lowercase();
        block.insert(field.clone(), value.trim().to_string());
        current_field = Some(field);
    }
    if !block.is_empty() {
        blocks.push(block);
    }
    blocks
}

fn bird3_source_block_is_managed(block: &BTreeMap<String, String>, architecture: &str) -> bool {
    bird3_source_field_contains(block, "types", "deb")
        && bird3_source_field_contains(block, "uris", BIRD3_APT_REPOSITORY)
        && block
            .get("suites")
            .is_some_and(|value| value.split_whitespace().next().is_some())
        && bird3_source_field_contains(block, "components", "main")
        && bird3_source_field_contains(block, "architectures", architecture)
        && bird3_source_field_contains(block, "signed-by", BIRD3_APT_KEYRING_PATH)
}

fn bird3_source_field_contains(
    block: &BTreeMap<String, String>,
    field: &str,
    expected: &str,
) -> bool {
    block
        .get(field)
        .is_some_and(|value| value.split_whitespace().any(|part| part == expected))
}

fn native_dpkg_architecture() -> Result<String> {
    let output = require_success(
        "detect native Debian architecture",
        Command::new("dpkg").arg("--print-architecture"),
    )?;
    let architecture = output.stdout.trim();
    if architecture.is_empty() {
        bail!("dpkg --print-architecture returned an empty architecture");
    }
    Ok(architecture.to_string())
}

fn apply_host_ssh(
    config: &AgentHostConfig,
    client_ca_public_key: &str,
    server_certificate: &str,
    principal_grants: &[AegisPrincipalGrant],
) -> Result<()> {
    ensure_directory(&config.authorized_principals_dir)?;
    let principals = authorized_principals_by_login_principal(&config.host_id, principal_grants);
    let client_ca = line_with_newline(client_ca_public_key);
    let server_certificate = line_with_newline(server_certificate);
    let sshd_dropin = sshd_install_dropin_contents(
        &config.client_ca_path.display().to_string(),
        &format!("{}/%u", config.authorized_principals_dir.display()),
        Some(&config.host_private_key_path.display().to_string()),
        Some(&config.host_certificate_path.display().to_string()),
    );
    let mut desired_files = BTreeMap::from([
        (
            config.client_ca_path.display().to_string(),
            client_ca.clone(),
        ),
        (
            config.host_certificate_path.display().to_string(),
            server_certificate.clone(),
        ),
        (
            config.sshd_dropin_path.display().to_string(),
            sshd_dropin.clone(),
        ),
    ]);
    for (login_principal, values) in &principals {
        desired_files.insert(
            config
                .authorized_principals_dir
                .join(login_principal)
                .display()
                .to_string(),
            line_with_newline(&values.join("\n")),
        );
    }
    let applied = AppliedConfig::new(
        SSHD_APPLIED_CONFIG_NAME,
        &serde_json::to_vec(&desired_files).context("failed to encode managed SSH state")?,
    );
    let mut changed = write_text_file_if_changed(&config.client_ca_path, &client_ca, Some(0o644))?;
    changed |= apply_authorized_principals(config, &principals)?;
    changed |= write_text_file_if_changed(
        &config.host_certificate_path,
        &server_certificate,
        Some(0o644),
    )?;
    changed |= write_text_file_if_changed(&config.sshd_dropin_path, &sshd_dropin, Some(0o644))?;
    #[cfg(target_os = "macos")]
    crate::ssh_service::ensure_certificate_integration()?;
    activate_sshd_if_needed(&applied, changed)
}

fn apply_authorized_principals(
    config: &AgentHostConfig,
    desired: &BTreeMap<String, Vec<String>>,
) -> Result<bool> {
    let mut changed = false;
    for entry in fs::read_dir(&config.authorized_principals_dir).with_context(|| {
        format!(
            "failed to read {}",
            config.authorized_principals_dir.display()
        )
    })? {
        let entry = entry.with_context(|| {
            format!(
                "failed to read entry in {}",
                config.authorized_principals_dir.display()
            )
        })?;
        let account = entry.file_name().to_string_lossy().to_string();
        if entry.file_type()?.is_file()
            && !desired.contains_key(&account)
            && !valid_direct_account(&account)
        {
            changed |= remove_file_if_exists_changed(&entry.path())?;
        }
    }
    for (login_principal, principals) in desired {
        changed |= write_text_file_if_changed(
            &config.authorized_principals_dir.join(login_principal),
            &line_with_newline(&principals.join("\n")),
            Some(0o644),
        )?;
    }
    Ok(changed)
}

fn disable_local_ssh(config: &AgentHostConfig) -> Result<()> {
    let applied = AppliedConfig::new(SSHD_APPLIED_CONFIG_NAME, b"disabled");
    let changed = remove_file_if_exists_changed(&config.sshd_dropin_path)?;
    if changed && sshd_is_active()? {
        reload_sshd()?;
    }
    applied.mark()
}

fn activate_sshd_if_needed(applied: &AppliedConfig, changed: bool) -> Result<()> {
    let active = sshd_is_active()?;
    let activation_required = config_activation_required(applied, changed)?;
    if active && !activation_required {
        return Ok(());
    }
    if !activation_required {
        applied.mark_pending()?;
    }
    validate_sshd()?;
    reload_sshd()?;
    applied.mark()
}

fn authorized_principals_by_login_principal(
    host_id: &HostId,
    principal_grants: &[AegisPrincipalGrant],
) -> BTreeMap<String, Vec<String>> {
    let mut grouped = BTreeMap::<String, Vec<String>>::new();
    for grant in principal_grants {
        let principal = aegis_user_cert_principal(host_id, &grant.login_principal, &grant.user_id);
        let principals = grouped.entry(grant.login_principal.clone()).or_default();
        if !principals.contains(&principal) {
            principals.push(principal);
        }
    }
    grouped
}

fn select_peers<'a>(
    mode: AgentMode,
    hosts: &'a [InventoryHost],
    local_host_id: &HostId,
) -> Vec<&'a InventoryHost> {
    let mut peers = hosts
        .iter()
        .filter(|host| host.host_id != *local_host_id && host.wireguard.is_some())
        .filter(|host| match mode {
            AgentMode::Hub => true,
            AgentMode::Leaf => !host.pending && host.mode == AegisHostMode::Hub,
        })
        .collect::<Vec<_>>();
    peers.sort_by(|left, right| left.alias().cmp(right.alias()));
    peers
}

fn reconcile_direct_gateway(plan: &DirectGatewayPlan) -> Result<()> {
    match plan {
        DirectGatewayPlan::Configuring(inventory) | DirectGatewayPlan::Ready(inventory) => {
            apply_direct_gateway_config(inventory)
        }
        DirectGatewayPlan::Disabled { config, .. } => disable_direct_gateway(config),
        DirectGatewayPlan::Preserve | DirectGatewayPlan::Unsupported => Ok(()),
    }
}

fn gateway_members(inventory: &AegisEgressInventory, local: HostId) -> Vec<&AegisEgressHost> {
    inventory
        .hosts
        .values()
        .filter(|host| host.host_id != local)
        .collect()
}

fn reconcile_egress_plane(state: &AppState) -> Result<()> {
    let _guard = crate::tunnel_operation::lock(&state.egress_lock)?;
    crate::tunnel_operation::bounded(Duration::from_secs(30), || {
        let mut inventory = fetch_egress_plane(state)?;
        let token = access_token(state)?;
        tunnel::recover_pending(state, &token, &mut inventory)?;
        let local_id = state.config.host.host_id;
        let local = inventory
            .hosts
            .get(&local_id)
            .context("local egress identity missing")?;
        let policy = inventory.policies.get(&local_id);
        let target = egress_target(&inventory, policy.and_then(|policy| policy.active_via))?;
        let sources = gateway_members(&inventory, local_id);
        let wireguard = managed_wireguard_config(&inventory.config.interface);
        let private_key = load_private_key(&wireguard.private_key_path)?;
        let config = egress_wireguard_config_contents(
            &inventory.config,
            local,
            &EgressWireGuardPeerPlan {
                default_target: target,
                gateway_sources: &sources,
            },
            &private_key,
        )?;
        restore_previous_egress_source_state(
            &EgressSourceTransition {
                config: &inventory.config,
                local,
                wireguard: &wireguard,
                private_key: &private_key,
                api_base: &state.config.api_base,
                active_target: target,
                desired_target: target,
                gateway_sources: &sources,
            },
            &config,
        )?;
        state.runtime.lock().expect("runtime").tunnel = agent_tunnel_status(policy, &inventory);
        Ok(())
    })
}

fn egress_target(
    inventory: &AegisEgressInventory,
    target_host_id: Option<HostId>,
) -> Result<Option<&AegisEgressHost>> {
    target_host_id
        .map(|target_host_id| {
            inventory.hosts.get(&target_host_id).ok_or_else(|| {
                anyhow!("egress policy references unknown target `{target_host_id}`")
            })
        })
        .transpose()
}

struct EgressSourceTransition<'a> {
    config: &'a AegisEgressConfig,
    local: &'a AegisEgressHost,
    wireguard: &'a WireGuardConfig,
    private_key: &'a str,
    api_base: &'a str,
    active_target: Option<&'a AegisEgressHost>,
    desired_target: Option<&'a AegisEgressHost>,
    gateway_sources: &'a [&'a AegisEgressHost],
}

fn reconcile_egress_source_transition(state: &EgressSourceTransition<'_>) -> Result<()> {
    let config = state.config;
    let local = state.local;
    let private_key = state.private_key;
    let api_base = state.api_base;
    let desired_target = state.desired_target;
    let gateway_sources = state.gateway_sources;
    if let Some(desired_target) = desired_target {
        crate::tunnel_operation::phase("Checking IPv4, IPv6 and DNS")?;
        crate::egress_probe::prove_candidate(CandidateProbe {
            config,
            local,
            target: desired_target,
            private_key,
            api_base,
        })
        .with_context(|| {
            format!(
                "candidate egress path through `{}` did not pass isolated dual-stack validation; the existing local route was not changed",
                desired_target.aliases.primary()
            )
        })?;
        // The isolated probe used this identity with a different UDP socket. Discard the
        // source interface's old session so the committed peer immediately handshakes
        // again, rather than waiting for WireGuard's retry timer with stale keys.
        require_success(
            "reset candidate WireGuard session",
            bounded_egress_command("/usr/bin/wg").args([
                "set",
                &config.interface,
                "peer",
                &desired_target.public_key,
                "remove",
            ]),
        )?;
    }

    crate::tunnel_operation::phase("Switching route")?;
    if let Some(desired_target) = desired_target {
        transition_egress_source_to_target(state, desired_target)
    } else {
        let direct = egress_wireguard_config_contents(
            config,
            local,
            &EgressWireGuardPeerPlan {
                default_target: None,
                gateway_sources,
            },
            private_key,
        )?;
        transition_egress_source_to_direct(state, &direct)
    }
}

fn transition_egress_source_to_target(
    state: &EgressSourceTransition<'_>,
    desired_target: &AegisEgressHost,
) -> Result<()> {
    let config = state.config;
    let local = state.local;
    let wireguard = state.wireguard;
    let private_key = state.private_key;
    let api_base = state.api_base;
    let active_target = state.active_target;
    let gateway_sources = state.gateway_sources;
    let committed = egress_wireguard_config_contents(
        config,
        local,
        &EgressWireGuardPeerPlan {
            default_target: Some(desired_target),
            gateway_sources,
        },
        private_key,
    )?;
    let gateway_routes = egress_gateway_routes(gateway_sources);
    if let Some(active_target) = active_target {
        let handoff = egress_wireguard_handoff_contents(
            config,
            local,
            active_target,
            desired_target,
            gateway_sources,
            private_key,
        )?;
        reconcile_egress_main_routes(config, &gateway_routes)?;
        apply_egress_nftables_runtime(EgressNftablesState {
            config,
            local,
            mode: LocalEgressMode::Tunnel,
            gateway_chained: true,
            target_sources: gateway_sources,
        })?;
        WireGuardRuntime::parse(&wireguard.interface, &handoff)?.reconcile()?;
        configure_egress_dns(config, desired_target)?;
        // Existing traffic remains on the active peer through the handoff state. This sync is
        // the single commit that moves the already-fail-closed interface to the new default peer.
        WireGuardRuntime::parse(&wireguard.interface, &committed)?.reconcile()?;
    } else {
        WireGuardRuntime::parse(&wireguard.interface, &committed)?.reconcile()?;
        apply_egress_nftables_runtime(EgressNftablesState {
            config,
            local,
            mode: LocalEgressMode::Staging,
            gateway_chained: false,
            target_sources: gateway_sources,
        })?;
        reconcile_egress_main_routes(config, &gateway_routes)?;
        prepare_egress_tunnel_routing(config, desired_target)?;
        // Replacing this table is the one local commit point: the staging mark disappears and
        // the fail-closed output guard appears in the same nftables transaction.
        apply_egress_nftables_runtime(EgressNftablesState {
            config,
            local,
            mode: LocalEgressMode::Tunnel,
            gateway_chained: true,
            target_sources: gateway_sources,
        })?;
    }
    crate::tunnel_operation::phase("Checking committed route")?;
    crate::egress_probe::prove_committed(CommittedProbe {
        local,
        target: desired_target,
        api_base,
    })
    .with_context(|| {
        format!(
            "committed egress path through `{}` failed dual-stack validation",
            desired_target.aliases.primary()
        )
    })?;

    apply_egress_wireguard_config(wireguard, local, &committed)?;
    apply_egress_policy_state(EgressPolicyState {
        config,
        local,
        selected_target: Some(desired_target),
        target_sources: gateway_sources,
    })
}

fn transition_egress_source_to_direct(
    state: &EgressSourceTransition<'_>,
    direct_wireguard: &str,
) -> Result<()> {
    let config = state.config;
    let local = state.local;
    let wireguard = state.wireguard;
    let gateway_sources = state.gateway_sources;
    commit_direct_egress_runtime(config, local, gateway_sources)?;
    WireGuardRuntime::parse(&wireguard.interface, direct_wireguard)?.reconcile()?;
    apply_egress_wireguard_config(wireguard, local, direct_wireguard)?;
    apply_egress_policy_state(EgressPolicyState {
        config,
        local,
        selected_target: None,
        target_sources: gateway_sources,
    })
}

fn restore_previous_egress_source_state(
    state: &EgressSourceTransition<'_>,
    previous_wireguard: &str,
) -> Result<()> {
    let config = state.config;
    let local = state.local;
    let wireguard = state.wireguard;
    let active_target = state.active_target;
    let gateway_sources = state.gateway_sources;
    let mut failures = Vec::new();
    if !wireguard_service_is_active(&wireguard_service_name(wireguard))? {
        record_egress_recovery(
            &mut failures,
            "WireGuard service",
            apply_egress_wireguard_config(wireguard, local, previous_wireguard),
        );
    }
    record_egress_recovery(
        &mut failures,
        "gateway forwarding",
        configure_egress_forwarding(&config.interface),
    );
    if let Some(active_target) = active_target {
        record_egress_recovery(
            &mut failures,
            "WireGuard",
            WireGuardRuntime::parse(&wireguard.interface, previous_wireguard)
                .and_then(|runtime| runtime.reconcile()),
        );
        record_egress_recovery(
            &mut failures,
            "tunneled routing",
            restore_tunneled_egress_runtime(config, local, active_target, gateway_sources),
        );
    } else {
        record_egress_recovery(
            &mut failures,
            "direct routing",
            restore_direct_egress_runtime(config, local, gateway_sources),
        );
        record_egress_recovery(
            &mut failures,
            "WireGuard",
            WireGuardRuntime::parse(&wireguard.interface, previous_wireguard)
                .and_then(|runtime| runtime.reconcile()),
        );
    }
    record_egress_recovery(
        &mut failures,
        "persistent WireGuard configuration",
        apply_egress_wireguard_config(wireguard, local, previous_wireguard),
    );
    record_egress_recovery(
        &mut failures,
        "persistent policy",
        apply_egress_policy_state(EgressPolicyState {
            config,
            local,
            selected_target: active_target,
            target_sources: gateway_sources,
        }),
    );
    if failures.is_empty() {
        Ok(())
    } else {
        bail!(failures.join("; "))
    }
}

fn record_egress_recovery(failures: &mut Vec<String>, phase: &str, result: Result<()>) {
    if let Err(error) = result {
        failures.push(format!("{phase}: {error:#}"));
    }
}

fn agent_tunnel_status(
    policy: Option<&AegisEgressPolicy>,
    inventory: &AegisEgressInventory,
) -> AgentTunnelStatus {
    let Some(policy) = policy else {
        return AgentTunnelStatus::Disabled;
    };
    if policy.is_steady() {
        return match policy.active_via {
            Some(host_id) => AgentTunnelStatus::Enabled {
                via: egress_host_alias(inventory, host_id),
            },
            None => AgentTunnelStatus::Disabled,
        };
    }
    AgentTunnelStatus::Reconciling {
        active_via: policy
            .active_via
            .map(|host_id| egress_host_alias(inventory, host_id)),
        desired_via: policy
            .desired_via
            .map(|host_id| egress_host_alias(inventory, host_id)),
    }
}

fn egress_host_alias(inventory: &AegisEgressInventory, host_id: HostId) -> String {
    inventory
        .hosts
        .get(&host_id)
        .map(|host| host.aliases.primary().to_string())
        .unwrap_or_else(|| host_id.to_string())
}

struct EgressWireGuardPeerPlan<'a> {
    default_target: Option<&'a AegisEgressHost>,
    gateway_sources: &'a [&'a AegisEgressHost],
}

fn egress_wireguard_config_contents(
    config: &AegisEgressConfig,
    local: &AegisEgressHost,
    peers: &EgressWireGuardPeerPlan<'_>,
    private_key: &str,
) -> Result<String> {
    let listen_port = WireGuardListenPort::for_listener(config.endpoint_port, true)?;
    let mut content = format!(
        "{MANAGED_CONFIG_HEADER}\
         [Interface]\n\
         Address = {}/32,{}/128,{}/32,{}/128\n\
         PrivateKey = {private_key}\n\
         ListenPort = {}\n\
         MTU = {}\n\
         FwMark = {}\n\
         Table = off\n\n",
        local.ipv4,
        local.ipv6,
        local.dns_ipv4,
        local.dns_ipv6,
        listen_port.config_port(),
        config.mtu,
        config.fwmark,
    );
    if let Some(target) = peers.default_target {
        append_egress_target_peer(&mut content, config, target, "0.0.0.0/0,::/0");
    }
    for source in peers.gateway_sources {
        if peers
            .default_target
            .is_some_and(|target| target.public_key == source.public_key)
        {
            continue;
        }
        content.push_str("[Peer]\n");
        content.push_str(&format!("PublicKey = {}\n", source.public_key));
        content.push_str(&format!(
            "AllowedIPs = {}/32,{}/128,{}/32,{}/128\n\n",
            source.ipv4, source.ipv6, source.dns_ipv4, source.dns_ipv6
        ));
    }
    if peers.default_target.is_none() && peers.gateway_sources.is_empty() {
        content.push_str("# No egress relationships are currently assigned to this host.\n");
    }
    Ok(content)
}

fn egress_wireguard_handoff_contents(
    config: &AegisEgressConfig,
    local: &AegisEgressHost,
    active_target: &AegisEgressHost,
    desired_target: &AegisEgressHost,
    gateway_sources: &[&AegisEgressHost],
    private_key: &str,
) -> Result<String> {
    let sources = gateway_sources
        .iter()
        .copied()
        .filter(|host| host.host_id != desired_target.host_id)
        .collect::<Vec<_>>();
    let mut content = egress_wireguard_config_contents(
        config,
        local,
        &EgressWireGuardPeerPlan {
            default_target: Some(active_target),
            gateway_sources: &sources,
        },
        private_key,
    )?;
    append_egress_target_peer(
        &mut content,
        config,
        desired_target,
        &format!(
            "{}/32,{}/128,{}/32,{}/128",
            desired_target.ipv4,
            desired_target.ipv6,
            desired_target.dns_ipv4,
            desired_target.dns_ipv6
        ),
    );
    Ok(content)
}

fn append_egress_target_peer(
    content: &mut String,
    config: &AegisEgressConfig,
    target: &AegisEgressHost,
    allowed_ips: &str,
) {
    content.push_str("[Peer]\n");
    content.push_str(&format!("PublicKey = {}\n", target.public_key));
    content.push_str(&format!(
        "Endpoint = {}:{}\n",
        target.internal_ipv4, config.endpoint_port
    ));
    content.push_str(&format!("AllowedIPs = {allowed_ips}\n"));
    content.push_str("PersistentKeepalive = 25\n\n");
}

fn apply_egress_wireguard_config(
    wireguard: &WireGuardConfig,
    local: &AegisEgressHost,
    desired_config: &str,
) -> Result<()> {
    ensure_local_wireguard_public_key(wireguard, &local.public_key)?;
    let runtime = WireGuardRuntime::parse(&wireguard.interface, desired_config)?;
    let quick_applied = wireguard_quick_applied_config(&wireguard.interface, desired_config)?;
    let quick_content_changed = wireguard_quick_config_changed(
        &wireguard.config_path,
        &wireguard.interface,
        &quick_applied,
    )?;
    ensure_directory_mode(Path::new(AEGIS_WIREGUARD_DIR), 0o755)?;
    ensure_wireguard_systemd_unit()?;
    write_text_file_if_changed(&wireguard.config_path, desired_config, Some(0o600))?;
    let service = wireguard_service_name(wireguard);
    ensure_service_enabled(&service, "Aegis egress WireGuard")?;
    let active = wireguard_service_is_active(&service)?;
    let quick_activation_required =
        config_activation_required(&quick_applied, quick_content_changed)?;
    let expected_addresses = BTreeSet::from([
        (local.ipv4.clone(), 32),
        (local.ipv6.clone(), 128),
        (local.dns_ipv4.clone(), 32),
        (local.dns_ipv6.clone(), 128),
    ]);
    if !active {
        if !quick_activation_required {
            quick_applied.mark_pending()?;
        }
        require_success(
            "start Aegis egress WireGuard service",
            bounded_egress_command("/usr/bin/systemctl").args(["start", &service]),
        )?;
        runtime.record_start()?;
        quick_applied.mark()?;
    } else if !wireguard_interface_address_set_matches(&wireguard.interface, &expected_addresses)?
        || quick_activation_required
    {
        require_success(
            "restart Aegis egress WireGuard after configuration change",
            bounded_egress_command("/usr/bin/systemctl").args(["restart", &service]),
        )?;
        runtime.record_start()?;
        quick_applied.mark()?;
    } else {
        runtime.reconcile()?;
    }
    Ok(())
}

fn configure_egress_forwarding(interface: &str) -> Result<()> {
    set_sysctl_if_changed(
        Path::new("/proc/sys/net/ipv4/ip_forward"),
        "net.ipv4.ip_forward",
        "1",
    )?;
    set_sysctl_if_changed(
        Path::new("/proc/sys/net/ipv6/conf/all/forwarding"),
        "net.ipv6.conf.all.forwarding",
        "1",
    )?;
    set_ipv4_rp_filter(interface, "2")?;
    configure_egress_docker_forwarding(interface)
}

fn egress_docker_forwarding_rules(interface: &str) -> [Vec<&str>; 2] {
    [
        vec![
            "-i",
            interface,
            "-m",
            "comment",
            "--comment",
            "aegis-egress",
            "-j",
            "ACCEPT",
        ],
        vec![
            "-o",
            interface,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-m",
            "comment",
            "--comment",
            "aegis-egress",
            "-j",
            "ACCEPT",
        ],
    ]
}

fn configure_egress_docker_forwarding(interface: &str) -> Result<()> {
    // Docker's FORWARD policy can drop packets accepted by our independent nftables
    // base chain. Its documented user chain is the scoped integration point; our own
    // chain still enforces enrolled source addresses and established return traffic.
    for (family, program) in [("ip", "/usr/sbin/iptables"), ("ip6", "/usr/sbin/ip6tables")] {
        let chain = run_capture(bounded_egress_command("/usr/sbin/nft").args([
            "list",
            "chain",
            family,
            "filter",
            "DOCKER-USER",
        ]))?;
        if !chain.status.success() {
            ensure!(
                chain.stderr.contains("No such file"),
                "could not inspect Docker forwarding: {}",
                chain.stderr.trim()
            );
            continue;
        }
        for rule in egress_docker_forwarding_rules(interface) {
            let existing = run_capture(
                bounded_egress_command(program)
                    .args(["--wait", "2", "--check", "DOCKER-USER"])
                    .args(&rule),
            )?;
            if existing.status.success() {
                continue;
            }
            ensure!(
                existing.status.code() == Some(1),
                "could not inspect the Aegis Docker forwarding rule: {}",
                existing.stderr.trim()
            );
            require_success(
                "allow Aegis forwarding through Docker",
                bounded_egress_command(program)
                    .args(["--wait", "2", "--insert", "DOCKER-USER"])
                    .args(&rule),
            )?;
        }
    }
    Ok(())
}

fn egress_docker_forwarding_cleanup(interface: &str) -> String {
    egress_docker_forwarding_rules(interface)
        .iter()
        .map(|rule| {
            let rule = rule
                .iter()
                .map(|word| format!("'{}'", word.replace('\'', "'\\''")))
                .collect::<Vec<_>>()
                .join(" ");
            format!(
                "    for program in /usr/sbin/iptables /usr/sbin/ip6tables; do\n\
                 if run \"$program\" --wait 2 --check DOCKER-USER {rule} 2>/dev/null; then\n\
                   run \"$program\" --wait 2 --delete DOCKER-USER {rule}\n\
                 fi\n\
                 done\n"
            )
        })
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocalEgressMode {
    Direct,
    Staging,
    Tunnel,
}

struct EgressNftablesState<'a> {
    config: &'a AegisEgressConfig,
    local: &'a AegisEgressHost,
    mode: LocalEgressMode,
    gateway_chained: bool,
    target_sources: &'a [&'a AegisEgressHost],
}

struct EgressPolicyState<'a> {
    config: &'a AegisEgressConfig,
    local: &'a AegisEgressHost,
    selected_target: Option<&'a AegisEgressHost>,
    target_sources: &'a [&'a AegisEgressHost],
}

fn apply_egress_policy_state(state: EgressPolicyState<'_>) -> Result<()> {
    let EgressPolicyState {
        config,
        local,
        selected_target,
        target_sources,
    } = state;
    let fail_closed = selected_target.is_some();
    let gateway_routes = egress_gateway_routes(target_sources);
    let nftables = egress_nftables_contents(EgressNftablesState {
        config,
        local,
        mode: if fail_closed {
            LocalEgressMode::Tunnel
        } else {
            LocalEgressMode::Direct
        },
        gateway_chained: fail_closed,
        target_sources,
    });
    require_success_with_input(
        "validate Aegis egress nftables policy",
        bounded_egress_command("/usr/sbin/nft").args(["--check", "--file", "/dev/stdin"]),
        nftables.as_bytes(),
    )?;
    let script = egress_policy_script_contents(config);
    let unit = egress_policy_systemd_unit_contents();
    let resolved = egress_resolved_dropin_contents(local);
    write_text_file_if_changed(
        Path::new(aegis_dto::layout::EGRESS_NFTABLES_PATH),
        &nftables,
        Some(0o600),
    )?;
    write_text_file_if_changed(
        Path::new(aegis_dto::layout::EGRESS_POLICY_SCRIPT_PATH),
        &script,
        Some(0o700),
    )?;
    let unit_changed = write_text_file_if_changed(
        Path::new(aegis_dto::layout::EGRESS_POLICY_SYSTEMD_UNIT_PATH),
        &unit,
        Some(0o644),
    )?;
    let resolved_changed = write_text_file_if_changed(
        Path::new(aegis_dto::layout::EGRESS_RESOLVED_DROPIN_PATH),
        &resolved,
        Some(0o644),
    )?;
    if unit_changed {
        require_success(
            "reload systemd after Aegis egress policy unit update",
            bounded_egress_command("/usr/bin/systemctl").arg("daemon-reload"),
        )?;
    }
    if resolved_changed || !wireguard_service_is_active("systemd-resolved.service")? {
        require_success(
            "restart systemd-resolved after Aegis egress listener update",
            bounded_egress_command("/usr/bin/systemctl")
                .args(["restart", "systemd-resolved.service"]),
        )?;
        if let Some(target) = selected_target {
            configure_egress_dns(config, target)?;
        }
    }
    ensure_service_enabled(
        aegis_dto::layout::EGRESS_POLICY_SYSTEMD_SERVICE_NAME,
        "Aegis egress policy",
    )?;
    ensure_egress_services_running()?;
    let applied_contents = [
        nftables.as_bytes(),
        script.as_bytes(),
        unit.as_bytes(),
        resolved.as_bytes(),
    ]
    .concat();
    let applied = AppliedConfig::new(EGRESS_NFTABLES_APPLIED_CONFIG_NAME, &applied_contents);
    let runtime_matches =
        egress_policy_runtime_matches(config, local, fail_closed, selected_target, target_sources)?;
    let routes_match = egress_main_routes_match(config, &gateway_routes)?;
    ensure!(
        runtime_matches && routes_match,
        "pre-applied Aegis egress policy does not match its persistent state"
    );
    applied.mark()?;
    Ok(())
}

fn apply_egress_nftables_runtime(state: EgressNftablesState<'_>) -> Result<()> {
    let nftables = egress_nftables_contents(state);
    require_success_with_input(
        "validate Aegis egress nftables policy",
        bounded_egress_command("/usr/sbin/nft").args(["--check", "--file", "/dev/stdin"]),
        nftables.as_bytes(),
    )?;
    require_success_with_input(
        "commit Aegis egress nftables policy",
        bounded_egress_command("/usr/sbin/nft").args(["--file", "/dev/stdin"]),
        nftables.as_bytes(),
    )?;
    Ok(())
}

fn bounded_egress_command(program: &str) -> Command {
    let mut command = Command::new("/usr/bin/timeout");
    command.args(["--signal=KILL", EGRESS_COMMAND_TIMEOUT, program]);
    command
}

fn prepare_egress_tunnel_routing(
    config: &AegisEgressConfig,
    target: &AegisEgressHost,
) -> Result<()> {
    clear_egress_policy_routing(config)?;
    let table = config.routing_table.to_string();
    for family in ["-4", "-6"] {
        require_success(
            "install fail-closed Aegis egress fallback route",
            bounded_egress_command("/usr/sbin/ip").args([
                family,
                "route",
                "replace",
                "table",
                &table,
                "unreachable",
                "default",
                "metric",
                "32760",
            ]),
        )?;
        require_success(
            "install live Aegis egress default route",
            bounded_egress_command("/usr/sbin/ip").args([
                family,
                "route",
                "replace",
                "table",
                &table,
                "default",
                "dev",
                &config.interface,
                "metric",
                "10",
            ]),
        )?;
    }
    configure_egress_dns(config, target)?;
    for family in ["-4", "-6"] {
        require_success(
            "install Aegis main-table control route rule",
            bounded_egress_command("/usr/sbin/ip").args([
                family,
                "rule",
                "add",
                "priority",
                &config.main_rule_priority.to_string(),
                "table",
                "main",
                "suppress_prefixlength",
                "0",
            ]),
        )?;
        require_success(
            "install Aegis egress route rule",
            bounded_egress_command("/usr/sbin/ip").args([
                family,
                "rule",
                "add",
                "priority",
                &config.egress_rule_priority.to_string(),
                "not",
                "fwmark",
                &config.fwmark.to_string(),
                "table",
                &table,
            ]),
        )?;
    }
    Ok(())
}

fn clear_egress_policy_routing(config: &AegisEgressConfig) -> Result<()> {
    let mut failures = Vec::new();
    for family in ["-4", "-6"] {
        for priority in [config.main_rule_priority, config.egress_rule_priority] {
            loop {
                let rules = match require_success(
                    "inspect Aegis egress route rules",
                    bounded_egress_command("/usr/sbin/ip").args([family, "rule", "show"]),
                ) {
                    Ok(rules) => rules,
                    Err(error) => {
                        failures.push(format!(
                            "inspect {family} route rules at priority {priority}: {error:#}"
                        ));
                        break;
                    }
                };
                if !policy_rule_present(&rules.stdout, priority, "") {
                    break;
                }
                if let Err(error) = require_success(
                    "remove Aegis egress route rule",
                    bounded_egress_command("/usr/sbin/ip").args([
                        family,
                        "rule",
                        "del",
                        "priority",
                        &priority.to_string(),
                    ]),
                ) {
                    failures.push(format!(
                        "remove {family} route rule at priority {priority}: {error:#}"
                    ));
                    break;
                }
            }
        }
        record_egress_recovery(
            &mut failures,
            &format!("clear {family} egress routing table"),
            reconcile_empty_egress_routing_table(family, config.routing_table),
        );
    }
    match wireguard_service_is_active("systemd-resolved.service") {
        Ok(true) => record_egress_recovery(
            &mut failures,
            "restore direct DNS routing",
            require_success(
                "restore direct DNS routing",
                bounded_egress_command("/usr/bin/resolvectl").args(["revert", &config.interface]),
            )
            .map(|_| ()),
        ),
        Ok(false) => {}
        Err(error) => failures.push(format!("inspect systemd-resolved: {error:#}")),
    }
    if !failures.is_empty() {
        bail!(failures.join("; "));
    }
    Ok(())
}

fn reconcile_empty_egress_routing_table(family: &str, table: u32) -> Result<()> {
    if !egress_routing_table_has_routes(family, table)? {
        return Ok(());
    }

    let output = run_capture(bounded_egress_command("/usr/sbin/ip").args([
        family,
        "route",
        "flush",
        "table",
        &table.to_string(),
    ]))?;
    if !egress_routing_table_has_routes(family, table)? {
        return Ok(());
    }

    let detail = command_output_detail(&output);
    bail!("routing table {table} still contains {family} routes after flush: {detail}")
}

fn egress_routing_table_has_routes(family: &str, table: u32) -> Result<bool> {
    Ok(!egress_routing_table_routes(family, table)?.is_empty())
}

fn egress_routing_table_routes(family: &str, table: u32) -> Result<Vec<IpRouteEntry>> {
    let output = require_success(
        "inspect all routing tables while reconciling Aegis egress",
        bounded_egress_command("/usr/sbin/ip")
            .args(["-j", family, "route", "show", "table", "all"]),
    )?;
    route_table_routes(&output.stdout, table)
}

fn route_table_routes(json: &str, table: u32) -> Result<Vec<IpRouteEntry>> {
    let routes = serde_json::from_str::<Vec<IpRouteEntry>>(json)
        .context("failed to parse the complete kernel routing table inventory")?;
    Ok(routes
        .into_iter()
        .filter(|route| {
            route
                .table
                .as_ref()
                .is_some_and(|value| value.matches(table))
        })
        .collect())
}

fn egress_routing_table_matches(
    family: &str,
    table: u32,
    interface: &str,
    tunneled: bool,
) -> Result<bool> {
    let routes = egress_routing_table_routes(family, table)?;
    Ok(egress_route_entries_match(&routes, interface, tunneled))
}

fn egress_route_entries_match(routes: &[IpRouteEntry], interface: &str, tunneled: bool) -> bool {
    if !tunneled {
        return routes.is_empty();
    }
    let live_defaults = routes
        .iter()
        .filter(|route| route.is_live_egress_default(interface))
        .count();
    let unreachable_defaults = routes
        .iter()
        .filter(|route| route.is_unreachable_egress_default())
        .count();
    routes.len() == 2 && live_defaults == 1 && unreachable_defaults == 1
}

fn command_output_detail(output: &crate::command::CommandOutput) -> String {
    let stderr = output.stderr.trim();
    if !stderr.is_empty() {
        return stderr.to_string();
    }
    let stdout = output.stdout.trim();
    if !stdout.is_empty() {
        return stdout.to_string();
    }
    format!("exit status {}", output.status.code().unwrap_or(1))
}

fn configure_egress_dns(config: &AegisEgressConfig, target: &AegisEgressHost) -> Result<()> {
    ensure!(
        wireguard_service_is_active("systemd-resolved.service")?,
        "systemd-resolved must be active before enabling Aegis egress"
    );
    require_success(
        "configure Aegis egress DNS servers",
        bounded_egress_command("/usr/bin/resolvectl").args([
            "dns",
            &config.interface,
            &target.dns_ipv4,
            &target.dns_ipv6,
        ]),
    )?;
    require_success(
        "route all DNS names through Aegis egress",
        bounded_egress_command("/usr/bin/resolvectl").args(["domain", &config.interface, "~."]),
    )?;
    require_success(
        "make Aegis egress the default DNS route",
        bounded_egress_command("/usr/bin/resolvectl").args([
            "default-route",
            &config.interface,
            "yes",
        ]),
    )?;
    Ok(())
}

fn restore_tunneled_egress_runtime(
    config: &AegisEgressConfig,
    local: &AegisEgressHost,
    target: &AegisEgressHost,
    gateway_sources: &[&AegisEgressHost],
) -> Result<()> {
    let gateway_routes = egress_gateway_routes(gateway_sources);
    reconcile_egress_main_routes(config, &gateway_routes)?;
    if egress_policy_runtime_matches(config, local, true, Some(target), gateway_sources)?
        && egress_main_routes_match(config, &gateway_routes)?
    {
        return Ok(());
    }
    // An API-observed active tunnel is already beyond the fail-closed commit boundary. Repair it
    // under the tunnel guard: agent control traffic retains its explicit main-route exception,
    // while ordinary traffic cannot leak onto the direct route if routing or DNS needs repair.
    apply_egress_nftables_runtime(EgressNftablesState {
        config,
        local,
        mode: LocalEgressMode::Tunnel,
        gateway_chained: true,
        target_sources: gateway_sources,
    })?;
    if !egress_tunnel_routing_matches(config, target)? {
        prepare_egress_tunnel_routing(config, target)?;
    }
    ensure!(
        egress_policy_runtime_matches(config, local, true, Some(target), gateway_sources)?
            && egress_main_routes_match(config, &gateway_routes)?,
        "restored Aegis tunnel does not match its requested runtime state"
    );
    Ok(())
}

fn restore_direct_egress_runtime(
    config: &AegisEgressConfig,
    local: &AegisEgressHost,
    gateway_sources: &[&AegisEgressHost],
) -> Result<()> {
    let gateway_routes = egress_gateway_routes(gateway_sources);
    if egress_policy_runtime_matches(config, local, false, None, gateway_sources)?
        && egress_main_routes_match(config, &gateway_routes)?
    {
        return Ok(());
    }
    commit_direct_egress_runtime(config, local, gateway_sources)
}

fn commit_direct_egress_runtime(
    config: &AegisEgressConfig,
    local: &AegisEgressHost,
    gateway_sources: &[&AegisEgressHost],
) -> Result<()> {
    apply_direct_egress_staging(config, local, gateway_sources)?;
    let mut failures = Vec::new();
    record_egress_recovery(
        &mut failures,
        "policy routing cleanup",
        clear_egress_policy_routing(config),
    );
    record_egress_recovery(
        &mut failures,
        "gateway return routes",
        reconcile_egress_main_routes(config, &egress_gateway_routes(gateway_sources)),
    );
    let stable_direct = apply_egress_nftables_runtime(EgressNftablesState {
        config,
        local,
        mode: LocalEgressMode::Direct,
        gateway_chained: false,
        target_sources: gateway_sources,
    });
    if let Err(error) = stable_direct {
        failures.push(format!("stable direct policy: {error:#}"));
        record_egress_recovery(
            &mut failures,
            "temporary staging policy removal",
            destroy_egress_nftables_runtime(),
        );
    }
    if failures.is_empty() {
        Ok(())
    } else {
        bail!(failures.join("; "))
    }
}

fn apply_direct_egress_staging(
    config: &AegisEgressConfig,
    local: &AegisEgressHost,
    gateway_sources: &[&AegisEgressHost],
) -> Result<()> {
    if let Err(staging_error) = apply_egress_nftables_runtime(EgressNftablesState {
        config,
        local,
        mode: LocalEgressMode::Staging,
        gateway_chained: false,
        target_sources: gateway_sources,
    }) {
        destroy_egress_nftables_runtime().with_context(|| {
            format!(
                "could not commit the direct-routing staging policy ({staging_error:#}), and removing the fail-closed table also failed"
            )
        })?;
    }
    Ok(())
}

fn destroy_egress_nftables_runtime() -> Result<()> {
    let output = run_capture(bounded_egress_command("/usr/sbin/nft").args([
        "destroy",
        "table",
        "inet",
        "aegis_egress",
    ]))?;
    if output.status.success() || output.stderr.contains("No such file") {
        Ok(())
    } else {
        bail!(
            "nft destroy exited with {}: {}",
            output.status,
            output.stderr.trim()
        )
    }
}

fn egress_tunnel_routing_matches(
    config: &AegisEgressConfig,
    target: &AegisEgressHost,
) -> Result<bool> {
    for family in ["-4", "-6"] {
        let rules =
            run_capture(bounded_egress_command("/usr/sbin/ip").args([family, "rule", "show"]))?;
        if !rules.status.success()
            || !egress_routing_table_matches(family, config.routing_table, &config.interface, true)?
            || !policy_rule_present(&rules.stdout, config.main_rule_priority, "lookup main")
            || !policy_rule_present(
                &rules.stdout,
                config.egress_rule_priority,
                &format!("lookup {}", config.routing_table),
            )
        {
            return Ok(false);
        }
    }
    egress_dns_state_matches(config, Some(target))
}

fn egress_dns_state_matches(
    config: &AegisEgressConfig,
    target: Option<&AegisEgressHost>,
) -> Result<bool> {
    if !wireguard_service_is_active("systemd-resolved.service")? {
        return Ok(target.is_none());
    }
    let query = |property: &str| {
        run_capture(
            bounded_egress_command("/usr/bin/resolvectl").args([property, &config.interface]),
        )
    };
    let dns = query("dns")?;
    let domains = query("domain")?;
    let default_route = query("default-route")?;
    if !dns.status.success() || !domains.status.success() || !default_route.status.success() {
        return Ok(false);
    }
    let Some(dns) = resolvectl_link_values(&dns.stdout) else {
        return Ok(false);
    };
    let Some(domains) = resolvectl_link_values(&domains.stdout) else {
        return Ok(false);
    };
    let Some(default_route) = resolvectl_link_values(&default_route.stdout) else {
        return Ok(false);
    };
    Ok(match target {
        Some(target) => {
            dns.contains(&target.dns_ipv4.as_str())
                && dns.contains(&target.dns_ipv6.as_str())
                && domains.contains(&"~.")
                && default_route == ["yes"]
        }
        None => dns.is_empty() && domains.is_empty() && default_route == ["no"],
    })
}

fn resolvectl_link_values(output: &str) -> Option<Vec<&str>> {
    let (_, values) = output.trim().split_once(':')?;
    Some(values.split_ascii_whitespace().collect())
}

fn egress_policy_runtime_matches(
    config: &AegisEgressConfig,
    local: &AegisEgressHost,
    fail_closed: bool,
    selected_target: Option<&AegisEgressHost>,
    target_sources: &[&AegisEgressHost],
) -> Result<bool> {
    let nftables = run_capture(bounded_egress_command("/usr/sbin/nft").args([
        "list",
        "table",
        "inet",
        "aegis_egress",
    ]))?;
    if !nftables.status.success()
        || !nftables
            .stdout
            .contains("socket cgroupv2 level 1 \"aegis.slice\"")
        || nftables.stdout.contains("admin-prohibited") != fail_closed
        || !nftables.stdout.contains(&format!(
            "iifname \"{}\" ct state established,related accept",
            config.interface
        ))
        || !nftables
            .stdout
            .contains(&format!("ip saddr {} return", local.dns_ipv4))
        || !nftables
            .stdout
            .contains(&format!("ip6 saddr {} return", local.dns_ipv6))
        || !egress_gateway_rules_present(
            &nftables.stdout,
            &config.interface,
            fail_closed,
            target_sources,
        )
    {
        return Ok(false);
    }
    if !target_sources.is_empty()
        && (!fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .is_ok_and(|value| value.trim() == "1")
            || !fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding")
                .is_ok_and(|value| value.trim() == "1"))
    {
        return Ok(false);
    }
    for family in ["-4", "-6"] {
        let rules =
            run_capture(bounded_egress_command("/usr/sbin/ip").args([family, "rule", "show"]))?;
        if !rules.status.success()
            || !egress_routing_table_matches(
                family,
                config.routing_table,
                &config.interface,
                fail_closed,
            )?
            || policy_rule_present(&rules.stdout, config.main_rule_priority, "lookup main")
                != fail_closed
            || policy_rule_present(
                &rules.stdout,
                config.egress_rule_priority,
                &format!("lookup {}", config.routing_table),
            ) != fail_closed
        {
            return Ok(false);
        }
        if fail_closed != selected_target.is_some() {
            return Ok(false);
        }
    }
    egress_dns_state_matches(config, selected_target)
}

fn egress_gateway_rules_present(
    nftables: &str,
    interface: &str,
    chained: bool,
    target_sources: &[&AegisEgressHost],
) -> bool {
    target_sources.iter().all(|source| {
        [
            ("ip", source.ipv4.as_str()),
            ("ip6", source.ipv6.as_str()),
            ("ip", source.dns_ipv4.as_str()),
            ("ip6", source.dns_ipv6.as_str()),
        ]
        .into_iter()
        .all(|(family, address)| {
            let ingress = format!("iifname \"{interface}\"");
            let transit = if chained {
                format!("oifname \"{interface}\" ")
            } else {
                String::new()
            };
            let accept = format!("{ingress} {transit}{family} saddr {address} accept");
            let masquerade = format!("{ingress} {family} saddr {address} masquerade");
            nftables.lines().any(|line| line.trim().contains(&accept))
                && nftables
                    .lines()
                    .any(|line| line.trim().contains(&masquerade))
        })
    })
}

fn egress_host_routes(host: &AegisEgressHost) -> BTreeSet<String> {
    BTreeSet::from([
        format!("{}/32", host.ipv4),
        format!("{}/128", host.ipv6),
        format!("{}/32", host.dns_ipv4),
        format!("{}/128", host.dns_ipv6),
    ])
}

fn egress_gateway_routes(sources: &[&AegisEgressHost]) -> BTreeSet<String> {
    sources
        .iter()
        .flat_map(|source| egress_host_routes(source))
        .collect()
}

fn reconcile_egress_main_routes(
    config: &AegisEgressConfig,
    desired: &BTreeSet<String>,
) -> Result<()> {
    let current = current_egress_main_routes(config)?;
    for route in desired.difference(&current) {
        let family = if route.contains(':') { "-6" } else { "-4" };
        require_success(
            "install Aegis egress return route",
            bounded_egress_command("/usr/sbin/ip").args([
                family,
                "route",
                "replace",
                "table",
                "main",
                route,
                "dev",
                &config.interface,
                "proto",
                &EGRESS_ROUTE_PROTOCOL.to_string(),
                "metric",
                &EGRESS_ROUTE_METRIC.to_string(),
            ]),
        )?;
    }
    for route in current.difference(desired) {
        let family = if route.contains(':') { "-6" } else { "-4" };
        require_success(
            "remove stale Aegis egress return route",
            bounded_egress_command("/usr/sbin/ip").args([
                family,
                "route",
                "del",
                "table",
                "main",
                route,
                "dev",
                &config.interface,
                "proto",
                &EGRESS_ROUTE_PROTOCOL.to_string(),
                "metric",
                &EGRESS_ROUTE_METRIC.to_string(),
            ]),
        )?;
    }
    Ok(())
}

fn egress_main_routes_match(
    config: &AegisEgressConfig,
    desired: &BTreeSet<String>,
) -> Result<bool> {
    Ok(current_egress_main_routes(config)? == *desired)
}

fn current_egress_main_routes(config: &AegisEgressConfig) -> Result<BTreeSet<String>> {
    let mut routes = BTreeSet::new();
    for family in ["-4", "-6"] {
        let output = require_success(
            "list managed Aegis egress return routes",
            bounded_egress_command("/usr/sbin/ip").args([
                "-j",
                family,
                "route",
                "show",
                "table",
                "main",
                "dev",
                &config.interface,
                "proto",
                &EGRESS_ROUTE_PROTOCOL.to_string(),
            ]),
        )?;
        for entry in serde_json::from_str::<Vec<IpRouteEntry>>(&output.stdout)
            .context("failed to parse managed Aegis egress return routes")?
        {
            let Some(destination) = entry.dst.as_deref() else {
                continue;
            };
            if entry.metric != Some(u32::from(EGRESS_ROUTE_METRIC)) {
                continue;
            }
            if let Some(route) = normalize_managed_wireguard_route_in_subnets(
                &config.subnet_ipv4,
                &config.subnet_ipv6,
                destination,
            )
            .or_else(|| {
                normalize_managed_wireguard_route_in_subnets(
                    &config.dns_subnet_ipv4,
                    &config.dns_subnet_ipv6,
                    destination,
                )
            }) {
                routes.insert(route);
            }
        }
    }
    Ok(routes)
}

fn policy_rule_present(output: &str, priority: u32, lookup: &str) -> bool {
    let priority = format!("{priority}:");
    output.lines().any(|line| {
        let line = line.trim_start();
        line.starts_with(&priority) && line.contains(lookup)
    })
}

fn egress_nftables_contents(state: EgressNftablesState<'_>) -> String {
    let EgressNftablesState {
        config,
        local,
        mode,
        gateway_chained,
        target_sources,
    } = state;
    let interface = &config.interface;
    let mut content = format!(
        "{MANAGED_CONFIG_HEADER}destroy table inet aegis_egress\n\
         table inet aegis_egress {{\n\
           chain mark_control {{\n\
             type route hook output priority mangle; policy accept;\n\
             socket cgroupv2 level 1 \"aegis.slice\" ip daddr {{ 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4 }} return\n\
             socket cgroupv2 level 1 \"aegis.slice\" ip6 daddr {{ ::1/128, fc00::/7, fe80::/10, ff00::/8 }} return\n\
             ip saddr {} return\n\
             ip6 saddr {} return\n\
             socket cgroupv2 level 1 \"aegis.slice\" meta mark set {}\n\
",
        local.dns_ipv4, local.dns_ipv6, config.fwmark,
    );
    if mode == LocalEgressMode::Staging {
        content.push_str(&format!(
            "    ip daddr {{ 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4 }} return\n\
             ip6 daddr {{ ::1/128, fc00::/7, fe80::/10, ff00::/8 }} return\n\
             meta mark set {}\n",
            config.fwmark
        ));
    }
    content.push_str(&format!(
        "  }}\n\
           chain input_guard {{\n\
             type filter hook input priority filter; policy accept;\n\
             iifname \"{interface}\" ct state established,related accept\n\
             iifname \"{interface}\" ip daddr {} meta l4proto {{ tcp, udp }} th dport 53 accept\n\
             iifname \"{interface}\" ip6 daddr {} meta l4proto {{ tcp, udp }} th dport 53 accept\n\
             iifname \"{interface}\" meta l4proto {{ icmp, ipv6-icmp }} accept\n\
             iifname \"{interface}\" drop\n\
           }}\n\
           chain forward_guard {{\n\
             type filter hook forward priority filter; policy accept;\n\
             oifname \"{interface}\" ct state established,related accept\n",
        local.dns_ipv4, local.dns_ipv6,
    ));
    for source in target_sources {
        for (family, address) in [
            ("ip", &source.ipv4),
            ("ip6", &source.ipv6),
            ("ip", &source.dns_ipv4),
            ("ip6", &source.dns_ipv6),
        ] {
            let transit = if gateway_chained {
                format!(" oifname \"{interface}\"")
            } else {
                String::new()
            };
            content.push_str(&format!(
                "    iifname \"{interface}\"{transit} {family} saddr {address} accept\n"
            ));
        }
    }
    content.push_str(&format!(
        "    iifname \"{interface}\" drop\n\
             oifname \"{interface}\" drop\n\
           }}\n\
           chain postrouting {{\n\
             type nat hook postrouting priority srcnat; policy accept;\n"
    ));
    for source in target_sources {
        for (family, address) in [
            ("ip", &source.ipv4),
            ("ip6", &source.ipv6),
            ("ip", &source.dns_ipv4),
            ("ip6", &source.dns_ipv6),
        ] {
            content.push_str(&format!(
                "    iifname \"{interface}\" {family} saddr {address} masquerade\n"
            ));
        }
    }
    content.push_str("  }\n");
    content.push_str(
        "  chain output_guard {\n    type filter hook output priority filter; policy accept;\n",
    );
    if mode == LocalEgressMode::Tunnel {
        content.push_str(&format!(
            "    meta mark {} accept\n\
             oifname \"lo\" accept\n\
             oifname \"{interface}\" accept\n\
             meta l4proto {{ tcp, udp }} th dport 53 reject\n\
             ip daddr {{ 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4 }} accept\n\
             ip6 daddr {{ ::1/128, fc00::/7, fe80::/10, ff00::/8 }} accept\n\
             reject with icmpx type admin-prohibited\n",
            config.fwmark
        ));
    }
    content.push_str("  }\n}\n");
    content
}

fn egress_policy_script_contents(config: &AegisEgressConfig) -> String {
    format!(
        r#"#!/bin/bash
set -euo pipefail
run() {{ /usr/bin/timeout --signal=KILL {timeout} "$@"; }}
case "${{1:-}}" in
  apply)
    run /usr/sbin/nft --file {nftables}
    ;;
  remove)
{docker_cleanup}    run /usr/sbin/nft destroy table inet aegis_egress
    for family in -4 -6; do
      for priority in {main_priority} {egress_priority}; do
        while run /usr/sbin/ip "$family" rule del priority "$priority" 2>/dev/null; do :; done
      done
      run /usr/sbin/ip "$family" route flush table {table} 2>/dev/null || true
      run /usr/sbin/ip "$family" route flush table main dev {interface} proto {protocol} 2>/dev/null || true
    done
    run /usr/bin/resolvectl revert {interface} 2>/dev/null || true
    ;;
  *) echo "usage: $0 apply|remove" >&2; exit 2 ;;
esac
"#,
        timeout = EGRESS_COMMAND_TIMEOUT,
        docker_cleanup = egress_docker_forwarding_cleanup(&config.interface),
        nftables = aegis_dto::layout::EGRESS_NFTABLES_PATH,
        main_priority = config.main_rule_priority,
        egress_priority = config.egress_rule_priority,
        table = config.routing_table,
        interface = config.interface,
        protocol = EGRESS_ROUTE_PROTOCOL,
    )
}

fn egress_policy_systemd_unit_contents() -> String {
    format!(
        "[Unit]\n\
         Description=aegis fail-closed egress policy\n\
         DefaultDependencies=no\n\
         Requires=aegis.slice\n\
         After=local-fs.target aegis.slice\n\
         Before=network-pre.target shutdown.target\n\
         Conflicts=shutdown.target\n\
         Wants=network-pre.target\n\n\
         [Service]\n\
         Type=oneshot\n\
         RemainAfterExit=yes\n\
         TimeoutStartSec=30s\n\
         ExecStart=/usr/sbin/nft --file {}\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        aegis_dto::layout::EGRESS_NFTABLES_PATH,
    )
}

fn egress_resolved_dropin_contents(local: &AegisEgressHost) -> String {
    format!(
        "# Managed by aegis.\n[Resolve]\nDNSStubListenerExtra={}\nDNSStubListenerExtra={}\n",
        local.dns_ipv4, local.dns_ipv6
    )
}

fn publish_direct_gateway_ready(state: &AppState, plan: &DirectGatewayPlan) -> Result<()> {
    let token = access_token(state)?;
    match plan {
        DirectGatewayPlan::Configuring(inventory) => {
            let published = state.api.put_direct_gateway(
                &token,
                &state.config.host.host_id,
                &AegisDirectGatewayPublishRequest {
                    public_key: inventory.gateway.wireguard.public_key.clone(),
                    endpoints: inventory.gateway.wireguard.endpoints.clone(),
                },
            )?;
            if published.host_id != state.config.host.host_id
                || published.aliases != inventory.gateway.aliases
                || published.wireguard.public_key != inventory.gateway.wireguard.public_key
                || published.wireguard.ipv4 != inventory.gateway.wireguard.ipv4
                || published.wireguard.ipv6 != inventory.gateway.wireguard.ipv6
            {
                bail!(
                    "publishing direct gateway `{}` returned a different identity",
                    state.config.host.host_id
                );
            }
            Ok(())
        }
        DirectGatewayPlan::Disabled {
            remove_published: true,
            ..
        } => state
            .api
            .delete_direct_gateway(&token, &state.config.host.host_id)
            .context("failed to remove the retired direct gateway"),
        DirectGatewayPlan::Disabled {
            remove_published: false,
            ..
        }
        | DirectGatewayPlan::Ready(_)
        | DirectGatewayPlan::Preserve
        | DirectGatewayPlan::Unsupported => Ok(()),
    }
}

fn apply_direct_gateway_config(inventory: &DirectGatewayState) -> Result<()> {
    let config = managed_wireguard_config(&inventory.config.interface);
    ensure_local_wireguard_public_key(&config, &inventory.gateway.wireguard.public_key)?;
    let desired_config = direct_gateway_wireguard_config_contents(
        inventory,
        &load_private_key(&config.private_key_path)?,
    )?;
    let runtime = WireGuardRuntime::parse(&config.interface, &desired_config)?;
    let quick_applied = wireguard_quick_applied_config(&config.interface, &desired_config)?;
    let quick_content_changed =
        wireguard_quick_config_changed(&config.config_path, &config.interface, &quick_applied)?;
    reconcile_direct_accounts(&inventory.satellites, true)?;
    write_text_file_if_changed(
        Path::new(aegis_dto::layout::DIRECT_CLIENT_CA_PATH),
        &line_with_newline(&inventory.direct_client_ca_public_key),
        Some(0o644),
    )?;
    install_sshd_dropin(
        Path::new(aegis_dto::layout::DIRECT_SSHD_DROPIN_PATH),
        &direct_gateway_sshd_dropin_contents(inventory),
    )?;
    ensure_directory_mode(Path::new(AEGIS_WIREGUARD_DIR), 0o755)?;
    ensure_wireguard_systemd_unit()?;
    write_text_file_if_changed(&config.config_path, &desired_config, Some(0o600))?;

    let service = wireguard_service_name(&config);
    ensure_service_enabled(&service, "Aegis direct-gateway WireGuard")?;
    let active = wireguard_service_is_active(&service)?;
    let quick_activation_required =
        config_activation_required(&quick_applied, quick_content_changed)?;
    if !active {
        if !quick_activation_required {
            quick_applied.mark_pending()?;
        }
        require_success(
            "start Aegis direct-gateway WireGuard service",
            Command::new("systemctl").args(["start", &service]),
        )?;
        runtime.record_start()?;
        quick_applied.mark()?;
    } else if !wireguard_interface_addresses_match(
        &config.interface,
        &inventory.gateway.wireguard.ipv4,
        &inventory.gateway.wireguard.ipv6,
    )? || quick_activation_required
    {
        require_success(
            "restart Aegis direct-gateway WireGuard service after wg-quick configuration change",
            Command::new("systemctl").args(["restart", &service]),
        )?;
        runtime.record_start()?;
        quick_applied.mark()?;
    } else {
        runtime.reconcile()?;
    }
    ensure_direct_gateway_reply_rules()?;
    reconcile_direct_gateway_routes(&inventory.config, &config.interface, inventory)
}

fn ensure_direct_gateway_reply_rules() -> Result<()> {
    for program in ["iptables", "ip6tables"] {
        let rule = [
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ];
        let present = run_capture(
            Command::new(program)
                .args(["-C", "AEGIS_DIRECT_IN"])
                .args(rule),
        )?;
        if present.status.success() {
            continue;
        }
        require_success(
            &format!("install {program} Aegis direct-gateway reply rule"),
            Command::new(program)
                .args(["-I", "AEGIS_DIRECT_IN", "1"])
                .args(rule),
        )?;
    }
    Ok(())
}

fn reconcile_direct_accounts(satellites: &[AegisDirectSatellite], keep_group: bool) -> Result<()> {
    let state_directory = Path::new(aegis_dto::layout::DIRECT_STATE_DIRECTORY);
    let home_directory = Path::new(aegis_dto::layout::DIRECT_HOME_DIRECTORY);
    let principals_directory = Path::new(aegis_dto::layout::AUTHORIZED_PRINCIPALS_DIRECTORY);
    let managed_state_present = state_directory.exists() || home_directory.exists();
    if keep_group || !satellites.is_empty() {
        ensure_directory_mode(state_directory, 0o755)?;
        ensure_directory_mode(home_directory, 0o755)?;
        ensure_directory_mode(principals_directory, 0o755)?;
        ensure_direct_group(managed_state_present)?;
    }

    let mut desired = BTreeMap::new();
    for satellite in satellites {
        validate_direct_identity(satellite)?;
        if let Some(existing) = desired.insert(satellite.account.clone(), satellite) {
            bail!(
                "satellites `{}` and `{}` resolve to the same direct account `{}`",
                existing.slug,
                satellite.slug,
                satellite.account
            );
        }
    }

    for entry in read_directory_if_exists(state_directory)? {
        if !entry.file_type()?.is_file()
            || entry.path().extension().and_then(|value| value.to_str()) != Some("json")
        {
            continue;
        }
        let raw = fs::read_to_string(entry.path())
            .with_context(|| format!("failed to read {}", entry.path().display()))?;
        let state = serde_json::from_str::<DirectAccountState>(&raw)
            .with_context(|| format!("failed to parse {}", entry.path().display()))?;
        if !valid_direct_account(&state.account) {
            bail!(
                "refusing to remove invalid managed direct account `{}`",
                state.account
            );
        }
        let expected_path = direct_account_state_path(&state.account);
        if entry.path() != expected_path {
            bail!(
                "direct account state {} does not match account `{}`",
                entry.path().display(),
                state.account
            );
        }
        if !desired.contains_key(&state.account) {
            remove_direct_account(&state.account)?;
        }
    }

    for entry in read_directory_if_exists(principals_directory)? {
        if entry.file_type()?.is_file() {
            let account = entry.file_name().to_string_lossy().to_string();
            if valid_direct_account(&account) && !desired.contains_key(&account) {
                remove_file_if_exists(&entry.path())?;
            }
        }
    }

    for (account, satellite) in &desired {
        ensure_direct_account(account, &satellite.slug)?;
        write_text_file_if_changed(
            &principals_directory.join(account),
            &line_with_newline(&satellite.ssh_principal),
            Some(0o644),
        )?;
    }

    if !keep_group && desired.is_empty() {
        remove_empty_directory(state_directory)?;
        remove_empty_directory(home_directory)?;
        if managed_state_present && system_group_exists(aegis_dto::layout::DIRECT_LOGIN_GROUP)? {
            require_success(
                "remove Aegis direct-login group",
                Command::new("groupdel").arg(aegis_dto::layout::DIRECT_LOGIN_GROUP),
            )?;
        }
    }
    Ok(())
}

fn validate_direct_identity(satellite: &AegisDirectSatellite) -> Result<()> {
    if !valid_direct_account(&satellite.account) {
        bail!(
            "satellite `{}` has invalid managed account `{}`",
            satellite.slug,
            satellite.account
        );
    }
    let valid_principal = satellite
        .ssh_principal
        .strip_prefix("aegis-direct-")
        .is_some_and(|suffix| {
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        });
    if !valid_principal {
        bail!(
            "satellite `{}` has invalid direct SSH principal `{}`",
            satellite.slug,
            satellite.ssh_principal
        );
    }
    Ok(())
}

fn ensure_direct_group(managed_state_present: bool) -> Result<()> {
    if system_group_exists(aegis_dto::layout::DIRECT_LOGIN_GROUP)? {
        if !managed_state_present {
            bail!(
                "refusing to adopt existing unmanaged Unix group `{}` for paired satellites",
                aegis_dto::layout::DIRECT_LOGIN_GROUP
            );
        }
    } else {
        require_success(
            "create Aegis direct-login group",
            Command::new("groupadd")
                .arg("--system")
                .arg(aegis_dto::layout::DIRECT_LOGIN_GROUP),
        )?;
    }
    Ok(())
}

fn system_group_exists(group: &str) -> Result<bool> {
    Ok(system_group_gid(group)?.is_some())
}

fn system_group_gid(group: &str) -> Result<Option<u32>> {
    let Some(entry) = getent_entry("group", group)? else {
        return Ok(None);
    };
    let gid = entry
        .trim_end()
        .split(':')
        .nth(2)
        .ok_or_else(|| anyhow!("invalid getent group result for `{group}`"))?
        .parse::<u32>()
        .with_context(|| format!("invalid GID in getent group result for `{group}`"))?;
    Ok(Some(gid))
}

#[derive(Debug, PartialEq, Eq)]
struct SystemAccount {
    uid: u32,
    gid: u32,
    home: PathBuf,
    shell: PathBuf,
}

fn system_account(account: &str) -> Result<Option<SystemAccount>> {
    let Some(entry) = getent_entry("passwd", account)? else {
        return Ok(None);
    };
    let fields = entry.trim_end().split(':').collect::<Vec<_>>();
    if fields.len() != 7 || fields[0] != account {
        bail!("invalid getent passwd result for `{account}`");
    }
    Ok(Some(SystemAccount {
        uid: fields[2]
            .parse::<u32>()
            .with_context(|| format!("invalid UID in getent passwd result for `{account}`"))?,
        gid: fields[3]
            .parse::<u32>()
            .with_context(|| format!("invalid GID in getent passwd result for `{account}`"))?,
        home: PathBuf::from(fields[5]),
        shell: PathBuf::from(fields[6]),
    }))
}

fn getent_entry(database: &str, key: &str) -> Result<Option<String>> {
    let output = run_capture(
        Command::new("timeout")
            .args(["--signal=TERM", "--kill-after=2s"])
            .arg(format!("{}s", NSS_QUERY_TIMEOUT.as_secs()))
            .args(["getent", database, key]),
    )?;
    match output.status.code() {
        Some(0) => Ok(Some(output.stdout)),
        Some(2) => Ok(None),
        Some(124 | 137) => bail!(
            "getent {database} {key} timed out after {} seconds",
            NSS_QUERY_TIMEOUT.as_secs()
        ),
        status => bail!(
            "getent {database} {key} failed with status {}: {}",
            status
                .map(|status| status.to_string())
                .unwrap_or_else(|| "signal".to_string()),
            output.stderr.trim()
        ),
    }
}

fn direct_account_state_path(account: &str) -> PathBuf {
    Path::new(aegis_dto::layout::DIRECT_STATE_DIRECTORY).join(format!("{account}.json"))
}

fn ensure_direct_account(account: &str, satellite_slug: &str) -> Result<()> {
    let state_path = direct_account_state_path(account);
    let existing_account = system_account(account)?;
    let expected_state = DirectAccountState {
        account: account.to_string(),
        satellite_slug: satellite_slug.to_string(),
    };
    let existing_state = match fs::read_to_string(&state_path) {
        Ok(raw) => Some(
            serde_json::from_str::<DirectAccountState>(&raw)
                .with_context(|| format!("failed to parse {}", state_path.display()))?,
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", state_path.display()));
        }
    };
    if existing_account.is_some() && existing_state.is_none() {
        bail!(
            "refusing to adopt existing unmanaged Unix account `{account}` for satellite `{satellite_slug}`"
        );
    }
    if let Some(existing_state) = existing_state
        && existing_state != expected_state
    {
        bail!(
            "managed direct account `{account}` belongs to satellite `{}` instead of `{satellite_slug}`",
            existing_state.satellite_slug
        );
    }
    let mut state_content =
        serde_json::to_string(&expected_state).context("failed to encode direct account")?;
    state_content.push('\n');
    write_text_file_if_changed(&state_path, &state_content, Some(0o600))?;

    let home = Path::new(aegis_dto::layout::DIRECT_HOME_DIRECTORY).join(account);
    let group_gid = system_group_gid(aegis_dto::layout::DIRECT_LOGIN_GROUP)?
        .ok_or_else(|| anyhow!("Aegis direct-login group is missing"))?;
    if existing_account.is_none() {
        require_success(
            "create Aegis direct-login account",
            Command::new("useradd")
                .arg("--system")
                .arg("--gid")
                .arg(aegis_dto::layout::DIRECT_LOGIN_GROUP)
                .arg("--home-dir")
                .arg(&home)
                .arg("--create-home")
                .arg("--shell")
                .arg("/bin/sh")
                .arg(account),
        )?;
    } else if existing_account.as_ref().is_some_and(|existing| {
        existing.gid != group_gid || existing.home != home || existing.shell != Path::new("/bin/sh")
    }) {
        require_success(
            "reconcile Aegis direct-login account",
            Command::new("usermod")
                .arg("--gid")
                .arg(aegis_dto::layout::DIRECT_LOGIN_GROUP)
                .arg("--home")
                .arg(&home)
                .arg("--shell")
                .arg("/bin/sh")
                .arg(account),
        )?;
    }
    ensure_directory_mode(&home, 0o700)?;
    let account_uid = system_account(account)?
        .ok_or_else(|| anyhow!("new Aegis direct-login account `{account}` is missing"))?
        .uid;
    let metadata =
        fs::metadata(&home).with_context(|| format!("failed to inspect {}", home.display()))?;
    if metadata.uid() != account_uid || metadata.gid() != group_gid {
        require_success(
            "set Aegis direct-login home ownership",
            Command::new("chown")
                .arg(format!(
                    "{account}:{}",
                    aegis_dto::layout::DIRECT_LOGIN_GROUP
                ))
                .arg(&home),
        )?;
    }
    Ok(())
}

fn remove_direct_account(account: &str) -> Result<()> {
    if !valid_direct_account(account) {
        bail!("refusing to remove invalid direct account `{account}`");
    }
    remove_file_if_exists(
        &Path::new(aegis_dto::layout::AUTHORIZED_PRINCIPALS_DIRECTORY).join(account),
    )?;
    if system_account(account)?.is_some() {
        let _ = run_capture(Command::new("loginctl").args(["terminate-user", account]));
        let _ = run_capture(Command::new("pkill").args(["-KILL", "-u", account]));
        require_success(
            "remove revoked Aegis direct-login account",
            Command::new("userdel").arg("--remove").arg(account),
        )?;
    }
    let home = Path::new(aegis_dto::layout::DIRECT_HOME_DIRECTORY).join(account);
    match fs::remove_dir_all(&home) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to remove {}", home.display()));
        }
    }
    remove_file_if_exists(&direct_account_state_path(account))?;
    Ok(())
}

fn remove_empty_directory(path: &Path) -> Result<()> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

fn read_directory_if_exists(path: &Path) -> Result<Vec<fs::DirEntry>> {
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    entries
        .map(|entry| entry.with_context(|| format!("failed to read entry in {}", path.display())))
        .collect()
}

pub(crate) fn disable_direct_gateway(config: &AegisDirectGatewayConfig) -> Result<()> {
    reconcile_direct_accounts(&[], false)?;
    remove_file_if_exists(Path::new(aegis_dto::layout::DIRECT_CLIENT_CA_PATH))?;
    let wireguard_config = managed_wireguard_config(&config.interface);
    let service = wireguard_service_name(&wireguard_config);
    if wireguard_service_is_active(&service)? || service_is_enabled(&service)? {
        let output = run_capture(Command::new("systemctl").args(["disable", "--now", &service]))?;
        if !output.status.success()
            && (wireguard_service_is_active(&service)? || service_is_enabled(&service)?)
        {
            bail!(
                "failed to disable Aegis direct-gateway WireGuard service `{service}`: {}",
                command_output_error(&output)
            );
        }
    }
    if wireguard_config.config_path.exists() {
        fs::remove_file(&wireguard_config.config_path).with_context(|| {
            format!(
                "failed to remove {}",
                wireguard_config.config_path.display()
            )
        })?;
    }
    remove_sshd_dropin(Path::new(aegis_dto::layout::DIRECT_SSHD_DROPIN_PATH))
}

fn direct_gateway_sshd_dropin_contents(inventory: &DirectGatewayState) -> String {
    format!(
        "# Managed by aegis. Makes the direct-gateway interface certificate-only.\n\
         Match LocalAddress {ipv4},{ipv6}\n\
           AuthenticationMethods publickey\n\
           PubkeyAuthentication yes\n\
           PasswordAuthentication no\n\
           KbdInteractiveAuthentication no\n\
           ChallengeResponseAuthentication no\n\
           GSSAPIAuthentication no\n\
           HostbasedAuthentication no\n\
           AuthorizedKeysFile none\n\
           DisableForwarding yes\n\
           PermitTTY yes\n\
           X11Forwarding no\n\
         Match LocalAddress {ipv4},{ipv6} Group {direct_group}\n\
           ForceCommand {aegis_binary} agent direct-ssh\n\
           DisableForwarding yes\n\
           PermitTTY yes\n\
         Match all\n",
        aegis_binary = aegis_dto::layout::SYSTEM_BINARY_PATH,
        direct_group = aegis_dto::layout::DIRECT_LOGIN_GROUP,
        ipv4 = inventory.gateway.wireguard.ipv4,
        ipv6 = inventory.gateway.wireguard.ipv6,
    )
}

#[cfg(target_os = "linux")]
fn apply_wireguard_config(
    config: &WireGuardConfig,
    network_wireguard: &AegisNetworkWireGuardConfig,
    local: &InventoryHost,
    peers: &[&InventoryHost],
    public_ipv6_available: bool,
    ipv4_endpoint_required: bool,
) -> Result<()> {
    let wireguard = local.wireguard.as_ref().ok_or_else(|| {
        anyhow!(
            "local host `{}` is missing a WireGuard identity",
            local.alias()
        )
    })?;
    let desired_config = wireguard_config_contents(WireGuardConfigOptions {
        network: network_wireguard,
        private_key: &load_private_key(&config.private_key_path)?,
        wireguard_ipv4: &wireguard.ipv4,
        wireguard_ipv6: &wireguard.ipv6,
        peers,
        public_ipv6_available,
        ipv4_endpoint_required,
        mode: local.mode,
    })?;
    let runtime = WireGuardRuntime::parse(&config.interface, &desired_config)?;
    let quick_applied = wireguard_quick_applied_config(&config.interface, &desired_config)?;
    let quick_content_changed =
        wireguard_quick_config_changed(&config.config_path, &config.interface, &quick_applied)?;
    ensure_directory_mode(Path::new(AEGIS_WIREGUARD_DIR), 0o755)?;
    ensure_wireguard_systemd_unit()?;
    write_text_file(&config.config_path, &desired_config, Some(0o600))?;

    let service = wireguard_service_name(config);
    ensure_service_enabled(&service, "WireGuard")?;
    let active = wireguard_service_is_active(&service)?;
    let quick_activation_required =
        config_activation_required(&quick_applied, quick_content_changed)?;
    if !active {
        if !quick_activation_required {
            quick_applied.mark_pending()?;
        }
        require_success(
            "start WireGuard service",
            Command::new("systemctl").args(["start", &service]),
        )?;
        runtime.record_start()?;
        quick_applied.mark()?;
    } else if !wireguard_interface_addresses_match(
        &config.interface,
        &wireguard.ipv4,
        &wireguard.ipv6,
    )? || quick_activation_required
    {
        require_success(
            "restart WireGuard service after wg-quick configuration change",
            Command::new("systemctl").args(["restart", &service]),
        )?;
        runtime.record_start()?;
        quick_applied.mark()?;
    } else {
        runtime.reconcile()?;
    }
    reconcile_wireguard_routes(network_wireguard, &config.interface, peers)?;
    Ok(())
}

fn ensure_service_enabled(service: &str, description: &str) -> Result<()> {
    if service_is_enabled(service)? {
        return Ok(());
    }
    require_success(
        &format!("enable {description} service"),
        Command::new("systemctl").args(["enable", service]),
    )?;
    Ok(())
}

fn service_is_enabled(service: &str) -> Result<bool> {
    Ok(
        run_capture(Command::new("systemctl").args(["is-enabled", "--quiet", service]))?
            .status
            .success(),
    )
}

fn ensure_egress_services_running() -> Result<()> {
    ensure_managed_service_running(
        aegis_dto::layout::EGRESS_RESOLVED_DROPIN_PATH,
        "systemd-resolved.service",
    )?;
    ensure_managed_service_running(
        aegis_dto::layout::EGRESS_POLICY_SYSTEMD_UNIT_PATH,
        aegis_dto::layout::EGRESS_POLICY_SYSTEMD_SERVICE_NAME,
    )
}

fn ensure_managed_service_running(path: &str, service: &str) -> Result<()> {
    if Path::new(path).exists() && !wireguard_service_is_active(service)? {
        require_success(
            &format!("restore {service}"),
            bounded_egress_command("/usr/bin/systemctl").args(["start", service]),
        )?;
        ensure!(
            wireguard_service_is_active(service)?,
            "{service} is still inactive after start"
        );
    }
    Ok(())
}

fn wireguard_service_is_active(service: &str) -> Result<bool> {
    Ok(
        run_capture(bounded_egress_command("/usr/bin/systemctl").args([
            "is-active",
            "--quiet",
            service,
        ]))?
        .status
        .success(),
    )
}

fn wireguard_interface_addresses_match(
    interface: &str,
    expected_ipv4: &str,
    expected_ipv6: &str,
) -> Result<bool> {
    wireguard_interface_address_set_matches(
        interface,
        &BTreeSet::from([
            (expected_ipv4.to_string(), 32),
            (expected_ipv6.to_string(), 128),
        ]),
    )
}

fn wireguard_interface_address_set_matches(
    interface: &str,
    expected: &BTreeSet<(String, u8)>,
) -> Result<bool> {
    let output = run_capture(Command::new("ip").args(["-j", "address", "show", "dev", interface]))?;
    if !output.status.success() {
        return Ok(false);
    }
    let interfaces = serde_json::from_str::<Vec<IpAddressInterface>>(&output.stdout)
        .context("failed to parse WireGuard interface addresses")?;
    let actual = interfaces
        .into_iter()
        .flat_map(|interface| interface.addr_info)
        .filter(|address| address.scope == "global")
        .filter(|address| matches!(address.family.as_str(), "inet" | "inet6"))
        .map(|address| (address.local, address.prefixlen))
        .collect::<BTreeSet<_>>();
    Ok(actual == *expected)
}

fn strip_wg_quick_fields(config: &str) -> Result<String> {
    let mut output = String::new();
    let mut in_interface = false;
    let mut found_interface = false;
    for line in config.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_interface = trimmed.eq_ignore_ascii_case("[Interface]");
            found_interface |= in_interface;
        }
        let skip = in_interface
            && trimmed
                .split_once('=')
                .map(|(key, _)| key.trim())
                .is_some_and(|key| {
                    WG_QUICK_INTERFACE_FIELDS
                        .iter()
                        .any(|field| key.eq_ignore_ascii_case(field))
                });
        if !skip {
            output.push_str(line);
            output.push('\n');
        }
    }
    if !found_interface {
        bail!("generated WireGuard configuration has no [Interface] section");
    }
    Ok(output)
}

fn wireguard_quick_applied_config(interface: &str, desired: &str) -> Result<AppliedConfig> {
    let mut parsed = parse_wireguard_runtime_config(desired)?;
    parsed
        .interface
        .retain(|field, _| WG_QUICK_INTERFACE_FIELDS.contains(&field.as_str()));
    Ok(AppliedConfig::new(
        &format!("wireguard-{interface}-quick"),
        &serde_json::to_vec(&parsed.interface)
            .context("failed to encode wg-quick applied configuration")?,
    ))
}

fn wireguard_quick_config_changed(
    path: &Path,
    interface: &str,
    desired: &AppliedConfig,
) -> Result<bool> {
    let current = match fs::read_to_string(path) {
        Ok(current) => current,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    let current = match wireguard_quick_applied_config(interface, &current) {
        Ok(current) => current,
        Err(_) => return Ok(true),
    };
    Ok(current.digest != desired.digest)
}

#[derive(Clone, Copy)]
enum WireGuardRuntimeSection {
    Interface,
    Peer,
}

fn parse_wireguard_runtime_config(config: &str) -> Result<WireGuardRuntimeConfig> {
    let mut parsed = WireGuardRuntimeConfig::default();
    let mut saw_interface = false;
    let mut current = None;
    let mut fields = BTreeMap::<String, Vec<String>>::new();
    for (line_index, line) in config.lines().enumerate() {
        let line = line.split_once('#').map_or(line, |(value, _)| value).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            if let Some(section) = current.take() {
                finish_wireguard_runtime_section(section, &mut fields, &mut parsed)?;
            }
            current = Some(
                match line[1..line.len() - 1].trim().to_ascii_lowercase().as_str() {
                    "interface" if !saw_interface => {
                        saw_interface = true;
                        WireGuardRuntimeSection::Interface
                    }
                    "interface" => bail!("WireGuard runtime configuration has multiple interfaces"),
                    "peer" => WireGuardRuntimeSection::Peer,
                    section => bail!("unsupported WireGuard runtime section `{section}`"),
                },
            );
            continue;
        }
        if current.is_none() {
            bail!(
                "WireGuard runtime configuration field appears before a section on line {}",
                line_index + 1
            );
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            anyhow!(
                "invalid WireGuard runtime configuration field on line {}",
                line_index + 1
            )
        })?;
        let key = key.trim().to_ascii_lowercase();
        let values = if key == "allowedips" {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        } else {
            vec![value.trim().to_string()]
        };
        if values.is_empty() {
            bail!(
                "WireGuard runtime configuration field `{key}` is empty on line {}",
                line_index + 1
            );
        }
        fields.entry(key).or_default().extend(values);
    }
    if let Some(section) = current {
        finish_wireguard_runtime_section(section, &mut fields, &mut parsed)?;
    }
    if !saw_interface {
        bail!("WireGuard runtime configuration has no [Interface] section");
    }
    Ok(parsed)
}

fn finish_wireguard_runtime_section(
    section: WireGuardRuntimeSection,
    fields: &mut BTreeMap<String, Vec<String>>,
    parsed: &mut WireGuardRuntimeConfig,
) -> Result<()> {
    if let Some(values) = fields.get_mut("allowedips") {
        values.sort();
        values.dedup();
    }
    match section {
        WireGuardRuntimeSection::Interface => {
            if let Some(values) = fields.get_mut("fwmark") {
                ensure!(
                    values.len() == 1,
                    "WireGuard must contain at most one FwMark"
                );
                let value = values[0].to_ascii_lowercase();
                let mark = if value == "off" {
                    0
                } else {
                    let (digits, radix) = if let Some(hex) = value.strip_prefix("0x") {
                        (hex, 16)
                    } else if value.starts_with('0') && value.len() > 1 {
                        (&value[1..], 8)
                    } else {
                        (value.as_str(), 10)
                    };
                    u32::from_str_radix(digits, radix).context("invalid WireGuard FwMark")?
                };
                if mark == 0 {
                    fields.remove("fwmark");
                } else {
                    values[0] = format!("0x{mark:x}");
                }
            }
            parsed.interface = std::mem::take(fields);
        }
        WireGuardRuntimeSection::Peer => {
            // syncconf preserves omitted keepalives on existing peers. Always express the
            // default so a former upstream becomes a passive gateway member on handoff.
            fields
                .entry("persistentkeepalive".to_string())
                .or_insert_with(|| vec!["0".to_string()]);
            let public_keys = fields
                .get("publickey")
                .filter(|values| values.len() == 1)
                .ok_or_else(|| anyhow!("WireGuard peer must contain exactly one PublicKey"))?;
            let public_key = public_keys[0].clone();
            if parsed
                .peers
                .insert(public_key, std::mem::take(fields))
                .is_some()
            {
                bail!("WireGuard runtime configuration contains a duplicate peer");
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn reconcile_wireguard_routes(
    network: &AegisNetworkWireGuardConfig,
    interface: &str,
    peers: &[&InventoryHost],
) -> Result<()> {
    let desired = peers
        .iter()
        .filter_map(|peer| peer.wireguard.as_ref())
        .flat_map(|wireguard| {
            [
                format!("{}/32", wireguard.ipv4),
                format!("{}/128", wireguard.ipv6),
            ]
        })
        .collect::<BTreeSet<_>>();
    reconcile_managed_wireguard_routes(
        &network.subnet_ipv4,
        &network.subnet_ipv6,
        interface,
        desired,
    )
}

fn reconcile_direct_gateway_routes(
    config: &AegisDirectGatewayConfig,
    interface: &str,
    inventory: &DirectGatewayState,
) -> Result<()> {
    let desired = direct_gateway_peers(inventory)
        .into_iter()
        .flat_map(|peer| [format!("{}/32", peer.ipv4), format!("{}/128", peer.ipv6)])
        .collect::<BTreeSet<_>>();
    reconcile_managed_wireguard_routes(&config.subnet_ipv4, &config.subnet_ipv6, interface, desired)
}

fn reconcile_managed_wireguard_routes(
    subnet_ipv4: &str,
    subnet_ipv6: &str,
    interface: &str,
    desired: BTreeSet<String>,
) -> Result<()> {
    let current = current_managed_wireguard_routes(subnet_ipv4, subnet_ipv6, interface)?;
    for route in desired.difference(&current.direct) {
        let family = if route.contains(':') { "-6" } else { "-4" };
        require_success(
            "install WireGuard peer route",
            Command::new("ip").args([family, "route", "replace", route, "dev", interface]),
        )?;
    }
    for route in current.all.difference(&desired) {
        let family = if route.contains(':') { "-6" } else { "-4" };
        require_success(
            "remove stale WireGuard peer route",
            Command::new("ip").args([family, "route", "del", route, "dev", interface]),
        )?;
    }
    Ok(())
}

fn current_managed_wireguard_routes(
    subnet_ipv4: &str,
    subnet_ipv6: &str,
    interface: &str,
) -> Result<ManagedWireGuardRoutes> {
    let mut routes = ManagedWireGuardRoutes::default();
    for family in ["-4", "-6"] {
        let output = require_success(
            "list WireGuard peer routes",
            Command::new("ip").args(["-j", family, "route", "show", "dev", interface]),
        )?;
        let entries = serde_json::from_str::<Vec<IpRouteEntry>>(&output.stdout)
            .context("failed to parse WireGuard peer routes")?;
        for entry in entries {
            let Some(route) = normalize_managed_wireguard_route_in_subnets(
                subnet_ipv4,
                subnet_ipv6,
                match entry.dst.as_deref() {
                    Some(destination) => destination,
                    None => continue,
                },
            ) else {
                continue;
            };
            routes.all.insert(route.clone());
            if entry.gateway.is_none()
                && entry
                    .route_type
                    .as_deref()
                    .is_none_or(|route_type| route_type == "unicast")
            {
                routes.direct.insert(route);
            }
        }
    }
    Ok(routes)
}

#[derive(Debug, Default)]
struct ManagedWireGuardRoutes {
    all: BTreeSet<String>,
    direct: BTreeSet<String>,
}

#[derive(Debug, Deserialize)]
struct IpRouteEntry {
    dst: Option<String>,
    #[serde(default)]
    table: Option<IpRouteTable>,
    #[serde(default)]
    dev: Option<String>,
    #[serde(default)]
    metric: Option<u32>,
    #[serde(default)]
    gateway: Option<String>,
    #[serde(default, rename = "type")]
    route_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum IpRouteTable {
    Number(u32),
    Name(String),
}

impl IpRouteTable {
    fn matches(&self, table: u32) -> bool {
        match self {
            Self::Number(value) => *value == table,
            Self::Name(value) => value.parse::<u32>() == Ok(table),
        }
    }
}

impl IpRouteEntry {
    fn is_live_egress_default(&self, interface: &str) -> bool {
        self.dst.as_deref() == Some("default")
            && self.dev.as_deref() == Some(interface)
            && self.metric == Some(10)
            && self
                .route_type
                .as_deref()
                .is_none_or(|route_type| route_type == "unicast")
    }

    fn is_unreachable_egress_default(&self) -> bool {
        self.dst.as_deref() == Some("default")
            && self.metric == Some(32_760)
            && self.route_type.as_deref() == Some("unreachable")
    }
}

#[cfg(all(test, target_os = "linux"))]
fn normalize_managed_wireguard_route(
    network: &AegisNetworkWireGuardConfig,
    destination: &str,
) -> Option<String> {
    normalize_managed_wireguard_route_in_subnets(
        &network.subnet_ipv4,
        &network.subnet_ipv6,
        destination,
    )
}

fn normalize_managed_wireguard_route_in_subnets(
    subnet_ipv4: &str,
    subnet_ipv6: &str,
    destination: &str,
) -> Option<String> {
    let (address, prefix) = match destination.split_once('/') {
        Some((address, prefix)) => (address, prefix.parse::<u8>().ok()?),
        None => (
            destination,
            if destination.contains(':') { 128 } else { 32 },
        ),
    };
    let address = address.parse::<IpAddr>().ok()?;
    match address {
        IpAddr::V4(address)
            if prefix == 32
                && parse_ipv4_subnet(subnet_ipv4)
                    .is_ok_and(|subnet| ipv4_in_subnet(subnet, address)) =>
        {
            Some(format!("{address}/32"))
        }
        IpAddr::V6(address)
            if prefix == 128
                && parse_ipv6_subnet(subnet_ipv6)
                    .is_ok_and(|subnet| ipv6_in_subnet(subnet, address)) =>
        {
            Some(format!("{address}/128"))
        }
        _ => None,
    }
}

fn wireguard_service_name(config: &WireGuardConfig) -> String {
    format!("{AEGIS_WIREGUARD_UNIT_PREFIX}{}", config.interface)
}

fn managed_wireguard_config(interface: &str) -> WireGuardConfig {
    let base = Path::new(AEGIS_WIREGUARD_DIR);
    WireGuardConfig {
        interface: interface.to_string(),
        config_path: base.join(format!("{interface}.conf")),
        private_key_path: base.join(format!("{interface}.key")),
        public_key_path: base.join(format!("{interface}.pub")),
    }
}

fn ensure_wireguard_systemd_unit() -> Result<()> {
    let desired = aegis_dto::managed_wireguard_systemd_unit_contents();
    let applied = AppliedConfig::new(WIREGUARD_UNIT_APPLIED_CONFIG_NAME, desired.as_bytes());
    let changed = write_text_file_if_changed(
        Path::new(AEGIS_WIREGUARD_UNIT_TEMPLATE_PATH),
        &desired,
        Some(0o644),
    )?;
    if !config_activation_required(&applied, changed)? {
        return Ok(());
    }
    require_success(
        "reload systemd after WireGuard unit update",
        Command::new("systemctl").arg("daemon-reload"),
    )?;
    applied.mark()
}

#[cfg(target_os = "linux")]
struct WireGuardConfigOptions<'a> {
    network: &'a AegisNetworkWireGuardConfig,
    private_key: &'a str,
    wireguard_ipv4: &'a str,
    wireguard_ipv6: &'a str,
    mode: AegisHostMode,
    peers: &'a [&'a InventoryHost],
    public_ipv6_available: bool,
    ipv4_endpoint_required: bool,
}

#[cfg(target_os = "linux")]
fn wireguard_config_contents(options: WireGuardConfigOptions<'_>) -> Result<String> {
    let WireGuardConfigOptions {
        network: network_wireguard,
        private_key,
        wireguard_ipv4,
        wireguard_ipv6,
        mode,
        peers,
        public_ipv6_available,
        ipv4_endpoint_required,
    } = options;
    let listen_port = WireGuardListenPort::for_listener(
        network_wireguard.endpoint_port,
        mode == AegisHostMode::Hub,
    )?;
    let mut content = format!(
        "{MANAGED_CONFIG_HEADER}\
         [Interface]\n\
         Address = {wireguard_ipv4}/32,{wireguard_ipv6}/128\n\
         PrivateKey = {private_key}\n\
         ListenPort = {}\n\
         MTU = {}\n\
         FwMark = {}\n\n",
        listen_port.config_port(),
        network_wireguard.mtu,
        network_wireguard.fwmark,
    );

    for peer in peers {
        let Some(wireguard) = peer.wireguard.as_ref() else {
            continue;
        };
        content.push_str("[Peer]\n");
        content.push_str(&format!("PublicKey = {}\n", wireguard.public_key));
        if let Some(endpoint) = selected_wireguard_endpoint(
            peer,
            network_wireguard.endpoint_port,
            public_ipv6_available,
            ipv4_endpoint_required,
        ) {
            content.push_str(&format!("Endpoint = {endpoint}\n"));
            content.push_str("PersistentKeepalive = 5\n");
        }
        let allowed_ips = [
            format!("{}/32", wireguard.ipv4),
            format!("{}/128", wireguard.ipv6),
        ];
        content.push_str(&format!("AllowedIPs = {}\n\n", allowed_ips.join(",")));
    }

    if peers.is_empty() {
        content.push_str("# No peers are currently published for this node.\n");
    }

    Ok(content)
}

fn selected_wireguard_endpoint(
    peer: &InventoryHost,
    port: u16,
    public_ipv6_available: bool,
    ipv4_endpoint_required: bool,
) -> Option<SocketAddr> {
    let endpoint = if ipv4_endpoint_required {
        wireguard_endpoint_ipv4(peer.wireguard_endpoints())
    } else {
        preferred_wireguard_endpoint_ip_with_ipv6_support(
            peer.wireguard_endpoints(),
            public_ipv6_available,
        )
    };
    endpoint
        .and_then(|endpoint| endpoint.parse::<IpAddr>().ok())
        .map(|endpoint| SocketAddr::new(endpoint, port))
}

fn wireguard_endpoint_peer(
    interface: &str,
    port: u16,
    peer: &InventoryHost,
    public_ipv6_available: bool,
    ipv4_endpoint_required: bool,
) -> Option<WireGuardEndpointPeer> {
    let wireguard = peer.wireguard.as_ref()?;
    let endpoint =
        selected_wireguard_endpoint(peer, port, public_ipv6_available, ipv4_endpoint_required)?;
    let probe = wireguard
        .ipv4
        .parse::<Ipv4Addr>()
        .ok()
        .zip(peer.ssh.as_ref().and_then(|ssh| ssh.port))
        .map(SocketAddr::from);
    Some(WireGuardEndpointPeer {
        host_id: peer.host_id,
        alias: peer.alias().clone(),
        interface: interface.to_string(),
        public_key: wireguard.public_key.clone(),
        endpoint,
        probe,
    })
}

fn direct_gateway_wireguard_config_contents(
    inventory: &DirectGatewayState,
    private_key: &str,
) -> Result<String> {
    let listen_port = WireGuardListenPort::for_listener(inventory.config.endpoint_port, true)?;
    let mut content = format!(
        "{MANAGED_CONFIG_HEADER}\
         [Interface]\n\
         Address = {}/32,{}/128\n\
         PrivateKey = {private_key}\n\
         ListenPort = {}\n\
         MTU = {}\n\
         FwMark = {}\n\
         Table = off\n\
         PostUp = {}\n\
         PostUp = {}\n\
         PreDown = {}\n\
         PreDown = {}\n\n",
        inventory.gateway.wireguard.ipv4,
        inventory.gateway.wireguard.ipv6,
        listen_port.config_port(),
        inventory.config.mtu,
        inventory.config.fwmark,
        direct_gateway_firewall_command(
            "iptables",
            "PostUp",
            &inventory.gateway.wireguard.ipv4,
            &inventory.config.subnet_ipv4,
        ),
        direct_gateway_firewall_command(
            "ip6tables",
            "PostUp",
            &inventory.gateway.wireguard.ipv6,
            &inventory.config.subnet_ipv6,
        ),
        direct_gateway_firewall_command(
            "iptables",
            "PreDown",
            &inventory.gateway.wireguard.ipv4,
            &inventory.config.subnet_ipv4,
        ),
        direct_gateway_firewall_command(
            "ip6tables",
            "PreDown",
            &inventory.gateway.wireguard.ipv6,
            &inventory.config.subnet_ipv6,
        ),
    );
    let peers = direct_gateway_peers(inventory);
    for peer in &peers {
        content.push_str("[Peer]\n");
        content.push_str(&format!("PublicKey = {}\n", peer.public_key));
        content.push_str(&format!(
            "AllowedIPs = {}/32,{}/128\n\n",
            peer.ipv4, peer.ipv6
        ));
    }
    if peers.is_empty() {
        content.push_str("# No direct identities are currently published for this hub.\n");
    }
    Ok(content)
}

fn direct_gateway_peers(inventory: &DirectGatewayState) -> Vec<&AegisDirectWireGuard> {
    inventory
        .satellites
        .iter()
        .map(|satellite| &satellite.wireguard)
        .collect()
}

fn direct_gateway_firewall_command(
    program: &str,
    phase: &str,
    destination: &str,
    source_subnet: &str,
) -> String {
    let blocked_destinations = match program {
        "iptables" => [
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "224.0.0.0/4",
            "240.0.0.0/4",
        ]
        .as_slice(),
        "ip6tables" => [
            "::/128",
            "::1/128",
            "100::/64",
            "2001:db8::/32",
            "fc00::/7",
            "fe80::/10",
            "ff00::/8",
        ]
        .as_slice(),
        _ => unreachable!("direct-gateway firewall family is fixed"),
    };
    let blocked_rules = blocked_destinations
        .iter()
        .map(|subnet| {
            format!(
                "{program} -w 5 -A AEGIS_DIRECT_FWD -i %i -s {source_subnet} -d {subnet} -j DROP; "
            )
        })
        .collect::<String>();
    match phase {
        "PostUp" => format!(
            "/usr/sbin/sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1; \
             {program} -w 5 -N AEGIS_DIRECT_IN 2>/dev/null || true; \
             {program} -w 5 -F AEGIS_DIRECT_IN; \
             {program} -w 5 -A AEGIS_DIRECT_IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; \
             {program} -w 5 -A AEGIS_DIRECT_IN -d {destination} -p tcp --dport 22 -j ACCEPT; \
             {program} -w 5 -A AEGIS_DIRECT_IN -j DROP; \
             {program} -w 5 -C INPUT -i %i -j AEGIS_DIRECT_IN 2>/dev/null || \
             {program} -w 5 -I INPUT 1 -i %i -j AEGIS_DIRECT_IN; \
             {program} -w 5 -N AEGIS_DIRECT_FWD 2>/dev/null || true; \
             {program} -w 5 -F AEGIS_DIRECT_FWD; \
             {program} -w 5 -A AEGIS_DIRECT_FWD -i %i -o %i -j DROP; \
             {program} -w 5 -A AEGIS_DIRECT_FWD -o %i -d {source_subnet} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; \
             {blocked_rules}\
             {program} -w 5 -A AEGIS_DIRECT_FWD -i %i -s {source_subnet} -j ACCEPT; \
             {program} -w 5 -A AEGIS_DIRECT_FWD -j DROP; \
             {program} -w 5 -C FORWARD -i %i -j AEGIS_DIRECT_FWD 2>/dev/null || \
             {program} -w 5 -I FORWARD 1 -i %i -j AEGIS_DIRECT_FWD; \
             {program} -w 5 -C FORWARD -o %i -j AEGIS_DIRECT_FWD 2>/dev/null || \
             {program} -w 5 -I FORWARD 1 -o %i -j AEGIS_DIRECT_FWD; \
             {program} -w 5 -t nat -N AEGIS_DIRECT_NAT 2>/dev/null || true; \
             {program} -w 5 -t nat -F AEGIS_DIRECT_NAT; \
             {program} -w 5 -t nat -A AEGIS_DIRECT_NAT -s {source_subnet} -j MASQUERADE; \
             {program} -w 5 -t nat -C POSTROUTING -s {source_subnet} -j AEGIS_DIRECT_NAT 2>/dev/null || \
             {program} -w 5 -t nat -I POSTROUTING 1 -s {source_subnet} -j AEGIS_DIRECT_NAT"
        ),
        "PreDown" => format!(
            "{program} -w 5 -D INPUT -i %i -j AEGIS_DIRECT_IN 2>/dev/null || true; \
             {program} -w 5 -D FORWARD -i %i -j AEGIS_DIRECT_FWD 2>/dev/null || true; \
             {program} -w 5 -D FORWARD -o %i -j AEGIS_DIRECT_FWD 2>/dev/null || true; \
             {program} -w 5 -t nat -D POSTROUTING -s {source_subnet} -j AEGIS_DIRECT_NAT 2>/dev/null || true; \
             {program} -w 5 -F AEGIS_DIRECT_IN 2>/dev/null || true; \
             {program} -w 5 -X AEGIS_DIRECT_IN 2>/dev/null || true; \
             {program} -w 5 -F AEGIS_DIRECT_FWD 2>/dev/null || true; \
             {program} -w 5 -X AEGIS_DIRECT_FWD 2>/dev/null || true; \
             {program} -w 5 -t nat -F AEGIS_DIRECT_NAT 2>/dev/null || true; \
             {program} -w 5 -t nat -X AEGIS_DIRECT_NAT 2>/dev/null || true"
        ),
        _ => unreachable!("direct-gateway firewall phase is fixed"),
    }
}

#[cfg(target_os = "linux")]
fn configure_loopback_internal_addresses(
    mesh: &AegisMeshConfig,
    internal: Option<&AegisNetworkMemberInternalAddresses>,
) -> Result<()> {
    let mut desired = BTreeSet::new();
    if let Some(internal) = internal {
        desired.insert((internal.ipv4.clone(), 32));
        desired.insert((internal.ipv6.clone(), 128));
    }
    let existing = configured_loopback_internal_addresses(mesh)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    for (address, prefixlen) in existing.difference(&desired) {
        let family = if address.contains(':') { "-6" } else { "-4" };
        require_success(
            "remove stale loopback internal IP",
            Command::new("ip").args([
                family,
                "address",
                "del",
                &format!("{address}/{prefixlen}"),
                "dev",
                "lo",
            ]),
        )?;
    }
    for (address, prefixlen) in desired.difference(&existing) {
        let family = if address.contains(':') { "-6" } else { "-4" };
        require_success(
            "configure loopback internal IP",
            Command::new("ip").args([
                family,
                "address",
                "replace",
                &format!("{address}/{prefixlen}"),
                "dev",
                "lo",
            ]),
        )?;
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct IpAddressInterface {
    #[serde(default)]
    addr_info: Vec<IpAddressEntry>,
}

#[derive(Debug, Deserialize)]
struct IpAddressEntry {
    family: String,
    local: String,
    prefixlen: u8,
    scope: String,
}

#[cfg(target_os = "linux")]
fn configured_loopback_internal_addresses(mesh: &AegisMeshConfig) -> Result<Vec<(String, u8)>> {
    let output = require_success(
        "list loopback internal IPs",
        Command::new("ip").args(["-j", "address", "show", "dev", "lo"]),
    )?;
    let interfaces = serde_json::from_str::<Vec<IpAddressInterface>>(&output.stdout)
        .context("failed to parse loopback address inventory")?;
    Ok(interfaces
        .into_iter()
        .flat_map(|interface| interface.addr_info)
        .filter(|address| address.scope == "global")
        .filter_map(|address| {
            let ip = address.local.parse::<IpAddr>().ok()?;
            mesh_contains_ip(mesh, ip).then_some(match address.family.as_str() {
                "inet" | "inet6" => (address.local, address.prefixlen),
                _ => return None,
            })
        })
        .collect())
}

fn mesh_contains_ip(mesh: &AegisMeshConfig, ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => parse_ipv4_subnet(&mesh.subnet_ipv4)
            .map(|subnet| ipv4_in_subnet(subnet, ipv4))
            .unwrap_or(false),
        IpAddr::V6(ipv6) => parse_ipv6_subnet(&mesh.subnet_ipv6)
            .map(|subnet| ipv6_in_subnet(subnet, ipv6))
            .unwrap_or(false),
    }
}

fn parse_ipv4_subnet(cidr: &str) -> Result<(Ipv4Addr, u8)> {
    let (address, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow!("invalid IPv4 subnet `{cidr}`"))?;
    let address = address
        .parse::<Ipv4Addr>()
        .with_context(|| format!("invalid IPv4 subnet `{cidr}`"))?;
    let prefix = prefix
        .parse::<u8>()
        .with_context(|| format!("invalid IPv4 subnet `{cidr}`"))?;
    if prefix > 32 {
        bail!("invalid IPv4 subnet `{cidr}`");
    }
    Ok((address, prefix))
}

fn parse_ipv6_subnet(cidr: &str) -> Result<(Ipv6Addr, u8)> {
    let (address, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow!("invalid IPv6 subnet `{cidr}`"))?;
    let address = address
        .parse::<Ipv6Addr>()
        .with_context(|| format!("invalid IPv6 subnet `{cidr}`"))?;
    let prefix = prefix
        .parse::<u8>()
        .with_context(|| format!("invalid IPv6 subnet `{cidr}`"))?;
    if prefix > 128 {
        bail!("invalid IPv6 subnet `{cidr}`");
    }
    Ok((address, prefix))
}

fn ipv4_in_subnet((network, prefix): (Ipv4Addr, u8), address: Ipv4Addr) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    (u32::from(network) & mask) == (u32::from(address) & mask)
}

fn ipv6_in_subnet((network, prefix): (Ipv6Addr, u8), address: Ipv6Addr) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    };
    (u128::from(network) & mask) == (u128::from(address) & mask)
}

#[cfg(target_os = "linux")]
fn reconcile_babel_overlays(
    wireguard_interface: &str,
    local_host_id: &HostId,
    local_wireguard_ipv4: &str,
    peers: &[&InventoryHost],
    overlay_mtu: u16,
) -> Result<Vec<String>> {
    let expected = peers
        .iter()
        .filter_map(|peer| {
            peer.wireguard.as_ref().map(|wireguard| {
                (
                    peer.host_id,
                    peer_overlay_name(&peer.host_id),
                    peer_overlay_vni(local_host_id, &peer.host_id),
                    wireguard.ipv4.as_str(),
                )
            })
        })
        .collect::<Vec<_>>();
    let expected_names = expected
        .iter()
        .map(|(_, name, _, _)| name.as_str())
        .collect::<BTreeSet<_>>();
    let mut changed_names = BTreeSet::new();

    let output = require_success(
        "list Babel overlays",
        Command::new("ip").args(["-o", "link", "show"]),
    )?;
    for line in output.stdout.lines() {
        let Some(name) = line
            .split_once(": ")
            .map(|(_, rest)| rest)
            .and_then(|rest| rest.split(':').next())
            .and_then(|rest| rest.split('@').next())
        else {
            continue;
        };
        if name.starts_with(BABEL_OVERLAY_PREFIX) && !expected_names.contains(name) {
            require_success(
                "remove stale Babel overlay",
                Command::new("ip").args(["link", "del", "dev", name]),
            )?;
            changed_names.insert(name.to_string());
        }
    }

    for (peer_host_id, name, vni, remote_wireguard_ipv4) in expected {
        if ensure_babel_overlay(
            &name,
            vni,
            wireguard_interface,
            local_wireguard_ipv4,
            remote_wireguard_ipv4,
            &peer_overlay_transit_addrs(local_host_id, &peer_host_id),
            overlay_mtu,
        )? {
            changed_names.insert(name);
        }
    }

    Ok(changed_names.into_iter().collect())
}

#[cfg(target_os = "linux")]
fn configure_mesh_sysctls(mode: AgentMode, wireguard_interface: &str) -> Result<()> {
    if mode == AgentMode::Hub {
        set_sysctl_if_changed(
            Path::new("/proc/sys/net/ipv4/ip_forward"),
            "net.ipv4.ip_forward",
            "1",
        )?;
        set_sysctl_if_changed(
            Path::new("/proc/sys/net/ipv6/conf/all/forwarding"),
            "net.ipv6.conf.all.forwarding",
            "1",
        )?;
    }
    set_ipv4_rp_filter("all", "1")?;
    set_ipv4_rp_filter("default", "1")?;
    set_ipv4_rp_filter(wireguard_interface, "1")?;
    for interface in mesh_overlay_interfaces()? {
        set_ipv4_rp_filter(&interface, "2")?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn enable_mesh_ipv6(wireguard_interface: &str, require_wireguard_interface: bool) -> Result<()> {
    set_ipv6_enabled("all")?;
    set_ipv6_enabled("default")?;
    set_ipv6_enabled("lo")?;
    if require_wireguard_interface || ipv6_interface_sysctl_exists(wireguard_interface) {
        set_ipv6_enabled(wireguard_interface)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_ipv6_enabled(interface: &str) -> Result<()> {
    set_sysctl_if_changed(
        &Path::new("/proc/sys/net/ipv6/conf")
            .join(interface)
            .join("disable_ipv6"),
        &format!("net.ipv6.conf.{interface}.disable_ipv6"),
        "0",
    )
}

#[cfg(target_os = "linux")]
fn ipv6_interface_sysctl_exists(interface: &str) -> bool {
    Path::new("/proc/sys/net/ipv6/conf")
        .join(interface)
        .join("disable_ipv6")
        .exists()
}

fn set_ipv4_rp_filter(interface: &str, value: &str) -> Result<()> {
    set_sysctl_if_changed(
        &Path::new("/proc/sys/net/ipv4/conf")
            .join(interface)
            .join("rp_filter"),
        &format!("net.ipv4.conf.{interface}.rp_filter"),
        value,
    )
}

fn set_sysctl_if_changed(path: &Path, key: &str, value: &str) -> Result<()> {
    if fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?
        .trim()
        == value
    {
        return Ok(());
    }
    require_success(
        &format!("set {key}"),
        Command::new("sysctl").args(["-w", &format!("{key}={value}")]),
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn mesh_overlay_interfaces() -> Result<Vec<String>> {
    let mut interfaces = fs::read_dir("/proc/sys/net/ipv4/conf")
        .context("failed to list IPv4 interfaces")?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name();
            let name = name.to_str()?;
            name.starts_with(BABEL_OVERLAY_PREFIX)
                .then(|| name.to_string())
        })
        .collect::<Vec<_>>();
    interfaces.sort();
    Ok(interfaces)
}

#[cfg(target_os = "linux")]
fn ensure_babel_overlay(
    name: &str,
    vni: u32,
    wireguard_interface: &str,
    local_wireguard_ipv4: &str,
    remote_wireguard_ipv4: &str,
    transit: &OverlayTransitAddrs,
    overlay_mtu: u16,
) -> Result<bool> {
    let mut details = existing_babel_overlay_details(name)?;
    let mut changed = false;
    if let Some(existing) = details.as_deref()
        && !babel_overlay_matches(
            existing,
            vni,
            wireguard_interface,
            local_wireguard_ipv4,
            remote_wireguard_ipv4,
        )
    {
        require_success(
            "remove outdated Babel overlay",
            Command::new("ip").args(["link", "del", "dev", name]),
        )?;
        details = None;
        changed = true;
    }
    if details.is_none() {
        create_babel_overlay(
            name,
            vni,
            wireguard_interface,
            local_wireguard_ipv4,
            remote_wireguard_ipv4,
        )?;
        changed = true;
    }

    changed |= configure_babel_overlay_addresses(name, transit)?;
    if details
        .as_deref()
        .is_none_or(|details| !details.contains(&format!(" mtu {overlay_mtu} ")))
    {
        require_success(
            "set Babel overlay MTU",
            Command::new("ip").args(["link", "set", "dev", name, "mtu", &overlay_mtu.to_string()]),
        )?;
        changed = true;
    }
    if details
        .as_deref()
        .is_none_or(|details| !link_is_up(details))
    {
        require_success(
            "bring up Babel overlay",
            Command::new("ip").args(["link", "set", "dev", name, "up"]),
        )?;
        changed = true;
    }
    Ok(changed)
}

#[cfg(target_os = "linux")]
fn link_is_up(details: &str) -> bool {
    details
        .split_once('<')
        .and_then(|(_, flags)| flags.split_once('>'))
        .is_some_and(|(flags, _)| flags.split(',').any(|flag| flag == "UP"))
}

#[cfg(target_os = "linux")]
fn existing_babel_overlay_details(name: &str) -> Result<Option<String>> {
    let output = run_capture(Command::new("ip").args(["-d", "link", "show", "dev", name]))
        .with_context(|| format!("failed to inspect Babel overlay {name}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(output.stdout.replace(['\\', '\n'], " ")))
}

#[cfg(target_os = "linux")]
fn babel_overlay_matches(
    details: &str,
    vni: u32,
    wireguard_interface: &str,
    local_wireguard_ipv4: &str,
    remote_wireguard_ipv4: &str,
) -> bool {
    details.contains("vxlan")
        && details.contains(&format!("vxlan id {vni} "))
        && details.contains(&format!(" remote {remote_wireguard_ipv4} "))
        && details.contains(&format!(" local {local_wireguard_ipv4} "))
        && details.contains(&format!(" dev {wireguard_interface} "))
        && details.contains(&format!(" dstport {BABEL_VXLAN_PORT} "))
        && details.contains("nolearning")
}

#[cfg(target_os = "linux")]
fn create_babel_overlay(
    name: &str,
    vni: u32,
    wireguard_interface: &str,
    local_wireguard_ipv4: &str,
    remote_wireguard_ipv4: &str,
) -> Result<()> {
    let args = [
        "link",
        "add",
        name,
        "type",
        "vxlan",
        "id",
        &vni.to_string(),
        "local",
        local_wireguard_ipv4,
        "remote",
        remote_wireguard_ipv4,
        "dev",
        wireguard_interface,
        "dstport",
        BABEL_VXLAN_PORT,
        "nolearning",
    ];
    require_success("create Babel overlay", Command::new("ip").args(args))?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct OverlayTransitAddrs {
    pub(crate) local_ipv4: Ipv4Addr,
    pub(crate) local_ipv6: Ipv6Addr,
}

#[cfg(target_os = "linux")]
fn configure_babel_overlay_addresses(name: &str, transit: &OverlayTransitAddrs) -> Result<bool> {
    let existing = existing_babel_overlay_addresses(name)?;
    if overlay_addresses_match(&existing, transit) {
        return Ok(false);
    }

    require_success(
        "flush Babel overlay IPv4 addresses",
        Command::new("ip").args(["-4", "address", "flush", "dev", name, "scope", "global"]),
    )?;
    require_success(
        "flush Babel overlay IPv6 addresses",
        Command::new("ip").args(["-6", "address", "flush", "dev", name, "scope", "global"]),
    )?;
    require_success(
        "configure Babel overlay IPv4 address",
        Command::new("ip").args([
            "-4",
            "address",
            "replace",
            &format!("{}/30", transit.local_ipv4),
            "dev",
            name,
        ]),
    )?;
    require_success(
        "configure Babel overlay IPv6 address",
        Command::new("ip").args([
            "-6",
            "address",
            "replace",
            &format!("{}/127", transit.local_ipv6),
            "dev",
            name,
        ]),
    )?;
    Ok(true)
}

#[cfg(target_os = "linux")]
fn existing_babel_overlay_addresses(name: &str) -> Result<String> {
    let output = run_capture(Command::new("ip").args(["-o", "address", "show", "dev", name]))
        .with_context(|| format!("failed to inspect Babel overlay addresses for {name}"))?;
    if !output.status.success() {
        return Ok(String::new());
    }
    Ok(output.stdout)
}

#[cfg(target_os = "linux")]
fn overlay_addresses_match(details: &str, transit: &OverlayTransitAddrs) -> bool {
    details.contains(&format!(" {}/30 ", transit.local_ipv4))
        && details.contains(&format!(" {}/127 ", transit.local_ipv6))
}

pub(crate) fn peer_overlay_name(host_id: &HostId) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in host_id.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{BABEL_OVERLAY_PREFIX}{:010x}", hash & 0xffffffffff)
}

fn peer_overlay_pair_hash(left_host_id: &HostId, right_host_id: &HostId) -> u64 {
    let (left, right) = if left_host_id <= right_host_id {
        (left_host_id.as_bytes(), right_host_id.as_bytes())
    } else {
        (right_host_id.as_bytes(), left_host_id.as_bytes())
    };
    let mut hash = 0xcbf29ce484222325u64;
    for byte in left
        .iter()
        .chain([&0xff].iter().copied())
        .chain(right.iter())
    {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

pub(crate) fn peer_overlay_transit_addrs(
    local_host_id: &HostId,
    peer_host_id: &HostId,
) -> OverlayTransitAddrs {
    let link_id = (peer_overlay_pair_hash(local_host_id, peer_host_id) as u32) & 0x000f_ffff;
    let base_ipv4 = u32::from(BABEL_TRANSIT_IPV4_BASE) + (link_id << 2);
    let base_ipv6 = u128::from(BABEL_TRANSIT_IPV6_BASE) + u128::from(link_id << 1);
    let local_offset = if local_host_id <= peer_host_id { 1 } else { 2 };
    OverlayTransitAddrs {
        local_ipv4: Ipv4Addr::from(base_ipv4 + local_offset),
        local_ipv6: Ipv6Addr::from(base_ipv6 + u128::from(local_offset)),
    }
}

pub(crate) fn peer_overlay_vni(local_host_id: &HostId, peer_host_id: &HostId) -> u32 {
    1 + (((peer_overlay_pair_hash(local_host_id, peer_host_id) as u32) & 0x00ff_ffff) % 0x00ff_ffff)
}

#[cfg(target_os = "linux")]
fn apply_bird_config(
    config: &AgentBirdConfig,
    mesh: &AegisMeshConfig,
    local: &InventoryHost,
    mode: AgentMode,
    babel_overlay_changes: &[String],
) -> Result<()> {
    let desired = bird_config_contents(mesh, mode, local)?;
    let applied = AppliedConfig::new(BIRD_APPLIED_CONFIG_NAME, desired.as_bytes());
    let changed = write_text_file_if_changed(&config.config_path, &desired, Some(0o644))?;
    ensure_service_enabled(&config.service, "BIRD")?;
    let active =
        run_capture(Command::new("systemctl").args(["is-active", "--quiet", &config.service]))?
            .status
            .success();
    if !babel_overlay_changes.is_empty() {
        applied.mark_pending()?;
    }
    let activation_required = config_activation_required(&applied, changed)?;
    if !active {
        if !activation_required {
            applied.mark_pending()?;
        }
        require_success(
            "start BIRD service",
            Command::new("systemctl").args(["start", &config.service]),
        )?;
        applied.mark()?;
    } else if activation_required {
        require_success(
            "configure BIRD without interrupting active routes",
            Command::new("birdc").arg("configure"),
        )?;
        if !babel_overlay_changes.is_empty() {
            eprintln!(
                "aegis-agent: restarting {BABEL_PROTOCOL_NAME} after managed overlay changes: {}",
                babel_overlay_changes.join(", ")
            );
            require_success(
                "restart BIRD Babel protocol after data-plane change",
                Command::new("birdc").args(["restart", BABEL_PROTOCOL_NAME]),
            )?;
        }
        applied.mark()?;
    }
    Ok(())
}

pub(crate) fn bird_config_contents(
    mesh: &AegisMeshConfig,
    mode: AgentMode,
    local: &InventoryHost,
) -> Result<String> {
    let router_id = local.wireguard_ipv4().ok_or_else(|| {
        anyhow!(
            "local host `{}` is missing a WireGuard IPv4 address",
            local.alias()
        )
    })?;
    let preferred_source_ipv4 = local.internal_ipv4().unwrap_or(router_id);
    let preferred_source_ipv6 = local
        .internal_ipv6()
        .or_else(|| local.wireguard_ipv6())
        .ok_or_else(|| {
            anyhow!(
                "local host `{}` is missing a WireGuard IPv6 address",
                local.alias()
            )
        })?;
    let babel_protocol_name = BABEL_PROTOCOL_NAME;
    Ok(format!(
        "router id {router_id};\n\
         timeformat route iso long ms;\n\n\
         protocol device {{\n  scan time 1;\n}}\n\n\
         protocol static self_v4 {{\n  ipv4;\n{}}}\n\n\
         protocol static self_v6 {{\n  ipv6;\n{}}}\n\n\
         protocol kernel kernel_v4 {{\n  ipv4 {{\n    import none;\n    export filter {{\n      if proto = \"self_v4\" then reject;\n      krt_prefsrc = {preferred_source_ipv4};\n      accept;\n    }};\n  }};\n  persist;\n}}\n\n\
         protocol kernel kernel_v6 {{\n  ipv6 {{\n    import none;\n    export filter {{\n      if proto = \"self_v6\" then reject;\n      krt_prefsrc = {preferred_source_ipv6};\n      accept;\n    }};\n  }};\n  persist;\n}}\n\n\
         protocol babel {babel_protocol_name} {{\n  randomize router id yes;\n{}{}\n{}\n}}\n",
        bird_static_routes(local, false),
        bird_static_routes(local, true),
        bird_babel_channel_block("ipv4", &mesh.subnet_ipv4, "self_v4", mode),
        bird_babel_channel_block("ipv6", &mesh.subnet_ipv6, "self_v6", mode),
        bird_babel_interface_block(),
    ))
}

fn bird_babel_channel_block(
    family: &str,
    mesh_subnet: &str,
    self_protocol: &str,
    mode: AgentMode,
) -> String {
    let learned_export = if mode.is_hub() {
        format!("      if proto = \"{BABEL_PROTOCOL_NAME}\" then accept;\n")
    } else {
        String::new()
    };
    format!(
        concat!(
            "  {family} {{\n",
            "    import filter {{\n",
            "      if net ~ [ {mesh_subnet}+ ] then accept;\n",
            "      reject;\n",
            "    }};\n",
            "    export filter {{\n",
            "      if net !~ [ {mesh_subnet}+ ] then reject;\n",
            "      if proto = \"{self_protocol}\" then accept;\n",
            "{learned_export}",
            "      reject;\n",
            "    }};\n",
            "  }};\n",
        ),
        family = family,
        mesh_subnet = mesh_subnet,
        self_protocol = self_protocol,
        learned_export = learned_export,
    )
}

fn bird_babel_interface_block() -> String {
    format!(
        "  interface \"{BABEL_OVERLAY_PREFIX}*\" {{\n\
             type wireless;\n\
             hello interval 1 s;\n\
             update interval 4 s;\n\
             check link yes;\n\
             rxcost 256;\n\
             rtt cost 256;\n\
             rtt min 10 ms;\n\
             rtt max 350 ms;\n\
             rtt decay 42;\n\
             send timestamps yes;\n\
           }};"
    )
}

fn bird_static_routes(local: &InventoryHost, ipv6: bool) -> String {
    let mut routes = BTreeSet::new();
    let internal_ip = if ipv6 {
        local.internal_ipv6()
    } else {
        local.internal_ipv4()
    };
    if let Some(internal_ip) = internal_ip {
        routes.insert(format!(
            "  route {internal_ip}/{} via \"lo\";\n",
            if ipv6 { 128 } else { 32 }
        ));
    }
    routes.into_iter().collect()
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        bail!("{} has no parent directory", path.display());
    };
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))
}

fn ensure_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("failed to create {}", path.display()))
}

fn ensure_directory_mode(path: &Path, mode: u32) -> Result<()> {
    ensure_directory(path)?;
    #[cfg(unix)]
    {
        let current_mode = fs::metadata(path)
            .with_context(|| format!("failed to inspect {}", path.display()))?
            .permissions()
            .mode()
            & 0o7777;
        if current_mode != mode {
            fs::set_permissions(path, fs::Permissions::from_mode(mode))
                .with_context(|| format!("failed to chmod {}", path.display()))?;
        }
    }
    Ok(())
}

fn write_text_file(path: &Path, content: &str, mode: Option<u32>) -> Result<()> {
    let _ = write_text_file_if_changed(path, content, mode)?;
    Ok(())
}

fn read_optional_trimmed_text(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(content) => {
            let content = content.trim();
            Ok((!content.is_empty()).then(|| content.to_string()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    let _ = remove_file_if_exists_changed(path)?;
    Ok(())
}

fn remove_file_if_exists_changed(path: &Path) -> Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

fn install_sshd_dropin(path: &Path, content: &str) -> Result<()> {
    replace_sshd_dropin(path, Some(content))
}

fn remove_sshd_dropin(path: &Path) -> Result<()> {
    replace_sshd_dropin(path, None)
}

fn replace_sshd_dropin(path: &Path, desired: Option<&str>) -> Result<()> {
    let previous = match fs::read_to_string(path) {
        Ok(content) => Some(content),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    if previous.as_deref() == desired {
        return Ok(());
    }

    match desired {
        Some(content) => {
            write_text_file(path, content, Some(0o644))?;
        }
        None => remove_file_if_exists(path)?,
    }

    if let Err(change_error) = validate_sshd().and_then(|()| reload_sshd()) {
        let restore_result = match previous {
            Some(previous) => write_text_file(path, &previous, Some(0o644)),
            None => remove_file_if_exists(path),
        }
        .and_then(|()| validate_sshd())
        .and_then(|()| reload_sshd());
        return match restore_result {
            Ok(()) => Err(change_error).with_context(|| {
                format!(
                    "failed to activate SSH policy {}; restored the previous configuration",
                    path.display()
                )
            }),
            Err(restore_error) => Err(anyhow!(
                "failed to activate SSH policy {}: {change_error:#}; restoring the previous configuration also failed: {restore_error:#}",
                path.display()
            )),
        };
    }
    Ok(())
}

fn write_text_file_if_changed(path: &Path, content: &str, mode: Option<u32>) -> Result<bool> {
    ensure_parent_dir(path)?;
    match fs::read(path) {
        Ok(existing) if existing == content.as_bytes() => {
            #[cfg(unix)]
            if let Some(mode) = mode {
                let current_mode = fs::metadata(path)
                    .with_context(|| format!("failed to inspect {}", path.display()))?
                    .permissions()
                    .mode()
                    & 0o7777;
                if current_mode != mode {
                    fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
                        .with_context(|| format!("failed to chmod {}", path.display()))?;
                }
            }
            return Ok(false);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()));
        }
    }
    capulus::store::atomic_write(path, content.as_bytes(), mode, None)
        .with_context(|| format!("failed to update {}", path.display()))?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)
            .with_context(|| format!("failed to open {} for synchronization", parent.display()))?
            .sync_all()
            .with_context(|| format!("failed to synchronize {}", parent.display()))?;
    }
    Ok(true)
}

impl AppliedConfig {
    fn new(name: &str, desired: &[u8]) -> Self {
        Self::at_path(
            Path::new(APPLIED_CONFIG_DIRECTORY).join(format!("{name}.sha256")),
            desired,
        )
    }

    fn at_path(path: PathBuf, desired: &[u8]) -> Self {
        let digest = Sha256::digest(desired);
        Self {
            path,
            digest: digest.iter().map(|byte| format!("{byte:02x}")).collect(),
        }
    }

    fn status(&self) -> Result<AppliedConfigStatus> {
        match fs::read_to_string(&self.path) {
            Ok(current) if current.trim() == self.digest => Ok(AppliedConfigStatus::Current),
            Ok(_) => Ok(AppliedConfigStatus::Stale),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(AppliedConfigStatus::Uninitialized)
            }
            Err(error) => {
                Err(error).with_context(|| format!("failed to read {}", self.path.display()))
            }
        }
    }

    fn mark(&self) -> Result<()> {
        self.write_status(&self.digest)
    }

    fn mark_pending(&self) -> Result<()> {
        self.write_status("pending")
    }

    fn write_status(&self, status: &str) -> Result<()> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| anyhow!("{} has no parent directory", self.path.display()))?;
        ensure_directory_mode(parent, 0o755)?;
        write_text_file(&self.path, &line_with_newline(status), Some(0o644))
    }
}

fn config_activation_required(applied: &AppliedConfig, content_changed: bool) -> Result<bool> {
    if content_changed {
        applied.mark_pending()?;
        return Ok(true);
    }
    match applied.status()? {
        AppliedConfigStatus::Current => Ok(false),
        AppliedConfigStatus::Uninitialized => {
            applied.mark()?;
            Ok(false)
        }
        AppliedConfigStatus::Stale => Ok(true),
    }
}

fn line_with_newline(value: &str) -> String {
    let mut value = value.trim().to_string();
    value.push('\n');
    value
}

fn load_private_key(path: &Path) -> Result<String> {
    let value =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(crate::wireguard_keys::Keypair::from_private_key(&value)?.private_key)
}

fn ensure_wireguard_keypair(config: &WireGuardConfig) -> Result<()> {
    crate::wireguard_keys::Keypair::ensure(&config.private_key_path, &config.public_key_path)
        .map(|_| ())
}

fn ensure_local_wireguard_public_key(config: &WireGuardConfig, expected: &str) -> Result<()> {
    ensure_wireguard_keypair(config)?;
    verify_local_wireguard_public_key(config, expected)
}

fn verify_local_wireguard_public_key(config: &WireGuardConfig, expected: &str) -> Result<()> {
    let stored_public = fs::read_to_string(&config.public_key_path)
        .with_context(|| format!("failed to read {}", config.public_key_path.display()))?;
    let private_key = load_private_key(&config.private_key_path)?;
    let derived_public = crate::wireguard_keys::Keypair::from_private_key(&private_key)?.public_key;
    let stored_public = aegis_dto::normalize_wireguard_key(&stored_public).with_context(|| {
        format!(
            "stored WireGuard public key at {} is invalid",
            config.public_key_path.display()
        )
    })?;
    if stored_public != derived_public {
        bail!(
            "local WireGuard public key at {} does not match private key at {}",
            config.public_key_path.display(),
            config.private_key_path.display()
        );
    }
    let expected = aegis_dto::normalize_wireguard_key(expected)
        .context("published WireGuard public key is invalid")?;
    if derived_public != expected {
        bail!(
            "local WireGuard public key at {} does not match published key for interface `{}`",
            config.public_key_path.display(),
            config.interface
        );
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
#[path = "agent/wireguard_kernel_tests.rs"]
mod wireguard_kernel_tests;

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[test]
    fn tls_provisioning_rejects_unprivileged_and_missing_peer_identity() {
        use axum::response::IntoResponse;
        for uid in [None, Some(1000), Some(65534)] {
            let error = super::AgentPeerCredentials { uid }
                .require_root()
                .unwrap_err();
            assert_eq!(
                super::AgentHttpError(error).into_response().status(),
                axum::http::StatusCode::FORBIDDEN
            );
        }
        super::AgentPeerCredentials { uid: Some(0) }
            .require_root()
            .unwrap();
    }
    fn wireguard_runtime_configs_match(desired: &str, live: &str) -> anyhow::Result<bool> {
        super::parse_wireguard_runtime_config(desired)?
            .matches(&super::parse_wireguard_runtime_config(live)?)
    }

    #[test]
    fn direct_target_cache_serves_menu_without_a_network_request() {
        let cache = super::DirectTargetCache::default();
        let targets = aegis_dto::protocol::AegisDirectTargetListResponse {
            targets: Vec::new(),
        };
        assert_eq!(
            cache.get_or_fetch("phone", || Ok(targets.clone())).unwrap(),
            targets
        );
        assert_eq!(
            cache
                .get_or_fetch("phone", || panic!("a warm menu must not wait for the API"))
                .unwrap(),
            targets
        );
        assert!(
            cache
                .get_or_fetch("another-phone", || anyhow::bail!("not authorized"))
                .is_err()
        );
        assert_eq!(
            cache
                .get_or_fetch("another-phone", || Ok(targets.clone()))
                .unwrap(),
            targets
        );
    }

    use super::{
        AgentBabelStatus, AgentTunnelStatus, AppliedConfig, AppliedConfigStatus,
        BABEL_OVERLAY_PREFIX, BabelRouteSnapshot, DirectGatewayState, EgressNftablesState,
        EgressWireGuardPeerPlan, HostCertificatePrincipals, InventoryHost, LocalEgressMode,
        OverlayTransitAddrs, RuntimeState, WireGuardConfigOptions, WireGuardListenPort,
        WireGuardRuntime, WireGuardRuntimeConfig, agent_http_error_message, agent_tunnel_status,
        apply_authorized_principals, babel_overlay_matches, babel_status_from_snapshot,
        bird_config_contents, bird3_repository_file_message, bird3_source_block_is_managed,
        bird3_source_blocks, config_activation_required, direct_gateway_firewall_command,
        direct_gateway_sshd_dropin_contents, direct_gateway_wireguard_config_contents,
        egress_gateway_rules_present, egress_nftables_contents, egress_policy_script_contents,
        egress_policy_systemd_unit_contents, egress_route_entries_match,
        egress_wireguard_config_contents, egress_wireguard_handoff_contents,
        network_member_needs_update, normalize_managed_wireguard_route, overlay_addresses_match,
        parse_babel_route_snapshot, parse_live_wireguard_handshakes, peer_overlay_name,
        peer_overlay_transit_addrs, peer_overlay_vni, relevant_underlay_change,
        required_babel_backbone_routes, resolvectl_link_values, reusable_host_certificate,
        route_table_routes, select_peers, strip_wg_quick_fields, usable_link_name,
        valid_direct_account, wireguard_config_contents, wireguard_endpoint_peer,
        wireguard_peer_keys, wireguard_quick_applied_config, wireguard_quick_config_changed,
        write_text_file_if_changed,
    };
    use crate::cli::AgentMode;
    use crate::config::{AgentConfig, AgentConfigOptions, AgentHostConfig};
    use aegis_dto::{
        AegisHostMode, HostAlias, HostAliases, HostId,
        protocol::{
            AegisDirectGateway, AegisDirectGatewayConfig, AegisDirectGatewayReport,
            AegisDirectPeerObservation, AegisDirectSatellite, AegisDirectWireGuard,
            AegisEgressConfig, AegisEgressHost, AegisEgressInventory, AegisEgressPolicy,
            AegisMeshConfig, AegisNetworkHost, AegisNetworkHostSsh, AegisNetworkMember,
            AegisNetworkMemberInternalAddresses, AegisNetworkMemberWireGuard,
            AegisNetworkWireGuardConfig, AegisPutNetworkMemberRequest,
            AegisPutNetworkMemberWireGuard,
        },
    };
    #[cfg(target_os = "linux")]
    use rtnetlink::{
        packet_core::NetlinkPayload,
        packet_route::{
            AddressFamily, RouteNetlinkMessage,
            link::{LinkAttribute, LinkMessage, State as LinkState},
            route::{RouteAddress, RouteAttribute, RouteMessage},
        },
    };
    use ssh_key::{Algorithm, PrivateKey, certificate::Builder, rand_core::OsRng};
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        io::Write,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        os::unix::fs::PermissionsExt,
        process::{Command, Stdio},
        time::Instant,
    };

    fn host_id(alias: &str) -> HostId {
        let value = alias.bytes().fold(1_u128, |value, byte| {
            value.wrapping_mul(257).wrapping_add(u128::from(byte))
        });
        format!("{value:032x}").parse().expect("test host UUID")
    }

    pub(super) fn raw_agent_config() -> AgentConfigOptions {
        toml::from_str(
            r#"
api_base = "https://api.example.test/v2/namespaces/test"
cache_path = "/var/lib/aegis/cache.json"

[auth]
refresh_token = "refresh-token"

[host]
host_id = "00000000-0000-4000-8000-000000000001"
ssh_user = "ubuntu"
port = 22
host_private_key_path = "/etc/ssh/aegis-host"
host_public_key_path = "/etc/ssh/aegis-host.pub"
host_certificate_path = "/etc/ssh/aegis-host-cert.pub"
client_ca_path = "/etc/ssh/aegis-client-ca.pub"
authorized_principals_dir = "/etc/ssh/auth_principals"
sshd_dropin_path = "/etc/ssh/sshd_config.d/aegis.conf"

[routing]
backend = "bird"
config_path = "/etc/bird/bird.conf"
service = "bird"
"#,
        )
        .expect("test agent config")
    }

    #[test]
    fn raw_agent_config_is_validated_before_becoming_runtime_config() {
        assert!(AgentConfig::try_from(raw_agent_config()).is_ok());

        let mut raw = raw_agent_config();
        raw.api_base = "https://api.example.test/v2".to_string();
        let error = AgentConfig::try_from(raw).expect_err("unscoped agent must fail");
        assert!(format!("{error:#}").contains("select an Aegis namespace"));

        let mut raw = raw_agent_config();
        raw.auth.refresh_token = " refresh-token".to_string();
        let error = AgentConfig::try_from(raw).expect_err("uncanonical token must fail");
        assert!(error.to_string().contains("refresh_token"));
    }

    #[test]
    fn raw_agent_config_rejects_unknown_fields() {
        let raw = r#"
api_base = "https://api.example.test/v2/namespaces/test"
unexpected = true

[auth]
refresh_token = "refresh-token"

[host]
host_id = "00000000-0000-4000-8000-000000000001"
ssh_user = "ubuntu"
host_private_key_path = "/etc/ssh/aegis-host"
host_public_key_path = "/etc/ssh/aegis-host.pub"
host_certificate_path = "/etc/ssh/aegis-host-cert.pub"
client_ca_path = "/etc/ssh/aegis-client-ca.pub"
authorized_principals_dir = "/etc/ssh/auth_principals"
sshd_dropin_path = "/etc/ssh/sshd_config.d/aegis.conf"

[routing]
backend = "bird"
config_path = "/etc/bird/bird.conf"
"#;
        assert!(toml::from_str::<AgentConfigOptions>(raw).is_err());
    }

    #[test]
    fn raw_agent_config_rejects_the_removed_listen_field() {
        let raw = format!(
            "listen = '/run/aegis/agent.sock'\n{}",
            toml::to_string(&raw_agent_config()).expect("test config should encode")
        );
        assert!(toml::from_str::<AgentConfigOptions>(&raw).is_err());
    }

    fn aliases(alias: &str) -> HostAliases {
        HostAliases::new(vec![HostAlias::parse(alias).expect("test host alias")])
            .expect("test host aliases")
    }

    #[test]
    fn live_wireguard_handshakes_accept_all_and_single_interface_shapes() {
        let peers = parse_live_wireguard_handshakes(
            "wg-aegis\tAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t0\n\
             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t12\n\
             wg-aegis-egress\tBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=\t9\n",
        )
        .expect("live handshakes should parse");

        assert_eq!(2, peers.len());
        assert_eq!(Some(12), peers[0].latest_handshake_unix);
        assert_eq!(Some(9), peers[1].latest_handshake_unix);
    }

    fn assert_bash_syntax(script: &str) {
        let mut child = Command::new("bash")
            .arg("-n")
            .stdin(Stdio::piped())
            .spawn()
            .expect("bash -n should start");
        child
            .stdin
            .as_mut()
            .expect("bash stdin should be piped")
            .write_all(script.as_bytes())
            .expect("script should be written to bash");
        let status = child.wait().expect("bash -n should exit");
        assert!(status.success(), "rendered bash script has invalid syntax");
    }

    #[test]
    fn agent_http_error_message_includes_cause_chain() {
        let error = anyhow::anyhow!("Server returned error response: invalid_grant")
            .context("failed to refresh oauth access token");

        assert_eq!(
            "aegis-agent request failed: failed to refresh oauth access token: Server returned error response: invalid_grant",
            agent_http_error_message(&error)
        );
    }

    #[test]
    fn direct_account_names_use_the_full_linux_username_budget() {
        assert!(valid_direct_account("aegis-d-0123456789abcdef01234567"));
        assert!(!valid_direct_account("aegis-d-0123456789abcdef"));
        assert!(!valid_direct_account("aegis-d-0123456789ABCDEF01234567"));
        assert!(!valid_direct_account("aegis-d-0123456789abcdef012345678"));
    }

    #[test]
    fn ordinary_principal_reconciliation_preserves_direct_accounts() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let principals = temporary.path().join("principals");
        fs::create_dir(&principals).expect("principals directory");
        let direct = "aegis-d-0123456789abcdef01234567";
        fs::write(principals.join(direct), "aegis-direct-principal\n").expect("direct principal");
        fs::write(principals.join("stale"), "stale-principal\n").expect("stale principal");
        let config = AgentHostConfig {
            host_id: host_id("hub-a"),
            ssh_user: "ubuntu".to_string(),
            port: Some(22),
            host_private_key_path: temporary.path().join("host-key"),
            host_public_key_path: temporary.path().join("host-key.pub"),
            host_certificate_path: temporary.path().join("host-key-cert.pub"),
            client_ca_path: temporary.path().join("client-ca.pub"),
            authorized_principals_dir: principals.clone(),
            sshd_dropin_path: temporary.path().join("sshd.conf"),
        };
        let desired = BTreeMap::from([("alice".to_string(), vec!["alice-cert".to_string()])]);

        assert!(apply_authorized_principals(&config, &desired).expect("reconcile principals"));
        assert_eq!(
            "aegis-direct-principal\n",
            fs::read_to_string(principals.join(direct)).expect("preserved direct principal")
        );
        assert!(!principals.join("stale").exists());
        assert_eq!(
            "alice-cert\n",
            fs::read_to_string(principals.join("alice")).expect("ordinary principal")
        );
    }

    fn inventory_host(alias: &str, mode: AegisHostMode, pending: bool) -> InventoryHost {
        InventoryHost {
            host_id: host_id(alias),
            aliases: aliases(alias),
            host: AegisNetworkHost {
                platform: aegis_dto::platform::HostPlatform {
                    operating_system: aegis_dto::platform::OperatingSystem::Ubuntu,
                    architecture: aegis_dto::platform::Architecture::X86_64,
                },
                mode,
                ssh: Some(AegisNetworkHostSsh {
                    port: Some(22),
                    public_key: None,
                    internal_principals: vec![format!("{alias}.internal")],
                    external_principals: Vec::new(),
                }),
                wireguard: Some(AegisNetworkMemberWireGuard {
                    public_key: format!("{alias}-wg-key"),
                    ipv4: "10.75.0.1".to_string(),
                    ipv6: "fd75::1".to_string(),
                    endpoints: vec!["34.1.2.3".to_string()],
                }),
                egress: None,
                internal: None,
                messages: Vec::new(),
                agent: None,
                ssh_lockdown_enabled: false,
                observed_public_ips: aegis_dto::protocol::AegisObservedPublicIps::default(),
                transient: false,
                pending,
                updated_unix: 0,
            },
        }
    }

    fn test_mesh() -> AegisMeshConfig {
        AegisMeshConfig {
            endpoint_port: 51820,
            overlay_mtu: 1350,
            subnet_ipv4: "10.75.0.0/16".to_string(),
            subnet_ipv6: "fd75::/64".to_string(),
            wireguard_subnet_ipv4: "10.75.1.0/24".to_string(),
            wireguard_subnet_ipv6: "fd75::1:0/120".to_string(),
            host_dns_suffix: None,
        }
    }

    fn test_wireguard_config() -> AegisNetworkWireGuardConfig {
        let mesh = test_mesh();
        AegisNetworkWireGuardConfig {
            interface: "wg-aegis".to_string(),
            endpoint_port: mesh.endpoint_port,
            mtu: 1400,
            fwmark: 44_641,
            subnet_ipv4: mesh.wireguard_subnet_ipv4,
            subnet_ipv6: mesh.wireguard_subnet_ipv6,
        }
    }

    pub(super) fn test_egress_config() -> AegisEgressConfig {
        AegisEgressConfig {
            network: "aegis".to_string(),
            interface: "wg-aegis-egress".to_string(),
            endpoint_port: 51_823,
            mtu: 1290,
            fwmark: 44_641,
            routing_table: 51_823,
            main_rule_priority: 11_000,
            egress_rule_priority: 11_010,
            subnet_ipv4: "10.78.1.0/24".to_string(),
            subnet_ipv6: "fd78::1:0/120".to_string(),
            dns_subnet_ipv4: "10.78.0.0/24".to_string(),
            dns_subnet_ipv6: "fd78::/120".to_string(),
        }
    }

    pub(super) fn egress_host(alias: &str, id: u8) -> AegisEgressHost {
        AegisEgressHost {
            host_id: host_id(alias),
            aliases: aliases(alias),
            public_key: format!("{alias}-egress-key"),
            ipv4: format!("10.78.1.{id}"),
            ipv6: format!("fd78::1:{id:x}"),
            internal_ipv4: format!("10.75.0.{id}"),
            internal_ipv6: format!("fd75::{id:x}"),
            dns_ipv4: format!("10.78.0.{id}"),
            dns_ipv6: format!("fd78::{id:x}"),
        }
    }

    fn egress_policy(
        source_host_id: HostId,
        active_via: Option<HostId>,
        desired_via: Option<HostId>,
    ) -> AegisEgressPolicy {
        AegisEgressPolicy {
            source_host_id,
            revision: 7,
            active_via,
            desired_via,
            updated_unix: 1,
            updated_by_principal: "OperatorUserID".to_string(),
        }
    }

    #[test]
    fn agent_tunnel_status_uses_operator_facing_aliases() {
        let source = egress_host("source", 2);
        let target = egress_host("hub-a", 3);
        let inventory = AegisEgressInventory {
            config: test_egress_config(),
            hosts: BTreeMap::from([
                (source.host_id, source.clone()),
                (target.host_id, target.clone()),
            ]),
            policies: BTreeMap::new(),
        };

        assert_eq!(
            AgentTunnelStatus::Disabled,
            agent_tunnel_status(None, &inventory)
        );
        assert_eq!(
            AgentTunnelStatus::Enabled {
                via: "hub-a".to_string(),
            },
            agent_tunnel_status(
                Some(&egress_policy(
                    source.host_id,
                    Some(target.host_id),
                    Some(target.host_id),
                )),
                &inventory,
            )
        );
        assert_eq!(
            AgentTunnelStatus::Reconciling {
                active_via: None,
                desired_via: Some("hub-a".to_string()),
            },
            agent_tunnel_status(
                Some(&egress_policy(source.host_id, None, Some(target.host_id),)),
                &inventory,
            )
        );
    }

    #[test]
    fn managed_wireguard_routes_are_host_routes_inside_the_peer_pool() {
        let config = test_wireguard_config();

        assert_eq!(
            Some("10.75.1.42/32".to_string()),
            normalize_managed_wireguard_route(&config, "10.75.1.42")
        );
        assert_eq!(
            Some("fd75::1:2a/128".to_string()),
            normalize_managed_wireguard_route(&config, "fd75::1:2a/128")
        );
        assert_eq!(
            None,
            normalize_managed_wireguard_route(&config, "10.75.1.0/24")
        );
        assert_eq!(
            None,
            normalize_managed_wireguard_route(&config, "10.75.2.42/32")
        );
        assert_eq!(
            None,
            normalize_managed_wireguard_route(&config, "fd75::2:2a/128")
        );
    }

    #[test]
    fn direct_gateway_allows_only_hub_ssh_and_public_internet_forwarding() {
        let inventory = DirectGatewayState {
            config: AegisDirectGatewayConfig {
                interface: "wg-aegis-direct".to_string(),
                endpoint_port: 51_822,
                mtu: 1380,
                fwmark: 44_641,
                subnet_ipv4: "10.77.1.0/24".to_string(),
                subnet_ipv6: "fd77::1:0/120".to_string(),
                full_tunnel_dns: Vec::new(),
            },
            gateway: AegisDirectGateway {
                host_id: host_id("hub-a"),
                aliases: aliases("hub-a"),
                wireguard: AegisDirectWireGuard {
                    public_key: "hub-public-key".to_string(),
                    ipv4: "10.77.1.1".to_string(),
                    ipv6: "fd77::1:1".to_string(),
                    endpoints: vec!["203.0.113.8".to_string()],
                },
                updated_unix: 10,
            },
            direct_client_ca_public_key: "ssh-ed25519 direct-ca".to_string(),
            satellites: vec![AegisDirectSatellite {
                slug: "pocket-a".to_string(),
                account: "aegis-d-0123456789abcdef01234567".to_string(),
                ssh_principal: "aegis-direct-0123456789abcdef0123456789abcdef".to_string(),
                wireguard: AegisDirectWireGuard {
                    public_key: "peer-public-key".to_string(),
                    ipv4: "10.77.1.2".to_string(),
                    ipv6: "fd77::1:2".to_string(),
                    endpoints: Vec::new(),
                },
            }],
        };

        let config = direct_gateway_wireguard_config_contents(&inventory, "private-key")
            .expect("WireGuard config");
        assert!(config.contains("Address = 10.77.1.1/32,fd77::1:1/128"));
        assert!(config.contains("ListenPort = 51822"));
        assert!(config.contains("Table = off"));
        assert!(config.contains("PublicKey = peer-public-key"));
        assert!(config.contains("AllowedIPs = 10.77.1.2/32,fd77::1:2/128"));
        assert!(!config.contains("Endpoint ="));
        assert!(!config.contains("0.0.0.0/0"));
        assert!(!config.contains("::/0"));

        let firewall =
            direct_gateway_firewall_command("iptables", "PostUp", "10.77.1.1", "10.77.1.0/24");
        assert_bash_syntax(&firewall);
        assert!(firewall.contains("-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"));
        assert!(firewall.contains("-d 10.77.1.1 -p tcp --dport 22 -j ACCEPT"));
        assert!(
            firewall
                .find("--ctstate ESTABLISHED,RELATED")
                .expect("reply rule")
                < firewall.find("--dport 22").expect("SSH rule")
        );
        assert!(firewall.contains("-A AEGIS_DIRECT_IN -j DROP"));
        assert!(firewall.contains("-A AEGIS_DIRECT_FWD -j DROP"));
        assert!(firewall.contains("-i %i -o %i -j DROP"));
        assert!(firewall.contains("-s 10.77.1.0/24 -d 10.0.0.0/8 -j DROP"));
        assert!(firewall.contains("-s 10.77.1.0/24 -d 192.168.0.0/16 -j DROP"));
        assert!(firewall.contains("-i %i -s 10.77.1.0/24 -j ACCEPT"));
        assert!(firewall.contains("-t nat -A AEGIS_DIRECT_NAT -s 10.77.1.0/24 -j MASQUERADE"));
        assert!(
            firewall
                .find("-d 10.0.0.0/8 -j DROP")
                .expect("private drop")
                < firewall
                    .find("-i %i -s 10.77.1.0/24 -j ACCEPT")
                    .expect("public accept")
        );

        let ipv6_firewall =
            direct_gateway_firewall_command("ip6tables", "PostUp", "fd77::1:1", "fd77::1:0/120");
        assert_bash_syntax(&ipv6_firewall);
        assert!(ipv6_firewall.contains("-s fd77::1:0/120 -d fc00::/7 -j DROP"));
        assert!(ipv6_firewall.contains("-s fd77::1:0/120 -d fe80::/10 -j DROP"));
        assert!(ipv6_firewall.contains("-s fd77::1:0/120 -j MASQUERADE"));

        let sshd = direct_gateway_sshd_dropin_contents(&inventory);
        assert!(sshd.contains("Match LocalAddress 10.77.1.1,fd77::1:1"));
        assert!(sshd.contains("AuthenticationMethods publickey"));
        assert!(sshd.contains("AuthorizedKeysFile none"));
        assert!(sshd.contains("Group aegis-direct"));
        assert!(!sshd.contains("AuthorizedPrincipalsFile"));
        assert!(sshd.contains("ForceCommand /usr/local/bin/aegis agent direct-ssh"));
        assert!(sshd.contains("DisableForwarding yes"));
        assert!(sshd.contains("PasswordAuthentication no"));
        assert!(sshd.ends_with("Match all\n"));
    }

    #[test]
    fn egress_wireguard_terminates_each_hop_at_the_selected_mesh_host() {
        let config = test_egress_config();
        let local = egress_host("source", 2);
        let target = egress_host("target", 3);
        let child = egress_host("child", 4);

        let rendered = egress_wireguard_config_contents(
            &config,
            &local,
            &EgressWireGuardPeerPlan {
                default_target: Some(&target),
                gateway_sources: &[&child],
            },
            "private-key",
        )
        .expect("WireGuard config");

        assert!(rendered.contains("Address = 10.78.1.2/32,fd78::1:2/128,10.78.0.2/32,fd78::2/128"));
        assert!(rendered.contains("MTU = 1290"));
        assert!(rendered.contains("FwMark = 44641"));
        assert!(rendered.contains("Endpoint = 10.75.0.3:51823"));
        assert!(rendered.contains("AllowedIPs = 0.0.0.0/0,::/0"));
        assert!(rendered.contains("PublicKey = child-egress-key"));
        assert!(
            rendered.contains("AllowedIPs = 10.78.1.4/32,fd78::1:4/128,10.78.0.4/32,fd78::4/128")
        );
        assert!(!rendered.contains("10.75.0.4/32"));
    }

    #[test]
    fn egress_wireguard_configuration_contains_only_the_committed_default() {
        let config = test_egress_config();
        let local = egress_host("source", 2);
        let active = egress_host("active", 3);

        let rendered = egress_wireguard_config_contents(
            &config,
            &local,
            &EgressWireGuardPeerPlan {
                default_target: Some(&active),
                gateway_sources: &[],
            },
            "private-key",
        )
        .expect("WireGuard config");

        assert!(rendered.contains("PublicKey = active-egress-key"));
        assert!(rendered.contains("AllowedIPs = 0.0.0.0/0,::/0"));
        assert_eq!(1, rendered.matches("0.0.0.0/0").count());
    }

    #[test]
    fn egress_wireguard_handoff_moves_dns_before_the_default_route() {
        let config = test_egress_config();
        let local = egress_host("source", 2);
        let active = egress_host("active", 3);
        let desired = egress_host("desired", 4);

        let rendered = egress_wireguard_handoff_contents(
            &config,
            &local,
            &active,
            &desired,
            &[&active, &desired],
            "private-key",
        )
        .expect("WireGuard config");

        assert!(rendered.contains("PublicKey = active-egress-key"));
        assert_eq!(1, rendered.matches("AllowedIPs = 0.0.0.0/0,::/0").count());
        assert!(rendered.contains("PublicKey = desired-egress-key"));
        assert_eq!(
            1,
            rendered.matches("PublicKey = desired-egress-key").count()
        );
        assert!(
            rendered.contains("AllowedIPs = 10.78.1.4/32,fd78::1:4/128,10.78.0.4/32,fd78::4/128")
        );
    }

    #[test]
    fn egress_kill_switch_covers_local_and_chained_transit_traffic() {
        let config = test_egress_config();
        let local = egress_host("middle", 2);
        let source = egress_host("source", 3);
        let rendered = egress_nftables_contents(EgressNftablesState {
            config: &config,
            local: &local,
            mode: LocalEgressMode::Tunnel,
            gateway_chained: true,
            target_sources: &[&source],
        });

        assert!(rendered.contains("socket cgroupv2 level 1 \"aegis.slice\" meta mark set 44641"));
        assert!(rendered.contains("ip saddr 10.78.0.2 return"));
        assert!(rendered.contains("ip6 saddr fd78::2 return"));
        assert!(!rendered.contains("ip saddr 10.78.1.2 return"));
        assert!(rendered.contains("socket cgroupv2 level 1 \"aegis.slice\" ip daddr { 10.0.0.0/8"));
        assert!(
            rendered.contains("iifname \"wg-aegis-egress\" ct state established,related accept")
        );
        assert!(rendered.contains(
            "iifname \"wg-aegis-egress\" oifname \"wg-aegis-egress\" ip saddr 10.78.1.3 accept"
        ));
        assert!(!rendered.contains("iifname \"wg-aegis-egress\" ip saddr 10.78.1.3 accept"));
        assert!(rendered.contains("iifname \"wg-aegis-egress\" ip saddr 10.78.1.3 masquerade"));
        assert!(rendered.contains("iifname \"wg-aegis-egress\" ip saddr 10.78.0.3 masquerade"));
        assert!(rendered.contains("meta l4proto { tcp, udp } th dport 53 reject"));
        assert!(rendered.contains("reject with icmpx type admin-prohibited"));
        assert!(egress_gateway_rules_present(
            &rendered,
            &config.interface,
            true,
            &[&source],
        ));

        let staging = egress_nftables_contents(EgressNftablesState {
            config: &config,
            local: &local,
            mode: LocalEgressMode::Staging,
            gateway_chained: false,
            target_sources: &[&source],
        });
        assert_eq!(2, staging.matches("meta mark set 44641").count());
        assert!(!staging.contains("reject with icmpx type admin-prohibited"));
        let private_return = staging
            .find("ip daddr { 10.0.0.0/8")
            .expect("private destination bypass");
        let staging_mark = staging.rfind("meta mark set 44641").expect("staging mark");
        assert!(private_return < staging_mark);

        let final_hop = egress_nftables_contents(EgressNftablesState {
            config: &config,
            local: &local,
            mode: LocalEgressMode::Direct,
            gateway_chained: false,
            target_sources: &[&source],
        });
        assert_eq!(1, final_hop.matches("meta mark set 44641").count());
        assert!(final_hop.contains("iifname \"wg-aegis-egress\" ip saddr 10.78.1.3 accept"));
        assert!(!final_hop.contains("reject with icmpx type admin-prohibited"));
        assert!(egress_gateway_rules_present(
            &final_hop,
            &config.interface,
            false,
            &[&source],
        ));
    }

    #[test]
    fn egress_boot_only_loads_firewall_rules() {
        let script = egress_policy_script_contents(&test_egress_config());
        assert_bash_syntax(&script);
        let apply = script
            .split("  apply)")
            .nth(1)
            .unwrap()
            .split(";;")
            .next()
            .unwrap();
        assert!(apply.contains("/usr/sbin/nft --file"));
        assert!(!apply.contains("resolvectl"));
        assert!(!apply.contains("/usr/sbin/ip"));
        let unit = egress_policy_systemd_unit_contents();
        assert!(unit.contains("DefaultDependencies=no"));
        assert!(unit.contains("Requires=aegis.slice"));
        assert!(unit.contains("After=local-fs.target aegis.slice"));
        assert!(unit.contains("ExecStart=/usr/sbin/nft --file"));
        let wireguard = aegis_dto::managed_wireguard_systemd_unit_contents();
        assert!(!wireguard.contains("Before="));
    }

    #[test]
    fn resolvectl_link_state_is_parsed_without_confusing_ipv6_colons() {
        assert_eq!(
            Some(vec!["10.78.0.3", "fd78::3"]),
            resolvectl_link_values("Link 14 (wg-aegis-egress): 10.78.0.3 fd78::3\n")
        );
        assert_eq!(
            Some(Vec::<&str>::new()),
            resolvectl_link_values("Link 14 (wg-aegis-egress):\n")
        );
    }

    #[test]
    fn absent_numeric_routing_table_is_an_empty_reconciled_state() {
        let routes = r#"[
            {"dst":"default","dev":"eth0"},
            {"dst":"127.0.0.0/8","dev":"lo","table":"local"}
        ]"#;

        let egress_routes = route_table_routes(routes, 51_823).unwrap();
        assert!(egress_routes.is_empty());
        assert!(egress_route_entries_match(
            &egress_routes,
            "wg-aegis-egress",
            false,
        ));
    }

    #[test]
    fn numeric_routing_table_routes_are_detected_in_ip_json() {
        let numeric = r#"[{"dst":"default","dev":"wg-aegis-egress","table":51823}]"#;
        let numeric_text =
            r#"[{"dst":"default","type":"unreachable","table":"51823","metric":32760}]"#;

        assert!(!route_table_routes(numeric, 51_823).unwrap().is_empty());
        assert!(!route_table_routes(numeric_text, 51_823).unwrap().is_empty());
        assert!(route_table_routes(numeric, 51_824).unwrap().is_empty());
    }

    #[test]
    fn tunneled_routing_table_requires_exact_live_and_fail_closed_defaults() {
        let routes = r#"[
            {"dst":"default","dev":"wg-aegis-egress","table":51823,"metric":10},
            {"dst":"default","type":"unreachable","table":51823,"metric":32760}
        ]"#;
        let routes = route_table_routes(routes, 51_823).unwrap();

        assert!(egress_route_entries_match(&routes, "wg-aegis-egress", true));
        assert!(!egress_route_entries_match(&routes, "wg-other", true));
        assert!(!egress_route_entries_match(
            &routes,
            "wg-aegis-egress",
            false,
        ));
    }

    #[test]
    fn live_wireguard_config_is_derived_without_reading_the_secret_file() {
        let config = "\
[Interface]
Address = 10.77.1.1/32,fd77::1:1/128
PrivateKey = private-key
ListenPort = 51822
Table = off
PostUp = iptables setup
PreDown = iptables cleanup

[Peer]
PublicKey = peer-key
AllowedIPs = 10.77.1.2/32,fd77::1:2/128
";

        let live = strip_wg_quick_fields(config).expect("config should strip");
        assert!(!live.contains("Address ="));
        assert!(!live.contains("Table ="));
        assert!(!live.contains("PostUp ="));
        assert!(!live.contains("PreDown ="));
        assert!(live.contains("PrivateKey = private-key"));
        assert!(live.contains("ListenPort = 51822"));
        assert!(live.contains("AllowedIPs = 10.77.1.2/32,fd77::1:2/128"));
    }

    #[test]
    fn wireguard_runtime_comparison_ignores_order_and_passive_roaming_endpoint() {
        let desired = "\
[Interface]
PrivateKey = private-key
ListenPort = 51820

[Peer]
PublicKey = passive-peer
AllowedIPs = 10.75.1.2/32,fd75::1:2/128

[Peer]
PublicKey = active-peer
Endpoint = 203.0.113.8:51820
PersistentKeepalive = 5
AllowedIPs = 10.75.1.1/32,fd75::1:1/128
";
        let live = "\
[Interface]
ListenPort = 51820
PrivateKey = private-key

[Peer]
PublicKey = active-peer
AllowedIPs = fd75::1:1/128, 10.75.1.1/32
PersistentKeepalive = 5
Endpoint = 203.0.113.8:51820

[Peer]
PublicKey = passive-peer
Endpoint = 198.51.100.42:49152
AllowedIPs = fd75::1:2/128, 10.75.1.2/32
";

        assert!(wireguard_runtime_configs_match(desired, live).expect("configs should parse"));
    }

    #[test]
    fn wireguard_runtime_comparison_detects_managed_drift() {
        let desired = "\
[Interface]
PrivateKey = private-key
ListenPort = 51820

[Peer]
PublicKey = peer-key
Endpoint = 203.0.113.8:51820
AllowedIPs = 10.75.1.1/32
";
        assert!(
            !wireguard_runtime_configs_match(
                desired,
                &desired.replace("ListenPort = 51820", "ListenPort = 49152")
            )
            .expect("configs should parse")
        );
        assert!(
            !wireguard_runtime_configs_match(
                desired,
                &desired.replace("203.0.113.8:51820", "203.0.113.9:51820")
            )
            .expect("configs should parse")
        );
    }

    #[test]
    fn wireguard_automatic_port_does_not_hide_other_runtime_drift() {
        let desired = "[Interface]\nPrivateKey = key\nListenPort = 0\nFwMark = 44641\n\n\
            [Peer]\nPublicKey = peer\nAllowedIPs = 10.75.1.1/32,fd75::1:1/128\n\
            Endpoint = 192.0.2.1:51820\nPersistentKeepalive = 5\n";
        let live = desired.replace("ListenPort = 0", "ListenPort = 49152");
        assert!(wireguard_runtime_configs_match(desired, &live).unwrap());
        assert!(
            wireguard_runtime_configs_match(
                desired,
                &live.replace("ListenPort = 49152", "ListenPort = 60000")
            )
            .unwrap()
        );
        for (before, after) in [
            ("PrivateKey = key", "PrivateKey = wrong"),
            ("FwMark = 44641", "FwMark = 1"),
            ("192.0.2.1:51820", "192.0.2.1:51824"),
            ("10.75.1.1/32", "10.75.1.2/32"),
            ("PersistentKeepalive = 5", "PersistentKeepalive = 25"),
            ("PublicKey = peer", "PublicKey = other"),
        ] {
            assert!(
                !wireguard_runtime_configs_match(desired, &live.replace(before, after)).unwrap(),
                "must detect drift in {before}",
            );
        }
        assert!(!wireguard_runtime_configs_match(desired, desired).unwrap());
    }

    #[test]
    fn wireguard_runtime_serialization_preserves_peer_configuration() {
        let desired = "[Interface]\nPrivateKey = key\nListenPort = 0\nFwMark = 44641\n\n\
            [Peer]\nPublicKey = first\nPresharedKey = shared\n\
            AllowedIPs = fd75::1:1/128,10.75.1.1/32\n\
            Endpoint = [2001:db8::1]:51820\nPersistentKeepalive = 5\n\n\
            [Peer]\nPublicKey = second\nAllowedIPs = 10.75.1.2/32\n";
        let mut parsed = super::parse_wireguard_runtime_config(desired).unwrap();
        parsed.set_listen_port(49152.try_into().unwrap());
        let serialized = parsed.contents();
        assert_eq!(
            parsed,
            super::parse_wireguard_runtime_config(&serialized).unwrap()
        );
        assert_eq!(49152, parsed.listen_port().unwrap());
        assert!(wireguard_runtime_configs_match(desired, &serialized).unwrap());
    }

    #[test]
    fn wireguard_runtime_normalizes_firewall_mark_representation() {
        let config = "[Interface]\nListenPort = 51820\n";
        let live = format!("{config}FwMark = 0xae61\n");
        for value in ["44641", "0xae61", "0xAE61", "0127141"] {
            assert!(
                wireguard_runtime_configs_match(&format!("{config}FwMark = {value}\n"), &live)
                    .unwrap()
            );
        }
        for value in ["0", "off", "0x0"] {
            assert!(
                wireguard_runtime_configs_match(&format!("{config}FwMark = {value}\n"), config)
                    .unwrap()
            );
        }
        for value in ["4294967296", "-1", "invalid", "1\nFwMark = 2"] {
            assert!(
                WireGuardRuntime::parse("test", &format!("{config}FwMark = {value}\n")).is_err()
            );
        }
    }

    #[test]
    fn wireguard_runtime_normalizes_clamped_private_keys() {
        let desired = "[Interface]\nPrivateKey = cdt8IXi7m5Z9YllMYSdjjk3RBA5XiTyLzV7JTkEsBHg=\nListenPort = 51820\n";
        let live = desired.replace(
            "cdt8IXi7m5Z9YllMYSdjjk3RBA5XiTyLzV7JTkEsBHg=",
            "cNt8IXi7m5Z9YllMYSdjjk3RBA5XiTyLzV7JTkEsBHg=",
        );
        assert!(wireguard_runtime_configs_match(desired, &live).unwrap());
    }

    #[test]
    fn wireguard_port_policy_retries_pending_changes_and_preserves_applied_ports() {
        let directory = tempfile::tempdir().unwrap();
        let automatic = WireGuardListenPort::Automatic;
        let fixed = WireGuardListenPort::for_listener(51820, true).unwrap();
        let path = directory.path().join("port.sha256");
        let applied = automatic.applied_config(&path, 49152);

        assert!(automatic.needs_activation(applied.status().unwrap(), 51820));
        applied.mark_pending().unwrap();
        assert!(automatic.needs_activation(applied.status().unwrap(), 49152));
        applied.mark().unwrap();
        assert!(!automatic.needs_activation(applied.status().unwrap(), 49152));
        assert!(automatic.needs_activation(applied.status().unwrap(), 0));
        let restored = automatic.applied_config(&path, 51820);
        assert!(automatic.needs_activation(restored.status().unwrap(), 51820));

        let promoted = fixed.applied_config(&path, 51820);
        assert_eq!(AppliedConfigStatus::Stale, promoted.status().unwrap());
        assert!(fixed.needs_activation(promoted.status().unwrap(), 49152));
        promoted.mark_pending().unwrap();
        assert!(fixed.needs_activation(promoted.status().unwrap(), 49152));
        assert!(!fixed.needs_activation(promoted.status().unwrap(), 51820));
        promoted.mark().unwrap();
        assert!(fixed.needs_activation(promoted.status().unwrap(), 49152));
        assert!(automatic.needs_activation(applied.status().unwrap(), 51820));
    }

    #[test]
    fn wireguard_port_validation_rejects_invalid_or_duplicate_values() {
        for value in ["65536", "-1", "invalid", "0\nListenPort = 51820"] {
            assert!(
                WireGuardRuntime::parse("test", &format!("[Interface]\nListenPort = {value}\n"))
                    .is_err()
            );
        }
        assert!(WireGuardListenPort::for_listener(0, true).is_err());
        assert!(WireGuardListenPort::for_listener(0, false).is_err());
        assert_eq!(
            WireGuardListenPort::Automatic,
            WireGuardRuntimeConfig::default()
                .listen_port_policy()
                .unwrap()
        );
    }

    #[test]
    fn wireguard_mesh_role_changes_only_the_local_listen_port() {
        let network = test_wireguard_config();
        let hub = inventory_host("hub-a", AegisHostMode::Hub, false);
        let render = |mode| {
            wireguard_config_contents(WireGuardConfigOptions {
                network: &network,
                private_key: "key",
                wireguard_ipv4: "10.75.1.2",
                wireguard_ipv6: "fd75::1:2",
                mode,
                peers: &[&hub],
                public_ipv6_available: false,
                ipv4_endpoint_required: true,
            })
            .unwrap()
        };
        let leaf = render(AegisHostMode::Leaf);
        let listener = render(AegisHostMode::Hub);
        assert!(leaf.contains("ListenPort = 0\n"));
        assert!(leaf.contains("Endpoint = 34.1.2.3:51820\n"));
        assert!(leaf.contains("PersistentKeepalive = 5\n"));
        assert_eq!(
            leaf.replace("ListenPort = 0", "ListenPort = 51820"),
            listener
        );
    }

    #[test]
    fn enrolled_egress_gateway_always_listens_including_when_chained() {
        let config = test_egress_config();
        let local = egress_host("local", 2);
        let upstream = egress_host("upstream", 3);
        let child = egress_host("child", 4);
        for default_target in [None, Some(&upstream)] {
            for gateway_sources in [&[][..], &[&child][..]] {
                let rendered = egress_wireguard_config_contents(
                    &config,
                    &local,
                    &EgressWireGuardPeerPlan {
                        default_target,
                        gateway_sources,
                    },
                    "key",
                )
                .unwrap();
                let runtime = WireGuardRuntime::parse("test", &rendered).unwrap();
                assert_eq!(51823, runtime.desired.listen_port().unwrap(),);
                if default_target.is_some() {
                    assert!(rendered.contains("Endpoint = 10.75.0.3:51823\n"));
                }
            }
        }
    }

    #[test]
    fn post_apply_host_report_is_required_only_when_wireguard_peer_membership_changes() {
        let report = |observed_unix, peers: &[(&str, Option<i64>)]| AegisDirectGatewayReport {
            observed_unix,
            peers: peers
                .iter()
                .map(
                    |(public_key, latest_handshake_unix)| AegisDirectPeerObservation {
                        public_key: (*public_key).to_string(),
                        latest_handshake_unix: *latest_handshake_unix,
                    },
                )
                .collect(),
        };
        let reported = wireguard_peer_keys(&report(100, &[("peer-a", Some(80))]));

        assert_eq!(
            wireguard_peer_keys(&report(101, &[("peer-a", Some(90))])),
            reported,
            "timestamps and handshakes do not require a duplicate report"
        );
        assert_ne!(
            wireguard_peer_keys(&report(
                101,
                &[("peer-a", Some(90)), ("new-satellite", None)]
            )),
            reported,
            "an applied satellite must be reported in the same reconciliation"
        );
        assert_ne!(
            wireguard_peer_keys(&report(101, &[])),
            reported,
            "a revoked peer must also be reported in the same reconciliation"
        );
    }

    #[test]
    fn atomic_text_write_is_a_noop_for_identical_content() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("config");

        assert!(
            write_text_file_if_changed(&path, "desired\n", Some(0o640)).expect("initial write")
        );
        assert!(
            !write_text_file_if_changed(&path, "desired\n", Some(0o640)).expect("identical write")
        );
        assert_eq!("desired\n", fs::read_to_string(&path).expect("config"));
        assert_eq!(
            0o640,
            fs::metadata(&path).expect("metadata").permissions().mode() & 0o7777
        );
        assert_eq!(
            1,
            fs::read_dir(directory.path()).expect("directory").count()
        );
    }

    #[test]
    fn applied_config_stamp_tracks_pending_and_successful_activation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let applied = AppliedConfig {
            path: directory.path().join("applied/config.sha256"),
            digest: "desired-digest".to_string(),
        };

        assert_eq!(
            AppliedConfigStatus::Uninitialized,
            applied.status().expect("initial status")
        );
        applied.mark().expect("mark applied");
        assert_eq!(
            AppliedConfigStatus::Current,
            applied.status().expect("current status")
        );
        assert!(
            config_activation_required(&applied, true).expect("changed config needs activation")
        );
        assert_eq!(
            AppliedConfigStatus::Stale,
            applied.status().expect("pending status")
        );
        assert!(
            config_activation_required(&applied, false).expect("failed activation remains pending")
        );
        applied.mark().expect("mark retry applied");
        assert!(!config_activation_required(&applied, false).expect("applied config is current"));
    }

    #[test]
    fn wg_quick_applied_state_ignores_comments_but_tracks_quick_fields() {
        let first = "\
# generated by aegis v1
[Interface]
Address = 10.75.1.2/32,fd75::1:2/128
PrivateKey = private-key
ListenPort = 51820
PostUp = first command
PostUp = following command

[Peer]
PublicKey = peer-key
AllowedIPs = 10.75.1.1/32
";
        let comment_only = first.replace("generated by aegis v1", "generated by aegis v2");
        let changed = first.replace("PostUp = first command", "PostUp = second command");
        let reordered = first.replace(
            "PostUp = first command\nPostUp = following command",
            "PostUp = following command\nPostUp = first command",
        );

        assert_eq!(
            wireguard_quick_applied_config("wg-aegis", first)
                .expect("first state")
                .digest,
            wireguard_quick_applied_config("wg-aegis", &comment_only)
                .expect("comment state")
                .digest
        );
        assert_ne!(
            wireguard_quick_applied_config("wg-aegis", first)
                .expect("first state")
                .digest,
            wireguard_quick_applied_config("wg-aegis", &changed)
                .expect("changed state")
                .digest
        );
        assert_ne!(
            wireguard_quick_applied_config("wg-aegis", first)
                .expect("first state")
                .digest,
            wireguard_quick_applied_config("wg-aegis", &reordered)
                .expect("reordered state")
                .digest
        );

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("wg-aegis.conf");
        fs::write(&path, comment_only).expect("existing configuration");
        let desired = wireguard_quick_applied_config("wg-aegis", first).expect("desired state");
        assert!(
            !wireguard_quick_config_changed(&path, "wg-aegis", &desired)
                .expect("comment-only comparison")
        );
        fs::write(&path, changed).expect("changed configuration");
        assert!(
            wireguard_quick_config_changed(&path, "wg-aegis", &desired)
                .expect("quick-field comparison")
        );
    }

    #[test]
    fn reusable_host_certificate_rotates_only_for_material_change_or_age() {
        let ca = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("CA key");
        let host = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("host key");
        let mut builder = Builder::new(vec![0x42; 16], host.public_key(), 900, 1_900)
            .expect("certificate builder");
        builder
            .cert_type(ssh_key::certificate::CertType::Host)
            .expect("host certificate");
        builder.key_id("host:aegis:alpha").expect("key id");
        for principal in ["alpha.aegis.example", "10.75.0.1"] {
            builder.valid_principal(principal).expect("principal");
        }
        let certificate = builder
            .sign(&ca)
            .expect("signed certificate")
            .to_openssh()
            .expect("OpenSSH certificate");
        let mut file = tempfile::NamedTempFile::new().expect("certificate file");
        writeln!(file, "{certificate}").expect("write certificate");
        let principals = HostCertificatePrincipals {
            required: ["alpha.aegis.example", "10.75.0.1"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            exact: true,
        };
        let host_public_key = host.public_key().to_openssh().expect("host public key");
        let ca_public_key = ca.public_key().to_openssh().expect("CA public key");

        assert!(
            reusable_host_certificate(
                file.path(),
                &host_public_key,
                &ca_public_key,
                "host:aegis:alpha",
                &principals,
                1_000,
            )
            .expect("certificate inspection")
            .is_some()
        );
        assert!(
            reusable_host_certificate(
                file.path(),
                &host_public_key,
                &ca_public_key,
                "host:aegis:alpha",
                &principals,
                1_600,
            )
            .expect("certificate inspection")
            .is_none()
        );
        let mismatched_principals = HostCertificatePrincipals {
            required: ["alpha.aegis.example".to_string()].into_iter().collect(),
            exact: true,
        };
        assert!(
            reusable_host_certificate(
                file.path(),
                &host_public_key,
                &ca_public_key,
                "host:aegis:alpha",
                &mismatched_principals,
                1_000,
            )
            .expect("certificate inspection")
            .is_none()
        );
    }

    #[test]
    fn runtime_status_reports_cached_inventory_warning() {
        let mut runtime = RuntimeState::default();
        runtime.record_reconcile_success(
            123,
            Some("using cached host inventory".to_string()),
            AgentBabelStatus {
                ready: true,
                ..AgentBabelStatus::default()
            },
            BTreeSet::new(),
            aliases("hub-a"),
        );

        let status = runtime.status();

        assert!(status.ready);
        assert_eq!(
            Some("using cached host inventory"),
            status.last_reconcile_warning.as_deref()
        );
        assert_eq!(None, status.last_reconcile_error);
    }

    #[test]
    fn runtime_coalesces_control_plane_warning_as_success() {
        let mut runtime = RuntimeState::default();
        let requested_at = Instant::now();
        runtime.record_reconcile_success(
            123,
            Some("control-plane sync failed; using cached inventory".to_string()),
            AgentBabelStatus {
                ready: true,
                ..AgentBabelStatus::default()
            },
            BTreeSet::new(),
            aliases("hub-a"),
        );

        assert!(
            runtime
                .coalesced_reconcile_result(requested_at)
                .expect("recent reconcile")
                .is_ok()
        );
    }

    #[test]
    fn runtime_coalesces_data_plane_error_as_failure() {
        let mut runtime = RuntimeState::default();
        let requested_at = Instant::now();
        runtime.record_reconcile_error("data-plane reconcile failed".to_string());

        let error = runtime
            .coalesced_reconcile_result(requested_at)
            .expect("recent reconcile")
            .expect_err("data-plane error");

        assert_eq!("data-plane reconcile failed", error.to_string());
    }

    #[test]
    fn runtime_status_revokes_and_reestablishes_live_babel_readiness() {
        let required = BTreeSet::from([
            "10.75.0.9".parse::<IpAddr>().expect("IPv4"),
            "fd75::9".parse::<IpAddr>().expect("IPv6"),
        ]);
        let mut runtime = RuntimeState::default();
        runtime.record_reconcile_success(
            123,
            None,
            AgentBabelStatus {
                ready: true,
                ready_unix: Some(123),
                learned_route_count: required.len(),
                stable_polls: super::BABEL_ROUTE_READY_STABLE_POLLS,
                ..AgentBabelStatus::default()
            },
            required.clone(),
            aliases("source"),
        );

        runtime.record_babel_observation(BabelRouteSnapshot {
            routes: BTreeSet::from(["10.75.0.9".parse::<IpAddr>().expect("IPv4")]),
            ..BabelRouteSnapshot::default()
        });
        assert!(!runtime.status().ready);
        assert_eq!(0, runtime.status().babel.stable_polls);

        let recovered = BabelRouteSnapshot {
            routes: required,
            ..BabelRouteSnapshot::default()
        };
        runtime.record_babel_observation(BabelRouteSnapshot {
            routes: recovered.routes.clone(),
            ..BabelRouteSnapshot::default()
        });
        assert!(!runtime.status().ready);
        runtime.record_babel_observation(recovered);
        assert!(runtime.status().ready);
    }

    #[test]
    fn runtime_preserves_known_tunnel_state_when_control_plane_is_unavailable() {
        let mut runtime = RuntimeState {
            tunnel: AgentTunnelStatus::Enabled {
                via: "hub-a".into(),
            },
            ..RuntimeState::default()
        };
        runtime.record_reconcile_success(
            123,
            None,
            AgentBabelStatus::default(),
            BTreeSet::new(),
            aliases("source"),
        );
        runtime.record_reconcile_success(
            124,
            Some("using cached host inventory".to_string()),
            AgentBabelStatus::default(),
            BTreeSet::new(),
            aliases("source"),
        );

        assert_eq!(
            AgentTunnelStatus::Enabled {
                via: "hub-a".to_string(),
            },
            runtime.status().tunnel
        );
    }

    #[test]
    fn hub_peer_selection_includes_pending_bootstrap_hosts() {
        let hosts = vec![
            inventory_host("hub-a", AegisHostMode::Hub, false),
            inventory_host("hub-b", AegisHostMode::Hub, false),
            inventory_host("hub-c", AegisHostMode::Hub, true),
            inventory_host("leaf-a", AegisHostMode::Leaf, false),
            inventory_host("leaf-b", AegisHostMode::Leaf, true),
        ];

        let peers = select_peers(AgentMode::Hub, &hosts, &host_id("hub-a"))
            .into_iter()
            .map(|host| host.alias().as_str())
            .collect::<Vec<_>>();

        assert_eq!(peers, vec!["hub-b", "hub-c", "leaf-a", "leaf-b"]);
    }

    #[test]
    fn babel_readiness_requires_non_pending_backbone_hosts_only() {
        let mut hub = inventory_host("hub-a", AegisHostMode::Hub, false);
        hub.host.internal = Some(AegisNetworkMemberInternalAddresses {
            ipv4: "10.75.0.9".to_string(),
            ipv6: "fd75::9".to_string(),
        });
        let pending_hub = inventory_host("hub-b", AegisHostMode::Hub, true);
        let leaf = inventory_host("leaf-a", AegisHostMode::Leaf, false);

        let routes =
            required_babel_backbone_routes(&[&hub, &pending_hub, &leaf]).expect("backbone routes");

        assert_eq!(
            BTreeSet::from([
                "10.75.0.9".parse::<IpAddr>().expect("IPv4"),
                "fd75::9".parse::<IpAddr>().expect("IPv6"),
            ]),
            routes
        );
    }

    #[test]
    fn leaf_peer_selection_includes_all_non_pending_hubs() {
        let hosts = vec![
            inventory_host("hub-a", AegisHostMode::Hub, false),
            inventory_host("hub-b", AegisHostMode::Hub, true),
            inventory_host("hub-c", AegisHostMode::Hub, false),
            inventory_host("leaf-a", AegisHostMode::Leaf, false),
        ];

        let peers = select_peers(AgentMode::Leaf, &hosts, &host_id("leaf-a"))
            .into_iter()
            .map(|host| host.alias().as_str())
            .collect::<Vec<_>>();

        assert_eq!(peers, vec!["hub-a", "hub-c"]);
    }

    #[test]
    fn non_managed_hub_wireguard_config_includes_manual_leaf_peer() {
        let network_wireguard = test_wireguard_config();
        let mut manual_peer = inventory_host("manual-a", AegisHostMode::Leaf, false);
        manual_peer.host.transient = true;
        manual_peer
            .host
            .wireguard
            .as_mut()
            .expect("wireguard")
            .endpoints
            .clear();
        manual_peer.host.wireguard.as_mut().expect("wireguard").ipv4 = "10.75.1.50".to_string();
        manual_peer.host.wireguard.as_mut().expect("wireguard").ipv6 = "fd75::1:50".to_string();
        let hosts = vec![
            inventory_host("hub-a", AegisHostMode::Hub, false),
            inventory_host("leaf-a", AegisHostMode::Leaf, false),
            manual_peer,
        ];
        let peers = select_peers(AgentMode::Hub, &hosts, &host_id("hub-a"));

        assert_eq!(
            peers
                .iter()
                .map(|host| host.alias().as_str())
                .collect::<Vec<_>>(),
            vec!["leaf-a", "manual-a"]
        );

        let contents = wireguard_config_contents(WireGuardConfigOptions {
            network: &network_wireguard,
            private_key: "private-key",
            wireguard_ipv4: "10.75.1.1",
            wireguard_ipv6: "fd75::1:1",
            peers: &peers,
            public_ipv6_available: false,
            ipv4_endpoint_required: false,
            mode: AegisHostMode::Hub,
        })
        .expect("WireGuard config");

        assert!(contents.contains("PublicKey = manual-a-wg-key\n"));
        assert!(contents.contains("AllowedIPs = 10.75.1.50/32,fd75::1:50/128\n"));
    }

    #[test]
    fn non_managed_leaf_wireguard_config_excludes_manual_leaf_peer() {
        let mut manual_peer = inventory_host("manual-a", AegisHostMode::Leaf, false);
        manual_peer.host.transient = true;
        manual_peer
            .host
            .wireguard
            .as_mut()
            .expect("wireguard")
            .endpoints
            .clear();
        let hosts = vec![
            inventory_host("hub-a", AegisHostMode::Hub, false),
            inventory_host("leaf-a", AegisHostMode::Leaf, false),
            manual_peer,
        ];

        let peers = select_peers(AgentMode::Leaf, &hosts, &host_id("leaf-a"))
            .into_iter()
            .map(|host| host.alias().as_str())
            .collect::<Vec<_>>();

        assert_eq!(peers, vec!["hub-a"]);
    }

    #[test]
    fn bird3_source_block_requires_native_architecture_and_keyring() {
        let blocks = bird3_source_blocks(
            "Types: deb\n\
             URIs: https://pkg.labs.nic.cz/bird3\n\
             Suites: noble\n\
             Components: main\n\
             Architectures: amd64\n\
             Signed-By: /usr/share/keyrings/cznic-labs-bird3.gpg\n",
        );
        assert!(bird3_source_block_is_managed(&blocks[0], "amd64"));

        let blocks = bird3_source_blocks(
            "Types: deb\n\
             URIs: https://pkg.labs.nic.cz/bird3\n\
             Suites: noble\n\
             Components: main\n\
             Architectures: amd64\n",
        );
        assert!(!bird3_source_block_is_managed(&blocks[0], "amd64"));

        let blocks = bird3_source_blocks(
            "Types: deb\n\
             URIs: https://pkg.labs.nic.cz/bird3\n\
             Suites: noble\n\
             Components: main\n\
             Architectures: arm64\n\
             Signed-By: /usr/share/keyrings/cznic-labs-bird3.gpg\n",
        );
        assert!(!bird3_source_block_is_managed(&blocks[0], "amd64"));
    }

    #[test]
    fn bird3_repository_files_must_be_world_readable_regular_root_files() {
        let file = tempfile::NamedTempFile::new().expect("temporary repository file");
        fs::set_permissions(file.path(), fs::Permissions::from_mode(0o600))
            .expect("set restrictive mode");

        let warning = bird3_repository_file_message(
            file.path().to_str().expect("UTF-8 temporary path"),
            "apt source",
        )
        .expect("mode 0600 must be rejected");
        assert!(warning.value.contains("mode 0600"));
        assert!(
            warning
                .value
                .contains("root-owned regular file with mode 0644")
        );
    }

    #[test]
    fn bird3_source_blocks_ignore_comments_and_blank_lines() {
        let blocks = bird3_source_blocks(
            "\n# ignored\n\
             Types: deb\n\
             URIs: https://pkg.labs.nic.cz/bird3\n\
             Suites: noble\n\
             Components: main\n\
             Architectures: amd64\n\
             Signed-By: /usr/share/keyrings/cznic-labs-bird3.gpg\n",
        );

        assert_eq!(1, blocks.len());
        assert!(bird3_source_block_is_managed(&blocks[0], "amd64"));
    }

    #[test]
    fn matching_hub_member_does_not_require_an_update() {
        let mut current = inventory_host("hub-a", AegisHostMode::Hub, false).host;
        current.internal = Some(AegisNetworkMemberInternalAddresses {
            ipv4: "10.75.99.9".to_string(),
            ipv6: "fd75::99:9".to_string(),
        });
        let desired = AegisPutNetworkMemberRequest {
            mode: AegisHostMode::Hub,
            wireguard: current
                .wireguard
                .as_ref()
                .map(|wireguard| AegisPutNetworkMemberWireGuard {
                    public_key: wireguard.public_key.clone(),
                    ipv4: None,
                    ipv6: None,
                    endpoints: wireguard.endpoints.clone(),
                }),
            pending: false,
        };
        let current = AegisNetworkMember {
            aliases: aliases("hub-a"),
            mode: current.mode,
            wireguard: current.wireguard,
            internal: current.internal,
            pending: current.pending,
            updated_unix: current.updated_unix,
        };

        assert!(!network_member_needs_update(&current, &desired, true));
    }

    #[test]
    fn wireguard_config_keeps_passive_leaf_peer_without_endpoint() {
        let peer = inventory_host("leaf-a", AegisHostMode::Leaf, false);
        let network_wireguard = test_wireguard_config();
        let mut peer = peer;
        peer.host
            .wireguard
            .as_mut()
            .expect("wireguard")
            .endpoints
            .clear();
        peer.host.internal = None;

        let contents = wireguard_config_contents(WireGuardConfigOptions {
            network: &network_wireguard,
            private_key: "private-key",
            wireguard_ipv4: "10.75.1.3",
            wireguard_ipv6: "fd75::1:3",
            peers: &[&peer],
            public_ipv6_available: false,
            ipv4_endpoint_required: true,
            mode: AegisHostMode::Hub,
        })
        .expect("WireGuard config");

        assert!(contents.starts_with("# THIS FILE IS AUTOMATICALLY GENERATED BY aegis.\n"));
        assert!(contents.contains("# ALL MODIFICATIONS WILL BE LOST.\n\n[Interface]\n"));
        assert!(contents.contains("ListenPort = 51820\n"));
        assert!(contents.contains("[Peer]\nPublicKey = leaf-a-wg-key\n"));
        assert!(contents.contains("AllowedIPs = 10.75.0.1/32,fd75::1/128\n"));
        assert!(!contents.contains("fe80"));
        assert!(!contents.contains("Endpoint ="));
        assert!(!contents.contains("PersistentKeepalive = 5\nAllowedIPs"));
    }

    #[test]
    fn bird_config_uses_loss_adaptive_babel_overlay_policy() {
        let mut host = inventory_host("hub-a", AegisHostMode::Hub, false);
        host.host.wireguard.as_mut().expect("wireguard").ipv4 = "10.75.1.3".to_string();
        host.host.wireguard.as_mut().expect("wireguard").ipv6 = "fd75::1:3".to_string();
        host.host.internal = Some(AegisNetworkMemberInternalAddresses {
            ipv4: "10.75.99.9".to_string(),
            ipv6: "fd75::99:9".to_string(),
        });

        let contents = bird_config_contents(&test_mesh(), AgentMode::Hub, &host)
            .expect("bird config should render");

        assert!(contents.contains("protocol static self_v4"));
        assert!(contents.contains("timeformat route iso long ms;"));
        assert!(contents.contains("route 10.75.99.9/32 via \"lo\";"));
        assert!(contents.contains("protocol static self_v6"));
        assert!(contents.contains("route fd75::99:9/128 via \"lo\";"));
        assert!(contents.contains("protocol babel babel_mesh"));
        assert!(contents.contains("randomize router id yes;"));
        assert!(contents.contains(&format!("interface \"{BABEL_OVERLAY_PREFIX}*\"")));
        assert!(contents.contains("type wireless;"));
        assert!(contents.contains("hello interval 1 s;"));
        assert!(contents.contains("update interval 4 s;"));
        assert!(contents.contains("rxcost 256;"));
        assert!(contents.contains("rtt cost 256;"));
        assert!(contents.contains("rtt min 10 ms;"));
        assert!(contents.contains("rtt max 350 ms;"));
        assert!(contents.contains("rtt decay 42;"));
        assert!(contents.contains("send timestamps yes;"));
        assert!(!contents.contains("limit "));
        assert!(!contents.contains("type tunnel;"));
        assert!(contents.contains("if net ~ [ 10.75.0.0/16+ ] then accept;"));
        assert!(contents.contains("if net !~ [ 10.75.0.0/16+ ] then reject;"));
        assert!(contents.contains("if net ~ [ fd75::/64+ ] then accept;"));
        assert!(contents.contains("if net !~ [ fd75::/64+ ] then reject;"));
        assert!(contents.contains("if proto = \"babel_mesh\" then accept;"));
        assert!(contents.contains("if proto = \"self_v4\" then reject;"));
        assert!(contents.contains("krt_prefsrc = 10.75.99.9;"));
        assert!(contents.contains("if proto = \"self_v6\" then reject;"));
        assert!(contents.contains("krt_prefsrc = fd75::99:9;"));
        assert!(!contents.contains("import all"));
        assert!(!contents.contains("export all"));
        assert!(!contents.contains("route 10.75.1.3/32 via \"wg-aegis\";"));
        assert!(!contents.contains("route fd75::1:3/128 via \"wg-aegis\";"));
        assert!(!contents.contains("learn;"));
        assert!(!contents.contains("route 10.75.1.3/32 via \"wg-aegis\";"));
        assert!(!contents.contains("route fd75::1:3/128 via \"wg-aegis\";"));
    }

    #[test]
    fn leaf_bird_config_does_not_export_babel_routes() {
        let host = inventory_host("leaf-a", AegisHostMode::Leaf, false);

        let contents = bird_config_contents(&test_mesh(), AgentMode::Leaf, &host)
            .expect("bird config should render");

        assert!(!contents.contains("if proto = \"babel_mesh\" then accept;"));
        assert!(contents.contains("if proto = \"self_v4\" then accept;"));
        assert!(contents.contains("if proto = \"self_v6\" then accept;"));
    }

    #[test]
    fn parse_babel_route_snapshot_reads_routes_and_latest_timestamp() {
        let output = "\
BIRD 3.1.0 ready.\n\
Table master4:\n\
10.75.0.5/32         unicast [babel_mesh 2026-04-29 12:16:03.217] * (100/96) [10.75.1.4]\n\
\tdev agx111\n\
10.75.0.7/32         unicast [babel_mesh 2026-04-29 12:16:04.031] * (100/96) [10.75.1.7]\n\
Table master6:\n\
fd75::5/128          unicast [babel_mesh 2026-04-29 12:16:03.917] * (100/96) [fd75::1:4]\n";

        let snapshot = parse_babel_route_snapshot(output);

        assert_eq!(
            BTreeSet::from([
                "10.75.0.5".parse::<IpAddr>().expect("IPv4"),
                "10.75.0.7".parse::<IpAddr>().expect("IPv4"),
                "fd75::5".parse::<IpAddr>().expect("IPv6"),
            ]),
            snapshot.routes
        );
        assert_eq!(
            Some("2026-04-29 12:16:04.031".to_string()),
            snapshot.latest_route_update
        );
    }

    #[test]
    fn babel_status_requires_every_backbone_route() {
        let required = BTreeSet::from([
            "10.75.0.9".parse::<IpAddr>().expect("IPv4"),
            "fd75::9".parse::<IpAddr>().expect("IPv6"),
        ]);
        let snapshot = BabelRouteSnapshot {
            routes: BTreeSet::from(["10.75.0.9".parse::<IpAddr>().expect("IPv4")]),
            latest_route_update: Some("2026-08-23 12:00:00.000".to_string()),
            last_error: None,
        };

        let status = babel_status_from_snapshot(
            &snapshot,
            &required,
            super::BABEL_ROUTE_READY_STABLE_POLLS,
            None,
        );

        assert!(!status.ready);
        assert_eq!(1, status.learned_route_count);
        assert_eq!(
            Some("Babel is missing required backbone routes: fd75::9"),
            status.last_error.as_deref()
        );
    }

    #[test]
    fn wireguard_config_does_not_use_internal_addresses_as_endpoints() {
        let network_wireguard = test_wireguard_config();
        let mut peer = inventory_host("deus-kellnr", AegisHostMode::Leaf, false);
        peer.host
            .wireguard
            .as_mut()
            .expect("wireguard")
            .endpoints
            .clear();
        peer.host.internal = Some(AegisNetworkMemberInternalAddresses {
            ipv4: "10.75.99.9".to_string(),
            ipv6: "fd75::99:9".to_string(),
        });
        peer.host.wireguard.as_mut().expect("wireguard").ipv4 = "10.75.1.2".to_string();
        peer.host.wireguard.as_mut().expect("wireguard").ipv6 = "fd75::1:2".to_string();

        let contents = wireguard_config_contents(WireGuardConfigOptions {
            network: &network_wireguard,
            private_key: "private-key",
            wireguard_ipv4: "10.75.1.4",
            wireguard_ipv6: "fd75::1:4",
            peers: &[&peer],
            public_ipv6_available: false,
            ipv4_endpoint_required: true,
            mode: AegisHostMode::Hub,
        })
        .expect("WireGuard config");

        assert!(contents.contains("AllowedIPs = 10.75.1.2/32,fd75::1:2/128\n"));
        assert!(!contents.contains("fe80"));
        assert!(!contents.contains("Endpoint = 10.75.99.9:51820"));
        assert!(!contents.contains("PersistentKeepalive = 5\nAllowedIPs"));
    }

    #[test]
    fn wireguard_config_skips_peers_without_wireguard_endpoints() {
        let network_wireguard = test_wireguard_config();
        let mut peer = inventory_host("hub-a", AegisHostMode::Hub, false);
        peer.host
            .wireguard
            .as_mut()
            .expect("wireguard")
            .endpoints
            .clear();

        let contents = wireguard_config_contents(WireGuardConfigOptions {
            network: &network_wireguard,
            private_key: "private-key",
            wireguard_ipv4: "10.75.1.42",
            wireguard_ipv6: "fd75::1:2a",
            peers: &[&peer],
            public_ipv6_available: false,
            ipv4_endpoint_required: true,
            mode: AegisHostMode::Leaf,
        })
        .expect("WireGuard config");

        assert!(contents.contains("PublicKey = hub-a-wg-key"));
        assert!(!contents.contains("Endpoint ="));
    }

    #[test]
    fn wireguard_config_brackets_ipv6_endpoints() {
        let network_wireguard = test_wireguard_config();
        let mut peer = inventory_host("hub-a", AegisHostMode::Hub, false);
        peer.host.wireguard.as_mut().expect("wireguard").endpoints =
            vec!["2001:db8::10".to_string()];

        let contents = wireguard_config_contents(WireGuardConfigOptions {
            network: &network_wireguard,
            private_key: "private-key",
            wireguard_ipv4: "10.75.1.42",
            wireguard_ipv6: "fd75::1:2a",
            peers: &[&peer],
            public_ipv6_available: true,
            ipv4_endpoint_required: false,
            mode: AegisHostMode::Leaf,
        })
        .expect("WireGuard config");

        assert!(contents.contains("Endpoint = [2001:db8::10]:51820"));
    }

    #[test]
    fn endpoint_recovery_target_matches_rendered_wireguard_peer() {
        let network_wireguard = test_wireguard_config();
        let peer = inventory_host("hub-a", AegisHostMode::Hub, false);
        let target = wireguard_endpoint_peer(
            &network_wireguard.interface,
            network_wireguard.endpoint_port,
            &peer,
            false,
            true,
        )
        .expect("peer should have a recovery endpoint");
        let contents = wireguard_config_contents(WireGuardConfigOptions {
            network: &network_wireguard,
            private_key: "private-key",
            wireguard_ipv4: "10.75.1.42",
            wireguard_ipv6: "fd75::1:2a",
            peers: &[&peer],
            public_ipv6_available: false,
            ipv4_endpoint_required: true,
            mode: AegisHostMode::Leaf,
        })
        .expect("WireGuard config");

        assert_eq!("wg-aegis", target.interface);
        assert_eq!("34.1.2.3:51820", target.endpoint.to_string());
        assert_eq!("10.75.0.1:22", target.probe.expect("probe").to_string());
        assert!(contents.contains(&format!("Endpoint = {}\n", target.endpoint)));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn underlay_route_events_only_match_configured_endpoint_paths() {
        let peer = inventory_host("hub-a", AegisHostMode::Hub, false);
        let target = wireguard_endpoint_peer("wg-aegis", 51820, &peer, false, true)
            .expect("peer should have a recovery endpoint");
        let peers = [target];

        let mut default_route = RouteMessage::default();
        default_route.header.address_family = AddressFamily::Inet;
        let default_route =
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(default_route.clone()));
        assert_eq!(
            Some(super::UnderlayChange::Route {
                network: Ipv4Addr::UNSPECIFIED.into(),
                prefix: 0,
            }),
            relevant_underlay_change(&default_route, &peers)
        );

        let mut unrelated_route = RouteMessage::default();
        unrelated_route.header.address_family = AddressFamily::Inet;
        unrelated_route.header.destination_prefix_length = 24;
        unrelated_route
            .attributes
            .push(RouteAttribute::Destination(RouteAddress::Inet(
                Ipv4Addr::new(192, 0, 2, 0),
            )));
        let unrelated_route =
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(unrelated_route));
        assert_eq!(None, relevant_underlay_change(&unrelated_route, &peers));

        let mut deleted_default = RouteMessage::default();
        deleted_default.header.address_family = AddressFamily::Inet;
        let deleted_default =
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelRoute(deleted_default));
        assert_eq!(None, relevant_underlay_change(&deleted_default, &peers));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn usable_link_events_require_a_ready_state_and_name() {
        let mut link = LinkMessage::default();
        link.attributes = vec![
            LinkAttribute::IfName("wlan0".to_string()),
            LinkAttribute::OperState(LinkState::Dormant),
        ];
        assert_eq!(Some("wlan0"), usable_link_name(&link));

        link.attributes[1] = LinkAttribute::OperState(LinkState::Down);
        assert_eq!(None, usable_link_name(&link));
    }

    #[test]
    fn peer_overlay_name_is_stable_and_prefixed() {
        let host_id = host_id("deus-hub-6zefhwxw");
        let name = peer_overlay_name(&host_id);

        assert_eq!(name, peer_overlay_name(&host_id));
        assert!(name.starts_with(BABEL_OVERLAY_PREFIX));
        assert!(name.len() <= 15);
    }

    #[test]
    fn peer_overlay_vni_is_symmetric_and_nonzero() {
        let left_host_id = host_id("sabretop-ubu");
        let right_host_id = host_id("deus-hub-6zefhwxw");
        let left = peer_overlay_vni(&left_host_id, &right_host_id);
        let right = peer_overlay_vni(&right_host_id, &left_host_id);

        assert_eq!(left, right);
        assert_ne!(left, 0);
        assert!(left <= 0x00ff_ffff);
    }

    #[test]
    fn peer_overlay_transit_addresses_are_symmetric_and_ordered() {
        let left_host_id = host_id("sabretop-ubu");
        let right_host_id = host_id("deus-hub-fe4p11w3");
        let left = peer_overlay_transit_addrs(&left_host_id, &right_host_id);
        let right = peer_overlay_transit_addrs(&right_host_id, &left_host_id);

        assert_ne!(left.local_ipv4, right.local_ipv4);
        assert_ne!(left.local_ipv6, right.local_ipv6);
        assert_eq!(left.local_ipv4.octets()[0], 100);
        assert!((64..128).contains(&left.local_ipv4.octets()[1]));
        assert_eq!(right.local_ipv4.octets()[0], 100);
        assert!((64..128).contains(&right.local_ipv4.octets()[1]));
    }

    #[test]
    fn overlay_address_match_requires_expected_dual_stack_addresses() {
        let transit = OverlayTransitAddrs {
            local_ipv4: Ipv4Addr::new(100, 64, 12, 34),
            local_ipv6: Ipv6Addr::new(0xfd75, 0xffff, 0, 0, 0, 0, 0, 0x1234),
        };

        assert!(overlay_addresses_match(
            "41: agx0 inet 100.64.12.34/30 scope global agx0\n41: agx0 inet6 fd75:ffff::1234/127 scope global\n",
            &transit,
        ));
        assert!(!overlay_addresses_match(
            "41: agx0 inet 100.64.12.35/30 scope global agx0\n41: agx0 inet6 fd75:ffff::1234/127 scope global\n",
            &transit,
        ));
    }

    #[test]
    fn babel_overlay_matches_expected_device() {
        let details = "159: agx0948490ec8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1280 qdisc \
                       noqueue state UNKNOWN mode DEFAULT group default qlen 1000 \
                       link/ether 16:d5:2e:0a:6a:a1 brd ff:ff:ff:ff:ff:ff \
                       vxlan id 718309 remote 10.75.1.3 local 10.75.1.2 dev wg-aegis \
                       srcport 0 0 dstport 4789 ttl auto ageing 300 nolearning";

        assert!(babel_overlay_matches(
            details,
            718309,
            "wg-aegis",
            "10.75.1.2",
            "10.75.1.3"
        ));
        assert!(!babel_overlay_matches(
            details,
            718309,
            "wg-aegis",
            "10.75.1.2",
            "10.75.1.4"
        ));
        assert!(!babel_overlay_matches(
            "138: agx67428f2c52@if188: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1280 \
             qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000 \
             link/gre6 fd75::1:3 peer fd75::1:1",
            718309,
            "wg-aegis",
            "10.75.1.2",
            "10.75.1.3"
        ));
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn remove_native_resources() -> Result<()> {
    macos::remove_owned_resources()
}
