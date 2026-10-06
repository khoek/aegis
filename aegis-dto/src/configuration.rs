use crate::{
    mtu,
    protocol::{
        AegisDirectGatewayConfig, AegisDnsConfig, AegisEgressConfig, AegisNetworkConfig,
        AegisWireGuardAddressPool,
    },
};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClientCaConfig {
    /// OpenSSH private key PEM ("BEGIN OPENSSH PRIVATE KEY") used for user/client certs.
    pub private_key_pem: String,
    /// Optional passphrase for encrypted key
    pub passphrase: Option<String>,
    pub cert_ttl_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DirectClientCaConfig {
    /// OpenSSH private key PEM used only for persistent direct-device certificates.
    pub private_key_pem: String,
    pub passphrase: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ServerCaConfig {
    /// OpenSSH private key PEM ("BEGIN OPENSSH PRIVATE KEY")
    pub private_key_pem: String,
    /// Optional passphrase for encrypted key
    pub passphrase: Option<String>,
    pub cert_ttl_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TlsCaConfig {
    pub certificate_pem: String,
    pub private_key_pem: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TlsConfig {
    pub root: TlsCaConfig,
    pub issuing: TlsCaConfig,
    pub issuing_crl_pem: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AegisConfig {
    pub networks: BTreeMap<String, AegisNetworkConfig>,
    pub direct_gateway: AegisDirectGatewayConfig,
    pub egress: AegisEgressConfig,
    pub dns: Option<AegisDnsConfig>,
}

#[derive(Clone, Debug)]
pub struct AegisInstanceConfig {
    pub client_ca: ClientCaConfig,
    pub direct_client_ca: DirectClientCaConfig,
    pub server_ca: ServerCaConfig,
    pub tls: TlsConfig,
    pub config: AegisConfig,
}

impl AegisInstanceConfig {
    pub fn require(self) -> anyhow::Result<Self> {
        if self.client_ca.cert_ttl_seconds == 0 {
            anyhow::bail!("aegis.ssh.ca.user.cert_ttl_seconds must be > 0");
        }
        if self.server_ca.cert_ttl_seconds == 0 {
            anyhow::bail!("aegis.ssh.ca.host.cert_ttl_seconds must be > 0");
        }
        if self.tls.root.certificate_pem.trim().is_empty() {
            anyhow::bail!("aegis.tls.cas.root.certificate_pem must not be empty");
        }
        if self.tls.root.private_key_pem.trim().is_empty() {
            anyhow::bail!("aegis.tls.cas.root.private_key_pem must not be empty");
        }
        if self.tls.issuing.certificate_pem.trim().is_empty() {
            anyhow::bail!("aegis.tls.cas.issuing.certificate_pem must not be empty");
        }
        if self.tls.issuing.private_key_pem.trim().is_empty() {
            anyhow::bail!("aegis.tls.cas.issuing.private_key_pem must not be empty");
        }
        if self.tls.issuing_crl_pem.trim().is_empty() {
            anyhow::bail!("aegis.tls.cas.issuing.crl_pem must not be empty");
        }
        self.config.validate()?;

        Ok(self)
    }
}

fn validate_wireguard_interface(field: &str, value: &str) -> anyhow::Result<()> {
    crate::validate_wireguard_interface_name(value)
        .map_err(|error| anyhow::anyhow!("{field}: {error}"))
}

fn validate_address_pool(field: &str, pool: &AegisWireGuardAddressPool) -> anyhow::Result<()> {
    crate::validate_wireguard_address_pool(pool)
        .map_err(|error| anyhow::anyhow!("{field}: {error}"))
}

fn reject_address_pool_overlap(
    left_field: &str,
    left: &AegisWireGuardAddressPool,
    right_field: &str,
    right: &AegisWireGuardAddressPool,
) -> anyhow::Result<()> {
    if crate::wireguard_address_pools_overlap(left, right)
        .map_err(|error| anyhow::anyhow!("{left_field} / {right_field}: {error}"))?
    {
        anyhow::bail!("{left_field} overlaps {right_field}");
    }
    Ok(())
}

impl AegisConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.networks.is_empty() {
            anyhow::bail!("aegis.networks must define at least one network");
        }
        for (name, network) in &self.networks {
            if name.trim().is_empty() {
                anyhow::bail!("aegis.networks contains an empty network name");
            }
            if network.name != *name {
                anyhow::bail!("aegis.networks.{name}.name must equal `{name}`");
            }
            if network.wireguard.interface.trim().is_empty() {
                anyhow::bail!("aegis.networks.{name}.wireguard.interface must not be empty");
            }
            validate_wireguard_interface(
                &format!("aegis.networks.{name}.wireguard.interface"),
                &network.wireguard.interface,
            )?;
            if network.wireguard.endpoint_port == 0 {
                anyhow::bail!("aegis.networks.{name}.wireguard.endpoint_port must be > 0");
            }
            if !(mtu::IPV6_MINIMUM..=9000).contains(&network.wireguard.mtu) {
                anyhow::bail!(
                    "aegis.networks.{name}.wireguard.mtu must support IPv6 and be at most 9000"
                );
            }
            if network.wireguard.fwmark == 0 {
                anyhow::bail!("aegis.networks.{name}.wireguard.fwmark must be > 0");
            }
            if network.wireguard.subnet_ipv4.trim().is_empty() {
                anyhow::bail!("aegis.networks.{name}.wireguard.subnet_ipv4 must not be empty");
            }
            if network.wireguard.subnet_ipv6.trim().is_empty() {
                anyhow::bail!("aegis.networks.{name}.wireguard.subnet_ipv6 must not be empty");
            }
            validate_address_pool(
                &format!("aegis.networks.{name}.wireguard"),
                &network.wireguard.address_pool(),
            )?;
            if let Some(mesh) = &network.mesh {
                if mesh.overlay_mtu >= network.wireguard.mtu {
                    anyhow::bail!(
                        "aegis.networks.{name}.mesh.overlay_mtu must be below its WireGuard MTU"
                    );
                }
                if u32::from(mesh.overlay_mtu) + u32::from(mtu::VXLAN_OVER_IPV4)
                    > u32::from(network.wireguard.mtu)
                {
                    anyhow::bail!(
                        "aegis.networks.{name}.mesh.overlay_mtu leaves insufficient space for IPv4/UDP/VXLAN encapsulation"
                    );
                }
                if mesh.subnet_ipv4.trim().is_empty() {
                    anyhow::bail!("aegis.networks.{name}.mesh.subnet_ipv4 must not be empty");
                }
                if mesh.subnet_ipv6.trim().is_empty() {
                    anyhow::bail!("aegis.networks.{name}.mesh.subnet_ipv6 must not be empty");
                }
                validate_address_pool(
                    &format!("aegis.networks.{name}.mesh"),
                    &AegisWireGuardAddressPool {
                        subnet_ipv4: mesh.subnet_ipv4.clone(),
                        subnet_ipv6: mesh.subnet_ipv6.clone(),
                    },
                )?;
            }
        }
        let networks = self.networks.iter().collect::<Vec<_>>();
        for (index, (left_name, left)) in networks.iter().enumerate() {
            for (right_name, right) in networks.iter().skip(index + 1) {
                if left.wireguard.interface == right.wireguard.interface {
                    anyhow::bail!(
                        "aegis networks `{left_name}` and `{right_name}` use the same WireGuard interface `{}`",
                        left.wireguard.interface
                    );
                }
                if left.wireguard.endpoint_port == right.wireguard.endpoint_port {
                    anyhow::bail!(
                        "aegis networks `{left_name}` and `{right_name}` use the same WireGuard endpoint port {}",
                        left.wireguard.endpoint_port
                    );
                }
            }
        }
        let mut address_pools = Vec::new();
        for (name, network) in &self.networks {
            address_pools.push((
                format!("aegis.networks.{name}.wireguard"),
                network.wireguard.address_pool(),
            ));
            if let Some(mesh) = &network.mesh {
                address_pools.push((
                    format!("aegis.networks.{name}.mesh"),
                    AegisWireGuardAddressPool {
                        subnet_ipv4: mesh.subnet_ipv4.clone(),
                        subnet_ipv6: mesh.subnet_ipv6.clone(),
                    },
                ));
            }
        }
        let direct_gateway = &self.direct_gateway;
        if direct_gateway.interface.trim().is_empty() {
            anyhow::bail!("aegis.direct_gateway.interface must not be empty");
        }
        validate_wireguard_interface("aegis.direct_gateway.interface", &direct_gateway.interface)?;
        if direct_gateway.endpoint_port == 0 {
            anyhow::bail!("aegis.direct_gateway.endpoint_port must be > 0");
        }
        if !(mtu::IPV6_MINIMUM..=9000).contains(&direct_gateway.mtu) {
            anyhow::bail!("aegis.direct_gateway.mtu must support IPv6 and be at most 9000");
        }
        if direct_gateway.fwmark == 0 {
            anyhow::bail!("aegis.direct_gateway.fwmark must be > 0");
        }
        if direct_gateway.subnet_ipv4.trim().is_empty() {
            anyhow::bail!("aegis.direct_gateway.subnet_ipv4 must not be empty");
        }
        if direct_gateway.subnet_ipv6.trim().is_empty() {
            anyhow::bail!("aegis.direct_gateway.subnet_ipv6 must not be empty");
        }
        let direct_gateway_pool = direct_gateway.address_pool();
        validate_address_pool("aegis.direct_gateway", &direct_gateway_pool)?;
        address_pools.push(("aegis.direct_gateway".to_string(), direct_gateway_pool));
        for (name, network) in &self.networks {
            if direct_gateway.interface == network.wireguard.interface {
                anyhow::bail!(
                    "aegis.direct_gateway and network `{name}` use the same WireGuard interface `{}`",
                    direct_gateway.interface
                );
            }
            if direct_gateway.endpoint_port == network.wireguard.endpoint_port {
                anyhow::bail!(
                    "aegis.direct_gateway and network `{name}` use the same WireGuard endpoint port {}",
                    direct_gateway.endpoint_port
                );
            }
        }
        let egress = &self.egress;
        validate_wireguard_interface("aegis.egress.interface", &egress.interface)?;
        if !self.networks.contains_key(&egress.network)
            || self.networks[&egress.network].mesh.is_none()
        {
            anyhow::bail!("aegis.egress.network must select a managed mesh network");
        }
        if egress.endpoint_port == 0 {
            anyhow::bail!("aegis.egress.endpoint_port must be > 0");
        }
        if !(mtu::IPV6_MINIMUM..=9000).contains(&egress.mtu) {
            anyhow::bail!("aegis.egress.mtu must support IPv6 and be at most 9000");
        }
        let egress_mesh = self.networks[&egress.network]
            .mesh
            .as_ref()
            .expect("validated egress network must have a mesh");
        if u32::from(egress.mtu) + u32::from(mtu::WIREGUARD_OVER_IPV4)
            > u32::from(egress_mesh.overlay_mtu)
        {
            anyhow::bail!(
                "aegis.egress.mtu leaves insufficient space for WireGuard-over-IPv4 encapsulation inside the mesh overlay"
            );
        }
        if egress.fwmark == 0 || egress.routing_table == 0 {
            anyhow::bail!("aegis.egress fwmark and routing_table must be non-zero");
        }
        for (name, network) in &self.networks {
            if network.wireguard.fwmark != egress.fwmark {
                anyhow::bail!(
                    "aegis.networks.{name}.wireguard.fwmark must equal aegis.egress.fwmark"
                );
            }
        }
        if direct_gateway.fwmark != egress.fwmark {
            anyhow::bail!("aegis.direct_gateway.fwmark must equal aegis.egress.fwmark");
        }
        if egress.main_rule_priority >= egress.egress_rule_priority {
            anyhow::bail!("aegis.egress.main_rule_priority must precede egress_rule_priority");
        }
        if self.networks.values().any(|network| {
            network.wireguard.interface == egress.interface
                || network.wireguard.endpoint_port == egress.endpoint_port
        }) {
            anyhow::bail!("aegis.egress must use a distinct WireGuard interface and port");
        }
        if direct_gateway.interface == egress.interface
            || direct_gateway.endpoint_port == egress.endpoint_port
        {
            anyhow::bail!(
                "aegis.egress and aegis.direct_gateway must use distinct interfaces and ports"
            );
        }
        let egress_pool = egress.address_pool();
        let egress_dns_pool = egress.dns_address_pool();
        validate_address_pool("aegis.egress", &egress_pool)?;
        validate_address_pool("aegis.egress.dns", &egress_dns_pool)?;
        address_pools.push(("aegis.egress".to_string(), egress_pool));
        address_pools.push(("aegis.egress.dns".to_string(), egress_dns_pool));
        for (index, (left_field, left_pool)) in address_pools.iter().enumerate() {
            for (right_field, right_pool) in address_pools.iter().skip(index + 1) {
                reject_address_pool_overlap(left_field, left_pool, right_field, right_pool)?;
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceDefinition {
    host_identity_schema: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    direct_gateway: Option<StoredAegisDirectGatewayConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    egress: Option<StoredAegisEgressConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    networks: Option<BTreeMap<String, StoredAegisNetworkConfig>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subnets: Option<BTreeMap<String, StoredAegisIpFamilyPair>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wireguard: Option<BTreeMap<String, StoredAegisWireGuardConfig>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dns: Option<crate::protocol::AegisDnsConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct StoredAegisDirectGatewayConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    interface: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    full_tunnel_dns: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct StoredAegisEgressConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    interface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dns_subnet: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fwmark: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    routing_table: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    main_rule_priority: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    egress_rule_priority: Option<u32>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct StoredAegisNetworkConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    interface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mesh_subnet: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    overlay_mtu: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    managed_ssh: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host_dns_suffix: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct StoredAegisIpFamilyPair {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ipv4: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ipv6: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct StoredAegisWireGuardConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subnet: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mtu: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fwmark: Option<u32>,
}

impl NamespaceDefinition {
    pub fn validate(self) -> anyhow::Result<AegisConfig> {
        let stored = self;
        anyhow::ensure!(
            stored.host_identity_schema == crate::HOST_IDENTITY_SCHEMA,
            "namespace.host_identity_schema must be `{}`",
            crate::HOST_IDENTITY_SCHEMA
        );
        let networks = validate_aegis_networks(&stored)?;
        let direct_gateway = validate_aegis_direct_gateway(&stored)?;
        let egress = validate_aegis_egress(&stored, &networks)?;
        let dns = stored
            .dns
            .clone()
            .map(|dns| validate_aegis_dns_config(dns, &networks))
            .transpose()?;
        networks
            .get(crate::DEFAULT_AEGIS_NETWORK)
            .and_then(|network| network.mesh.as_ref())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "namespace.networks.{} must define mesh_subnet",
                    crate::DEFAULT_AEGIS_NETWORK
                )
            })?;
        Ok(AegisConfig {
            networks,
            direct_gateway,
            egress,

            dns,
        })
    }
}

fn validate_aegis_dns_config(
    mut dns: crate::protocol::AegisDnsConfig,
    networks: &BTreeMap<String, crate::protocol::AegisNetworkConfig>,
) -> anyhow::Result<crate::protocol::AegisDnsConfig> {
    dns.zone = normalize_dns_name(&dns.zone, "namespace.dns.zone")?;
    dns.suffix = normalize_dns_name(&dns.suffix, "namespace.dns.suffix")?;
    if dns.suffix != dns.zone && !dns.suffix.ends_with(&format!(".{}", dns.zone)) {
        anyhow::bail!(
            "namespace.dns.suffix `{}` is not inside zone `{}`",
            dns.suffix,
            dns.zone
        );
    }
    if dns.ttl < 60 {
        anyhow::bail!("namespace.dns.ttl must be at least 60 seconds");
    }
    if dns.cloudflare.api_token.trim().is_empty() {
        anyhow::bail!("namespace.dns.cloudflare.api_token is required");
    }
    dns.cloudflare.api_token = dns.cloudflare.api_token.trim().to_string();
    for (label, binding) in &mut dns.bindings {
        validate_dns_label(label, "namespace.dns.bindings")?;
        validate_network_name(&binding.network)
            .with_context(|| format!("namespace.dns.bindings.{label}.network is invalid"))?;
        if !networks.contains_key(&binding.network) {
            anyhow::bail!(
                "namespace.dns.bindings.{label}.network references unknown network `{}`",
                binding.network
            );
        }
        binding.network = binding.network.trim().to_string();
    }
    for (name, network) in networks {
        let expected = format!("{name}.{}", dns.suffix);
        if network.host_dns_suffix.as_deref() != Some(expected.as_str()) {
            anyhow::bail!(
                "namespace.networks.{name}.host_dns_suffix must be `{expected}` while DNS is configured"
            );
        }
    }
    Ok(dns)
}

fn normalize_dns_name(value: &str, field: &str) -> anyhow::Result<String> {
    let normalized = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 253 {
        anyhow::bail!("{field} is not a valid DNS name");
    }
    for label in normalized.split('.') {
        validate_dns_label(label, field)?;
    }
    Ok(normalized)
}

fn validate_dns_label(label: &str, field: &str) -> anyhow::Result<()> {
    if label.is_empty()
        || label.len() > 63
        || label.starts_with('-')
        || label.ends_with('-')
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        anyhow::bail!("{field} contains invalid DNS label `{label}`");
    }
    Ok(())
}

fn validate_aegis_direct_gateway(
    stored: &NamespaceDefinition,
) -> anyhow::Result<crate::protocol::AegisDirectGatewayConfig> {
    let Some(direct_gateway) = stored.direct_gateway.as_ref() else {
        anyhow::bail!("namespace.direct_gateway is required");
    };
    let interface_name = normalized_text(direct_gateway.interface.as_ref())
        .ok_or_else(|| anyhow::anyhow!("namespace.direct_gateway.interface is required"))?;
    let interfaces = stored.wireguard.as_ref().cloned().unwrap_or_default();
    let interface = interfaces.get(interface_name).ok_or_else(|| {
        anyhow::anyhow!(
            "namespace.direct_gateway.interface references unknown WireGuard interface `{interface_name}`"
        )
    })?;
    let subnet_name = normalized_text(interface.subnet.as_ref()).ok_or_else(|| {
        anyhow::anyhow!("namespace.wireguard.{interface_name}.subnet is required")
    })?;
    let subnets = stored.subnets.as_ref().cloned().unwrap_or_default();
    let subnet = subnets.get(subnet_name).ok_or_else(|| {
        anyhow::anyhow!(
            "namespace.wireguard.{interface_name}.subnet references unknown subnet `{subnet_name}`"
        )
    })?;
    let full_tunnel_dns = direct_gateway
        .full_tunnel_dns
        .iter()
        .map(|address| {
            address
                .trim()
                .parse::<IpAddr>()
                .map(|address| address.to_string())
                .with_context(|| {
                    format!(
                        "namespace.direct_gateway.full_tunnel_dns contains invalid address `{address}`"
                    )
                })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    if !full_tunnel_dns.iter().any(|address| address.contains('.'))
        || !full_tunnel_dns.iter().any(|address| address.contains(':'))
    {
        anyhow::bail!(
            "namespace.direct_gateway.full_tunnel_dns must contain IPv4 and IPv6 addresses"
        );
    }
    Ok(crate::protocol::AegisDirectGatewayConfig {
        interface: interface_name.to_string(),
        endpoint_port: interface.port.filter(|port| *port > 0).ok_or_else(|| {
            anyhow::anyhow!("namespace.wireguard.{interface_name}.port is required")
        })?,
        mtu: interface.mtu.filter(|mtu| *mtu > 0).ok_or_else(|| {
            anyhow::anyhow!("namespace.wireguard.{interface_name}.mtu is required")
        })?,
        fwmark: interface.fwmark.filter(|mark| *mark > 0).ok_or_else(|| {
            anyhow::anyhow!("namespace.wireguard.{interface_name}.fwmark is required")
        })?,
        subnet_ipv4: required_ip_family_field(subnet, "namespace.subnets", subnet_name, "ipv4")?,
        subnet_ipv6: required_ip_family_field(subnet, "namespace.subnets", subnet_name, "ipv6")?,
        full_tunnel_dns,
    })
}

fn validate_aegis_egress(
    stored: &NamespaceDefinition,
    networks: &BTreeMap<String, crate::protocol::AegisNetworkConfig>,
) -> anyhow::Result<crate::protocol::AegisEgressConfig> {
    let egress = stored
        .egress
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("namespace.egress is required"))?;
    let interface_name = normalized_text(egress.interface.as_ref())
        .ok_or_else(|| anyhow::anyhow!("namespace.egress.interface is required"))?;
    let network = normalized_text(egress.network.as_ref())
        .ok_or_else(|| anyhow::anyhow!("namespace.egress.network is required"))?;
    if networks
        .get(network)
        .and_then(|network| network.mesh.as_ref())
        .is_none()
    {
        anyhow::bail!("namespace.egress.network must reference a managed mesh network");
    }
    let interfaces = stored.wireguard.as_ref().cloned().unwrap_or_default();
    let interface = interfaces.get(interface_name).ok_or_else(|| {
        anyhow::anyhow!(
            "namespace.egress.interface references unknown WireGuard interface `{interface_name}`"
        )
    })?;
    let subnet_name = normalized_text(interface.subnet.as_ref()).ok_or_else(|| {
        anyhow::anyhow!("namespace.wireguard.{interface_name}.subnet is required")
    })?;
    let dns_subnet_name = normalized_text(egress.dns_subnet.as_ref())
        .ok_or_else(|| anyhow::anyhow!("namespace.egress.dns_subnet is required"))?;
    let subnets = stored.subnets.as_ref().cloned().unwrap_or_default();
    let subnet = subnets.get(subnet_name).ok_or_else(|| {
        anyhow::anyhow!(
            "namespace.wireguard.{interface_name}.subnet references unknown subnet `{subnet_name}`"
        )
    })?;
    let dns_subnet = subnets.get(dns_subnet_name).ok_or_else(|| {
        anyhow::anyhow!("namespace.egress.dns_subnet references unknown subnet `{dns_subnet_name}`")
    })?;
    Ok(crate::protocol::AegisEgressConfig {
        network: network.to_string(),
        interface: interface_name.to_string(),
        endpoint_port: interface.port.filter(|port| *port > 0).ok_or_else(|| {
            anyhow::anyhow!("namespace.wireguard.{interface_name}.port is required")
        })?,
        mtu: interface.mtu.filter(|mtu| *mtu > 0).ok_or_else(|| {
            anyhow::anyhow!("namespace.wireguard.{interface_name}.mtu is required")
        })?,
        fwmark: egress
            .fwmark
            .filter(|value| *value > 0)
            .ok_or_else(|| anyhow::anyhow!("namespace.egress.fwmark is required"))?,
        routing_table: egress
            .routing_table
            .filter(|value| *value > 0)
            .ok_or_else(|| anyhow::anyhow!("namespace.egress.routing_table is required"))?,
        main_rule_priority: egress
            .main_rule_priority
            .ok_or_else(|| anyhow::anyhow!("namespace.egress.main_rule_priority is required"))?,
        egress_rule_priority: egress
            .egress_rule_priority
            .ok_or_else(|| anyhow::anyhow!("namespace.egress.egress_rule_priority is required"))?,
        subnet_ipv4: required_ip_family_field(subnet, "namespace.subnets", subnet_name, "ipv4")?,
        subnet_ipv6: required_ip_family_field(subnet, "namespace.subnets", subnet_name, "ipv6")?,
        dns_subnet_ipv4: required_ip_family_field(
            dns_subnet,
            "namespace.subnets",
            dns_subnet_name,
            "ipv4",
        )?,
        dns_subnet_ipv6: required_ip_family_field(
            dns_subnet,
            "namespace.subnets",
            dns_subnet_name,
            "ipv6",
        )?,
    })
}

fn validate_aegis_networks(
    stored: &NamespaceDefinition,
) -> anyhow::Result<BTreeMap<String, crate::protocol::AegisNetworkConfig>> {
    let subnets = stored.subnets.as_ref().cloned().unwrap_or_default();
    let interfaces = stored.wireguard.as_ref().cloned().unwrap_or_default();
    let networks = stored
        .networks
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("namespace.networks is required"))?;
    let mut validated = BTreeMap::new();
    for (name, network) in networks {
        validate_network_name(name)?;
        let interface_name = normalized_text(network.interface.as_ref())
            .ok_or_else(|| anyhow::anyhow!("namespace.networks.{name}.interface is required"))?;
        let interface = interfaces.get(interface_name).ok_or_else(|| {
            anyhow::anyhow!(
                "namespace.networks.{name}.interface references unknown WireGuard interface `{interface_name}`"
            )
        })?;
        let wireguard_subnet_name =
            normalized_text(interface.subnet.as_ref()).ok_or_else(|| {
                anyhow::anyhow!("namespace.wireguard.{interface_name}.subnet is required")
            })?;
        let wireguard_subnet = subnets.get(wireguard_subnet_name).ok_or_else(|| {
            anyhow::anyhow!(
                "namespace.wireguard.{interface_name}.subnet references unknown subnet `{wireguard_subnet_name}`"
            )
        })?;
        let endpoint_port = interface.port.filter(|port| *port > 0).ok_or_else(|| {
            anyhow::anyhow!("namespace.wireguard.{interface_name}.port is required")
        })?;
        let mesh = if let Some(mesh_subnet_name) = normalized_text(network.mesh_subnet.as_ref()) {
            if mesh_subnet_name == wireguard_subnet_name {
                anyhow::bail!(
                    "namespace.networks.{name}.mesh_subnet must differ from wireguard_subnet"
                );
            }
            let mesh_subnet = subnets.get(mesh_subnet_name).ok_or_else(|| {
                anyhow::anyhow!(
                    "namespace.networks.{name}.mesh_subnet references unknown subnet `{mesh_subnet_name}`"
                )
            })?;
            Some(crate::protocol::AegisMeshConfig {
                endpoint_port,
                overlay_mtu: network.overlay_mtu.ok_or_else(|| {
                    anyhow::anyhow!("namespace.networks.{name}.overlay_mtu is required")
                })?,
                subnet_ipv4: required_ip_family_field(
                    mesh_subnet,
                    "namespace.subnets",
                    mesh_subnet_name,
                    "ipv4",
                )?,
                subnet_ipv6: required_ip_family_field(
                    mesh_subnet,
                    "namespace.subnets",
                    mesh_subnet_name,
                    "ipv6",
                )?,
                wireguard_subnet_ipv4: required_ip_family_field(
                    wireguard_subnet,
                    "namespace.subnets",
                    wireguard_subnet_name,
                    "ipv4",
                )?,
                wireguard_subnet_ipv6: required_ip_family_field(
                    wireguard_subnet,
                    "namespace.subnets",
                    wireguard_subnet_name,
                    "ipv6",
                )?,
                host_dns_suffix: normalized_text(network.host_dns_suffix.as_ref())
                    .map(str::to_string),
            })
        } else {
            None
        };
        validated.insert(
            name.clone(),
            crate::protocol::AegisNetworkConfig {
                name: name.clone(),
                wireguard: crate::protocol::AegisNetworkWireGuardConfig {
                    interface: interface_name.to_string(),
                    endpoint_port,
                    mtu: interface.mtu.filter(|mtu| *mtu > 0).ok_or_else(|| {
                        anyhow::anyhow!("namespace.wireguard.{interface_name}.mtu is required")
                    })?,
                    fwmark: interface.fwmark.filter(|mark| *mark > 0).ok_or_else(|| {
                        anyhow::anyhow!("namespace.wireguard.{interface_name}.fwmark is required")
                    })?,
                    subnet_ipv4: required_ip_family_field(
                        wireguard_subnet,
                        "namespace.subnets",
                        wireguard_subnet_name,
                        "ipv4",
                    )?,
                    subnet_ipv6: required_ip_family_field(
                        wireguard_subnet,
                        "namespace.subnets",
                        wireguard_subnet_name,
                        "ipv6",
                    )?,
                },
                mesh,
                managed_ssh: network.managed_ssh.unwrap_or(false),
                host_dns_suffix: normalized_text(network.host_dns_suffix.as_ref())
                    .map(str::to_string),
            },
        );
    }
    if validated.is_empty() {
        anyhow::bail!("namespace.networks must not be empty");
    }
    Ok(validated)
}

fn validate_network_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty()
        || name.len() > 63
        || name.starts_with('-')
        || name.ends_with('-')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        anyhow::bail!("invalid Aegis network name `{name}`");
    }
    Ok(())
}

fn required_ip_family_field(
    pair: &StoredAegisIpFamilyPair,
    prefix: &str,
    subnet_name: &str,
    field: &str,
) -> anyhow::Result<String> {
    let value = match field {
        "ipv4" => pair.ipv4.as_ref(),
        "ipv6" => pair.ipv6.as_ref(),
        _ => unreachable!("only IPv4 and IPv6 fields are supported"),
    };
    normalized_text(value)
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("{prefix}.{subnet_name}.{field} is required"))
}

fn normalized_text(value: Option<&String>) -> Option<&str> {
    value.map(|s| s.trim()).filter(|s| !s.is_empty())
}
