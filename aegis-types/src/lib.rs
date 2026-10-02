pub mod configuration;
pub mod identity;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    ops::Deref,
    str::FromStr,
};
use uuid::Uuid;

pub mod namespace;
pub use namespace::{NamespaceId, NamespaceMembership, NamespaceRole};

pub const DEFAULT_AEGIS_NETWORK: &str = "aegis";
pub const DEFAULT_AEGIS_ENROLLMENT_TTL_SECONDS: u64 = 2 * 60 * 60;
pub const MAX_HOST_ALIASES: usize = 8;
pub const HOST_IDENTITY_SCHEMA: &str = "uuid-aliases-v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct HostId(Uuid);

impl HostId {
    pub fn new_v4() -> Self {
        Self(Uuid::new_v4())
    }

    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl fmt::Display for HostId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for HostId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidHostAlias;

impl fmt::Display for InvalidHostAlias {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "host alias must use lowercase ascii letters, digits, '.', '-' or '_', must not be empty, and must not be a UUID",
        )
    }
}

impl std::error::Error for InvalidHostAlias {}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HostAlias(String);

impl HostAlias {
    pub fn parse(value: impl Into<String>) -> Result<Self, InvalidHostAlias> {
        let value = value.into();
        if !value.is_empty()
            && Uuid::parse_str(&value).is_err()
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'-' | b'_')
            })
        {
            Ok(Self(value))
        } else {
            Err(InvalidHostAlias)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HostAlias {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for HostAlias {
    type Err = InvalidHostAlias;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl AsRef<str> for HostAlias {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Serialize for HostAlias {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for HostAlias {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvalidHostAliases {
    Empty,
    TooMany { maximum: usize },
    Duplicate(HostAlias),
    PrimaryRemoval(HostAlias),
}

impl fmt::Display for InvalidHostAliases {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("host aliases must not be empty"),
            Self::TooMany { maximum } => {
                write!(
                    formatter,
                    "host aliases must contain at most {maximum} entries"
                )
            }
            Self::Duplicate(alias) => write!(formatter, "duplicate host alias `{alias}`"),
            Self::PrimaryRemoval(alias) => {
                write!(formatter, "cannot remove primary host alias `{alias}`")
            }
        }
    }
}

impl std::error::Error for InvalidHostAliases {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct HostAliases(Vec<HostAlias>);

impl HostAliases {
    pub fn new(aliases: Vec<HostAlias>) -> Result<Self, InvalidHostAliases> {
        if aliases.is_empty() {
            return Err(InvalidHostAliases::Empty);
        }
        if aliases.len() > MAX_HOST_ALIASES {
            return Err(InvalidHostAliases::TooMany {
                maximum: MAX_HOST_ALIASES,
            });
        }
        let mut unique = BTreeSet::new();
        for alias in &aliases {
            if !unique.insert(alias) {
                return Err(InvalidHostAliases::Duplicate(alias.clone()));
            }
        }
        Ok(Self(aliases))
    }

    pub fn primary(&self) -> &HostAlias {
        self.0
            .first()
            .expect("validated host aliases are non-empty")
    }

    pub fn contains(&self, alias: &HostAlias) -> bool {
        self.0.contains(alias)
    }

    pub fn added(&self, alias: HostAlias) -> Result<Self, InvalidHostAliases> {
        if self.contains(&alias) {
            return Ok(self.clone());
        }
        let mut aliases = self.0.clone();
        aliases.push(alias);
        Self::new(aliases)
    }

    pub fn promoted(&self, alias: &HostAlias) -> Option<Self> {
        let position = self.0.iter().position(|candidate| candidate == alias)?;
        let mut aliases = self.0.clone();
        let alias = aliases.remove(position);
        aliases.insert(0, alias);
        Some(Self(aliases))
    }

    pub fn removed(&self, alias: &HostAlias) -> Result<Option<Self>, InvalidHostAliases> {
        let Some(position) = self.0.iter().position(|candidate| candidate == alias) else {
            return Ok(None);
        };
        if position == 0 {
            return Err(InvalidHostAliases::PrimaryRemoval(alias.clone()));
        }
        let mut aliases = self.0.clone();
        aliases.remove(position);
        Self::new(aliases).map(Some)
    }
}

impl Deref for HostAliases {
    type Target = [HostAlias];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl IntoIterator for HostAliases {
    type Item = HostAlias;
    type IntoIter = std::vec::IntoIter<HostAlias>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a HostAliases {
    type Item = &'a HostAlias;
    type IntoIter = std::slice::Iter<'a, HostAlias>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'de> Deserialize<'de> for HostAliases {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(Vec::<HostAlias>::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

pub mod mtu {
    /// Minimum link MTU required to carry IPv6.
    pub const IPV6_MINIMUM: u16 = 1280;
    /// IPv4, UDP, WireGuard data-message header, and authentication tag.
    pub const WIREGUARD_OVER_IPV4: u16 = 60;
    /// IPv4, UDP, VXLAN, and the inner Ethernet header.
    pub const VXLAN_OVER_IPV4: u16 = 50;
}

pub mod layout {
    pub const DIRECT_SSHD_DROPIN_PATH: &str = "/etc/ssh/sshd_config.d/92-aegis-direct.conf";
    pub const APPLIED_CONFIG_DIRECTORY: &str = "/var/lib/aegis/applied";
    pub const AGENT_CONFIG_PATH: &str = "/etc/aegis/agent.toml";
    pub const AGENT_SYSTEMD_SERVICE_NAME: &str = "aegis-agent.service";
    pub const AGENT_SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/aegis-agent.service";
    pub const DIRECT_STATE_DIRECTORY: &str = "/var/lib/aegis/direct/accounts";
    pub const DIRECT_HOME_DIRECTORY: &str = "/var/lib/aegis/direct/home";
    pub const AUTHORIZED_PRINCIPALS_DIRECTORY: &str = "/etc/ssh/aegis/authorized_principals";
    pub const DIRECT_CLIENT_CA_PATH: &str = "/etc/ssh/aegis/direct-ca.pub";
    pub const DIRECT_LOGIN_GROUP: &str = "aegis-direct";
    pub const EGRESS_NFTABLES_PATH: &str = "/etc/aegis/egress.nft";
    pub const EGRESS_POLICY_SCRIPT_PATH: &str = "/etc/aegis/egress-policy.sh";
    pub const EGRESS_POLICY_SYSTEMD_UNIT_PATH: &str =
        "/etc/systemd/system/aegis-egress-policy.service";
    pub const EGRESS_POLICY_SYSTEMD_SERVICE_NAME: &str = "aegis-egress-policy.service";
    pub const EGRESS_RESOLVED_DROPIN_PATH: &str = "/etc/systemd/resolved.conf.d/aegis-egress.conf";
    pub const APPARMOR_WG_QUICK_AEGIS_RULES_PATH: &str = "/etc/apparmor.d/local/aegis-wg-quick";
    pub const APPARMOR_WG_QUICK_LOCAL_PATH: &str = "/etc/apparmor.d/local/wg-quick";
    pub const APPARMOR_WG_QUICK_PROFILE_PATH: &str = "/etc/apparmor.d/wg-quick";
    pub const STATE_DIRECTORY: &str = "/etc/aegis";
    pub const SYSTEM_BINARY_PATH: &str = "/usr/local/bin/aegis";
    pub const USER_BINARY_RELATIVE_PATH: &str = ".cargo/bin/aegis";
    pub const WIREGUARD_DIRECTORY: &str = "/etc/aegis/wireguard";
    pub const WIREGUARD_SYSTEMD_UNIT_PREFIX: &str = "aegis-wireguard@";
    pub const WIREGUARD_SYSTEMD_UNIT_TEMPLATE_PATH: &str =
        "/etc/systemd/system/aegis-wireguard@.service";
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidSatelliteSlug;

impl fmt::Display for InvalidSatelliteSlug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "satellite slug must use lowercase ascii letters, digits, '.', '-' or '_' and must not be empty",
        )
    }
}

impl std::error::Error for InvalidSatelliteSlug {}

pub fn validate_satellite_slug(slug: &str) -> Result<(), InvalidSatelliteSlug> {
    if !slug.is_empty()
        && slug.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '-' | '_' | '.')
        })
    {
        Ok(())
    } else {
        Err(InvalidSatelliteSlug)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidWireGuardInterfaceName;

impl fmt::Display for InvalidWireGuardInterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "WireGuard interface name must be 1-15 ascii letters, digits, '.', '-' or '_' and must not be '.' or '..'",
        )
    }
}

impl std::error::Error for InvalidWireGuardInterfaceName {}

pub fn validate_wireguard_interface_name(
    interface: &str,
) -> Result<(), InvalidWireGuardInterfaceName> {
    if !interface.is_empty()
        && interface.len() <= 15
        && !matches!(interface, "." | "..")
        && interface.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
        })
    {
        Ok(())
    } else {
        Err(InvalidWireGuardInterfaceName)
    }
}

pub fn managed_wireguard_systemd_unit_contents() -> String {
    format!(
        "[Unit]
Description=aegis WireGuard interface %i
After=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash /usr/bin/wg-quick up {}/%i.conf
ExecStop=/bin/bash /usr/bin/wg-quick down {}/%i.conf

[Install]
WantedBy=multi-user.target
",
        layout::WIREGUARD_DIRECTORY,
        layout::WIREGUARD_DIRECTORY,
    )
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum AegisHostMode {
    Leaf,
    Hub,
}

impl AegisHostMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Leaf => "leaf",
            Self::Hub => "hub",
        }
    }
}

impl fmt::Display for AegisHostMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseAegisHostModeError {
    value: String,
}

impl fmt::Display for ParseAegisHostModeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown host mode `{}`", self.value)
    }
}

impl std::error::Error for ParseAegisHostModeError {}

impl FromStr for AegisHostMode {
    type Err = ParseAegisHostModeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "leaf" => Ok(Self::Leaf),
            "hub" => Ok(Self::Hub),
            _ => Err(ParseAegisHostModeError {
                value: value.to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseWireGuardKeyError;

impl fmt::Display for ParseWireGuardKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("wireguard keys must be base64-encoded 32-byte values")
    }
}

impl std::error::Error for ParseWireGuardKeyError {}

pub fn normalize_wireguard_key(value: &str) -> Result<String, ParseWireGuardKeyError> {
    let trimmed = value.trim();
    if STANDARD
        .decode(trimmed)
        .map(|decoded| decoded.len() == 32)
        .unwrap_or(false)
    {
        Ok(trimmed.to_string())
    } else {
        Err(ParseWireGuardKeyError)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseWireGuardIpv4Error {
    value: String,
}

impl fmt::Display for ParseWireGuardIpv4Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid IPv4 address `{}`", self.value)
    }
}

impl std::error::Error for ParseWireGuardIpv4Error {}

pub fn normalize_wireguard_ipv4(value: &str) -> Result<String, ParseWireGuardIpv4Error> {
    value
        .trim()
        .parse::<Ipv4Addr>()
        .map(|address| address.to_string())
        .map_err(|_| ParseWireGuardIpv4Error {
            value: value.trim().to_string(),
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseWireGuardIpv6Error {
    value: String,
}

impl fmt::Display for ParseWireGuardIpv6Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid IPv6 address `{}`", self.value)
    }
}

impl std::error::Error for ParseWireGuardIpv6Error {}

pub fn normalize_wireguard_ipv6(value: &str) -> Result<String, ParseWireGuardIpv6Error> {
    value
        .trim()
        .parse::<Ipv6Addr>()
        .map(|address| address.to_string())
        .map_err(|_| ParseWireGuardIpv6Error {
            value: value.trim().to_string(),
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireGuardAddressError {
    InvalidSubnetIpv4(String),
    InvalidSubnetIpv6(String),
    InvalidIpv4(String),
    InvalidIpv6(String),
    AddressOutsideSubnet {
        address: String,
        subnet: String,
    },
    AddressHostIdMismatch {
        ipv4: String,
        ipv6: String,
    },
    HostIdOutOfRange {
        host_id: u16,
        subnet_ipv4: String,
        subnet_ipv6: String,
    },
    NoAvailableHostId {
        subnet_ipv4: String,
        subnet_ipv6: String,
    },
}

impl fmt::Display for WireGuardAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSubnetIpv4(subnet) => {
                write!(f, "invalid WireGuard IPv4 subnet `{subnet}`")
            }
            Self::InvalidSubnetIpv6(subnet) => {
                write!(f, "invalid WireGuard IPv6 subnet `{subnet}`")
            }
            Self::InvalidIpv4(address) => write!(f, "invalid WireGuard IPv4 `{address}`"),
            Self::InvalidIpv6(address) => write!(f, "invalid WireGuard IPv6 `{address}`"),
            Self::AddressOutsideSubnet { address, subnet } => {
                write!(f, "WireGuard address `{address}` is outside `{subnet}`")
            }
            Self::AddressHostIdMismatch { ipv4, ipv6 } => {
                write!(
                    f,
                    "WireGuard addresses `{ipv4}` and `{ipv6}` do not encode the same host id"
                )
            }
            Self::HostIdOutOfRange {
                host_id,
                subnet_ipv4,
                subnet_ipv6,
            } => write!(
                f,
                "WireGuard host id `{host_id}` is outside `{subnet_ipv4}` / `{subnet_ipv6}`"
            ),
            Self::NoAvailableHostId {
                subnet_ipv4,
                subnet_ipv6,
            } => write!(
                f,
                "no WireGuard addresses remain available in `{subnet_ipv4}` / `{subnet_ipv6}`"
            ),
        }
    }
}

impl std::error::Error for WireGuardAddressError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireGuardHostIdentity {
    Peer(u16),
}

pub fn wireguard_host_id_from_addresses(
    pool: &v1::AegisWireGuardAddressPool,
    wireguard_ipv4: &str,
    wireguard_ipv6: &str,
) -> Result<u16, WireGuardAddressError> {
    wireguard_host_id_from_addresses_in_subnets(
        &pool.subnet_ipv4,
        &pool.subnet_ipv6,
        wireguard_ipv4,
        wireguard_ipv6,
    )
}

pub fn wireguard_host_identity_from_addresses(
    pool: &v1::AegisWireGuardAddressPool,
    wireguard_ipv4: &str,
    wireguard_ipv6: &str,
) -> Result<WireGuardHostIdentity, WireGuardAddressError> {
    let wireguard_ipv4 = normalize_wireguard_ipv4(wireguard_ipv4)
        .map_err(|error| WireGuardAddressError::InvalidIpv4(error.value))?;
    let wireguard_ipv6 = normalize_wireguard_ipv6(wireguard_ipv6)
        .map_err(|error| WireGuardAddressError::InvalidIpv6(error.value))?;
    wireguard_host_id_from_addresses(pool, &wireguard_ipv4, &wireguard_ipv6)
        .map(WireGuardHostIdentity::Peer)
}

pub fn allocate_lowest_free_wireguard_host_id<'a>(
    pool: &v1::AegisWireGuardAddressPool,
    used: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<u16, WireGuardAddressError> {
    allocate_lowest_free_host_id(&pool.subnet_ipv4, &pool.subnet_ipv6, used)
}

pub fn validate_wireguard_address_pool(
    pool: &v1::AegisWireGuardAddressPool,
) -> Result<(), WireGuardAddressError> {
    max_wireguard_host_id(&pool.subnet_ipv4, &pool.subnet_ipv6).map(|_| ())
}

pub fn wireguard_address_pools_overlap(
    left: &v1::AegisWireGuardAddressPool,
    right: &v1::AegisWireGuardAddressPool,
) -> Result<bool, WireGuardAddressError> {
    validate_wireguard_address_pool(left)?;
    validate_wireguard_address_pool(right)?;
    let (left_ipv4, left_ipv4_prefix) = parse_ipv4_cidr(&left.subnet_ipv4)?;
    let (right_ipv4, right_ipv4_prefix) = parse_ipv4_cidr(&right.subnet_ipv4)?;
    let ipv4_prefix = left_ipv4_prefix.min(right_ipv4_prefix);
    let ipv4_mask = ipv4_mask(ipv4_prefix);
    let ipv4_overlap = u32::from(left_ipv4) & ipv4_mask == u32::from(right_ipv4) & ipv4_mask;

    let (left_ipv6, left_ipv6_prefix) = parse_ipv6_cidr(&left.subnet_ipv6)?;
    let (right_ipv6, right_ipv6_prefix) = parse_ipv6_cidr(&right.subnet_ipv6)?;
    let ipv6_prefix = left_ipv6_prefix.min(right_ipv6_prefix);
    let ipv6_mask = ipv6_mask(ipv6_prefix);
    let ipv6_overlap = u128::from(left_ipv6) & ipv6_mask == u128::from(right_ipv6) & ipv6_mask;
    Ok(ipv4_overlap || ipv6_overlap)
}

pub fn wireguard_ipv4_for_host_id(
    pool: &v1::AegisWireGuardAddressPool,
    host_id: u16,
) -> Result<String, WireGuardAddressError> {
    wireguard_ipv4_for_host_id_in_subnet(&pool.subnet_ipv4, &pool.subnet_ipv6, host_id)
}

pub fn wireguard_ipv6_for_host_id(
    pool: &v1::AegisWireGuardAddressPool,
    host_id: u16,
) -> Result<String, WireGuardAddressError> {
    wireguard_ipv6_for_host_id_in_subnet(&pool.subnet_ipv4, &pool.subnet_ipv6, host_id)
}

fn wireguard_host_id_from_addresses_in_subnets(
    subnet_ipv4: &str,
    subnet_ipv6: &str,
    wireguard_ipv4: &str,
    wireguard_ipv6: &str,
) -> Result<u16, WireGuardAddressError> {
    let ipv4_host_id = wireguard_host_id_from_ipv4(subnet_ipv4, wireguard_ipv4)?;
    let ipv6_host_id = wireguard_host_id_from_ipv6(subnet_ipv6, wireguard_ipv6)?;
    if ipv4_host_id != ipv6_host_id {
        return Err(WireGuardAddressError::AddressHostIdMismatch {
            ipv4: wireguard_ipv4.to_string(),
            ipv6: wireguard_ipv6.to_string(),
        });
    }
    Ok(ipv4_host_id)
}

fn allocate_lowest_free_host_id<'a>(
    subnet_ipv4: &str,
    subnet_ipv6: &str,
    used: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<u16, WireGuardAddressError> {
    let mut used_host_ids = std::collections::BTreeSet::new();
    for (wireguard_ipv4, wireguard_ipv6) in used {
        used_host_ids.insert(wireguard_host_id_from_addresses_in_subnets(
            subnet_ipv4,
            subnet_ipv6,
            wireguard_ipv4,
            wireguard_ipv6,
        )?);
    }

    let max_host_id = max_wireguard_host_id(subnet_ipv4, subnet_ipv6)?;
    for host_id in 1..=max_host_id {
        if !used_host_ids.contains(&host_id) {
            return Ok(host_id);
        }
    }

    Err(WireGuardAddressError::NoAvailableHostId {
        subnet_ipv4: subnet_ipv4.to_string(),
        subnet_ipv6: subnet_ipv6.to_string(),
    })
}

fn wireguard_ipv4_for_host_id_in_subnet(
    subnet_ipv4: &str,
    subnet_ipv6: &str,
    host_id: u16,
) -> Result<String, WireGuardAddressError> {
    let _ = max_wireguard_host_id(subnet_ipv4, subnet_ipv6)?;
    let (base, prefix) = parse_ipv4_cidr(subnet_ipv4)?;
    let capacity = subnet_host_capacity_ipv4(prefix);
    if host_id == 0 || u128::from(host_id) > capacity {
        return Err(WireGuardAddressError::HostIdOutOfRange {
            host_id,
            subnet_ipv4: subnet_ipv4.to_string(),
            subnet_ipv6: subnet_ipv6.to_string(),
        });
    }

    let network = u32::from(base) & ipv4_mask(prefix);
    Ok(Ipv4Addr::from(network + u32::from(host_id)).to_string())
}

fn wireguard_ipv6_for_host_id_in_subnet(
    subnet_ipv4: &str,
    subnet_ipv6: &str,
    host_id: u16,
) -> Result<String, WireGuardAddressError> {
    let _ = max_wireguard_host_id(subnet_ipv4, subnet_ipv6)?;
    let (base, prefix) = parse_ipv6_cidr(subnet_ipv6)?;
    let capacity = subnet_host_capacity_ipv6(prefix);
    if host_id == 0 || u128::from(host_id) > capacity {
        return Err(WireGuardAddressError::HostIdOutOfRange {
            host_id,
            subnet_ipv4: subnet_ipv4.to_string(),
            subnet_ipv6: subnet_ipv6.to_string(),
        });
    }

    let network = u128::from(base) & ipv6_mask(prefix);
    Ok(Ipv6Addr::from(network + u128::from(host_id)).to_string())
}

fn wireguard_host_id_from_ipv4(
    subnet_ipv4: &str,
    wireguard_ipv4: &str,
) -> Result<u16, WireGuardAddressError> {
    let address = wireguard_ipv4
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|_| WireGuardAddressError::InvalidIpv4(wireguard_ipv4.trim().to_string()))?;
    let (base, prefix) = parse_ipv4_cidr(subnet_ipv4)?;
    let mask = ipv4_mask(prefix);
    let address_u32 = u32::from(address);
    let network = u32::from(base) & mask;
    if (address_u32 & mask) != network {
        return Err(WireGuardAddressError::AddressOutsideSubnet {
            address: address.to_string(),
            subnet: subnet_ipv4.to_string(),
        });
    }
    let host_id = address_u32 - network;
    if host_id == 0 || host_id > u32::from(u16::MAX) {
        return Err(WireGuardAddressError::AddressOutsideSubnet {
            address: address.to_string(),
            subnet: subnet_ipv4.to_string(),
        });
    }
    Ok(host_id as u16)
}

fn wireguard_host_id_from_ipv6(
    subnet_ipv6: &str,
    wireguard_ipv6: &str,
) -> Result<u16, WireGuardAddressError> {
    let address = wireguard_ipv6
        .trim()
        .parse::<Ipv6Addr>()
        .map_err(|_| WireGuardAddressError::InvalidIpv6(wireguard_ipv6.trim().to_string()))?;
    let (base, prefix) = parse_ipv6_cidr(subnet_ipv6)?;
    let mask = ipv6_mask(prefix);
    let address_u128 = u128::from(address);
    let network = u128::from(base) & mask;
    if (address_u128 & mask) != network {
        return Err(WireGuardAddressError::AddressOutsideSubnet {
            address: address.to_string(),
            subnet: subnet_ipv6.to_string(),
        });
    }
    let host_id = address_u128 - network;
    if host_id == 0 || host_id > u128::from(u16::MAX) {
        return Err(WireGuardAddressError::AddressOutsideSubnet {
            address: address.to_string(),
            subnet: subnet_ipv6.to_string(),
        });
    }
    Ok(host_id as u16)
}

fn max_wireguard_host_id(
    subnet_ipv4: &str,
    subnet_ipv6: &str,
) -> Result<u16, WireGuardAddressError> {
    let (_, prefix_ipv4) = parse_ipv4_cidr(subnet_ipv4)?;
    let (_, prefix_ipv6) = parse_ipv6_cidr(subnet_ipv6)?;
    let max_host_id = subnet_host_capacity_ipv4(prefix_ipv4)
        .min(subnet_host_capacity_ipv6(prefix_ipv6))
        .min(u128::from(u16::MAX));
    if max_host_id == 0 {
        return Err(WireGuardAddressError::NoAvailableHostId {
            subnet_ipv4: subnet_ipv4.to_string(),
            subnet_ipv6: subnet_ipv6.to_string(),
        });
    }
    Ok(max_host_id as u16)
}

fn parse_ipv4_cidr(cidr: &str) -> Result<(Ipv4Addr, u8), WireGuardAddressError> {
    let (address, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| WireGuardAddressError::InvalidSubnetIpv4(cidr.to_string()))?;
    let address = address
        .parse::<Ipv4Addr>()
        .map_err(|_| WireGuardAddressError::InvalidSubnetIpv4(cidr.to_string()))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| WireGuardAddressError::InvalidSubnetIpv4(cidr.to_string()))?;
    if prefix > 32 {
        return Err(WireGuardAddressError::InvalidSubnetIpv4(cidr.to_string()));
    }
    Ok((address, prefix))
}

fn parse_ipv6_cidr(cidr: &str) -> Result<(Ipv6Addr, u8), WireGuardAddressError> {
    let (address, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| WireGuardAddressError::InvalidSubnetIpv6(cidr.to_string()))?;
    let address = address
        .parse::<Ipv6Addr>()
        .map_err(|_| WireGuardAddressError::InvalidSubnetIpv6(cidr.to_string()))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| WireGuardAddressError::InvalidSubnetIpv6(cidr.to_string()))?;
    if prefix > 128 {
        return Err(WireGuardAddressError::InvalidSubnetIpv6(cidr.to_string()));
    }
    Ok((address, prefix))
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    }
}

fn subnet_host_capacity_ipv4(prefix: u8) -> u128 {
    if prefix == 32 {
        0
    } else {
        (1u128 << (32 - u32::from(prefix))) - 1
    }
}

fn subnet_host_capacity_ipv6(prefix: u8) -> u128 {
    if prefix == 128 {
        0
    } else if prefix <= 112 {
        u128::from(u16::MAX)
    } else {
        (1u128 << (128 - u32::from(prefix))) - 1
    }
}

pub mod path {
    pub const AEGIS_NETWORKS: &str = "/aegis/networks";
    pub const AEGIS_NETWORK: &str = "/aegis/networks/{network}";
    pub const AEGIS_NETWORK_MEMBERS: &str = "/aegis/networks/{network}/members";
    pub const AEGIS_NETWORK_MEMBER: &str = "/aegis/networks/{network}/members/{host_id}";
    pub const AEGIS_NETWORK_MEMBER_CLIENT_CERT: &str =
        "/aegis/networks/{network}/members/{host_id}/client-cert";
    pub const AEGIS_NETWORK_MEMBER_SERVER_CERT: &str =
        "/aegis/networks/{network}/members/{host_id}/server-cert";
    pub const AEGIS_DIRECT_GATEWAY: &str = "/aegis/direct-gateways/{host_id}";
    pub const AEGIS_DIRECT_GATEWAY_INVENTORY: &str = "/aegis/direct-gateways/{host_id}/inventory";
    pub const AEGIS_EGRESS: &str = "/aegis/egress/{host_id}";
    pub const AEGIS_EGRESS_INVENTORY: &str = "/aegis/egress";
    pub const AEGIS_EGRESS_RESULT: &str = "/aegis/egress/{host_id}/result";
    pub const AEGIS_SATELLITES: &str = "/aegis/satellites";
    pub const AEGIS_SATELLITE: &str = "/aegis/satellites/{slug}";
    pub const AEGIS_SATELLITE_TARGETS: &str = "/aegis/satellites/{slug}/targets";
    pub const AEGIS_SATELLITE_CLIENT_CERT: &str = "/aegis/satellites/{slug}/client-cert";
    pub const AEGIS_DNS_SYNC: &str = "/aegis/dns/sync";
    pub const AEGIS_TLS_SYNC: &str = "/aegis/tls/sync";
    pub const AEGIS_TLS_ROOT_CA: &str = "/aegis/tls/cas/root.pem";
    pub const AEGIS_TLS_ISSUING_CA: &str = "/aegis/tls/cas/issuing.pem";
    pub const AEGIS_TLS_ISSUING_CRL: &str = "/aegis/tls/cas/issuing.crl";
    pub const AEGIS_TLS_CERT: &str = "/aegis/tls/certs/{label}/cert.pem";
    pub const AEGIS_TLS_CERT_PUBLIC_KEY: &str = "/aegis/tls/certs/{label}/public-key.pem";
    pub const AEGIS_HOSTS: &str = "/aegis/hosts";
    pub const AEGIS_HOST: &str = "/aegis/hosts/{host_id}";
    pub const AEGIS_HOST_REPORT: &str = "/aegis/hosts/{host_id}/report";
    pub const AEGIS_HOST_EGRESS: &str = "/aegis/hosts/{host_id}/egress";
    pub const AEGIS_HOST_ALIAS: &str = "/aegis/hosts/{host_id}/aliases/{alias}";
    pub const AEGIS_HOST_ALIAS_PROMOTE: &str = "/aegis/hosts/{host_id}/aliases/{alias}/promote";
    pub const AEGIS_ALIAS: &str = "/aegis/aliases/{alias}";
    pub const AEGIS_AGENT_TOKEN: &str = "/aegis/agent/token";
    pub const AEGIS_USER_SSH_CA: &str = "/aegis/ssh/ca/user";
    pub const AEGIS_HOST_SSH_CA: &str = "/aegis/ssh/ca/host";
    pub const AEGIS_HOST_AGENT_TOKEN: &str = "/aegis/hosts/{host_id}/agent-token";
    pub const AEGIS_ENROLLMENTS: &str = "/aegis/enrollments";
    pub const AEGIS_ENROLLMENT: &str = "/aegis/enrollments/{host_id}";
    pub const AEGIS_ENROLLMENT_CREDENTIAL: &str = "/aegis/enrollments/{host_id}/credential";
    pub const AEGIS_ENROLLMENT_PREPARE: &str = "/aegis/enrollments/{host_id}/prepare";
    pub const AEGIS_ENROLLMENT_HEARTBEAT: &str = "/aegis/enrollments/{host_id}/heartbeat";
    pub const AEGIS_ENROLLMENT_ACTIVATE: &str = "/aegis/enrollments/{host_id}/activate";
    pub const PHONE_TWILIO_CALL: &str = "/phone/twilio/call";
    pub const PHONE_TWILIO_SMS: &str = "/phone/twilio/sms";

    pub fn aegis_host(host_id: &crate::HostId) -> String {
        format!("/aegis/hosts/{host_id}")
    }

    pub fn aegis_host_report(host_id: &crate::HostId) -> String {
        format!("/aegis/hosts/{host_id}/report")
    }

    pub fn aegis_network(network: &str) -> String {
        format!("/aegis/networks/{network}")
    }

    pub fn aegis_network_members(network: &str) -> String {
        format!("/aegis/networks/{network}/members")
    }

    pub fn aegis_network_member(network: &str, host_id: &crate::HostId) -> String {
        format!("/aegis/networks/{network}/members/{host_id}")
    }

    pub fn aegis_network_member_client_cert(network: &str, host_id: &crate::HostId) -> String {
        format!("/aegis/networks/{network}/members/{host_id}/client-cert")
    }

    pub fn aegis_network_member_server_cert(network: &str, host_id: &crate::HostId) -> String {
        format!("/aegis/networks/{network}/members/{host_id}/server-cert")
    }

    pub fn aegis_direct_gateway(host_id: &crate::HostId) -> String {
        format!("/aegis/direct-gateways/{host_id}")
    }

    pub fn aegis_direct_gateway_inventory(host_id: &crate::HostId) -> String {
        format!("/aegis/direct-gateways/{host_id}/inventory")
    }

    pub fn aegis_egress(host_id: &crate::HostId) -> String {
        format!("/aegis/egress/{host_id}")
    }

    pub fn aegis_egress_result(host_id: &crate::HostId) -> String {
        format!("/aegis/egress/{host_id}/result")
    }

    pub fn aegis_satellite(slug: &str) -> String {
        format!("/aegis/satellites/{slug}")
    }

    pub fn aegis_satellite_targets(slug: &str) -> String {
        format!("/aegis/satellites/{slug}/targets")
    }

    pub fn aegis_satellite_client_cert(slug: &str) -> String {
        format!("/aegis/satellites/{slug}/client-cert")
    }

    pub fn aegis_host_agent_token(host_id: &crate::HostId) -> String {
        format!("/aegis/hosts/{host_id}/agent-token")
    }

    pub fn aegis_enrollment(host_id: &crate::HostId) -> String {
        format!("/aegis/enrollments/{host_id}")
    }

    pub fn aegis_enrollment_credential(host_id: &crate::HostId) -> String {
        format!("/aegis/enrollments/{host_id}/credential")
    }

    pub fn aegis_enrollment_prepare(host_id: &crate::HostId) -> String {
        format!("/aegis/enrollments/{host_id}/prepare")
    }

    pub fn aegis_enrollment_heartbeat(host_id: &crate::HostId) -> String {
        format!("/aegis/enrollments/{host_id}/heartbeat")
    }

    pub fn aegis_enrollment_activate(host_id: &crate::HostId) -> String {
        format!("/aegis/enrollments/{host_id}/activate")
    }

    pub fn aegis_host_egress(host_id: &crate::HostId) -> String {
        format!("/aegis/hosts/{host_id}/egress")
    }

    pub fn aegis_host_alias(host_id: &crate::HostId, alias: &crate::HostAlias) -> String {
        format!("/aegis/hosts/{host_id}/aliases/{alias}")
    }

    pub fn aegis_host_alias_promote(host_id: &crate::HostId, alias: &crate::HostAlias) -> String {
        format!("/aegis/hosts/{host_id}/aliases/{alias}/promote")
    }

    pub fn aegis_alias(alias: &crate::HostAlias) -> String {
        format!("/aegis/aliases/{alias}")
    }

    pub fn aegis_tls_cert(label: &str) -> String {
        format!("/aegis/tls/certs/{label}/cert.pem")
    }

    pub fn aegis_tls_cert_public_key(label: &str) -> String {
        format!("/aegis/tls/certs/{label}/public-key.pem")
    }
}

pub fn sshd_install_dropin_contents(
    trusted_user_ca_path: &str,
    authorized_principals_path: &str,
    host_key_path: Option<&str>,
    host_cert_path: Option<&str>,
) -> String {
    let mut content =
        String::from("# Managed by aegis. Enables SSH user certificate authentication.\n");
    content.push_str("PubkeyAuthentication yes\n");
    content.push_str("AllowAgentForwarding yes\n");
    content.push_str(&format!("TrustedUserCAKeys {trusted_user_ca_path}\n"));
    content.push_str(&format!(
        "AuthorizedPrincipalsFile {authorized_principals_path}\n"
    ));
    if let (Some(host_key_path), Some(host_cert_path)) = (host_key_path, host_cert_path) {
        content.push_str(&format!("HostKey {host_key_path}\n"));
        content.push_str(&format!("HostCertificate {host_cert_path}\n"));
    }
    content
}

pub mod v1 {
    use crate::{AegisHostMode, HostAlias, HostAliases, HostId};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    pub struct AegisMeshConfig {
        pub endpoint_port: u16,
        pub overlay_mtu: u16,
        pub subnet_ipv4: String,
        pub subnet_ipv6: String,
        pub wireguard_subnet_ipv4: String,
        pub wireguard_subnet_ipv6: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub host_dns_suffix: Option<String>,
    }

    impl AegisMeshConfig {
        pub fn wireguard_address_pool(&self) -> AegisWireGuardAddressPool {
            AegisWireGuardAddressPool {
                subnet_ipv4: self.wireguard_subnet_ipv4.clone(),
                subnet_ipv6: self.wireguard_subnet_ipv6.clone(),
            }
        }
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    pub struct AegisWireGuardAddressPool {
        pub subnet_ipv4: String,
        pub subnet_ipv6: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    pub struct AegisNetworkWireGuardConfig {
        pub interface: String,
        pub endpoint_port: u16,
        pub mtu: u16,
        pub fwmark: u32,
        pub subnet_ipv4: String,
        pub subnet_ipv6: String,
    }

    impl AegisNetworkWireGuardConfig {
        pub fn address_pool(&self) -> AegisWireGuardAddressPool {
            AegisWireGuardAddressPool {
                subnet_ipv4: self.subnet_ipv4.clone(),
                subnet_ipv6: self.subnet_ipv6.clone(),
            }
        }
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    pub struct AegisNetworkConfig {
        pub name: String,
        pub wireguard: AegisNetworkWireGuardConfig,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mesh: Option<AegisMeshConfig>,
        #[serde(default)]
        pub managed_ssh: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub host_dns_suffix: Option<String>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisEgressConfig {
        pub network: String,
        pub interface: String,
        pub endpoint_port: u16,
        pub mtu: u16,
        pub fwmark: u32,
        pub routing_table: u32,
        pub main_rule_priority: u32,
        pub egress_rule_priority: u32,
        pub subnet_ipv4: String,
        pub subnet_ipv6: String,
        pub dns_subnet_ipv4: String,
        pub dns_subnet_ipv6: String,
    }

    impl AegisEgressConfig {
        pub fn address_pool(&self) -> AegisWireGuardAddressPool {
            AegisWireGuardAddressPool {
                subnet_ipv4: self.subnet_ipv4.clone(),
                subnet_ipv6: self.subnet_ipv6.clone(),
            }
        }

        pub fn dns_address_pool(&self) -> AegisWireGuardAddressPool {
            AegisWireGuardAddressPool {
                subnet_ipv4: self.dns_subnet_ipv4.clone(),
                subnet_ipv6: self.dns_subnet_ipv6.clone(),
            }
        }
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisHostEgress {
        pub public_key: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisEgressHost {
        pub host_id: HostId,
        pub aliases: HostAliases,
        pub public_key: String,
        pub ipv4: String,
        pub ipv6: String,
        pub internal_ipv4: String,
        pub internal_ipv6: String,
        pub dns_ipv4: String,
        pub dns_ipv6: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisEgressPolicy {
        pub source_host_id: HostId,
        pub revision: u64,
        pub active_via: Option<HostId>,
        pub desired_via: Option<HostId>,
        pub updated_unix: i64,
        pub updated_by_principal: String,
    }

    impl AegisEgressPolicy {
        pub fn is_steady(&self) -> bool {
            self.active_via == self.desired_via
        }
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisEgressStatus {
        pub source_host_id: HostId,
        pub aliases: HostAliases,
        pub config: AegisEgressConfig,
        pub policy: Option<AegisEgressPolicy>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisEgressInventory {
        pub config: AegisEgressConfig,
        pub hosts: BTreeMap<HostId, AegisEgressHost>,
        pub policies: BTreeMap<HostId, AegisEgressPolicy>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct AegisEgressEnableRequest {
        pub via: HostId,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct AegisEgressIdentityRequest {
        pub public_key: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct AegisEgressResult {
        pub revision: u64,
        pub outcome: AegisEgressOutcome,
    }

    #[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(rename_all = "kebab-case")]
    pub enum AegisEgressOutcome {
        Applied,
        Rejected,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisDirectGatewayConfig {
        pub interface: String,
        pub endpoint_port: u16,
        pub mtu: u16,
        pub fwmark: u32,
        pub subnet_ipv4: String,
        pub subnet_ipv6: String,
        pub full_tunnel_dns: Vec<String>,
    }

    impl AegisDirectGatewayConfig {
        pub fn address_pool(&self) -> AegisWireGuardAddressPool {
            AegisWireGuardAddressPool {
                subnet_ipv4: self.subnet_ipv4.clone(),
                subnet_ipv6: self.subnet_ipv6.clone(),
            }
        }
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisDirectWireGuard {
        pub public_key: String,
        pub ipv4: String,
        pub ipv6: String,
        #[serde(default)]
        pub endpoints: Vec<String>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisDirectGateway {
        pub host_id: HostId,
        pub aliases: HostAliases,
        pub wireguard: AegisDirectWireGuard,
        pub updated_unix: i64,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct AegisDirectGatewayPublishRequest {
        pub public_key: String,
        pub endpoints: Vec<String>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisDirectPeerObservation {
        pub public_key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub latest_handshake_unix: Option<i64>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisDirectGatewayReport {
        pub observed_unix: i64,
        pub peers: Vec<AegisDirectPeerObservation>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisDirectSatellite {
        pub slug: String,
        pub account: String,
        pub ssh_principal: String,
        pub wireguard: AegisDirectWireGuard,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisDirectGatewayInventory {
        pub config: AegisDirectGatewayConfig,
        pub enabled: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub published: Option<AegisDirectGateway>,
        pub direct_client_ca_public_key: String,
        pub satellites: Vec<AegisDirectSatellite>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisSatellite {
        pub slug: String,
        pub account: String,
        pub owner_principal: String,
        pub wireguard: AegisDirectWireGuard,
        pub created_unix: i64,
        pub created_by_principal: String,
        pub status: AegisSatelliteStatus,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisSatelliteGatewayStatus {
        pub aliases: HostAliases,
        pub installed: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub observed_unix: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub latest_handshake_unix: Option<i64>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisSatelliteBrokerUse {
        pub used_unix: i64,
        pub gateway_host_id: HostId,
        pub gateway_aliases: HostAliases,
        pub target_host_id: HostId,
        pub target_aliases: HostAliases,
    }

    #[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisSatelliteStatus {
        pub gateways: BTreeMap<HostId, AegisSatelliteGatewayStatus>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub last_broker_use: Option<AegisSatelliteBrokerUse>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct AegisSatelliteCreateRequest {
        pub wireguard_public_key: String,
        pub ssh_public_key: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisSatelliteListResponse {
        pub satellites: BTreeMap<String, AegisSatellite>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisSatelliteDetailsResponse {
        pub satellite: AegisSatellite,
        pub config: AegisDirectGatewayConfig,
        pub gateways: BTreeMap<HostId, AegisDirectGateway>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct AegisSatelliteProvisionResponse {
        pub satellite: AegisSatellite,
        pub config: AegisDirectGatewayConfig,
        pub gateways: BTreeMap<HostId, AegisDirectGateway>,
        pub ssh_certificate: String,
        pub server_ca_public_key: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisDirectTarget {
        pub host_id: HostId,
        pub aliases: HostAliases,
        pub mode: AegisHostMode,
        pub ssh_port: u16,
        pub wireguard_ipv4: String,
        pub wireguard_ipv6: String,
        pub login_principals: Vec<String>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisDirectTargetListResponse {
        pub targets: Vec<AegisDirectTarget>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct AegisDirectClientCertRequest {
        pub target_host_id: HostId,
        pub login_principal: String,
        pub ed25519_public_key: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct AegisDirectClientCertResponse {
        pub target: AegisDirectTarget,
        pub login_principal: String,
        pub certificate: String,
        pub server_ca_public_key: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    pub struct AegisNetworkListResponse {
        pub networks: BTreeMap<String, AegisNetworkConfig>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    pub struct AegisNetworkResponse {
        pub network: AegisNetworkConfig,
    }

    #[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum AegisEnrollmentPhase {
        AwaitingMachine,
        PreparingMachine,
        Prepared,
        InstallingAgent,
        Activating,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisEnrollmentSsh {
        #[serde(default = "default_ssh_port", skip_serializing_if = "Option::is_none")]
        pub port: Option<u16>,
        #[serde(default)]
        pub external_principals: Vec<String>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisEnrollmentCreateRequest {
        pub aliases: HostAliases,
        pub network: String,
        pub mode: AegisHostMode,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ssh: Option<AegisEnrollmentSsh>,
        #[serde(default)]
        pub transient: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub initial_oauth_principal: Option<String>,
        #[serde(default = "default_enrollment_ttl_seconds")]
        pub ttl_seconds: u64,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisEnrollment {
        pub host_id: HostId,
        pub aliases: HostAliases,
        pub network: String,
        pub mode: AegisHostMode,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ssh: Option<AegisEnrollmentSsh>,
        pub transient: bool,
        pub initial_oauth_principal: String,
        pub phase: AegisEnrollmentPhase,
        pub credential_issued: bool,
        pub created_unix: i64,
        pub expires_unix: i64,
        pub updated_unix: i64,
        pub created_by_principal: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisEnrollmentListResponse {
        pub enrollments: BTreeMap<HostId, AegisEnrollment>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisEnrollmentCredentialResponse {
        pub api_base: String,
        pub enrollment: AegisEnrollment,
        pub refresh_token: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisEnrollmentPrepareRequest {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub host_public_key: Option<String>,
        pub wireguard_public_key: String,
        #[serde(default)]
        pub wireguard_endpoints: Vec<String>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisEnrollmentPrepareResponse {
        pub enrollment: AegisEnrollment,
        pub host: AegisHost,
        pub member: AegisNetworkMemberResponse,
        pub network: AegisNetworkConfig,
        pub active_hosts: AegisHostListResponse,
        pub active_members: AegisNetworkMemberListResponse,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub server_certificate: Option<String>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisEnrollmentHeartbeatRequest {
        pub phase: AegisEnrollmentPhase,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisEnrollmentActivateResponse {
        pub host: AegisHost,
        pub member: AegisNetworkMemberResponse,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AgentTokenIssueResponse {
        pub host_id: HostId,
        pub aliases: HostAliases,
        pub created_by_principal: String,
        pub refresh_token: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AgentTokenRevokeRequest {
        pub refresh_token: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisDnsCloudflareConfig {
        pub api_token: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisDnsBinding {
        pub host_id: HostId,
        pub network: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisDnsConfig {
        pub zone: String,
        pub suffix: String,
        pub ttl: u32,
        pub cloudflare: AegisDnsCloudflareConfig,
        #[serde(default)]
        pub bindings: BTreeMap<String, AegisDnsBinding>,
    }

    #[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(rename_all = "lowercase")]
    pub enum AegisSyncAction {
        Create,
        Update,
        Delete,
    }

    #[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
    pub enum AegisDnsRecordKind {
        A,
        AAAA,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisDnsChange {
        pub action: AegisSyncAction,
        pub kind: AegisDnsRecordKind,
        pub name: String,
        pub content: String,
    }

    #[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisDnsSyncRequest {
        #[serde(default)]
        pub dry_run: bool,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisDnsSyncResponse {
        pub dry_run: bool,
        pub desired: usize,
        pub created: usize,
        pub updated: usize,
        pub deleted: usize,
        pub changes: Vec<AegisDnsChange>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisTlsCertificateConfig {
        pub label: String,
        pub host_id: HostId,
        pub dns_names: Vec<String>,
    }

    #[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisTlsDesiredState {
        #[serde(default)]
        pub certificates: Vec<AegisTlsCertificateConfig>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisTlsSyncRequest {
        pub desired: AegisTlsDesiredState,
        #[serde(default)]
        pub dry_run: bool,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisTlsChange {
        pub action: AegisSyncAction,
        pub label: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisTlsSyncResponse {
        pub dry_run: bool,
        pub desired: usize,
        pub created: usize,
        pub updated: usize,
        pub deleted: usize,
        pub changes: Vec<AegisTlsChange>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    pub struct AgentTokenRequest {
        pub grant_type: String,
        pub refresh_token: String,
    }

    #[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum AegisCredentialKind {
        Enrollment,
        Agent,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    pub struct AgentTokenResponse {
        pub access_token: String,
        pub token_type: String,
        pub expires_in: u64,
        pub host_id: HostId,
        pub credential_kind: AegisCredentialKind,
        pub refresh_token: String,
        pub refresh_expires_in: u64,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct SshIssueCertResponse {
        /// OpenSSH certificate line (e.g. "ssh-ed25519-cert-v01@openssh.com AAAA...").
        pub certificate: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    pub struct SshCaPublicKeyResponse {
        pub public_key: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisHostSsh {
        #[serde(default = "default_ssh_port", skip_serializing_if = "Option::is_none")]
        pub port: Option<u16>,
        #[serde(default)]
        pub public_key: Option<String>,
        #[serde(default)]
        pub external_principals: Vec<String>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisNetworkHostSsh {
        #[serde(default = "default_ssh_port", skip_serializing_if = "Option::is_none")]
        pub port: Option<u16>,
        #[serde(default)]
        pub public_key: Option<String>,
        #[serde(default)]
        pub internal_principals: Vec<String>,
        #[serde(default)]
        pub external_principals: Vec<String>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisNetworkMemberWireGuard {
        pub public_key: String,
        pub ipv4: String,
        pub ipv6: String,
        #[serde(default)]
        pub endpoints: Vec<String>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisObservedPublicIp {
        pub ip: String,
        pub observed_unix: i64,
    }

    #[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisObservedPublicIps {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ipv4: Option<AegisObservedPublicIp>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ipv6: Option<AegisObservedPublicIp>,
    }

    impl AegisObservedPublicIps {
        pub fn is_empty(&self) -> bool {
            self.ipv4.is_none() && self.ipv6.is_none()
        }
    }

    #[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(rename_all = "lowercase")]
    pub enum AegisHostMessageLevel {
        Warning,
        Error,
    }

    impl AegisHostMessageLevel {
        pub const fn as_str(self) -> &'static str {
            match self {
                Self::Warning => "warning",
                Self::Error => "error",
            }
        }
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisHostMessage {
        pub level: AegisHostMessageLevel,
        #[serde(rename = "msg")]
        pub value: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisPutHostSsh {
        #[serde(default = "default_ssh_port", skip_serializing_if = "Option::is_none")]
        pub port: Option<u16>,
        #[serde(default)]
        pub public_key: Option<String>,
        #[serde(default)]
        pub external_principals: Vec<String>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisPutNetworkMemberWireGuard {
        pub public_key: String,
        #[serde(default)]
        pub ipv4: Option<String>,
        #[serde(default)]
        pub ipv6: Option<String>,
        #[serde(default)]
        pub endpoints: Vec<String>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisNetworkMemberInternalAddresses {
        pub ipv4: String,
        pub ipv6: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisAgentHealth {
        pub boot_id: String,
        pub reconciled_since_boot: bool,
        pub applied_aliases: Option<HostAliases>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub last_reconcile_unix: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub last_reconcile_warning: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub last_reconcile_error: Option<String>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisAgentReport {
        pub version: String,
        pub health: AegisAgentHealth,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisAgentStatus {
        pub version: String,
        pub health: AegisAgentHealth,
        pub reported_unix: i64,
    }

    #[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisHostReport {
        #[serde(default)]
        pub messages: Vec<AegisHostMessage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub agent: Option<AegisAgentStatus>,
        pub ssh_lockdown_enabled: bool,
        #[serde(default, skip_serializing_if = "AegisObservedPublicIps::is_empty")]
        pub observed_public_ips: AegisObservedPublicIps,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisHost {
        pub aliases: HostAliases,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ssh: Option<AegisHostSsh>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub egress: Option<AegisHostEgress>,
        #[serde(default)]
        pub report: AegisHostReport,
        #[serde(default)]
        pub transient: bool,
        #[serde(default)]
        pub pending: bool,
        pub updated_unix: i64,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisNetworkMember {
        pub aliases: HostAliases,
        pub mode: AegisHostMode,
        #[serde(default)]
        pub wireguard: Option<AegisNetworkMemberWireGuard>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub internal: Option<AegisNetworkMemberInternalAddresses>,
        #[serde(default)]
        pub pending: bool,
        pub updated_unix: i64,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisNetworkHost {
        pub mode: AegisHostMode,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ssh: Option<AegisNetworkHostSsh>,
        #[serde(default)]
        pub wireguard: Option<AegisNetworkMemberWireGuard>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub egress: Option<AegisHostEgress>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub internal: Option<AegisNetworkMemberInternalAddresses>,
        #[serde(default)]
        pub messages: Vec<AegisHostMessage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub agent: Option<AegisAgentStatus>,
        pub ssh_lockdown_enabled: bool,
        #[serde(default, skip_serializing_if = "AegisObservedPublicIps::is_empty")]
        pub observed_public_ips: AegisObservedPublicIps,
        #[serde(default)]
        pub transient: bool,
        #[serde(default)]
        pub pending: bool,
        pub updated_unix: i64,
    }

    impl AegisNetworkHost {
        pub fn resolve(host: AegisHost, member: AegisNetworkMember) -> Self {
            let internal_principals = member
                .wireguard
                .iter()
                .flat_map(|wireguard| [wireguard.ipv4.clone(), wireguard.ipv6.clone()])
                .chain(
                    member
                        .internal
                        .iter()
                        .flat_map(|internal| [internal.ipv4.clone(), internal.ipv6.clone()]),
                )
                .fold(Vec::new(), |mut principals, principal| {
                    if !principals.contains(&principal) {
                        principals.push(principal);
                    }
                    principals
                });
            let ssh = host.ssh.map(|ssh| AegisNetworkHostSsh {
                port: ssh.port,
                public_key: ssh.public_key,
                internal_principals,
                external_principals: ssh.external_principals,
            });
            Self {
                mode: member.mode,
                ssh,
                wireguard: member.wireguard,
                egress: host.egress,
                internal: member.internal,
                messages: host.report.messages,
                agent: host.report.agent,
                ssh_lockdown_enabled: host.report.ssh_lockdown_enabled,
                observed_public_ips: host.report.observed_public_ips,
                transient: host.transient,
                pending: host.pending || member.pending,
                updated_unix: host.updated_unix.max(member.updated_unix),
            }
        }

        pub fn host_label(&self, primary_alias: &HostAlias) -> String {
            let host = self
                .internal_ipv4()
                .or_else(|| self.internal_ipv6())
                .or_else(|| self.wireguard_ipv4())
                .or(self.wireguard_ipv6())
                .unwrap_or(primary_alias.as_str());
            let host = if host.contains(':') {
                format!("[{host}]")
            } else {
                host.to_string()
            };
            match self.ssh.as_ref() {
                Some(ssh) => match ssh.port {
                    Some(22) => host,
                    Some(port) => format!("{host}:{port}"),
                    None => host,
                },
                None => host,
            }
        }

        pub fn internal_principals(&self) -> &[String] {
            self.ssh
                .as_ref()
                .map(|ssh| ssh.internal_principals.as_slice())
                .unwrap_or(&[])
        }

        pub fn external_principals(&self) -> &[String] {
            self.ssh
                .as_ref()
                .map(|ssh| ssh.external_principals.as_slice())
                .unwrap_or(&[])
        }

        pub fn wireguard_public_key(&self) -> Option<&str> {
            self.wireguard
                .as_ref()
                .map(|wireguard| wireguard.public_key.as_str())
        }

        pub fn wireguard_ipv4(&self) -> Option<&str> {
            self.wireguard
                .as_ref()
                .map(|wireguard| wireguard.ipv4.as_str())
        }

        pub fn wireguard_ipv6(&self) -> Option<&str> {
            self.wireguard
                .as_ref()
                .map(|wireguard| wireguard.ipv6.as_str())
        }

        pub fn internal_ipv4(&self) -> Option<&str> {
            self.internal
                .as_ref()
                .map(|internal| internal.ipv4.as_str())
        }

        pub fn internal_ipv6(&self) -> Option<&str> {
            self.internal
                .as_ref()
                .map(|internal| internal.ipv6.as_str())
        }

        pub fn wireguard_endpoints(&self) -> &[String] {
            self.wireguard
                .as_ref()
                .map(|wireguard| wireguard.endpoints.as_slice())
                .unwrap_or(&[])
        }

        pub fn egress_public_key(&self) -> Option<&str> {
            self.egress
                .as_ref()
                .map(|egress| egress.public_key.as_str())
        }
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisHostListResponse {
        pub hosts: BTreeMap<HostId, AegisHost>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisAliasResponse {
        pub alias: HostAlias,
        pub host_id: HostId,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisNetworkMemberListResponse {
        pub network: String,
        pub members: BTreeMap<HostId, AegisNetworkMember>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisNetworkMemberResponse {
        pub network: String,
        pub host_id: HostId,
        pub member: AegisNetworkMember,
    }

    pub fn aegis_user_cert_principal(
        host_id: &HostId,
        login_principal: &str,
        user_id: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(host_id.as_bytes());
        hasher.update([0]);
        hasher.update(login_principal.as_bytes());
        hasher.update([0]);
        hasher.update(user_id.as_bytes());
        let digest = hasher.finalize();
        format!(
            "aegis-{}-{}-{}",
            host_id,
            ssh_principal_component(login_principal),
            URL_SAFE_NO_PAD.encode(&digest[..16])
        )
    }

    pub fn aegis_direct_account(credential_id: &str) -> Option<String> {
        is_direct_credential_id(credential_id).then(|| format!("aegis-d-{}", &credential_id[..24]))
    }

    pub fn aegis_direct_cert_principal(credential_id: &str) -> Option<String> {
        is_direct_credential_id(credential_id).then(|| format!("aegis-direct-{credential_id}"))
    }

    fn is_direct_credential_id(value: &str) -> bool {
        value.len() == 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    pub fn aegis_login_principal_from_user_cert_principal(
        host_id: &HostId,
        cert_principal: &str,
    ) -> Option<String> {
        let prefix = format!("aegis-{host_id}-");
        let remainder = cert_principal.strip_prefix(&prefix)?;
        if !remainder.is_ascii() || remainder.len() <= 23 {
            return None;
        }
        let (login_principal, digest) = remainder.split_at(remainder.len() - 23);
        let digest = digest.strip_prefix('-')?;
        if login_principal.is_empty()
            || digest.len() != 22
            || !digest
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
        {
            return None;
        }
        Some(login_principal.to_string())
    }

    fn ssh_principal_component(value: &str) -> String {
        value
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                    ch
                } else {
                    '_'
                }
            })
            .collect()
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
    #[serde(deny_unknown_fields)]
    pub struct AegisPrincipalGrant {
        pub login_principal: String,
        pub oauth_principal: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct AegisHostClientCertRequest {
        pub ed25519_public_key: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct AegisHostReportRequest {
        pub messages: Vec<AegisHostMessage>,
        pub agent: AegisAgentStatus,
        pub principal_grants: Vec<AegisPrincipalGrant>,
        pub ssh_lockdown_enabled: bool,
        pub direct_gateway: AegisDirectGatewayReport,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct AegisHostReportResponse {
        pub principal_grants: Vec<AegisPrincipalGrant>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct AegisPutHostRequest {
        pub aliases: HostAliases,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ssh: Option<AegisPutHostSsh>,
        #[serde(default)]
        pub transient: bool,
        #[serde(default)]
        pub pending: bool,
    }

    impl AegisPutHostRequest {
        pub fn external_principals(&self) -> &[String] {
            self.ssh
                .as_ref()
                .map(|ssh| ssh.external_principals.as_slice())
                .unwrap_or(&[])
        }
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct AegisPutNetworkMemberRequest {
        pub mode: AegisHostMode,
        #[serde(default)]
        pub wireguard: Option<AegisPutNetworkMemberWireGuard>,
        #[serde(default)]
        pub pending: bool,
    }

    impl AegisPutNetworkMemberRequest {
        pub fn wireguard_public_key(&self) -> Option<&str> {
            self.wireguard
                .as_ref()
                .map(|wireguard| wireguard.public_key.as_str())
        }

        pub fn wireguard_ipv4(&self) -> Option<&str> {
            self.wireguard
                .as_ref()
                .and_then(|wireguard| wireguard.ipv4.as_deref())
        }

        pub fn wireguard_ipv6(&self) -> Option<&str> {
            self.wireguard
                .as_ref()
                .and_then(|wireguard| wireguard.ipv6.as_deref())
        }
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    pub struct ErrorResponse {
        pub error: String,
    }

    fn default_ssh_port() -> Option<u16> {
        Some(22)
    }

    fn default_enrollment_ttl_seconds() -> u64 {
        crate::DEFAULT_AEGIS_ENROLLMENT_TTL_SECONDS
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AegisHostMode, HostAlias, HostAliases, HostId, InvalidHostAliases, MAX_HOST_ALIASES,
        WireGuardHostIdentity, allocate_lowest_free_wireguard_host_id, normalize_wireguard_ipv4,
        normalize_wireguard_key, path, v1,
        v1::AegisMeshConfig,
        v1::{AegisHostMessage, AegisHostMessageLevel},
        validate_satellite_slug, validate_wireguard_address_pool,
        validate_wireguard_interface_name, wireguard_address_pools_overlap,
        wireguard_host_id_from_addresses, wireguard_host_identity_from_addresses,
        wireguard_ipv4_for_host_id, wireguard_ipv6_for_host_id,
    };

    fn test_host_id(index: u64) -> HostId {
        format!("00000000-0000-4000-8000-{index:012x}")
            .parse()
            .expect("test host id should parse")
    }

    #[test]
    fn host_aliases_are_ordered_unique_and_finite() {
        let first = "host-a".parse::<HostAlias>().expect("first alias");
        let second = "host-b".parse::<HostAlias>().expect("second alias");
        let aliases = HostAliases::new(vec![first.clone(), second.clone()]).expect("valid aliases");
        assert_eq!(&first, aliases.primary());
        assert!(aliases.contains(&second));
        assert!(matches!(
            HostAliases::new(Vec::new()),
            Err(InvalidHostAliases::Empty)
        ));
        assert!(matches!(
            HostAliases::new(vec![first.clone(), first]),
            Err(InvalidHostAliases::Duplicate(_))
        ));
        let too_many = (0..=MAX_HOST_ALIASES)
            .map(|index| format!("host-{index}").parse::<HostAlias>().expect("alias"))
            .collect();
        assert!(matches!(
            HostAliases::new(too_many),
            Err(InvalidHostAliases::TooMany { .. })
        ));
    }

    #[test]
    fn agent_token_response_has_one_explicit_credential_schema() {
        let response = v1::AgentTokenResponse {
            access_token: "access".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 300,
            host_id: test_host_id(1),
            credential_kind: v1::AegisCredentialKind::Agent,
            refresh_token: "refresh".to_string(),
            refresh_expires_in: 3600,
        };
        let encoded = serde_json::to_value(&response).expect("serialize agent token response");
        assert_eq!(
            serde_json::json!({
                "access_token": "access",
                "token_type": "Bearer",
                "expires_in": 300,
                "host_id": test_host_id(1),
                "credential_kind": "agent",
                "refresh_token": "refresh",
                "refresh_expires_in": 3600
            }),
            encoded
        );
        assert_eq!(
            response,
            serde_json::from_value(encoded).expect("deserialize agent token response")
        );
    }

    #[test]
    fn host_alias_mutations_preserve_primary_semantics() {
        let old = "old-name".parse::<HostAlias>().expect("old alias");
        let new = "new-name".parse::<HostAlias>().expect("new alias");
        let aliases = HostAliases::new(vec![old.clone()]).expect("initial aliases");
        let added = aliases.added(new.clone()).expect("add alias");
        assert_eq!(&old, added.primary());
        let reordered = added.promoted(&new).expect("promote existing alias");
        assert_eq!(&new, reordered.primary());
        let final_aliases = reordered
            .removed(&old)
            .expect("remove non-primary alias")
            .expect("alias existed");
        assert_eq!(&new, final_aliases.primary());
        assert!(matches!(
            final_aliases.removed(&new),
            Err(InvalidHostAliases::PrimaryRemoval(_))
        ));
    }

    #[test]
    fn host_alias_deserialization_enforces_public_namespace_invariants() {
        assert!(serde_json::from_str::<HostAliases>(r#"["host-a","storage.box_2"]"#).is_ok());
        assert!(serde_json::from_str::<HostAliases>(r#"[]"#).is_err());
        assert!(serde_json::from_str::<HostAliases>(r#"["host-a","host-a"]"#).is_err());
        for invalid in [
            "Upper",
            "with space",
            "with/slash",
            "",
            "00000000-0000-4000-8000-000000000001",
        ] {
            assert!(
                invalid.parse::<HostAlias>().is_err(),
                "accepted `{invalid}`"
            );
        }
    }

    #[test]
    fn satellite_slug_validation_matches_the_public_api_namespace() {
        assert!(validate_satellite_slug("deus-kellnr").is_ok());
        assert!(validate_satellite_slug("storage.box_2").is_ok());
        assert!(validate_satellite_slug("").is_err());
        assert!(validate_satellite_slug("Uppercase").is_err());
        assert!(validate_satellite_slug("with space").is_err());
    }

    #[test]
    fn wireguard_interface_validation_matches_the_managed_systemd_template() {
        assert!(validate_wireguard_interface_name("wg-aegis").is_ok());
        assert!(validate_wireguard_interface_name("wg.access_1").is_ok());
        assert!(validate_wireguard_interface_name("").is_err());
        assert!(validate_wireguard_interface_name(".").is_err());
        assert!(validate_wireguard_interface_name("..").is_err());
        assert!(validate_wireguard_interface_name("wg/aegis").is_err());
        assert!(validate_wireguard_interface_name("wireguard-interface").is_err());
    }

    #[test]
    fn wireguard_pool_validation_and_overlap_cover_both_address_families() {
        let base = v1::AegisWireGuardAddressPool {
            subnet_ipv4: "10.77.1.0/24".to_string(),
            subnet_ipv6: "fd77::1:0/120".to_string(),
        };
        validate_wireguard_address_pool(&base).expect("ordinary dual-stack pool should validate");

        let disjoint = v1::AegisWireGuardAddressPool {
            subnet_ipv4: "10.77.2.0/24".to_string(),
            subnet_ipv6: "fd77::2:0/120".to_string(),
        };
        assert!(
            !wireguard_address_pools_overlap(&base, &disjoint)
                .expect("disjoint pools should compare")
        );

        let overlapping_ipv6 = v1::AegisWireGuardAddressPool {
            subnet_ipv4: "10.77.2.0/24".to_string(),
            subnet_ipv6: "fd77::1:80/121".to_string(),
        };
        assert!(
            wireguard_address_pools_overlap(&base, &overlapping_ipv6)
                .expect("overlapping pools should compare")
        );

        let too_small = v1::AegisWireGuardAddressPool {
            subnet_ipv4: "192.0.2.1/32".to_string(),
            subnet_ipv6: "2001:db8::1/128".to_string(),
        };
        assert!(validate_wireguard_address_pool(&too_small).is_err());
    }

    #[test]
    fn host_message_level_is_typed_but_serializes_to_msg_shape() {
        let message = AegisHostMessage {
            level: AegisHostMessageLevel::Warning,
            value: "Bird3 apt source is misconfigured".to_string(),
        };
        let json = serde_json::to_string(&message).expect("message should serialize");

        assert_eq!(
            r#"{"level":"warning","msg":"Bird3 apt source is misconfigured"}"#,
            json
        );
        let decoded: AegisHostMessage =
            serde_json::from_str(&json).expect("message should deserialize");
        assert_eq!(message, decoded);
    }

    #[test]
    fn host_report_requires_complete_agent_observations() {
        assert!(
            serde_json::from_str::<v1::AegisHostReportRequest>(
                r#"{"messages":[],"principal_grants":[]}"#
            )
            .is_err()
        );

        let report = v1::AegisHostReportRequest {
            messages: Vec::new(),
            agent: v1::AegisAgentStatus {
                version: "1.2.3".to_string(),
                health: v1::AegisAgentHealth {
                    boot_id: "00000000-0000-0000-0000-000000000001".to_string(),
                    reconciled_since_boot: true,
                    applied_aliases: Some(
                        HostAliases::new(vec!["alpha".parse().expect("alias should parse")])
                            .expect("aliases should validate"),
                    ),
                    last_reconcile_unix: Some(99),
                    last_reconcile_warning: None,
                    last_reconcile_error: None,
                },
                reported_unix: 100,
            },
            principal_grants: Vec::new(),
            ssh_lockdown_enabled: true,
            direct_gateway: v1::AegisDirectGatewayReport {
                observed_unix: 100,
                peers: vec![v1::AegisDirectPeerObservation {
                    public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
                    latest_handshake_unix: Some(99),
                }],
            },
        };
        let encoded = serde_json::to_value(report).expect("host report should serialize");
        assert_eq!(
            Some(&serde_json::Value::Bool(true)),
            encoded.get("ssh_lockdown_enabled")
        );
        assert!(encoded.get("direct_gateway").is_some());
    }

    #[test]
    fn direct_gateway_config_requires_full_tunnel_dns() {
        let incomplete = r#"{"interface":"wg-aegis-direct","endpoint_port":51822,"mtu":1380,"fwmark":44641,"subnet_ipv4":"10.77.1.0/24","subnet_ipv6":"fd77::1:0/120"}"#;
        assert!(serde_json::from_str::<v1::AegisDirectGatewayConfig>(incomplete).is_err());
    }

    #[test]
    fn direct_gateway_inventory_rejects_removed_setup_state() {
        let mut inventory = serde_json::json!({
            "config": {
                "interface": "wg-aegis-direct",
                "endpoint_port": 51822,
                "mtu": 1380,
                "fwmark": 44641,
                "subnet_ipv4": "10.77.1.0/24",
                "subnet_ipv6": "fd77::1:0/120",
                "full_tunnel_dns": ["1.1.1.1"]
            },
            "enabled": false,
            "direct_client_ca_public_key": "ssh-ed25519 AAAA",
            "satellites": []
        });
        serde_json::from_value::<v1::AegisDirectGatewayInventory>(inventory.clone())
            .expect("current direct-gateway inventory should deserialize");
        inventory
            .as_object_mut()
            .expect("inventory should be an object")
            .insert("setups".to_string(), serde_json::json!([]));
        assert!(serde_json::from_value::<v1::AegisDirectGatewayInventory>(inventory).is_err());
    }

    #[test]
    fn path_helpers_match_templates() {
        let host_id = test_host_id(1);
        assert_eq!(
            format!("/aegis/hosts/{host_id}"),
            path::aegis_host(&host_id)
        );
    }

    #[test]
    fn user_cert_principal_is_stable_pair_scoped_and_id_exact() {
        let host_id = test_host_id(1);
        let left = v1::aegis_user_cert_principal(&host_id, "khoek", "OpaqueUserID");
        let same = v1::aegis_user_cert_principal(&host_id, "khoek", "OpaqueUserID");
        let different_login = v1::aegis_user_cert_principal(&host_id, "root", "OpaqueUserID");
        let different_id = v1::aegis_user_cert_principal(&host_id, "khoek", "opaqueuserid");

        assert_eq!(left, same);
        assert_ne!(left, different_login);
        assert_ne!(left, different_id);
        assert!(left.starts_with(&format!("aegis-{host_id}-khoek-")));
        assert!(!left.chars().any(char::is_whitespace));
    }

    #[test]
    fn user_cert_principal_login_round_trip_preserves_dashes() {
        let host_id = test_host_id(1);
        let principal = v1::aegis_user_cert_principal(&host_id, "pj-hoek", "OpaqueUserID");

        assert_eq!(
            Some("pj-hoek".to_string()),
            v1::aegis_login_principal_from_user_cert_principal(&host_id, &principal)
        );
        assert_eq!(
            None,
            v1::aegis_login_principal_from_user_cert_principal(&test_host_id(2), &principal)
        );
    }

    #[test]
    fn wireguard_key_normalizer_accepts_base64_encoded_curve25519_keys() {
        assert_eq!(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            normalize_wireguard_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .expect("wireguard key should normalize")
        );
    }

    #[test]
    fn wireguard_key_normalizer_rejects_wrong_lengths() {
        assert!(normalize_wireguard_key("AAAA").is_err());
    }

    #[test]
    fn wireguard_ipv4_normalizer_round_trips_ipv4_addresses() {
        assert_eq!(
            "10.0.0.42",
            normalize_wireguard_ipv4("10.0.0.42").expect("ipv4 should normalize")
        );
    }

    #[test]
    fn wireguard_ipv4_normalizer_rejects_non_ipv4_input() {
        assert!(normalize_wireguard_ipv4("not-an-ip").is_err());
    }

    #[test]
    fn wireguard_host_identity_uses_one_peer_namespace() {
        let pool = v1::AegisMeshConfig {
            endpoint_port: 51820,
            overlay_mtu: 1350,
            subnet_ipv4: "10.75.0.0/16".to_string(),
            subnet_ipv6: "fd75::/64".to_string(),
            wireguard_subnet_ipv4: "10.75.1.0/24".to_string(),
            wireguard_subnet_ipv6: "fd75::1:0/120".to_string(),
            host_dns_suffix: None,
        }
        .wireguard_address_pool();

        assert_eq!(
            WireGuardHostIdentity::Peer(1),
            wireguard_host_identity_from_addresses(&pool, "10.75.1.1", "fd75::1:1")
                .expect("peer identity should validate")
        );
        assert_eq!(
            WireGuardHostIdentity::Peer(7),
            wireguard_host_identity_from_addresses(&pool, "10.75.1.7", "fd75::1:7")
                .expect("peer identity should validate")
        );
    }

    #[test]
    fn aegis_host_mode_round_trips_as_lowercase_strings() {
        assert_eq!("leaf", AegisHostMode::Leaf.to_string());
        assert_eq!("hub", AegisHostMode::Hub.to_string());
        assert_eq!(Ok(AegisHostMode::Leaf), "leaf".parse());
        assert_eq!(Ok(AegisHostMode::Hub), "hub".parse());
        assert!("service".parse::<AegisHostMode>().is_err());
    }

    fn sample_mesh() -> AegisMeshConfig {
        AegisMeshConfig {
            endpoint_port: 51_820,
            overlay_mtu: 1350,
            subnet_ipv4: "10.75.0.0/16".to_string(),
            subnet_ipv6: "fd75::/64".to_string(),
            wireguard_subnet_ipv4: "10.75.1.0/24".to_string(),
            wireguard_subnet_ipv6: "fd75::1:0/120".to_string(),
            host_dns_suffix: None,
        }
    }

    #[test]
    fn wireguard_identity_round_trips_for_host_id() {
        let pool = sample_mesh().wireguard_address_pool();
        let ipv4 = wireguard_ipv4_for_host_id(&pool, 7).expect("IPv4 should allocate");
        let ipv6 = wireguard_ipv6_for_host_id(&pool, 7).expect("IPv6 should allocate");

        assert_eq!("10.75.1.7", ipv4);
        assert_eq!("fd75::1:7", ipv6);
        assert_eq!(
            7,
            wireguard_host_id_from_addresses(&pool, &ipv4, &ipv6).expect("host id should parse")
        );
    }

    #[test]
    fn allocate_lowest_free_wireguard_host_id_picks_first_gap() {
        let pool = sample_mesh().wireguard_address_pool();
        let used = [
            ("10.75.1.1", "fd75::1:1"),
            ("10.75.1.2", "fd75::1:2"),
            ("10.75.1.4", "fd75::1:4"),
        ];

        assert_eq!(
            3,
            allocate_lowest_free_wireguard_host_id(&pool, used).expect("allocation should succeed")
        );
    }
}
