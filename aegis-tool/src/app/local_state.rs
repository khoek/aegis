use std::collections::BTreeSet;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::process::Command;

use aegis_dto::{HostId, normalize_wireguard_ipv4, normalize_wireguard_ipv6};
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use crate::api::{ApiClient, AuthenticatedApiClient};
use crate::command::require_success;
use crate::config::{
    CachedHost, SHARED_CACHE_PATH, load_all_hosts, namespace_endpoint, resolve_api_base,
};

use super::{AEGIS_STATE_PATH, WIREGUARD_INTERFACE, system, wireguard};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManagedHostState {
    pub(super) api_base: String,
    pub(super) host_id: HostId,
}

pub(super) struct ManagedHostStateStore;

impl ManagedHostStateStore {
    pub(super) fn persist(api_base: &str, host_id: HostId) -> Result<()> {
        let state = ManagedHostState {
            api_base: namespace_endpoint(api_base)?.base_url(),
            host_id,
        };
        system::TextFile::new(Path::new(AEGIS_STATE_PATH)).write_atomic(
            &toml::to_string(&state).context("failed to encode aegis state")?,
            0o600,
        )
    }

    pub(super) fn load() -> Result<Option<ManagedHostState>> {
        let path = Path::new(AEGIS_STATE_PATH);
        if !path.exists() {
            return Ok(None);
        }
        let raw = match fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == ErrorKind::PermissionDenied => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("failed to read {}", path.display()));
            }
        };
        let state: ManagedHostState =
            toml::from_str(&raw).context("failed to parse aegis state")?;
        namespace_endpoint(&state.api_base)?;
        Ok(Some(state))
    }

    pub(super) fn recover(
        api_base_override: Option<&str>,
        api_token: Option<&str>,
    ) -> Result<Option<ManagedHostState>> {
        let identity = match RuntimeWireGuardIdentity::read() {
            Ok(identity) => identity,
            Err(_) => return Ok(None),
        };
        let installed_agent_api_base = crate::api::installed_agent_api_base()?;
        let api_base = resolve_api_base(api_base_override, installed_agent_api_base.as_deref())?;
        let host = if let Some(api_token) = api_token {
            let api = ApiClient::new(&api_base)?;
            super::cached_network_members_from_response(
                api.get_hosts(api_token)?,
                api.get_network_members(api_token, aegis_dto::DEFAULT_AEGIS_NETWORK)?,
            )?
            .into_iter()
            .find(|host| identity.matches(host))
        } else {
            let mut api = AuthenticatedApiClient::load(Some(&api_base))?;
            super::cached_network_members_from_response(
                api.get_hosts()?,
                api.get_network_members(aegis_dto::DEFAULT_AEGIS_NETWORK)?,
            )?
            .into_iter()
            .find(|host| identity.matches(host))
        };
        Ok(host.map(|host| ManagedHostState {
            api_base,
            host_id: host.host_id,
        }))
    }
}

pub(super) struct LocalHostIdentity;

impl LocalHostIdentity {
    pub(super) fn host_id_from_managed_state_or_cache() -> Result<Option<HostId>> {
        if let Some(state) = ManagedHostStateStore::load()? {
            return Ok(Some(state.host_id));
        }
        let hosts = load_all_hosts(Path::new(SHARED_CACHE_PATH))?;
        let Some(addresses) = WireGuardAddressSet::read_active().ok() else {
            return Ok(None);
        };
        Ok(Self::host_id_from_hosts_and_addresses(
            &hosts,
            addresses.as_set(),
        ))
    }

    pub(super) fn host_id_from_hosts_and_addresses(
        hosts: &[CachedHost],
        addresses: &BTreeSet<String>,
    ) -> Option<HostId> {
        hosts
            .iter()
            .find(|host| {
                host.wireguard_ipv4()
                    .is_some_and(|address| addresses.contains(address))
                    || host
                        .wireguard_ipv6()
                        .is_some_and(|address| addresses.contains(address))
            })
            .map(|host| host.host_id)
    }
}

pub(super) struct WireGuardAddressSet {
    addresses: BTreeSet<String>,
}

impl WireGuardAddressSet {
    fn read_active() -> Result<Self> {
        let output = require_success(
            "list active WireGuard interface addresses",
            Command::new("ip").args(["-o", "address", "show", "dev", WIREGUARD_INTERFACE]),
        )?;
        let addresses = IpAddressOutput::new(&output.stdout).parse()?;
        if addresses.is_empty() {
            bail!("{WIREGUARD_INTERFACE} has no active IP addresses");
        }
        Ok(Self { addresses })
    }

    fn as_set(&self) -> &BTreeSet<String> {
        &self.addresses
    }
}

pub(super) struct IpAddressOutput<'a> {
    output: &'a str,
}

impl<'a> IpAddressOutput<'a> {
    pub(super) fn new(output: &'a str) -> Self {
        Self { output }
    }

    pub(super) fn parse(&self) -> Result<BTreeSet<String>> {
        let mut addresses = BTreeSet::new();
        let mut fields = self.output.split_whitespace();
        while let Some(field) = fields.next() {
            let is_ipv4 = field == "inet";
            if !is_ipv4 && field != "inet6" {
                continue;
            }
            let Some(address) = fields.next() else {
                bail!("ip address output ended after `{field}`");
            };
            let address = address.split('/').next().unwrap_or_default();
            if is_ipv4 {
                addresses.insert(normalize_wireguard_ipv4(address)?);
            } else {
                addresses.insert(normalize_wireguard_ipv6(address)?);
            }
        }
        Ok(addresses)
    }
}

pub(super) struct RuntimeWireGuardIdentity {
    ipv4: String,
    ipv6: Option<String>,
}

impl RuntimeWireGuardIdentity {
    pub(super) fn read() -> Result<Self> {
        let (ipv4, ipv6) = wireguard::interface_addresses()?;
        Ok(Self { ipv4, ipv6 })
    }

    pub(super) fn find_host(&self, hosts: Vec<CachedHost>) -> Result<CachedHost> {
        hosts
            .into_iter()
            .find(|host| self.matches(host))
            .ok_or_else(|| {
                anyhow!(
                    "could not find an enrolled aegis host matching the local WireGuard addresses {}{}",
                    self.ipv4,
                    self.ipv6
                        .as_deref()
                        .map(|wireguard_ipv6| format!(", {wireguard_ipv6}"))
                        .unwrap_or_default()
                )
            })
    }

    fn matches(&self, host: &CachedHost) -> bool {
        host.wireguard_ipv4() == Some(&self.ipv4)
            || self
                .ipv6
                .as_deref()
                .is_some_and(|wireguard_ipv6| host.wireguard_ipv6() == Some(wireguard_ipv6))
    }
}
