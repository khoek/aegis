use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};

use crate::api::AuthenticatedApiClient;
use crate::ui;
use crate::{
    cli::{SshArgs, TransferArgs},
    config::{CachedHost, CachedNetworkConfig, SHARED_CACHE_PATH, load_cached_network},
    wireguard_endpoint::preferred_wireguard_endpoint_ip,
};

use super::{host_list, list};

pub(super) struct AvailableHostLookup<'a> {
    api_base_override: Option<&'a str>,
    network: &'a str,
    host: &'a str,
    allow_pending: bool,
    refresh: bool,
}

impl<'a> AvailableHostLookup<'a> {
    pub(super) fn new(
        api_base_override: Option<&'a str>,
        network: &'a str,
        host: &'a str,
        allow_pending: bool,
    ) -> Self {
        Self {
            api_base_override,
            network,
            host,
            allow_pending,
            refresh: true,
        }
    }

    pub(super) fn refresh(mut self, refresh: bool) -> Self {
        self.refresh = refresh;
        self
    }

    pub(super) fn load(&self) -> Result<CachedHost> {
        if !crate::api::uses_local_agent(self.api_base_override)? {
            return self.load_from_api();
        }
        if let Some(host) = load_cached_network(Path::new(SHARED_CACHE_PATH), self.network)?
            .and_then(|network| {
                network
                    .hosts
                    .into_iter()
                    .find(|host| host.matches(self.host))
            })
        {
            if host_is_visible(&host, self.allow_pending)
                && host_offers_ssh(&host)
                && host_has_pinned_public_key(&host)
            {
                return Ok(host);
            }
            if !host_is_visible(&host, self.allow_pending) {
                if self.refresh {
                    ui::warn(&format!(
                        "host `{}` is pending in the cache; refreshing host inventory",
                        self.host
                    ));
                } else {
                    bail!(
                        "host `{}` is pending in the cache; rerun with `--allow-pending` to use it or `--refresh` to sync host inventory",
                        self.host
                    );
                }
            } else if !host_offers_ssh(&host) {
                bail!("host `{}` offers no SSH access", self.host);
            } else {
                if self.refresh {
                    ui::warn(&format!(
                        "host `{}` is cached without a pinned host public key; refreshing host inventory",
                        self.host
                    ));
                } else {
                    bail!(
                        "host `{}` is cached without a pinned host public key; rerun with `--refresh` to sync host inventory",
                        self.host
                    );
                }
            }
        } else if !self.refresh {
            bail!(
                "host `{}` is not cached in network `{}`; run `aegis list --network {} --refresh` or rerun with `--refresh`",
                self.host,
                self.network,
                self.network,
            );
        } else {
            ui::warn(&format!(
                "host `{}` is not cached in network `{}`; refreshing host inventory",
                self.host, self.network
            ));
        }
        self.load_from_api()
    }

    fn load_from_api(&self) -> Result<CachedHost> {
        match list::refresh_host_cache_for_network(self.api_base_override, self.network)?
            .into_iter()
            .find(|host| host.matches(self.host))
        {
            Some(host) if !host_is_visible(&host, self.allow_pending) => {
                bail!(
                    "host `{}` is pending; rerun with `--allow-pending` to use it",
                    self.host
                )
            }
            Some(host) if !host_offers_ssh(&host) => {
                bail!("host `{}` offers no SSH access", self.host)
            }
            Some(host) if !host_has_pinned_public_key(&host) => {
                bail!("host `{}` is missing a pinned host public key", self.host)
            }
            Some(host) => Ok(host),
            None => bail!(
                "unknown host `{}` in network `{}` after refresh",
                self.host,
                self.network
            ),
        }
    }
}

pub(super) fn load_network_config(
    api: &mut AuthenticatedApiClient,
    network: &str,
) -> Result<CachedNetworkConfig> {
    if crate::api::uses_local_agent(Some(api.api_base()))?
        && let Some(cached) = load_cached_network(Path::new(SHARED_CACHE_PATH), network)?
    {
        return Ok(cached.config);
    }
    api.get_networks()?
        .networks
        .remove(network)
        .ok_or_else(|| anyhow!("unknown aegis network `{network}`"))
}

pub(super) fn logical_dns_host(alias: &str, suffix: Option<&str>) -> Option<String> {
    let suffix = suffix?.trim().trim_start_matches('.').trim_end_matches('.');
    (!suffix.is_empty()).then(|| format!("{alias}.{suffix}"))
}

pub(super) fn host_is_visible(host: &CachedHost, allow_pending: bool) -> bool {
    allow_pending || !host.pending
}

pub(super) fn host_offers_ssh(host: &CachedHost) -> bool {
    host.ssh.as_ref().and_then(|ssh| ssh.port).is_some()
}

pub(super) fn host_has_pinned_public_key(host: &CachedHost) -> bool {
    host.ssh
        .as_ref()
        .and_then(|ssh| ssh.public_key.as_deref())
        .is_some()
}

pub(super) fn host_ssh_port(host: &CachedHost) -> Result<u16> {
    host.ssh
        .as_ref()
        .and_then(|ssh| ssh.port)
        .ok_or_else(|| anyhow!("host `{}` offers no SSH access", host.alias()))
}

pub(super) fn validate_login_principal(value: &str) -> Result<()> {
    crate::principal_grants::validate_login_principal(value)
}

pub(super) fn host_registration_ssh_port(host: &CachedHost) -> Option<u16> {
    host.ssh.as_ref().and_then(|ssh| ssh.port)
}

pub(super) fn host_registration_ssh_public_key(host: &CachedHost) -> Option<&str> {
    host.ssh.as_ref().and_then(|ssh| ssh.public_key.as_deref())
}

pub(super) fn filter_visible_hosts(hosts: Vec<CachedHost>, allow_pending: bool) -> Vec<CachedHost> {
    let mut hosts = hosts
        .into_iter()
        .filter(|host| host_is_visible(host, allow_pending))
        .collect::<Vec<_>>();
    sort_hosts_for_list(&mut hosts);
    hosts
}

pub(super) fn sort_hosts_for_list(hosts: &mut [CachedHost]) {
    hosts.sort_by(|left, right| {
        host_list::list_host_kind(left)
            .cmp(&host_list::list_host_kind(right))
            .then_with(|| left.alias().cmp(right.alias()))
    });
}

#[derive(Clone, Copy)]
enum AddressFamily {
    Auto,
    Ipv4,
    Ipv6,
}

trait ConnectOptions {
    fn use_endpoint(&self) -> bool;
    fn address_family(&self) -> AddressFamily;
    fn ipv4_flag(&self) -> &'static str;
    fn ipv6_flag(&self) -> &'static str;
}

impl ConnectOptions for SshArgs {
    fn use_endpoint(&self) -> bool {
        self.use_endpoint
    }

    fn address_family(&self) -> AddressFamily {
        requested_address_family(self.ipv4, self.ipv6)
    }

    fn ipv4_flag(&self) -> &'static str {
        "--ipv4"
    }

    fn ipv6_flag(&self) -> &'static str {
        "--ipv6"
    }
}

impl ConnectOptions for TransferArgs {
    fn use_endpoint(&self) -> bool {
        self.use_endpoint
    }

    fn address_family(&self) -> AddressFamily {
        requested_address_family(self.ipv4, self.ipv6)
    }

    fn ipv4_flag(&self) -> &'static str {
        "--ipv4"
    }

    fn ipv6_flag(&self) -> &'static str {
        "--ipv6"
    }
}

fn requested_address_family(ipv4: bool, ipv6: bool) -> AddressFamily {
    if ipv4 {
        AddressFamily::Ipv4
    } else if ipv6 {
        AddressFamily::Ipv6
    } else {
        AddressFamily::Auto
    }
}

pub(super) fn resolve_ssh_connect_host(host: &CachedHost, args: &SshArgs) -> Result<String> {
    resolve_connect_host_for(host, args)
}

pub(super) fn resolve_transfer_connect_host(
    host: &CachedHost,
    args: &TransferArgs,
) -> Result<String> {
    resolve_connect_host_for(host, args)
}

pub(super) fn ssh_mesh_route_targets(host: &CachedHost, args: &SshArgs) -> Result<Vec<IpAddr>> {
    mesh_route_targets(host, args)
}

pub(super) fn transfer_mesh_route_targets(
    host: &CachedHost,
    args: &TransferArgs,
) -> Result<Vec<IpAddr>> {
    mesh_route_targets(host, args)
}

fn mesh_route_targets(host: &CachedHost, options: &impl ConnectOptions) -> Result<Vec<IpAddr>> {
    if options.use_endpoint() {
        return Ok(Vec::new());
    }
    let value = resolve_connect_host_for(host, options)?;
    Ok(vec![value.parse::<IpAddr>().with_context(|| {
        format!(
            "host `{}` has an invalid mesh address `{value}`",
            host.alias()
        )
    })?])
}

fn resolve_connect_host_for(host: &CachedHost, options: &impl ConnectOptions) -> Result<String> {
    if options.use_endpoint() {
        return preferred_wireguard_endpoint_ip(host.wireguard_endpoints())?.ok_or_else(|| {
            anyhow!(
                "host `{}` has no published WireGuard endpoint",
                host.alias()
            )
        });
    }
    match options.address_family() {
        AddressFamily::Auto => resolve_mesh_connect_host(host),
        AddressFamily::Ipv4 => mesh_ipv4_connect_host(host).ok_or_else(|| {
            anyhow!(
                "host `{}` has no mesh IPv4 address and cannot be reached with `{}`",
                host.alias(),
                options.ipv4_flag()
            )
        }),
        AddressFamily::Ipv6 => mesh_ipv6_connect_host(host).ok_or_else(|| {
            anyhow!(
                "host `{}` has no mesh IPv6 address and cannot be reached with `{}`",
                host.alias(),
                options.ipv6_flag()
            )
        }),
    }
}

pub(super) fn resolve_mesh_connect_host(host: &CachedHost) -> Result<String> {
    mesh_ipv4_connect_host(host)
        .or_else(|| mesh_ipv6_connect_host(host))
        .ok_or_else(|| {
            anyhow!(
                "host `{}` has no mesh address and cannot be reached on the mesh",
                host.alias()
            )
        })
}

pub(super) fn mesh_ipv4_connect_host(host: &CachedHost) -> Option<String> {
    host.internal_ipv4()
        .map(str::to_string)
        .or_else(|| host.wireguard_ipv4().map(str::to_string))
}

pub(super) fn mesh_ipv6_connect_host(host: &CachedHost) -> Option<String> {
    host.internal_ipv6()
        .map(str::to_string)
        .or_else(|| host.wireguard_ipv6().map(str::to_string))
}

pub(super) fn resolve_connect_host(host: &CachedHost) -> Result<String> {
    resolve_mesh_connect_host(host)
}

pub(super) fn host_wireguard_identity(host: &CachedHost) -> Result<(String, String)> {
    Ok((
        host.wireguard_ipv4()
            .map(str::to_string)
            .ok_or_else(|| anyhow!("host `{}` is missing wireguard IPv4", host.alias()))?,
        host.wireguard_ipv6()
            .map(str::to_string)
            .ok_or_else(|| anyhow!("host `{}` is missing wireguard IPv6", host.alias()))?,
    ))
}
