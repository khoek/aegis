use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;

use aegis_dto::{
    HostId, normalize_wireguard_ipv4, normalize_wireguard_ipv6, normalize_wireguard_key,
};
use anyhow::{Context, Result, bail};

use crate::command::{require_success, require_success_with_input};

use super::{WIREGUARD_CONFIG_PATH, line_with_newline};

#[derive(Debug, Clone)]
pub(super) struct Keypair {
    pub(super) private_key: String,
    pub(super) public_key: String,
}

impl Keypair {
    pub(super) fn generate() -> Result<Self> {
        Self::from_private_key(
            &require_success(
                "generate WireGuard private key",
                Command::new("wg").arg("genkey"),
            )?
            .stdout,
        )
        .context("generated WireGuard keypair is invalid")
    }

    pub(super) fn from_private_key(private_key: &str) -> Result<Self> {
        let private_key =
            normalize_wireguard_key(private_key).context("WireGuard private key is invalid")?;
        let public_key = normalize_wireguard_key(
            &require_success_with_input(
                "derive WireGuard public key",
                Command::new("wg").arg("pubkey"),
                line_with_newline(&private_key).as_bytes(),
            )?
            .stdout,
        )
        .context("derived WireGuard public key is invalid")?;
        Ok(Self {
            private_key,
            public_key,
        })
    }
}

#[derive(Debug, Clone)]
pub(super) struct HubPeer {
    pub(super) host_id: HostId,
    pub(super) endpoint_ip: String,
    pub(super) public_key: String,
    pub(super) wireguard_ipv4: String,
    pub(super) wireguard_ipv6: String,
}

impl HubPeer {
    fn config_contents(&self, endpoint_port: u16, default_route: bool) -> String {
        let allowed_ips = if default_route {
            "0.0.0.0/0,::/0".to_string()
        } else {
            format!("{}/32,{}/128", self.wireguard_ipv4, self.wireguard_ipv6)
        };
        format!(
            "\n[Peer]\nPublicKey = {public_key}\nEndpoint = {endpoint_ip}:{endpoint_port}\nAllowedIPs = {allowed_ips}\nPersistentKeepalive = 25\n",
            endpoint_ip = endpoint_literal(&self.endpoint_ip),
            public_key = self.public_key,
        )
    }
}

pub(super) enum ClientRouting<'a> {
    PeerAddresses,
    DefaultRoute { dns: &'a [String] },
}

pub(super) struct ClientConfigOptions<'a> {
    pub(super) private_key: &'a str,
    pub(super) wireguard_ipv4: &'a str,
    pub(super) wireguard_ipv6: &'a str,
    pub(super) hub_peers: &'a [HubPeer],
    pub(super) endpoint_port: u16,
    pub(super) mtu: Option<u16>,
    pub(super) routing: ClientRouting<'a>,
}

pub(super) struct ClientConfig<'a> {
    options: ClientConfigOptions<'a>,
}

impl<'a> ClientConfig<'a> {
    pub(super) fn new(options: ClientConfigOptions<'a>) -> Result<Self> {
        if options.endpoint_port == 0 {
            bail!("WireGuard endpoint port cannot be zero");
        }
        if options.hub_peers.is_empty() {
            bail!("a WireGuard client must have at least one peer");
        }
        if options
            .mtu
            .is_some_and(|mtu| mtu < aegis_dto::mtu::IPV6_MINIMUM)
        {
            bail!("WireGuard client MTU must support IPv6");
        }
        if let ClientRouting::DefaultRoute { dns } = &options.routing {
            if options.hub_peers.len() != 1 {
                bail!("a default-route WireGuard client must select exactly one gateway");
            }
            if dns.is_empty() {
                bail!("a default-route WireGuard client must define DNS servers");
            }
            for address in *dns {
                address
                    .parse::<IpAddr>()
                    .with_context(|| format!("invalid full-tunnel DNS address `{address}`"))?;
            }
        }
        Ok(Self { options })
    }

    pub(super) fn contents(&self) -> String {
        let mut content = format!(
            "[Interface]\nAddress = {}/32,{}/128\nPrivateKey = {}\n",
            self.options.wireguard_ipv4, self.options.wireguard_ipv6, self.options.private_key,
        );
        if let Some(mtu) = self.options.mtu {
            content.push_str(&format!("MTU = {mtu}\n"));
        }
        let default_route = match &self.options.routing {
            ClientRouting::PeerAddresses => false,
            ClientRouting::DefaultRoute { dns } => {
                content.push_str(&format!("DNS = {}\n", dns.join(",")));
                true
            }
        };
        for hub_peer in self.options.hub_peers {
            content.push_str(&hub_peer.config_contents(self.options.endpoint_port, default_route));
        }
        content
    }
}

pub(super) fn endpoint_literal(endpoint_ip: &str) -> String {
    endpoint_ip
        .parse::<IpAddr>()
        .ok()
        .filter(IpAddr::is_ipv6)
        .map(|_| format!("[{endpoint_ip}]"))
        .unwrap_or_else(|| endpoint_ip.to_string())
}

pub(super) fn interface_addresses() -> Result<(String, Option<String>)> {
    if !Path::new(WIREGUARD_CONFIG_PATH).exists() {
        bail!(
            "could not determine the WireGuard interface address because {WIREGUARD_CONFIG_PATH} does not exist"
        );
    }
    let config = fs::read_to_string(WIREGUARD_CONFIG_PATH)
        .with_context(|| format!("failed to read {WIREGUARD_CONFIG_PATH}"))?;
    parse_interface_addresses(&config).with_context(|| {
        format!("could not determine the WireGuard interface address from {WIREGUARD_CONFIG_PATH}")
    })
}

pub(super) fn parse_interface_addresses(config: &str) -> Result<(String, Option<String>)> {
    for line in config.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if let Some(rest) = line.strip_prefix("Address =") {
            let mut wireguard_ipv4 = None;
            let mut wireguard_ipv6 = None;
            for address in rest
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                let address = address.split('/').next().unwrap_or_default().trim();
                if address.is_empty() {
                    continue;
                }
                if let Ok(address) = normalize_wireguard_ipv4(address) {
                    wireguard_ipv4 = Some(address);
                    continue;
                }
                if let Ok(address) = normalize_wireguard_ipv6(address) {
                    wireguard_ipv6 = Some(address);
                    continue;
                }
                bail!("wireguard interface address is invalid");
            }
            if let Some(wireguard_ipv4) = wireguard_ipv4 {
                return Ok((wireguard_ipv4, wireguard_ipv6));
            }
        }
    }
    bail!("config has no Address line with a WireGuard IPv4 address")
}

#[cfg(test)]
mod tests {
    use aegis_dto::HostId;

    use super::{ClientConfig, ClientConfigOptions, ClientRouting, HubPeer};

    #[test]
    fn client_config_includes_local_and_hub_ipv4_and_ipv6() {
        let hubs = [HubPeer {
            host_id: "00000000-0000-4000-8000-000000000001"
                .parse::<HostId>()
                .expect("test host UUID"),
            endpoint_ip: "203.0.113.10".to_string(),
            public_key: "hub-public-key".to_string(),
            wireguard_ipv4: "10.75.1.1".to_string(),
            wireguard_ipv6: "fd75::1:1".to_string(),
        }];
        let config = ClientConfig::new(ClientConfigOptions {
            private_key: "private-key",
            wireguard_ipv4: "10.75.1.50",
            wireguard_ipv6: "fd75::1:50",
            hub_peers: &hubs,
            endpoint_port: 51820,
            mtu: None,
            routing: ClientRouting::PeerAddresses,
        })
        .expect("valid client config")
        .contents();

        assert!(config.contains("[Interface]\nAddress = 10.75.1.50/32,fd75::1:50/128\n"));
        assert!(config.contains("AllowedIPs = 10.75.1.1/32,fd75::1:1/128\n"));
    }

    #[test]
    fn default_route_client_requires_one_gateway_and_valid_dns() {
        fn options<'a>(hub_peers: &'a [HubPeer], dns: &'a [String]) -> ClientConfigOptions<'a> {
            ClientConfigOptions {
                private_key: "private-key",
                wireguard_ipv4: "10.75.1.50",
                wireguard_ipv6: "fd75::1:50",
                hub_peers,
                endpoint_port: 51820,
                mtu: Some(1380),
                routing: ClientRouting::DefaultRoute { dns },
            }
        }

        let hubs = [HubPeer {
            host_id: "00000000-0000-4000-8000-000000000001"
                .parse::<HostId>()
                .expect("test host UUID"),
            endpoint_ip: "34.123.45.67".to_string(),
            public_key: "public-key".to_string(),
            wireguard_ipv4: "10.75.1.1".to_string(),
            wireguard_ipv6: "fd75::1:1".to_string(),
        }];

        assert!(ClientConfig::new(options(&[], &["1.1.1.1".to_string()])).is_err());
        assert!(ClientConfig::new(options(&hubs, &[])).is_err());
        assert!(ClientConfig::new(options(&hubs, &["not-an-address".to_string()])).is_err());
        assert!(ClientConfig::new(options(&hubs, &["1.1.1.1".to_string()])).is_ok());
    }
}
