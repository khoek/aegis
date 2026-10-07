use std::{collections::BTreeMap, net::IpAddr};

use aegis_dto::protocol::{AegisMeshConfig, AegisNetworkMemberInternalAddresses};
use anyhow::{Context, Result, ensure};

pub(super) struct LeafOptions<'a> {
    pub mesh: &'a AegisMeshConfig,
    pub internal: &'a AegisNetworkMemberInternalAddresses,
    pub interfaces: &'a [String],
    pub control_socket: &'a str,
    pub state_file: &'a str,
}

impl LeafOptions<'_> {
    pub fn render(&self) -> Result<String> {
        let ipv4 = self.internal.ipv4.parse::<std::net::Ipv4Addr>()?;
        let ipv6 = self.internal.ipv6.parse::<std::net::Ipv6Addr>()?;
        super::parse_ipv4_subnet(&self.mesh.subnet_ipv4)?;
        super::parse_ipv6_subnet(&self.mesh.subnet_ipv6)?;
        ensure!(
            super::mesh_contains_ip(self.mesh, ipv4.into())
                && super::mesh_contains_ip(self.mesh, ipv6.into()),
            "stable addresses must belong to their mesh subnets"
        );
        for path in [self.control_socket, self.state_file] {
            ensure!(
                path.starts_with('/')
                    && path
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b)),
                "invalid Babel runtime path"
            );
        }
        let mut config = format!(
            "random-id true\nskip-kernel-setup true\nlocal-path {}\nstate-file {}\n\
             default type wireless rxcost 256 hello-interval 1 update-interval 4 \
             enable-timestamps true rtt-decay 42 rtt-min 10 rtt-max 350 max-rtt-penalty 256 v4-via-v6 false\n\
             in ip {} eq 32 allow\nin ip {} eq 128 allow\nin deny\n\
             out ip {ipv4}/32 eq 32 allow\nout ip {ipv6}/128 eq 128 allow\nout deny\n\
             redistribute local ip {ipv4}/32 eq 32 allow\n\
             redistribute local ip {ipv6}/128 eq 128 allow\n\
             redistribute local deny\nredistribute deny\n",
            self.control_socket, self.state_file, self.mesh.subnet_ipv4, self.mesh.subnet_ipv6,
        );
        for interface in self.interfaces {
            ensure!(
                interface.strip_prefix("feth").is_some_and(
                    |index| !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit())
                ),
                "invalid Babel Ethernet interface"
            );
            config.push_str(&format!("interface {interface}\n"));
        }
        Ok(config)
    }
}

pub(super) fn validation_arguments(configuration: &str) -> Vec<&str> {
    configuration
        .lines()
        .filter(|line| !line.trim().is_empty())
        .flat_map(|line| ["-C", line])
        .chain(std::iter::once("-V"))
        .collect()
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct InstalledRoute {
    pub address: IpAddr,
    pub interface: String,
}

pub(super) fn installed_routes(dump: &str) -> Result<Vec<InstalledRoute>> {
    let mut routes = Vec::new();
    for line in dump.lines() {
        let words = line.split_whitespace().collect::<Vec<_>>();
        if words.get(1) != Some(&"route") {
            continue;
        }
        let fields = words.get(3..).context("truncated Babel route")?;
        ensure!(fields.len() % 2 == 0, "unpaired Babel route fields");
        let fields = fields
            .chunks_exact(2)
            .map(|pair| (pair[0], pair[1]))
            .collect::<BTreeMap<_, _>>();
        if fields.get("installed") != Some(&"yes") {
            continue;
        }
        let prefix = fields.get("prefix").context("Babel route omitted prefix")?;
        let (address, length) = prefix
            .split_once('/')
            .context("invalid Babel route prefix")?;
        let address = address.parse::<IpAddr>()?;
        ensure!(
            length == if address.is_ipv4() { "32" } else { "128" },
            "Babel installed a non-host route"
        );
        routes.push(InstalledRoute {
            address,
            interface: fields
                .get("if")
                .context("Babel route omitted interface")?
                .to_string(),
        });
    }
    Ok(routes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configuration() -> Result<String> {
        LeafOptions {
            mesh: &AegisMeshConfig {
                endpoint_port: 51820,
                overlay_mtu: 1280,
                subnet_ipv4: "10.75.0.0/16".into(),
                subnet_ipv6: "fd75::/64".into(),
                wireguard_subnet_ipv4: "10.75.1.0/24".into(),
                wireguard_subnet_ipv6: "fd75::1:0/120".into(),
                host_dns_suffix: None,
            },
            internal: &AegisNetworkMemberInternalAddresses {
                ipv4: "10.75.0.3".into(),
                ipv6: "fd75::3".into(),
            },
            interfaces: &["feth0".into(), "feth2".into()],
            control_socket: "/private/var/run/aegis/babel-test.sock",
            state_file: "/private/var/lib/aegis/native/test.babel",
        }
        .render()
    }

    #[test]
    fn leaf_policy_advertises_only_stable_host_addresses_without_changing_system_forwarding() {
        let config = configuration().unwrap();
        assert!(config.contains("skip-kernel-setup true\n"));
        assert!(config.contains(
            "out ip 10.75.0.3/32 eq 32 allow\nout ip fd75::3/128 eq 128 allow\nout deny\n"
        ));
        assert!(config.contains("redistribute local deny\nredistribute deny\n"));
        assert!(!config.contains("0.0.0.0/0"));
    }

    #[test]
    #[ignore = "requires a compiled upstream babeld in AEGIS_TEST_BABELD"]
    fn configuration_is_accepted_by_upstream_babeld_without_kernel_changes() {
        let binary = std::env::var_os("AEGIS_TEST_BABELD").expect("AEGIS_TEST_BABELD");
        // -C parses immediately; -V exits before daemon initialization or any kernel mutation.
        crate::command::require_success(
            "validate native Babel configuration",
            std::process::Command::new(binary)
                .args(validation_arguments(&configuration().unwrap())),
        )
        .unwrap();
    }

    #[test]
    fn only_installed_host_routes_are_reported() {
        let dump = "add route 1 prefix 10.75.0.1/32 from 0.0.0.0/0 installed yes id 1 metric 256 refmetric 0 via fe80::1 if feth4\n\
                    add route 2 prefix fd75::2/128 from ::/0 installed no id 2 metric 512 refmetric 0 via fe80::2 if feth6\n";
        assert_eq!(
            installed_routes(dump).unwrap(),
            vec![InstalledRoute {
                address: "10.75.0.1".parse().unwrap(),
                interface: "feth4".into(),
            }]
        );
        assert!(installed_routes("add route 1 prefix 0.0.0.0/0 installed yes if feth4").is_err());
        assert!(installed_routes("add route 1 prefix").is_err());
    }
}
