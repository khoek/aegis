use aegis_dto::{AegisHostMode, HostId, protocol::AegisNetworkConfig};
use anyhow::{Context, Result, bail, ensure};
use capulus::shell::shell_quote as sh_quote;

use crate::agent::{
    BABEL_OVERLAY_PREFIX, BABEL_VXLAN_PORT, bird_config_contents, peer_overlay_name,
    peer_overlay_transit_addrs, peer_overlay_vni,
};
use crate::apparmor;
use crate::cli::AgentMode;
use crate::config::CachedHost;
use crate::ui;
use crate::wireguard_endpoint::wireguard_endpoint_ipv4;

use super::{
    BIRD_SERVICE_NAME, WIREGUARD_CONFIG_PATH, WIREGUARD_DIR, WIREGUARD_INTERFACE,
    WIREGUARD_PRIVATE_KEY_PATH, WIREGUARD_UNIT_PREFIX, WIREGUARD_UNIT_TEMPLATE_PATH, host,
    wireguard,
};

pub(super) struct HubPeerSelection {
    local_host_id: HostId,
}

impl HubPeerSelection {
    pub(super) fn new(local_host_id: HostId) -> Self {
        Self { local_host_id }
    }

    pub(super) fn select_from_hosts(
        &self,
        hosts: Vec<CachedHost>,
    ) -> Result<Vec<wireguard::HubPeer>> {
        let mut hubs = hosts
            .into_iter()
            .filter(|host| host.mode == AegisHostMode::Hub && host.host_id != self.local_host_id)
            .collect::<Vec<_>>();
        hubs.sort_by(|left, right| left.alias().cmp(right.alias()));
        let mut hub_peers = Vec::with_capacity(hubs.len());
        for hub in hubs {
            let Some(endpoint_ip) = wireguard_endpoint_ipv4(hub.wireguard_endpoints()) else {
                ui::warn(&format!(
                    "skipping hub `{}` because it has no IPv4 WireGuard endpoint",
                    hub.alias()
                ));
                continue;
            };
            let Some(public_key) = hub.wireguard_public_key().map(str::to_string) else {
                ui::warn(&format!(
                    "skipping hub `{}` because it has no WireGuard public key",
                    hub.alias()
                ));
                continue;
            };
            let Some(wireguard_ipv4) = hub.wireguard_ipv4().map(str::to_string) else {
                ui::warn(&format!(
                    "skipping hub `{}` because it has no WireGuard IPv4 address",
                    hub.alias()
                ));
                continue;
            };
            let Some(wireguard_ipv6) = hub.wireguard_ipv6().map(str::to_string) else {
                ui::warn(&format!(
                    "skipping hub `{}` because it has no WireGuard IPv6 address",
                    hub.alias()
                ));
                continue;
            };
            hub_peers.push(wireguard::HubPeer {
                host_id: hub.host_id,
                endpoint_ip,
                public_key,
                wireguard_ipv4,
                wireguard_ipv6,
            });
        }
        if hub_peers.is_empty() {
            bail!(
                "no active hub hosts with a published WireGuard endpoint are currently published by the aegis API"
            );
        }
        Ok(hub_peers)
    }
}

pub(super) struct BootstrapMeshScript<'a> {
    local: &'a CachedHost,
    hub_peers: &'a [wireguard::HubPeer],
    network: &'a AegisNetworkConfig,
    mode: AgentMode,
}

impl<'a> BootstrapMeshScript<'a> {
    pub(super) fn new(
        local: &'a CachedHost,
        hub_peers: &'a [wireguard::HubPeer],
        network: &'a AegisNetworkConfig,
        mode: AgentMode,
    ) -> Self {
        Self {
            local,
            hub_peers,
            network,
            mode,
        }
    }

    pub(super) fn render(&self) -> Result<String> {
        let mesh = self
            .network
            .mesh
            .as_ref()
            .context("network has no managed mesh")?;
        ensure!(
            u32::from(self.network.wireguard.mtu)
                >= u32::from(mesh.overlay_mtu) + u32::from(aegis_dto::mtu::VXLAN_OVER_IPV4),
            "WireGuard MTU must leave 50 bytes for the IPv4 VXLAN overlay"
        );
        let (wireguard_ipv4, wireguard_ipv6) = host::host_wireguard_identity(self.local)?;
        let config = wireguard::ClientConfig::new(wireguard::ClientConfigOptions {
            private_key: "$PRIVATE_KEY",
            wireguard_ipv4: &wireguard_ipv4,
            wireguard_ipv6: &wireguard_ipv6,
            hub_peers: self.hub_peers,
            endpoint_port: self.network.wireguard.endpoint_port,
            mtu: Some(self.network.wireguard.mtu),
            routing: wireguard::ClientRouting::PeerAddresses,
        })?
        .contents();
        let expected_overlays = self
            .hub_peers
            .iter()
            .map(|peer| sh_quote(&peer_overlay_name(&peer.host_id)))
            .collect::<Vec<_>>()
            .join(" ");
        let overlay_setup = self
            .hub_peers
            .iter()
            .map(|peer| {
                let name = peer_overlay_name(&peer.host_id);
                let transit = peer_overlay_transit_addrs(&self.local.host_id, &peer.host_id);
                format!(
                    "ensure_overlay {name} {vni} {remote_wireguard_ipv4} {transit_ipv4} {transit_ipv6}\n",
                    name = sh_quote(&name),
                    vni = peer_overlay_vni(&self.local.host_id, &peer.host_id),
                    remote_wireguard_ipv4 = sh_quote(&peer.wireguard_ipv4),
                    transit_ipv4 = sh_quote(&transit.local_ipv4.to_string()),
                    transit_ipv6 = sh_quote(&transit.local_ipv6.to_string()),
                )
            })
            .collect::<String>();
        let loopback_setup = LoopbackInternalAddresses::new(self.local).render();
        let bird_config = bird_config_contents(mesh, self.mode, self.local)?;
        Ok(format!(
            r#"set -euo pipefail
source /etc/os-release
if [[ "${{ID:-}}" != "ubuntu" && "${{ID:-}}" != "arch" ]]; then
  echo "Unsupported Linux distribution: ${{ID:-unknown}}" >&2
  exit 1
fi
sudo install -d -m 755 {wireguard_dir}
PRIVATE_KEY="$(sudo cat {private_key_path})"
cat <<EOF_WIREGUARD | sudo tee {config_path} >/dev/null
{config}
EOF_WIREGUARD
sudo chmod 600 {config_path}
{apparmor_setup}
cat <<'EOF_AEGIS_WIREGUARD_UNIT' | sudo tee {wireguard_unit_path} >/dev/null
{wireguard_unit}
EOF_AEGIS_WIREGUARD_UNIT
sudo chmod 644 {wireguard_unit_path}
sudo systemctl daemon-reload
sudo systemctl enable {wireguard_unit_prefix}{interface}
sudo systemctl restart {wireguard_unit_prefix}{interface}
expected_overlays=({expected_overlays})
keep_overlay() {{
  local name="$1"
  local expected
  for expected in "${{expected_overlays[@]}}"; do
    if [[ "$expected" == "$name" ]]; then
      return 0
    fi
  done
  return 1
}}
ensure_overlay() {{
  local name="$1"
  local vni="$2"
  local remote_wireguard_ipv4="$3"
  local transit_ipv4="$4"
  local transit_ipv6="$5"
  local details addresses
  details="$(ip -d link show dev "$name" 2>/dev/null | tr '\\\n' '  ' || true)"
  if [[ "$details" != *"vxlan"* ]] \
    || [[ "$details" != *"vxlan id $vni "* ]] \
    || [[ "$details" != *" remote $remote_wireguard_ipv4 "* ]] \
    || [[ "$details" != *" local {wireguard_ipv4} "* ]] \
    || [[ "$details" != *" dev {interface} "* ]] \
    || [[ "$details" != *" dstport {vxlan_port} "* ]] \
    || [[ "$details" != *"nolearning"* ]]; then
    if [[ -n "$details" ]]; then
      sudo ip link del dev "$name"
    fi
    sudo ip link add "$name" type vxlan id "$vni" local {wireguard_ipv4} remote "$remote_wireguard_ipv4" dev {interface} dstport {vxlan_port} nolearning
  fi
  addresses="$(ip -o address show dev "$name" 2>/dev/null || true)"
  if [[ "$addresses" != *" $transit_ipv4/30 "* ]] || [[ "$addresses" != *" $transit_ipv6/127 "* ]]; then
    sudo ip -4 address flush dev "$name" scope global
    sudo ip -6 address flush dev "$name" scope global
    sudo ip -4 address replace "$transit_ipv4/30" dev "$name"
    sudo ip -6 address replace "$transit_ipv6/127" dev "$name"
  fi
  sudo ip link set dev "$name" mtu {overlay_mtu}
  sudo ip link set dev "$name" up
  sudo sysctl -w "net.ipv4.conf.$name.rp_filter=2" >/dev/null
}}
while IFS= read -r line; do
  name="${{line#*: }}"
  name="${{name%%:*}}"
  name="${{name%%@*}}"
  if [[ "$name" == {overlay_prefix}* ]] && ! keep_overlay "$name"; then
    sudo ip link del dev "$name"
  fi
done < <(ip -o link show)
sudo sysctl -w net.ipv4.conf.all.rp_filter=1 >/dev/null
sudo sysctl -w net.ipv4.conf.default.rp_filter=1 >/dev/null
sudo sysctl -w net.ipv4.conf.{interface}.rp_filter=1 >/dev/null
{loopback_setup}sudo ip link set dev lo up
{overlay_setup}cat <<'EOF_BIRD' | sudo tee {bird_config_path} >/dev/null
{bird_config}
EOF_BIRD
sudo chmod 644 {bird_config_path}
sudo systemctl enable {bird_service}
sudo ip route flush proto bird || true
sudo ip -6 route flush proto bird || true
sudo systemctl restart {bird_service}

"#,
            apparmor_setup = apparmor::wireguard_access_install_shell(),
            bird_config = bird_config,
            bird_config_path = crate::platform::bird_config_path(self.local.platform)?,
            bird_service = BIRD_SERVICE_NAME,
            config = config,
            config_path = WIREGUARD_CONFIG_PATH,
            expected_overlays = expected_overlays,
            interface = WIREGUARD_INTERFACE,
            loopback_setup = loopback_setup,
            overlay_mtu = mesh.overlay_mtu,
            overlay_prefix = BABEL_OVERLAY_PREFIX,
            overlay_setup = overlay_setup,
            private_key_path = WIREGUARD_PRIVATE_KEY_PATH,
            vxlan_port = BABEL_VXLAN_PORT,
            wireguard_dir = WIREGUARD_DIR,
            wireguard_ipv4 = wireguard_ipv4,
            wireguard_unit = wireguard_unit_template_contents(),
            wireguard_unit_path = WIREGUARD_UNIT_TEMPLATE_PATH,
            wireguard_unit_prefix = WIREGUARD_UNIT_PREFIX,
        ))
    }
}

fn wireguard_unit_template_contents() -> String {
    format!(
        "[Unit]
Description=aegis WireGuard interface %i
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash /usr/bin/wg-quick up {WIREGUARD_DIR}/%i.conf
ExecStop=/bin/bash /usr/bin/wg-quick down {WIREGUARD_DIR}/%i.conf

[Install]
WantedBy=multi-user.target"
    )
}

struct LoopbackInternalAddresses<'a> {
    host: &'a CachedHost,
}

impl<'a> LoopbackInternalAddresses<'a> {
    fn new(host: &'a CachedHost) -> Self {
        Self { host }
    }

    fn render(&self) -> String {
        let Some(internal) = self.host.internal.as_ref() else {
            return String::new();
        };
        [
            format!(
                "sudo ip -4 address replace {address} dev lo\n",
                address = sh_quote(&format!("{}/32", internal.ipv4)),
            ),
            format!(
                "sudo ip -6 address replace {address} dev lo\n",
                address = sh_quote(&format!("{}/128", internal.ipv6)),
            ),
        ]
        .join("")
    }
}
