use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use aegis_dto::{
    HostAlias, HostId,
    v1::{
        AegisDirectGateway, AegisSatellite, AegisSatelliteCreateRequest,
        AegisSatelliteProvisionResponse, AegisSatelliteStatus,
    },
};
use anyhow::{Context, Result, bail};
use qrcode::{QrCode, render::unicode};
use serde::Serialize;
use ssh_key::{Algorithm, LineEnding, PrivateKey, rand_core::OsRng};

use crate::api::AuthenticatedApiClient;
use crate::cli::{SatelliteArgs, SatelliteCommands, SatellitePairArgs, SatelliteSlugArgs};
use crate::ui::{self, LiveRow, TaskOptions, TaskVisibility};
use crate::wireguard_endpoint::preferred_wireguard_endpoint_ip_with_ipv6_support;

use super::{system, wireguard};

const GATEWAY_READY_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const SATELLITE_ONLINE_SECONDS: i64 = 180;
pub(super) fn run(api_base_override: Option<&str>, args: &SatelliteArgs) -> Result<i32> {
    match &args.command {
        SatelliteCommands::Pair(args) => pair(api_base_override, args),
        SatelliteCommands::List => list(api_base_override),
        SatelliteCommands::Show(args) => show(api_base_override, args),
        SatelliteCommands::Revoke(args) => revoke(api_base_override, args),
    }
}

fn pair(api_base_override: Option<&str>, args: &SatellitePairArgs) -> Result<i32> {
    if args.no_qr && args.out.is_none() {
        bail!("--no-qr requires --out because otherwise every credential would be discarded");
    }
    if let Some(output_directory) = args.out.as_deref()
        && output_directory.exists()
    {
        bail!(
            "satellite output directory {} already exists",
            output_directory.display()
        );
    }

    let workflow = ui::task(TaskOptions {
        label: format!("Pairing satellite `{}`", args.slug),
        visibility: TaskVisibility::Immediate,
        ..TaskOptions::default()
    })?;
    workflow.set_phase("generating WireGuard and SSH identities");
    let wireguard_keypair = wireguard::Keypair::generate()?;
    let ssh_private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .context("failed to generate satellite SSH key")?;
    let ssh_public_key = ssh_private_key
        .public_key()
        .to_openssh()
        .context("failed to encode satellite SSH public key")?;
    workflow.set_phase("loading administrator credentials");
    let mut api = AuthenticatedApiClient::load(api_base_override)?;
    api.require_user_admin("aegis manage satellite pair")?;
    let request = AegisSatelliteCreateRequest {
        wireguard_public_key: wireguard_keypair.public_key.clone(),
        ssh_public_key,
    };
    workflow.set_phase("creating the satellite and preparing every gateway");
    let provision = prepare_satellite(&mut api, &args.slug, &request)?;
    workflow.set_phase("building import credentials");
    let bundle =
        match SatelliteBundle::new(&wireguard_keypair.private_key, &ssh_private_key, &provision) {
            Ok(bundle) => bundle,
            Err(error) => {
                revoke_failed_pair(&mut api, &args.slug, "credential generation");
                return Err(error);
            }
        };

    workflow.set_phase("rendering credential output");
    let qr_output = if args.no_qr {
        None
    } else {
        match bundle.render_qr_output() {
            Ok(output) => Some(output),
            Err(error) if args.out.is_some() => {
                ui::warn(&format!(
                    "the credential bundle is complete, but QR rendering failed: {error:#}"
                ));
                None
            }
            Err(error) => {
                revoke_failed_pair(&mut api, &args.slug, "QR rendering failure");
                return Err(error);
            }
        }
    };

    if let Some(output_directory) = args.out.as_deref()
        && let Err(error) = bundle.write_atomic(output_directory)
    {
        revoke_failed_pair(&mut api, &args.slug, "bundle write failure");
        return Err(error);
    }

    if let Some(qr_output) = qr_output {
        let write_result = ui::suspend(|| {
            let mut stdout = io::stdout().lock();
            stdout
                .write_all(qr_output.as_bytes())
                .and_then(|()| stdout.flush())
        });
        if let Err(error) = write_result {
            let error = anyhow::Error::new(error).context("failed to print satellite QR codes");
            if args.out.is_some() {
                ui::warn(&format!(
                    "the credential bundle is complete, but QR output failed: {error:#}"
                ));
            } else {
                revoke_failed_pair(&mut api, &args.slug, "QR output failure");
                return Err(error);
            }
        }
    }
    let gateway_count = provision.gateways.len();
    workflow.finish(if let Some(output_directory) = args.out.as_deref() {
        format!(
            "Satellite `{}` was paired with {gateway_count} gateway{}; credentials were written to {}.",
            args.slug,
            if gateway_count == 1 { "" } else { "s" },
            output_directory.display()
        )
    } else {
        format!(
            "Satellite `{}` was paired with {gateway_count} gateway{}; credentials were displayed and were not written to disk.",
            args.slug,
            if gateway_count == 1 { "" } else { "s" }
        )
    });
    Ok(0)
}

fn revoke_failed_pair(api: &mut AuthenticatedApiClient, slug: &str, reason: &str) {
    if let Err(cleanup_error) = api.delete_satellite(slug) {
        ui::warn(&format!(
            "failed to revoke satellite `{slug}` after {reason}: {cleanup_error:#}"
        ));
    }
}

fn list(api_base_override: Option<&str>) -> Result<i32> {
    let task = ui::task(TaskOptions {
        label: "Loading satellites".to_string(),
        ..TaskOptions::default()
    })?;
    let mut api = AuthenticatedApiClient::load(api_base_override)?;
    api.require_user_admin("aegis manage satellite list")?;
    let satellites = api.get_satellites()?.satellites;
    task.finish_and_clear();
    if satellites.is_empty() {
        println!("No satellites are paired.");
        return Ok(0);
    }
    let rows = satellites
        .into_values()
        .map(|satellite| {
            let status = satellite_status_summary(&satellite);
            (
                satellite.slug,
                satellite.account,
                satellite.wireguard.ipv4,
                satellite.owner_principal,
                status,
            )
        })
        .collect::<Vec<_>>();
    let slug_width = rows.iter().map(|row| row.0.len()).max().unwrap_or_default();
    let account_width = rows.iter().map(|row| row.1.len()).max().unwrap_or_default();
    let address_width = rows.iter().map(|row| row.2.len()).max().unwrap_or_default();
    let owner_width = rows.iter().map(|row| row.3.len()).max().unwrap_or_default();
    for (slug, account, address, owner, status) in rows {
        println!(
            "{slug:<slug_width$} · {account:<account_width$} · {address:<address_width$} · {owner:<owner_width$} · {status}"
        );
    }
    Ok(0)
}

fn show(api_base_override: Option<&str>, args: &SatelliteSlugArgs) -> Result<i32> {
    let task = ui::task(TaskOptions {
        label: format!("Loading satellite `{}`", args.slug),
        ..TaskOptions::default()
    })?;
    let mut api = AuthenticatedApiClient::load(api_base_override)?;
    api.require_user_admin("aegis manage satellite show")?;
    let details = api.get_satellite(&args.slug)?;
    task.finish_and_clear();
    println!("slug: {}", details.satellite.slug);
    println!("account: {}", details.satellite.account);
    println!("owner: {}", details.satellite.owner_principal);
    println!("ipv4: {}", details.satellite.wireguard.ipv4);
    println!("ipv6: {}", details.satellite.wireguard.ipv6);
    println!(
        "gateways: {}",
        details
            .gateways
            .values()
            .map(|gateway| gateway.aliases.primary().as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    let status = &details.satellite.status;
    println!("gateway status:");
    for presence in status.gateways.values() {
        let observed = presence
            .observed_unix
            .map(age_text)
            .unwrap_or_else(|| "not reported".to_string());
        let handshake = presence
            .latest_handshake_unix
            .map(age_text)
            .unwrap_or_else(|| "never".to_string());
        println!(
            "  {}: {} · report {observed} · handshake {handshake}",
            presence.aliases.primary(),
            if presence.installed {
                "installed"
            } else {
                "pending"
            }
        );
    }
    if let Some(activity) = &status.last_broker_use {
        println!(
            "last SSH handoff: {} via {} to {}",
            age_text(activity.used_unix),
            activity.gateway_aliases.primary(),
            activity.target_aliases.primary()
        );
    } else {
        println!("last SSH handoff: never");
    }
    Ok(0)
}

fn prepare_satellite(
    api: &mut AuthenticatedApiClient,
    slug: &str,
    request: &AegisSatelliteCreateRequest,
) -> Result<AegisSatelliteProvisionResponse> {
    let mutation = ui::task(TaskOptions {
        label: format!("Creating satellite `{slug}`"),
        visibility: TaskVisibility::Immediate,
        ..TaskOptions::default()
    })?;
    mutation.set_phase("committing satellite identity and gateway assignments");
    let provision = match api.put_satellite(slug, request) {
        Ok(provision) => provision,
        Err(error) => {
            // The PUT is idempotent, but a transport failure can happen after the API
            // commits it. A freshly generated key unambiguously identifies the record
            // created by this invocation, so remove only that exact record.
            if api.get_satellite(slug).is_ok_and(|details| {
                details.satellite.wireguard.public_key == request.wireguard_public_key
            }) && let Err(cleanup_error) = api.delete_satellite(slug)
            {
                ui::warn(&format!(
                    "failed to revoke satellite `{slug}` after provisioning failed: {cleanup_error:#}"
                ));
            }
            mutation.abandon(
                "Satellite creation failed; exact-record cleanup was attempted after ambiguous transport state",
            );
            return Err(error);
        }
    };
    mutation.finish(format!(
        "Satellite identity committed; assigned gateways: {}",
        provision
            .gateways
            .values()
            .map(|gateway| gateway.aliases.primary().as_str())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    if let Err(error) = wait_for_gateways(api, slug, &provision.gateways) {
        if let Err(cleanup_error) = api.delete_satellite(slug) {
            ui::warn(&format!(
                "failed to revoke satellite `{slug}` after gateway preparation failed: {cleanup_error:#}"
            ));
        }
        return Err(error);
    }
    Ok(provision)
}

fn wait_for_gateways(
    api: &mut AuthenticatedApiClient,
    slug: &str,
    gateways: &BTreeMap<HostId, AegisDirectGateway>,
) -> Result<()> {
    let gateway_ids = gateways.keys().copied().collect::<Vec<_>>();
    let group = ui::live_group(format!(
        "Waiting for {} satellite gateway{}",
        gateways.len(),
        if gateways.len() == 1 { "" } else { "s" }
    ))?;
    let rows = gateways
        .iter()
        .map(|(host_id, gateway)| {
            Ok((
                *host_id,
                group.row(
                    gateway.aliases.primary().as_str(),
                    "waiting for agent reconciliation",
                )?,
            ))
        })
        .collect::<Result<BTreeMap<HostId, LiveRow>>>()?;
    let started = Instant::now();
    loop {
        let details = match api.get_satellite(slug) {
            Ok(details) => details,
            Err(error) => {
                group.fail("Satellite gateway status polling failed");
                return Err(error);
            }
        };
        let status = &details.satellite.status;
        let now = crate::config::now_unix();
        let mut ready = 0;
        for host_id in &gateway_ids {
            let presence = status.gateways.get(host_id);
            let is_fresh = presence
                .and_then(|presence| presence.observed_unix)
                .is_some_and(|observed| now.saturating_sub(observed) <= SATELLITE_ONLINE_SECONDS);
            let installed = presence.is_some_and(|presence| presence.installed) && is_fresh;
            if installed {
                ready += 1;
                if let Some(row) = rows.get(host_id) {
                    row.finish("ready");
                }
            } else if let Some(row) = rows.get(host_id) {
                let message = presence
                    .and_then(|presence| presence.observed_unix)
                    .map(|observed| {
                        format!("waiting for reconciliation · report {}", age_text(observed))
                    })
                    .unwrap_or_else(|| "waiting for first gateway report".to_string());
                row.set_detail(message);
            }
        }
        if ready == gateway_ids.len() {
            group.finish(format!(
                "All {} satellite gateways are ready",
                gateway_ids.len()
            ));
            return Ok(());
        }
        if started.elapsed() >= GATEWAY_READY_TIMEOUT {
            for row in rows.values() {
                row.abandon("timed out");
            }
            group.abandon("Satellite gateway convergence timed out");
            bail!(
                "satellite gateways did not install `{slug}` within {} minutes",
                GATEWAY_READY_TIMEOUT.as_secs() / 60
            );
        }
        group.set_summary(format!(
            "Waiting for satellite gateways ({ready}/{} ready; {} elapsed)",
            gateway_ids.len(),
            super::host_list::elapsed_duration_text(started.elapsed())
        ));
        if let Err(error) = ui::sleep(Duration::from_secs(2)) {
            for row in rows.values() {
                row.abandon("interrupted");
            }
            group.abandon("Satellite gateway wait interrupted");
            return Err(error);
        }
    }
}

fn satellite_status_summary(satellite: &AegisSatellite) -> String {
    let status = &satellite.status;
    let Some((gateway, handshake)) = latest_handshake(status) else {
        let installed = status
            .gateways
            .values()
            .filter(|presence| presence.installed)
            .count();
        return format!(
            "never seen · {installed}/{} gateways",
            status.gateways.len()
        );
    };
    let age = crate::config::now_unix().saturating_sub(handshake);
    if age <= SATELLITE_ONLINE_SECONDS {
        format!("online via {gateway}")
    } else {
        format!("last seen {} via {gateway}", age_text(handshake))
    }
}

fn latest_handshake(status: &AegisSatelliteStatus) -> Option<(&HostAlias, i64)> {
    status
        .gateways
        .values()
        .filter_map(|presence| {
            presence
                .latest_handshake_unix
                .map(|handshake| (presence.aliases.primary(), handshake))
        })
        .max_by_key(|(_, handshake)| *handshake)
}

fn age_text(unix: i64) -> String {
    let age = crate::config::now_unix().saturating_sub(unix).max(0) as u64;
    format!(
        "{} ago",
        super::host_list::elapsed_duration_text(Duration::from_secs(age))
    )
}

fn revoke(api_base_override: Option<&str>, args: &SatelliteSlugArgs) -> Result<i32> {
    let task = ui::task(TaskOptions {
        label: format!("Revoking satellite `{}`", args.slug),
        visibility: TaskVisibility::Immediate,
        ..TaskOptions::default()
    })?;
    let mut api = AuthenticatedApiClient::load(api_base_override)?;
    api.require_user_admin("aegis manage satellite revoke")?;
    api.delete_satellite(&args.slug)?;
    task.finish(format!("Satellite `{}` revoked", args.slug));
    Ok(0)
}

struct SatelliteBundle {
    satellite_slug: String,
    account: String,
    host: String,
    wireguard_profiles: Vec<SatelliteWireGuardProfile>,
    ssh_private_key: String,
    ssh_certificate: String,
    known_hosts: String,
    ssh_import: String,
}

struct SatelliteWireGuardProfile {
    gateway_alias: String,
    kind: ProfileKind,
    contents: String,
}

impl SatelliteBundle {
    fn new(
        wireguard_private_key: &str,
        ssh_private_key: &PrivateKey,
        provision: &AegisSatelliteProvisionResponse,
    ) -> Result<Self> {
        let mut wireguard_profiles = Vec::with_capacity(provision.gateways.len() * 2);
        for gateway in provision.gateways.values() {
            for kind in [ProfileKind::Direct, ProfileKind::FullTunnel] {
                wireguard_profiles.push(SatelliteWireGuardProfile {
                    gateway_alias: gateway.aliases.primary().to_string(),
                    kind,
                    contents: wireguard_profile(wireguard_private_key, provision, gateway, kind)?,
                });
            }
        }

        let ssh_private_key = ssh_private_key
            .to_openssh(LineEnding::LF)
            .context("failed to encode satellite SSH private key")?
            .to_string();
        let gateway_addresses = provision
            .gateways
            .values()
            .flat_map(|gateway| {
                [
                    gateway.wireguard.ipv4.as_str(),
                    gateway.wireguard.ipv6.as_str(),
                ]
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let host = provision
            .gateways
            .values()
            .next()
            .map(|gateway| gateway.wireguard.ipv4.clone())
            .ok_or_else(|| anyhow::anyhow!("satellite bundle has no ready gateways"))?;
        let known_hosts = format!(
            "@cert-authority {} {}\n",
            gateway_addresses.join(","),
            provision.server_ca_public_key.trim()
        );
        let ssh_certificate = provision.ssh_certificate.trim().to_string();
        let ssh_import = serde_json::to_string(&SshImport {
            host: &host,
            port: 22,
            user: &provision.satellite.account,
            private_key: &ssh_private_key,
            certificate: &ssh_certificate,
            known_hosts: known_hosts.trim(),
        })
        .context("failed to encode satellite SSH import")?;

        Ok(Self {
            satellite_slug: provision.satellite.slug.clone(),
            account: provision.satellite.account.clone(),
            host,
            wireguard_profiles,
            ssh_private_key,
            ssh_certificate,
            known_hosts,
            ssh_import,
        })
    }

    fn write_atomic(&self, directory: &Path) -> Result<()> {
        let parent = directory
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        capulus::store::ensure_directory(parent, Some(0o700))?;
        let staging = tempfile::Builder::new()
            .prefix(".aegis-satellite-")
            .tempdir_in(parent)
            .with_context(|| {
                format!(
                    "failed to create staging directory below {}",
                    parent.display()
                )
            })?;
        self.write_files(staging.path(), directory)?;
        fs::rename(staging.path(), directory).with_context(|| {
            format!(
                "failed to publish satellite bundle from {} to {}",
                staging.path().display(),
                directory.display()
            )
        })
    }

    fn write_files(&self, staging_directory: &Path, published_directory: &Path) -> Result<()> {
        for profile in &self.wireguard_profiles {
            write_file(
                staging_directory
                    .join(wireguard_profile_name(&profile.gateway_alias, profile.kind)),
                &profile.contents,
                0o600,
            )?;
        }

        let ssh_config = format!(
            "Host {slug}\n\
               HostName {host}\n\
               User {user}\n\
               Port 22\n\
               IdentityFile {directory}/id_ed25519\n\
               CertificateFile {directory}/id_ed25519-cert.pub\n\
               IdentitiesOnly yes\n\
               StrictHostKeyChecking yes\n\
               UserKnownHostsFile {directory}/known_hosts\n\
               GlobalKnownHostsFile /dev/null\n\
               HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com\n",
            slug = self.satellite_slug,
            host = self.host,
            user = self.account,
            directory = published_directory.display(),
        );
        write_file(
            staging_directory.join("id_ed25519"),
            &self.ssh_private_key,
            0o600,
        )?;
        write_file(
            staging_directory.join("id_ed25519-cert.pub"),
            &super::line_with_newline(&self.ssh_certificate),
            0o644,
        )?;
        write_file(
            staging_directory.join("known_hosts"),
            &self.known_hosts,
            0o644,
        )?;
        write_file(staging_directory.join("ssh_config"), &ssh_config, 0o600)?;
        write_file(
            staging_directory.join("ssh-import.json"),
            &super::line_with_newline(&self.ssh_import),
            0o600,
        )
    }

    fn render_qr_output(&self) -> Result<String> {
        let mut output = String::new();
        for profile in &self.wireguard_profiles {
            let label = match profile.kind {
                ProfileKind::Direct => "direct SSH only",
                ProfileKind::FullTunnel => "full Internet tunnel",
            };
            output.push_str(&render_qr(
                &format!("WireGuard import · {} · {label}", profile.gateway_alias),
                &profile.contents,
            )?);
        }
        output.push_str(&render_qr("SSH import", &self.ssh_import)?);
        Ok(output)
    }
}

fn wireguard_profile(
    wireguard_private_key: &str,
    provision: &AegisSatelliteProvisionResponse,
    gateway: &AegisDirectGateway,
    kind: ProfileKind,
) -> Result<String> {
    let endpoint =
        preferred_wireguard_endpoint_ip_with_ipv6_support(&gateway.wireguard.endpoints, false)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "gateway `{}` has no public endpoint",
                    gateway.aliases.primary()
                )
            })?;
    if kind == ProfileKind::FullTunnel && provision.config.full_tunnel_dns.is_empty() {
        bail!("the Aegis direct gateway has no full-tunnel DNS servers configured");
    }
    Ok(
        wireguard::ClientConfig::new(wireguard::ClientConfigOptions {
            private_key: wireguard_private_key,
            wireguard_ipv4: &provision.satellite.wireguard.ipv4,
            wireguard_ipv6: &provision.satellite.wireguard.ipv6,
            hub_peers: &[wireguard::HubPeer {
                host_id: gateway.host_id,
                endpoint_ip: endpoint,
                public_key: gateway.wireguard.public_key.clone(),
                wireguard_ipv4: gateway.wireguard.ipv4.clone(),
                wireguard_ipv6: gateway.wireguard.ipv6.clone(),
            }],
            endpoint_port: provision.config.endpoint_port,
            mtu: Some(provision.config.mtu),
            routing: match kind {
                ProfileKind::Direct => wireguard::ClientRouting::PeerAddresses,
                ProfileKind::FullTunnel => wireguard::ClientRouting::DefaultRoute {
                    dns: &provision.config.full_tunnel_dns,
                },
            },
        })?
        .contents(),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProfileKind {
    Direct,
    FullTunnel,
}

fn wireguard_profile_name(gateway_alias: &str, kind: ProfileKind) -> String {
    let suffix = match kind {
        ProfileKind::Direct => "direct",
        ProfileKind::FullTunnel => "full-tunnel",
    };
    format!("wireguard-{gateway_alias}-{suffix}.conf")
}

fn write_file(path: PathBuf, contents: &str, mode: u32) -> Result<()> {
    system::TextFile::new(&path).write_atomic(contents, mode)
}

fn render_qr(title: &str, payload: &str) -> Result<String> {
    let qr = QrCode::new(payload.as_bytes())
        .with_context(|| format!("failed to encode {title} QR code"))?;
    Ok(format!(
        "\n{title}\n{}\n",
        qr.render::<unicode::Dense1x2>()
            .quiet_zone(true)
            .dark_color(unicode::Dense1x2::Light)
            .light_color(unicode::Dense1x2::Dark)
            .module_dimensions(1, 1)
            .build()
    ))
}

#[derive(Serialize)]
struct SshImport<'a> {
    host: &'a str,
    port: u16,
    user: &'a str,
    private_key: &'a str,
    certificate: &'a str,
    known_hosts: &'a str,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aegis_dto::{
        HostAlias, HostAliases, HostId,
        v1::{
            AegisDirectGateway, AegisDirectGatewayConfig, AegisDirectWireGuard, AegisSatellite,
            AegisSatelliteProvisionResponse, AegisSatelliteStatus,
        },
    };
    use ssh_key::{Algorithm, PrivateKey, rand_core::OsRng};

    use super::SatelliteBundle;

    #[test]
    fn satellite_bundle_contains_one_wireguard_profile_per_gateway_and_one_ssh_identity() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let output = directory.path().join("pocket-a");
        let ssh_private_key =
            PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("ssh key should generate");
        let gateways = [
            ("00000000-0000-4000-8000-000000000001", "gateway-a"),
            ("00000000-0000-4000-8000-000000000002", "gateway-b"),
        ]
        .into_iter()
        .map(|(host_id, alias)| {
            let host_id = host_id.parse::<HostId>().expect("test host UUID");
            (
                host_id,
                AegisDirectGateway {
                    host_id,
                    aliases: HostAliases::new(vec![
                        alias.parse::<HostAlias>().expect("test host alias"),
                    ])
                    .expect("test host aliases"),
                    wireguard: AegisDirectWireGuard {
                        public_key: format!("{alias}-public-key"),
                        ipv4: "10.77.1.1".to_string(),
                        ipv6: "fd77::1:1".to_string(),
                        endpoints: vec!["203.0.113.8".to_string()],
                    },
                    updated_unix: 10,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
        let provision = AegisSatelliteProvisionResponse {
            satellite: AegisSatellite {
                slug: "pocket-a".to_string(),
                account: "aegis-d-0123456789abcdef01234567".to_string(),
                owner_principal: "OpaqueUserID".to_string(),
                wireguard: AegisDirectWireGuard {
                    public_key: "peer-public-key".to_string(),
                    ipv4: "10.77.1.2".to_string(),
                    ipv6: "fd77::1:2".to_string(),
                    endpoints: Vec::new(),
                },
                created_unix: 10,
                created_by_principal: "OpaqueUserID".to_string(),
                status: AegisSatelliteStatus::default(),
            },
            config: AegisDirectGatewayConfig {
                interface: "wg-aegis-direct".to_string(),
                endpoint_port: 51_822,
                mtu: 1380,
                fwmark: 44_641,
                subnet_ipv4: "10.77.1.0/24".to_string(),
                subnet_ipv6: "fd77::1:0/120".to_string(),
                full_tunnel_dns: vec!["1.1.1.1".to_string(), "2606:4700:4700::1111".to_string()],
            },
            gateways,
            ssh_certificate: "ssh-ed25519-cert-v01@openssh.com certificate".to_string(),
            server_ca_public_key: "ssh-ed25519 server-ca".to_string(),
        };

        let bundle = SatelliteBundle::new("peer-private-key", &ssh_private_key, &provision)
            .expect("bundle should render");
        assert!(!output.exists());
        let qr_output = bundle.render_qr_output().expect("QRs should render");
        assert!(!output.exists());
        assert!(qr_output.contains("gateway-a · direct SSH only"));
        assert!(qr_output.contains("gateway-a · full Internet tunnel"));
        assert!(qr_output.contains("SSH import"));
        bundle.write_atomic(&output).expect("bundle should write");

        for slug in ["gateway-a", "gateway-b"] {
            let direct =
                std::fs::read_to_string(output.join(format!("wireguard-{slug}-direct.conf")))
                    .expect("direct WireGuard config");
            assert!(direct.contains("Address = 10.77.1.2/32,fd77::1:2/128"));
            assert!(direct.contains("AllowedIPs = 10.77.1.1/32,fd77::1:1/128"));
            assert!(!direct.contains("DNS ="));
            assert_eq!(1, direct.matches("[Peer]").count());

            let full =
                std::fs::read_to_string(output.join(format!("wireguard-{slug}-full-tunnel.conf")))
                    .expect("full-tunnel WireGuard config");
            assert!(full.contains("AllowedIPs = 0.0.0.0/0,::/0"));
            assert!(full.contains("DNS = 1.1.1.1,2606:4700:4700::1111"));
            assert!(full.contains("MTU = 1380"));
        }
        let ssh_config = std::fs::read_to_string(output.join("ssh_config")).expect("ssh config");
        assert!(ssh_config.contains("HostName 10.77.1.1"));
        assert!(ssh_config.contains("User aegis-d-0123456789abcdef01234567"));
        assert!(ssh_config.contains("StrictHostKeyChecking yes"));
        assert!(!ssh_config.contains(".aegis-satellite-"));
    }
}
