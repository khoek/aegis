use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    time::{Duration, Instant},
};

use aegis_dto::{AegisHostMode, HostAlias};
use anyhow::{Context, Result, ensure};
use capulus::shell::shell_quote;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::deployment::{Deployment, array, text};
use aegis_tool::{
    client::{self, AuthenticatedApiClient, enrollment as invitation},
    ui,
};

const HUB: &str = "aegis-hub";
const NETWORK: &str = "aegis-hub";
const DESCRIPTION: &str = "Managed by Aegis setup";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Hub {
    subnet_cidr: String,
    host: Option<aegis_dto::HostId>,
}

pub(super) fn validate(deployment: &Deployment) -> Result<()> {
    ensure!(
        !deployment.hub_regions.is_empty(),
        "select at least one hub region"
    );
    for region in deployment.hub_regions.iter().chain(deployment.hubs.keys()) {
        ensure!(
            super::deployment::valid_region(region),
            "invalid hub region: {region}"
        );
    }
    let mut subnets = BTreeSet::new();
    let mut hosts = BTreeSet::new();
    for hub in deployment.hubs.values() {
        ensure!(
            (0..=255).any(|index| hub.subnet_cidr == format!("10.76.{index}.0/24")),
            "invalid hub subnet"
        );
        ensure!(subnets.insert(&hub.subnet_cidr), "duplicate hub subnet");
        if let Some(host) = hub.host {
            ensure!(hosts.insert(host), "duplicate hub host");
        }
    }
    Ok(())
}

pub(super) fn configure(
    deployment: &mut Deployment,
    requested: &[String],
    yes: bool,
) -> Result<()> {
    let cloud = deployment.cloud()?;
    let available = cloud.json(&["compute", "regions", "list"])?;
    let regions: BTreeSet<String> = array(&available)?
        .iter()
        .filter(|region| region["status"] == "UP")
        .map(|region| text(region, "name").map(str::to_owned))
        .collect::<Result<_>>()?;
    let selected = if !requested.is_empty() {
        requested.iter().cloned().collect()
    } else if yes {
        deployment.hub_regions.clone()
    } else {
        // Include saved regions even when unavailable so operators can remove them.
        let mut choices = regions.clone();
        choices.extend(deployment.hub_regions.iter().cloned());
        choices.extend(deployment.hubs.keys().cloned());
        let mut regions: Vec<_> = choices.into_iter().collect();
        regions.sort_by_key(|region| (!deployment.hub_regions.contains(region), region.clone()));
        let labels: Vec<_> = regions
            .iter()
            .map(|region| {
                format!(
                    "{region}{}",
                    if deployment.hubs.contains_key(region) {
                        " (existing)"
                    } else if region == &deployment.config.region {
                        " (suggested)"
                    } else {
                        ""
                    }
                )
            })
            .collect();
        let defaults: Vec<_> = regions
            .iter()
            .map(|region| deployment.hub_regions.contains(region))
            .collect();
        ui::require_interactive("Use --hub-region REGION --yes to choose hubs without a terminal")?;
        ui::detail(
            "One e2-medium VM and reserved address per region. Space selects; Enter confirms. Uncheck an existing region to remove its hub.",
        );
        let indices = ui::suspend(|| {
            dialoguer::MultiSelect::new()
                .with_prompt("Hub regions")
                .items(&labels)
                .defaults(&defaults)
                .max_length(12)
                .interact()
        })?;
        indices
            .into_iter()
            .map(|index| regions[index].clone())
            .collect()
    };
    ensure!(
        !selected.is_empty(),
        "keep at least one hub region; no hub resources were changed"
    );
    for region in &selected {
        ensure!(
            regions.contains(region) || deployment.hubs.contains_key(region),
            "GCP region {region} is unavailable"
        );
    }
    let additions: Vec<_> = selected
        .iter()
        .filter(|region| !deployment.hubs.contains_key(*region))
        .cloned()
        .collect();
    let removals: Vec<_> = deployment
        .hubs
        .keys()
        .filter(|region| !selected.contains(*region))
        .cloned()
        .collect();
    ui::stage(&format!(
        "Hub regions: {}",
        selected.iter().cloned().collect::<Vec<_>>().join(", ")
    ));
    if !additions.is_empty() {
        ui::detail(&format!(
            "Add: {} (billed to {})",
            additions.join(", "),
            cloud.project
        ));
    }
    if !removals.is_empty() {
        ui::warn(&format!(
            "Remove: {}. Their VM disks, addresses, subnets and Aegis host records will be deleted after the selected hubs are healthy.",
            removals.join(", ")
        ));
    }
    if !yes && (!additions.is_empty() || !removals.is_empty()) {
        let accepted = ui::suspend(|| {
            dialoguer::Confirm::new()
                .with_prompt("Apply these hub changes?")
                .default(removals.is_empty())
                .wait_for_newline(true)
                .interact()
        })?;
        ensure!(
            accepted,
            "Hub changes declined; existing resources are retained"
        );
    }
    deployment.hub_regions = selected;
    deployment.persist()?;
    let result = reconcile(deployment);
    if result.is_err() {
        ui::warn(
            "Hub changes stopped. Completed changes and remaining resources are recorded in the deployment receipt; rerun setup to resume.",
        );
    }
    result
}

fn reconcile(deployment: &mut Deployment) -> Result<()> {
    for region in deployment.hub_regions.clone() {
        if !deployment.hubs.contains_key(&region) {
            let subnets = deployment
                .cloud()?
                .json(&["compute", "networks", "subnets", "list"])?;
            let subnet_cidr = allocate_subnet(&deployment.hubs, &subnets)?;
            deployment.hubs.insert(
                region.clone(),
                Hub {
                    subnet_cidr,
                    host: None,
                },
            );
            deployment.persist()?;
        }
        // Provision every selected hub before waiting for readiness. A hub's
        // Babel backbone cannot become ready until at least one other hub is
        // present, so waiting after each individual installation deadlocks a
        // fresh multi-region setup.
        ensure_hub(deployment, &region)?;
    }
    let endpoint = deployment.namespace_endpoint()?;
    let mut api = AuthenticatedApiClient::load(Some(&endpoint))?;
    for region in &deployment.hub_regions {
        let host = deployment
            .hubs
            .get(region)
            .and_then(|hub| hub.host)
            .with_context(|| format!("Hub in {region} has not been enrolled"))?;
        wait(host, region, &mut api)?;
    }
    check_selected(deployment, &mut api)?;
    for region in deployment.hubs.keys().cloned().collect::<Vec<_>>() {
        if !deployment.hub_regions.contains(&region) {
            remove(deployment, &region, &mut api)?;
        }
    }
    Ok(())
}

fn allocate_subnet(hubs: &BTreeMap<String, Hub>, subnets: &Value) -> Result<String> {
    let ranges = array(subnets)?
        .iter()
        .filter(|subnet| suffix(&subnet["network"], NETWORK))
        .map(|subnet| {
            text(subnet, "ipCidrRange").and_then(|cidr| {
                cidr.parse::<ipnet::Ipv4Net>()
                    .context("invalid GCP subnet CIDR")
            })
        })
        .collect::<Result<Vec<_>>>()?;
    (0..=255)
        .map(|index| format!("10.76.{index}.0/24"))
        .find(|cidr| {
            !hubs.values().any(|hub| &hub.subnet_cidr == cidr)
                && ranges.iter().all(|range| {
                    let candidate: ipnet::Ipv4Net = cidr.parse().expect("valid generated subnet");
                    !range.contains(&candidate.network()) && !candidate.contains(&range.network())
                })
        })
        .context("no available hub subnet in 10.76.0.0/16")
}

fn remove(
    deployment: &mut Deployment,
    region: &str,
    api: &mut AuthenticatedApiClient,
) -> Result<()> {
    let cloud = deployment.cloud()?;
    let name = format!("aegis-hub-{region}");
    let instances = cloud.json(&["compute", "instances", "list"])?;
    let addresses = cloud.json(&["compute", "addresses", "list"])?;
    let subnets = cloud.json(&["compute", "networks", "subnets", "list"])?;
    let instance = named(&instances, &name)?;
    let address = regional_named(&addresses, &name, region)?;
    let subnet = regional_named(&subnets, &name, region)?;
    validate_removal(
        instance,
        address,
        subnet,
        region,
        &deployment.hubs[region].subnet_cidr,
    )?;
    ui::stage(&format!("Removing hub in {region}"));
    if let Some(host) = deployment.hubs[region].host {
        if let Some(observed) = api.get_hosts()?.hosts.get(&host) {
            if observed.pending {
                api.delete_enrollment(&host)?;
            } else {
                api.delete_host(&host)?;
            }
            ui::success(&format!(
                "Deleted Aegis host {host} and network memberships"
            ));
        }
        deployment
            .hubs
            .get_mut(region)
            .context("missing hub receipt")?
            .host = None;
        deployment.persist()?;
    }
    if let Some(instance) = instance {
        let zone = text(instance, "zone")?
            .rsplit('/')
            .next()
            .context("hub zone missing")?;
        cloud.json(&[
            "compute",
            "instances",
            "delete",
            &name,
            "--zone",
            zone,
            "--delete-disks=all",
        ])?;
        ui::success(&format!("Deleted hub VM and disk in {region}"));
    }
    if address.is_some() {
        cloud.json(&["compute", "addresses", "delete", &name, "--region", region])?;
        ui::success(&format!("Released hub address in {region}"));
    }
    if subnet.is_some() {
        cloud.json(&[
            "compute", "networks", "subnets", "delete", &name, "--region", region,
        ])?;
        ui::success(&format!("Deleted hub subnet in {region}"));
    }
    deployment.hubs.remove(region);
    deployment.persist()?;
    Ok(())
}

fn validate_removal(
    instance: Option<&Value>,
    address: Option<&Value>,
    subnet: Option<&Value>,
    region: &str,
    cidr: &str,
) -> Result<()> {
    if let Some(instance) = instance {
        let zone = text(instance, "zone")?
            .rsplit('/')
            .next()
            .context("hub zone missing")?;
        ensure!(
            instance["labels"]["managed-by"] == "aegis"
                && suffix(&instance["networkInterfaces"][0]["network"], NETWORK)
                && zone.starts_with(&format!("{region}-")),
            "hub VM ownership or region differs; refusing deletion"
        );
    }
    if let Some(address) = address {
        ensure!(
            address["description"] == DESCRIPTION && suffix(&address["region"], region),
            "hub address ownership differs; refusing deletion"
        );
    }
    if let Some(subnet) = subnet {
        ensure!(
            subnet["description"] == DESCRIPTION
                && suffix(&subnet["network"], NETWORK)
                && suffix(&subnet["region"], region)
                && subnet["ipCidrRange"] == cidr,
            "hub subnet ownership differs; refusing deletion"
        );
    }
    Ok(())
}

pub(super) fn check_all(deployment: &Deployment, api: &mut AuthenticatedApiClient) -> Result<()> {
    ensure!(
        deployment.hubs.keys().cloned().collect::<BTreeSet<_>>() == deployment.hub_regions,
        "hub changes remain incomplete; rerun setup"
    );
    check_selected(deployment, api)
}

fn check_selected(deployment: &Deployment, api: &mut AuthenticatedApiClient) -> Result<()> {
    for region in &deployment.hub_regions {
        let host = deployment
            .hubs
            .get(region)
            .and_then(|hub| hub.host)
            .with_context(|| format!("Hub in {region} has not been enrolled"))?;
        check(host, api).with_context(|| format!("Hub in {region} is not ready"))?;
    }
    Ok(())
}

fn regional_named<'a>(values: &'a Value, name: &str, region: &str) -> Result<Option<&'a Value>> {
    let values = array(values)?;
    let mut matches = values
        .iter()
        .filter(|value| value["name"] == name && suffix(&value["region"], region));
    let value = matches.next();
    ensure!(
        matches.next().is_none(),
        "multiple resources named {name} in {region}"
    );
    Ok(value)
}

fn ensure_hub(deployment: &mut Deployment, region: &str) -> Result<()> {
    let name = format!("aegis-hub-{region}");
    let hub = &deployment.hubs[region];
    let subnet_cidr = hub.subnet_cidr.clone();
    let host_id = hub.host;
    let endpoint = deployment.namespace_endpoint()?;
    let mut api = AuthenticatedApiClient::load(Some(&endpoint))?;
    if host_id.is_some_and(|host| check(host, &mut api).is_ok()) {
        ui::success(&format!("Hub in {region} is healthy"));
        return Ok(());
    }
    let cloud = deployment.cloud()?;
    cloud.json(&["services", "enable", "iap.googleapis.com"])?;
    let networks = cloud.json(&["compute", "networks", "list"])?;
    if let Some(network) = named(&networks, NETWORK)? {
        ensure!(
            network["description"] == DESCRIPTION && network["autoCreateSubnetworks"] == false,
            "existing hub network differs from Aegis setup; refusing to alter it"
        );
    } else {
        cloud.json(&[
            "compute",
            "networks",
            "create",
            NETWORK,
            "--subnet-mode=custom",
            "--description",
            DESCRIPTION,
        ])?;
    }
    let subnets = cloud.json(&["compute", "networks", "subnets", "list"])?;
    if let Some(subnet) = regional_named(&subnets, &name, region)? {
        ensure!(
            subnet["description"] == DESCRIPTION
                && subnet["ipCidrRange"] == subnet_cidr
                && suffix(&subnet["region"], region)
                && suffix(&subnet["network"], NETWORK),
            "existing hub subnet differs from setup"
        );
    } else {
        cloud.json(&[
            "compute",
            "networks",
            "subnets",
            "create",
            &name,
            "--network",
            NETWORK,
            "--region",
            region,
            "--range",
            &subnet_cidr,
            "--description",
            DESCRIPTION,
        ])?;
    }
    let firewalls = cloud.json(&["compute", "firewall-rules", "list"])?;
    for (name, allow, source, protocol, ports) in [
        (
            "aegis-hub-ssh",
            "tcp:22",
            "35.235.240.0/20",
            "tcp",
            vec!["22"],
        ),
        (
            "aegis-hub-wireguard",
            "udp:51820,udp:51822",
            "0.0.0.0/0",
            "udp",
            vec!["51820", "51822"],
        ),
    ] {
        if let Some(rule) = named(&firewalls, name)? {
            ensure!(
                rule["description"] == DESCRIPTION
                    && suffix(&rule["network"], NETWORK)
                    && rule["sourceRanges"] == serde_json::json!([source])
                    && rule["targetTags"] == serde_json::json!([HUB])
                    && rule["direction"] == "INGRESS"
                    && rule["disabled"] == false
                    && allowed_ports_match(&rule["allowed"], protocol, &ports),
                "existing firewall rule {name} differs from setup; inspect it explicitly"
            );
        } else {
            cloud.json(&[
                "compute",
                "firewall-rules",
                "create",
                name,
                "--network",
                NETWORK,
                "--target-tags",
                HUB,
                "--allow",
                allow,
                "--source-ranges",
                source,
                "--description",
                DESCRIPTION,
            ])?;
        }
    }
    cloud.json(&[
        "projects",
        "add-iam-policy-binding",
        &deployment.config.project,
        "--member",
        &cloud.operator_member()?,
        "--role=roles/iap.tunnelResourceAccessor",
        "--condition=None",
    ])?;
    let addresses = cloud.json(&["compute", "addresses", "list"])?;
    if let Some(address) = regional_named(&addresses, &name, region)? {
        ensure!(
            address["description"] == DESCRIPTION && suffix(&address["region"], region),
            "existing hub address differs from setup"
        );
    } else {
        cloud.json(&[
            "compute",
            "addresses",
            "create",
            &name,
            "--region",
            region,
            "--description",
            DESCRIPTION,
        ])?;
    }
    let address = cloud.json(&[
        "compute",
        "addresses",
        "describe",
        &name,
        "--region",
        region,
    ])?;
    let address = text(&address, "address")?;
    let instances = cloud.json(&["compute", "instances", "list"])?;
    let zone = if let Some(instance) = named(&instances, &name)? {
        ensure!(
            instance["labels"]["managed-by"] == "aegis"
                && instance["canIpForward"] == true
                && instance["serviceAccounts"]
                    .as_array()
                    .is_none_or(Vec::is_empty)
                && instance["networkInterfaces"][0]["accessConfigs"][0]["natIP"] == address
                && suffix(&instance["networkInterfaces"][0]["network"], NETWORK),
            "existing hub VM differs from setup"
        );
        let zone = text(instance, "zone")?
            .rsplit('/')
            .next()
            .context("hub zone missing")?
            .to_owned();
        ensure!(
            zone.starts_with(&format!("{region}-")),
            "existing hub VM is in another region"
        );
        ensure!(
            instance["status"] == "RUNNING",
            "hub VM is not running; inspect or start it before resuming setup"
        );
        zone
    } else {
        let zones = cloud.json(&[
            "compute",
            "zones",
            "list",
            "--filter",
            &format!("region:{region} AND status:UP"),
        ])?;
        let zone = text(
            array(&zones)?
                .first()
                .context("No available GCP zone in selected region")?,
            "name",
        )?
        .to_owned();
        cloud.json(&[
            "compute",
            "instances",
            "create",
            &name,
            "--zone",
            &zone,
            "--machine-type=e2-medium",
            "--image-family=ubuntu-2404-lts-amd64",
            "--image-project=ubuntu-os-cloud",
            "--boot-disk-size=30GB",
            "--boot-disk-type=pd-balanced",
            "--network",
            NETWORK,
            "--subnet",
            &name,
            "--address",
            address,
            "--can-ip-forward",
            "--no-service-account",
            "--no-scopes",
            "--tags",
            HUB,
            "--labels=managed-by=aegis",
            "--metadata=enable-oslogin=FALSE,block-project-ssh-keys=TRUE",
            "--shielded-secure-boot",
        ])?;
        zone
    };
    wait_for_ssh(&cloud, &name, &zone)?;
    if let Some(host) = host_id
        && api
            .get_hosts()?
            .hosts
            .get(&host)
            .is_some_and(|host| !host.pending)
    {
        ui::stage("Hub is enrolled; starting its installed agent and requesting reconciliation");
        let script = format!(
            "{}sudo /usr/local/bin/aegis advanced reconcile\n",
            invitation::system_agent_activation_script(),
        );
        cloud.stream(
            &[
                "compute",
                "ssh",
                &format!("aegis-bootstrap@{name}"),
                "--zone",
                &zone,
                "--tunnel-through-iap",
                "--ssh-key-expire-after=1h",
                "--command=bash -seuo pipefail",
                "--ssh-flag=-oConnectTimeout=20",
            ],
            script.as_bytes(),
            Duration::from_secs(180),
        )?;
        return Ok(());
    }
    let host = match host_id {
        Some(host) => host,
        None => {
            let enrollment =
                invitation::reserve(&mut api, HostAlias::parse(&name)?, AegisHostMode::Hub)?;
            deployment
                .hubs
                .get_mut(region)
                .context("missing hub receipt")?
                .host = Some(enrollment.host_id);
            deployment.persist().with_context(|| {
                format!(
                    "Hub reservation {} committed; record it in the receipt before retrying",
                    enrollment.host_id
                )
            })?;
            enrollment.host_id
        }
    };
    let (invitation, local_file) = invitation::issue(&mut api, &host)?;
    let script = bootstrap_script(&invitation)?;
    ui::stage(&format!(
        "Installing hub in {region} from crates.io. The Rust build may take 15–25 minutes; build output follows."
    ));
    let result = cloud.stream(
        &[
            "compute",
            "ssh",
            &format!("aegis-bootstrap@{name}"),
            "--zone",
            &zone,
            "--tunnel-through-iap",
            "--ssh-key-expire-after=1h",
            "--ssh-flag=-oConnectTimeout=20",
            "--ssh-flag=-oServerAliveInterval=15",
            "--ssh-flag=-oServerAliveCountMax=4",
            "--command=bash -seuo pipefail",
        ],
        script.as_bytes(),
        Duration::from_secs(90 * 60),
    );
    if let Err(error) = fs::remove_file(&local_file) {
        ui::warn(&format!(
            "Delete the temporary hub invitation at {}",
            local_file.display()
        ));
        if result.is_ok() {
            return Err(error).context("hub installation completed, but invitation cleanup failed");
        }
    }
    result.context("Hub resources and any staged agent are retained. Rerun setup; it checks active enrollment before replacing a pending invitation")?;
    Ok(())
}

fn wait_for_ssh(cloud: &super::gcloud::Gcloud, name: &str, zone: &str) -> Result<()> {
    let timeout = Duration::from_secs(300);
    let deadline = Instant::now() + timeout;
    let task = ui::task(ui::TaskOptions {
        label: "Waiting for hub SSH through IAP".into(),
        deadline: Some(timeout),
        ..Default::default()
    })?;
    loop {
        let result = cloud.run(
            &[
                "compute",
                "ssh",
                &format!("aegis-bootstrap@{name}"),
                "--zone",
                zone,
                "--tunnel-through-iap",
                "--ssh-key-expire-after=1h",
                "--ssh-flag=-oConnectTimeout=15",
                "--ssh-flag=-oBatchMode=yes",
                "--command=true",
            ],
            None,
            Duration::from_secs(40).min(deadline.saturating_duration_since(Instant::now())),
        );
        match result {
            Ok(_) => {
                task.finish_and_clear();
                return Ok(());
            }
            Err(error) => {
                if capulus::error_is_cancelled(&error) || Instant::now() >= deadline {
                    return Err(error)
                        .context("hub VM is retained; resume setup after SSH becomes reachable");
                }
                task.set_phase(format!("Waiting for SSH: {error}"));
            }
        }
        ui::sleep(Duration::from_secs(5))?;
    }
}

fn bootstrap_script(
    invitation: &aegis_dto::protocol::AegisEnrollmentCredentialResponse,
) -> Result<String> {
    Ok(format!(
        r#"set -euo pipefail
umask 077
sudo -n true
source /etc/os-release
test "$ID" = ubuntu
if ! swapon --show=NAME --noheadings | grep -q .; then
  sudo fallocate -l 4G /var/swap.aegis
  sudo chmod 600 /var/swap.aegis
  sudo mkswap /var/swap.aegis
  sudo swapon /var/swap.aegis
  printf '%s\n' '/var/swap.aegis none swap sw 0 0' | sudo tee -a /etc/fstab >/dev/null
fi
timeout --signal=TERM --kill-after=30s 15m sudo env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 -o Acquire::Retries=3 update
timeout --signal=TERM --kill-after=30s 15m sudo env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 -o Acquire::Retries=3 install -y --no-install-recommends build-essential pkg-config libssl-dev curl ca-certificates
{bootstrap}
invitation="$(mktemp /tmp/aegis-invitation.XXXXXX)"
trap 'rm -f -- "$invitation"' EXIT
printf '%s' {credential} > "$invitation"
/usr/local/bin/aegis --progress plain manage enroll --local --invitation "$invitation"
"#,
        bootstrap = aegis_tool::client::enrollment::system_program_bootstrap_script(true),
        credential = shell_quote(&serde_json::to_string(invitation)?)
    ))
}

fn check(host_id: aegis_dto::HostId, api: &mut AuthenticatedApiClient) -> Result<()> {
    let hosts = api.get_hosts()?;
    let host = hosts.hosts.get(&host_id).context("Hub host is missing")?;
    ensure!(!host.pending, "Hub is still pending activation");
    let agent = host
        .report
        .agent
        .as_ref()
        .context("Hub has not reported agent health")?;
    ensure!(
        agent.health.reconciled_since_boot
            && agent.health.last_reconcile_error.is_none()
            && agent.reported_unix > client::now_unix() - 180,
        "Hub has no recent healthy reconciliation"
    );
    let members = api.get_network_members("aegis")?;
    let member = members
        .members
        .get(&host_id)
        .context("Hub network membership missing")?;
    ensure!(
        member.mode == AegisHostMode::Hub
            && !member.pending
            && member
                .wireguard
                .as_ref()
                .is_some_and(|wg| !wg.endpoints.is_empty()),
        "Hub has no published WireGuard endpoint"
    );
    Ok(())
}
fn wait(host: aegis_dto::HostId, region: &str, api: &mut AuthenticatedApiClient) -> Result<()> {
    let timeout = Duration::from_secs(300);
    let task = ui::task(ui::TaskOptions {
        label: format!("Waiting for hub in {region}"),
        deadline: Some(timeout),
        ..Default::default()
    })?;
    let deadline = Instant::now() + timeout;
    loop {
        ui::check_cancelled()?;
        match check(host, api) {
            Ok(()) => {
                task.finish("Hub is ready");
                return Ok(());
            }
            Err(error) => {
                task.set_phase(format!("Last observed state: {error}"));
                if Instant::now() >= deadline {
                    return Err(
                        error.context("Hub readiness deadline exceeded; VM and agent are retained")
                    );
                }
            }
        }
        ui::sleep(Duration::from_secs(5))?;
    }
}
fn allowed_ports_match(value: &Value, protocol: &str, expected: &[&str]) -> bool {
    let Some(rules) = value.as_array() else {
        return false;
    };
    let mut ports = BTreeSet::new();
    for rule in rules {
        if rule["IPProtocol"] != protocol {
            return false;
        }
        let Some(values) = rule["ports"].as_array().filter(|ports| !ports.is_empty()) else {
            return false;
        };
        for value in values {
            let Some(port) = value.as_str() else {
                return false;
            };
            ports.insert(port);
        }
    }
    ports == expected.iter().copied().collect()
}

fn named<'a>(values: &'a Value, name: &str) -> Result<Option<&'a Value>> {
    let matches: Vec<_> = array(values)?
        .iter()
        .filter(|value| value["name"] == name)
        .collect();
    ensure!(
        matches.len() <= 1,
        "multiple resources named {name}; select or repair them explicitly"
    );
    Ok(matches.into_iter().next())
}
fn suffix(value: &Value, name: &str) -> bool {
    value
        .as_str()
        .is_some_and(|s| s.ends_with(&format!("/{name}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn subnet_allocation_avoids_saved_and_overlapping_cloud_ranges() {
        let hubs = BTreeMap::from([(
            "us-central1".into(),
            Hub {
                subnet_cidr: "10.76.2.0/24".into(),
                host: None,
            },
        )]);
        let subnets = json!([
            {"network":"projects/test/global/networks/aegis-hub", "ipCidrRange":"10.76.0.0/23"},
            {"network":"projects/test/global/networks/unrelated", "ipCidrRange":"10.0.0.0/8"}
        ]);
        assert_eq!(allocate_subnet(&hubs, &subnets).unwrap(), "10.76.3.0/24");
        assert!(
            allocate_subnet(
                &hubs,
                &json!([
                    {"network":"networks/aegis-hub", "ipCidrRange":"10.76.0.0/16"}
                ])
            )
            .is_err()
        );
    }

    #[test]
    fn hub_removal_refuses_unowned_resources_and_accepts_partial_completion() {
        let instance = json!({"labels":{"managed-by":"aegis"}, "zone":"zones/us-central1-a",
            "networkInterfaces":[{"network":"networks/aegis-hub"}]});
        let address = json!({"description":DESCRIPTION,"region":"regions/us-central1"});
        let subnet = json!({"description":DESCRIPTION,"region":"regions/us-central1",
            "network":"networks/aegis-hub", "ipCidrRange":"10.76.0.0/24"});
        for vm in [None, Some(&instance)] {
            for ip in [None, Some(&address)] {
                for net in [None, Some(&subnet)] {
                    validate_removal(vm, ip, net, "us-central1", "10.76.0.0/24").unwrap();
                }
            }
        }
        assert!(validate_removal(Some(&instance), None, None, "us-east1", "10.76.0.0/24").is_err());
        let mut unowned = instance.clone();
        unowned["labels"] = json!({});
        assert!(
            validate_removal(Some(&unowned), None, None, "us-central1", "10.76.0.0/24").is_err()
        );
        assert!(
            validate_removal(None, None, Some(&subnet), "us-central1", "10.76.1.0/24").is_err()
        );
        let mut unowned = address.clone();
        unowned["description"] = json!("operator managed");
        assert!(
            validate_removal(None, Some(&unowned), None, "us-central1", "10.76.0.0/24").is_err()
        );
    }

    #[test]
    fn firewall_comparison_accepts_grouped_and_separate_port_entries() {
        for rules in [
            json!([{"IPProtocol":"udp","ports":["51820","51822"]}]),
            json!([{"IPProtocol":"udp","ports":["51822"]},{"IPProtocol":"udp","ports":["51820"]}]),
        ] {
            assert!(allowed_ports_match(&rules, "udp", &["51820", "51822"]));
        }
        for rules in [
            json!([{"IPProtocol":"udp"}]),
            json!([{"IPProtocol":"udp","ports":[]}]),
            json!([{"IPProtocol":"tcp","ports":["51820","51822"]}]),
            json!([{"IPProtocol":"udp","ports":["51820","51822","51821"]}]),
            json!([{"IPProtocol":"udp","ports":["51820"]}]),
        ] {
            assert!(!allowed_ports_match(&rules, "udp", &["51820", "51822"]));
        }
    }
}
