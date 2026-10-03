use std::{
    collections::BTreeSet,
    fs,
    time::{Duration, Instant},
};

use aegis_dto::{AegisHostMode, HostAlias};
use anyhow::{Context, Result, ensure};
use capulus::shell::shell_quote;
use serde_json::Value;

use super::deployment::{Deployment, array, text};
use aegis_tool::{
    client::{self, AuthenticatedApiClient, enrollment as invitation},
    ui,
};

const HUB: &str = "aegis-hub";
const NETWORK: &str = "aegis-hub";
const DESCRIPTION: &str = "Managed by Aegis setup";

pub(super) fn ensure(deployment: &mut Deployment) -> Result<()> {
    let endpoint = deployment.namespace_endpoint()?;
    let mut api = AuthenticatedApiClient::load(Some(&endpoint))?;
    if deployment.hub.is_some() && check(deployment, &mut api).is_ok() {
        ui::success("First hub is already healthy");
        return Ok(());
    }
    let cloud = deployment.cloud()?;
    let region = &deployment.config.region;
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
    if let Some(subnet) = named(&subnets, HUB)? {
        ensure!(
            subnet["description"] == DESCRIPTION
                && subnet["ipCidrRange"] == "10.76.0.0/24"
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
            HUB,
            "--network",
            NETWORK,
            "--region",
            region,
            "--range=10.76.0.0/24",
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
    let account = cloud.user_account()?;
    cloud.json(&[
        "projects",
        "add-iam-policy-binding",
        &deployment.config.project,
        "--member",
        &format!("user:{account}"),
        "--role=roles/iap.tunnelResourceAccessor",
        "--condition=None",
    ])?;
    let addresses = cloud.json(&["compute", "addresses", "list"])?;
    if let Some(address) = named(&addresses, HUB)? {
        ensure!(
            address["description"] == DESCRIPTION && suffix(&address["region"], region),
            "existing hub address differs from setup"
        );
    } else {
        cloud.json(&[
            "compute",
            "addresses",
            "create",
            HUB,
            "--region",
            region,
            "--description",
            DESCRIPTION,
        ])?;
    }
    let address = cloud.json(&["compute", "addresses", "describe", HUB, "--region", region])?;
    let address = text(&address, "address")?;
    let instances = cloud.json(&["compute", "instances", "list"])?;
    let zone = if let Some(instance) = named(&instances, HUB)? {
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
            HUB,
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
            HUB,
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
    wait_for_ssh(&cloud, &zone)?;
    if let Some(host) = deployment.hub
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
                &format!("aegis-bootstrap@{HUB}"),
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
        return wait(deployment, &mut api);
    }
    let host = match deployment.hub {
        Some(host) => host,
        None => {
            let enrollment =
                invitation::reserve(&mut api, HostAlias::parse(HUB)?, AegisHostMode::Hub)?;
            deployment.save_hub(enrollment.host_id)?;
            enrollment.host_id
        }
    };
    let (invitation, local_file) = invitation::issue(&mut api, &host)?;
    let script = bootstrap_script(&invitation)?;
    ui::stage(
        "Installing the first hub from crates.io. The Rust build may take 15–25 minutes; build output follows.",
    );
    let result = cloud.stream(
        &[
            "compute",
            "ssh",
            &format!("aegis-bootstrap@{HUB}"),
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
    wait(deployment, &mut api)
}

fn wait_for_ssh(cloud: &super::gcloud::Gcloud, zone: &str) -> Result<()> {
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
                &format!("aegis-bootstrap@{HUB}"),
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
    invitation: &aegis_dto::v1::AegisEnrollmentCredentialResponse,
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

pub(super) fn check(deployment: &Deployment, api: &mut AuthenticatedApiClient) -> Result<()> {
    let host_id = deployment.hub.context("First hub has not been enrolled")?;
    let hosts = api.get_hosts()?;
    let host = hosts
        .hosts
        .get(&host_id)
        .context("First hub host is missing")?;
    ensure!(!host.pending, "First hub is still pending activation");
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
fn wait(deployment: &Deployment, api: &mut AuthenticatedApiClient) -> Result<()> {
    let timeout = Duration::from_secs(300);
    let task = ui::task(ui::TaskOptions {
        label: "Waiting for the first hub".into(),
        deadline: Some(timeout),
        ..Default::default()
    })?;
    let deadline = Instant::now() + timeout;
    loop {
        ui::check_cancelled()?;
        match check(deployment, api) {
            Ok(()) => {
                task.finish("First hub is ready");
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
