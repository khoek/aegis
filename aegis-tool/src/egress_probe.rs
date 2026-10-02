use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    net::{IpAddr, SocketAddr},
    os::unix::fs::MetadataExt,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use aegis_types::v1::{AegisEgressConfig, AegisEgressHost};
use anyhow::{Context, Result, anyhow, bail, ensure};
use hickory_resolver::{
    TokioResolver,
    config::{LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts},
    net::runtime::TokioRuntimeProvider,
};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use url::{Host, Url};

use crate::command::{require_success, require_success_with_input};
use crate::tunnel_operation;

const NAMESPACE_READY_TIMEOUT: Duration = Duration::from_secs(5);
const CANDIDATE_PROBE_DEADLINE: Duration = Duration::from_secs(8);
const COMMITTED_PROBE_DEADLINE: Duration = Duration::from_secs(5);
const COMMAND_TIMEOUT: &str = "5s";
const DNS_TIMEOUT: Duration = Duration::from_secs(4);
const HTTPS_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HTTPS_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) struct CandidateProbe<'a> {
    pub(crate) config: &'a AegisEgressConfig,
    pub(crate) local: &'a AegisEgressHost,
    pub(crate) target: &'a AegisEgressHost,
    pub(crate) private_key: &'a str,
    pub(crate) api_base: &'a str,
}

pub(crate) struct CommittedProbe<'a> {
    pub(crate) local: &'a AegisEgressHost,
    pub(crate) target: &'a AegisEgressHost,
    pub(crate) api_base: &'a str,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProbeWorkerRequest {
    interface: String,
    config: AegisEgressConfig,
    local: AegisEgressHost,
    target: AegisEgressHost,
    private_key: String,
    timeout_ms: u64,
    api_base: String,
}

struct ProbeIdentity<'a> {
    ipv4: &'a str,
    ipv6: &'a str,
}

struct ProbePath<'a> {
    local: ProbeIdentity<'a>,
    gateway_dns: ProbeIdentity<'a>,
    api_base: &'a str,
}

pub(crate) fn prove_candidate(probe: CandidateProbe<'_>) -> Result<()> {
    let interface = format!("agp{}", std::process::id());
    ensure!(
        interface.len() < libc::IFNAMSIZ,
        "temporary egress probe interface name is too long"
    );
    let request = ProbeWorkerRequest {
        interface: interface.clone(),
        config: probe.config.clone(),
        local: probe.local.clone(),
        target: probe.target.clone(),
        private_key: probe.private_key.to_string(),
        timeout_ms: tunnel_operation::request_timeout(CANDIDATE_PROBE_DEADLINE)?.as_millis() as u64,
        api_base: probe.api_base.to_string(),
    };

    let executable =
        std::env::current_exe().context("failed to locate the system Aegis executable")?;
    #[cfg(test)]
    let executable = std::env::var_os("AEGIS_TEST_BINARY")
        .map(std::path::PathBuf::from)
        .unwrap_or(executable);
    let mut child = Command::new(executable)
        .args(["agent", "egress-probe-worker"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to start isolated egress probe")?;
    let mut guard = ProbeChildGuard {
        child: &mut child,
        root_interface: Some(interface.clone()),
    };
    wait_for_private_network_namespace(guard.child)?;

    require_success(
        "create isolated egress probe interface",
        &mut bounded_command(
            "/usr/sbin/ip",
            &["link", "add", "dev", &interface, "type", "wireguard"],
        ),
    )?;
    require_success(
        "move egress probe interface into its isolated network namespace",
        &mut bounded_command(
            "/usr/sbin/ip",
            &[
                "link",
                "set",
                "dev",
                &interface,
                "netns",
                &guard.child.id().to_string(),
            ],
        ),
    )?;
    guard.root_interface = None;

    serde_json::to_writer(
        guard
            .child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("isolated egress probe stdin is unavailable"))?,
        &request,
    )
    .context("failed to send isolated egress probe configuration")?;
    drop(guard.child.stdin.take());

    let status = wait_for_probe(guard.child)?;
    let stderr = read_child_stderr(guard.child);
    if !status.success() {
        let detail = stderr.trim();
        if detail.is_empty() {
            bail!("isolated egress probe exited with {status}");
        }
        bail!("isolated egress probe failed: {detail}");
    }
    Ok(())
}

pub(crate) fn prove_committed(probe: CommittedProbe<'_>) -> Result<()> {
    prove_path(
        &ProbePath {
            // The per-host DNS addresses are also WireGuard identities, but ordinary sockets
            // never select them implicitly. Binding the probe to them distinguishes this one
            // validation flow from the agent's fail-safe control-plane traffic.
            local: ProbeIdentity {
                ipv4: &probe.local.dns_ipv4,
                ipv6: &probe.local.dns_ipv6,
            },
            gateway_dns: ProbeIdentity {
                ipv4: &probe.target.dns_ipv4,
                ipv6: &probe.target.dns_ipv6,
            },
            api_base: probe.api_base,
        },
        tunnel_operation::request_timeout(COMMITTED_PROBE_DEADLINE)?,
    )
}

pub(crate) fn run_worker() -> Result<()> {
    enter_private_network_namespace()?;
    let request: ProbeWorkerRequest = serde_json::from_reader(std::io::stdin().lock())
        .context("failed to read isolated egress probe configuration")?;
    ensure!(
        request.timeout_ms > 0 && request.timeout_ms <= CANDIDATE_PROBE_DEADLINE.as_millis() as u64,
        "invalid probe deadline"
    );
    tunnel_operation::bounded(Duration::from_millis(request.timeout_ms), || {
        configure_probe_interface(&request)?;
        prove_path(
            &ProbePath {
                local: ProbeIdentity {
                    ipv4: &request.local.ipv4,
                    ipv6: &request.local.ipv6,
                },
                gateway_dns: ProbeIdentity {
                    ipv4: &request.target.dns_ipv4,
                    ipv6: &request.target.dns_ipv6,
                },
                api_base: &request.api_base,
            },
            tunnel_operation::request_timeout(CANDIDATE_PROBE_DEADLINE)?,
        )
    })
}

fn enter_private_network_namespace() -> Result<()> {
    let parent = unsafe { libc::getppid() };
    ensure!(
        parent > 1,
        "isolated egress probe has no supervising parent"
    );
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to bind isolated egress probe lifetime to its parent");
    }
    ensure!(
        unsafe { libc::getppid() } == parent,
        "isolated egress probe parent exited during startup"
    );
    if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to create isolated egress probe network namespace");
    }
    Ok(())
}

fn wait_for_private_network_namespace(child: &mut Child) -> Result<()> {
    let parent_namespace = fs::metadata("/proc/thread-self/ns/net")
        .context("failed to inspect the agent network namespace")?
        .ino();
    let child_namespace_path = format!("/proc/{}/ns/net", child.id());
    let deadline = Instant::now() + tunnel_operation::request_timeout(NAMESPACE_READY_TIMEOUT)?;
    loop {
        tunnel_operation::check()?;
        if fs::metadata(&child_namespace_path)
            .is_ok_and(|metadata| metadata.ino() != parent_namespace)
        {
            return Ok(());
        }
        if let Some(status) = child
            .try_wait()
            .context("failed to inspect isolated egress probe")?
        {
            let stderr = read_child_stderr(child);
            let detail = stderr.trim();
            if detail.is_empty() {
                bail!("isolated egress probe exited during startup with {status}");
            }
            bail!("isolated egress probe failed during startup: {detail}");
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for the isolated egress probe network namespace");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn configure_probe_interface(request: &ProbeWorkerRequest) -> Result<()> {
    let endpoint = format!(
        "{}:{}",
        request.target.internal_ipv4, request.config.endpoint_port
    );
    // The owning agent reads the key once. wg receives private configuration through stdin,
    // just like ordinary peer updates; it never opens a key file under a different AppArmor profile.
    let config = format!(
        "[Interface]\nPrivateKey = {}\nListenPort = 0\nFwMark = {}\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = 0.0.0.0/0,::/0\nPersistentKeepalive = 25\n",
        request.private_key, request.config.fwmark, request.target.public_key, endpoint,
    );
    require_success_with_input(
        "configure isolated egress probe WireGuard peer",
        &mut bounded_command(
            "/usr/bin/wg",
            &["setconf", &request.interface, "/dev/stdin"],
        ),
        config.as_bytes(),
    )?;
    require_success(
        "bring up isolated egress probe loopback interface",
        &mut bounded_command("/usr/sbin/ip", &["link", "set", "dev", "lo", "up"]),
    )?;
    for (family, address, prefix) in [
        ("-4", &request.local.ipv4, "32"),
        ("-6", &request.local.ipv6, "128"),
    ] {
        require_success(
            "assign isolated egress probe address",
            &mut bounded_command(
                "/usr/sbin/ip",
                &[
                    family,
                    "address",
                    "add",
                    &format!("{address}/{prefix}"),
                    "dev",
                    &request.interface,
                ],
            ),
        )?;
    }
    require_success(
        "bring up isolated egress probe WireGuard interface",
        &mut bounded_command(
            "/usr/sbin/ip",
            &[
                "link",
                "set",
                "dev",
                &request.interface,
                "mtu",
                &request.config.mtu.to_string(),
                "up",
            ],
        ),
    )?;
    for family in ["-4", "-6"] {
        require_success(
            "install isolated egress probe default route",
            &mut bounded_command(
                "/usr/sbin/ip",
                &[family, "route", "add", "default", "dev", &request.interface],
            ),
        )?;
    }
    Ok(())
}

fn prove_path(path: &ProbePath<'_>, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let local_ipv4 = parse_family_address(path.local.ipv4, false, "local egress IPv4 address")?;
    let local_ipv6 = parse_family_address(path.local.ipv6, true, "local egress IPv6 address")?;
    let dns_ipv4 = parse_family_address(path.gateway_dns.ipv4, false, "gateway DNS IPv4 address")?;
    let dns_ipv6 = parse_family_address(path.gateway_dns.ipv6, true, "gateway DNS IPv6 address")?;
    let url = Url::parse(path.api_base).context("agent API base is not a valid URL")?;
    ensure!(
        url.scheme() == "https",
        "egress validation requires an HTTPS agent API base"
    );
    let Host::Domain(hostname) = url
        .host()
        .ok_or_else(|| anyhow!("agent API base has no host"))?
    else {
        bail!("egress validation requires a DNS hostname in the agent API base");
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to start isolated DNS validation runtime")?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    ensure!(
        !remaining.is_zero(),
        "dual-stack egress validation exceeded its {timeout:?} deadline"
    );
    let (ipv4_dns_result, ipv6_dns_result) = runtime
        .block_on(async {
            tokio::time::timeout(remaining, async {
                tokio::join!(
                    resolve_gateway_dns(dns_ipv4, local_ipv4, hostname, DNS_TIMEOUT.min(remaining)),
                    resolve_gateway_dns(dns_ipv6, local_ipv6, hostname, DNS_TIMEOUT.min(remaining))
                )
            })
            .await
        })
        .context("gateway DNS validation exceeded its deadline")?;
    let mut resolved = BTreeSet::new();
    for (server, result) in [(dns_ipv4, ipv4_dns_result), (dns_ipv6, ipv6_dns_result)] {
        let addresses =
            result.with_context(|| format!("gateway DNS query through {server} failed"))?;
        ensure!(
            addresses.iter().any(IpAddr::is_ipv4),
            "gateway DNS server {server} returned no IPv4 address for `{hostname}`"
        );
        ensure!(
            addresses.iter().any(IpAddr::is_ipv6),
            "gateway DNS server {server} returned no IPv6 address for `{hostname}`"
        );
        resolved.extend(addresses);
    }
    drop(runtime);

    let ipv4_addresses = resolved
        .iter()
        .copied()
        .filter(IpAddr::is_ipv4)
        .collect::<Vec<_>>();
    let ipv6_addresses = resolved
        .iter()
        .copied()
        .filter(IpAddr::is_ipv6)
        .collect::<Vec<_>>();
    let (ipv4_https, ipv6_https) = thread::scope(|scope| {
        let ipv4 = scope.spawn(|| {
            prove_https_family(
                &url,
                hostname,
                local_ipv4,
                ipv4_addresses.into_iter(),
                deadline,
            )
        });
        let ipv6 = scope.spawn(|| {
            prove_https_family(
                &url,
                hostname,
                local_ipv6,
                ipv6_addresses.into_iter(),
                deadline,
            )
        });
        (ipv4.join(), ipv6.join())
    });
    ipv4_https
        .map_err(|_| anyhow!("IPv4 HTTPS validation worker panicked"))?
        .context("IPv4 HTTPS egress validation failed")?;
    ipv6_https
        .map_err(|_| anyhow!("IPv6 HTTPS validation worker panicked"))?
        .context("IPv6 HTTPS egress validation failed")
}

async fn resolve_gateway_dns(
    server: IpAddr,
    bind: IpAddr,
    hostname: &str,
    timeout: Duration,
) -> Result<BTreeSet<IpAddr>> {
    let mut name_server = NameServerConfig::udp_and_tcp(server);
    for connection in &mut name_server.connections {
        connection.bind_addr = Some(SocketAddr::new(bind, 0));
    }
    let name_servers = vec![name_server];
    let config = ResolverConfig::from_parts(None, Vec::new(), name_servers);
    let mut options = ResolverOpts::default();
    options.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    options.timeout = timeout;
    options.attempts = 1;
    options.num_concurrent_reqs = 1;
    options.use_hosts_file = ResolveHosts::Never;
    let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(options)
        .build()?;
    let lookup = resolver
        .lookup_ip(format!("{hostname}."))
        .await
        .with_context(|| format!("could not resolve `{hostname}`"))?;
    Ok(lookup.iter().collect())
}

fn prove_https_family(
    url: &Url,
    hostname: &str,
    bind: IpAddr,
    addresses: impl Iterator<Item = IpAddr>,
    deadline: Instant,
) -> Result<()> {
    let mut failures = Vec::new();
    let mut attempted = false;
    for address in addresses {
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(
            !remaining.is_zero(),
            "dual-stack HTTPS validation exceeded its deadline"
        );
        attempted = true;
        let client = Client::builder()
            .user_agent(format!("aegis-tool/{}", env!("CARGO_PKG_VERSION")))
            .no_proxy()
            .https_only(true)
            .connect_timeout(HTTPS_CONNECT_TIMEOUT.min(remaining))
            .timeout(HTTPS_REQUEST_TIMEOUT.min(remaining))
            .local_address(bind)
            .resolve(hostname, SocketAddr::new(address, 0))
            .build()
            .context("failed to construct egress validation HTTPS client")?;
        // Any HTTP response proves DNS, routing, TCP, and TLS; the tunnel validator deliberately
        // does not couple transport safety to an application response body or status code.
        match client.get(url.clone()).send() {
            Ok(_) => return Ok(()),
            Err(error) => failures.push(format!("{address}: {:#}", anyhow::Error::new(error))),
        }
    }
    ensure!(attempted, "DNS returned no addresses for this IP family");
    bail!("all resolved addresses failed: {}", failures.join("; "))
}

fn parse_family_address(value: &str, ipv6: bool, description: &str) -> Result<IpAddr> {
    let address = value
        .parse::<IpAddr>()
        .with_context(|| format!("invalid {description} `{value}`"))?;
    ensure!(
        address.is_ipv6() == ipv6,
        "{description} `{value}` has the wrong address family"
    );
    Ok(address)
}

fn bounded_command(program: &str, arguments: &[&str]) -> Command {
    let mut command = Command::new("/usr/bin/timeout");
    command
        .args(["--signal=KILL", COMMAND_TIMEOUT, program])
        .args(arguments);
    command
}

fn wait_for_probe(child: &mut Child) -> Result<std::process::ExitStatus> {
    let deadline = Instant::now() + tunnel_operation::request_timeout(CANDIDATE_PROBE_DEADLINE)?;
    loop {
        tunnel_operation::check()?;
        if let Some(status) = child
            .try_wait()
            .context("failed to inspect isolated egress probe")?
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("isolated egress probe exceeded its deadline");
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn read_child_stderr(child: &mut Child) -> String {
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    stderr
}

struct ProbeChildGuard<'a> {
    child: &'a mut Child,
    root_interface: Option<String>,
}

impl Drop for ProbeChildGuard<'_> {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(interface) = self.root_interface.take() {
            let _ = tunnel_operation::recover("Cleaning up probe", || {
                require_success(
                    "remove probe interface",
                    &mut bounded_command("/usr/sbin/ip", &["link", "del", "dev", &interface]),
                )
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{ProbeIdentity, ProbePath, bounded_command, prove_path};

    fn probe_path(api_base: &str) -> ProbePath<'_> {
        ProbePath {
            local: ProbeIdentity {
                ipv4: "10.78.1.2",
                ipv6: "fd78::1:2",
            },
            gateway_dns: ProbeIdentity {
                ipv4: "10.78.0.3",
                ipv6: "fd78::3",
            },
            api_base,
        }
    }

    #[test]
    fn transport_validation_requires_https_before_performing_network_io() {
        let error = prove_path(
            &probe_path("http://api.example.test/v2"),
            Duration::from_secs(1),
        )
        .expect_err("plain HTTP must be rejected");

        assert!(error.to_string().contains("requires an HTTPS"));
    }

    #[test]
    fn transport_validation_requires_dns_before_performing_network_io() {
        let error = prove_path(&probe_path("https://192.0.2.10/v2"), Duration::from_secs(1))
            .expect_err("literal IP API hosts must be rejected");

        assert!(error.to_string().contains("requires a DNS hostname"));
    }

    #[test]
    fn probe_subprocesses_have_a_hard_deadline() {
        let command = bounded_command("/usr/sbin/ip", &["link", "show"]);
        assert_eq!(command.get_program(), "/usr/bin/timeout");
        assert_eq!(
            command
                .get_args()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            ["--signal=KILL", "5s", "/usr/sbin/ip", "link", "show"]
        );
    }
}
