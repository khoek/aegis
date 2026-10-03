//! Real WireGuard, routing and nftables tests. Every mutation is inside private namespaces.
use super::*;
use crate::tunnel_operation::{self as operation, Request};
use std::{
    ffi::CString,
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::Child,
};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/egress_fixture.py");

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            libc::kill(-(self.0.id() as i32), libc::SIGKILL);
        }
        let _ = self.0.wait();
    }
}

struct Namespace(Process);
impl Namespace {
    fn new() -> Self {
        let initial = fs::metadata("/proc/thread-self/ns/net").unwrap().ino();
        let child = Command::new("/usr/bin/unshare")
            .args(["--net", "/usr/bin/timeout", "180s", "/usr/bin/sleep", "180"])
            .process_group(0)
            .spawn()
            .unwrap();
        let namespace = Self(Process(child));
        let deadline = Instant::now() + Duration::from_secs(3);
        while fs::metadata(format!("/proc/{}/ns/net", namespace.pid()))
            .unwrap()
            .ino()
            == initial
        {
            assert!(Instant::now() < deadline, "namespace creation timed out");
            thread::sleep(Duration::from_millis(10));
        }
        namespace.run(&["ip", "link", "set", "lo", "up"]);
        namespace
    }
    fn pid(&self) -> String {
        self.0.0.id().to_string()
    }
    fn run(&self, args: &[&str]) -> String {
        run(&[
            &["nsenter", "--net", "--target", &self.pid(), "--"][..],
            args,
        ]
        .concat())
    }
    fn enter(&self) -> Enter {
        let original = fs::File::open("/proc/thread-self/ns/net").unwrap();
        let destination = fs::File::open(format!("/proc/{}/ns/net", self.pid())).unwrap();
        assert_eq!(
            unsafe { libc::setns(destination.as_raw_fd(), libc::CLONE_NEWNET) },
            0
        );
        Enter(original)
    }
    fn fixture(&self, directory: &Path, mode: &str, extra: &[&str]) -> Process {
        let child = Command::new("nsenter")
            .args([
                "--net",
                "--target",
                &self.pid(),
                "--",
                "python3",
                FIXTURE,
                mode,
                "--directory",
            ])
            .arg(directory)
            .args(extra)
            .process_group(0)
            .spawn()
            .unwrap();
        Process(child)
    }
}
struct Enter(fs::File);
impl Drop for Enter {
    fn drop(&mut self) {
        assert_eq!(
            unsafe { libc::setns(self.0.as_raw_fd(), libc::CLONE_NEWNET) },
            0
        );
    }
}

fn run(args: &[&str]) -> String {
    require_success(
        "isolated kernel fixture",
        Command::new("timeout").arg("5s").args(args),
    )
    .unwrap()
    .stdout
}

fn bind(source: &Path, target: &str) {
    let source = CString::new(source.as_os_str().as_encoded_bytes()).unwrap();
    let target = CString::new(target).unwrap();
    assert_eq!(
        unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        },
        0,
        "bind mount failed: {}",
        std::io::Error::last_os_error()
    );
}

fn isolate_files(directory: &Path) {
    for (index, target) in [
        "/etc/aegis",
        "/var/lib/aegis",
        "/etc/systemd/system",
        "/etc/systemd/resolved.conf.d",
        "/run/systemd",
        "/run/dbus",
    ]
    .iter()
    .enumerate()
    {
        assert!(
            Path::new(target).is_dir(),
            "test mount target is absent: {target}"
        );
        let path = directory.join(format!("mount-{index}"));
        fs::create_dir(&path).unwrap();
        bind(&path, target);
    }
    fs::create_dir_all("/etc/aegis/wireguard").unwrap();
    let systemctl = directory.join("systemctl");
    fs::write(&systemctl, r#"#!/usr/bin/python3
import pathlib, subprocess, sys
args = sys.argv[1:]
unit = args[-1] if args else ''
if '@' in unit and args[0] in ['is-active', 'start', 'restart']:
    interface = unit.split('@', 1)[1].removesuffix('.service')
    if args[0] == 'is-active':
        sys.exit(subprocess.call(['ip', 'link', 'show', interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    text = pathlib.Path('/etc/aegis/wireguard/' + interface + '.conf').read_text()
    subprocess.run(['ip', 'link', 'add', interface, 'type', 'wireguard'], stderr=subprocess.DEVNULL)
    lines = []
    for line in text.splitlines():
        if line.startswith('Address = '):
            for address in line.split('=',1)[1].strip().split(','):
                subprocess.run(['ip','address','replace',address,'dev',interface], check=True)
        elif line.startswith('MTU = '):
            subprocess.run(['ip','link','set',interface,'mtu',line.split('=',1)[1].strip()], check=True)
        elif not line.startswith(('Table = ', '#')):
            lines.append(line)
    subprocess.run(['wg','setconf',interface,'/dev/stdin'], input='\n'.join(lines), text=True, check=True)
    subprocess.run(['ip','link','set',interface,'up'], check=True)
"#).unwrap();
    fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o755)).unwrap();
    bind(&systemctl, "/usr/bin/systemctl");
    let resolvectl = directory.join("resolvectl");
    fs::write(&resolvectl, r#"#!/usr/bin/python3
import pathlib,sys
args=sys.argv[1:]
root=pathlib.Path('/var/lib/aegis')
if args[0]=='revert':
    for kind,value in [('dns',''),('domain',''),('default-route','no')]:
        (root/('resolver-'+kind)).write_text(value)
elif len(args)>2:
    (root/('resolver-'+args[0])).write_text(' '.join(args[2:]))
else:
    path=root/('resolver-'+args[0])
    print('Link 1 ('+args[1]+'): '+(path.read_text() if path.exists() else ('no' if args[0]=='default-route' else '')))
"#).unwrap();
    fs::set_permissions(&resolvectl, fs::Permissions::from_mode(0o755)).unwrap();
    bind(&resolvectl, "/usr/bin/resolvectl");
}

fn keypair() -> (String, String) {
    let private = run(&["wg", "genkey"]).trim().to_string();
    let public = require_success_with_input(
        "test key",
        Command::new("wg").arg("pubkey"),
        private.as_bytes(),
    )
    .unwrap()
    .stdout
    .trim()
    .to_string();
    (private, public)
}

fn ready(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "fixture did not become ready: {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn mesh_link(hub: &Namespace, suffix: &str, address: &str) {
    let source_link = format!("s{suffix}");
    let hub_link = format!("h{suffix}");
    run(&[
        "ip",
        "link",
        "add",
        &source_link,
        "type",
        "veth",
        "peer",
        "name",
        &hub_link,
    ]);
    run(&["ip", "link", "set", &hub_link, "netns", &hub.pid()]);
    run(&["ip", "address", "add", "10.75.0.2/32", "dev", &source_link]);
    run(&["ip", "link", "set", &source_link, "up"]);
    run(&[
        "ip",
        "route",
        "add",
        &format!("{address}/32"),
        "dev",
        &source_link,
    ]);
    hub.run(&[
        "ip",
        "address",
        "add",
        &format!("{address}/32"),
        "dev",
        &hub_link,
    ]);
    hub.run(&["ip", "link", "set", &hub_link, "up"]);
    hub.run(&["ip", "route", "add", "10.75.0.2/32", "dev", &hub_link]);
}

fn internet_link(internet: &Namespace, suffix: &str, ipv4: &str, ipv6: &str) {
    let wan = format!("w{suffix}");
    let other = format!("i{suffix}");
    run(&[
        "ip", "link", "add", &wan, "type", "veth", "peer", "name", &other,
    ]);
    run(&["ip", "link", "set", &other, "netns", &internet.pid()]);
    run(&["ip", "address", "add", &format!("{ipv4}.2/24"), "dev", &wan]);
    run(&[
        "ip",
        "-6",
        "address",
        "add",
        &format!("{ipv6}::2/64"),
        "dev",
        &wan,
        "nodad",
    ]);
    run(&["ip", "link", "set", &wan, "up"]);
    internet.run(&[
        "ip",
        "address",
        "add",
        &format!("{ipv4}.1/24"),
        "dev",
        &other,
    ]);
    internet.run(&[
        "ip",
        "-6",
        "address",
        "add",
        &format!("{ipv6}::1/64"),
        "dev",
        &other,
        "nodad",
    ]);
    internet.run(&["ip", "link", "set", &other, "up"]);
    run(&["ip", "route", "add", "default", "via", &format!("{ipv4}.1")]);
    run(&[
        "ip",
        "-6",
        "route",
        "add",
        "default",
        "via",
        &format!("{ipv6}::1"),
    ]);
}

fn provision_gateway(inventory: &AegisEgressInventory, local: &AegisEgressHost, key: &str) {
    let config = &inventory.config;
    run(&["ip", "link", "add", &config.interface, "type", "wireguard"]);
    for (family, address, prefix) in [
        ("-4", &local.ipv4, 32),
        ("-4", &local.dns_ipv4, 32),
        ("-6", &local.ipv6, 128),
        ("-6", &local.dns_ipv6, 128),
    ] {
        run(&[
            "ip",
            family,
            "address",
            "add",
            &format!("{address}/{prefix}"),
            "dev",
            &config.interface,
        ]);
    }
    run(&[
        "ip",
        "link",
        "set",
        &config.interface,
        "mtu",
        &config.mtu.to_string(),
        "up",
    ]);
    let sources = gateway_members(inventory, local.host_id);
    let rendered = egress_wireguard_config_contents(
        config,
        local,
        &EgressWireGuardPeerPlan {
            default_target: None,
            gateway_sources: &sources,
        },
        key,
    )
    .unwrap();
    WireGuardRuntime::parse(&config.interface, &rendered)
        .unwrap()
        .reconcile()
        .unwrap();
    configure_egress_forwarding(&config.interface).unwrap();
    reconcile_egress_main_routes(config, &egress_gateway_routes(&sources)).unwrap();
    apply_egress_nftables_runtime(EgressNftablesState {
        config,
        local,
        mode: LocalEgressMode::Direct,
        gateway_chained: false,
        target_sources: &sources,
    })
    .unwrap();
}

fn ordinary_https(ipv6: bool) -> Result<serde_json::Value> {
    let address = if ipv6 {
        "[2001:db8:ffff::1]:443"
    } else {
        "192.0.2.1:443"
    };
    Ok(reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .resolve("egress.test", address.parse().unwrap())
        .build()?
        .get("https://egress.test/")
        .send()?
        .json()?)
}

fn assert_exit(ipv6: bool, ipv4_address: &str, ipv6_address: &str) {
    let result = ordinary_https(ipv6).expect("ordinary application HTTPS");
    assert_eq!(
        result["exit"],
        if ipv6 { ipv6_address } else { ipv4_address }
    );
}

#[test]
#[ignore = "requires root; creates a private network namespace before changing firewall rules"]
fn isolated_docker_forwarding_is_scoped_and_reversible() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let namespace = Namespace::new();
    let _entered = namespace.enter();
    configure_egress_docker_forwarding("wg-test").unwrap();
    let programs = ["/usr/sbin/iptables", "/usr/sbin/ip6tables"];
    for program in programs {
        run(&[program, "-N", "DOCKER-USER"]);
        run(&[program, "-P", "FORWARD", "DROP"]);
        run(&[
            program,
            "-A",
            "DOCKER-USER",
            "-m",
            "comment",
            "--comment",
            "operator",
            "-j",
            "RETURN",
        ]);
    }
    let original = programs.map(|program| run(&[program, "-S"]));
    configure_egress_docker_forwarding("wg-test").unwrap();
    let configured = programs.map(|program| run(&[program, "-S"]));
    configure_egress_docker_forwarding("wg-test").unwrap();
    assert_eq!(configured, programs.map(|program| run(&[program, "-S"])));
    for policy in &configured {
        assert!(
            policy.contains("-P FORWARD DROP"),
            "global policy was widened"
        );
        let rules = policy
            .lines()
            .filter(|line| line.contains("aegis-egress"))
            .collect::<Vec<_>>();
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().all(|line| line.contains("wg-test")));
        assert!(
            rules
                .iter()
                .any(|line| line.contains("RELATED,ESTABLISHED"))
        );
        assert!(policy.contains("--comment operator -j RETURN"));
    }
    let cleanup = format!(
        "set -euo pipefail\nrun() {{ /usr/bin/timeout 5s \"$@\"; }}\n{}",
        egress_docker_forwarding_cleanup("wg-test")
    );
    run(&["/bin/bash", "-c", &cleanup]);
    assert_eq!(original, programs.map(|program| run(&[program, "-S"])));
    run(&["/bin/bash", "-c", &cleanup]);
    assert_eq!(original, programs.map(|program| run(&[program, "-S"])));
}

#[test]
#[ignore = "requires root; isolates network and mount namespaces before any mutation; run tests/run-isolated.sh"]
fn isolated_tunnel_end_to_end() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "run the isolated test runner as root"
    );
    assert!(
        std::env::var_os("AEGIS_TEST_BINARY").is_some(),
        "runner must supply the compiled worker executable"
    );
    let host_net = fs::metadata("/proc/thread-self/ns/net").unwrap().ino();
    let host_mount = fs::metadata("/proc/thread-self/ns/mnt").unwrap().ino();
    assert_eq!(
        unsafe { libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWNS) },
        0,
        "isolation failed: {}",
        std::io::Error::last_os_error()
    );
    assert_ne!(
        host_net,
        fs::metadata("/proc/thread-self/ns/net").unwrap().ino()
    );
    assert_ne!(
        host_mount,
        fs::metadata("/proc/thread-self/ns/mnt").unwrap().ino()
    );
    let slash = c"/";
    assert_eq!(
        unsafe {
            libc::mount(
                std::ptr::null(),
                slash.as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        },
        0
    );
    // No host routes or devices can exist here, and mounts cannot propagate to the host.
    assert_eq!(
        run(&["ip", "-j", "route", "show", "table", "main"]).trim(),
        "[]"
    );
    let directory = tempfile::tempdir().unwrap();
    isolate_files(directory.path());
    run(&["ip", "link", "set", "lo", "up"]);
    let cert = directory.path().join("cert.pem");
    let key = directory.path().join("key.pem");
    run(&[
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-noenc",
        "-days",
        "1",
        "-subj",
        "/CN=egress.test",
        "-addext",
        "subjectAltName=DNS:egress.test",
        "-addext",
        "basicConstraints=critical,CA:FALSE",
        "-keyout",
        key.to_str().unwrap(),
        "-out",
        cert.to_str().unwrap(),
    ]);
    // This dedicated test process has no other tests running. Child probes inherit only test trust.
    unsafe {
        std::env::set_var("SSL_CERT_FILE", &cert);
    }
    let internet = Namespace::new();
    internet.run(&["ip", "address", "add", "192.0.2.1/32", "dev", "lo"]);
    internet.run(&[
        "ip",
        "-6",
        "address",
        "add",
        "2001:db8:ffff::1/128",
        "dev",
        "lo",
        "nodad",
    ]);
    let _https = internet.fixture(directory.path(), "internet", &[]);
    ready(&directory.path().join("ready-internet"));
    internet_link(&internet, "direct", "198.18.0", "2001:db8:3");
    let hub_a = Namespace::new();
    let hub_b = Namespace::new();
    mesh_link(&hub_a, "a", "10.75.0.3");
    mesh_link(&hub_b, "b", "10.75.0.4");
    let (source_key, source_public) = keypair();
    let (a_key, a_public) = keypair();
    let (b_key, b_public) = keypair();
    let mut source = tests::egress_host("source", 2);
    source.public_key = source_public;
    let mut a = tests::egress_host("hub-a", 3);
    a.public_key = a_public;
    let mut b = tests::egress_host("hub-b", 4);
    b.public_key = b_public;
    let inventory = AegisEgressInventory {
        config: tests::test_egress_config(),
        hosts: [source.clone(), a.clone(), b.clone()]
            .into_iter()
            .map(|host| (host.host_id, host))
            .collect(),
        policies: BTreeMap::new(),
    };
    {
        let _enter = hub_a.enter();
        internet_link(&internet, "a", "203.0.113", "2001:db8:1");
        provision_gateway(&inventory, &a, &a_key);
    }
    {
        let _enter = hub_b.enter();
        internet_link(&internet, "b", "198.51.100", "2001:db8:2");
        provision_gateway(&inventory, &b, &b_key);
    }
    let _dns_a = hub_a.fixture(
        directory.path(),
        "dns",
        &["--ipv4", &a.dns_ipv4, "--ipv6", &a.dns_ipv6],
    );
    let _dns_b = hub_b.fixture(
        directory.path(),
        "dns",
        &["--ipv4", &b.dns_ipv4, "--ipv6", &b.dns_ipv6],
    );
    ready(&directory.path().join(format!("ready-dns-{}", a.dns_ipv4)));
    ready(&directory.path().join(format!("ready-dns-{}", b.dns_ipv4)));
    fs::write(
        directory.path().join("inventory.json"),
        serde_json::to_vec(&inventory).unwrap(),
    )
    .unwrap();
    let _api = Process(
        Command::new("python3")
            .args([FIXTURE, "api", "--directory"])
            .arg(directory.path())
            .process_group(0)
            .spawn()
            .unwrap(),
    );
    ready(&directory.path().join("ready-api"));
    let wireguard = managed_wireguard_config(&inventory.config.interface);
    fs::write(&wireguard.private_key_path, &source_key).unwrap();
    fs::set_permissions(
        &wireguard.private_key_path,
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::write(&wireguard.public_key_path, &source.public_key).unwrap();
    let mut raw = tests::raw_agent_config();
    raw.api_base = "https://egress.test/v2/namespaces/test".into();
    raw.host.host_id = source.host_id;
    let config = AgentConfig::try_from(raw).unwrap();
    let mut credentials = AgentCredentials::new("test-refresh".into());
    credentials.accept(
        crate::api::AgentAccessState {
            access_token: "test-agent".into(),
            refresh_token: "test-refresh".into(),
            host_id: source.host_id,
            credential_kind: aegis_dto::v1::AegisCredentialKind::Agent,
            access_expires_at_unix: crate::config::now_unix() + 3600,
        },
        |_| Ok(()),
    );
    let state = Arc::new(AppState {
        config,
        api: ApiClient::new("http://127.0.0.1:18080/v2/namespaces/test").unwrap(),
        config_path: PathBuf::from("/etc/aegis/agent.toml"),
        credentials: Mutex::new(credentials),
        reconcile_lock: Mutex::new(()),
        data_plane_lock: Mutex::new(()),
        egress_lock: Mutex::new(()),
        tunnel_operations: Mutex::new(Vec::new()),
        endpoint_recovery_peers: Mutex::new(Vec::new()),
        direct_targets: DirectTargetCache::default(),
        runtime: Mutex::new(RuntimeState::default()),
    });
    // Enrollment installs the passive gateway independently of any selected route.
    let sources = gateway_members(&inventory, source.host_id);
    let source_config = egress_wireguard_config_contents(
        &inventory.config,
        &source,
        &EgressWireGuardPeerPlan {
            default_target: None,
            gateway_sources: &sources,
        },
        &source_key,
    )
    .unwrap();
    restore_previous_egress_source_state(
        &EgressSourceTransition {
            config: &inventory.config,
            local: &source,
            wireguard: &wireguard,
            private_key: &source_key,
            api_base: &state.config.api_base,
            active_target: None,
            desired_target: None,
            gateway_sources: &sources,
        },
        &source_config,
    )
    .unwrap();
    for family in [false, true] {
        assert_exit(family, "198.18.0.2", "2001:db8:3::2");
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let socket = directory.path().join("agent.sock");
    let listener = runtime.block_on(async { tokio::net::UnixListener::bind(&socket).unwrap() });
    let app = agent_app(Arc::clone(&state));
    let server = runtime.spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<AgentPeerCredentials>(),
        )
        .await
        .unwrap();
    });
    let client = reqwest::blocking::Client::builder()
        .unix_socket(socket.as_path())
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let request = |alias: &str, isolated| Request {
        via: Some(alias.parse().unwrap()),
        isolated,
    };
    let start = |request: &Request| -> operation::Snapshot {
        client
            .post(format!("http://localhost{}", operation::PATH))
            .bearer_auth("test-user")
            .json(request)
            .send()
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .unwrap()
    };
    let wait = |mut snapshot: operation::Snapshot| -> Result<String> {
        let deadline = Instant::now()
            + operation::TIMEOUT
            + operation::RECOVERY_TIMEOUT
            + Duration::from_secs(2);
        loop {
            match snapshot.state {
                operation::State::Succeeded { message } => return Ok(message),
                operation::State::Failed {
                    message,
                    interrupted,
                    ..
                } => {
                    return if interrupted {
                        Err(anyhow::Error::new(capulus::Cancelled).context(message))
                    } else {
                        Err(anyhow!(message))
                    };
                }
                operation::State::Running { .. } => {}
            }
            ensure!(
                Instant::now() < deadline,
                "test operation deadline exceeded"
            );
            thread::sleep(Duration::from_millis(30));
            snapshot = client
                .get(format!(
                    "http://localhost{}/{}",
                    operation::PATH,
                    snapshot.id
                ))
                .send()?
                .error_for_status()?
                .json()?;
        }
    };
    let execute = |request: &Request| {
        let started = Instant::now();
        let result = wait(start(request));
        eprintln!(
            "MEASUREMENT {:?} isolated={} elapsed_ms={} outcome={:?}",
            request.via,
            request.isolated,
            started.elapsed().as_millis(),
            result
        );
        (started.elapsed(), result)
    };
    let routes_before = run(&["ip", "-j", "rule", "show"]);
    let (elapsed, result) = execute(&request("hub-a", true));
    result.expect("isolated DNS/dual-stack HTTPS probe");
    assert!(
        elapsed < Duration::from_secs(4),
        "healthy isolated probe is too slow"
    );
    assert_eq!(routes_before, run(&["ip", "-j", "rule", "show"]));
    assert!(!Path::new(tunnel::JOURNAL).exists());
    let first_id = state.tunnel_operations.lock().unwrap().last().unwrap().id;
    let (elapsed, result) = execute(&request("hub-a", false));
    result.expect("enable through pre-enrolled gateway");
    let earlier: operation::Snapshot = client
        .get(format!("http://localhost{}/{}", operation::PATH, first_id))
        .send()
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .unwrap();
    assert!(
        matches!(earlier.state, operation::State::Succeeded { .. }),
        "a new command must not erase the preceding result"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "healthy enable is too slow"
    );
    for family in [false, true] {
        assert_exit(family, "203.0.113.2", "2001:db8:1::2");
    }
    // A failed IPv6 candidate must retain A, including its DNS and kill switch.
    hub_b.run(&["nft", "add", "table", "inet", "test_fault"]);
    hub_b.run(&[
        "nft",
        "add",
        "chain",
        "inet",
        "test_fault",
        "forward",
        "{ type filter hook forward priority -10; policy accept; }",
    ]);
    hub_b.run(&[
        "nft",
        "add",
        "rule",
        "inet",
        "test_fault",
        "forward",
        "meta",
        "nfproto",
        "ipv6",
        "drop",
    ]);
    let (elapsed, failed) = execute(&request("hub-b", false));
    assert!(failed.is_err(), "broken IPv6 must fail validation");
    assert!(elapsed < operation::TIMEOUT + operation::RECOVERY_TIMEOUT);
    for family in [false, true] {
        assert_exit(family, "203.0.113.2", "2001:db8:1::2");
    }
    // Cancellation uses the same local HTTP operation, and must retain its typed result.
    let snapshot = start(&request("hub-b", false));
    thread::sleep(Duration::from_millis(150));
    let started = Instant::now();
    client
        .delete(format!(
            "http://localhost{}/{}",
            operation::PATH,
            snapshot.id
        ))
        .send()
        .unwrap()
        .error_for_status()
        .unwrap();
    let error = wait(snapshot).expect_err("cancelled operation");
    assert!(capulus::error_is_cancelled(&error));
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(!Path::new(tunnel::JOURNAL).exists());
    for family in [false, true] {
        assert_exit(family, "203.0.113.2", "2001:db8:1::2");
    }
    hub_b.run(&["nft", "delete", "table", "inet", "test_fault"]);
    // Candidate uses the transport identity; the committed probe uses the DNS identity.
    // Break only the latter to exercise rollback after the local route has changed.
    hub_b.run(&["nft", "add", "table", "inet", "test_fault"]);
    hub_b.run(&[
        "nft",
        "add",
        "chain",
        "inet",
        "test_fault",
        "forward",
        "{ type filter hook forward priority -10; policy accept; }",
    ]);
    hub_b.run(&[
        "nft",
        "add",
        "rule",
        "inet",
        "test_fault",
        "forward",
        "ip6",
        "saddr",
        &source.dns_ipv6,
        "drop",
    ]);
    let (_, result) = execute(&request("hub-b", false));
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("previous Internet route restored")
    );
    for family in [false, true] {
        assert_exit(family, "203.0.113.2", "2001:db8:1::2");
    }
    hub_b.run(&["nft", "delete", "table", "inet", "test_fault"]);

    // Old gateway failure cannot hold up switching to B.
    run(&["ip", "link", "set", "sa", "down"]);
    fs::write(directory.path().join("reject-report"), "").unwrap();
    let (elapsed, result) = execute(&request("hub-b", false));
    assert!(
        result
            .expect("switch while previous gateway is offline")
            .contains("central reporting pending")
    );
    assert!(Path::new(tunnel::JOURNAL).exists());
    fs::remove_file(directory.path().join("reject-report")).unwrap();
    let mut current = state.api.get_egress_inventory("test-agent").unwrap();
    operation::bounded(operation::RECOVERY_TIMEOUT, || {
        tunnel::recover_pending(&state, "test-agent", &mut current)
    })
    .unwrap();
    assert!(!Path::new(tunnel::JOURNAL).exists());
    assert_eq!(
        Some(b.host_id),
        current.policies[&source.host_id].active_via
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "healthy switch is too slow"
    );
    for family in [false, true] {
        assert_exit(family, "198.51.100.2", "2001:db8:2::2");
    }
    run(&["ip", "link", "set", "sb", "down"]);
    for family in [false, true] {
        assert!(
            ordinary_https(family).is_err(),
            "kill switch must prevent direct fallback"
        );
    }
    fs::write(directory.path().join("lose-ack"), "").unwrap();
    let (_, result) = execute(&Request {
        via: None,
        isolated: false,
    });
    assert!(
        result
            .expect("disable without gateway acknowledgement")
            .contains("central reporting pending")
    );
    fs::remove_file(directory.path().join("lose-ack")).unwrap();
    let mut current = state.api.get_egress_inventory("test-agent").unwrap();
    operation::bounded(operation::RECOVERY_TIMEOUT, || {
        tunnel::recover_pending(&state, "test-agent", &mut current)
    })
    .unwrap();
    assert!(!Path::new(tunnel::JOURNAL).exists());
    assert!(current.policies.is_empty());
    // A process crash before the Applied record must not resume an abandoned selection.
    let pending = state
        .api
        .put_egress(
            "test-user",
            &source.host_id,
            &AegisEgressEnableRequest { via: a.host_id },
        )
        .unwrap();
    fs::write(
        tunnel::JOURNAL,
        serde_json::to_vec(&serde_json::json!({
            "source": source.host_id, "revision": pending.policy.unwrap().revision,
            "previous": null, "requested": a.host_id, "outcome": "rejected",
        }))
        .unwrap(),
    )
    .unwrap();
    let mut current = state.api.get_egress_inventory("test-agent").unwrap();
    operation::bounded(operation::RECOVERY_TIMEOUT, || {
        tunnel::recover_pending(&state, "test-agent", &mut current)
    })
    .unwrap();
    assert!(current.policies.is_empty());
    assert!(!Path::new(tunnel::JOURNAL).exists());
    for family in [false, true] {
        assert_exit(family, "198.18.0.2", "2001:db8:3::2");
    }
    // Chaining uses the same pre-enrolled peers. A forwards to B over the egress
    // interface; ordinary source traffic must leave through B's WAN in both families.
    run(&["ip", "link", "set", "sa", "up"]);
    run(&["ip", "link", "set", "sb", "up"]);
    run(&["ip", "route", "replace", "10.75.0.3/32", "dev", "sa"]);
    run(&["ip", "route", "replace", "10.75.0.4/32", "dev", "sb"]);
    {
        let _enter = hub_a.enter();
        run(&[
            "ip", "link", "add", "ab", "type", "veth", "peer", "name", "ba",
        ]);
        run(&["ip", "link", "set", "ba", "netns", &hub_b.pid()]);
        run(&["ip", "address", "add", "10.75.0.3/32", "dev", "ab"]);
        run(&["ip", "link", "set", "ab", "up"]);
        run(&["ip", "route", "add", "10.75.0.4/32", "dev", "ab"]);
        hub_b.run(&["ip", "address", "add", "10.75.0.4/32", "dev", "ba"]);
        hub_b.run(&["ip", "link", "set", "ba", "up"]);
        hub_b.run(&["ip", "route", "add", "10.75.0.3/32", "dev", "ba"]);
        let members = gateway_members(&inventory, a.host_id);
        let config = egress_wireguard_config_contents(
            &inventory.config,
            &a,
            &EgressWireGuardPeerPlan {
                default_target: Some(&b),
                gateway_sources: &members,
            },
            &a_key,
        )
        .unwrap();
        WireGuardRuntime::parse(&inventory.config.interface, &config)
            .unwrap()
            .reconcile()
            .unwrap();
        restore_tunneled_egress_runtime(&inventory.config, &a, &b, &members).unwrap();
    }
    let pending = state
        .api
        .put_egress(
            "test-user",
            &a.host_id,
            &AegisEgressEnableRequest { via: b.host_id },
        )
        .unwrap();
    state
        .api
        .post_egress_result(
            "test-agent",
            &a.host_id,
            &AegisEgressResult {
                revision: pending.policy.unwrap().revision,
                outcome: AegisEgressOutcome::Applied,
            },
        )
        .unwrap();
    let (elapsed, result) = execute(&request("hub-a", false));
    result.expect("source through gateway A through gateway B");
    assert!(elapsed < Duration::from_secs(5));
    for family in [false, true] {
        assert_exit(family, "198.51.100.2", "2001:db8:2::2");
    }
    assert!(
        execute(&request("hub-a", true))
            .1
            .unwrap_err()
            .to_string()
            .contains("active WireGuard peer")
    );
    execute(&Request {
        via: None,
        isolated: false,
    })
    .1
    .unwrap();
    for family in [false, true] {
        assert_exit(family, "198.18.0.2", "2001:db8:3::2");
    }
    // A membership removal revokes access without consulting route selections.
    {
        let _enter = hub_b.enter();
        let mut revoked = inventory.clone();
        revoked.hosts.remove(&source.host_id);
        let members = gateway_members(&revoked, b.host_id);
        let config = egress_wireguard_config_contents(
            &inventory.config,
            &b,
            &EgressWireGuardPeerPlan {
                default_target: None,
                gateway_sources: &members,
            },
            &b_key,
        )
        .unwrap();
        WireGuardRuntime::parse(&inventory.config.interface, &config)
            .unwrap()
            .reconcile()
            .unwrap();
        reconcile_egress_main_routes(&inventory.config, &egress_gateway_routes(&members)).unwrap();
        apply_egress_nftables_runtime(EgressNftablesState {
            config: &inventory.config,
            local: &b,
            mode: LocalEgressMode::Direct,
            gateway_chained: false,
            target_sources: &members,
        })
        .unwrap();
    }
    assert!(
        execute(&request("hub-b", true)).1.is_err(),
        "revoked peers must lose gateway access"
    );
    for family in [false, true] {
        assert_exit(family, "198.18.0.2", "2001:db8:3::2");
    }
    server.abort();
    runtime.shutdown_timeout(Duration::from_secs(2));
    eprintln!(
        "PASS: isolated probe, dual-stack enable, candidate and committed failure rollback, cancellation, offline-old-gateway switch, kill switch, disable, acknowledgement recovery, crash recovery, chained gateways, peer revocation"
    );
}
