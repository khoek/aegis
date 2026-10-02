use super::{AppliedConfigStatus, WireGuardRuntime};
use crate::command::{require_success, require_success_with_input};
use std::{
    fs::{self, File},
    net::{Ipv4Addr, UdpSocket},
    os::{fd::AsRawFd, unix::fs::MetadataExt, unix::process::CommandExt},
    path::Path,
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};

struct NetworkNamespace(File);

impl NetworkNamespace {
    fn enter() -> Self {
        let previous = File::open("/proc/thread-self/ns/net").unwrap();
        assert_eq!(
            unsafe { libc::unshare(libc::CLONE_NEWNET) },
            0,
            "kernel test needs CAP_SYS_ADMIN: {}",
            std::io::Error::last_os_error(),
        );
        Self(previous)
    }
}

impl Drop for NetworkNamespace {
    fn drop(&mut self) {
        assert_eq!(
            unsafe { libc::setns(self.0.as_raw_fd(), libc::CLONE_NEWNET) },
            0
        );
    }
}

struct HubNamespace(Child);

impl HubNamespace {
    fn start() -> Self {
        let current = fs::metadata("/proc/thread-self/ns/net").unwrap().ino();
        let mut hub = Self(
            Command::new("/usr/bin/unshare")
                .args(["--net", "/usr/bin/timeout", "90s", "/usr/bin/sleep", "90"])
                .process_group(0)
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(hub.0.try_wait().unwrap().is_none(), "hub namespace exited");
            if fs::metadata(format!("/proc/{}/ns/net", hub.0.id()))
                .is_ok_and(|namespace| namespace.ino() != current)
            {
                return hub;
            }
            assert!(
                Instant::now() < deadline,
                "hub namespace creation timed out"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn run(&self, arguments: &[&str], input: Option<&str>) -> String {
        let pid = self.0.id().to_string();
        run(
            &[
                &["/usr/bin/nsenter", "--target", &pid, "--net", "--"],
                arguments,
            ]
            .concat(),
            input,
        )
    }
}

impl Drop for HubNamespace {
    fn drop(&mut self) {
        unsafe { libc::kill(-(self.0.id() as i32), libc::SIGKILL) };
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.0.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "hub namespace cleanup timed out");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn run(arguments: &[&str], input: Option<&str>) -> String {
    let mut command = Command::new("/usr/bin/timeout");
    command.arg("5s").args(arguments);
    match input {
        Some(input) => {
            require_success_with_input("WireGuard kernel test", &mut command, input.as_bytes())
        }
        None => require_success("WireGuard kernel test", &mut command),
    }
    .unwrap()
    .stdout
}

struct KeyPair {
    private: String,
    public: String,
}

impl KeyPair {
    fn generate() -> Self {
        let private = run(&["/usr/bin/wg", "genkey"], None).trim().to_string();
        let public = run(&["/usr/bin/wg", "pubkey"], Some(&private))
            .trim()
            .to_string();
        Self { private, public }
    }
}

fn runtime<'a>(interface: &'a str, config: &str, state: &Path) -> WireGuardRuntime<'a> {
    let mut runtime = WireGuardRuntime::parse(interface, config).unwrap();
    runtime.port_state_path = state.to_owned();
    runtime
}

fn listening_port(interface: &str) -> u16 {
    run(&["/usr/bin/wg", "show", interface, "listen-port"], None)
        .trim()
        .parse()
        .unwrap()
}

fn ping_hub() {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let output = Command::new("/usr/bin/timeout")
            .args([
                "2s",
                "/usr/bin/ping",
                "-n",
                "-c",
                "1",
                "-W",
                "1",
                "10.254.0.1",
            ])
            .output()
            .unwrap();
        if output.status.success() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "WireGuard handshake/data path timed out"
        );
    }
}

fn start_leaf(config: &str) {
    run(
        &["/usr/sbin/ip", "link", "add", "leaf", "type", "wireguard"],
        None,
    );
    run(
        &["/usr/bin/wg", "setconf", "leaf", "/dev/stdin"],
        Some(config),
    );
    run(
        &[
            "/usr/sbin/ip",
            "address",
            "add",
            "10.254.0.2/32",
            "dev",
            "leaf",
        ],
        None,
    );
    run(&["/usr/sbin/ip", "link", "set", "leaf", "up"], None);
    run(
        &[
            "/usr/sbin/ip",
            "route",
            "add",
            "10.254.0.1/32",
            "dev",
            "leaf",
        ],
        None,
    );
}

#[test]
#[ignore = "requires root/CAP_SYS_ADMIN and WireGuard; all interfaces are created in private network namespaces"]
fn automatic_ports_survive_upgrade_peer_updates_restarts_and_gateway_transitions() {
    let _namespace = NetworkNamespace::enter();
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("port.sha256");
    let hub = HubNamespace::start();
    let hub_key = KeyPair::generate();
    let leaf_key = KeyPair::generate();

    run(&["/usr/sbin/ip", "link", "set", "lo", "up"], None);
    run(
        &[
            "/usr/sbin/ip",
            "link",
            "add",
            "underlay",
            "type",
            "veth",
            "peer",
            "name",
            "hub-underlay",
        ],
        None,
    );
    run(
        &[
            "/usr/sbin/ip",
            "link",
            "set",
            "hub-underlay",
            "netns",
            &hub.0.id().to_string(),
        ],
        None,
    );
    run(
        &[
            "/usr/sbin/ip",
            "address",
            "add",
            "192.0.2.2/30",
            "dev",
            "underlay",
        ],
        None,
    );
    run(&["/usr/sbin/ip", "link", "set", "underlay", "up"], None);
    hub.run(&["/usr/sbin/ip", "link", "set", "lo", "up"], None);
    hub.run(
        &[
            "/usr/sbin/ip",
            "address",
            "add",
            "192.0.2.1/30",
            "dev",
            "hub-underlay",
        ],
        None,
    );
    hub.run(&["/usr/sbin/ip", "link", "set", "hub-underlay", "up"], None);
    hub.run(
        &["/usr/sbin/ip", "link", "add", "hub", "type", "wireguard"],
        None,
    );
    let hub_config = format!(
        "[Interface]\nPrivateKey = {}\nListenPort = 51820\n\n\
         [Peer]\nPublicKey = {}\nAllowedIPs = 10.254.0.2/32\n",
        hub_key.private, leaf_key.public,
    );
    hub.run(
        &["/usr/bin/wg", "setconf", "hub", "/dev/stdin"],
        Some(&hub_config),
    );
    hub.run(
        &[
            "/usr/sbin/ip",
            "address",
            "add",
            "10.254.0.1/32",
            "dev",
            "hub",
        ],
        None,
    );
    hub.run(&["/usr/sbin/ip", "link", "set", "hub", "up"], None);
    hub.run(
        &[
            "/usr/sbin/ip",
            "route",
            "add",
            "10.254.0.2/32",
            "dev",
            "hub",
        ],
        None,
    );

    let fixed = format!(
        "[Interface]\nPrivateKey = {}\nListenPort = 51820\nFwMark = 44641\n\n\
         [Peer]\nPublicKey = {}\nAllowedIPs = 10.254.0.1/32\n\
         Endpoint = 192.0.2.1:51820\nPersistentKeepalive = 5\n",
        leaf_key.private, hub_key.public,
    );
    let automatic = fixed.replace("ListenPort = 51820", "ListenPort = 0");
    start_leaf(&fixed);
    ping_hub();
    eprintln!("verified fixed-port leaf with a fixed-port hub; applying automatic policy");
    runtime("leaf", &automatic, &state).reconcile().unwrap();
    let selected = listening_port("leaf");
    assert_ne!(selected, 0);
    assert_ne!(selected, 51820);

    run(
        &["/usr/sbin/ip", "link", "add", "wg0", "type", "wireguard"],
        None,
    );
    run(&["/usr/bin/wg", "set", "wg0", "listen-port", "51820"], None);
    run(&["/usr/sbin/ip", "link", "set", "wg0", "up"], None);
    for _ in 0..3 {
        runtime("leaf", &automatic, &state).reconcile().unwrap();
        assert_eq!(listening_port("leaf"), selected);
    }
    ping_hub();
    assert!(
        hub.run(&["/usr/bin/wg", "show", "hub", "endpoints"], None)
            .contains(&format!("192.0.2.2:{selected}"))
    );

    let extra = KeyPair::generate();
    let expanded = format!(
        "{automatic}\n[Peer]\nPublicKey = {}\nAllowedIPs = 10.254.0.3/32\n",
        extra.public
    );
    runtime("leaf", &expanded, &state).reconcile().unwrap();
    assert_eq!(listening_port("leaf"), selected);
    assert_eq!(
        run(&["/usr/bin/wg", "show", "leaf", "peers"], None)
            .lines()
            .count(),
        2
    );
    runtime("leaf", &automatic, &state).reconcile().unwrap();
    assert_eq!(listening_port("leaf"), selected);
    assert_eq!(
        run(&["/usr/bin/wg", "show", "leaf", "peers"], None)
            .lines()
            .count(),
        1
    );
    ping_hub();
    eprintln!("verified coexistence on 51820 and stable port across peer updates");

    run(&["/usr/sbin/ip", "link", "delete", "leaf"], None);
    start_leaf(&automatic);
    let restarted = listening_port("leaf");
    runtime("leaf", &automatic, &state).record_start().unwrap();
    runtime("leaf", &automatic, &state).reconcile().unwrap();
    assert_eq!(listening_port("leaf"), restarted);
    ping_hub();

    let gateway = fixed.replace("ListenPort = 51820", "ListenPort = 51823");
    let listener = runtime("leaf", &gateway, &state);
    let occupied = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 51823)).unwrap();
    assert!(listener.reconcile().is_err());
    assert_eq!(
        listener
            .applied_port(listening_port("leaf"))
            .status()
            .unwrap(),
        AppliedConfigStatus::Stale
    );
    assert_eq!(listening_port("leaf"), restarted);
    drop(occupied);
    listener.reconcile().unwrap();
    assert_eq!(listening_port("leaf"), 51823);
    assert_eq!(
        listener
            .applied_port(listening_port("leaf"))
            .status()
            .unwrap(),
        AppliedConfigStatus::Current
    );
    ping_hub();

    run(&["/usr/bin/wg", "set", "leaf", "listen-port", "0"], None);
    listener.reconcile().unwrap();
    assert_eq!(listening_port("leaf"), 51823);
    runtime("leaf", &automatic, &state).reconcile().unwrap();
    let retired = listening_port("leaf");
    assert_ne!(retired, 51823);
    runtime("leaf", &automatic, &state).reconcile().unwrap();
    assert_eq!(listening_port("leaf"), retired);
    // A reboot after a crash can restore the old on-disk fixed port even though
    // the automatic runtime policy had already been recorded successfully.
    run(&["/usr/sbin/ip", "link", "delete", "leaf"], None);
    start_leaf(&gateway);
    runtime("leaf", &automatic, &state).reconcile().unwrap();
    let recovered = listening_port("leaf");
    assert_ne!(recovered, 51823);
    runtime("leaf", &automatic, &state).reconcile().unwrap();
    assert_eq!(listening_port("leaf"), recovered);
    assert_eq!(listening_port("wg0"), 51820);
    assert_eq!(
        hub.run(&["/usr/bin/wg", "show", "hub", "listen-port"], None)
            .trim(),
        "51820"
    );
    ping_hub();
    eprintln!(
        "verified restart, failed gateway activation/retry, fixed-port repair, gateway retirement and stale startup recovery"
    );
}
