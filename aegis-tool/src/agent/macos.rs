mod transport;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    net::{IpAddr, SocketAddr, UdpSocket},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        LazyLock, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{babel, *};

const STATE: &str = "/private/var/lib/aegis/native";
const RUNTIME: &str = "/private/var/run/aegis";
const HELPER: &str = "/Library/PrivilegedHelperTools/aegis-babeld";
const HELPER_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/aegis-babeld"));
const NATIVE_TIMEOUT: Duration = Duration::from_secs(10);

static SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);

static MESH: LazyLock<Mutex<Option<Mesh>>> = LazyLock::new(|| Mutex::new(None));

pub(super) struct NetworkOptions<'a> {
    pub network: &'a str,
    pub config: &'a NetworkAgentConfig,
    pub inventory: &'a ResolvedNetwork,
    pub local: &'a InventoryHost,
    pub peers: &'a [&'a InventoryHost],
}

struct Mesh {
    _lock: File,
    sessions: BTreeMap<String, Session>,
}

struct Session {
    fingerprint: Vec<u8>,
    journal: Journal,
    wireguard: Option<Child>,
    babel: Option<Child>,
    transport: Option<transport::Transport>,
    uapi: String,
    mesh: Option<AegisMeshConfig>,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    network: String,
    wireguard: String,
    overlays: Vec<OwnedEthernet>,
    internal: Vec<IpAddr>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnedEthernet {
    interface: String,
    peer: String,
    mac: [u8; 6],
    peer_mac: [u8; 6],
}

impl Mesh {
    fn open() -> Result<Self> {
        secure_directory(Path::new(STATE))?;
        fs::create_dir_all(RUNTIME)?;
        let runtime = fs::symlink_metadata(RUNTIME)?;
        ensure!(
            runtime.file_type().is_dir() && runtime.uid() == 0 && runtime.mode() & 0o022 == 0,
            "unsafe Aegis runtime directory"
        );
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(Path::new(STATE).join("owner.lock"))?;
        lock.try_lock()
            .context("another Aegis process owns the native mesh")?;
        for entry in fs::read_dir(STATE)? {
            let path = entry?.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                let journal = Journal::read(&path)?;
                journal.cleanup()?;
            }
        }
        Ok(Self {
            _lock: lock,
            sessions: BTreeMap::new(),
        })
    }
}

pub(super) fn reconcile(options: NetworkOptions<'_>) -> Result<()> {
    options.local.platform.require_role(options.local.mode)?;
    ensure!(
        options.local.mode == AegisHostMode::Leaf,
        "the macOS mesh requires a leaf role"
    );
    let fingerprint = Sha256::digest(serde_json::to_vec(&(
        &options.inventory.config,
        options.local.host_id,
        &options.local.wireguard,
        &options.local.internal,
        options
            .peers
            .iter()
            .map(|peer| (peer.host_id, &peer.wireguard, peer.mode))
            .collect::<Vec<_>>(),
        load_private_key(&options.config.wireguard.private_key_path)?,
    ))?)
    .to_vec();
    let mut mesh = MESH.lock().expect("native mesh lock");
    ensure!(
        !SHUTTING_DOWN.load(Ordering::Acquire),
        "native mesh is shutting down"
    );
    if mesh.is_none() {
        *mesh = Some(Mesh::open()?);
    }
    let mesh = mesh.as_mut().expect("native mesh initialized");
    let rebuild = match mesh.sessions.get_mut(options.network) {
        Some(session) => session.fingerprint != fingerprint || !session.running()?,
        None => true,
    };
    if rebuild {
        if let Some(mut previous) = mesh.sessions.remove(options.network) {
            previous.stop()?;
        }
        let session = Session::start(&options, fingerprint)?;
        mesh.sessions.insert(options.network.into(), session);
    }
    Ok(())
}

impl Session {
    fn start(options: &NetworkOptions<'_>, fingerprint: Vec<u8>) -> Result<Self> {
        install_helper()?;
        ensure!(
            options
                .network
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
            "invalid network name"
        );
        let wireguard = options
            .local
            .wireguard
            .as_ref()
            .context("local WireGuard identity is missing")?;
        let mut session = Self {
            fingerprint,
            journal: Journal {
                network: options.network.into(),
                wireguard: unused_interface("utun", 32)?,
                ..Default::default()
            },
            wireguard: None,
            babel: None,
            transport: None,
            uapi: wireguard_uapi(options)?,
            mesh: options.inventory.config.mesh.clone(),
        };
        session.journal.persist()?;
        let started = (|| -> Result<()> {
            secure_directory(Path::new("/private/var/run/wireguard"))?;
            session.wireguard = Some(
                Command::new(
                    crate::managed::product()?
                        .program()
                        .trusted_installed_path()?,
                )
                .args([
                    "agent",
                    "wireguard-worker",
                    "--interface",
                    &session.journal.wireguard,
                ])
                .env_clear()
                .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                .env("LC_ALL", "C")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()?,
            );
            let deadline = Instant::now() + NATIVE_TIMEOUT;
            while !uapi_path(&session.journal.wireguard).exists() {
                ensure!(
                    Instant::now() < deadline,
                    "WireGuard startup deadline elapsed"
                );
                ensure!(
                    session
                        .wireguard
                        .as_mut()
                        .expect("started child")
                        .try_wait()?
                        .is_none(),
                    "WireGuard worker exited during startup"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
            fs::set_permissions(
                uapi_path(&session.journal.wireguard),
                fs::Permissions::from_mode(0o600),
            )?;
            uapi_request(&session.journal.wireguard, &session.uapi)?;
            native(
                "configure WireGuard IPv4",
                "/sbin/ifconfig",
                &[
                    &session.journal.wireguard,
                    "inet",
                    &wireguard.ipv4,
                    &wireguard.ipv4,
                    "netmask",
                    "255.255.255.255",
                    "up",
                ],
            )?;
            native(
                "configure WireGuard IPv6",
                "/sbin/ifconfig",
                &[
                    &session.journal.wireguard,
                    "inet6",
                    &format!("{}/128", wireguard.ipv6),
                    "alias",
                ],
            )?;
            native(
                "configure WireGuard MTU",
                "/sbin/ifconfig",
                &[
                    &session.journal.wireguard,
                    "mtu",
                    &options.inventory.config.wireguard.mtu.to_string(),
                ],
            )?;
            for peer in options.peers {
                if let Some(peer) = &peer.wireguard {
                    for address in [&peer.ipv4, &peer.ipv6] {
                        let address = address.parse::<IpAddr>()?;
                        native(
                            "route WireGuard peer",
                            "/sbin/route",
                            &[
                                "-n",
                                "add",
                                family(address),
                                "-host",
                                &address.to_string(),
                                "-interface",
                                &session.journal.wireguard,
                            ],
                        )?;
                    }
                }
            }
            if options.config.managed_mesh {
                session.start_mesh(options)?;
            }
            Ok(())
        })();
        if let Err(error) = started {
            let cleanup = session.stop();
            return Err(match cleanup {
                Ok(()) => error.context(
                    "native mesh startup failed; owned interfaces and workers were removed",
                ),
                Err(cleanup) => anyhow!(
                    "native mesh startup failed: {error:#}; cleanup failed: {cleanup:#}; ownership journal retained"
                ),
            });
        }
        Ok(session)
    }

    fn start_mesh(&mut self, options: &NetworkOptions<'_>) -> Result<()> {
        let mesh = options
            .inventory
            .config
            .mesh
            .as_ref()
            .context("managed mesh configuration is missing")?;
        let internal = options
            .local
            .internal
            .as_ref()
            .context("stable mesh addresses are missing")?;
        let internal_addresses: Vec<IpAddr> = vec![internal.ipv4.parse()?, internal.ipv6.parse()?];
        let loopback = native("inspect loopback ownership", "/sbin/ifconfig", &["lo0"])?;
        for address in &internal_addresses {
            ensure!(
                !loopback
                    .split_whitespace()
                    .any(|word| word == address.to_string()),
                "stable address {address} already exists outside this ownership journal"
            );
        }
        self.journal.internal = internal_addresses;
        self.journal.persist()?;
        for &address in &self.journal.internal {
            add_alias("lo0", address)?;
        }
        let local_wireguard = options
            .local
            .wireguard
            .as_ref()
            .context("WireGuard identity missing")?;
        let mut peers = Vec::new();
        for peer in options.peers {
            let Some(wireguard) = &peer.wireguard else {
                continue;
            };
            let identity = super::vxlan::Peer {
                address: wireguard.ipv4.parse()?,
                vni: peer_overlay_vni(&options.local.host_id, &peer.host_id),
            }
            .validate()?;
            let ethernet = OwnedEthernet::allocate()?;
            self.journal.overlays.push(ethernet);
            self.journal.persist()?;
            let ethernet = self
                .journal
                .overlays
                .last()
                .expect("reserved Ethernet pair");
            let transit = peer_overlay_transit_addrs(&options.local.host_id, &peer.host_id);
            let device = tun_rs::DeviceBuilder::new()
                .layer(tun_rs::Layer::L2)
                .name(&ethernet.interface)
                .peer_feth(&ethernet.peer)
                .reuse_dev(false)
                .persist(true)
                .mac_addr(ethernet.mac)
                .mtu(mesh.overlay_mtu)
                .ipv4(transit.local_ipv4, 30, None)
                .ipv6(transit.local_ipv6, 127)
                .enable(true)
                .build_async()
                .context("create native VXLAN Ethernet pair")?;
            native(
                "tag owned Ethernet peer",
                "/sbin/ifconfig",
                &[&ethernet.peer, "ether", &format_mac(ethernet.peer_mac)],
            )?;
            ensure!(
                device.name()? == ethernet.interface,
                "native Ethernet allocation changed its requested name"
            );
            // Strong-end IPv6 selection requires the stable address on each outgoing interface.
            for &address in &self.journal.internal {
                add_alias(&ethernet.interface, address)?;
            }
            peers.push((identity, device));
        }
        self.transport = Some(transport::Transport::start(transport::Options {
            local: local_wireguard.ipv4.parse()?,
            wireguard_interface: &self.journal.wireguard,
            mtu: mesh.overlay_mtu,
            peers,
        })?);
        let configuration = babel::LeafOptions {
            mesh,
            internal,
            interfaces: &self
                .journal
                .overlays
                .iter()
                .map(|item| item.interface.clone())
                .collect::<Vec<_>>(),
            control_socket: self
                .journal
                .control_path()
                .to_str()
                .context("invalid Babel socket path")?,
            state_file: self
                .journal
                .babel_state_path()
                .to_str()
                .context("invalid Babel state path")?,
        }
        .render()?;
        native(
            "validate native Babel configuration",
            HELPER,
            &babel::validation_arguments(&configuration),
        )?;
        capulus::store::atomic_write(
            &self.journal.config_path(),
            configuration.as_bytes(),
            Some(0o600),
            Some(0o700),
        )?;
        self.babel = Some(
            Command::new(HELPER)
                .args(["-c"])
                .arg(self.journal.config_path())
                .env_clear()
                .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                .env("LC_ALL", "C")
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()?,
        );
        Ok(())
    }

    fn running(&mut self) -> Result<bool> {
        for child in [&mut self.wireguard, &mut self.babel].into_iter().flatten() {
            if child.try_wait()?.is_some() {
                return Ok(false);
            }
        }
        Ok(self
            .transport
            .as_ref()
            .is_none_or(|transport| transport.running()))
    }

    fn verify_routes(&self) -> Result<Vec<IpAddr>> {
        if self.babel.is_none() {
            return Ok(Vec::new());
        }
        let routes = babel::installed_routes(&babel_dump(&self.journal.control_path())?)?;
        let interfaces = self
            .journal
            .overlays
            .iter()
            .map(|item| item.interface.as_str())
            .collect::<BTreeSet<_>>();
        let mut verified = Vec::new();
        for route in routes {
            ensure!(
                self.mesh
                    .as_ref()
                    .is_some_and(|mesh| mesh_contains_ip(mesh, route.address)),
                "Babel installed a route outside the managed mesh"
            );
            ensure!(
                interfaces.contains(route.interface.as_str()),
                "Babel route uses an unowned interface"
            );
            let expected = self
                .journal
                .internal
                .iter()
                .copied()
                .find(|address| address.is_ipv4() == route.address.is_ipv4())
                .context("stable source address is missing")?;
            if selected_source(route.address)? != expected {
                native(
                    "select stable mesh source",
                    "/sbin/route",
                    &[
                        "-n",
                        "change",
                        family(route.address),
                        "-host",
                        &route.address.to_string(),
                        "-ifa",
                        &expected.to_string(),
                    ],
                )?;
            }
            ensure!(
                selected_source(route.address)? == expected,
                "macOS selected an unstable source for {}; expected {expected}; route is not ready",
                route.address
            );
            verified.push(route.address);
        }
        Ok(verified)
    }

    fn stop(&mut self) -> Result<()> {
        stop_child(&mut self.babel)?;
        self.transport.take();
        stop_child(&mut self.wireguard)?;
        self.journal.cleanup()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            eprintln!("native mesh cleanup incomplete; ownership journal retained: {error:#}");
        }
    }
}

impl OwnedEthernet {
    fn allocate() -> Result<Self> {
        let interface = unused_interface("feth", 0)?;
        let index = interface.trim_start_matches("feth").parse::<u32>()?;
        let peer = unused_interface("feth", index + 1)?;
        let bytes = uuid::Uuid::new_v4().into_bytes();
        let mut mac = [0; 6];
        mac.copy_from_slice(&bytes[..6]);
        mac[0] = (mac[0] & 0xfc) | 2;
        let mut peer_mac = mac;
        peer_mac[5] ^= 1;
        Ok(Self {
            interface,
            peer,
            mac,
            peer_mac,
        })
    }
}

impl Journal {
    fn path(&self) -> PathBuf {
        Path::new(STATE).join(format!("{}.json", self.network))
    }
    fn config_path(&self) -> PathBuf {
        Path::new(STATE).join(format!("{}.conf", self.network))
    }
    fn control_path(&self) -> PathBuf {
        Path::new(RUNTIME).join(format!("babel-{}.sock", self.network))
    }
    fn babel_state_path(&self) -> PathBuf {
        Path::new(STATE).join(format!("{}.babel", self.network))
    }
    fn persist(&self) -> Result<()> {
        capulus::store::atomic_write(
            &self.path(),
            &serde_json::to_vec(self)?,
            Some(0o600),
            Some(0o700),
        )
    }
    fn read(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.file_type().is_file() && metadata.uid() == 0 && metadata.mode() & 0o077 == 0,
            "native ownership journal is not private and root owned"
        );
        let journal: Self = serde_json::from_slice(&fs::read(path)?)?;
        ensure!(
            journal.path() == path
                && !journal.network.is_empty()
                && journal
                    .network
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
            "invalid native ownership journal"
        );
        ensure!(
            valid_interface(&journal.wireguard, "utun"),
            "invalid owned WireGuard interface"
        );
        for ethernet in &journal.overlays {
            ensure!(
                valid_interface(&ethernet.interface, "feth")
                    && valid_interface(&ethernet.peer, "feth"),
                "invalid owned Ethernet pair"
            );
        }
        Ok(journal)
    }
    fn cleanup(&self) -> Result<()> {
        ensure!(
            !interface_exists(&self.wireguard)?,
            "previous WireGuard worker still owns {}; stop it before recovery",
            self.wireguard
        );
        let socket = uapi_path(&self.wireguard);
        if socket.exists() {
            use std::os::unix::fs::FileTypeExt;
            let metadata = fs::symlink_metadata(&socket)?;
            ensure!(
                metadata.file_type().is_socket() && metadata.uid() == 0,
                "unsafe stale WireGuard socket"
            );
            fs::remove_file(socket)?;
        }
        for ethernet in &self.overlays {
            for (name, mac) in [
                (&ethernet.interface, ethernet.mac),
                (&ethernet.peer, ethernet.peer_mac),
            ] {
                if interface_exists(name)? {
                    let output = native(
                        "inspect owned Ethernet interface",
                        "/sbin/ifconfig",
                        &[name],
                    )?;
                    ensure!(
                        output.contains(&format!("ether {}", format_mac(mac))),
                        "interface {name} does not have its recorded ownership MAC; retained for explicit repair"
                    );
                    native(
                        "remove owned Ethernet interface",
                        "/sbin/ifconfig",
                        &[name, "destroy"],
                    )?;
                }
            }
        }
        for &address in &self.internal {
            let output = native("inspect loopback aliases", "/sbin/ifconfig", &["lo0"])?;
            if output
                .split_whitespace()
                .any(|word| word == address.to_string())
            {
                native(
                    "remove owned mesh address",
                    "/sbin/ifconfig",
                    &[
                        "lo0",
                        family_ifconfig(address),
                        &address.to_string(),
                        "-alias",
                    ],
                )?;
            }
        }
        for path in [self.control_path(), self.config_path(), self.path()] {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}

fn wireguard_uapi(options: &NetworkOptions<'_>) -> Result<String> {
    let private_key = key_hex(&load_private_key(
        &options.config.wireguard.private_key_path,
    )?)?;
    let mut config = format!("set=1\nprivate_key={private_key}\nreplace_peers=true\n");
    for peer in options.peers {
        let Some(wireguard) = &peer.wireguard else {
            continue;
        };
        config.push_str(&format!(
            "public_key={}\nreplace_allowed_ips=true\nallowed_ip={}/32\nallowed_ip={}/128\n",
            key_hex(&wireguard.public_key)?,
            wireguard.ipv4,
            wireguard.ipv6
        ));
        if let Some(endpoint) = selected_wireguard_endpoint(
            peer,
            options.inventory.config.wireguard.endpoint_port,
            false,
            true,
        ) {
            config.push_str(&format!(
                "endpoint={endpoint}\npersistent_keepalive_interval=5\n"
            ));
        }
    }
    config.push('\n');
    Ok(config)
}

fn key_hex(value: &str) -> Result<String> {
    let key = base64::engine::general_purpose::STANDARD.decode(value.trim())?;
    ensure!(key.len() == 32, "WireGuard key must contain 32 bytes");
    Ok(key.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn uapi_path(interface: &str) -> PathBuf {
    Path::new("/private/var/run/wireguard").join(format!("{interface}.sock"))
}

fn connect_control(path: &Path) -> Result<UnixStream> {
    let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
    socket.connect_timeout(&socket2::SockAddr::unix(path)?, Duration::from_secs(3))?;
    Ok(socket.into())
}

fn uapi_request(interface: &str, request: &str) -> Result<()> {
    let mut stream = connect_control(&uapi_path(interface))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    stream.write_all(request.as_bytes())?;
    let mut response = BufReader::new(stream);
    let mut line = String::new();
    response.by_ref().take(1024).read_line(&mut line)?;
    ensure!(
        line.trim() == "errno=0",
        "WireGuard rejected a configuration update"
    );
    Ok(())
}

pub(crate) fn wireguard_worker(interface: &str) -> Result<()> {
    ensure!(
        valid_interface(interface, "utun"),
        "invalid native WireGuard interface"
    );
    // This dedicated child owns BoringTun's signal handlers and blocking device threads.
    unsafe {
        libc::umask(0o077);
    }
    let mut handle = boringtun::device::DeviceHandle::new(
        interface,
        boringtun::device::DeviceConfig {
            n_threads: 2,
            use_connected_socket: false,
        },
    )?;
    handle.wait();
    Ok(())
}

fn babel_dump(path: &Path) -> Result<String> {
    let mut stream = connect_control(path)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(b"dump\nquit\n")?;
    let mut reader = BufReader::new(stream);
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut result = String::new();
    let mut terminators = 0;
    while terminators < 2 {
        ensure!(
            Instant::now() < deadline && result.len() < 1024 * 1024,
            "Babel control response exceeded its bound"
        );
        let mut line = String::new();
        let remaining = (1024 * 1024 - result.len()) as u64;
        reader.get_ref().set_read_timeout(Some(
            deadline
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(1)),
        ))?;
        ensure!(
            reader.by_ref().take(remaining).read_line(&mut line)? != 0 && line.ends_with('\n'),
            "Babel control connection ended early or exceeded its response bound"
        );
        if line.trim() == "ok" {
            terminators += 1;
        }
        ensure!(
            !matches!(line.trim(), "no" | "bad"),
            "Babel rejected its status request"
        );
        result.push_str(&line);
    }
    Ok(result)
}

pub(super) fn current_babel_route_snapshot() -> BabelRouteSnapshot {
    let mut snapshot = BabelRouteSnapshot::default();
    let mut mesh = MESH.lock().expect("native mesh lock");
    let Some(mesh) = mesh.as_mut() else {
        snapshot.last_error = Some("native mesh has not started".into());
        return snapshot;
    };
    for session in mesh.sessions.values_mut() {
        match session.running().and_then(|running| {
            ensure!(running, "native mesh worker stopped");
            session.verify_routes()
        }) {
            Ok(routes) => snapshot.routes.extend(routes),
            Err(error) => {
                snapshot.last_error = Some(format!("{}: {error:#}", session.journal.network));
                break;
            }
        }
    }
    snapshot
}

pub(super) async fn monitor_underlay_events(state: Arc<AppState>) -> Result<()> {
    transport::monitor_routes(move |underlay_changed| {
        let state = Arc::clone(&state);
        async move {
            run_blocking(move || {
                let _guard = state.data_plane_lock.lock().expect("data plane lock");
                let mut mesh = MESH.lock().expect("native mesh lock");
                if let Some(mesh) = mesh.as_mut() {
                    for session in mesh.sessions.values_mut() {
                        if session.running()? {
                            if underlay_changed {
                                uapi_request(&session.journal.wireguard, &session.uapi)?;
                            }
                            session.verify_routes()?;
                        }
                    }
                }
                Ok(())
            })
            .await
        }
    })
    .await
}

pub(crate) fn shutdown() -> Result<()> {
    SHUTTING_DOWN.store(true, Ordering::Release);
    let mut mesh = MESH.lock().expect("native mesh lock");
    if let Some(mesh) = mesh.as_mut() {
        for session in mesh.sessions.values_mut() {
            session.stop()?;
        }
        mesh.sessions.clear();
    }
    Ok(())
}

pub(super) fn retain_networks(networks: &[String]) -> Result<()> {
    let mut mesh = MESH.lock().expect("native mesh lock");
    if let Some(mesh) = mesh.as_mut() {
        let removed = mesh
            .sessions
            .keys()
            .filter(|name| !networks.contains(name))
            .cloned()
            .collect::<Vec<_>>();
        for network in removed {
            if let Some(mut session) = mesh.sessions.remove(&network) {
                session.stop()?;
            }
        }
    }
    Ok(())
}

pub(crate) fn remove_owned_resources() -> Result<()> {
    if Path::new(STATE).exists() {
        let mesh = Mesh::open()?;
        drop(mesh);
        for entry in fs::read_dir(STATE)? {
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
            ensure!(
                metadata.file_type().is_file()
                    && metadata.uid() == 0
                    && metadata.mode() & 0o077 == 0,
                "unrecognized native state retained at {}",
                path.display()
            );
            ensure!(
                path.file_name().is_some_and(|name| name == "owner.lock")
                    || path
                        .extension()
                        .is_some_and(|extension| extension == "babel"),
                "unrecognized native state retained at {}",
                path.display()
            );
            fs::remove_file(path)?;
        }
        fs::remove_dir(STATE)?;
    }
    if Path::new(HELPER).exists() {
        let metadata = fs::symlink_metadata(HELPER)?;
        ensure!(
            metadata.file_type().is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
            "unsafe Babel helper retained"
        );
        fs::remove_file(HELPER)?;
    }
    match fs::remove_dir(RUNTIME) {
        Ok(()) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
            ) => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn native(action: &str, executable: &str, arguments: &[&str]) -> Result<String> {
    let output = capulus::process::CaptureOptions {
        timeout: NATIVE_TIMEOUT,
        ..Default::default()
    }
    .validate()?
    .run(
        Command::new(executable)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("LC_ALL", "C")
            .args(arguments),
        None,
    )?;
    ensure!(
        output.status.success(),
        "{action}: {}",
        output.stderr.trim()
    );
    Ok(output.stdout)
}

fn secure_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_dir() && metadata.uid() == 0,
        "native state directory is not root owned: {}",
        path.display()
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn install_helper() -> Result<()> {
    let path = Path::new(HELPER);
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.file_type().is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
            "unsafe Babel helper path"
        );
        if Sha256::digest(fs::read(path)?) == Sha256::digest(HELPER_BYTES) {
            return Ok(());
        }
    }
    capulus::store::atomic_write(path, HELPER_BYTES, Some(0o755), None)
}

fn stop_child(child: &mut Option<Child>) -> Result<()> {
    let Some(process) = child.as_mut() else {
        return Ok(());
    };
    if process.try_wait()?.is_none() {
        unsafe {
            libc::kill(process.id() as i32, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while process.try_wait()?.is_none() {
            if Instant::now() >= deadline {
                process.kill()?;
                let kill_deadline = Instant::now() + Duration::from_secs(5);
                while process.try_wait()?.is_none() {
                    ensure!(
                        Instant::now() < kill_deadline,
                        "native worker {} did not exit after SIGKILL; ownership journal retained",
                        process.id()
                    );
                    std::thread::sleep(Duration::from_millis(50));
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    child.take();
    Ok(())
}

fn valid_interface(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .is_some_and(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
        && name.len() < libc::IFNAMSIZ
}
fn interface_exists(name: &str) -> Result<bool> {
    let name = std::ffi::CString::new(name)?;
    Ok(unsafe { libc::if_nametoindex(name.as_ptr()) } != 0)
}
fn unused_interface(prefix: &str, start: u32) -> Result<String> {
    for index in start..4096 {
        let name = format!("{prefix}{index}");
        if !interface_exists(&name)? && (prefix != "utun" || !uapi_path(&name).exists()) {
            return Ok(name);
        }
    }
    bail!("no unused {prefix} interface is available")
}
fn format_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
fn family(address: IpAddr) -> &'static str {
    if address.is_ipv4() { "-inet" } else { "-inet6" }
}
fn family_ifconfig(address: IpAddr) -> &'static str {
    if address.is_ipv4() { "inet" } else { "inet6" }
}
fn add_alias(interface: &str, address: IpAddr) -> Result<()> {
    native(
        "configure stable mesh address",
        "/sbin/ifconfig",
        &[
            interface,
            family_ifconfig(address),
            &format!("{address}/{}", if address.is_ipv4() { 32 } else { 128 }),
            "alias",
        ],
    )?;
    Ok(())
}
fn selected_source(destination: IpAddr) -> Result<IpAddr> {
    let socket = UdpSocket::bind(if destination.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    socket.connect(SocketAddr::new(destination, 9))?;
    Ok(socket.local_addr()?.ip())
}
