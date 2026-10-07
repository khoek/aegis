use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    future::Future,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    num::NonZeroU32,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{io::unix::AsyncFd, net::UdpSocket, task::JoinHandle};

use super::super::vxlan::{self, Peer};

pub(super) struct Options<'a> {
    pub local: Ipv4Addr,
    pub wireguard_interface: &'a str,
    pub mtu: u16,
    pub peers: Vec<(Peer, tun_rs::AsyncDevice)>,
}

pub(super) struct Transport {
    workers: Vec<JoinHandle<()>>,
}

impl Transport {
    pub fn start(options: Options<'_>) -> Result<Self> {
        ensure!(
            options.mtu >= 1280,
            "VXLAN must preserve the IPv6 minimum MTU"
        );
        let interface = CString::new(options.wireguard_interface)?;
        let index = NonZeroU32::new(unsafe { libc::if_nametoindex(interface.as_ptr()) })
            .context("native WireGuard interface is missing")?;
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_nonblocking(true)?;
        socket.bind_device_by_index_v4(Some(index))?;
        socket.bind(&SocketAddrV4::new(options.local, vxlan::PORT).into())?;
        let socket = Arc::new(UdpSocket::from_std(socket.into())?);
        let mut peers = BTreeMap::new();
        for (peer, device) in options.peers {
            ensure!(
                peers.insert(peer.validate()?, Arc::new(device)).is_none(),
                "duplicate VXLAN peer address/VNI"
            );
        }
        let mut workers = Vec::new();
        for (&peer, device) in &peers {
            let device = Arc::clone(device);
            let socket = Arc::clone(&socket);
            let mtu = options.mtu;
            workers.push(tokio::spawn(async move {
                if let Err(error) = transmit(peer, device, socket, mtu).await {
                    eprintln!("native VXLAN transmitter {peer:?} stopped: {error:#}");
                }
            }));
        }
        workers.push(tokio::spawn(async move {
            if let Err(error) = receive(socket, peers, options.mtu).await {
                eprintln!("native VXLAN receiver stopped: {error:#}");
            }
        }));
        Ok(Self { workers })
    }

    pub fn running(&self) -> bool {
        self.workers.iter().all(|worker| !worker.is_finished())
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        for worker in &self.workers {
            worker.abort();
        }
    }
}

async fn transmit(
    peer: Peer,
    device: Arc<tun_rs::AsyncDevice>,
    socket: Arc<UdpSocket>,
    mtu: u16,
) -> Result<()> {
    let mut packet = vec![0; vxlan::HEADER_LEN + vxlan::ETHERNET_LEN + usize::from(mtu)];
    packet[..vxlan::HEADER_LEN].copy_from_slice(&peer.header());
    loop {
        let size = device.recv(&mut packet[vxlan::HEADER_LEN..]).await?;
        if size < vxlan::ETHERNET_LEN {
            continue;
        }
        tokio::time::timeout(
            Duration::from_secs(1),
            socket.send_to(
                &packet[..vxlan::HEADER_LEN + size],
                SocketAddrV4::new(peer.address, vxlan::PORT),
            ),
        )
        .await??;
    }
}

async fn receive(
    socket: Arc<UdpSocket>,
    peers: BTreeMap<Peer, Arc<tun_rs::AsyncDevice>>,
    mtu: u16,
) -> Result<()> {
    // The extra byte distinguishes oversized datagrams from valid maximum-size frames.
    let mut packet = vec![0; vxlan::HEADER_LEN + vxlan::ETHERNET_LEN + usize::from(mtu) + 1];
    loop {
        let (size, sender) = socket.recv_from(&mut packet).await?;
        let SocketAddr::V4(sender) = sender else {
            continue;
        };
        let Some((vni, frame)) = vxlan::decode(&packet[..size], mtu) else {
            continue;
        };
        // Linux hashes the source UDP port. Authenticate the configured WireGuard IP and VNI instead.
        let Some(device) = peers.get(&Peer {
            address: *sender.ip(),
            vni,
        }) else {
            continue;
        };
        tokio::time::timeout(Duration::from_secs(1), device.send(frame)).await??;
    }
}

pub(super) async fn monitor_routes<F, Fut>(mut changed: F) -> Result<()>
where
    F: FnMut(bool) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let descriptor = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
    ensure!(
        descriptor >= 0,
        "open routing notifications: {}",
        std::io::Error::last_os_error()
    );
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    ensure!(
        unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } == 0,
        "make routing notifications nonblocking"
    );
    ensure!(
        unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == 0,
        "protect routing-notification descriptor"
    );
    let descriptor = AsyncFd::new(descriptor)?;
    let mut buffer = [0u8; 8192];
    eprintln!("aegis-agent is watching native link and route changes");
    loop {
        let mut ready =
            match tokio::time::timeout(Duration::from_secs(15), descriptor.readable()).await {
                Ok(ready) => ready?,
                Err(_) => {
                    changed(false).await?;
                    continue;
                }
            };
        let read = ready.try_io(|fd| {
            let size = unsafe {
                libc::read(
                    fd.get_ref().as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if size < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(size as usize)
            }
        });
        let Ok(size) = read else { continue };
        let size = size?;
        let Some(mut underlay_changed) = route_message(&buffer[..size]) else {
            continue;
        };
        tokio::time::sleep(Duration::from_millis(500)).await;
        // Drain queued events to avoid repeated endpoint updates during a network switch.
        for _ in 0..256 {
            let size = unsafe {
                libc::read(
                    descriptor.get_ref().as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if size <= 0 {
                break;
            }
            underlay_changed |= route_message(&buffer[..size as usize]).unwrap_or(false);
        }
        changed(underlay_changed).await?;
    }
}

fn route_message(message: &[u8]) -> Option<bool> {
    if message.len() < 4 || message[2] != libc::RTM_VERSION as u8 {
        return None;
    }
    let index = unsafe {
        match i32::from(message[3]) {
            libc::RTM_ADD | libc::RTM_DELETE | libc::RTM_CHANGE
                if message.len() >= size_of::<libc::rt_msghdr>() =>
            {
                std::ptr::read_unaligned(message.as_ptr().cast::<libc::rt_msghdr>()).rtm_index
            }
            libc::RTM_IFINFO if message.len() >= size_of::<libc::if_msghdr>() => {
                std::ptr::read_unaligned(message.as_ptr().cast::<libc::if_msghdr>()).ifm_index
            }
            libc::RTM_NEWADDR | libc::RTM_DELADDR
                if message.len() >= size_of::<libc::ifa_msghdr>() =>
            {
                std::ptr::read_unaligned(message.as_ptr().cast::<libc::ifa_msghdr>()).ifam_index
            }
            _ => return None,
        }
    };
    let mut name = [0; libc::IFNAMSIZ];
    let name = unsafe { libc::if_indextoname(u32::from(index), name.as_mut_ptr()) };
    if name.is_null() {
        return Some(true);
    }
    let name = unsafe { CStr::from_ptr(name) }.to_string_lossy();
    Some(name != "lo0" && !name.starts_with("feth") && !name.starts_with("utun"))
}
