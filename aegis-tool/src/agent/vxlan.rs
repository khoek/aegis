use std::net::Ipv4Addr;

use anyhow::{Result, ensure};

#[cfg(target_os = "macos")]
pub(super) const PORT: u16 = 4789;
pub(super) const HEADER_LEN: usize = 8;
pub(super) const ETHERNET_LEN: usize = 14;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Peer {
    pub address: Ipv4Addr,
    pub vni: u32,
}

impl Peer {
    pub fn validate(self) -> Result<Self> {
        ensure!(
            !self.address.is_unspecified() && !self.address.is_multicast(),
            "invalid VXLAN peer address"
        );
        ensure!(
            (1..=0x00ff_ffff).contains(&self.vni),
            "VXLAN VNI must fit in 24 bits and be nonzero"
        );
        Ok(self)
    }

    pub fn header(self) -> [u8; HEADER_LEN] {
        let vni = self.vni.to_be_bytes();
        [0x08, 0, 0, 0, vni[1], vni[2], vni[3], 0]
    }
}

/// RFC 7348: receivers ignore reserved bits; the VNI-present flag is mandatory.
/// The caller authenticates the source address and VNI against its configured peers.
pub(super) fn decode(packet: &[u8], mtu: u16) -> Option<(u32, &[u8])> {
    if packet.len() < HEADER_LEN + ETHERNET_LEN
        || packet.len() > HEADER_LEN + ETHERNET_LEN + usize::from(mtu)
        || packet[0] & 0x08 == 0
    {
        return None;
    }
    let vni = u32::from_be_bytes([0, packet[4], packet[5], packet[6]]);
    (vni != 0).then_some((vni, &packet[HEADER_LEN..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format_preserves_ethernet_multicast_and_ignores_reserved_bits() {
        let peer = Peer {
            address: Ipv4Addr::new(10, 1, 2, 3),
            vni: 0xabcdef,
        }
        .validate()
        .unwrap();
        let frame = [0x33; ETHERNET_LEN + 1280];
        let mut packet = peer.header().to_vec();
        packet.extend(frame);
        assert_eq!(decode(&packet, 1280), Some((peer.vni, frame.as_slice())));
        packet[1] = 0xff;
        assert_eq!(decode(&packet, 1280), Some((peer.vni, frame.as_slice())));
        packet.push(0);
        assert!(decode(&packet, 1280).is_none());
    }

    #[test]
    fn truncated_missing_flag_and_invalid_vni_are_rejected() {
        assert!(decode(&[0; HEADER_LEN + ETHERNET_LEN], 1280).is_none());
        for vni in [0, 0x0100_0000, u32::MAX] {
            assert!(
                Peer {
                    address: Ipv4Addr::LOCALHOST,
                    vni
                }
                .validate()
                .is_err()
            );
        }
        assert!(decode(&[8; HEADER_LEN + ETHERNET_LEN - 1], 1280).is_none());
    }

    #[test]
    fn peer_identity_includes_both_wireguard_address_and_vni() {
        let a = Peer {
            address: Ipv4Addr::new(10, 0, 0, 1),
            vni: 1,
        };
        let b = Peer {
            address: Ipv4Addr::new(10, 0, 0, 2),
            ..a
        };
        let c = Peer { vni: 2, ..a };
        assert_ne!(a, b);
        assert_ne!(a, c);
    }
}
