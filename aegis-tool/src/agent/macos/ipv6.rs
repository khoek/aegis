use std::{
    net::Ipv6Addr,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};

use super::{NATIVE_TIMEOUT, native};

pub(super) fn add_address(interface: &str, address: Ipv6Addr, prefix: u8) -> Result<()> {
    // tun-rs sets IN6_IFF_NODAD. On feth, macOS can leave that address tentative
    // indefinitely, which also blocks mDNSResponder from adopting DNS changes.
    // Use normal DAD, as we do for the stable mesh aliases.
    native(
        "configure native IPv6 transit address",
        "/sbin/ifconfig",
        &[interface, "inet6", &format!("{address}/{prefix}"), "alias"],
    )?;
    Ok(())
}

pub(super) fn wait_ready(interface: &str, address: Ipv6Addr) -> Result<()> {
    let deadline = Instant::now() + NATIVE_TIMEOUT;
    loop {
        let configuration = native(
            "inspect native IPv6 readiness",
            "/sbin/ifconfig",
            &[interface],
        )?;
        if ready(&configuration, address).with_context(|| format!("IPv6 on {interface}"))? {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "IPv6 on {interface} did not become ready for {address}; native startup deadline elapsed"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn ready(configuration: &str, required: Ipv6Addr) -> Result<bool> {
    let mut present = false;
    let mut tentative = false;
    for line in configuration.lines() {
        let mut words = line.split_whitespace();
        if words.next() != Some("inet6") {
            continue;
        }
        let address = words.next().context("missing IPv6 address")?;
        let address = address.split('%').next().expect("address component");
        let address = address
            .parse::<Ipv6Addr>()
            .context("invalid IPv6 address")?;
        present |= address == required;
        for flag in words {
            ensure!(flag != "duplicated", "duplicate IPv6 address {address}");
            tentative |= flag == "tentative";
        }
    }
    Ok(present && !tentative)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDRESS: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);

    #[test]
    fn readiness_waits_for_transit_and_other_interface_addresses() -> Result<()> {
        assert!(!ready("feth2: flags=8843<UP>\n", ADDRESS)?);
        assert!(!ready("inet6 fd00::2 prefixlen 127\n", ADDRESS)?);
        assert!(!ready("inet6 fd00::1 prefixlen 127 tentative\n", ADDRESS)?);
        assert!(!ready(
            "inet6 fd00::1 prefixlen 127\ninet6 fe80::1%feth2 prefixlen 64 tentative\n",
            ADDRESS
        )?);
        assert!(ready(
            "inet6 fd00::1 prefixlen 127\ninet6 fe80::1%feth2 prefixlen 64 scopeid 0x13\n",
            ADDRESS
        )?);
        Ok(())
    }

    #[test]
    fn readiness_rejects_duplicates_and_invalid_addresses() {
        assert!(ready("inet6 fd00::1 prefixlen 127 duplicated\n", ADDRESS).is_err());
        assert!(ready("inet6 not-an-address prefixlen 127\n", ADDRESS).is_err());
        assert!(ready("inet6\n", ADDRESS).is_err());
    }

    #[test]
    #[ignore = "requires root; creates and removes an isolated feth pair"]
    fn native_transit_ipv6_finishes_duplicate_address_detection() -> Result<()> {
        ensure!(unsafe { libc::geteuid() } == 0, "native test requires root");
        let interface = super::super::unused_interface("feth", 0)?;
        let peer = super::super::unused_interface(
            "feth",
            interface.trim_start_matches("feth").parse::<u32>()? + 1,
        )?;
        // The nonpersistent device owns cleanup, including on a failed assertion.
        let device = tun_rs::DeviceBuilder::new()
            .layer(tun_rs::Layer::L2)
            .name(&interface)
            .peer_feth(&peer)
            .reuse_dev(false)
            .persist(false)
            .enable(true)
            .build_sync()?;
        let mut bytes = *uuid::Uuid::new_v4().as_bytes();
        bytes[0] = 0xfd;
        let address = Ipv6Addr::from(bytes);
        add_address(&interface, address, 127)?;
        wait_ready(&interface, address)?;
        drop(device);
        ensure!(
            !super::super::interface_exists(&interface)? && !super::super::interface_exists(&peer)?,
            "native test left an Ethernet interface behind"
        );
        Ok(())
    }
}
