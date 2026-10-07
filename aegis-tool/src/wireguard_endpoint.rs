use std::net::IpAddr;
use std::process::Command;

pub fn preferred_wireguard_endpoint_ip(endpoints: &[String]) -> anyhow::Result<Option<String>> {
    Ok(preferred_wireguard_endpoint_ip_with_ipv6_support(
        endpoints,
        system_supports_public_ipv6()?,
    ))
}

pub fn wireguard_endpoint_ipv4(endpoints: &[String]) -> Option<String> {
    endpoints.iter().find_map(|endpoint| {
        endpoint
            .parse::<IpAddr>()
            .ok()
            .filter(IpAddr::is_ipv4)
            .map(|_| endpoint.clone())
    })
}

pub fn system_supports_public_ipv6() -> anyhow::Result<bool> {
    #[cfg(target_os = "linux")]
    let output = crate::command::require_success(
        "inspect public IPv6 route",
        Command::new("ip").args(["-6", "route", "show", "default"]),
    )?;
    #[cfg(target_os = "macos")]
    let output = crate::command::require_success(
        "inspect public IPv6 route",
        Command::new("/usr/sbin/netstat").args(["-rn", "-f", "inet6"]),
    )?;
    Ok(output
        .stdout
        .lines()
        .any(|line| line.split_whitespace().next() == Some("default")))
}

pub fn preferred_wireguard_endpoint_ip_with_ipv6_support(
    endpoints: &[String],
    ipv6_supported: bool,
) -> Option<String> {
    let mut ipv4 = None;
    let mut ipv6 = None;

    for endpoint in endpoints {
        match endpoint.parse::<IpAddr>().ok()? {
            IpAddr::V4(_) if ipv4.is_none() => ipv4 = Some(endpoint.clone()),
            IpAddr::V6(_) if ipv6.is_none() => ipv6 = Some(endpoint.clone()),
            _ => {}
        }
    }

    if ipv6_supported {
        ipv6.or(ipv4)
    } else {
        ipv4.or(ipv6)
    }
}

#[cfg(test)]
mod tests {
    use super::{preferred_wireguard_endpoint_ip_with_ipv6_support, wireguard_endpoint_ipv4};

    #[test]
    fn ipv4_only_selection_never_falls_back_to_ipv6() {
        let dual_stack = vec!["2600:1900:4000:fec::1".to_string(), "34.1.2.3".to_string()];
        assert_eq!(
            Some("34.1.2.3".to_string()),
            wireguard_endpoint_ipv4(&dual_stack)
        );
        assert_eq!(
            None,
            wireguard_endpoint_ipv4(&["2600:1900:4000:fec::1".to_string()])
        );
    }

    #[test]
    fn prefers_ipv6_when_supported() {
        let endpoints = vec!["34.1.2.3".to_string(), "2600:1900:4000:fec::1".to_string()];
        assert_eq!(
            Some("2600:1900:4000:fec::1".to_string()),
            preferred_wireguard_endpoint_ip_with_ipv6_support(&endpoints, true)
        );
    }

    #[test]
    fn falls_back_to_ipv4_when_ipv6_is_not_supported() {
        let endpoints = vec!["2600:1900:4000:fec::1".to_string(), "34.1.2.3".to_string()];
        assert_eq!(
            Some("34.1.2.3".to_string()),
            preferred_wireguard_endpoint_ip_with_ipv6_support(&endpoints, false)
        );
    }

    #[test]
    fn still_returns_ipv6_when_it_is_the_only_option() {
        let endpoints = vec!["2600:1900:4000:fec::1".to_string()];
        assert_eq!(
            Some("2600:1900:4000:fec::1".to_string()),
            preferred_wireguard_endpoint_ip_with_ipv6_support(&endpoints, false)
        );
    }
}
