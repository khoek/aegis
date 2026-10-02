use std::{net::IpAddr, time::Duration};

use reqwest::blocking::Client;

const GCE_METADATA_BASE_URL: &str = "http://metadata.google.internal/computeMetadata/v1";
const GCE_METADATA_HEADER: (&str, &str) = ("Metadata-Flavor", "Google");

fn metadata_value(path: &str) -> Option<String> {
    let response = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .ok()?
        .get(format!("{GCE_METADATA_BASE_URL}/{path}"))
        .header(GCE_METADATA_HEADER.0, GCE_METADATA_HEADER.1)
        .send()
        .ok()?
        .error_for_status()
        .ok()?
        .text()
        .ok()?;
    let response = response.trim();
    (!response.is_empty()).then(|| response.to_string())
}

pub fn parse_published_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim();
    value
        .parse()
        .ok()
        .or_else(|| value.split_once('/').and_then(|(ip, _)| ip.parse().ok()))
}

pub fn gce_external_ipv4() -> Option<String> {
    metadata_value("instance/network-interfaces/0/access-configs/0/external-ip")
        .and_then(|value| parse_published_ip(&value).map(|ip| ip.to_string()))
}

pub fn gce_external_ipv6() -> Option<String> {
    metadata_value("instance/network-interfaces/0/ipv6")
        .and_then(|value| parse_published_ip(&value).map(|ip| ip.to_string()))
}

pub fn gce_wireguard_endpoint_ips() -> Vec<String> {
    let mut endpoints = Vec::new();
    if let Some(ipv6) = gce_external_ipv6() {
        endpoints.push(ipv6);
    }
    if let Some(ipv4) = gce_external_ipv4()
        && !endpoints.iter().any(|existing| existing == &ipv4)
    {
        endpoints.push(ipv4);
    }
    endpoints
}
