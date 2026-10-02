use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr},
};

use aegis_types::v1::{
    AegisDnsChange, AegisDnsConfig, AegisDnsRecordKind, AegisDnsSyncResponse, AegisSyncAction,
};
use anyhow::{Context, anyhow, bail};
use reqwest::{Method, RequestBuilder};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::aegis::AegisState;
use crate::aegis_store::{AegisNetworkMemberRecord, AegisStore};

const CLOUDFLARE_PAGE_SIZE: u32 = 5_000;
const CLOUDFLARE_API_BASE: &str = "https://api.cloudflare.com/client/v4";

pub(super) async fn sync<S>(
    state: &AegisState<S>,
    dry_run: bool,
) -> anyhow::Result<AegisDnsSyncResponse>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    sync_if_configured(state, dry_run)
        .await?
        .ok_or_else(|| anyhow!("Aegis DNS is not configured"))
}

pub(super) async fn sync_if_configured<S>(
    state: &AegisState<S>,
    dry_run: bool,
) -> anyhow::Result<Option<AegisDnsSyncResponse>>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let Some(config) = state.cfg.dns.as_ref() else {
        return Ok(None);
    };
    let desired = desired_records(state, config).await?;
    let client = CloudflareDnsClient::new(&config.cloudflare.api_token)?;
    let zone_id = client.zone_id(&config.zone).await?;
    let existing = client.managed_records(&zone_id, &config.suffix).await?;
    let changes = DnsChanges::new(desired, existing, config.ttl);
    let response = changes.response(dry_run);
    if !dry_run {
        changes.apply(&client, &zone_id, config.ttl).await?;
    }
    Ok(Some(response))
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RecordKey {
    name: String,
    kind: AegisDnsRecordKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RecordValue {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
}

impl RecordValue {
    const fn kind(&self) -> AegisDnsRecordKind {
        match self {
            Self::A(_) => AegisDnsRecordKind::A,
            Self::Aaaa(_) => AegisDnsRecordKind::AAAA,
        }
    }

    fn content(&self) -> String {
        match self {
            Self::A(address) => address.to_string(),
            Self::Aaaa(address) => address.to_string(),
        }
    }
}

#[derive(Clone, Debug)]
struct DesiredRecord {
    name: String,
    value: RecordValue,
}

impl DesiredRecord {
    fn key(&self) -> RecordKey {
        RecordKey {
            name: self.name.clone(),
            kind: self.value.kind(),
        }
    }

    fn change(&self, action: AegisSyncAction) -> AegisDnsChange {
        AegisDnsChange {
            action,
            kind: self.value.kind(),
            name: self.name.clone(),
            content: self.value.content(),
        }
    }
}

struct DnsChanges {
    desired_count: usize,
    create: Vec<DesiredRecord>,
    update: Vec<(CloudflareDnsRecord, DesiredRecord)>,
    delete: Vec<CloudflareDnsRecord>,
}

impl DnsChanges {
    fn new(
        desired: BTreeMap<RecordKey, DesiredRecord>,
        existing: Vec<CloudflareDnsRecord>,
        ttl: u32,
    ) -> Self {
        let desired_count = desired.len();
        let mut existing_by_key = BTreeMap::<RecordKey, Vec<CloudflareDnsRecord>>::new();
        for record in existing {
            if let Some(key) = existing_record_key(&record) {
                existing_by_key.entry(key).or_default().push(record);
            }
        }

        let mut create = Vec::new();
        let mut update = Vec::new();
        let mut delete = Vec::new();
        for (key, desired_record) in &desired {
            let mut records = existing_by_key.remove(key).unwrap_or_default();
            if records.is_empty() {
                create.push(desired_record.clone());
                continue;
            }
            let first = records.remove(0);
            if !record_matches(&first, desired_record, ttl) {
                update.push((first, desired_record.clone()));
            }
            delete.extend(records);
        }
        delete.extend(existing_by_key.into_values().flatten());
        Self {
            desired_count,
            create,
            update,
            delete,
        }
    }

    fn response(&self, dry_run: bool) -> AegisDnsSyncResponse {
        let mut changes = self
            .create
            .iter()
            .map(|record| record.change(AegisSyncAction::Create))
            .chain(
                self.update
                    .iter()
                    .map(|(_, record)| record.change(AegisSyncAction::Update)),
            )
            .chain(
                self.delete
                    .iter()
                    .filter_map(|record| existing_record_change(record, AegisSyncAction::Delete)),
            )
            .collect::<Vec<_>>();
        changes.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| dns_kind_order(left.kind).cmp(&dns_kind_order(right.kind)))
                .then_with(|| sync_action_order(left.action).cmp(&sync_action_order(right.action)))
        });
        AegisDnsSyncResponse {
            dry_run,
            desired: self.desired_count,
            created: self.create.len(),
            updated: self.update.len(),
            deleted: self.delete.len(),
            changes,
        }
    }

    async fn apply(
        self,
        client: &CloudflareDnsClient,
        zone_id: &str,
        ttl: u32,
    ) -> anyhow::Result<()> {
        for record in &self.create {
            client.create_record(zone_id, record, ttl).await?;
        }
        for (existing, desired) in &self.update {
            client
                .update_record(zone_id, &existing.id, desired, ttl)
                .await?;
        }
        for record in &self.delete {
            client.delete_record(zone_id, record).await?;
        }
        Ok(())
    }
}

async fn desired_records<S>(
    state: &AegisState<S>,
    config: &AegisDnsConfig,
) -> anyhow::Result<BTreeMap<RecordKey, DesiredRecord>>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let mut desired = BTreeMap::new();
    let mut members_by_network = BTreeMap::new();
    let hosts = state
        .store
        .list_aegis_hosts()
        .await?
        .into_iter()
        .map(|host| (host.host_id, host))
        .collect::<BTreeMap<_, _>>();
    for (network_name, network) in &state.cfg.networks {
        let members = state.store.list_aegis_network_members(network_name).await?;
        for member in &members {
            if let Some((ipv4, ipv6)) = member_addresses(member, network.mesh.is_some())? {
                let host = hosts.get(&member.host_id).ok_or_else(|| {
                    anyhow!(
                        "network member `{}/{}` has no host record",
                        network_name,
                        member.host_id
                    )
                })?;
                for alias in &host.aliases {
                    insert_address_records(
                        &mut desired,
                        &format!("{alias}.{network_name}.{}", config.suffix),
                        ipv4,
                        ipv6,
                    )?;
                }
            }
        }
        members_by_network.insert(
            network_name.clone(),
            members
                .into_iter()
                .map(|member| (member.host_id, member))
                .collect::<BTreeMap<_, _>>(),
        );
    }
    for (label, binding) in &config.bindings {
        let network = state.cfg.networks.get(&binding.network).ok_or_else(|| {
            anyhow!(
                "DNS binding `{label}` references unknown network `{}`",
                binding.network
            )
        })?;
        let member = members_by_network
            .get(&binding.network)
            .and_then(|members| members.get(&binding.host_id))
            .ok_or_else(|| {
                anyhow!(
                    "DNS binding `{label}` targets missing member `{}/{}`",
                    binding.network,
                    binding.host_id
                )
            })?;
        let (ipv4, ipv6) = member_addresses(member, network.mesh.is_some())?.ok_or_else(|| {
            anyhow!(
                "DNS binding `{label}` targets member `{}/{}` before its addresses are allocated",
                binding.network,
                binding.host_id
            )
        })?;
        insert_address_records(
            &mut desired,
            &format!("{label}.{}", config.suffix),
            ipv4,
            ipv6,
        )?;
    }
    Ok(desired)
}

fn member_addresses(
    member: &AegisNetworkMemberRecord,
    use_internal: bool,
) -> anyhow::Result<Option<(Ipv4Addr, Ipv6Addr)>> {
    let (ipv4, ipv6, kind) = if use_internal {
        (
            member.internal_ipv4.as_deref(),
            member.internal_ipv6.as_deref(),
            "internal",
        )
    } else {
        (
            member.wireguard_ipv4.as_deref(),
            member.wireguard_ipv6.as_deref(),
            "WireGuard",
        )
    };
    match (ipv4, ipv6) {
        (None, None) => Ok(None),
        (Some(ipv4), Some(ipv6)) => Ok(Some((
            ipv4.parse().with_context(|| {
                format!(
                    "member `{}` has invalid {kind} IPv4 address",
                    member.host_id
                )
            })?,
            ipv6.parse().with_context(|| {
                format!(
                    "member `{}` has invalid {kind} IPv6 address",
                    member.host_id
                )
            })?,
        ))),
        _ => bail!(
            "member `{}` has incomplete {kind} addresses",
            member.host_id
        ),
    }
}

fn insert_address_records(
    desired: &mut BTreeMap<RecordKey, DesiredRecord>,
    name: &str,
    ipv4: Ipv4Addr,
    ipv6: Ipv6Addr,
) -> anyhow::Result<()> {
    let name = normalize_dns_name(name);
    for record in [
        DesiredRecord {
            name: name.clone(),
            value: RecordValue::A(ipv4),
        },
        DesiredRecord {
            name: name.clone(),
            value: RecordValue::Aaaa(ipv6),
        },
    ] {
        if desired.insert(record.key(), record).is_some() {
            bail!("duplicate desired DNS record for `{name}`");
        }
    }
    Ok(())
}

struct CloudflareDnsClient {
    http: reqwest::Client,
    api_token: String,
}

impl CloudflareDnsClient {
    fn new(api_token: &str) -> anyhow::Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .build()
                .context("failed to build Cloudflare HTTP client")?,
            api_token: api_token.to_string(),
        })
    }

    async fn zone_id(&self, zone: &str) -> anyhow::Result<String> {
        let normalized_zone = normalize_dns_name(zone);
        let mut zones = self
            .json::<Vec<CloudflareZone>>(
                self.request(Method::GET, "zones")
                    .query(&[("name", normalized_zone.as_str()), ("per_page", "50")]),
                "zone list",
            )
            .await?
            .into_iter()
            .filter(|candidate| normalize_dns_name(&candidate.name) == normalized_zone)
            .collect::<Vec<_>>();
        match zones.len() {
            1 => Ok(zones.remove(0).id),
            0 => bail!("Cloudflare zone `{zone}` was not found"),
            _ => bail!("Cloudflare zone `{zone}` matched more than one zone"),
        }
    }

    async fn managed_records(
        &self,
        zone_id: &str,
        suffix: &str,
    ) -> anyhow::Result<Vec<CloudflareDnsRecord>> {
        let suffix = normalize_dns_name(suffix);
        let dotted_suffix = format!(".{suffix}");
        let mut records = Vec::new();
        for page in 1u32.. {
            let page_records = self
                .json::<Vec<CloudflareDnsRecord>>(
                    self.request(Method::GET, &format!("zones/{zone_id}/dns_records"))
                        .query(&[
                            ("page", page.to_string()),
                            ("per_page", CLOUDFLARE_PAGE_SIZE.to_string()),
                        ]),
                    "DNS record list",
                )
                .await?;
            let page_len = page_records.len();
            records.extend(page_records.into_iter().filter(|record| {
                let name = normalize_dns_name(&record.name);
                (name == suffix || name.ends_with(&dotted_suffix))
                    && existing_record_key(record).is_some()
            }));
            if page_len < CLOUDFLARE_PAGE_SIZE as usize {
                break;
            }
        }
        Ok(records)
    }

    async fn create_record(
        &self,
        zone_id: &str,
        record: &DesiredRecord,
        ttl: u32,
    ) -> anyhow::Result<()> {
        self.json::<CloudflareDnsRecord>(
            self.request(Method::POST, &format!("zones/{zone_id}/dns_records"))
                .json(&CloudflareDnsWrite {
                    kind: dns_kind_label(record.value.kind()),
                    name: &record.name,
                    content: &record.value.content(),
                    ttl,
                    proxied: false,
                }),
            &format!("DNS create for `{}`", record.name),
        )
        .await
        .map(|_| ())
    }

    async fn update_record(
        &self,
        zone_id: &str,
        record_id: &str,
        record: &DesiredRecord,
        ttl: u32,
    ) -> anyhow::Result<()> {
        self.json::<CloudflareDnsRecord>(
            self.request(
                Method::PUT,
                &format!("zones/{zone_id}/dns_records/{record_id}"),
            )
            .json(&CloudflareDnsWrite {
                kind: dns_kind_label(record.value.kind()),
                name: &record.name,
                content: &record.value.content(),
                ttl,
                proxied: false,
            }),
            &format!("DNS update for `{}`", record.name),
        )
        .await
        .map(|_| ())
    }

    async fn delete_record(
        &self,
        zone_id: &str,
        record: &CloudflareDnsRecord,
    ) -> anyhow::Result<()> {
        self.json::<serde_json::Value>(
            self.request(
                Method::DELETE,
                &format!("zones/{zone_id}/dns_records/{}", record.id),
            ),
            &format!("DNS delete for `{}`", record.name),
        )
        .await
        .map(|_| ())
    }

    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        self.http
            .request(method, format!("{CLOUDFLARE_API_BASE}/{path}"))
            .bearer_auth(&self.api_token)
    }

    async fn json<T>(&self, request: RequestBuilder, operation: &str) -> anyhow::Result<T>
    where
        T: DeserializeOwned,
    {
        let response = request
            .send()
            .await
            .with_context(|| format!("Cloudflare {operation} request failed"))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .with_context(|| format!("Cloudflare {operation} response body failed"))?;
        let response = serde_json::from_slice::<CloudflareResponse<T>>(&body)
            .with_context(|| format!("Cloudflare {operation} response was invalid JSON"))?;
        if !status.is_success() || !response.success {
            let errors = response
                .errors
                .iter()
                .map(|error| match error.code {
                    Some(code) => format!("{code}: {}", error.message),
                    None => error.message.clone(),
                })
                .collect::<Vec<_>>()
                .join("; ");
            bail!(
                "Cloudflare {operation} failed with HTTP {status}: {}",
                if errors.is_empty() {
                    "no error detail"
                } else {
                    &errors
                }
            );
        }
        response
            .result
            .ok_or_else(|| anyhow!("Cloudflare {operation} succeeded without a result"))
    }
}

#[derive(Deserialize)]
struct CloudflareResponse<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<CloudflareError>,
    result: Option<T>,
}

#[derive(Deserialize)]
struct CloudflareError {
    code: Option<u64>,
    message: String,
}

#[derive(Deserialize)]
struct CloudflareZone {
    id: String,
    name: String,
}

#[derive(Clone, Debug, Deserialize)]
struct CloudflareDnsRecord {
    id: String,
    name: String,
    #[serde(rename = "type")]
    kind: String,
    content: String,
    ttl: u32,
    #[serde(default)]
    proxied: bool,
}

#[derive(Serialize)]
struct CloudflareDnsWrite<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    name: &'a str,
    content: &'a str,
    ttl: u32,
    proxied: bool,
}

fn existing_record_key(record: &CloudflareDnsRecord) -> Option<RecordKey> {
    Some(RecordKey {
        name: normalize_dns_name(&record.name),
        kind: match record.kind.as_str() {
            "A" => AegisDnsRecordKind::A,
            "AAAA" => AegisDnsRecordKind::AAAA,
            _ => return None,
        },
    })
}

fn existing_record_change(
    record: &CloudflareDnsRecord,
    action: AegisSyncAction,
) -> Option<AegisDnsChange> {
    let kind = match record.kind.as_str() {
        "A" => AegisDnsRecordKind::A,
        "AAAA" => AegisDnsRecordKind::AAAA,
        _ => return None,
    };
    Some(AegisDnsChange {
        action,
        kind,
        name: normalize_dns_name(&record.name),
        content: record.content.clone(),
    })
}

fn record_matches(existing: &CloudflareDnsRecord, desired: &DesiredRecord, ttl: u32) -> bool {
    normalize_dns_name(&existing.name) == desired.name
        && existing.ttl == ttl
        && !existing.proxied
        && match (existing.kind.as_str(), &desired.value) {
            ("A", RecordValue::A(right)) => {
                existing.content.parse::<Ipv4Addr>().ok() == Some(*right)
            }
            ("AAAA", RecordValue::Aaaa(right)) => {
                existing.content.parse::<Ipv6Addr>().ok() == Some(*right)
            }
            _ => false,
        }
}

fn normalize_dns_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

const fn dns_kind_label(kind: AegisDnsRecordKind) -> &'static str {
    match kind {
        AegisDnsRecordKind::A => "A",
        AegisDnsRecordKind::AAAA => "AAAA",
    }
}

const fn dns_kind_order(kind: AegisDnsRecordKind) -> u8 {
    match kind {
        AegisDnsRecordKind::A => 0,
        AegisDnsRecordKind::AAAA => 1,
    }
}

const fn sync_action_order(action: AegisSyncAction) -> u8 {
    match action {
        AegisSyncAction::Create => 0,
        AegisSyncAction::Update => 1,
        AegisSyncAction::Delete => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn existing(name: &str, value: RecordValue, ttl: u32) -> CloudflareDnsRecord {
        CloudflareDnsRecord {
            name: name.to_string(),
            ttl,
            kind: dns_kind_label(value.kind()).to_string(),
            content: value.content(),
            id: format!("{name}-{}", value.content()),
            proxied: false,
        }
    }

    #[test]
    fn changes_remove_stale_and_duplicate_managed_records() {
        let current = existing(
            "alpha.aegis.x.hoek.io",
            RecordValue::A(Ipv4Addr::new(10, 75, 0, 2)),
            60,
        );
        let duplicate = existing(
            "alpha.aegis.x.hoek.io",
            RecordValue::A(Ipv4Addr::new(10, 75, 0, 2)),
            60,
        );
        let stale = existing(
            "old.aegis.x.hoek.io",
            RecordValue::Aaaa("fd75::99".parse().unwrap()),
            60,
        );
        let replacement = DesiredRecord {
            name: "alpha.aegis.x.hoek.io".to_string(),
            value: RecordValue::Aaaa("fd75::2".parse().unwrap()),
        };
        let changes = DnsChanges::new(
            BTreeMap::from([
                (
                    RecordKey {
                        name: current.name.clone(),
                        kind: AegisDnsRecordKind::A,
                    },
                    DesiredRecord {
                        name: current.name.clone(),
                        value: RecordValue::A(Ipv4Addr::new(10, 75, 0, 2)),
                    },
                ),
                (replacement.key(), replacement),
            ]),
            vec![current, duplicate, stale],
            60,
        );
        assert_eq!(changes.create.len(), 1);
        assert!(changes.update.is_empty());
        assert_eq!(changes.delete.len(), 2);
    }

    #[test]
    fn changes_update_content_ttl_and_proxy_state() {
        let mut current = existing(
            "alpha.aegis.x.hoek.io",
            RecordValue::A(Ipv4Addr::new(10, 75, 0, 1)),
            120,
        );
        current.proxied = true;
        let desired = DesiredRecord {
            name: current.name.clone(),
            value: RecordValue::A(Ipv4Addr::new(10, 75, 0, 2)),
        };
        let changes = DnsChanges::new(
            BTreeMap::from([(desired.key(), desired)]),
            vec![current],
            60,
        );
        assert!(changes.create.is_empty());
        assert_eq!(changes.update.len(), 1);
        assert!(changes.delete.is_empty());
    }

    #[test]
    fn record_listing_tolerates_cloudflare_types_that_aegis_does_not_manage() {
        let response = serde_json::from_value::<CloudflareResponse<Vec<CloudflareDnsRecord>>>(
            serde_json::json!({
                "success": true,
                "errors": [],
                "result": [
                    {
                        "id": "caa",
                        "name": "x.hoek.io",
                        "type": "CAA",
                        "content": "0 issue \"letsencrypt.org\"",
                        "ttl": 60,
                        "proxied": false
                    },
                    {
                        "id": "address",
                        "name": "alpha.aegis.x.hoek.io",
                        "type": "A",
                        "content": "10.75.0.2",
                        "ttl": 60,
                        "proxied": false
                    }
                ]
            }),
        )
        .expect("Cloudflare record envelope should decode");
        let records = response.result.expect("successful response has records");

        assert!(existing_record_key(&records[0]).is_none());
        assert_eq!(
            Some(AegisDnsRecordKind::A),
            existing_record_key(&records[1]).map(|key| key.kind)
        );
    }

    #[test]
    fn member_addresses_select_mesh_internal_or_direct_wireguard_identity() {
        let mut member = AegisNetworkMemberRecord {
            host_id: "00000000-0000-4000-8000-000000000001"
                .parse()
                .expect("test host id should parse"),
            mode: aegis_types::AegisHostMode::Leaf,
            wireguard_public_key: None,
            wireguard_ipv4: Some("10.76.1.2".to_string()),
            wireguard_ipv6: Some("fd76::1:2".to_string()),
            wireguard_endpoints: Vec::new(),
            internal_ipv4: Some("10.75.0.2".to_string()),
            internal_ipv6: Some("fd75::2".to_string()),
            pending: false,
            created_unix: 0,
            updated_unix: 0,
            updated_by_principal: "test".to_string(),
        };
        assert_eq!(
            Some(("10.75.0.2".parse().unwrap(), "fd75::2".parse().unwrap())),
            member_addresses(&member, true).unwrap()
        );
        assert_eq!(
            Some(("10.76.1.2".parse().unwrap(), "fd76::1:2".parse().unwrap())),
            member_addresses(&member, false).unwrap()
        );

        member.internal_ipv6 = None;
        assert!(
            member_addresses(&member, true)
                .expect_err("partial address pairs must be rejected")
                .to_string()
                .contains("incomplete internal addresses")
        );
    }
}
