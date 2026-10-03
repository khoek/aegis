use std::collections::BTreeMap;
use std::fs;
use std::ops::{Deref, DerefMut};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use aegis_dto::{HostAlias, HostAliases, HostId};
use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use capulus::paths;
use capulus::store::{atomic_write, ensure_directory, tighten_file_permissions};
use serde::{Deserialize, Serialize};

pub type CachedNetworkConfig = aegis_dto::v1::AegisNetworkConfig;
pub const SHARED_CACHE_PATH: &str = "/var/lib/aegis/cache.json";
pub const AEGIS_AGENT_SOCKET_PATH: &str = "/run/aegis/agent.sock";
pub const AGENT_CONTEXT_PATH: &str = "/var/lib/aegis/context.json";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentContext {
    pub api_base: String,
    pub host_id: HostId,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserContext {
    pub api_base: String,
}

impl UserContext {
    pub fn load() -> Result<Option<Self>> {
        match fs::read_to_string(app_dir()?.join("context.toml")) {
            Ok(raw) => {
                let context: Self =
                    toml::from_str(&raw).context("invalid selected Aegis context")?;
                namespace_endpoint(&context.api_base)?;
                Ok(Some(context))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).context("failed to read selected Aegis context"),
        }
    }

    pub fn persist(&self) -> Result<()> {
        namespace_endpoint(&self.api_base)?;
        atomic_write(
            &app_dir()?.join("context.toml"),
            toml::to_string(self)?.as_bytes(),
            Some(0o600),
            Some(0o700),
        )
    }
}

impl AgentContext {
    pub(crate) fn persist(&self) -> Result<()> {
        namespace_endpoint(&self.api_base)?;
        atomic_write(
            Path::new(AGENT_CONTEXT_PATH),
            &serde_json::to_vec(self)?,
            Some(0o644),
            Some(0o755),
        )
    }

    pub(crate) fn load() -> Result<Option<Self>> {
        match fs::read(AGENT_CONTEXT_PATH) {
            Ok(raw) => {
                let context: Self =
                    serde_json::from_slice(&raw).context("invalid local agent context")?;
                namespace_endpoint(&context.api_base)?;
                Ok(Some(context))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).context("failed to read local agent context"),
        }
    }
}

pub(crate) fn namespace_endpoint(api_base: &str) -> Result<aegis_dto::namespace::ApiEndpoint> {
    let endpoint =
        aegis_dto::namespace::ApiEndpoint::parse(api_base).map_err(anyhow::Error::msg)?;
    endpoint.require_namespace().map_err(anyhow::Error::msg)?;
    Ok(endpoint)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CachedHost {
    pub host_id: HostId,
    pub aliases: HostAliases,
    #[serde(flatten)]
    pub host: aegis_dto::v1::AegisNetworkHost,
}

impl CachedHost {
    pub fn alias(&self) -> &aegis_dto::HostAlias {
        self.aliases.primary()
    }

    pub fn matches(&self, value: &str) -> bool {
        value
            .parse::<HostId>()
            .is_ok_and(|host_id| host_id == self.host_id)
            || value
                .parse::<HostAlias>()
                .is_ok_and(|alias| self.aliases.contains(&alias))
    }

    pub fn host_label(&self) -> String {
        let host = self
            .internal_ipv4()
            .or_else(|| self.internal_ipv6())
            .or_else(|| self.host.wireguard_ipv4())
            .or(self.host.wireguard_ipv6())
            .unwrap_or_else(|| self.alias().as_str());
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_string()
        };
        match self.ssh.as_ref() {
            Some(ssh) => match ssh.port {
                Some(22) => host,
                Some(port) => format!("{host}:{port}"),
                None => host,
            },
            None => host,
        }
    }
}

impl Deref for CachedHost {
    type Target = aegis_dto::v1::AegisNetworkHost;

    fn deref(&self) -> &Self::Target {
        &self.host
    }
}

impl DerefMut for CachedHost {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.host
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CachedInventory {
    pub api_base: String,
    pub hosts: BTreeMap<HostId, aegis_dto::v1::AegisHost>,
    pub networks: BTreeMap<String, CachedNetwork>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CachedNetwork {
    pub config: CachedNetworkConfig,
    pub members: BTreeMap<HostId, aegis_dto::v1::AegisNetworkMember>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedNetwork {
    pub config: CachedNetworkConfig,
    pub hosts: Vec<CachedHost>,
}

impl CachedInventory {
    pub fn resolve_network(&self, network: &str) -> Result<Option<ResolvedNetwork>> {
        let Some(cached) = self.networks.get(network) else {
            return Ok(None);
        };
        let mut hosts = Vec::with_capacity(cached.members.len());
        for (host_id, member) in &cached.members {
            let host = self.hosts.get(host_id).cloned().ok_or_else(|| {
                anyhow::anyhow!("network member `{network}/{host_id}` has no matching host")
            })?;
            if member.aliases != host.aliases {
                anyhow::bail!("network member `{network}/{host_id}` aliases do not match its host");
            }
            hosts.push(CachedHost {
                host_id: *host_id,
                aliases: host.aliases.clone(),
                host: aegis_dto::v1::AegisNetworkHost::resolve(host, member.clone()),
            });
        }
        Ok(Some(ResolvedNetwork {
            config: cached.config.clone(),
            hosts,
        }))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UserAuthState {
    pub access_token: String,
    pub refresh_token: String,
    pub principal: String,
    pub access_expires_at_unix: i64,
    pub refresh_expires_at_unix: i64,
}

impl UserAuthState {
    pub fn access_needs_refresh(&self, now_unix: i64, skew_seconds: i64) -> bool {
        now_unix.saturating_add(skew_seconds) >= self.access_expires_at_unix
    }

    pub fn refresh_is_expired(&self, now_unix: i64) -> bool {
        now_unix >= self.refresh_expires_at_unix
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AgentAuthConfig {
    pub refresh_token: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentHostConfigOptions {
    pub(crate) host_id: HostId,
    pub(crate) ssh_user: String,
    #[serde(
        default = "default_agent_ssh_port",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) port: Option<u16>,
    pub(crate) host_private_key_path: PathBuf,
    pub(crate) host_public_key_path: PathBuf,
    pub(crate) host_certificate_path: PathBuf,
    pub(crate) client_ca_path: PathBuf,
    pub(crate) authorized_principals_dir: PathBuf,
    pub(crate) sshd_dropin_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentBirdConfigOptions {
    pub(crate) config_path: PathBuf,
    #[serde(default = "default_agent_bird_service")]
    pub(crate) service: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentConfigOptions {
    pub(crate) api_base: String,
    pub(crate) auth: AgentAuthConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cache_path: Option<PathBuf>,
    pub(crate) host: AgentHostConfigOptions,
    pub(crate) bird: AgentBirdConfigOptions,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct AgentHostConfig {
    pub(crate) host_id: HostId,
    pub(crate) ssh_user: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) port: Option<u16>,
    pub(crate) host_private_key_path: PathBuf,
    pub(crate) host_public_key_path: PathBuf,
    pub(crate) host_certificate_path: PathBuf,
    pub(crate) client_ca_path: PathBuf,
    pub(crate) authorized_principals_dir: PathBuf,
    pub(crate) sshd_dropin_path: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct AgentBirdConfig {
    pub(crate) config_path: PathBuf,
    pub(crate) service: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct AgentConfig {
    pub(crate) api_base: String,
    pub(crate) auth: AgentAuthConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cache_path: Option<PathBuf>,
    pub(crate) host: AgentHostConfig,
    pub(crate) bird: AgentBirdConfig,
}

impl AgentConfig {
    pub(crate) fn parse_toml(raw: &str) -> Result<Self> {
        toml::from_str::<AgentConfigOptions>(raw)
            .context("failed to parse aegis-agent config")?
            .try_into()
    }
}

impl TryFrom<AgentConfigOptions> for AgentConfig {
    type Error = anyhow::Error;

    fn try_from(raw: AgentConfigOptions) -> Result<Self> {
        let api_base = raw.api_base.trim();
        if api_base != raw.api_base || api_base.is_empty() {
            bail!("agent api_base must be non-empty and contain no surrounding whitespace");
        }
        let endpoint = namespace_endpoint(api_base).context("invalid agent api_base")?;

        let refresh_token = raw.auth.refresh_token.trim();
        if refresh_token.is_empty() || refresh_token != raw.auth.refresh_token {
            bail!(
                "agent auth.refresh_token must be non-empty and contain no surrounding whitespace"
            );
        }

        if let Some(cache_path) = raw.cache_path.as_ref() {
            require_absolute_agent_config_path("cache_path", cache_path)?;
        }

        crate::principal_grants::validate_login_principal(&raw.host.ssh_user)
            .context("agent host.ssh_user is invalid")?;
        if raw.host.port == Some(0) {
            bail!("agent host.port must be between 1 and 65535");
        }
        for (field, path) in [
            (
                "host.host_private_key_path",
                &raw.host.host_private_key_path,
            ),
            ("host.host_public_key_path", &raw.host.host_public_key_path),
            (
                "host.host_certificate_path",
                &raw.host.host_certificate_path,
            ),
            ("host.client_ca_path", &raw.host.client_ca_path),
            (
                "host.authorized_principals_dir",
                &raw.host.authorized_principals_dir,
            ),
            ("host.sshd_dropin_path", &raw.host.sshd_dropin_path),
            ("bird.config_path", &raw.bird.config_path),
        ] {
            require_absolute_agent_config_path(field, path)?;
        }
        let host_key_paths = [
            &raw.host.host_private_key_path,
            &raw.host.host_public_key_path,
            &raw.host.host_certificate_path,
        ];
        if host_key_paths[0] == host_key_paths[1]
            || host_key_paths[0] == host_key_paths[2]
            || host_key_paths[1] == host_key_paths[2]
        {
            bail!("agent host key and certificate paths must be distinct");
        }
        if raw.bird.service.is_empty()
            || !raw.bird.service.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@')
            })
        {
            bail!("agent bird.service is not a valid systemd service name");
        }

        Ok(Self {
            api_base: endpoint.base_url(),
            auth: raw.auth,
            cache_path: raw.cache_path,
            host: AgentHostConfig {
                host_id: raw.host.host_id,
                ssh_user: raw.host.ssh_user,
                port: raw.host.port,
                host_private_key_path: raw.host.host_private_key_path,
                host_public_key_path: raw.host.host_public_key_path,
                host_certificate_path: raw.host.host_certificate_path,
                client_ca_path: raw.host.client_ca_path,
                authorized_principals_dir: raw.host.authorized_principals_dir,
                sshd_dropin_path: raw.host.sshd_dropin_path,
            },
            bird: AgentBirdConfig {
                config_path: raw.bird.config_path,
                service: raw.bird.service,
            },
        })
    }
}

pub(crate) fn persist_agent_config(path: &Path, config: &AgentConfig) -> Result<()> {
    atomic_write(
        path,
        toml::to_string(config)
            .context("failed to encode aegis-agent config")?
            .as_bytes(),
        Some(0o600),
        Some(0o755),
    )
}

fn require_absolute_agent_config_path(field: &str, path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("agent {field} must be an absolute path");
    }
    Ok(())
}

fn default_agent_ssh_port() -> Option<u16> {
    Some(22)
}

fn default_agent_bird_service() -> String {
    "bird".to_string()
}

pub fn agent_refresh_token_env_value(refresh_token: &str) -> String {
    BASE64_STANDARD.encode(refresh_token)
}

pub fn agent_refresh_token_from_encoded_value(encoded: &str) -> Result<String> {
    let raw = BASE64_STANDARD
        .decode(encoded.trim())
        .context("failed to decode aegis-agent refresh token")?;
    let raw = String::from_utf8(raw).context("aegis-agent refresh token is not valid UTF-8")?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!("aegis-agent refresh token must not be empty");
    }
    Ok(trimmed.to_string())
}

pub fn canonical_saved_api_base_url(value: &str) -> String {
    let trimmed = value.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    trimmed.to_string()
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

pub fn resolve_api_base(
    cli_override: Option<&str>,
    installed_api_base: Option<&str>,
) -> Result<String> {
    let selected = match cli_override.or(installed_api_base) {
        Some(value) => value.to_owned(),
        None => UserContext::load()?.context("No Aegis deployment selected. Run `aegis-admin setup`, select an enrollment file, or pass --api-base once.")?.api_base,
    };
    Ok(aegis_dto::namespace::ApiEndpoint::parse(&selected)
        .map_err(anyhow::Error::msg)?
        .base_url())
}

pub fn app_dir() -> Result<PathBuf> {
    Ok(paths::home_dir()?.join(".aegis"))
}

pub fn locks_dir() -> Result<PathBuf> {
    Ok(app_dir()?.join("locks"))
}

pub fn keys_dir() -> Result<PathBuf> {
    Ok(app_dir()?.join("keys"))
}

pub fn user_auth_state_path() -> Result<PathBuf> {
    Ok(app_dir()?.join("auth.toml"))
}

pub fn scoped_private_key_path(api_base: &str, host_id: &HostId) -> Result<PathBuf> {
    use sha2::{Digest, Sha256};
    let endpoint = namespace_endpoint(api_base)?;
    let directory = keys_dir()?.join(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(endpoint.base_url().as_bytes())),
    );
    ensure_directory(&directory, Some(0o700))?;
    Ok(directory.join(host_id.to_string()))
}

pub fn load_cached_inventory(path: &Path) -> Result<Option<CachedInventory>> {
    let endpoint = crate::api::installed_agent_api_base()?;
    load_cached_inventory_for_endpoint(path, &resolve_api_base(endpoint.as_deref(), None)?)
}

pub(crate) fn load_cached_inventory_for_endpoint(
    path: &Path,
    api_base: &str,
) -> Result<Option<CachedInventory>> {
    let expected = namespace_endpoint(api_base)?;
    let raw = match fs::read(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    let inventory: CachedInventory = serde_json::from_slice(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    if namespace_endpoint(&inventory.api_base)? != expected {
        return Ok(None);
    }
    Ok(Some(inventory))
}

pub fn load_all_hosts(path: &Path) -> Result<Vec<CachedHost>> {
    load_all_hosts_for_network(path, aegis_dto::DEFAULT_AEGIS_NETWORK)
}

pub fn load_cached_network(path: &Path, network: &str) -> Result<Option<ResolvedNetwork>> {
    load_cached_inventory(path)?
        .map(|inventory| inventory.resolve_network(network))
        .transpose()
        .map(Option::flatten)
}

pub fn load_all_hosts_for_network(path: &Path, network: &str) -> Result<Vec<CachedHost>> {
    Ok(load_cached_network(path, network)?
        .map(|network| network.hosts)
        .unwrap_or_default())
}

pub fn persist_inventory(path: &Path, inventory: &CachedInventory) -> Result<()> {
    namespace_endpoint(&inventory.api_base)?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", path.display()))?;
    ensure_directory(parent, Some(0o755))?;
    let raw = serde_json::to_vec_pretty(inventory).context("failed to encode inventory cache")?;
    match fs::read(path) {
        Ok(existing) if existing == raw => {
            #[cfg(unix)]
            if fs::metadata(path)
                .with_context(|| format!("failed to inspect {}", path.display()))?
                .permissions()
                .mode()
                & 0o7777
                != 0o644
            {
                tighten_file_permissions(path, 0o644)?;
            }
            return Ok(());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()));
        }
    }
    atomic_write(path, &raw, Some(0o644), Some(0o755))
}

pub fn load_user_auth_state() -> Result<Option<UserAuthState>> {
    let path = user_auth_state_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let raw =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    toml::from_str(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))
        .map(Some)
}

pub fn persist_user_auth_state(auth_state: &UserAuthState) -> Result<()> {
    let path = user_auth_state_path()?;
    #[cfg(unix)]
    let existing_owner = match fs::metadata(&path) {
        Ok(metadata) => Some((metadata.uid(), metadata.gid())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    };
    let raw = toml::to_string(auth_state).context("failed to encode aegis user auth state")?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", path.display()))?;
    ensure_directory(parent, Some(0o700))?;
    atomic_write(&path, raw.as_bytes(), Some(0o600), Some(0o700))?;
    #[cfg(unix)]
    if unsafe { libc::geteuid() } == 0
        && let Some((uid, gid)) = existing_owner
    {
        std::os::unix::fs::chown(&path, Some(uid), Some(gid))
            .with_context(|| format!("failed to preserve ownership of {}", path.display()))?;
    }
    Ok(())
}

pub fn ensure_client_dirs() -> Result<()> {
    for dir in [app_dir()?, keys_dir()?] {
        ensure_directory(&dir, Some(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        AgentAuthConfig, CachedHost, CachedInventory, persist_inventory, resolve_api_base,
    };
    use std::{collections::BTreeMap, fs, os::unix::fs::MetadataExt};

    #[test]
    fn cached_inventory_is_bound_to_its_api_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.json");
        let inventory = CachedInventory {
            api_base: "https://example.test/v2/namespaces/alice".into(),
            hosts: BTreeMap::new(),
            networks: BTreeMap::new(),
        };
        persist_inventory(&path, &inventory).unwrap();
        let load = |base| super::load_cached_inventory_for_endpoint(&path, base).unwrap();
        assert!(load("https://example.test/v2/namespaces/alice/").is_some());
        assert!(load("https://example.test/v2/namespaces/bob").is_none());
        assert!(load("https://other.test/v2/namespaces/alice").is_none());
        assert!(
            super::load_cached_inventory_for_endpoint(&path, "https://example.test/v2").is_err()
        );
        fs::write(
            &path,
            r#"{"api_base":"https://example.test/v2","hosts":{},"networks":{}}"#,
        )
        .unwrap();
        assert!(
            super::load_cached_inventory_for_endpoint(
                &path,
                "https://example.test/v2/namespaces/alice"
            )
            .is_err()
        );
        fs::write(&path, r#"{"hosts":{},"networks":{}}"#).unwrap();
        assert!(
            super::load_cached_inventory_for_endpoint(
                &path,
                "https://example.test/v2/namespaces/alice"
            )
            .is_err()
        );
    }

    #[test]
    fn agent_auth_config_serializes_host_refresh_token() {
        let raw = toml::to_string(&AgentAuthConfig {
            refresh_token: "hrt.id.secret".to_string(),
        })
        .expect("agent auth config should serialize");

        assert!(raw.contains("refresh_token = \"hrt.id.secret\""));
    }

    #[test]
    fn resolve_api_base_prefers_cli_override() {
        assert_eq!(
            "https://override.example/v2",
            resolve_api_base(
                Some("https://override.example/v2"),
                Some("https://saved.example/v2")
            )
            .unwrap()
        );
    }

    #[test]
    fn cached_host_label_uses_port_only_when_non_default() {
        let mut host = CachedHost {
            host_id: "00000000-0000-4000-8000-000000000001"
                .parse()
                .expect("host id"),
            aliases: aegis_dto::HostAliases::new(vec![
                aegis_dto::HostAlias::parse("alpha").expect("alias"),
            ])
            .expect("aliases"),
            host: aegis_dto::v1::AegisNetworkHost {
                mode: aegis_dto::AegisHostMode::Leaf,
                ssh: Some(aegis_dto::v1::AegisNetworkHostSsh {
                    port: Some(22),
                    public_key: Some("ssh-ed25519 AAAA test".to_string()),
                    internal_principals: vec![
                        "10.0.0.42".to_string(),
                        "fd75::2a".to_string(),
                        "alpha.example.com".to_string(),
                    ],
                    external_principals: vec![],
                }),
                wireguard: Some(aegis_dto::v1::AegisNetworkMemberWireGuard {
                    public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
                    ipv4: "10.0.0.42".to_string(),
                    ipv6: "fd75::2a".to_string(),
                    endpoints: Vec::new(),
                }),
                egress: None,
                internal: None,
                messages: Vec::new(),
                agent: None,
                ssh_lockdown_enabled: false,
                observed_public_ips: aegis_dto::v1::AegisObservedPublicIps::default(),
                transient: false,
                pending: false,
                updated_unix: 10,
            },
        };

        assert_eq!("10.0.0.42", host.host_label());
        host.ssh.as_mut().expect("ssh config").port = Some(2200);
        assert_eq!("10.0.0.42:2200", host.host_label());

        host.internal = Some(aegis_dto::v1::AegisNetworkMemberInternalAddresses {
            ipv4: "10.75.0.42".to_string(),
            ipv6: "fd75::2a".to_string(),
        });
        assert_eq!("10.75.0.42:2200", host.host_label());
        host.internal = None;
        assert_eq!("10.0.0.42:2200", host.host_label());
        host.ssh.as_mut().expect("ssh config").port = None;
        assert_eq!("10.0.0.42", host.host_label());
    }

    #[test]
    fn resolve_api_base_keeps_saved_value() {
        assert_eq!(
            "https://api.hoek.io/v2",
            resolve_api_base(None, Some("https://api.hoek.io/v2")).unwrap()
        );
    }

    #[test]
    fn identical_inventory_persistence_keeps_the_existing_inode() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("cache.json");
        let inventory = CachedInventory {
            api_base: "https://api.hoek.io/v2/namespaces/test".into(),
            hosts: BTreeMap::new(),
            networks: BTreeMap::new(),
        };

        persist_inventory(&path, &inventory).expect("initial persistence");
        let inode = fs::metadata(&path).expect("initial metadata").ino();
        persist_inventory(&path, &inventory).expect("identical persistence");

        assert_eq!(inode, fs::metadata(path).expect("final metadata").ino());
    }
}
