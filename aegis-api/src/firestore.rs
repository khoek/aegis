use crate::aegis_store::{
    AegisAliasWriteError, AegisDirectGatewayRecord, AegisDirectLeaseRecord,
    AegisDirectWireGuardRecord, AegisDirectWriteError, AegisEgressSnapshot, AegisEgressWriteError,
    AegisEnrollmentPreparation, AegisEnrollmentPrepared, AegisEnrollmentRecord,
    AegisEnrollmentWriteError, AegisHostDeleteError, AegisHostRecord, AegisHostRecordSsh,
    AegisHostReportUpdate, AegisHostWriteError, AegisNetworkMemberRecord,
    AegisSatelliteBrokerUseRecord, AegisSatelliteRecord, AegisStore, AegisUserIdentity,
    enrollment_phase_rank, prepared_host_matches_enrollment, validate_current_enrollment,
};
use aegis_types::configuration::*;
use aegis_types::{
    AegisHostMode, HostAlias, HostAliases, HostId, WireGuardAddressError, WireGuardHostIdentity,
    allocate_lowest_free_wireguard_host_id,
    v1::{
        AegisAgentStatus, AegisEnrollmentPhase, AegisEnrollmentSsh, AegisHostMessage,
        AegisObservedPublicIp, AegisObservedPublicIps, AegisPrincipalGrant, AegisSyncAction,
        AegisTlsChange, AegisTlsDesiredState, AegisTlsSyncResponse, AegisWireGuardAddressPool,
    },
    wireguard_host_identity_from_addresses, wireguard_ipv4_for_host_id, wireguard_ipv6_for_host_id,
};
use anyhow::Context;
#[cfg(test)]
use chrono::Utc;
use firestore::{
    FirestoreConsistencySelector, FirestoreDb, FirestoreDocument, FirestoreTransaction,
    FirestoreTransactionOps, FirestoreWritePrecondition, errors::FirestoreError,
};
#[cfg(test)]
use rcgen::{BasicConstraints, CertificateRevocationListParams, GeneralSubtree, NameConstraints};
use rcgen::{
    CertificateParams, CrlDistributionPoint, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    IsCa, Issuer, KeyPair, KeyUsagePurpose, SerialNumber, SubjectPublicKeyInfo,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(test)]
use ssh_key::{Algorithm, LineEnding, PrivateKey, rand_core::OsRng};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use time::{Duration as TlsDuration, OffsetDateTime as TlsDateTime};
use x509_parser::pem::parse_x509_pem;
#[cfg(test)]
use x509_parser::{extensions::ParsedExtension, oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER};

pub(crate) use arche_firestore::*;
#[cfg(test)]
pub const DEFAULT_CLIENT_CERT_TTL_SECONDS: u64 = 31_557_600_000;

#[cfg(test)]
pub const DEFAULT_SERVER_CERT_TTL_SECONDS: u64 = 31_557_600_000;

const AEGIS_SSH_COLLECTION: &str = "ssh";

const AEGIS_SSH_DOC: &str = "config";

const SSH_CAS_COLLECTION: &str = "cas";

const SSH_USER_CA_DOC: &str = "user";

const SSH_DIRECT_CA_DOC: &str = "direct";

const SSH_HOST_CA_DOC: &str = "host";

const AEGIS_HOSTS_COLLECTION: &str = "hosts";

const AEGIS_ENROLLMENTS_COLLECTION: &str = "enrollments";

const AEGIS_ALIASES_COLLECTION: &str = "aliases";

const AEGIS_STATE_COLLECTION: &str = "state";

const AEGIS_EGRESS_STATE_DOCUMENT: &str = "egress";

const AEGIS_DIRECT_GATEWAYS_COLLECTION: &str = "direct-gateways";

const AEGIS_DIRECT_LEASES_COLLECTION: &str = "direct-leases";

const AEGIS_SATELLITES_COLLECTION: &str = "satellites";

const AEGIS_NETWORKS_COLLECTION: &str = "networks";

const AEGIS_NETWORK_MEMBERS_COLLECTION: &str = "members";

const AEGIS_TLS_COLLECTION: &str = "tls";

const AEGIS_TLS_DOC: &str = "config";

const TLS_CAS_COLLECTION: &str = "cas";

const TLS_CERTS_COLLECTION: &str = "certs";

const TLS_ROOT_CA_DOC: &str = "root";

const TLS_ISSUING_CA_DOC: &str = "issuing";

#[cfg(test)]
const TLS_CA_ORGANIZATION: &str = "Aegis";

#[cfg(test)]
const TLS_ROOT_CA_COMMON_NAME: &str = "aegis Root CA R1";

#[cfg(test)]
const TLS_SIGNING_CA_COMMON_NAME: &str = "aegis Signing CA S1";

const TLS_VALIDITY_DAYS: i64 = 365_000;

#[cfg(test)]
const TLS_CRL_NUMBER: u64 = 1;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct StoredClientCaConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    private_key_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    passphrase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cert_ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct StoredDirectClientCaConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    private_key_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    passphrase: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct StoredServerCaConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    private_key_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    passphrase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cert_ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[cfg(test)]
struct StoredSshConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    created_unix: Option<i64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct StoredTlsCaConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    certificate_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    private_key_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    crl_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    serial_number: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issued_unix: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    not_after_unix: Option<i64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredTlsCertConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dns_names: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host_id: Option<HostId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_key_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    certificate_chain_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    serial_number: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issued_unix: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    not_after_unix: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsCertRecord {
    pub label: String,
    pub dns_names: Vec<String>,
    pub host_id: HostId,
    pub public_key_pem: Option<String>,
    pub certificate_chain_pem: Option<String>,
    pub serial_number: Option<String>,
    pub issued_unix: Option<i64>,
    pub not_after_unix: Option<i64>,
}

#[derive(Clone)]
pub struct AegisDb {
    db: Db,
    parent: String,
}

impl AegisDb {
    pub fn new(db: Db, namespace: aegis_types::NamespaceId) -> Self {
        let parent = format!(
            "{}/v2/aegis/namespaces/{namespace}",
            db.inner().get_documents_path()
        );
        Self { db, parent }
    }

    async fn begin_write_transaction(&self) -> anyhow::Result<FirestoreTransaction<'_>> {
        Ok(tokio::time::timeout(
            std::time::Duration::from_secs(20),
            self.inner().begin_transaction(),
        )
        .await??)
    }

    #[cfg(test)]
    async fn create_typed_at<T>(
        &self,
        parent: &str,
        collection: &str,
        document: &str,
        value: &T,
    ) -> anyhow::Result<()>
    where
        T: Serialize + Sync + Send,
    {
        let mut tx = self.begin_write_transaction().await?;
        tx.update_object_at(
            parent,
            collection,
            document,
            value,
            None,
            Some(FirestoreWritePrecondition::Exists(false)),
            vec![],
        )?;
        tokio::time::timeout(std::time::Duration::from_secs(20), tx.commit()).await??;
        Ok(())
    }
    pub fn auth_store(
        &self,
        refresh_token: &phylax_gcp::identity::RefreshTokenConfig,
        oauth_login_session_ttl_seconds: u64,
    ) -> anyhow::Result<phylax_gcp::FirestoreAuthStore> {
        Ok(phylax_gcp::FirestoreAuthStore::new(
            self.db.shared(),
            format!("{}/auth/config", self.parent),
            phylax_gcp::FirestoreAuthStoreConfig::new(
                &refresh_token.pepper,
                refresh_token.ttl_seconds,
                oauth_login_session_ttl_seconds,
            )?,
        ))
    }

    pub fn inner(&self) -> &FirestoreDb {
        self.db.inner()
    }

    fn root(&self) -> (&str, &str, &str) {
        let (collection_parent, document) = self.parent.rsplit_once('/').expect("document path");
        let (parent, collection) = collection_parent.rsplit_once('/').expect("collection path");
        (parent, collection, document)
    }
}

pub async fn load_aegis_instance_config(
    db: &AegisDb,
) -> anyhow::Result<aegis_types::configuration::AegisInstanceConfig> {
    aegis_types::configuration::AegisInstanceConfig {
        config: load_aegis_config(db).await?,
        client_ca: load_client_ca_config(db).await?,
        direct_client_ca: load_direct_client_ca_config(db).await?,
        server_ca: load_server_ca_config(db).await?,
        tls: load_tls_config(db).await?,
    }
    .require()
}

pub async fn list_aegis_namespaces(db: &Db) -> anyhow::Result<Vec<aegis_types::NamespaceId>> {
    let docs = db
        .inner()
        .fluent()
        .select()
        .from("namespaces")
        .parent(format!("{}/v2/aegis", db.inner().get_documents_path()))
        .query()
        .await?;
    docs.into_iter()
        .map(|doc| {
            doc.name
                .rsplit('/')
                .next()
                .context("namespace document has no id")?
                .parse()
                .map_err(anyhow::Error::from)
        })
        .collect()
}

async fn load_aegis_config(db: &AegisDb) -> anyhow::Result<AegisConfig> {
    let (parent, collection, document) = db.root();
    let stored =
        load_optional_typed_at::<NamespaceDefinition>(db.inner(), parent, collection, document)
            .await?
            .ok_or_else(|| anyhow::anyhow!("{} config document is required", db.parent))?;
    stored.validate()
}

async fn load_client_ca_config(db: &AegisDb) -> anyhow::Result<ClientCaConfig> {
    let parent = aegis_ssh_parent(db)?;
    let stored = load_optional_typed_at::<StoredClientCaConfig>(
        db.inner(),
        &parent,
        SSH_CAS_COLLECTION,
        SSH_USER_CA_DOC,
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("v2/aegis/ssh/config/cas/user is required"))?;
    validate_client_ca_config(stored)
}

async fn load_server_ca_config(db: &AegisDb) -> anyhow::Result<ServerCaConfig> {
    let parent = aegis_ssh_parent(db)?;
    let stored = load_optional_typed_at::<StoredServerCaConfig>(
        db.inner(),
        &parent,
        SSH_CAS_COLLECTION,
        SSH_HOST_CA_DOC,
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("v2/aegis/ssh/config/cas/host is required"))?;
    validate_server_ca_config(stored)
}

async fn load_tls_config(db: &AegisDb) -> anyhow::Result<TlsConfig> {
    let parent = aegis_tls_parent(db)?;
    let root_path = "v2/aegis/tls/config/cas/root";
    let root = load_optional_typed_at::<StoredTlsCaConfig>(
        db.inner(),
        &parent,
        TLS_CAS_COLLECTION,
        TLS_ROOT_CA_DOC,
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("{root_path} is required"))?;
    let issuing_path = "v2/aegis/tls/config/cas/issuing";
    let issuing = load_optional_typed_at::<StoredTlsCaConfig>(
        db.inner(),
        &parent,
        TLS_CAS_COLLECTION,
        TLS_ISSUING_CA_DOC,
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("{issuing_path} is required"))?;
    let issuing_crl_pem = normalized_text(issuing.crl_pem.as_ref())
        .ok_or_else(|| anyhow::anyhow!("{issuing_path}.crl_pem is required"))?
        .to_string();
    Ok(TlsConfig {
        root: validate_tls_ca_config(root_path, root)?,
        issuing: validate_tls_ca_config(issuing_path, issuing)?,
        issuing_crl_pem,
    })
}

#[cfg(test)]
fn default_client_ca_document() -> anyhow::Result<StoredClientCaConfig> {
    Ok(StoredClientCaConfig {
        private_key_pem: Some(generate_open_ssh_private_key_pem()?),
        passphrase: None,
        cert_ttl_seconds: Some(DEFAULT_CLIENT_CERT_TTL_SECONDS),
    })
}

#[cfg(test)]
fn default_server_ca_document() -> anyhow::Result<StoredServerCaConfig> {
    Ok(StoredServerCaConfig {
        private_key_pem: Some(generate_open_ssh_private_key_pem()?),
        passphrase: None,
        cert_ttl_seconds: Some(DEFAULT_SERVER_CERT_TTL_SECONDS),
    })
}

#[cfg(test)]
fn default_tls_root_ca_document(dns_suffix: &str) -> anyhow::Result<StoredTlsCaConfig> {
    let key = KeyPair::generate()?;
    let mut params = tls_root_ca_params(dns_suffix);
    let issued = TlsDateTime::now_utc();
    params.not_before = issued - TlsDuration::minutes(5);
    params.not_after = issued + TlsDuration::days(TLS_VALIDITY_DAYS);
    let serial_number = serial_number_for("tls-root", issued.unix_timestamp());
    params.serial_number = Some(serial_number.clone());
    Ok(StoredTlsCaConfig {
        certificate_pem: Some(params.self_signed(&key)?.pem()),
        private_key_pem: Some(key.serialize_pem()),
        crl_pem: None,
        serial_number: Some(serial_number.to_string()),
        issued_unix: Some(issued.unix_timestamp()),
        not_after_unix: Some(params.not_after.unix_timestamp()),
    })
}

#[cfg(test)]
fn default_tls_issuing_ca_document(
    root: &TlsCaConfig,
    api_issuer: &str,
) -> anyhow::Result<StoredTlsCaConfig> {
    let root_key = KeyPair::from_pem(&root.private_key_pem)
        .context("aegis.tls.cas.root.private_key_pem failed to parse")?;
    let key = KeyPair::generate()?;
    let mut params = tls_issuing_ca_params(&tls_dns_constraint(root)?);
    let issued = TlsDateTime::now_utc();
    params.not_before = issued - TlsDuration::minutes(5);
    params.not_after = issued + TlsDuration::days(TLS_VALIDITY_DAYS);
    let serial_number = serial_number_for("tls-issuing", issued.unix_timestamp());
    params.serial_number = Some(serial_number.clone());
    let issuer = Issuer::from_ca_cert_pem(&root.certificate_pem, root_key)
        .context("aegis.tls.cas.root.certificate_pem failed to parse")?;
    let certificate_pem = params.signed_by(&key, &issuer)?.pem();
    let issuing = TlsCaConfig {
        certificate_pem: certificate_pem.clone(),
        private_key_pem: key.serialize_pem(),
    };
    Ok(StoredTlsCaConfig {
        certificate_pem: Some(certificate_pem),
        private_key_pem: Some(issuing.private_key_pem.clone()),
        crl_pem: Some(empty_tls_crl_pem(&issuing, api_issuer)?),
        serial_number: Some(serial_number.to_string()),
        issued_unix: Some(issued.unix_timestamp()),
        not_after_unix: Some(params.not_after.unix_timestamp()),
    })
}

fn validate_client_ca_config(stored: StoredClientCaConfig) -> anyhow::Result<ClientCaConfig> {
    let private_key_pem = normalized_text(stored.private_key_pem.as_ref()).ok_or_else(|| {
        anyhow::anyhow!("v2/aegis/ssh/config/cas/user.private_key_pem is required")
    })?;
    let cert_ttl_seconds = stored
        .cert_ttl_seconds
        .filter(|ttl| *ttl > 0)
        .ok_or_else(|| {
            anyhow::anyhow!("v2/aegis/ssh/config/cas/user.cert_ttl_seconds is required")
        })?;
    Ok(ClientCaConfig {
        private_key_pem: private_key_pem.to_string(),
        passphrase: stored.passphrase.filter(|value| !value.trim().is_empty()),
        cert_ttl_seconds,
    })
}

fn validate_direct_client_ca_config(
    stored: StoredDirectClientCaConfig,
) -> anyhow::Result<DirectClientCaConfig> {
    let private_key_pem = normalized_text(stored.private_key_pem.as_ref()).ok_or_else(|| {
        anyhow::anyhow!("v2/aegis/ssh/config/cas/direct.private_key_pem is required")
    })?;
    Ok(DirectClientCaConfig {
        private_key_pem: private_key_pem.to_string(),
        passphrase: stored.passphrase.filter(|value| !value.trim().is_empty()),
    })
}

fn validate_server_ca_config(stored: StoredServerCaConfig) -> anyhow::Result<ServerCaConfig> {
    let private_key_pem = normalized_text(stored.private_key_pem.as_ref()).ok_or_else(|| {
        anyhow::anyhow!("v2/aegis/ssh/config/cas/host.private_key_pem is required")
    })?;
    let cert_ttl_seconds = stored
        .cert_ttl_seconds
        .filter(|ttl| *ttl > 0)
        .ok_or_else(|| {
            anyhow::anyhow!("v2/aegis/ssh/config/cas/host.cert_ttl_seconds is required")
        })?;
    Ok(ServerCaConfig {
        private_key_pem: private_key_pem.to_string(),
        passphrase: stored.passphrase.filter(|value| !value.trim().is_empty()),
        cert_ttl_seconds,
    })
}

fn validate_tls_ca_config(path: &str, stored: StoredTlsCaConfig) -> anyhow::Result<TlsCaConfig> {
    let certificate_pem = normalized_text(stored.certificate_pem.as_ref())
        .ok_or_else(|| anyhow::anyhow!("{path}.certificate_pem is required"))?;
    let private_key_pem = normalized_text(stored.private_key_pem.as_ref())
        .ok_or_else(|| anyhow::anyhow!("{path}.private_key_pem is required"))?;
    KeyPair::from_pem(private_key_pem)
        .map_err(|error| anyhow::anyhow!("{path}.private_key_pem failed to parse: {error}"))?;
    Ok(TlsCaConfig {
        certificate_pem: certificate_pem.to_string(),
        private_key_pem: private_key_pem.to_string(),
    })
}

fn validate_tls_cert_config(
    label: &str,
    stored: StoredTlsCertConfig,
) -> anyhow::Result<TlsCertRecord> {
    validate_tls_label(label)?;
    let dns_names = stored
        .dns_names
        .unwrap_or_default()
        .into_iter()
        .map(|name| {
            let name = name.trim().to_string();
            validate_tls_dns_name(&name)?;
            Ok(name)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    if dns_names.is_empty() {
        anyhow::bail!("v2/aegis/tls/config/certs/{label}.dns_names must not be empty");
    }
    let mut sorted_dns_names = dns_names;
    sorted_dns_names.sort();
    sorted_dns_names.dedup();
    let host_id = stored
        .host_id
        .ok_or_else(|| anyhow::anyhow!("v2/aegis/tls/config/certs/{label}.host_id is required"))?;
    let public_key_pem = normalized_text(stored.public_key_pem.as_ref()).map(str::to_string);
    if let Some(public_key_pem) = public_key_pem.as_ref() {
        SubjectPublicKeyInfo::from_pem(public_key_pem).with_context(|| {
            format!("v2/aegis/tls/config/certs/{label}.public_key_pem failed to parse")
        })?;
    }
    Ok(TlsCertRecord {
        label: label.to_string(),
        dns_names: sorted_dns_names,
        host_id,
        public_key_pem,
        certificate_chain_pem: normalized_text(stored.certificate_chain_pem.as_ref())
            .map(str::to_string),
        serial_number: normalized_text(stored.serial_number.as_ref()).map(str::to_string),
        issued_unix: stored.issued_unix,
        not_after_unix: stored.not_after_unix,
    })
}

fn validate_tls_label(label: &str) -> anyhow::Result<()> {
    if label.trim().is_empty()
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        anyhow::bail!("TLS certificate label `{label}` must use lowercase DNS-label characters");
    }
    Ok(())
}

fn validate_tls_dns_name(name: &str) -> anyhow::Result<()> {
    if name.parse::<std::net::IpAddr>().is_ok() {
        anyhow::bail!("TLS DNS name `{name}` must not be an IP literal");
    }
    if name.contains('*') {
        anyhow::bail!("TLS DNS name `{name}` must be concrete, not a wildcard");
    }
    Ok(())
}

#[cfg(test)]
async fn ensure_client_ca_config(db: &AegisDb) -> anyhow::Result<ClientCaConfig> {
    ensure_ssh_parent_config(db).await?;
    let parent = aegis_ssh_parent(db)?;
    for attempt in 0..CONFIG_BOOTSTRAP_MAX_RETRIES {
        if let Some(stored) = load_optional_typed_at::<StoredClientCaConfig>(
            db.inner(),
            &parent,
            SSH_CAS_COLLECTION,
            SSH_USER_CA_DOC,
        )
        .await?
        {
            return validate_client_ca_config(stored);
        }

        let stored = default_client_ca_document()?;
        tracing::warn!(
            "missing v2/aegis/ssh/config/cas/user; creating a bootstrap document with a generated user SSH CA keypair"
        );
        match db
            .create_typed_at(&parent, SSH_CAS_COLLECTION, SSH_USER_CA_DOC, &stored)
            .await
        {
            Ok(()) => return validate_client_ca_config(stored),
            Err(error)
                if should_retry_bootstrap_conflict(
                    &error,
                    "v2/aegis/ssh/config/cas/user",
                    attempt,
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }

    anyhow::bail!(
        "v2/aegis/ssh/config/cas/user bootstrap did not converge after {CONFIG_BOOTSTRAP_MAX_RETRIES} attempts"
    )
}

async fn load_direct_client_ca_config(db: &AegisDb) -> anyhow::Result<DirectClientCaConfig> {
    let parent = aegis_ssh_parent(db)?;
    let stored = load_optional_typed_at::<StoredDirectClientCaConfig>(
        db.inner(),
        &parent,
        SSH_CAS_COLLECTION,
        SSH_DIRECT_CA_DOC,
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("v2/aegis/ssh/config/cas/direct is required"))?;
    validate_direct_client_ca_config(stored)
}

#[cfg(test)]
async fn ensure_ssh_parent_config(db: &AegisDb) -> anyhow::Result<()> {
    let parent = aegis_parent(db)?;
    for attempt in 0..CONFIG_BOOTSTRAP_MAX_RETRIES {
        if load_optional_typed_at::<StoredSshConfig>(
            db.inner(),
            &parent,
            AEGIS_SSH_COLLECTION,
            AEGIS_SSH_DOC,
        )
        .await?
        .is_some()
        {
            return Ok(());
        }
        let stored = StoredSshConfig {
            created_unix: Some(Utc::now().timestamp()),
        };
        tracing::warn!("missing v2/aegis/ssh/config; creating SSH parent document");
        match db
            .create_typed_at(&parent, AEGIS_SSH_COLLECTION, AEGIS_SSH_DOC, &stored)
            .await
        {
            Ok(()) => return Ok(()),
            Err(error)
                if should_retry_bootstrap_conflict(&error, "v2/aegis/ssh/config", attempt) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }

    anyhow::bail!(
        "v2/aegis/ssh/config bootstrap did not converge after {CONFIG_BOOTSTRAP_MAX_RETRIES} attempts"
    )
}

pub async fn fetch_tls_cert_config(
    db: &AegisDb,
    label: &str,
) -> anyhow::Result<Option<TlsCertRecord>> {
    let parent = aegis_tls_parent(db)?;
    let Some(stored) = load_optional_typed_at::<StoredTlsCertConfig>(
        db.inner(),
        &parent,
        TLS_CERTS_COLLECTION,
        label,
    )
    .await?
    else {
        return Ok(None);
    };
    validate_tls_cert_config(label, stored).map(Some)
}

pub async fn sync_tls_cert_configs(
    db: &AegisDb,
    desired: &AegisTlsDesiredState,
    dry_run: bool,
) -> anyhow::Result<AegisTlsSyncResponse> {
    let desired = normalized_tls_desired_state(desired)?;
    let parent = aegis_tls_parent(db)?;
    let docs = db
        .inner()
        .fluent()
        .select()
        .from(TLS_CERTS_COLLECTION)
        .parent(&parent)
        .query()
        .await?;
    let mut existing = BTreeMap::new();
    for document in docs {
        let label = firestore_document_id(&document.name)
            .ok_or_else(|| {
                anyhow::anyhow!("malformed Firestore document name `{}`", document.name)
            })?
            .to_string();
        let stored = deserialize_stored_document::<StoredTlsCertConfig>(&document)?;
        let record = validate_tls_cert_config(&label, stored.clone())?;
        existing.insert(label, (stored, record));
    }

    let mut changes = Vec::new();
    for (label, desired_record) in &desired {
        match existing.get(label) {
            None => changes.push(AegisTlsChange {
                action: AegisSyncAction::Create,
                label: label.clone(),
            }),
            Some((_, current))
                if current.host_id != desired_record.host_id
                    || current.dns_names != desired_record.dns_names =>
            {
                changes.push(AegisTlsChange {
                    action: AegisSyncAction::Update,
                    label: label.clone(),
                });
            }
            Some(_) => {}
        }
    }
    for label in existing
        .keys()
        .filter(|label| !desired.contains_key(*label))
    {
        changes.push(AegisTlsChange {
            action: AegisSyncAction::Delete,
            label: label.clone(),
        });
    }
    changes.sort_by(|left, right| left.label.cmp(&right.label));

    if !dry_run {
        for (label, desired_record) in &desired {
            let stored = match existing.get(label) {
                Some((stored, current))
                    if current.host_id == desired_record.host_id
                        && current.dns_names == desired_record.dns_names =>
                {
                    continue;
                }
                Some((stored, current)) => StoredTlsCertConfig {
                    dns_names: Some(desired_record.dns_names.clone()),
                    host_id: Some(desired_record.host_id),
                    public_key_pem: (current.host_id == desired_record.host_id)
                        .then(|| stored.public_key_pem.clone())
                        .flatten(),
                    certificate_chain_pem: None,
                    serial_number: None,
                    issued_unix: None,
                    not_after_unix: None,
                },
                None => StoredTlsCertConfig {
                    dns_names: Some(desired_record.dns_names.clone()),
                    host_id: Some(desired_record.host_id),
                    ..Default::default()
                },
            };
            let mut tx = db.begin_write_transaction().await?;
            tx.update_object_at(
                &parent,
                TLS_CERTS_COLLECTION,
                label,
                &stored,
                None,
                None,
                vec![],
            )?;
            tx.commit().await?;
        }
        for label in existing
            .keys()
            .filter(|label| !desired.contains_key(*label))
        {
            let mut tx = db.begin_write_transaction().await?;
            tx.delete_by_id_at(&parent, TLS_CERTS_COLLECTION, label, None)?;
            tx.commit().await?;
        }
    }

    Ok(AegisTlsSyncResponse {
        dry_run,
        desired: desired.len(),
        created: changes
            .iter()
            .filter(|change| change.action == AegisSyncAction::Create)
            .count(),
        updated: changes
            .iter()
            .filter(|change| change.action == AegisSyncAction::Update)
            .count(),
        deleted: changes
            .iter()
            .filter(|change| change.action == AegisSyncAction::Delete)
            .count(),
        changes,
    })
}

fn normalized_tls_desired_state(
    desired: &AegisTlsDesiredState,
) -> anyhow::Result<BTreeMap<String, TlsCertRecord>> {
    let mut normalized = BTreeMap::new();
    for certificate in &desired.certificates {
        let label = certificate.label.trim().to_string();
        let stored = StoredTlsCertConfig {
            dns_names: Some(certificate.dns_names.clone()),
            host_id: Some(certificate.host_id),
            ..Default::default()
        };
        let record = validate_tls_cert_config(&label, stored)?;
        if normalized.insert(label.clone(), record).is_some() {
            anyhow::bail!("TLS certificate label `{label}` is declared more than once");
        }
    }
    Ok(normalized)
}

pub async fn put_tls_cert_public_key(
    db: &AegisDb,
    issuing: &TlsCaConfig,
    api_issuer: &str,
    label: &str,
    public_key_pem: &str,
) -> anyhow::Result<Option<TlsCertRecord>> {
    let parent = aegis_tls_parent(db)?;
    let mut tx = db.begin_write_transaction().await?;
    let tx_db =
        db.inner()
            .clone_with_consistency_selector(FirestoreConsistencySelector::Transaction(
                tx.transaction_id().clone(),
            ));
    let Some(mut stored) =
        load_optional_typed_at::<StoredTlsCertConfig>(&tx_db, &parent, TLS_CERTS_COLLECTION, label)
            .await?
    else {
        tx.rollback().await.ok();
        return Ok(None);
    };
    let existing = validate_tls_cert_config(label, stored.clone())?;
    let public_key_pem = public_key_pem.trim();
    if public_key_pem.is_empty() {
        anyhow::bail!("TLS certificate `{label}` public key must not be empty");
    }
    let public_key_pem = public_key_pem.to_string();
    SubjectPublicKeyInfo::from_pem(&public_key_pem)
        .with_context(|| format!("TLS certificate `{label}` public key failed to parse"))?;
    if existing.public_key_pem.as_deref() != Some(public_key_pem.as_str()) {
        stored.public_key_pem = Some(public_key_pem);
        stored.certificate_chain_pem = None;
        stored.serial_number = None;
        stored.issued_unix = None;
        stored.not_after_unix = None;
    }
    let prepared = validate_tls_cert_config(label, stored.clone())?;
    let stored = if prepared.certificate_chain_pem.is_some() {
        stored
    } else {
        issue_tls_certificate(&prepared, issuing, api_issuer)?
    };
    tx.update_object_at(
        &parent,
        TLS_CERTS_COLLECTION,
        label,
        &stored,
        None,
        Some(FirestoreWritePrecondition::Exists(true)),
        vec![],
    )?;
    tx.commit().await?;
    validate_tls_cert_config(label, stored).map(Some)
}

#[cfg(test)]
fn generate_open_ssh_private_key_pem() -> anyhow::Result<String> {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
    Ok(key.to_openssh(LineEnding::LF)?.to_string())
}

#[cfg(test)]
fn tls_root_ca_params(dns_suffix: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = tls_ca_distinguished_name(TLS_ROOT_CA_COMMON_NAME);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.name_constraints = Some(tls_name_constraints(dns_suffix));
    params
}

#[cfg(test)]
fn tls_issuing_ca_params(dns_suffix: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = tls_ca_distinguished_name(TLS_SIGNING_CA_COMMON_NAME);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.name_constraints = Some(tls_name_constraints(dns_suffix));
    params.use_authority_key_identifier_extension = true;
    params
}

#[cfg(test)]
fn tls_ca_distinguished_name(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::OrganizationName, TLS_CA_ORGANIZATION);
    name.push(DnType::CommonName, common_name);
    name
}

fn tls_leaf_params(dns_names: &[String], api_issuer: &str) -> anyhow::Result<CertificateParams> {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, dns_names[0].as_str());
    let mut params = CertificateParams::new(dns_names.to_vec())?;
    let issued = TlsDateTime::now_utc();
    params.distinguished_name = name;
    params.not_before = issued - TlsDuration::minutes(5);
    params.not_after = issued + TlsDuration::days(TLS_VALIDITY_DAYS);
    params.is_ca = IsCa::ExplicitNoCa;
    params.use_authority_key_identifier_extension = true;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.crl_distribution_points = vec![CrlDistributionPoint {
        uris: vec![format!(
            "{}/aegis/tls/cas/issuing.crl",
            api_issuer.trim_end_matches('/')
        )],
    }];
    Ok(params)
}

#[cfg(test)]
fn tls_name_constraints(dns_suffix: &str) -> NameConstraints {
    NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DnsName(format!(".{dns_suffix}"))],
        excluded_subtrees: Vec::new(),
    }
}

fn serial_number_for(label: &str, unix: i64) -> SerialNumber {
    let digest = Sha256::digest(format!("{label}:{unix}").as_bytes());
    let mut bytes = digest[..16].to_vec();
    bytes[0] &= 0x7f;
    SerialNumber::from(bytes)
}

#[cfg(test)]
fn empty_tls_crl_pem(issuing: &TlsCaConfig, api_issuer: &str) -> anyhow::Result<String> {
    let key = KeyPair::from_pem(&issuing.private_key_pem)
        .context("aegis.tls.cas.issuing.private_key_pem failed to parse")?;
    let now = TlsDateTime::now_utc();
    let issuer = Issuer::from_ca_cert_pem(&issuing.certificate_pem, key)
        .context("aegis.tls.cas.issuing.certificate_pem failed to parse")?;
    Ok(CertificateRevocationListParams {
        this_update: now - TlsDuration::minutes(5),
        next_update: now + TlsDuration::days(TLS_VALIDITY_DAYS),
        crl_number: SerialNumber::from(TLS_CRL_NUMBER),
        issuing_distribution_point: None,
        revoked_certs: Vec::new(),
        key_identifier_method: rcgen::KeyIdMethod::PreSpecified(tls_ca_subject_key_identifier(
            &issuing.certificate_pem,
        )?),
    }
    .signed_by(&issuer)
    .with_context(|| {
        format!(
            "failed to sign TLS CRL for {}",
            api_issuer.trim_end_matches('/')
        )
    })?
    .pem()?)
}

#[cfg(test)]
fn tls_ca_subject_key_identifier(certificate_pem: &str) -> anyhow::Result<Vec<u8>> {
    let (_, pem) = parse_x509_pem(certificate_pem.as_bytes())
        .map_err(|_| anyhow::anyhow!("TLS CA certificate is not valid PEM"))?;
    let certificate = pem
        .parse_x509()
        .context("TLS CA certificate failed to parse")?;
    let extension = certificate
        .get_extension_unique(&OID_X509_EXT_SUBJECT_KEY_IDENTIFIER)
        .context("TLS CA certificate repeats its subject key identifier")?
        .ok_or_else(|| anyhow::anyhow!("TLS CA certificate has no subject key identifier"))?;
    match extension.parsed_extension() {
        ParsedExtension::SubjectKeyIdentifier(identifier) if !identifier.0.is_empty() => {
            Ok(identifier.0.to_vec())
        }
        _ => anyhow::bail!("TLS CA certificate has an invalid subject key identifier"),
    }
}

fn issue_tls_certificate(
    cert: &TlsCertRecord,
    issuing: &TlsCaConfig,
    api_issuer: &str,
) -> anyhow::Result<StoredTlsCertConfig> {
    let suffix = tls_dns_constraint(issuing)?;
    for name in &cert.dns_names {
        anyhow::ensure!(
            name.ends_with(&format!(".{suffix}")),
            "TLS DNS name {name} must be below {suffix}"
        );
    }
    let key = KeyPair::from_pem(&issuing.private_key_pem)
        .context("aegis.tls.cas.issuing.private_key_pem failed to parse")?;
    let public_key_pem = cert
        .public_key_pem
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("TLS cert {} has no submitted public key", cert.label))?;
    let public_key = SubjectPublicKeyInfo::from_pem(public_key_pem)
        .with_context(|| format!("TLS cert {} public key failed to parse", cert.label))?;
    let mut params = tls_leaf_params(&cert.dns_names, api_issuer)?;
    let issued = TlsDateTime::now_utc();
    let serial_number = serial_number_for(&cert.label, issued.unix_timestamp());
    params.serial_number = Some(serial_number.clone());
    let issuer = Issuer::from_ca_cert_pem(&issuing.certificate_pem, key)
        .context("aegis.tls.cas.issuing.certificate_pem failed to parse")?;
    let certificate_pem = params.signed_by(&public_key, &issuer)?.pem();
    Ok(StoredTlsCertConfig {
        dns_names: Some(cert.dns_names.clone()),
        host_id: Some(cert.host_id),
        public_key_pem: Some(public_key_pem.clone()),
        certificate_chain_pem: Some(format!("{certificate_pem}{}", issuing.certificate_pem)),
        serial_number: Some(serial_number.to_string()),
        issued_unix: Some(issued.unix_timestamp()),
        not_after_unix: Some(params.not_after.unix_timestamp()),
    })
}

fn aegis_parent(db: &AegisDb) -> anyhow::Result<String> {
    Ok(db.parent.clone())
}

fn aegis_network_parent(db: &AegisDb, network: &str) -> anyhow::Result<String> {
    Ok(format!(
        "{}/{}/{}",
        aegis_parent(db)?,
        AEGIS_NETWORKS_COLLECTION,
        network
    ))
}

fn aegis_ssh_parent(db: &AegisDb) -> anyhow::Result<String> {
    Ok(format!(
        "{}/{}/{}",
        aegis_parent(db)?,
        AEGIS_SSH_COLLECTION,
        AEGIS_SSH_DOC
    ))
}

fn aegis_tls_parent(db: &AegisDb) -> anyhow::Result<String> {
    Ok(format!(
        "{}/{}/{}",
        aegis_parent(db)?,
        AEGIS_TLS_COLLECTION,
        AEGIS_TLS_DOC
    ))
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAegisNetworkMemberWireguard {
    pub public_key: String,
    pub ipv4: String,
    pub ipv6: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAegisHostSsh {
    #[serde(
        default = "default_aegis_host_port",
        skip_serializing_if = "Option::is_none"
    )]
    port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    external_principals: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAegisDirectWireGuard {
    public_key: String,
    ipv4: String,
    ipv6: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    endpoints: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAegisDirectGateway {
    wireguard: StoredAegisDirectWireGuard,
    created_unix: i64,
    updated_unix: i64,
    updated_by_principal: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAegisSatellite {
    credential_id: String,
    owner_principal: String,
    wireguard: StoredAegisDirectWireGuard,
    ssh_public_key: String,
    created_unix: i64,
    created_by_principal: String,
    broker_uses: BTreeMap<HostId, AegisSatelliteBrokerUseRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAegisDirectLease {
    wireguard: StoredAegisDirectWireGuard,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAegisNetworkMemberInternal {
    pub ipv4: String,
    pub ipv6: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAegisHostRecordEgress {
    pub public_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAegisHostRecordUpdated {
    pub unix: i64,
    pub by_principal: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAegisHostReport {
    #[serde(default)]
    pub messages: Vec<AegisHostMessage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<AegisAgentStatus>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub principal_grants: Vec<AegisPrincipalGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_lockdown_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_gateway: Option<StoredAegisDirectGatewayReport>,
    #[serde(default, skip_serializing_if = "AegisObservedPublicIps::is_empty")]
    pub observed_public_ips: AegisObservedPublicIps,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAegisDirectPeerObservation {
    public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    latest_handshake_unix: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAegisDirectGatewayReport {
    observed_unix: i64,
    peers: Vec<StoredAegisDirectPeerObservation>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAegisHostRecord {
    pub aliases: HostAliases,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<StoredAegisHostSsh>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<StoredAegisHostRecordEgress>,
    #[serde(default)]
    pub report: StoredAegisHostReport,
    #[serde(default)]
    pub transient: bool,
    #[serde(default)]
    pub pending: bool,
    pub created_unix: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<StoredAegisHostRecordUpdated>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAegisEnrollment {
    aliases: HostAliases,
    network: String,
    mode: AegisHostMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ssh: Option<AegisEnrollmentSsh>,
    #[serde(default)]
    transient: bool,
    initial_oauth_principal: String,
    phase: AegisEnrollmentPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential_session_id: Option<String>,
    created_unix: i64,
    expires_unix: i64,
    updated_unix: i64,
    created_by_principal: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAegisNetworkMemberRecord {
    pub mode: AegisHostMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wireguard: Option<StoredAegisNetworkMemberWireguard>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub internal: Option<StoredAegisNetworkMemberInternal>,
    #[serde(default)]
    pub pending: bool,
    pub created_unix: i64,
    pub updated: StoredAegisHostRecordUpdated,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAegisEgressState {
    generation: u64,
    policies: BTreeMap<HostId, aegis_types::v1::AegisEgressPolicy>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAegisAliasClaim {
    host_id: HostId,
}

impl From<FirestoreError> for AegisHostDeleteError {
    fn from(error: FirestoreError) -> Self {
        Self::Internal(anyhow::Error::from(error))
    }
}

impl From<FirestoreError> for AegisEnrollmentWriteError {
    fn from(error: FirestoreError) -> Self {
        Self::Internal(anyhow::Error::from(error))
    }
}

fn default_aegis_host_port() -> Option<u16> {
    Some(22)
}

fn stored_direct_gateway_report(
    report: &aegis_types::v1::AegisDirectGatewayReport,
) -> StoredAegisDirectGatewayReport {
    StoredAegisDirectGatewayReport {
        observed_unix: report.observed_unix,
        peers: report
            .peers
            .iter()
            .map(|peer| StoredAegisDirectPeerObservation {
                public_key: peer.public_key.clone(),
                latest_handshake_unix: peer.latest_handshake_unix,
            })
            .collect(),
    }
}

fn domain_direct_gateway_report(
    report: StoredAegisDirectGatewayReport,
) -> aegis_types::v1::AegisDirectGatewayReport {
    aegis_types::v1::AegisDirectGatewayReport {
        observed_unix: report.observed_unix,
        peers: report
            .peers
            .into_iter()
            .map(|peer| aegis_types::v1::AegisDirectPeerObservation {
                public_key: peer.public_key,
                latest_handshake_unix: peer.latest_handshake_unix,
            })
            .collect(),
    }
}

fn stored_aegis_host_record_from_domain(host: &AegisHostRecord) -> StoredAegisHostRecord {
    StoredAegisHostRecord {
        aliases: host.aliases.clone(),
        ssh: host.ssh.as_ref().map(|ssh| StoredAegisHostSsh {
            port: ssh.port,
            public_key: ssh.public_key.clone(),
            external_principals: ssh.external_principals.clone(),
        }),
        egress: host
            .egress_public_key
            .as_ref()
            .map(|public_key| StoredAegisHostRecordEgress {
                public_key: public_key.clone(),
            }),
        report: StoredAegisHostReport {
            messages: host.messages.clone(),
            agent: host.agent.clone(),
            principal_grants: host.principal_grants.clone(),
            ssh_lockdown_enabled: host.ssh_lockdown_enabled,
            direct_gateway: host
                .direct_gateway_report
                .as_ref()
                .map(stored_direct_gateway_report),
            observed_public_ips: host.observed_public_ips.clone(),
        },
        transient: host.transient,
        pending: host.pending,
        created_unix: host.created_unix,
        updated: Some(StoredAegisHostRecordUpdated {
            unix: host.updated_unix,
            by_principal: host.updated_by_principal.clone(),
        }),
    }
}

fn domain_aegis_host_record_from_stored(
    host_id: HostId,
    stored: StoredAegisHostRecord,
) -> anyhow::Result<AegisHostRecord> {
    let updated = stored
        .updated
        .ok_or_else(|| anyhow::anyhow!("host `{host_id}` is missing updated"))?;
    Ok(AegisHostRecord {
        host_id,
        aliases: stored.aliases,
        ssh: stored.ssh.map(|ssh| AegisHostRecordSsh {
            port: ssh.port,
            public_key: ssh.public_key,
            external_principals: ssh.external_principals,
        }),
        egress_public_key: stored.egress.map(|egress| egress.public_key),
        messages: stored.report.messages,
        agent: stored.report.agent,
        principal_grants: stored.report.principal_grants,
        ssh_lockdown_enabled: stored.report.ssh_lockdown_enabled,
        direct_gateway_report: stored
            .report
            .direct_gateway
            .map(domain_direct_gateway_report),
        observed_public_ips: stored.report.observed_public_ips,
        transient: stored.transient,
        pending: stored.pending,
        created_unix: stored.created_unix,
        updated_unix: updated.unix,
        updated_by_principal: updated.by_principal,
    })
}

fn stored_aegis_enrollment(enrollment: &AegisEnrollmentRecord) -> StoredAegisEnrollment {
    StoredAegisEnrollment {
        aliases: enrollment.aliases.clone(),
        network: enrollment.network.clone(),
        mode: enrollment.mode,
        ssh: enrollment.ssh.clone(),
        transient: enrollment.transient,
        initial_oauth_principal: enrollment.initial_oauth_principal.clone(),
        phase: enrollment.phase,
        credential_session_id: enrollment.credential_session_id.clone(),
        created_unix: enrollment.created_unix,
        expires_unix: enrollment.expires_unix,
        updated_unix: enrollment.updated_unix,
        created_by_principal: enrollment.created_by_principal.clone(),
    }
}

fn domain_aegis_enrollment(
    host_id: HostId,
    stored: StoredAegisEnrollment,
) -> AegisEnrollmentRecord {
    AegisEnrollmentRecord {
        host_id,
        aliases: stored.aliases,
        network: stored.network,
        mode: stored.mode,
        ssh: stored.ssh,
        transient: stored.transient,
        initial_oauth_principal: stored.initial_oauth_principal,
        phase: stored.phase,
        credential_session_id: stored.credential_session_id,
        created_unix: stored.created_unix,
        expires_unix: stored.expires_unix,
        updated_unix: stored.updated_unix,
        created_by_principal: stored.created_by_principal,
    }
}

fn stored_aegis_network_member_from_domain(
    member: &AegisNetworkMemberRecord,
) -> StoredAegisNetworkMemberRecord {
    StoredAegisNetworkMemberRecord {
        mode: member.mode,
        wireguard: match (
            member.wireguard_public_key.as_ref(),
            member.wireguard_ipv4.as_ref(),
            member.wireguard_ipv6.as_ref(),
        ) {
            (Some(public_key), Some(ipv4), Some(ipv6)) => Some(StoredAegisNetworkMemberWireguard {
                public_key: public_key.clone(),
                ipv4: ipv4.clone(),
                ipv6: ipv6.clone(),
                endpoints: member.wireguard_endpoints.clone(),
            }),
            (None, None, None) => None,
            _ => None,
        },
        internal: match (member.internal_ipv4.as_ref(), member.internal_ipv6.as_ref()) {
            (Some(ipv4), Some(ipv6)) => Some(StoredAegisNetworkMemberInternal {
                ipv4: ipv4.clone(),
                ipv6: ipv6.clone(),
            }),
            (None, None) => None,
            _ => None,
        },
        pending: member.pending,
        created_unix: member.created_unix,
        updated: StoredAegisHostRecordUpdated {
            unix: member.updated_unix,
            by_principal: member.updated_by_principal.clone(),
        },
    }
}

fn domain_aegis_network_member_from_stored(
    host_id: HostId,
    stored: StoredAegisNetworkMemberRecord,
) -> AegisNetworkMemberRecord {
    let (wireguard_public_key, wireguard_ipv4, wireguard_ipv6, wireguard_endpoints) =
        match stored.wireguard {
            Some(wireguard) => (
                Some(wireguard.public_key),
                Some(wireguard.ipv4),
                Some(wireguard.ipv6),
                wireguard.endpoints,
            ),
            None => (None, None, None, Vec::new()),
        };
    let (internal_ipv4, internal_ipv6) = match stored.internal {
        Some(internal) => (Some(internal.ipv4), Some(internal.ipv6)),
        None => (None, None),
    };
    AegisNetworkMemberRecord {
        host_id,
        mode: stored.mode,
        wireguard_public_key,
        wireguard_ipv4,
        wireguard_ipv6,
        wireguard_endpoints,
        internal_ipv4,
        internal_ipv6,
        pending: stored.pending,
        created_unix: stored.created_unix,
        updated_unix: stored.updated.unix,
        updated_by_principal: stored.updated.by_principal,
    }
}

fn stored_direct_wireguard(wireguard: &AegisDirectWireGuardRecord) -> StoredAegisDirectWireGuard {
    StoredAegisDirectWireGuard {
        public_key: wireguard.public_key.clone(),
        ipv4: wireguard.ipv4.clone(),
        ipv6: wireguard.ipv6.clone(),
        endpoints: wireguard.endpoints.clone(),
    }
}

fn domain_direct_wireguard(wireguard: StoredAegisDirectWireGuard) -> AegisDirectWireGuardRecord {
    AegisDirectWireGuardRecord {
        public_key: wireguard.public_key,
        ipv4: wireguard.ipv4,
        ipv6: wireguard.ipv6,
        endpoints: wireguard.endpoints,
    }
}

fn stored_direct_gateway(hub: &AegisDirectGatewayRecord) -> StoredAegisDirectGateway {
    StoredAegisDirectGateway {
        wireguard: stored_direct_wireguard(&hub.wireguard),
        created_unix: hub.created_unix,
        updated_unix: hub.updated_unix,
        updated_by_principal: hub.updated_by_principal.clone(),
    }
}

fn domain_direct_gateway(
    host_id: HostId,
    hub: StoredAegisDirectGateway,
) -> AegisDirectGatewayRecord {
    AegisDirectGatewayRecord {
        host_id,
        wireguard: domain_direct_wireguard(hub.wireguard),
        created_unix: hub.created_unix,
        updated_unix: hub.updated_unix,
        updated_by_principal: hub.updated_by_principal,
    }
}

fn stored_satellite(satellite: &AegisSatelliteRecord) -> StoredAegisSatellite {
    StoredAegisSatellite {
        credential_id: satellite.credential_id.clone(),
        owner_principal: satellite.owner_principal.clone(),
        wireguard: stored_direct_wireguard(&satellite.wireguard),
        ssh_public_key: satellite.ssh_public_key.clone(),
        created_unix: satellite.created_unix,
        created_by_principal: satellite.created_by_principal.clone(),
        broker_uses: satellite.broker_uses.clone(),
    }
}

fn domain_satellite(slug: &str, satellite: StoredAegisSatellite) -> AegisSatelliteRecord {
    AegisSatelliteRecord {
        slug: slug.to_string(),
        credential_id: satellite.credential_id,
        owner_principal: satellite.owner_principal,
        wireguard: domain_direct_wireguard(satellite.wireguard),
        ssh_public_key: satellite.ssh_public_key,
        created_unix: satellite.created_unix,
        created_by_principal: satellite.created_by_principal,
        broker_uses: satellite.broker_uses,
    }
}

fn stored_direct_lease(lease: &AegisDirectLeaseRecord) -> StoredAegisDirectLease {
    StoredAegisDirectLease {
        wireguard: stored_direct_wireguard(&lease.wireguard),
    }
}

fn domain_direct_lease(id: &str, lease: StoredAegisDirectLease) -> AegisDirectLeaseRecord {
    AegisDirectLeaseRecord {
        id: id.to_string(),
        wireguard: domain_direct_wireguard(lease.wireguard),
    }
}

async fn fetch_aegis_egress_state(
    db: &AegisDb,
    parent: &str,
) -> anyhow::Result<StoredAegisEgressState> {
    let state = get_stored_obj_at_if_exists::<StoredAegisEgressState>(
        db.inner(),
        parent,
        AEGIS_STATE_COLLECTION,
        AEGIS_EGRESS_STATE_DOCUMENT,
    )
    .await?
    .unwrap_or_default();
    validate_stored_aegis_egress_state(&state)?;
    Ok(state)
}

fn validate_stored_aegis_egress_state(state: &StoredAegisEgressState) -> anyhow::Result<()> {
    for (source_host_id, policy) in &state.policies {
        anyhow::ensure!(
            source_host_id == &policy.source_host_id,
            "egress policy key `{source_host_id}` does not match source `{}`",
            policy.source_host_id
        );
    }
    Ok(())
}

async fn stage_aegis_egress_generation_increment(
    tx_db: &FirestoreDb,
    tx: &mut FirestoreTransaction<'_>,
    parent: &str,
) -> anyhow::Result<()> {
    let stored = get_stored_obj_at_if_exists::<StoredAegisEgressState>(
        tx_db,
        parent,
        AEGIS_STATE_COLLECTION,
        AEGIS_EGRESS_STATE_DOCUMENT,
    )
    .await?;
    let state_exists = stored.is_some();
    let mut state = stored.unwrap_or_default();
    validate_stored_aegis_egress_state(&state)?;
    state.generation = state
        .generation
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("egress topology generation is exhausted"))?;
    tx.update_object_at(
        parent,
        AEGIS_STATE_COLLECTION,
        AEGIS_EGRESS_STATE_DOCUMENT,
        &state,
        None,
        Some(FirestoreWritePrecondition::Exists(state_exists)),
        vec![],
    )?;
    Ok(())
}

enum HostAliasMutation {
    Add(HostAlias),
    Promote(HostAlias),
    Remove(HostAlias),
}

fn map_enrollment_firestore_error(error: anyhow::Error) -> AegisEnrollmentWriteError {
    if is_firestore_data_conflict(&error) {
        AegisEnrollmentWriteError::ConcurrentWrite
    } else {
        AegisEnrollmentWriteError::Internal(error)
    }
}

async fn update_host_aliases(
    db: &AegisDb,
    host_id: &HostId,
    mutation: HostAliasMutation,
    updated_by_principal: &str,
    updated_unix: i64,
) -> Result<AegisHostRecord, AegisAliasWriteError> {
    let parent = aegis_parent(db).map_err(AegisAliasWriteError::Internal)?;
    let host_document_id = host_id.to_string();
    let mut tx = db
        .begin_write_transaction()
        .await
        .map_err(AegisAliasWriteError::Internal)?;
    let tx_db =
        db.inner()
            .clone_with_consistency_selector(FirestoreConsistencySelector::Transaction(
                tx.transaction_id().clone(),
            ));
    let Some(mut stored) = get_stored_obj_at_if_exists::<StoredAegisHostRecord>(
        &tx_db,
        &parent,
        AEGIS_HOSTS_COLLECTION,
        &host_document_id,
    )
    .await
    .map_err(anyhow::Error::from)
    .map_err(AegisAliasWriteError::Internal)?
    else {
        tx.rollback().await.ok();
        return Err(AegisAliasWriteError::HostNotFound { host_id: *host_id });
    };
    if stored.pending {
        tx.rollback().await.ok();
        return Err(AegisAliasWriteError::EnrollmentPending { host_id: *host_id });
    }

    let (alias, next_aliases, claim_write) = match mutation {
        HostAliasMutation::Add(alias) => {
            if stored.aliases.contains(&alias) {
                tx.rollback().await.ok();
                return domain_aegis_host_record_from_stored(*host_id, stored)
                    .map_err(AegisAliasWriteError::Internal);
            }
            let claim = get_stored_obj_at_if_exists::<StoredAegisAliasClaim>(
                &tx_db,
                &parent,
                AEGIS_ALIASES_COLLECTION,
                alias.as_str(),
            )
            .await
            .map_err(anyhow::Error::from)
            .map_err(AegisAliasWriteError::Internal)?;
            if let Some(claim) = claim {
                tx.rollback().await.ok();
                return Err(AegisAliasWriteError::AlreadyAssigned {
                    alias,
                    host_id: claim.host_id,
                });
            }
            if get_stored_obj_at_if_exists::<StoredAegisSatellite>(
                &tx_db,
                &parent,
                AEGIS_SATELLITES_COLLECTION,
                alias.as_str(),
            )
            .await
            .map_err(anyhow::Error::from)
            .map_err(AegisAliasWriteError::Internal)?
            .is_some()
            {
                tx.rollback().await.ok();
                return Err(AegisAliasWriteError::AssignedToSatellite { alias });
            }
            let aliases = stored.aliases.added(alias.clone())?;
            (alias, aliases, Some(true))
        }
        HostAliasMutation::Promote(alias) => {
            let Some(aliases) = stored.aliases.promoted(&alias) else {
                tx.rollback().await.ok();
                return Err(AegisAliasWriteError::AliasNotFound {
                    host_id: *host_id,
                    alias,
                });
            };
            if aliases == stored.aliases {
                tx.rollback().await.ok();
                return domain_aegis_host_record_from_stored(*host_id, stored)
                    .map_err(AegisAliasWriteError::Internal);
            }
            (alias, aliases, None)
        }
        HostAliasMutation::Remove(alias) => {
            let aliases = match stored.aliases.removed(&alias)? {
                Some(aliases) => aliases,
                None => {
                    tx.rollback().await.ok();
                    return Err(AegisAliasWriteError::AliasNotFound {
                        host_id: *host_id,
                        alias,
                    });
                }
            };
            let claim = get_stored_obj_at_if_exists::<StoredAegisAliasClaim>(
                &tx_db,
                &parent,
                AEGIS_ALIASES_COLLECTION,
                alias.as_str(),
            )
            .await
            .map_err(anyhow::Error::from)
            .map_err(AegisAliasWriteError::Internal)?;
            if claim.as_ref().map(|claim| claim.host_id) != Some(*host_id) {
                tx.rollback().await.ok();
                return Err(AegisAliasWriteError::Internal(anyhow::anyhow!(
                    "alias `{alias}` is not claimed by host `{host_id}`"
                )));
            }
            (alias, aliases, Some(false))
        }
    };

    stored.aliases = next_aliases;
    stored.updated = Some(StoredAegisHostRecordUpdated {
        unix: updated_unix,
        by_principal: updated_by_principal.to_string(),
    });
    tx.update_object_at(
        &parent,
        AEGIS_HOSTS_COLLECTION,
        &host_document_id,
        &stored,
        None,
        Some(FirestoreWritePrecondition::Exists(true)),
        vec![],
    )
    .map_err(anyhow::Error::from)
    .map_err(AegisAliasWriteError::Internal)?;
    match claim_write {
        Some(true) => {
            tx.update_object_at(
                &parent,
                AEGIS_ALIASES_COLLECTION,
                alias.as_str(),
                &StoredAegisAliasClaim { host_id: *host_id },
                None,
                Some(FirestoreWritePrecondition::Exists(false)),
                vec![],
            )
            .map_err(anyhow::Error::from)
            .map_err(AegisAliasWriteError::Internal)?;
        }
        Some(false) => {
            tx.delete_by_id_at(
                &parent,
                AEGIS_ALIASES_COLLECTION,
                alias.as_str(),
                Some(FirestoreWritePrecondition::Exists(true)),
            )
            .map_err(anyhow::Error::from)
            .map_err(AegisAliasWriteError::Internal)?;
        }
        None => {}
    }
    tx.commit()
        .await
        .map_err(anyhow::Error::from)
        .map_err(|error| {
            if is_firestore_data_conflict(&error) {
                AegisAliasWriteError::ConcurrentWrite
            } else {
                AegisAliasWriteError::Internal(error)
            }
        })?;
    domain_aegis_host_record_from_stored(*host_id, stored).map_err(AegisAliasWriteError::Internal)
}

#[async_trait::async_trait]
impl AegisStore for AegisDb {
    async fn fetch_aegis_user_by_id(
        &self,
        user_id: &str,
    ) -> anyhow::Result<Option<AegisUserIdentity>> {
        let Some(user) = crate::identity::store(&self.db)?.user(user_id).await? else {
            return Ok(None);
        };
        let Some(member) = get_stored_obj_at_if_exists::<aegis_types::NamespaceMembership>(
            self.inner(),
            &self.parent,
            "members",
            user_id,
        )
        .await?
        else {
            return Ok(None);
        };
        let admin = member.role == aegis_types::NamespaceRole::Admin;
        Ok(Some(AegisUserIdentity {
            user_id: user.id,
            disabled: user.disabled,
            admin,
        }))
    }

    async fn list_aegis_enrollments(&self) -> anyhow::Result<Vec<AegisEnrollmentRecord>> {
        let parent = aegis_parent(self)?;
        let docs = self
            .inner()
            .fluent()
            .select()
            .from(AEGIS_ENROLLMENTS_COLLECTION)
            .parent(&parent)
            .query()
            .await?;
        let mut enrollments = docs
            .into_iter()
            .map(|doc| {
                let host_id = host_id_from_document_name(&doc.name)?;
                let stored = deserialize_stored_document::<StoredAegisEnrollment>(&doc)?;
                Ok(domain_aegis_enrollment(host_id, stored))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        enrollments.sort_by_key(|enrollment| enrollment.host_id);
        Ok(enrollments)
    }

    async fn fetch_aegis_enrollment(
        &self,
        host_id: &HostId,
    ) -> anyhow::Result<Option<AegisEnrollmentRecord>> {
        let stored = get_stored_obj_at_if_exists::<StoredAegisEnrollment>(
            self.inner(),
            &aegis_parent(self)?,
            AEGIS_ENROLLMENTS_COLLECTION,
            &host_id.to_string(),
        )
        .await?;
        Ok(stored.map(|stored| domain_aegis_enrollment(*host_id, stored)))
    }

    async fn create_aegis_enrollment(
        &self,
        enrollment: &AegisEnrollmentRecord,
    ) -> Result<AegisEnrollmentRecord, AegisEnrollmentWriteError> {
        if enrollment.expires_unix <= enrollment.created_unix {
            return Err(AegisEnrollmentWriteError::Internal(anyhow::anyhow!(
                "enrollment expiry must be after creation"
            )));
        }
        if enrollment.credential_session_id.is_some() {
            return Err(AegisEnrollmentWriteError::Internal(anyhow::anyhow!(
                "new enrollment must not already have a credential"
            )));
        }
        let parent = aegis_parent(self)?;
        let document_id = enrollment.host_id.to_string();
        let mut tx = self.begin_write_transaction().await?;
        let tx_db = self.inner().clone_with_consistency_selector(
            FirestoreConsistencySelector::Transaction(tx.transaction_id().clone()),
        );
        if get_stored_obj_at_if_exists::<StoredAegisHostRecord>(
            &tx_db,
            &parent,
            AEGIS_HOSTS_COLLECTION,
            &document_id,
        )
        .await?
        .is_some()
        {
            tx.rollback().await.ok();
            return Err(AegisEnrollmentWriteError::HostAlreadyExists {
                host_id: enrollment.host_id,
            });
        }
        if get_stored_obj_at_if_exists::<StoredAegisEnrollment>(
            &tx_db,
            &parent,
            AEGIS_ENROLLMENTS_COLLECTION,
            &document_id,
        )
        .await?
        .is_some()
        {
            tx.rollback().await.ok();
            return Err(AegisEnrollmentWriteError::AlreadyExists {
                host_id: enrollment.host_id,
            });
        }
        for alias in &enrollment.aliases {
            if let Some(claim) = get_stored_obj_at_if_exists::<StoredAegisAliasClaim>(
                &tx_db,
                &parent,
                AEGIS_ALIASES_COLLECTION,
                alias.as_str(),
            )
            .await?
            {
                tx.rollback().await.ok();
                return Err(AegisEnrollmentWriteError::AliasAlreadyAssigned {
                    alias: alias.clone(),
                    host_id: claim.host_id,
                });
            }
            if get_stored_obj_at_if_exists::<StoredAegisSatellite>(
                &tx_db,
                &parent,
                AEGIS_SATELLITES_COLLECTION,
                alias.as_str(),
            )
            .await?
            .is_some()
            {
                tx.rollback().await.ok();
                return Err(AegisEnrollmentWriteError::AliasAssignedToSatellite {
                    alias: alias.clone(),
                });
            }
        }
        tx.update_object_at(
            &parent,
            AEGIS_ENROLLMENTS_COLLECTION,
            &document_id,
            &stored_aegis_enrollment(enrollment),
            None,
            Some(FirestoreWritePrecondition::Exists(false)),
            vec![],
        )?;
        for alias in &enrollment.aliases {
            tx.update_object_at(
                &parent,
                AEGIS_ALIASES_COLLECTION,
                alias.as_str(),
                &StoredAegisAliasClaim {
                    host_id: enrollment.host_id,
                },
                None,
                Some(FirestoreWritePrecondition::Exists(false)),
                vec![],
            )?;
        }
        tx.commit()
            .await
            .map_err(anyhow::Error::from)
            .map_err(map_enrollment_firestore_error)?;
        Ok(enrollment.clone())
    }

    async fn replace_aegis_enrollment_credential(
        &self,
        host_id: &HostId,
        expected_session_id: Option<&str>,
        next_session_id: &str,
        updated_unix: i64,
    ) -> Result<AegisEnrollmentRecord, AegisEnrollmentWriteError> {
        if next_session_id.trim().is_empty() {
            return Err(AegisEnrollmentWriteError::Internal(anyhow::anyhow!(
                "enrollment credential session id must not be empty"
            )));
        }
        let parent = aegis_parent(self)?;
        let document_id = host_id.to_string();
        let mut tx = self.begin_write_transaction().await?;
        let tx_db = self.inner().clone_with_consistency_selector(
            FirestoreConsistencySelector::Transaction(tx.transaction_id().clone()),
        );
        let Some(stored) = get_stored_obj_at_if_exists::<StoredAegisEnrollment>(
            &tx_db,
            &parent,
            AEGIS_ENROLLMENTS_COLLECTION,
            &document_id,
        )
        .await?
        else {
            tx.rollback().await.ok();
            return Err(AegisEnrollmentWriteError::NotFound { host_id: *host_id });
        };
        let mut enrollment = domain_aegis_enrollment(*host_id, stored);
        if updated_unix >= enrollment.expires_unix {
            tx.rollback().await.ok();
            return Err(AegisEnrollmentWriteError::Expired {
                host_id: *host_id,
                expires_unix: enrollment.expires_unix,
            });
        }
        if enrollment.credential_session_id.as_deref() != expected_session_id {
            tx.rollback().await.ok();
            return Err(AegisEnrollmentWriteError::CredentialMismatch { host_id: *host_id });
        }
        enrollment.credential_session_id = Some(next_session_id.to_string());
        enrollment.updated_unix = updated_unix;
        tx.update_object_at(
            &parent,
            AEGIS_ENROLLMENTS_COLLECTION,
            &document_id,
            &stored_aegis_enrollment(&enrollment),
            None,
            Some(FirestoreWritePrecondition::Exists(true)),
            vec![],
        )?;
        tx.commit()
            .await
            .map_err(anyhow::Error::from)
            .map_err(map_enrollment_firestore_error)?;
        Ok(enrollment)
    }

    async fn update_aegis_enrollment_phase(
        &self,
        host_id: &HostId,
        credential_session_id: &str,
        phase: AegisEnrollmentPhase,
        updated_unix: i64,
    ) -> Result<AegisEnrollmentRecord, AegisEnrollmentWriteError> {
        let parent = aegis_parent(self)?;
        let document_id = host_id.to_string();
        let mut tx = self.begin_write_transaction().await?;
        let tx_db = self.inner().clone_with_consistency_selector(
            FirestoreConsistencySelector::Transaction(tx.transaction_id().clone()),
        );
        let Some(stored) = get_stored_obj_at_if_exists::<StoredAegisEnrollment>(
            &tx_db,
            &parent,
            AEGIS_ENROLLMENTS_COLLECTION,
            &document_id,
        )
        .await?
        else {
            tx.rollback().await.ok();
            return Err(AegisEnrollmentWriteError::NotFound { host_id: *host_id });
        };
        let mut enrollment = domain_aegis_enrollment(*host_id, stored);
        validate_current_enrollment(&enrollment, credential_session_id, updated_unix)?;
        if enrollment_phase_rank(phase) > enrollment_phase_rank(enrollment.phase) {
            enrollment.phase = phase;
        }
        enrollment.updated_unix = updated_unix;
        tx.update_object_at(
            &parent,
            AEGIS_ENROLLMENTS_COLLECTION,
            &document_id,
            &stored_aegis_enrollment(&enrollment),
            None,
            Some(FirestoreWritePrecondition::Exists(true)),
            vec![],
        )?;
        tx.commit()
            .await
            .map_err(anyhow::Error::from)
            .map_err(map_enrollment_firestore_error)?;
        Ok(enrollment)
    }

    async fn prepare_aegis_enrollment(
        &self,
        host_id: &HostId,
        credential_session_id: &str,
        preparation: AegisEnrollmentPreparation<'_>,
    ) -> Result<AegisEnrollmentPrepared, AegisEnrollmentWriteError> {
        let AegisEnrollmentPreparation {
            host_public_key,
            wireguard_public_key,
            wireguard_endpoints,
            network,
            updated_unix,
        } = preparation;
        let service_parent = aegis_parent(self)?;
        let document_id = host_id.to_string();
        let mut tx = self.begin_write_transaction().await?;
        let tx_db = self.inner().clone_with_consistency_selector(
            FirestoreConsistencySelector::Transaction(tx.transaction_id().clone()),
        );
        let Some(stored) = get_stored_obj_at_if_exists::<StoredAegisEnrollment>(
            &tx_db,
            &service_parent,
            AEGIS_ENROLLMENTS_COLLECTION,
            &document_id,
        )
        .await?
        else {
            tx.rollback().await.ok();
            return Err(AegisEnrollmentWriteError::NotFound { host_id: *host_id });
        };
        let mut enrollment = domain_aegis_enrollment(*host_id, stored);
        validate_current_enrollment(&enrollment, credential_session_id, updated_unix)?;
        crate::aegis_store::validate_enrollment_host_public_key(&enrollment, host_public_key)?;
        let network_parent = aegis_network_parent(self, &enrollment.network)?;
        let existing_host = get_stored_obj_at_if_exists::<StoredAegisHostRecord>(
            &tx_db,
            &service_parent,
            AEGIS_HOSTS_COLLECTION,
            &document_id,
        )
        .await?
        .map(|stored| domain_aegis_host_record_from_stored(*host_id, stored))
        .transpose()?;
        let existing_member = get_stored_obj_at_if_exists::<StoredAegisNetworkMemberRecord>(
            &tx_db,
            &network_parent,
            AEGIS_NETWORK_MEMBERS_COLLECTION,
            &document_id,
        )
        .await?
        .map(|stored| domain_aegis_network_member_from_stored(*host_id, stored));

        if let (Some(host), Some(member)) = (existing_host.as_ref(), existing_member.as_ref()) {
            if !host.pending
                || !member.pending
                || !prepared_host_matches_enrollment(&enrollment, host, member)
                || host.ssh.as_ref().and_then(|ssh| ssh.public_key.as_deref()) != host_public_key
                || member.wireguard_public_key.as_deref() != Some(wireguard_public_key)
                || member.wireguard_endpoints != wireguard_endpoints
            {
                tx.rollback().await.ok();
                return Err(AegisEnrollmentWriteError::InconsistentPreparedHost {
                    host_id: *host_id,
                });
            }
            if enrollment_phase_rank(enrollment.phase)
                < enrollment_phase_rank(AegisEnrollmentPhase::Prepared)
            {
                enrollment.phase = AegisEnrollmentPhase::Prepared;
                enrollment.updated_unix = updated_unix;
                tx.update_object_at(
                    &service_parent,
                    AEGIS_ENROLLMENTS_COLLECTION,
                    &document_id,
                    &stored_aegis_enrollment(&enrollment),
                    None,
                    Some(FirestoreWritePrecondition::Exists(true)),
                    vec![],
                )?;
                tx.commit()
                    .await
                    .map_err(anyhow::Error::from)
                    .map_err(map_enrollment_firestore_error)?;
            } else {
                tx.rollback().await.ok();
            }
            return Ok(AegisEnrollmentPrepared {
                enrollment,
                host: host.clone(),
                member: member.clone(),
            });
        }
        if existing_host.is_some() || existing_member.is_some() {
            tx.rollback().await.ok();
            return Err(AegisEnrollmentWriteError::InconsistentPreparedHost { host_id: *host_id });
        }
        for alias in &enrollment.aliases {
            let claim = get_stored_obj_at_if_exists::<StoredAegisAliasClaim>(
                &tx_db,
                &service_parent,
                AEGIS_ALIASES_COLLECTION,
                alias.as_str(),
            )
            .await?;
            if claim.as_ref().map(|claim| claim.host_id) != Some(*host_id) {
                tx.rollback().await.ok();
                return Err(AegisEnrollmentWriteError::InconsistentPreparedHost {
                    host_id: *host_id,
                });
            }
        }
        let principal = format!("enrollment:{host_id}");
        let host = AegisHostRecord {
            host_id: *host_id,
            aliases: enrollment.aliases.clone(),
            ssh: enrollment.ssh.as_ref().map(|ssh| AegisHostRecordSsh {
                port: ssh.port,
                public_key: host_public_key.map(str::to_string),
                external_principals: ssh.external_principals.clone(),
            }),
            egress_public_key: None,
            messages: Vec::new(),
            agent: None,
            principal_grants: Vec::new(),
            ssh_lockdown_enabled: None,
            direct_gateway_report: None,
            observed_public_ips: Default::default(),
            transient: enrollment.transient,
            pending: true,
            created_unix: updated_unix,
            updated_unix,
            updated_by_principal: principal.clone(),
        };
        let peers = deserialize_aegis_network_member_documents(
            tx_db
                .fluent()
                .select()
                .from(AEGIS_NETWORK_MEMBERS_COLLECTION)
                .parent(&network_parent)
                .query()
                .await?,
        )?;
        let mut member = AegisNetworkMemberRecord {
            host_id: *host_id,
            mode: enrollment.mode,
            wireguard_public_key: Some(wireguard_public_key.to_string()),
            wireguard_ipv4: None,
            wireguard_ipv6: None,
            wireguard_endpoints: wireguard_endpoints.to_vec(),
            internal_ipv4: None,
            internal_ipv6: None,
            pending: true,
            created_unix: updated_unix,
            updated_unix,
            updated_by_principal: principal,
        };
        maybe_allocate_wireguard_identity(
            &mut member,
            None,
            &peers,
            &network.wireguard.address_pool(),
        )?;
        if let Some(mesh) = network.mesh.as_ref() {
            maybe_allocate_internal_addresses(&mut member, None, &peers, mesh)?;
        }
        assert_unique_wireguard_identity(&member, None, &peers)?;
        assert_unique_internal_addresses(&member, None, &peers)?;
        enrollment.phase = AegisEnrollmentPhase::Prepared;
        enrollment.updated_unix = updated_unix;
        stage_aegis_egress_generation_increment(&tx_db, &mut tx, &service_parent).await?;
        tx.update_object_at(
            &service_parent,
            AEGIS_HOSTS_COLLECTION,
            &document_id,
            &stored_aegis_host_record_from_domain(&host),
            None,
            Some(FirestoreWritePrecondition::Exists(false)),
            vec![],
        )?;
        tx.update_object_at(
            &network_parent,
            AEGIS_NETWORK_MEMBERS_COLLECTION,
            &document_id,
            &stored_aegis_network_member_from_domain(&member),
            None,
            Some(FirestoreWritePrecondition::Exists(false)),
            vec![],
        )?;
        tx.update_object_at(
            &service_parent,
            AEGIS_ENROLLMENTS_COLLECTION,
            &document_id,
            &stored_aegis_enrollment(&enrollment),
            None,
            Some(FirestoreWritePrecondition::Exists(true)),
            vec![],
        )?;
        tx.commit()
            .await
            .map_err(anyhow::Error::from)
            .map_err(map_enrollment_firestore_error)?;
        Ok(AegisEnrollmentPrepared {
            enrollment,
            host,
            member,
        })
    }

    async fn activate_aegis_enrollment(
        &self,
        host_id: &HostId,
        credential_session_id: &str,
        updated_unix: i64,
    ) -> Result<AegisEnrollmentPrepared, AegisEnrollmentWriteError> {
        let service_parent = aegis_parent(self)?;
        let document_id = host_id.to_string();
        let mut tx = self.begin_write_transaction().await?;
        let tx_db = self.inner().clone_with_consistency_selector(
            FirestoreConsistencySelector::Transaction(tx.transaction_id().clone()),
        );
        let Some(stored) = get_stored_obj_at_if_exists::<StoredAegisEnrollment>(
            &tx_db,
            &service_parent,
            AEGIS_ENROLLMENTS_COLLECTION,
            &document_id,
        )
        .await?
        else {
            tx.rollback().await.ok();
            return Err(AegisEnrollmentWriteError::NotFound { host_id: *host_id });
        };
        let mut enrollment = domain_aegis_enrollment(*host_id, stored);
        validate_current_enrollment(&enrollment, credential_session_id, updated_unix)?;
        if enrollment_phase_rank(enrollment.phase)
            < enrollment_phase_rank(AegisEnrollmentPhase::Prepared)
        {
            tx.rollback().await.ok();
            return Err(AegisEnrollmentWriteError::NotPrepared { host_id: *host_id });
        }
        let network_parent = aegis_network_parent(self, &enrollment.network)?;
        let Some(stored_host) = get_stored_obj_at_if_exists::<StoredAegisHostRecord>(
            &tx_db,
            &service_parent,
            AEGIS_HOSTS_COLLECTION,
            &document_id,
        )
        .await?
        else {
            tx.rollback().await.ok();
            return Err(AegisEnrollmentWriteError::NotPrepared { host_id: *host_id });
        };
        let Some(stored_member) = get_stored_obj_at_if_exists::<StoredAegisNetworkMemberRecord>(
            &tx_db,
            &network_parent,
            AEGIS_NETWORK_MEMBERS_COLLECTION,
            &document_id,
        )
        .await?
        else {
            tx.rollback().await.ok();
            return Err(AegisEnrollmentWriteError::NotPrepared { host_id: *host_id });
        };
        let mut host = domain_aegis_host_record_from_stored(*host_id, stored_host)?;
        let mut member = domain_aegis_network_member_from_stored(*host_id, stored_member);
        if !host.pending
            || !member.pending
            || !prepared_host_matches_enrollment(&enrollment, &host, &member)
        {
            tx.rollback().await.ok();
            return Err(AegisEnrollmentWriteError::InconsistentPreparedHost { host_id: *host_id });
        }
        let principal = format!("enrollment:{host_id}");
        host.pending = false;
        host.updated_unix = updated_unix;
        host.updated_by_principal = principal.clone();
        member.pending = false;
        member.updated_unix = updated_unix;
        member.updated_by_principal = principal;
        enrollment.phase = AegisEnrollmentPhase::Activating;
        enrollment.updated_unix = updated_unix;
        stage_aegis_egress_generation_increment(&tx_db, &mut tx, &service_parent).await?;
        tx.update_object_at(
            &service_parent,
            AEGIS_HOSTS_COLLECTION,
            &document_id,
            &stored_aegis_host_record_from_domain(&host),
            None,
            Some(FirestoreWritePrecondition::Exists(true)),
            vec![],
        )?;
        tx.update_object_at(
            &network_parent,
            AEGIS_NETWORK_MEMBERS_COLLECTION,
            &document_id,
            &stored_aegis_network_member_from_domain(&member),
            None,
            Some(FirestoreWritePrecondition::Exists(true)),
            vec![],
        )?;
        tx.delete_by_id_at(
            &service_parent,
            AEGIS_ENROLLMENTS_COLLECTION,
            &document_id,
            Some(FirestoreWritePrecondition::Exists(true)),
        )?;
        tx.commit()
            .await
            .map_err(anyhow::Error::from)
            .map_err(map_enrollment_firestore_error)?;
        Ok(AegisEnrollmentPrepared {
            enrollment,
            host,
            member,
        })
    }

    async fn cancel_aegis_enrollment(
        &self,
        host_id: &HostId,
    ) -> Result<Option<AegisEnrollmentRecord>, AegisEnrollmentWriteError> {
        let service_parent = aegis_parent(self)?;
        let document_id = host_id.to_string();
        let mut tx = self.begin_write_transaction().await?;
        let tx_db = self.inner().clone_with_consistency_selector(
            FirestoreConsistencySelector::Transaction(tx.transaction_id().clone()),
        );
        let Some(stored) = get_stored_obj_at_if_exists::<StoredAegisEnrollment>(
            &tx_db,
            &service_parent,
            AEGIS_ENROLLMENTS_COLLECTION,
            &document_id,
        )
        .await?
        else {
            tx.rollback().await.ok();
            return Ok(None);
        };
        let enrollment = domain_aegis_enrollment(*host_id, stored);
        let network_parent = aegis_network_parent(self, &enrollment.network)?;
        let host = get_stored_obj_at_if_exists::<StoredAegisHostRecord>(
            &tx_db,
            &service_parent,
            AEGIS_HOSTS_COLLECTION,
            &document_id,
        )
        .await?;
        let member = get_stored_obj_at_if_exists::<StoredAegisNetworkMemberRecord>(
            &tx_db,
            &network_parent,
            AEGIS_NETWORK_MEMBERS_COLLECTION,
            &document_id,
        )
        .await?;
        if host.as_ref().is_some_and(|host| !host.pending)
            || member.as_ref().is_some_and(|member| !member.pending)
        {
            tx.rollback().await.ok();
            return Err(AegisEnrollmentWriteError::InconsistentPreparedHost { host_id: *host_id });
        }
        for alias in &enrollment.aliases {
            let claim = get_stored_obj_at_if_exists::<StoredAegisAliasClaim>(
                &tx_db,
                &service_parent,
                AEGIS_ALIASES_COLLECTION,
                alias.as_str(),
            )
            .await?;
            if claim.as_ref().map(|claim| claim.host_id) != Some(*host_id) {
                tx.rollback().await.ok();
                return Err(AegisEnrollmentWriteError::InconsistentPreparedHost {
                    host_id: *host_id,
                });
            }
        }
        tx.delete_by_id_at(
            &service_parent,
            AEGIS_ENROLLMENTS_COLLECTION,
            &document_id,
            Some(FirestoreWritePrecondition::Exists(true)),
        )?;
        if host.is_some() {
            tx.delete_by_id_at(
                &service_parent,
                AEGIS_HOSTS_COLLECTION,
                &document_id,
                Some(FirestoreWritePrecondition::Exists(true)),
            )?;
        }
        if member.is_some() {
            tx.delete_by_id_at(
                &network_parent,
                AEGIS_NETWORK_MEMBERS_COLLECTION,
                &document_id,
                Some(FirestoreWritePrecondition::Exists(true)),
            )?;
        }
        for alias in &enrollment.aliases {
            tx.delete_by_id_at(
                &service_parent,
                AEGIS_ALIASES_COLLECTION,
                alias.as_str(),
                Some(FirestoreWritePrecondition::Exists(true)),
            )?;
        }
        if host.is_some() || member.is_some() {
            stage_aegis_egress_generation_increment(&tx_db, &mut tx, &service_parent).await?;
        }
        tx.commit()
            .await
            .map_err(anyhow::Error::from)
            .map_err(map_enrollment_firestore_error)?;
        Ok(Some(enrollment))
    }

    async fn read_aegis_egress_snapshot(&self) -> anyhow::Result<AegisEgressSnapshot> {
        let parent = aegis_parent(self)?;
        let state = fetch_aegis_egress_state(self, &parent).await?;
        Ok(AegisEgressSnapshot {
            generation: state.generation,
            policies: state.policies.into_values().collect(),
        })
    }

    async fn fetch_aegis_egress_policy(
        &self,
        source_host_id: &HostId,
    ) -> anyhow::Result<Option<aegis_types::v1::AegisEgressPolicy>> {
        let state = fetch_aegis_egress_state(self, &aegis_parent(self)?).await?;
        Ok(state.policies.get(source_host_id).cloned())
    }

    async fn compare_and_set_aegis_egress_policy(
        &self,
        source_host_id: &HostId,
        expected_generation: u64,
        expected_revision: Option<u64>,
        replacement: Option<&aegis_types::v1::AegisEgressPolicy>,
    ) -> Result<(), AegisEgressWriteError> {
        if replacement.is_some_and(|policy| policy.source_host_id != *source_host_id) {
            return Err(AegisEgressWriteError::Internal(anyhow::anyhow!(
                "replacement egress policy source does not match document id"
            )));
        }
        if replacement
            .is_some_and(|policy| policy.revision != expected_generation.saturating_add(1))
        {
            return Err(AegisEgressWriteError::Internal(anyhow::anyhow!(
                "replacement egress policy revision is not the successor of the topology generation"
            )));
        }
        let parent = aegis_parent(self).map_err(AegisEgressWriteError::Internal)?;
        let mut tx = self
            .begin_write_transaction()
            .await
            .map_err(AegisEgressWriteError::Internal)?;
        let tx_db = self.inner().clone_with_consistency_selector(
            FirestoreConsistencySelector::Transaction(tx.transaction_id().clone()),
        );
        let stored = get_stored_obj_at_if_exists::<StoredAegisEgressState>(
            &tx_db,
            &parent,
            AEGIS_STATE_COLLECTION,
            AEGIS_EGRESS_STATE_DOCUMENT,
        )
        .await
        .map_err(anyhow::Error::from)
        .map_err(AegisEgressWriteError::Internal)?;
        let state_exists = stored.is_some();
        let mut state = stored.unwrap_or_default();
        validate_stored_aegis_egress_state(&state).map_err(AegisEgressWriteError::Internal)?;
        if state.generation != expected_generation
            || state
                .policies
                .get(source_host_id)
                .map(|policy| policy.revision)
                != expected_revision
        {
            tx.rollback().await.ok();
            return Err(AegisEgressWriteError::ConcurrentWrite {
                source_host_id: *source_host_id,
            });
        }
        match replacement {
            Some(policy) => {
                state.policies.insert(*source_host_id, policy.clone());
            }
            None if state.policies.remove(source_host_id).is_some() => {}
            None => {
                tx.rollback().await.ok();
                return Err(AegisEgressWriteError::NotFound {
                    source_host_id: *source_host_id,
                });
            }
        }
        state.generation = state.generation.checked_add(1).ok_or_else(|| {
            AegisEgressWriteError::Internal(anyhow::anyhow!(
                "egress topology generation is exhausted"
            ))
        })?;
        tx.update_object_at(
            &parent,
            AEGIS_STATE_COLLECTION,
            AEGIS_EGRESS_STATE_DOCUMENT,
            &state,
            None,
            Some(FirestoreWritePrecondition::Exists(state_exists)),
            vec![],
        )
        .map_err(anyhow::Error::from)
        .map_err(AegisEgressWriteError::Internal)?;
        tx.commit()
            .await
            .map_err(anyhow::Error::from)
            .map_err(|error| {
                if is_firestore_data_conflict(&error) {
                    AegisEgressWriteError::ConcurrentWrite {
                        source_host_id: *source_host_id,
                    }
                } else {
                    AegisEgressWriteError::Internal(error)
                }
            })?;
        Ok(())
    }

    async fn list_aegis_direct_gateways(&self) -> anyhow::Result<Vec<AegisDirectGatewayRecord>> {
        list_direct_gateways(self).await
    }

    async fn fetch_aegis_direct_gateway(
        &self,
        host_id: &HostId,
    ) -> anyhow::Result<Option<AegisDirectGatewayRecord>> {
        fetch_direct_gateway(self, host_id).await
    }

    async fn put_aegis_direct_gateway(
        &self,
        gateway: &AegisDirectGatewayRecord,
    ) -> Result<AegisDirectGatewayRecord, AegisDirectWriteError> {
        put_direct_gateway(self, gateway).await
    }

    async fn delete_aegis_direct_gateway(&self, host_id: &HostId) -> anyhow::Result<bool> {
        delete_direct_gateway(self, host_id).await
    }

    async fn list_aegis_satellites(&self) -> anyhow::Result<Vec<AegisSatelliteRecord>> {
        list_satellites(self).await
    }

    async fn create_aegis_satellite(
        &self,
        satellite: &AegisSatelliteRecord,
        pool: &AegisWireGuardAddressPool,
    ) -> Result<AegisSatelliteRecord, AegisDirectWriteError> {
        create_satellite(self, satellite, pool).await
    }

    async fn fetch_aegis_satellite(
        &self,
        slug: &str,
    ) -> anyhow::Result<Option<AegisSatelliteRecord>> {
        let satellite = get_stored_obj_at_if_exists::<StoredAegisSatellite>(
            self.inner(),
            &aegis_parent(self)?,
            AEGIS_SATELLITES_COLLECTION,
            slug,
        )
        .await?;
        Ok(satellite.map(|satellite| domain_satellite(slug, satellite)))
    }

    async fn record_aegis_satellite_broker_use(
        &self,
        slug: &str,
        activity: &AegisSatelliteBrokerUseRecord,
    ) -> anyhow::Result<bool> {
        record_satellite_broker_use(self, slug, activity).await
    }

    async fn delete_aegis_satellite(&self, slug: &str) -> anyhow::Result<bool> {
        delete_satellite(self, slug).await
    }

    async fn list_aegis_hosts(&self) -> anyhow::Result<Vec<AegisHostRecord>> {
        let parent = aegis_parent(self)?;
        let docs = self
            .inner()
            .fluent()
            .select()
            .from(AEGIS_HOSTS_COLLECTION)
            .parent(&parent)
            .query()
            .await?;
        let mut hosts = deserialize_aegis_host_documents(docs)?;
        hosts.sort_by(|left, right| left.aliases.primary().cmp(right.aliases.primary()));
        Ok(hosts)
    }

    async fn fetch_aegis_host(&self, host_id: &HostId) -> anyhow::Result<Option<AegisHostRecord>> {
        let parent = aegis_parent(self)?;
        let host = get_stored_obj_at_if_exists::<StoredAegisHostRecord>(
            self.inner(),
            &parent,
            AEGIS_HOSTS_COLLECTION,
            &host_id.to_string(),
        )
        .await
        .map_err(anyhow::Error::from)?;
        host.map(|host| domain_aegis_host_record_from_stored(*host_id, host))
            .transpose()
    }

    async fn fetch_host_id_by_alias(&self, alias: &HostAlias) -> anyhow::Result<Option<HostId>> {
        let claim = get_stored_obj_at_if_exists::<StoredAegisAliasClaim>(
            self.inner(),
            &aegis_parent(self)?,
            AEGIS_ALIASES_COLLECTION,
            alias.as_str(),
        )
        .await?;
        Ok(claim.map(|claim| claim.host_id))
    }

    async fn resolve_enrolled_host_alias(
        &self,
        alias: &HostAlias,
    ) -> anyhow::Result<Option<HostId>> {
        let parent = aegis_parent(self)?;
        let tx = self.inner().begin_transaction().await?;
        let tx_db = self.inner().clone_with_consistency_selector(
            FirestoreConsistencySelector::Transaction(tx.transaction_id().clone()),
        );
        let result = async {
            let Some(claim) = get_stored_obj_at_if_exists::<StoredAegisAliasClaim>(
                &tx_db,
                &parent,
                AEGIS_ALIASES_COLLECTION,
                alias.as_str(),
            )
            .await?
            else {
                return Ok(None);
            };
            let host_document_id = claim.host_id.to_string();
            if let Some(stored) = get_stored_obj_at_if_exists::<StoredAegisHostRecord>(
                &tx_db,
                &parent,
                AEGIS_HOSTS_COLLECTION,
                &host_document_id,
            )
            .await?
            {
                let host = domain_aegis_host_record_from_stored(claim.host_id, stored)?;
                if !host.aliases.contains(alias) {
                    anyhow::bail!(
                        "alias claim `{alias}` points to host `{}` whose authoritative alias list does not contain it",
                        claim.host_id
                    );
                }
                if !host.pending {
                    return Ok(Some(claim.host_id));
                }
            }
            if let Some(enrollment) = get_stored_obj_at_if_exists::<StoredAegisEnrollment>(
                &tx_db,
                &parent,
                AEGIS_ENROLLMENTS_COLLECTION,
                &host_document_id,
            )
            .await?
            {
                if !enrollment.aliases.contains(alias) {
                    anyhow::bail!(
                        "alias claim `{alias}` points to enrollment `{}` whose authoritative alias list does not contain it",
                        claim.host_id
                    );
                }
                return Ok(None);
            }
            anyhow::bail!(
                "alias claim `{alias}` points to `{}` without an enrolled host or enrollment",
                claim.host_id
            )
        }
        .await;
        tx.rollback().await.ok();
        result
    }

    async fn add_host_alias(
        &self,
        host_id: &HostId,
        alias: &HostAlias,
        updated_by_principal: &str,
        updated_unix: i64,
    ) -> Result<AegisHostRecord, AegisAliasWriteError> {
        update_host_aliases(
            self,
            host_id,
            HostAliasMutation::Add(alias.clone()),
            updated_by_principal,
            updated_unix,
        )
        .await
    }

    async fn promote_host_alias(
        &self,
        host_id: &HostId,
        alias: &HostAlias,
        updated_by_principal: &str,
        updated_unix: i64,
    ) -> Result<AegisHostRecord, AegisAliasWriteError> {
        update_host_aliases(
            self,
            host_id,
            HostAliasMutation::Promote(alias.clone()),
            updated_by_principal,
            updated_unix,
        )
        .await
    }

    async fn remove_host_alias(
        &self,
        host_id: &HostId,
        alias: &HostAlias,
        updated_by_principal: &str,
        updated_unix: i64,
    ) -> Result<AegisHostRecord, AegisAliasWriteError> {
        update_host_aliases(
            self,
            host_id,
            HostAliasMutation::Remove(alias.clone()),
            updated_by_principal,
            updated_unix,
        )
        .await
    }

    async fn list_aegis_network_members(
        &self,
        network: &str,
    ) -> anyhow::Result<Vec<AegisNetworkMemberRecord>> {
        let parent = aegis_network_parent(self, network)?;
        let docs = self
            .inner()
            .fluent()
            .select()
            .from(AEGIS_NETWORK_MEMBERS_COLLECTION)
            .parent(&parent)
            .query()
            .await?;
        let mut members = deserialize_aegis_network_member_documents(docs)?;
        members.sort_by_key(|member| member.host_id);
        Ok(members)
    }

    async fn fetch_aegis_network_member(
        &self,
        network: &str,
        host_id: &HostId,
    ) -> anyhow::Result<Option<AegisNetworkMemberRecord>> {
        let parent = aegis_network_parent(self, network)?;
        let member = get_stored_obj_at_if_exists::<StoredAegisNetworkMemberRecord>(
            self.inner(),
            &parent,
            AEGIS_NETWORK_MEMBERS_COLLECTION,
            &host_id.to_string(),
        )
        .await
        .map_err(anyhow::Error::from)?;
        Ok(member.map(|member| domain_aegis_network_member_from_stored(*host_id, member)))
    }

    async fn update_aegis_host(
        &self,
        host: &AegisHostRecord,
    ) -> Result<AegisHostRecord, AegisHostWriteError> {
        update_aegis_host_record(self, host).await
    }

    async fn update_aegis_network_member(
        &self,
        network: &str,
        member: &AegisNetworkMemberRecord,
        config: &aegis_types::v1::AegisNetworkConfig,
    ) -> Result<AegisNetworkMemberRecord, AegisHostWriteError> {
        update_aegis_network_member_record(self, network, member, config).await
    }

    async fn update_aegis_host_report(
        &self,
        host_id: &HostId,
        update: AegisHostReportUpdate,
    ) -> anyhow::Result<bool> {
        update_aegis_host_report(self, host_id, update).await
    }

    async fn delete_aegis_host(
        &self,
        host_id: &HostId,
        networks: &[String],
    ) -> Result<bool, AegisHostDeleteError> {
        let parent = aegis_parent(self)?;
        let mut tx = self.begin_write_transaction().await?;
        let tx_db = self.inner().clone_with_consistency_selector(
            FirestoreConsistencySelector::Transaction(tx.transaction_id().clone()),
        );
        let host_document_id = host_id.to_string();
        let host = get_stored_obj_at_if_exists::<StoredAegisHostRecord>(
            &tx_db,
            &parent,
            AEGIS_HOSTS_COLLECTION,
            &host_document_id,
        )
        .await?;
        if host.as_ref().is_some_and(|host| host.pending) {
            tx.rollback().await.ok();
            return Err(AegisHostDeleteError::EnrollmentPending { host_id: *host_id });
        }
        let mut found = host.is_some();
        let mut network_parents = Vec::with_capacity(networks.len());
        for network in networks {
            let network_parent = aegis_network_parent(self, network)?;
            found |= get_stored_obj_at_if_exists::<StoredAegisNetworkMemberRecord>(
                &tx_db,
                &network_parent,
                AEGIS_NETWORK_MEMBERS_COLLECTION,
                &host_document_id,
            )
            .await?
            .is_some();
            network_parents.push(network_parent);
        }
        let direct_gateway = get_stored_obj_at_if_exists::<StoredAegisDirectGateway>(
            &tx_db,
            &parent,
            AEGIS_DIRECT_GATEWAYS_COLLECTION,
            &host_document_id,
        )
        .await?;
        found |= direct_gateway.is_some();
        let stored_egress_state = get_stored_obj_at_if_exists::<StoredAegisEgressState>(
            &tx_db,
            &parent,
            AEGIS_STATE_COLLECTION,
            AEGIS_EGRESS_STATE_DOCUMENT,
        )
        .await?;
        let egress_state_exists = stored_egress_state.is_some();
        let mut egress_state = stored_egress_state.unwrap_or_default();
        validate_stored_aegis_egress_state(&egress_state)?;
        let egress_related = egress_state.policies.values().any(|policy| {
            policy.source_host_id == *host_id
                || policy.active_via == Some(*host_id)
                || policy.desired_via == Some(*host_id)
        });
        let mut blocking_sources = egress_state
            .policies
            .values()
            .filter(|policy| {
                policy.source_host_id != *host_id
                    && (policy.active_via == Some(*host_id) || policy.desired_via == Some(*host_id))
            })
            .map(|policy| policy.source_host_id)
            .collect::<Vec<_>>();
        blocking_sources.sort();
        blocking_sources.dedup();
        if !blocking_sources.is_empty() {
            tx.rollback().await.ok();
            return Err(AegisHostDeleteError::EgressTargetInUse {
                host_id: *host_id,
                source_host_ids: blocking_sources,
            });
        }
        found |= egress_related;
        if !found {
            tx.rollback().await.ok();
            return Ok(false);
        }
        egress_state.policies.remove(host_id);
        egress_state.generation = egress_state.generation.checked_add(1).ok_or_else(|| {
            AegisHostDeleteError::Internal(anyhow::anyhow!(
                "egress topology generation is exhausted"
            ))
        })?;
        if let Some(host) = &host {
            tx.delete_by_id_at(
                &parent,
                AEGIS_HOSTS_COLLECTION,
                &host_document_id,
                Some(FirestoreWritePrecondition::Exists(true)),
            )?;
            for alias in &host.aliases {
                tx.delete_by_id_at(
                    &parent,
                    AEGIS_ALIASES_COLLECTION,
                    alias.as_str(),
                    Some(FirestoreWritePrecondition::Exists(true)),
                )?;
            }
        }
        for network_parent in network_parents {
            tx.delete_by_id_at(
                &network_parent,
                AEGIS_NETWORK_MEMBERS_COLLECTION,
                &host_document_id,
                None,
            )?;
        }
        if direct_gateway.is_some() {
            tx.delete_by_id_at(
                &parent,
                AEGIS_DIRECT_GATEWAYS_COLLECTION,
                &host_document_id,
                Some(FirestoreWritePrecondition::Exists(true)),
            )?;
        }
        tx.update_object_at(
            &parent,
            AEGIS_STATE_COLLECTION,
            AEGIS_EGRESS_STATE_DOCUMENT,
            &egress_state,
            None,
            Some(FirestoreWritePrecondition::Exists(egress_state_exists)),
            vec![],
        )?;
        tx.commit().await.map_err(|error| {
            let error = anyhow::Error::from(error);
            if is_firestore_data_conflict(&error) {
                AegisHostDeleteError::ConcurrentWrite
            } else {
                AegisHostDeleteError::Internal(error)
            }
        })?;
        Ok(true)
    }
}

async fn list_direct_gateways(db: &AegisDb) -> anyhow::Result<Vec<AegisDirectGatewayRecord>> {
    let docs = db
        .inner()
        .fluent()
        .select()
        .from(AEGIS_DIRECT_GATEWAYS_COLLECTION)
        .parent(&aegis_parent(db)?)
        .query()
        .await?;
    let mut gateways = docs
        .into_iter()
        .map(|document| {
            let host_id = host_id_from_document_name(&document.name)?;
            let gateway = deserialize_stored_document::<StoredAegisDirectGateway>(&document)?;
            Ok(domain_direct_gateway(host_id, gateway))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    gateways.sort_by_key(|gateway| gateway.host_id);
    Ok(gateways)
}

async fn fetch_direct_gateway(
    db: &AegisDb,
    host_id: &HostId,
) -> anyhow::Result<Option<AegisDirectGatewayRecord>> {
    let gateway = get_stored_obj_at_if_exists::<StoredAegisDirectGateway>(
        db.inner(),
        &aegis_parent(db)?,
        AEGIS_DIRECT_GATEWAYS_COLLECTION,
        &host_id.to_string(),
    )
    .await?;
    Ok(gateway.map(|gateway| domain_direct_gateway(*host_id, gateway)))
}

async fn put_direct_gateway(
    db: &AegisDb,
    gateway: &AegisDirectGatewayRecord,
) -> Result<AegisDirectGatewayRecord, AegisDirectWriteError> {
    let parent = aegis_parent(db).map_err(AegisDirectWriteError::Internal)?;
    let mut tx = db
        .begin_write_transaction()
        .await
        .map_err(map_direct_write_internal_error)?;
    let tx_db =
        db.inner()
            .clone_with_consistency_selector(FirestoreConsistencySelector::Transaction(
                tx.transaction_id().clone(),
            ));
    let existing = get_stored_obj_at_if_exists::<StoredAegisDirectGateway>(
        &tx_db,
        &parent,
        AEGIS_DIRECT_GATEWAYS_COLLECTION,
        &gateway.host_id.to_string(),
    )
    .await
    .map_err(anyhow::Error::from)
    .map_err(map_direct_write_internal_error)?;
    let duplicate = tx_db
        .fluent()
        .select()
        .from(AEGIS_DIRECT_GATEWAYS_COLLECTION)
        .parent(&parent)
        .query()
        .await
        .map_err(anyhow::Error::from)
        .map_err(map_direct_write_internal_error)?
        .into_iter()
        .map(|document| {
            let host_id = host_id_from_document_name(&document.name)
                .map_err(map_direct_write_internal_error)?;
            let record = deserialize_stored_document::<StoredAegisDirectGateway>(&document)
                .map_err(anyhow::Error::from)
                .map_err(map_direct_write_internal_error)?;
            Ok::<_, AegisDirectWriteError>((host_id, record))
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .find(|(host_id, record)| {
            host_id != &gateway.host_id
                && record.wireguard.public_key == gateway.wireguard.public_key
        });
    if let Some((host_id, _)) = duplicate {
        tx.rollback().await.ok();
        return Err(AegisDirectWriteError::DuplicatePublicKey {
            resource: host_id.to_string(),
        });
    }
    let mut stored = stored_direct_gateway(gateway);
    if let Some(existing) = existing {
        stored.created_unix = existing.created_unix;
    }
    tx.update_object_at(
        &parent,
        AEGIS_DIRECT_GATEWAYS_COLLECTION,
        gateway.host_id.to_string(),
        &stored,
        None,
        None,
        vec![],
    )
    .map_err(anyhow::Error::from)
    .map_err(map_direct_write_internal_error)?;
    tx.commit()
        .await
        .map_err(anyhow::Error::from)
        .map_err(map_direct_write_internal_error)?;
    Ok(domain_direct_gateway(gateway.host_id, stored))
}

async fn delete_direct_gateway(db: &AegisDb, host_id: &HostId) -> anyhow::Result<bool> {
    let parent = aegis_parent(db)?;
    let mut tx = db.begin_write_transaction().await?;
    let tx_db =
        db.inner()
            .clone_with_consistency_selector(FirestoreConsistencySelector::Transaction(
                tx.transaction_id().clone(),
            ));
    if get_stored_obj_at_if_exists::<StoredAegisDirectGateway>(
        &tx_db,
        &parent,
        AEGIS_DIRECT_GATEWAYS_COLLECTION,
        &host_id.to_string(),
    )
    .await?
    .is_none()
    {
        tx.rollback().await.ok();
        return Ok(false);
    }
    tx.delete_by_id_at(
        &parent,
        AEGIS_DIRECT_GATEWAYS_COLLECTION,
        host_id.to_string(),
        Some(FirestoreWritePrecondition::Exists(true)),
    )?;
    tx.commit().await?;
    Ok(true)
}

async fn list_satellites(db: &AegisDb) -> anyhow::Result<Vec<AegisSatelliteRecord>> {
    let docs = db
        .inner()
        .fluent()
        .select()
        .from(AEGIS_SATELLITES_COLLECTION)
        .parent(&aegis_parent(db)?)
        .query()
        .await?;
    let mut satellites = docs
        .into_iter()
        .map(|document| {
            let slug = firestore_document_id(&document.name)
                .ok_or_else(|| anyhow::anyhow!("satellite document has no id"))?;
            let satellite = deserialize_stored_document::<StoredAegisSatellite>(&document)?;
            Ok::<_, anyhow::Error>(domain_satellite(slug, satellite))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    satellites.sort_by(|left, right| left.slug.cmp(&right.slug));
    Ok(satellites)
}

async fn record_satellite_broker_use(
    db: &AegisDb,
    slug: &str,
    activity: &AegisSatelliteBrokerUseRecord,
) -> anyhow::Result<bool> {
    let parent = aegis_parent(db)?;
    let mut tx = db.begin_write_transaction().await?;
    let tx_db =
        db.inner()
            .clone_with_consistency_selector(FirestoreConsistencySelector::Transaction(
                tx.transaction_id().clone(),
            ));
    let Some(mut satellite) = get_stored_obj_at_if_exists::<StoredAegisSatellite>(
        &tx_db,
        &parent,
        AEGIS_SATELLITES_COLLECTION,
        slug,
    )
    .await?
    else {
        tx.rollback().await.ok();
        return Ok(false);
    };
    if satellite
        .broker_uses
        .get(&activity.target_host_id)
        .is_some_and(|current| current.used_unix > activity.used_unix)
    {
        tx.rollback().await.ok();
        return Ok(true);
    }
    satellite
        .broker_uses
        .insert(activity.target_host_id, activity.clone());
    tx.update_object_at(
        &parent,
        AEGIS_SATELLITES_COLLECTION,
        slug,
        &satellite,
        None,
        Some(FirestoreWritePrecondition::Exists(true)),
        vec![],
    )?;
    tx.commit().await?;
    Ok(true)
}

async fn create_satellite(
    db: &AegisDb,
    satellite: &AegisSatelliteRecord,
    pool: &AegisWireGuardAddressPool,
) -> Result<AegisSatelliteRecord, AegisDirectWriteError> {
    for attempt in 0..CONFIG_BOOTSTRAP_MAX_RETRIES {
        match create_satellite_once(db, satellite, pool).await {
            Err(AegisDirectWriteError::ConcurrentWrite)
                if attempt + 1 < CONFIG_BOOTSTRAP_MAX_RETRIES =>
            {
                tracing::warn!(
                    attempt = attempt + 1,
                    slug = satellite.slug,
                    "Aegis satellite allocation conflicted; retrying"
                );
            }
            result => return result,
        }
    }
    unreachable!("satellite allocation retry loop always returns on its final attempt")
}

async fn create_satellite_once(
    db: &AegisDb,
    satellite: &AegisSatelliteRecord,
    pool: &AegisWireGuardAddressPool,
) -> Result<AegisSatelliteRecord, AegisDirectWriteError> {
    let parent = aegis_parent(db).map_err(AegisDirectWriteError::Internal)?;
    let mut tx = db
        .begin_write_transaction()
        .await
        .map_err(map_direct_write_internal_error)?;
    let tx_db =
        db.inner()
            .clone_with_consistency_selector(FirestoreConsistencySelector::Transaction(
                tx.transaction_id().clone(),
            ));
    let satellite_exists = get_stored_obj_at_if_exists::<StoredAegisSatellite>(
        &tx_db,
        &parent,
        AEGIS_SATELLITES_COLLECTION,
        &satellite.slug,
    )
    .await
    .map_err(anyhow::Error::from)
    .map_err(map_direct_write_internal_error)?
    .is_some();
    if satellite_exists {
        tx.rollback().await.ok();
        return Err(AegisDirectWriteError::AlreadyExists {
            resource: satellite.slug.clone(),
        });
    }
    let alias = HostAlias::parse(satellite.slug.clone())
        .map_err(|error| AegisDirectWriteError::Internal(anyhow::anyhow!(error)))?;
    if let Some(claim) = get_stored_obj_at_if_exists::<StoredAegisAliasClaim>(
        &tx_db,
        &parent,
        AEGIS_ALIASES_COLLECTION,
        alias.as_str(),
    )
    .await
    .map_err(anyhow::Error::from)
    .map_err(map_direct_write_internal_error)?
    {
        tx.rollback().await.ok();
        return Err(AegisDirectWriteError::HostAliasExists {
            alias,
            host_id: claim.host_id,
        });
    }
    let leases = list_direct_leases(&tx_db, &parent).await?;
    if let Some(existing) = leases
        .iter()
        .find(|existing| existing.wireguard.public_key == satellite.wireguard.public_key)
    {
        tx.rollback().await.ok();
        return Err(AegisDirectWriteError::DuplicatePublicKey {
            resource: existing.id.clone(),
        });
    }
    let reserved_ipv4 =
        wireguard_ipv4_for_host_id(pool, 1).map_err(map_direct_wireguard_address_error)?;
    let reserved_ipv6 =
        wireguard_ipv6_for_host_id(pool, 1).map_err(map_direct_wireguard_address_error)?;
    let host_id = allocate_lowest_free_wireguard_host_id(
        pool,
        std::iter::once((reserved_ipv4.as_str(), reserved_ipv6.as_str())).chain(
            leases
                .iter()
                .map(|lease| (lease.wireguard.ipv4.as_str(), lease.wireguard.ipv6.as_str())),
        ),
    )
    .map_err(map_direct_wireguard_address_error)?;
    let mut stored = satellite.clone();
    stored.wireguard.ipv4 =
        wireguard_ipv4_for_host_id(pool, host_id).map_err(map_direct_wireguard_address_error)?;
    stored.wireguard.ipv6 =
        wireguard_ipv6_for_host_id(pool, host_id).map_err(map_direct_wireguard_address_error)?;
    let lease = AegisDirectLeaseRecord {
        id: stored.slug.clone(),
        wireguard: stored.wireguard.clone(),
    };
    let stored_satellite = stored_satellite(&stored);
    let stored_lease = stored_direct_lease(&lease);
    tx.update_object_at(
        &parent,
        AEGIS_SATELLITES_COLLECTION,
        &stored.slug,
        &stored_satellite,
        None,
        Some(FirestoreWritePrecondition::Exists(false)),
        vec![],
    )
    .map_err(anyhow::Error::from)
    .map_err(map_direct_write_internal_error)?;
    tx.update_object_at(
        &parent,
        AEGIS_DIRECT_LEASES_COLLECTION,
        &stored.slug,
        &stored_lease,
        None,
        Some(FirestoreWritePrecondition::Exists(false)),
        vec![],
    )
    .map_err(anyhow::Error::from)
    .map_err(map_direct_write_internal_error)?;
    tx.commit()
        .await
        .map_err(anyhow::Error::from)
        .map_err(map_direct_write_internal_error)?;
    Ok(stored)
}

async fn list_direct_leases(
    db: &FirestoreDb,
    parent: &str,
) -> Result<Vec<AegisDirectLeaseRecord>, AegisDirectWriteError> {
    db.fluent()
        .select()
        .from(AEGIS_DIRECT_LEASES_COLLECTION)
        .parent(parent)
        .query()
        .await
        .map_err(anyhow::Error::from)
        .map_err(map_direct_write_internal_error)?
        .into_iter()
        .map(|document| {
            let slug = firestore_document_id(&document.name).ok_or_else(|| {
                AegisDirectWriteError::Internal(anyhow::anyhow!("direct lease document has no id"))
            })?;
            let lease = deserialize_stored_document::<StoredAegisDirectLease>(&document)
                .map_err(anyhow::Error::from)
                .map_err(map_direct_write_internal_error)?;
            Ok(domain_direct_lease(slug, lease))
        })
        .collect()
}

async fn delete_satellite(db: &AegisDb, slug: &str) -> anyhow::Result<bool> {
    let parent = aegis_parent(db)?;
    let mut tx = db.begin_write_transaction().await?;
    let tx_db =
        db.inner()
            .clone_with_consistency_selector(FirestoreConsistencySelector::Transaction(
                tx.transaction_id().clone(),
            ));
    if get_stored_obj_at_if_exists::<StoredAegisSatellite>(
        &tx_db,
        &parent,
        AEGIS_SATELLITES_COLLECTION,
        slug,
    )
    .await?
    .is_none()
    {
        tx.rollback().await.ok();
        return Ok(false);
    }
    get_stored_obj_at_if_exists::<StoredAegisDirectLease>(
        &tx_db,
        &parent,
        AEGIS_DIRECT_LEASES_COLLECTION,
        slug,
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("satellite `{slug}` has no direct lease"))?;
    tx.delete_by_id_at(
        &parent,
        AEGIS_SATELLITES_COLLECTION,
        slug,
        Some(FirestoreWritePrecondition::Exists(true)),
    )?;
    tx.delete_by_id_at(
        &parent,
        AEGIS_DIRECT_LEASES_COLLECTION,
        slug,
        Some(FirestoreWritePrecondition::Exists(true)),
    )?;
    tx.commit().await?;
    Ok(true)
}

fn map_direct_wireguard_address_error(error: WireGuardAddressError) -> AegisDirectWriteError {
    match error {
        WireGuardAddressError::NoAvailableHostId {
            subnet_ipv4,
            subnet_ipv6,
        } => AegisDirectWriteError::NoAvailableAddress {
            subnet_ipv4,
            subnet_ipv6,
        },
        error => AegisDirectWriteError::Internal(anyhow::anyhow!(error)),
    }
}

async fn update_aegis_host_report(
    db: &AegisDb,
    host_id: &HostId,
    update: AegisHostReportUpdate,
) -> anyhow::Result<bool> {
    let parent = aegis_parent(db)?;
    let mut tx = db.begin_write_transaction().await?;
    let tx_db =
        db.inner()
            .clone_with_consistency_selector(FirestoreConsistencySelector::Transaction(
                tx.transaction_id().clone(),
            ));
    let host_document_id = host_id.to_string();
    let Some(mut stored) = get_stored_obj_at_if_exists::<StoredAegisHostRecord>(
        &tx_db,
        &parent,
        AEGIS_HOSTS_COLLECTION,
        &host_document_id,
    )
    .await?
    else {
        tx.rollback().await.ok();
        return Ok(false);
    };
    if let Some((ip, observed_unix)) = update.observed_public_ip {
        let ip_text = ip.to_string();
        let current = match ip {
            IpAddr::V4(_) => &mut stored.report.observed_public_ips.ipv4,
            IpAddr::V6(_) => &mut stored.report.observed_public_ips.ipv6,
        };
        if current.as_ref().map(|observed| observed.ip.as_str()) != Some(ip_text.as_str()) {
            *current = Some(AegisObservedPublicIp {
                ip: ip_text,
                observed_unix,
            });
        }
    }
    let previous_direct_gateway = stored
        .report
        .direct_gateway
        .clone()
        .map(domain_direct_gateway_report);
    let direct_gateway_report = crate::aegis_store::merge_direct_gateway_handshakes(
        previous_direct_gateway.as_ref(),
        update.direct_gateway_report,
    );
    let replacement = StoredAegisHostReport {
        messages: update.messages,
        agent: Some(update.agent),
        principal_grants: update.principal_grants,
        ssh_lockdown_enabled: Some(update.ssh_lockdown_enabled),
        direct_gateway: Some(stored_direct_gateway_report(&direct_gateway_report)),
        observed_public_ips: stored.report.observed_public_ips.clone(),
    };
    let changed = stored.report != replacement;
    if !changed {
        tx.rollback().await.ok();
        return Ok(true);
    }
    stored.report = replacement;
    tx.update_object_at(
        &parent,
        AEGIS_HOSTS_COLLECTION,
        &host_document_id,
        &stored,
        None,
        Some(FirestoreWritePrecondition::Exists(true)),
        vec![],
    )?;
    tx.commit().await?;
    Ok(true)
}

async fn update_aegis_host_record(
    db: &AegisDb,
    host: &AegisHostRecord,
) -> Result<AegisHostRecord, AegisHostWriteError> {
    let parent = aegis_parent(db).map_err(AegisHostWriteError::from)?;
    try_update_aegis_host_record(db, &parent, host).await
}

async fn update_aegis_network_member_record(
    db: &AegisDb,
    network: &str,
    member: &AegisNetworkMemberRecord,
    config: &aegis_types::v1::AegisNetworkConfig,
) -> Result<AegisNetworkMemberRecord, AegisHostWriteError> {
    let parent = aegis_network_parent(db, network).map_err(AegisHostWriteError::from)?;
    let service_parent = aegis_parent(db).map_err(AegisHostWriteError::from)?;
    let wireguard_pool = config.wireguard.address_pool();
    let mut tx = db
        .begin_write_transaction()
        .await
        .map_err(map_host_write_internal_error)?;
    let tx_db =
        db.inner()
            .clone_with_consistency_selector(FirestoreConsistencySelector::Transaction(
                tx.transaction_id().clone(),
            ));
    let Some(existing) = get_stored_obj_at_if_exists::<StoredAegisNetworkMemberRecord>(
        &tx_db,
        &parent,
        AEGIS_NETWORK_MEMBERS_COLLECTION,
        &member.host_id.to_string(),
    )
    .await
    .map_err(anyhow::Error::from)
    .map_err(map_host_write_internal_error)?
    else {
        tx.rollback().await.ok();
        return Err(AegisHostWriteError::NotFound {
            host_id: member.host_id,
        });
    };
    let existing = domain_aegis_network_member_from_stored(member.host_id, existing);
    if existing.pending {
        tx.rollback().await.ok();
        return Err(AegisHostWriteError::EnrollmentPending {
            host_id: member.host_id,
        });
    }
    let peers = deserialize_aegis_network_member_documents(
        tx_db
            .fluent()
            .select()
            .from(AEGIS_NETWORK_MEMBERS_COLLECTION)
            .parent(&parent)
            .query()
            .await
            .map_err(anyhow::Error::from)
            .map_err(map_host_write_internal_error)?,
    )
    .map_err(map_host_write_internal_error)?;

    let mut stored = member.clone();
    stored.created_unix = existing.created_unix;
    maybe_allocate_wireguard_identity(&mut stored, Some(&existing), &peers, &wireguard_pool)?;
    if let Some(mesh) = config.mesh.as_ref() {
        maybe_allocate_internal_addresses(&mut stored, Some(&existing), &peers, mesh)?;
    } else {
        stored.internal_ipv4 = None;
        stored.internal_ipv6 = None;
    }
    assert_unique_wireguard_identity(&stored, Some(&existing), &peers)?;
    assert_unique_internal_addresses(&stored, Some(&existing), &peers)?;
    let stored_doc = stored_aegis_network_member_from_domain(&stored);
    stage_aegis_egress_generation_increment(&tx_db, &mut tx, &service_parent)
        .await
        .map_err(map_host_write_internal_error)?;
    tx.update_object_at(
        &parent,
        AEGIS_NETWORK_MEMBERS_COLLECTION,
        stored.host_id.to_string(),
        &stored_doc,
        None,
        Some(FirestoreWritePrecondition::Exists(true)),
        vec![],
    )
    .map_err(anyhow::Error::from)
    .map_err(map_host_write_internal_error)?;
    tx.commit()
        .await
        .map_err(anyhow::Error::from)
        .map_err(map_host_write_internal_error)?;
    Ok(stored)
}

async fn try_update_aegis_host_record(
    db: &AegisDb,
    parent: &str,
    host: &AegisHostRecord,
) -> Result<AegisHostRecord, AegisHostWriteError> {
    let mut tx = db
        .begin_write_transaction()
        .await
        .map_err(map_host_write_internal_error)?;
    let tx_db =
        db.inner()
            .clone_with_consistency_selector(FirestoreConsistencySelector::Transaction(
                tx.transaction_id().clone(),
            ));
    let Some(existing) = get_stored_obj_at_if_exists::<StoredAegisHostRecord>(
        &tx_db,
        parent,
        AEGIS_HOSTS_COLLECTION,
        &host.host_id.to_string(),
    )
    .await
    .map_err(anyhow::Error::from)
    .map_err(map_host_write_internal_error)?
    else {
        tx.rollback().await.ok();
        return Err(AegisHostWriteError::NotFound {
            host_id: host.host_id,
        });
    };
    let existing = domain_aegis_host_record_from_stored(host.host_id, existing)
        .map_err(map_host_write_internal_error)?;
    if existing.pending {
        tx.rollback().await.ok();
        return Err(AegisHostWriteError::EnrollmentPending {
            host_id: host.host_id,
        });
    }
    if existing.aliases != host.aliases {
        tx.rollback().await.ok();
        return Err(AegisHostWriteError::AliasesChanged);
    }
    let peers = deserialize_aegis_host_documents(
        tx_db
            .fluent()
            .select()
            .from(AEGIS_HOSTS_COLLECTION)
            .parent(parent)
            .query()
            .await
            .map_err(anyhow::Error::from)
            .map_err(map_host_write_internal_error)?,
    )
    .map_err(map_host_write_internal_error)?;

    let mut stored = host.clone();
    stored.created_unix = existing.created_unix;
    assert_unique_egress_public_key(&stored, Some(&existing), &peers)?;
    let stored_doc = stored_aegis_host_record_from_domain(&stored);
    stage_aegis_egress_generation_increment(&tx_db, &mut tx, parent)
        .await
        .map_err(map_host_write_internal_error)?;
    tx.update_object_at(
        parent,
        AEGIS_HOSTS_COLLECTION,
        stored.host_id.to_string(),
        &stored_doc,
        None,
        Some(FirestoreWritePrecondition::Exists(true)),
        vec![],
    )
    .map_err(anyhow::Error::from)
    .map_err(map_host_write_internal_error)?;
    tx.commit()
        .await
        .map_err(anyhow::Error::from)
        .map_err(map_host_write_internal_error)?;
    Ok(stored)
}

fn map_host_write_internal_error(error: anyhow::Error) -> AegisHostWriteError {
    if is_firestore_data_conflict(&error) {
        return AegisHostWriteError::ConcurrentWrite;
    }
    AegisHostWriteError::Internal(error)
}

fn host_wireguard_identity(
    host: &AegisNetworkMemberRecord,
    pool: &AegisWireGuardAddressPool,
) -> Result<Option<WireGuardHostIdentity>, AegisHostWriteError> {
    match (
        host.wireguard_ipv4.as_deref(),
        host.wireguard_ipv6.as_deref(),
    ) {
        (None, None) => Ok(None),
        (Some(wireguard_ipv4), Some(wireguard_ipv6)) => {
            wireguard_host_identity_from_addresses(pool, wireguard_ipv4, wireguard_ipv6)
                .map(Some)
                .map_err(map_wireguard_address_error)
        }
        _ => Err(AegisHostWriteError::InvalidWireguardIdentity(
            "wireguard identities must include both IPv4 and IPv6 when present".to_string(),
        )),
    }
}

fn assert_unique_wireguard_identity(
    host: &AegisNetworkMemberRecord,
    existing: Option<&AegisNetworkMemberRecord>,
    peers: &[AegisNetworkMemberRecord],
) -> Result<(), AegisHostWriteError> {
    let existing_host_id = existing.map(|record| record.host_id);
    if let Some(conflict) = peers.iter().find(|candidate| {
        Some(candidate.host_id) != existing_host_id
            && candidate.wireguard_ipv4.as_deref() == host.wireguard_ipv4.as_deref()
            && host.wireguard_ipv4.is_some()
    }) {
        return Err(AegisHostWriteError::DuplicateWireguardIpv4 {
            host_id: conflict.host_id,
            wireguard_ipv4: host
                .wireguard_ipv4
                .clone()
                .expect("checked wireguard_ipv4 should exist"),
        });
    }
    if let Some(conflict) = peers.iter().find(|candidate| {
        Some(candidate.host_id) != existing_host_id
            && candidate.wireguard_ipv6.as_deref() == host.wireguard_ipv6.as_deref()
            && host.wireguard_ipv6.is_some()
    }) {
        return Err(AegisHostWriteError::DuplicateWireguardIpv6 {
            host_id: conflict.host_id,
            wireguard_ipv6: host
                .wireguard_ipv6
                .clone()
                .expect("checked wireguard_ipv6 should exist"),
        });
    }
    Ok(())
}

fn assert_unique_internal_addresses(
    host: &AegisNetworkMemberRecord,
    existing: Option<&AegisNetworkMemberRecord>,
    peers: &[AegisNetworkMemberRecord],
) -> Result<(), AegisHostWriteError> {
    let existing_host_id = existing.map(|record| record.host_id);
    if let Some(internal_ipv4) = host.internal_ipv4.as_ref()
        && let Some(conflict) = peers.iter().find(|candidate| {
            Some(candidate.host_id) != existing_host_id
                && (candidate.wireguard_ipv4.as_deref() == Some(internal_ipv4.as_str())
                    || candidate.internal_ipv4.as_deref() == Some(internal_ipv4.as_str()))
        })
    {
        return Err(AegisHostWriteError::DuplicateInternalIpv4 {
            host_id: conflict.host_id,
            internal_ipv4: internal_ipv4.clone(),
        });
    }
    if let Some(internal_ipv6) = host.internal_ipv6.as_ref()
        && let Some(conflict) = peers.iter().find(|candidate| {
            Some(candidate.host_id) != existing_host_id
                && (candidate.wireguard_ipv6.as_deref() == Some(internal_ipv6.as_str())
                    || candidate.internal_ipv6.as_deref() == Some(internal_ipv6.as_str()))
        })
    {
        return Err(AegisHostWriteError::DuplicateInternalIpv6 {
            host_id: conflict.host_id,
            internal_ipv6: internal_ipv6.clone(),
        });
    }
    Ok(())
}

fn assert_unique_egress_public_key(
    host: &AegisHostRecord,
    existing: Option<&AegisHostRecord>,
    peers: &[AegisHostRecord],
) -> Result<(), AegisHostWriteError> {
    let Some(public_key) = host.egress_public_key.as_deref() else {
        return Ok(());
    };
    let existing_host_id = existing.map(|record| record.host_id);
    if let Some(conflict) = peers.iter().find(|candidate| {
        Some(candidate.host_id) != existing_host_id
            && candidate.egress_public_key.as_deref() == Some(public_key)
    }) {
        return Err(AegisHostWriteError::DuplicateEgressPublicKey {
            host_id: conflict.host_id,
        });
    }
    Ok(())
}

pub(crate) fn maybe_allocate_wireguard_identity(
    host: &mut AegisNetworkMemberRecord,
    existing: Option<&AegisNetworkMemberRecord>,
    peers: &[AegisNetworkMemberRecord],
    pool: &AegisWireGuardAddressPool,
) -> Result<(), AegisHostWriteError> {
    if host.wireguard_public_key.is_none() {
        return match (
            host.wireguard_ipv4.as_deref(),
            host.wireguard_ipv6.as_deref(),
        ) {
            (None, None) => Ok(()),
            (Some(_), Some(_)) => Err(AegisHostWriteError::InvalidWireguardIdentity(
                "wireguard_public_key is required when wireguard addresses are assigned"
                    .to_string(),
            )),
            _ => Err(AegisHostWriteError::InvalidWireguardIdentity(
                "wireguard identities must include both IPv4 and IPv6 when present".to_string(),
            )),
        };
    }
    match (
        host.wireguard_ipv4.as_deref(),
        host.wireguard_ipv6.as_deref(),
    ) {
        (Some(wireguard_ipv4), Some(wireguard_ipv6)) => {
            wireguard_host_identity_from_addresses(pool, wireguard_ipv4, wireguard_ipv6)
                .map_err(map_wireguard_address_error)?;
            return Ok(());
        }
        (None, None) => {}
        _ => {
            return Err(AegisHostWriteError::InvalidWireguardIdentity(
                "wireguard identities must include both IPv4 and IPv6 when present".to_string(),
            ));
        }
    }
    if let Some(existing) = existing
        && let (Some(wireguard_ipv4), Some(wireguard_ipv6)) = (
            existing.wireguard_ipv4.as_ref(),
            existing.wireguard_ipv6.as_ref(),
        )
        && host_wireguard_identity(existing, pool)?.is_some()
    {
        host.wireguard_ipv4 = Some(wireguard_ipv4.clone());
        host.wireguard_ipv6 = Some(wireguard_ipv6.clone());
        return Ok(());
    }

    let host_id = allocate_lowest_free_wireguard_peer_id(peers, pool)?;
    host.wireguard_ipv4 =
        Some(wireguard_ipv4_for_host_id(pool, host_id).map_err(map_wireguard_address_error)?);
    host.wireguard_ipv6 =
        Some(wireguard_ipv6_for_host_id(pool, host_id).map_err(map_wireguard_address_error)?);
    Ok(())
}

pub(crate) fn maybe_allocate_internal_addresses(
    host: &mut AegisNetworkMemberRecord,
    existing: Option<&AegisNetworkMemberRecord>,
    peers: &[AegisNetworkMemberRecord],
    mesh: &aegis_types::v1::AegisMeshConfig,
) -> Result<(), AegisHostWriteError> {
    if let Some(existing) = existing
        && let (Some(ipv4), Some(ipv6)) = (&existing.internal_ipv4, &existing.internal_ipv6)
    {
        host.internal_ipv4 = Some(ipv4.clone());
        host.internal_ipv6 = Some(ipv6.clone());
        return Ok(());
    }
    match (
        host.wireguard_ipv4.as_ref(),
        host.wireguard_ipv6.as_ref(),
        host.wireguard_public_key.as_ref(),
    ) {
        (Some(_), Some(_), Some(_)) => {
            let internal = allocate_default_internal_addresses(host, existing, peers, mesh)?;
            host.internal_ipv4 = Some(internal.ipv4);
            host.internal_ipv6 = Some(internal.ipv6);
        }
        _ => {
            host.internal_ipv4 = None;
            host.internal_ipv6 = None;
        }
    }
    Ok(())
}

fn allocate_lowest_free_wireguard_peer_id(
    peers: &[AegisNetworkMemberRecord],
    pool: &AegisWireGuardAddressPool,
) -> Result<u16, AegisHostWriteError> {
    let used = peers.iter().filter_map(|peer| {
        let _identity = host_wireguard_identity(peer, pool).ok()??;
        Some((
            peer.wireguard_ipv4.as_deref()?,
            peer.wireguard_ipv6.as_deref()?,
        ))
    });
    allocate_lowest_free_wireguard_host_id(pool, used).map_err(map_wireguard_address_error)
}

fn allocate_default_internal_addresses(
    host: &AegisNetworkMemberRecord,
    existing: Option<&AegisNetworkMemberRecord>,
    peers: &[AegisNetworkMemberRecord],
    mesh: &aegis_types::v1::AegisMeshConfig,
) -> Result<aegis_types::v1::AegisNetworkMemberInternalAddresses, AegisHostWriteError> {
    let mesh_ipv4 = parse_ipv4_subnet(&mesh.subnet_ipv4)?;
    let mesh_ipv6 = parse_ipv6_subnet(&mesh.subnet_ipv6)?;
    let wireguard_ipv4 = parse_ipv4_subnet(&mesh.wireguard_subnet_ipv4)?;
    let wireguard_ipv6 = parse_ipv6_subnet(&mesh.wireguard_subnet_ipv6)?;
    let mut used = BTreeSet::new();
    for peer in peers {
        if existing.is_some_and(|existing| peer.host_id == existing.host_id) {
            continue;
        }
        if let Some(wireguard_ipv4) = peer.wireguard_ipv4.as_ref() {
            used.insert(wireguard_ipv4.clone());
        }
        if let Some(wireguard_ipv6) = peer.wireguard_ipv6.as_ref() {
            used.insert(wireguard_ipv6.clone());
        }
        if let Some(internal_ipv4) = peer.internal_ipv4.as_ref() {
            used.insert(internal_ipv4.clone());
        }
        if let Some(internal_ipv6) = peer.internal_ipv6.as_ref() {
            used.insert(internal_ipv6.clone());
        }
    }
    if let Some(wireguard_ipv4) = host.wireguard_ipv4.as_ref() {
        used.insert(wireguard_ipv4.clone());
    }
    if let Some(wireguard_ipv6) = host.wireguard_ipv6.as_ref() {
        used.insert(wireguard_ipv6.clone());
    }

    let mesh_ipv4_base = u32::from(mesh_ipv4.0);
    let mesh_ipv6_base = u128::from(mesh_ipv6.0);
    for host_id in 1..u16::MAX {
        let candidate_ipv4 = Ipv4Addr::from(mesh_ipv4_base + u32::from(host_id));
        let candidate_ipv6 = Ipv6Addr::from(mesh_ipv6_base + u128::from(host_id));
        if !is_default_internal_ipv4(mesh_ipv4, wireguard_ipv4, candidate_ipv4) {
            continue;
        }
        if !is_default_internal_ipv6(mesh_ipv6, wireguard_ipv6, candidate_ipv6) {
            continue;
        }
        let candidate_ipv4 = candidate_ipv4.to_string();
        let candidate_ipv6 = candidate_ipv6.to_string();
        if used.contains(&candidate_ipv4) || used.contains(&candidate_ipv6) {
            continue;
        }
        return Ok(aegis_types::v1::AegisNetworkMemberInternalAddresses {
            ipv4: candidate_ipv4,
            ipv6: candidate_ipv6,
        });
    }

    Err(AegisHostWriteError::NoAvailableInternalIp {
        subnet_ipv4: mesh.subnet_ipv4.clone(),
        subnet_ipv6: mesh.subnet_ipv6.clone(),
    })
}

fn parse_ipv4_subnet(cidr: &str) -> Result<(Ipv4Addr, u8), AegisHostWriteError> {
    let (address, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| AegisHostWriteError::InvalidWireguardIdentity(cidr.to_string()))?;
    let address = address
        .parse::<Ipv4Addr>()
        .map_err(|_| AegisHostWriteError::InvalidWireguardIdentity(cidr.to_string()))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| AegisHostWriteError::InvalidWireguardIdentity(cidr.to_string()))?;
    if prefix > 32 {
        return Err(AegisHostWriteError::InvalidWireguardIdentity(
            cidr.to_string(),
        ));
    }
    Ok((address, prefix))
}

fn parse_ipv6_subnet(cidr: &str) -> Result<(Ipv6Addr, u8), AegisHostWriteError> {
    let (address, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| AegisHostWriteError::InvalidWireguardIdentity(cidr.to_string()))?;
    let address = address
        .parse::<Ipv6Addr>()
        .map_err(|_| AegisHostWriteError::InvalidWireguardIdentity(cidr.to_string()))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| AegisHostWriteError::InvalidWireguardIdentity(cidr.to_string()))?;
    if prefix > 128 {
        return Err(AegisHostWriteError::InvalidWireguardIdentity(
            cidr.to_string(),
        ));
    }
    Ok((address, prefix))
}

fn ipv4_in_subnet((network, prefix): (Ipv4Addr, u8), address: Ipv4Addr) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    (u32::from(network) & mask) == (u32::from(address) & mask)
}

fn ipv6_in_subnet((network, prefix): (Ipv6Addr, u8), address: Ipv6Addr) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    };
    (u128::from(network) & mask) == (u128::from(address) & mask)
}

fn map_wireguard_address_error(error: WireGuardAddressError) -> AegisHostWriteError {
    match error {
        WireGuardAddressError::NoAvailableHostId {
            subnet_ipv4,
            subnet_ipv6,
        } => AegisHostWriteError::NoAvailableWireguardHostId {
            subnet_ipv4,
            subnet_ipv6,
        },
        error => AegisHostWriteError::InvalidWireguardIdentity(error.to_string()),
    }
}

fn firestore_document_id(document_name: &str) -> Option<&str> {
    document_name
        .rsplit('/')
        .next()
        .filter(|segment| !segment.is_empty())
}

fn host_id_from_document_name(document_name: &str) -> anyhow::Result<HostId> {
    let document_id = firestore_document_id(document_name)
        .ok_or_else(|| anyhow::anyhow!("malformed Firestore document name `{document_name}`"))?;
    document_id
        .parse()
        .with_context(|| format!("Firestore document `{document_name}` has an invalid host id"))
}

fn deserialize_aegis_host_documents(
    docs: Vec<FirestoreDocument>,
) -> anyhow::Result<Vec<AegisHostRecord>> {
    docs.into_iter()
        .map(deserialize_aegis_host_document)
        .collect()
}

fn deserialize_aegis_host_document(doc: FirestoreDocument) -> anyhow::Result<AegisHostRecord> {
    let host_id = host_id_from_document_name(&doc.name)?;
    let stored = deserialize_stored_document::<StoredAegisHostRecord>(&doc)?;
    domain_aegis_host_record_from_stored(host_id, stored)
}

fn deserialize_aegis_network_member_documents(
    docs: Vec<FirestoreDocument>,
) -> anyhow::Result<Vec<AegisNetworkMemberRecord>> {
    docs.into_iter()
        .map(deserialize_aegis_network_member_document)
        .collect()
}

fn deserialize_aegis_network_member_document(
    doc: FirestoreDocument,
) -> anyhow::Result<AegisNetworkMemberRecord> {
    let host_id = host_id_from_document_name(&doc.name)?;
    let stored = deserialize_stored_document::<StoredAegisNetworkMemberRecord>(&doc)?;
    Ok(domain_aegis_network_member_from_stored(host_id, stored))
}

#[cfg(test)]
#[path = "firestore/namespace_tests.rs"]
mod namespace_tests;

fn map_direct_write_internal_error(error: anyhow::Error) -> AegisDirectWriteError {
    if is_firestore_data_conflict(&error) {
        AegisDirectWriteError::ConcurrentWrite
    } else {
        AegisDirectWriteError::Internal(error)
    }
}

fn is_default_internal_ipv4(
    mesh_subnet: (Ipv4Addr, u8),
    wireguard_subnet: (Ipv4Addr, u8),
    address: Ipv4Addr,
) -> bool {
    ipv4_in_subnet(mesh_subnet, address) && !ipv4_in_subnet(wireguard_subnet, address)
}

fn is_default_internal_ipv6(
    mesh_subnet: (Ipv6Addr, u8),
    wireguard_subnet: (Ipv6Addr, u8),
    address: Ipv6Addr,
) -> bool {
    ipv6_in_subnet(mesh_subnet, address) && !ipv6_in_subnet(wireguard_subnet, address)
}

fn tls_dns_constraint(ca: &TlsCaConfig) -> anyhow::Result<String> {
    use x509_parser::extensions::GeneralName;
    let (_, pem) = parse_x509_pem(ca.certificate_pem.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid CA PEM"))?;
    let cert = pem.parse_x509()?;
    let constraints = cert
        .name_constraints()?
        .ok_or_else(|| anyhow::anyhow!("CA must have a DNS name constraint"))?;
    let permitted = constraints
        .value
        .permitted_subtrees
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("CA requires a permitted DNS subtree"))?;
    anyhow::ensure!(
        permitted.len() == 1,
        "CA must have exactly one permitted DNS subtree"
    );
    match &permitted[0].base {
        GeneralName::DNSName(name) => Ok(name.trim_start_matches('.').to_string()),
        _ => anyhow::bail!("CA constraint must be a DNS subtree"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::v1::AegisHostMessageLevel;
    use firestore::FirestoreValue;
    use firestore::errors::{FirestoreDataConflictError, FirestoreErrorPublicGenericDetails};
    use x509_parser::{extensions::X509Extension, prelude::FromDer};
    fn test_host_id(index: u64) -> HostId {
        format!("00000000-0000-4000-8000-{index:012x}")
            .parse()
            .expect("test host id should parse")
    }

    fn test_aliases(primary: &str) -> HostAliases {
        HostAliases::new(vec![primary.parse().expect("test host alias should parse")])
            .expect("test host aliases should be valid")
    }

    #[test]
    fn firestore_document_id_uses_last_path_segment() {
        assert_eq!(
            Some("abc123"),
            firestore_document_id(
                "projects/p/databases/(default)/documents/v2/auth/oauth/config/flows/authorization_code/login_sessions/abc123"
            )
        );
        assert_eq!(None, firestore_document_id(""));
        assert_eq!(None, firestore_document_id("projects/p/documents/"));
    }

    #[test]
    fn aegis_config_requires_the_exact_host_identity_schema() {
        assert!(serde_json::from_value::<NamespaceDefinition>(serde_json::json!({})).is_err());
        let stored: NamespaceDefinition = serde_json::from_value(serde_json::json!({
            "host_identity_schema": "wrong"
        }))
        .expect("schema field should deserialize");
        assert!(
            stored
                .validate()
                .expect_err("wrong schema should fail before other config validation")
                .to_string()
                .contains("host_identity_schema")
        );
    }

    #[test]
    fn firestore_payloads_never_serialize_document_identity() {
        let gateway = AegisDirectGatewayRecord {
            host_id: test_host_id(1),
            wireguard: AegisDirectWireGuardRecord {
                public_key: "key".to_string(),
                ipv4: "10.77.1.1".to_string(),
                ipv6: "fd77::1:1".to_string(),
                endpoints: vec!["203.0.113.8".to_string()],
            },
            created_unix: 1,
            updated_unix: 2,
            updated_by_principal: "agent:hub-a".to_string(),
        };
        let encoded = serde_json::to_value(stored_direct_gateway(&gateway)).expect("serialize");
        assert!(encoded.get("slug").is_none());
        let decoded: StoredAegisDirectGateway =
            serde_json::from_value(encoded).expect("deserialize");
        assert_eq!(
            test_host_id(2),
            domain_direct_gateway(test_host_id(2), decoded).host_id
        );

        let satellite = AegisSatelliteRecord {
            slug: "pocket-a".to_string(),
            credential_id: "credential-a".to_string(),
            owner_principal: "owner-1".to_string(),
            wireguard: gateway.wireguard.clone(),
            ssh_public_key: "ssh-ed25519 key".to_string(),
            created_unix: 1,
            created_by_principal: "owner-1".to_string(),
            broker_uses: BTreeMap::new(),
        };
        let encoded = serde_json::to_value(stored_satellite(&satellite)).expect("serialize");
        assert!(encoded.get("slug").is_none());
        assert_eq!(Some(&serde_json::json!({})), encoded.get("broker_uses"));
        let mut incomplete = encoded.clone();
        incomplete
            .as_object_mut()
            .expect("stored satellite is an object")
            .remove("broker_uses");
        assert!(serde_json::from_value::<StoredAegisSatellite>(incomplete).is_err());
        let decoded: StoredAegisSatellite = serde_json::from_value(encoded).expect("deserialize");
        assert_eq!("document-id", domain_satellite("document-id", decoded).slug);

        let lease = AegisDirectLeaseRecord {
            id: "pocket-a".to_string(),
            wireguard: gateway.wireguard.clone(),
        };
        let encoded = serde_json::to_value(stored_direct_lease(&lease)).expect("serialize");
        assert!(encoded.get("id").is_none());
        assert!(encoded.get("kind").is_none());
        let mut obsolete = encoded.clone();
        obsolete
            .as_object_mut()
            .expect("stored direct lease is an object")
            .insert("kind".to_string(), serde_json::json!("satellite"));
        assert!(serde_json::from_value::<StoredAegisDirectLease>(obsolete).is_err());
        let decoded: StoredAegisDirectLease = serde_json::from_value(encoded).expect("deserialize");
        assert_eq!(
            "document-id",
            domain_direct_lease("document-id", decoded).id
        );

        let host = AegisHostRecord {
            host_id: test_host_id(3),
            aliases: test_aliases("host-a"),
            ssh: None,
            egress_public_key: None,
            messages: Vec::new(),
            agent: None,
            principal_grants: Vec::new(),
            ssh_lockdown_enabled: None,
            direct_gateway_report: None,
            observed_public_ips: AegisObservedPublicIps::default(),
            transient: false,
            pending: false,
            created_unix: 1,
            updated_unix: 2,
            updated_by_principal: "operator".to_string(),
        };
        let encoded =
            serde_json::to_value(stored_aegis_host_record_from_domain(&host)).expect("serialize");
        assert!(encoded.get("slug").is_none());
    }

    #[test]
    fn generate_open_ssh_private_key_pem_returns_parseable_openssh_key() {
        let pem = generate_open_ssh_private_key_pem().expect("key generation should succeed");
        let parsed =
            PrivateKey::from_openssh(&pem).expect("generated OpenSSH private key should parse");

        assert_eq!(Algorithm::Ed25519, parsed.algorithm());
    }

    #[test]
    fn default_client_ca_document_generates_parseable_key_and_ttl() {
        let stored = default_client_ca_document().expect("default client ca should generate");

        let private_key_pem = stored
            .private_key_pem
            .expect("default client ca should include private_key_pem");
        let parsed =
            PrivateKey::from_openssh(&private_key_pem).expect("generated OpenSSH key should parse");

        assert_eq!(Algorithm::Ed25519, parsed.algorithm());
        assert_eq!(None, stored.passphrase);
        assert_eq!(
            Some(DEFAULT_CLIENT_CERT_TTL_SECONDS),
            stored.cert_ttl_seconds
        );
    }

    #[test]
    fn default_server_ca_document_generates_parseable_key_and_ttl() {
        let stored = default_server_ca_document().expect("default server ca should generate");

        let private_key_pem = stored
            .private_key_pem
            .expect("default server ca should include private_key_pem");
        let parsed =
            PrivateKey::from_openssh(&private_key_pem).expect("generated OpenSSH key should parse");

        assert_eq!(Algorithm::Ed25519, parsed.algorithm());
        assert_eq!(None, stored.passphrase);
        assert_eq!(
            Some(DEFAULT_SERVER_CERT_TTL_SECONDS),
            stored.cert_ttl_seconds
        );
    }

    #[test]
    fn tls_ca_and_service_certificate_generation_uses_service_public_key() {
        let root = validate_tls_ca_config(
            "v2/aegis/tls/config/cas/root",
            default_tls_root_ca_document("x.hoek.io").expect("root CA should generate"),
        )
        .expect("root CA should validate");
        let issuing_document = default_tls_issuing_ca_document(&root, "https://aegis.example/v2")
            .expect("issuing CA should generate");
        let issuing =
            validate_tls_ca_config("v2/aegis/tls/config/cas/issuing", issuing_document.clone())
                .expect("issuing CA should validate");
        assert_tls_certificate_issuer(&issuing.certificate_pem, &root.certificate_pem);
        assert_tls_crl_issuer(
            issuing_document
                .crl_pem
                .as_deref()
                .expect("issuing CA should include CRL"),
            &issuing.certificate_pem,
        );

        let service_key = KeyPair::generate().expect("service key should generate");
        let cert = TlsCertRecord {
            label: "crates".to_string(),
            dns_names: vec!["crates.x.hoek.io".to_string()],
            host_id: test_host_id(1),
            public_key_pem: Some(service_key.public_key_pem()),
            certificate_chain_pem: None,
            serial_number: None,
            issued_unix: None,
            not_after_unix: None,
        };
        let issued = issue_tls_certificate(&cert, &issuing, "https://aegis.example/v2")
            .expect("certificate should issue");
        let chain = issued
            .certificate_chain_pem
            .expect("issued cert should include chain");

        assert_eq!(2, chain.matches("-----BEGIN CERTIFICATE-----").count());
        assert!(chain.ends_with(&issuing.certificate_pem));
        assert_tls_certificate_issuer(&chain, &issuing.certificate_pem);
        assert_eq!(Some(vec!["crates.x.hoek.io".to_string()]), issued.dns_names);
        assert_eq!(Some(service_key.public_key_pem()), issued.public_key_pem);
    }

    fn authority_key_identifier(extensions: &[X509Extension<'_>]) -> Vec<u8> {
        let identifiers = extensions
            .iter()
            .filter_map(|extension| match extension.parsed_extension() {
                ParsedExtension::AuthorityKeyIdentifier(authority) => Some(
                    authority
                        .key_identifier
                        .as_ref()
                        .expect("authority must identify its signing key")
                        .0
                        .to_vec(),
                ),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            1,
            identifiers.len(),
            "exactly one authority key identifier is required"
        );
        identifiers
            .into_iter()
            .next()
            .expect("authority key identifier")
    }

    fn assert_tls_certificate_issuer(certificate_pem: &str, issuer_pem: &str) {
        let (_, certificate_pem) =
            parse_x509_pem(certificate_pem.as_bytes()).expect("certificate PEM");
        let certificate = certificate_pem.parse_x509().expect("certificate DER");
        let (_, issuer_certificate) = parse_x509_pem(issuer_pem.as_bytes()).expect("issuer PEM");
        let issuer = issuer_certificate.parse_x509().expect("issuer DER");
        assert_eq!(issuer.subject(), certificate.issuer());
        assert_eq!(
            tls_ca_subject_key_identifier(issuer_pem).expect("issuer subject key identifier"),
            authority_key_identifier(certificate.extensions()),
        );
    }

    fn assert_tls_crl_issuer(crl_pem: &str, issuer_pem: &str) {
        let (_, pem) = parse_x509_pem(crl_pem.as_bytes()).expect("CRL PEM");
        let (_, crl) =
            x509_parser::revocation_list::CertificateRevocationList::from_der(&pem.contents)
                .expect("CRL DER");
        let (_, issuer_certificate) = parse_x509_pem(issuer_pem.as_bytes()).expect("issuer PEM");
        let issuer = issuer_certificate.parse_x509().expect("issuer DER");
        assert_eq!(issuer.subject(), crl.issuer());
        assert_eq!(
            tls_ca_subject_key_identifier(issuer_pem).expect("issuer subject key identifier"),
            authority_key_identifier(crl.extensions()),
        );
    }

    #[test]
    fn tls_signing_preserves_existing_ca_names_and_subject_key_identifiers() {
        let root_key = KeyPair::generate().expect("root key");
        let mut root_params = tls_root_ca_params("x.hoek.io");
        root_params.distinguished_name = tls_ca_distinguished_name("Existing namespace root");
        root_params.key_identifier_method = rcgen::KeyIdMethod::PreSpecified(vec![0xa5; 20]);
        let root = TlsCaConfig {
            certificate_pem: root_params
                .self_signed(&root_key)
                .expect("root certificate")
                .pem(),
            private_key_pem: root_key.serialize_pem(),
        };
        let api_issuer = "https://api.example.test/v2/namespaces/example";
        let generated = default_tls_issuing_ca_document(&root, api_issuer)
            .expect("issuing certificate from existing root");
        assert_tls_certificate_issuer(
            generated
                .certificate_pem
                .as_deref()
                .expect("issuing certificate"),
            &root.certificate_pem,
        );

        let issuing_key = KeyPair::generate().expect("issuing key");
        let mut issuing_params = tls_issuing_ca_params("x.hoek.io");
        issuing_params.distinguished_name = tls_ca_distinguished_name("Existing namespace issuer");
        issuing_params.key_identifier_method = rcgen::KeyIdMethod::PreSpecified(vec![0x5a; 20]);
        let issuer =
            Issuer::from_ca_cert_pem(&root.certificate_pem, root_key).expect("root issuer");
        let issuing = TlsCaConfig {
            certificate_pem: issuing_params
                .signed_by(&issuing_key, &issuer)
                .expect("issuing certificate")
                .pem(),
            private_key_pem: issuing_key.serialize_pem(),
        };
        let service_key = KeyPair::generate().expect("service key");
        let service = TlsCertRecord {
            label: "crates".to_string(),
            dns_names: vec!["crates.x.hoek.io".to_string()],
            host_id: test_host_id(1),
            public_key_pem: Some(service_key.public_key_pem()),
            certificate_chain_pem: None,
            serial_number: None,
            issued_unix: None,
            not_after_unix: None,
        };
        let issued =
            issue_tls_certificate(&service, &issuing, api_issuer).expect("service certificate");
        let chain = issued
            .certificate_chain_pem
            .expect("service certificate chain");
        assert!(chain.ends_with(&issuing.certificate_pem));
        assert_tls_certificate_issuer(&chain, &issuing.certificate_pem);
        let crl = empty_tls_crl_pem(&issuing, api_issuer).expect("CRL from existing issuer");
        assert_tls_crl_issuer(&crl, &issuing.certificate_pem);
    }

    #[test]
    fn tls_desired_state_is_authoritative_and_rejects_duplicate_labels() {
        let desired = AegisTlsDesiredState {
            certificates: vec![aegis_types::v1::AegisTlsCertificateConfig {
                label: " crates ".to_string(),
                host_id: test_host_id(1),
                dns_names: vec!["crates.x.hoek.io".to_string()],
            }],
        };
        let normalized =
            normalized_tls_desired_state(&desired).expect("desired state should validate");
        assert_eq!(
            vec!["crates"],
            normalized.keys().map(String::as_str).collect::<Vec<_>>()
        );

        let mut duplicate = desired;
        duplicate
            .certificates
            .push(aegis_types::v1::AegisTlsCertificateConfig {
                label: "crates".to_string(),
                host_id: test_host_id(2),
                dns_names: vec!["other.x.hoek.io".to_string()],
            });
        assert!(
            normalized_tls_desired_state(&duplicate)
                .expect_err("duplicate labels must be rejected")
                .to_string()
                .contains("declared more than once")
        );
    }

    #[test]
    fn stored_aegis_records_keep_global_and_network_state_separate() {
        let host = AegisHostRecord {
            host_id: test_host_id(1),
            aliases: test_aliases("leaf-01"),
            ssh: Some(AegisHostRecordSsh {
                port: Some(22),
                public_key: Some("ssh-ed25519 AAAA".to_string()),
                external_principals: vec!["leaf-01.example".to_string()],
            }),
            egress_public_key: None,
            messages: vec![AegisHostMessage {
                level: AegisHostMessageLevel::Warning,
                value: "Bird3 apt source is misconfigured".to_string(),
            }],
            agent: None,
            principal_grants: vec![AegisPrincipalGrant {
                login_principal: "khoek".to_string(),
                oauth_principal: "user-1".to_string(),
            }],
            ssh_lockdown_enabled: None,
            direct_gateway_report: None,
            observed_public_ips: AegisObservedPublicIps::default(),
            transient: true,
            pending: false,
            created_unix: 100,
            updated_unix: 200,
            updated_by_principal: "deus@hoek.io".to_string(),
        };

        let stored = stored_aegis_host_record_from_domain(&host);
        let value = serde_json::to_value(&stored).expect("stored host should serialize");

        assert!(value.get("mode").is_none());
        assert!(value.get("wireguard").is_none());
        assert!(value.get("internal").is_none());
        assert!(value.get("messages").is_none());
        assert_eq!(
            Some(&serde_json::json!({
                "messages": [{"level": "warning", "msg": "Bird3 apt source is misconfigured"}],
                "principal_grants": [{
                    "login_principal": "khoek",
                    "oauth_principal": "user-1"
                }]
            })),
            value.get("report")
        );
        let mut document = FirestoreDb::serialize_to_doc(
            format!(
                "projects/p/databases/(default)/documents/v2/aegis/hosts/{}",
                host.host_id
            ),
            &stored,
        )
        .expect("stored host should serialize as a Firestore document");
        document.update_time = Some(gcloud_sdk::prost_types::Timestamp {
            seconds: 1,
            nanos: 0,
        });
        assert_eq!(
            host,
            deserialize_aegis_host_document(document)
                .expect("host list decoding must exclude Firestore metadata")
        );

        let member = AegisNetworkMemberRecord {
            host_id: host.host_id,
            mode: AegisHostMode::Leaf,
            wireguard_public_key: Some("peer-public-key".to_string()),
            wireguard_ipv4: Some("10.75.1.2".to_string()),
            wireguard_ipv6: Some("fd75::1:2".to_string()),
            wireguard_endpoints: vec!["203.0.113.10".to_string()],
            internal_ipv4: Some("10.75.0.10".to_string()),
            internal_ipv6: Some("fd75::10".to_string()),
            pending: false,
            created_unix: 100,
            updated_unix: 200,
            updated_by_principal: "deus@hoek.io".to_string(),
        };
        let stored = stored_aegis_network_member_from_domain(&member);
        let value = serde_json::to_value(&stored).expect("stored member should serialize");
        assert_eq!(
            Some(&serde_json::json!({
                "public_key": "peer-public-key",
                "ipv4": "10.75.1.2",
                "ipv6": "fd75::1:2",
                "endpoints": ["203.0.113.10"]
            })),
            value.get("wireguard")
        );
        assert_eq!(
            Some(&serde_json::json!({
                "unix": 200,
                "by_principal": "deus@hoek.io"
            })),
            value.get("updated")
        );
        assert!(value.get("ssh").is_none());
        assert!(value.get("report").is_none());
        assert!(value.get("transient").is_none());
        let mut document = FirestoreDb::serialize_to_doc(
            format!(
                "projects/p/databases/(default)/documents/v2/aegis/networks/aegis/members/{}",
                member.host_id
            ),
            &stored,
        )
        .expect("stored member should serialize as a Firestore document");
        document.update_time = Some(gcloud_sdk::prost_types::Timestamp {
            seconds: 1,
            nanos: 0,
        });
        assert_eq!(
            member,
            deserialize_aegis_network_member_document(document)
                .expect("network-member list decoding must exclude Firestore metadata")
        );
    }

    #[test]
    fn stored_aegis_records_reject_obsolete_split_schema_fields() {
        let host = serde_json::json!({
            "report": {},
            "transient": false,
            "pending": false,
            "created_unix": 100,
            "updated": {"unix": 200, "by_principal": "deus@hoek.io"},
            "mode": "leaf"
        });
        assert!(serde_json::from_value::<StoredAegisHostRecord>(host).is_err());

        let member = serde_json::json!({
            "mode": "leaf",
            "pending": false,
            "created_unix": 100,
            "updated": {"unix": 200, "by_principal": "deus@hoek.io"},
            "messages": []
        });
        assert!(serde_json::from_value::<StoredAegisNetworkMemberRecord>(member).is_err());

        let nested_ssh = serde_json::json!({
            "ssh": {"server_cert_principals": []},
            "report": {},
            "transient": false,
            "pending": false,
            "created_unix": 100,
            "updated": {"unix": 200, "by_principal": "deus@hoek.io"}
        });
        assert!(serde_json::from_value::<StoredAegisHostRecord>(nested_ssh).is_err());

        let tls = serde_json::json!({
            "dns_names": ["alpha.example"],
            "host_id": test_host_id(1),
            "host_slug": "alpha"
        });
        assert!(serde_json::from_value::<StoredTlsCertConfig>(tls).is_err());
    }

    #[test]
    fn stored_document_decode_excludes_firestore_metadata_but_rejects_stored_drift() {
        let state = StoredAegisEgressState::default();
        let mut document = FirestoreDb::serialize_to_doc(
            "projects/p/databases/(default)/documents/v2/aegis/state/egress",
            &state,
        )
        .expect("egress state should serialize as a Firestore document");
        document.update_time = Some(gcloud_sdk::prost_types::Timestamp {
            seconds: 1,
            nanos: 0,
        });

        FirestoreDb::deserialize_doc_to::<StoredAegisEgressState>(&document)
            .expect_err("the generic Firestore decoder injects synthetic metadata");

        let decoded = deserialize_stored_document::<StoredAegisEgressState>(&document)
            .expect("Firestore metadata should remain outside the stored domain record");
        assert_eq!(0, decoded.generation);
        assert!(decoded.policies.is_empty());

        document.fields.insert(
            "unexpected".to_string(),
            Into::<FirestoreValue>::into(true).value,
        );
        deserialize_stored_document::<StoredAegisEgressState>(&document)
            .expect_err("unknown stored fields must still be rejected");
    }

    #[test]
    fn is_firestore_data_conflict_detects_conflict_errors() {
        let error = fake_firestore_conflict_error();

        assert!(is_firestore_data_conflict(&error));
        assert!(!is_firestore_data_conflict(&anyhow::anyhow!(
            "not a conflict"
        )));
    }

    #[test]
    fn maybe_allocate_wireguard_identity_preserves_existing_peer_address() {
        let mesh = aegis_types::v1::AegisMeshConfig {
            endpoint_port: 51820,
            overlay_mtu: 1350,
            subnet_ipv4: "10.75.0.0/16".to_string(),
            subnet_ipv6: "fd75::/64".to_string(),
            wireguard_subnet_ipv4: "10.75.1.0/24".to_string(),
            wireguard_subnet_ipv6: "fd75::1:0/120".to_string(),
            host_dns_suffix: None,
        };
        let existing = AegisNetworkMemberRecord {
            host_id: test_host_id(1),
            mode: AegisHostMode::Leaf,
            wireguard_public_key: Some("peer-public-key".to_string()),
            wireguard_ipv4: Some("10.75.1.1".to_string()),
            wireguard_ipv6: Some("fd75::1:1".to_string()),
            wireguard_endpoints: Vec::new(),
            internal_ipv4: None,
            internal_ipv6: None,
            pending: false,
            created_unix: 0,
            updated_unix: 0,
            updated_by_principal: "deus@hoek.io".to_string(),
        };
        let mut host = AegisNetworkMemberRecord {
            wireguard_ipv4: None,
            wireguard_ipv6: None,
            ..existing.clone()
        };

        let wireguard_pool = mesh.wireguard_address_pool();
        maybe_allocate_wireguard_identity(
            &mut host,
            Some(&existing),
            std::slice::from_ref(&existing),
            &wireguard_pool,
        )
        .expect("existing peer address should be preserved");

        assert_eq!(Some("10.75.1.1"), host.wireguard_ipv4.as_deref());
        assert_eq!(Some("fd75::1:1"), host.wireguard_ipv6.as_deref());
    }

    fn fake_firestore_conflict_error() -> anyhow::Error {
        anyhow::Error::new(FirestoreError::DataConflictError(
            FirestoreDataConflictError::new(
                FirestoreErrorPublicGenericDetails::new("AlreadyExists".to_string()),
                "already exists".to_string(),
            ),
        ))
    }
}
