use aegis_types::{NamespaceId, configuration::TlsCaConfig};
use anyhow::Context;
use arche_firestore::{
    Db, create_typed_at, is_firestore_data_conflict, load_optional_typed_at, normalized_text,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DistinguishedName,
    DnType, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose, NameConstraints, PublicKeyData,
    SerialNumber,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use ssh_key::{Algorithm, LineEnding, PrivateKey, rand_core::OsRng};
use time::{Duration as TlsDuration, OffsetDateTime as TlsDateTime};
use x509_parser::{
    extensions::ParsedExtension, oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER,
    pem::parse_x509_pem,
};
const DEFAULT_CLIENT_CERT_TTL_SECONDS: u64 = 31_557_600_000;
const DEFAULT_SERVER_CERT_TTL_SECONDS: u64 = 31_557_600_000;
const TLS_CA_ORGANIZATION: &str = "Aegis";
const TLS_ROOT_CA_COMMON_NAME: &str = "aegis Root CA R1";
const TLS_SIGNING_CA_COMMON_NAME: &str = "aegis Signing CA S1";
const TLS_VALIDITY_DAYS: i64 = 365_000;
const TLS_CRL_NUMBER: u64 = 1;

pub(super) struct AuthorityOptions<'a> {
    pub namespace: &'a NamespaceId,
    pub issuer: &'a str,
    pub dns_suffix: &'a str,
}

pub(super) async fn initialize(db: &Db, options: AuthorityOptions<'_>) -> anyhow::Result<()> {
    let AuthorityOptions {
        namespace,
        issuer,
        dns_suffix: suffix,
    } = options;
    let parent = format!(
        "{}/v2/aegis/namespaces/{namespace}",
        db.inner().get_documents_path()
    );
    let user: StoredClientCaConfig = ensure(
        db,
        &format!("{parent}/ssh/config/cas/user"),
        default_client_ca_document,
    )
    .await?;
    let direct: StoredDirectClientCaConfig = ensure(
        db,
        &format!("{parent}/ssh/config/cas/direct"),
        default_direct_client_ca_document,
    )
    .await?;
    let host: StoredServerCaConfig = ensure(
        db,
        &format!("{parent}/ssh/config/cas/host"),
        default_server_ca_document,
    )
    .await?;
    for key in [
        &user.private_key_pem,
        &direct.private_key_pem,
        &host.private_key_pem,
    ] {
        PrivateKey::from_openssh(key.as_deref().context("existing SSH CA has no key")?)?;
    }
    let root: StoredTlsCaConfig = ensure(db, &format!("{parent}/tls/config/cas/root"), || {
        default_tls_root_ca_document(suffix)
    })
    .await?;
    let root = validate_tls_ca_config("root", root)?;
    anyhow::ensure!(
        tls_dns_constraint(&root)? == suffix,
        "existing CA has a different DNS constraint; keys retained"
    );
    let issuing: StoredTlsCaConfig =
        ensure(db, &format!("{parent}/tls/config/cas/issuing"), || {
            default_tls_issuing_ca_document(&root, issuer)
        })
        .await?;
    anyhow::ensure!(
        issuing.crl_pem.as_ref().is_some_and(|v| !v.is_empty()),
        "existing issuing CA has no CRL; operator repair required"
    );
    let issuing = validate_tls_ca_config("issuing", issuing)?;
    anyhow::ensure!(
        tls_dns_constraint(&issuing)? == suffix,
        "existing issuing CA has a different DNS constraint"
    );
    Ok(())
}

async fn ensure<T: Serialize + DeserializeOwned + Send + Sync>(
    db: &Db,
    path: &str,
    generate: impl Fn() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let (parent, id) = path.rsplit_once('/').context("invalid document path")?;
    let (parent, collection) = parent.rsplit_once('/').context("invalid collection path")?;
    for _ in 0..8 {
        if let Some(existing) = load_optional_typed_at(db.inner(), parent, collection, id).await? {
            return Ok(existing);
        }
        let value = generate()?;
        match create_typed_at(db.inner(), parent, collection, id, &value).await {
            Ok(()) => return Ok(value),
            Err(error) if is_firestore_data_conflict(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    anyhow::bail!("certificate initialization did not converge; existing documents retained")
}
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

fn default_client_ca_document() -> anyhow::Result<StoredClientCaConfig> {
    Ok(StoredClientCaConfig {
        private_key_pem: Some(generate_open_ssh_private_key_pem()?),
        passphrase: None,
        cert_ttl_seconds: Some(DEFAULT_CLIENT_CERT_TTL_SECONDS),
    })
}

fn default_direct_client_ca_document() -> anyhow::Result<StoredDirectClientCaConfig> {
    Ok(StoredDirectClientCaConfig {
        private_key_pem: Some(generate_open_ssh_private_key_pem()?),
        passphrase: None,
    })
}

fn default_server_ca_document() -> anyhow::Result<StoredServerCaConfig> {
    Ok(StoredServerCaConfig {
        private_key_pem: Some(generate_open_ssh_private_key_pem()?),
        passphrase: None,
        cert_ttl_seconds: Some(DEFAULT_SERVER_CERT_TTL_SECONDS),
    })
}

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

fn generate_open_ssh_private_key_pem() -> anyhow::Result<String> {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
    Ok(key.to_openssh(LineEnding::LF)?.to_string())
}

fn tls_root_ca_params(dns_suffix: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = tls_ca_distinguished_name(TLS_ROOT_CA_COMMON_NAME);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.name_constraints = Some(tls_name_constraints(dns_suffix));
    params
}

fn tls_issuing_ca_params(dns_suffix: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = tls_ca_distinguished_name(TLS_SIGNING_CA_COMMON_NAME);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.name_constraints = Some(tls_name_constraints(dns_suffix));
    params.use_authority_key_identifier_extension = true;
    params
}

fn tls_ca_distinguished_name(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::OrganizationName, TLS_CA_ORGANIZATION);
    name.push(DnType::CommonName, common_name);
    name
}

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

fn validate_tls_ca_config(path: &str, stored: StoredTlsCaConfig) -> anyhow::Result<TlsCaConfig> {
    let certificate_pem = normalized_text(stored.certificate_pem.as_ref())
        .ok_or_else(|| anyhow::anyhow!("{path}.certificate_pem is required"))?;
    let private_key_pem = normalized_text(stored.private_key_pem.as_ref())
        .ok_or_else(|| anyhow::anyhow!("{path}.private_key_pem is required"))?;
    let key = KeyPair::from_pem(private_key_pem)
        .map_err(|error| anyhow::anyhow!("{path}.private_key_pem failed to parse: {error}"))?;
    let (_, pem) = parse_x509_pem(certificate_pem.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid CA PEM"))?;
    let certificate = pem.parse_x509()?;
    anyhow::ensure!(
        certificate.is_ca() && certificate.public_key().raw == key.subject_public_key_info(),
        "{path} certificate and private key do not form a CA keypair"
    );
    Ok(TlsCaConfig {
        certificate_pem: certificate_pem.to_string(),
        private_key_pem: private_key_pem.to_string(),
    })
}
