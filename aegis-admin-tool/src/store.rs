//! Operator-only setup and account administration. These operations are never HTTP routes.
use super::identity::{self, LoginConfiguration};
use anyhow::Context;
use arche_firestore::{Db, create_typed_at, load_optional_typed_at};
use firestore::FirestoreTransactionOps;
use phylax_gcp::identity::{ExternalIdentity, IdentityBootstrapOptions, UserRecord};
use serde_json::{Value, json};

pub struct AdminOptions {
    pub project_id: String,
    pub database_id: String,
}
impl Default for AdminOptions {
    fn default() -> Self {
        Self {
            project_id: String::new(),
            database_id: "(default)".into(),
        }
    }
}
pub struct AdminConfig {
    project_id: String,
    database_id: String,
}
pub struct Admin {
    pub(super) db: Db,
}
impl AdminOptions {
    pub fn validate(self) -> anyhow::Result<AdminConfig> {
        anyhow::ensure!(
            !self.project_id.is_empty()
                && self
                    .project_id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-'),
            "invalid GCP project id"
        );
        arche_firestore::DatabaseOptions {
            project_id: Some(self.project_id.clone()),
            database_id: self.database_id.clone(),
            ..Default::default()
        }
        .validate()?;
        Ok(AdminConfig {
            database_id: self.database_id,
            project_id: self.project_id,
        })
    }
}
impl AdminConfig {
    pub async fn connect(self, access_token: String) -> anyhow::Result<Admin> {
        anyhow::ensure!(
            !access_token.trim().is_empty(),
            "local gcloud access token is required"
        );
        Ok(Admin {
            db: arche_firestore::DatabaseOptions {
                project_id: Some(self.project_id),
                database_id: self.database_id,
                credentials: arche_firestore::Credentials::AccessToken(access_token),
                ..Default::default()
            }
            .validate()?
            .connect()
            .await?,
        })
    }
}
pub struct SetupOptions {
    pub issuer_url: String,
    pub audience: String,
    pub login: LoginConfiguration,
}
pub struct SetupConfig {
    identity: phylax_gcp::identity::ValidatedIdentityBootstrap,
    login: LoginConfiguration,
}
impl SetupOptions {
    pub fn validate(self) -> anyhow::Result<SetupConfig> {
        self.login.validate()?;
        let endpoint = aegis_dto::namespace::ApiEndpoint::parse(&self.issuer_url)
            .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(
            endpoint.namespace().is_none()
                && self.issuer_url.starts_with("https://")
                && endpoint.service_url() == self.issuer_url,
            "issuer_url must be a canonical HTTPS service URL without a namespace"
        );
        anyhow::ensure!(
            self.login.redirect_uri == format!("{}/oauth/callback", endpoint.service_url()),
            "OIDC callback must be issuer_url/oauth/callback"
        );
        Ok(SetupConfig {
            identity: IdentityBootstrapOptions {
                issuer_url: self.issuer_url,
                audience: self.audience,
                ..Default::default()
            }
            .validate()?,
            login: self.login,
        })
    }
}

pub struct NamespaceOptions {
    pub namespace: aegis_dto::NamespaceId,
    pub configuration: Value,
    pub tls_dns_suffix: String,
}
pub struct NamespaceConfig {
    options: NamespaceOptions,
}
impl NamespaceOptions {
    pub fn validate(self) -> anyhow::Result<NamespaceConfig> {
        let config = serde_json::from_value::<aegis_dto::configuration::NamespaceDefinition>(
            self.configuration.clone(),
        )?
        .validate()?;
        config.validate()?;
        anyhow::ensure!(
            self.tls_dns_suffix.contains('.')
                && !self.tls_dns_suffix.starts_with('.')
                && self.tls_dns_suffix.split('.').all(|label| !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')),
            "TLS DNS suffix must be a lowercase DNS name"
        );
        Ok(NamespaceConfig { options: self })
    }
}
impl Admin {
    pub async fn setup(&self, config: SetupConfig) -> anyhow::Result<()> {
        let identity = identity::store(&self.db)?;
        identity.bootstrap(config.identity).await?;
        let result = async {
            let existing = load_optional_typed_at::<LoginConfiguration>(
                self.db.inner(),
                identity.parent(),
                "settings",
                "login",
            )
            .await?;
            if let Some(existing) = existing {
                anyhow::ensure!(
                    serde_json::to_value(existing)? == serde_json::to_value(&config.login)?,
                    "existing login configuration differs; setup never overwrites it"
                );
            } else {
                create_typed_at(
                    self.db.inner(),
                    identity.parent(),
                    "settings",
                    "login",
                    &config.login,
                )
                .await?;
            }
            identity.load_config().await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        result.context("identity key configuration retained; login setup may need repair")
    }
    pub async fn create_namespace(&self, config: NamespaceConfig) -> anyhow::Result<()> {
        let options = config.options;
        let identities = identity::store(&self.db)?;
        let identity = identities.load_config().await?;
        let issuer = aegis_dto::namespace::ApiEndpoint::parse(&identity.api_token.iss)
            .map_err(anyhow::Error::msg)?
            .with_namespace(options.namespace.clone())
            .base_url();
        let parent = format!("{}/v2/aegis", self.db.inner().get_documents_path());
        let existing = load_optional_typed_at::<Value>(
            self.db.inner(),
            &parent,
            "namespaces",
            options.namespace.as_str(),
        )
        .await?;
        if let Some(existing) = existing {
            anyhow::ensure!(
                existing == options.configuration,
                "namespace already exists with different configuration; refusing to overwrite fleet state"
            );
        } else {
            create_typed_at(
                self.db.inner(),
                &parent,
                "namespaces",
                options.namespace.as_str(),
                &options.configuration,
            )
            .await?;
        }
        super::certificates::initialize(
            &self.db,
            super::certificates::AuthorityOptions {
                namespace: &options.namespace,
                issuer: &issuer,
                dns_suffix: &options.tls_dns_suffix,
            },
        )
        .await
        .context(
            "namespace retained; certificate initialization may be partial; rerun setup to finish",
        )?;
        Ok(())
    }
    pub async fn add_user(&self, user: UserRecord, provider_subject: String) -> anyhow::Result<()> {
        let login = identity::load_login(&self.db).await?;
        identity::store(&self.db)?
            .create_user(
                &user,
                &ExternalIdentity {
                    provider: login.issuer_url,
                    provider_sub: provider_subject,
                    user_id: user.id.clone(),
                },
            )
            .await
    }
    pub async fn set_user_disabled(&self, user_id: &str, disabled: bool) -> anyhow::Result<()> {
        identity::store(&self.db)?
            .set_disabled(user_id, disabled)
            .await
    }
    pub async fn set_membership(
        &self,
        namespace: aegis_dto::NamespaceId,
        user_id: &str,
        role: Option<aegis_dto::NamespaceRole>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            identity::store(&self.db)?.user(user_id).await?.is_some(),
            "user does not exist"
        );
        let root = format!("{}/v2/aegis", self.db.inner().get_documents_path());
        anyhow::ensure!(
            load_optional_typed_at::<Value>(
                self.db.inner(),
                &root,
                "namespaces",
                namespace.as_str()
            )
            .await?
            .is_some(),
            "namespace does not exist"
        );
        let parent = format!("{root}/namespaces/{namespace}");
        let mut tx = self.db.inner().begin_transaction().await?;
        match role {
            Some(role) => {
                tx.update_object_at(
                    &parent,
                    "members",
                    user_id,
                    &aegis_dto::NamespaceMembership { role },
                    None,
                    None,
                    vec![],
                )?;
            }
            None => {
                tx.delete_by_id_at(&parent, "members", user_id, None)?;
            }
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn users(&self) -> anyhow::Result<Vec<UserRecord>> {
        let identities = identity::store(&self.db)?;
        let documents = self
            .db
            .inner()
            .fluent()
            .select()
            .from("users")
            .parent(identities.parent())
            .query()
            .await?;
        documents
            .iter()
            .map(arche_firestore::deserialize_stored_document)
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }
    pub async fn members(&self, namespace: aegis_dto::NamespaceId) -> anyhow::Result<Value> {
        let parent = format!(
            "{}/v2/aegis/namespaces/{namespace}",
            self.db.inner().get_documents_path()
        );
        let documents = self
            .db
            .inner()
            .fluent()
            .select()
            .from("members")
            .parent(parent)
            .query()
            .await?;
        let mut members = serde_json::Map::new();
        for document in documents {
            let member: aegis_dto::NamespaceMembership =
                arche_firestore::deserialize_stored_document(&document)?;
            members.insert(
                document
                    .name
                    .rsplit('/')
                    .next()
                    .context("membership has no id")?
                    .to_string(),
                serde_json::to_value(member)?,
            );
        }
        Ok(Value::Object(members))
    }
    pub async fn namespaces(&self) -> anyhow::Result<Vec<aegis_dto::NamespaceId>> {
        let docs: Vec<firestore::FirestoreDocument> = self
            .db
            .inner()
            .fluent()
            .select()
            .from("namespaces")
            .parent(format!("{}/v2/aegis", self.db.inner().get_documents_path()))
            .query()
            .await?;
        docs.into_iter()
            .map(|doc| {
                doc.name
                    .rsplit('/')
                    .next()
                    .context("namespace id missing")?
                    .parse()
                    .map_err(Into::into)
            })
            .collect()
    }
    pub async fn status(&self) -> anyhow::Result<Value> {
        let identity = identity::store(&self.db)?.load_config().await?;
        let login = identity::load_login(&self.db).await?;
        let namespaces = self.namespaces().await?;
        Ok(
            json!({ "issuer_url": identity.api_token.iss, "audience": identity.api_token.audience, "oidc_issuer": login.issuer_url, "namespaces": namespaces }),
        )
    }
}

pub fn namespace_template() -> Value {
    json!({
        "host_identity_schema": aegis_dto::HOST_IDENTITY_SCHEMA,
        "networks": {"aegis": {"interface": "wg-aegis", "mesh_subnet": "mesh", "overlay_mtu": 1350, "managed_ssh": true}},
        "direct_gateway": {"interface": "wg-direct", "full_tunnel_dns": ["1.1.1.1", "2606:4700:4700::1111"]},
        "egress": {"interface": "wg-egress", "network": "aegis", "dns_subnet": "egress-dns", "fwmark": 44641, "routing_table": 51823, "main_rule_priority": 11000, "egress_rule_priority": 11010},
        "wireguard": {
            "wg-aegis": {"subnet": "peer", "port": 51820, "mtu": 1400, "fwmark": 44641},
            "wg-direct": {"subnet": "direct", "port": 51822, "mtu": 1380, "fwmark": 44641},
            "wg-egress": {"subnet": "egress", "port": 51823, "mtu": 1290, "fwmark": 44641}
        },
        "subnets": {
            "mesh": {"ipv4": "10.75.0.0/24", "ipv6": "fd75::/120"},
            "peer": {"ipv4": "10.75.1.0/24", "ipv6": "fd75::1:0/120"},
            "direct": {"ipv4": "10.77.1.0/24", "ipv6": "fd77::1:0/120"},
            "egress-dns": {"ipv4": "10.78.0.0/24", "ipv6": "fd78::/120"},
            "egress": {"ipv4": "10.78.1.0/24", "ipv6": "fd78::1:0/120"}
        }
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn standalone_namespace_template_is_complete_and_rejects_overlapping_pools() {
        NamespaceOptions {
            namespace: "example".parse().unwrap(),
            configuration: namespace_template(),
            tls_dns_suffix: "mesh.example.com".into(),
        }
        .validate()
        .unwrap();
        let mut config = namespace_template();
        config["subnets"]["peer"] = config["subnets"]["mesh"].clone();
        assert!(
            NamespaceOptions {
                namespace: "example".parse().unwrap(),
                configuration: config,
                tls_dns_suffix: "mesh.example.com".into()
            }
            .validate()
            .is_err()
        );
    }
}

#[cfg(test)]
mod emulator_tests {
    use super::*;
    use phylax_core::oauth::{PkceCodeChallengeMethod, pkce_s256_code_challenge};
    use phylax_core::{
        AuthorizationCodeOAuthStore, OAuthAuthorizationCodeGrantRequest,
        OAuthAuthorizationCodeIssueRequest,
    };

    #[tokio::test]
    #[ignore = "requires a loopback FIRESTORE_EMULATOR_HOST"]
    async fn setup_account_proof_membership_and_ca_resume() -> anyhow::Result<()> {
        let emulator = std::env::var("FIRESTORE_EMULATOR_HOST")?;
        anyhow::ensure!(
            emulator.starts_with("127.0.0.1:"),
            "test requires a local emulator"
        );
        tokio::time::timeout(std::time::Duration::from_secs(60), exercise()).await??;
        Ok(())
    }
    async fn exercise() -> anyhow::Result<()> {
        let admin = AdminOptions {
            project_id: format!(
                "aegis-admin-{}",
                &uuid::Uuid::new_v4().simple().to_string()[..12]
            ),
            ..Default::default()
        }
        .validate()?
        .connect("owner".into())
        .await?;
        let options = || {
            SetupOptions {
                issuer_url: "https://fleet.example/proxy/aegis".into(),
                audience: "aegis-test".into(),
                login: LoginConfiguration {
                    issuer_url: "https://accounts.google.com".into(),
                    client_id: "test-client".into(),
                    redirect_uri: "https://fleet.example/proxy/aegis/oauth/callback".into(),
                    login_session_ttl_seconds: 600,
                    authorization_code_ttl_seconds: 300,
                },
            }
            .validate()
        };
        admin.setup(options()?).await?;
        let identity = identity::store(&admin.db)?;
        let first_key = serde_json::to_value(identity.load_config().await?.api_token)?;
        admin.setup(options()?).await?;
        assert_eq!(
            first_key,
            serde_json::to_value(identity.load_config().await?.api_token)?
        );
        let namespace = || {
            NamespaceOptions {
                namespace: "personal".parse().unwrap(),
                configuration: namespace_template(),
                tls_dns_suffix: "aegis.internal".into(),
            }
            .validate()
        };
        admin.create_namespace(namespace()?).await?;
        let parent = format!(
            "{}/v2/aegis/namespaces/personal/tls/config",
            admin.db.inner().get_documents_path()
        );
        let first_ca = load_optional_typed_at::<Value>(admin.db.inner(), &parent, "cas", "issuing")
            .await?
            .unwrap();
        admin.create_namespace(namespace()?).await?;
        assert_eq!(
            Some(first_ca.clone()),
            load_optional_typed_at::<Value>(admin.db.inner(), &parent, "cas", "issuing").await?
        );
        let (_, pem) =
            x509_parser::pem::parse_x509_pem(first_ca["crl_pem"].as_str().unwrap().as_bytes())
                .unwrap();
        let (_, crl) = x509_parser::parse_x509_crl(&pem.contents).unwrap();
        assert_eq!(crl.tbs_cert_list.revoked_certificates.len(), 0);
        assert!(crl.next_update().is_some());
        let config = identity.load_config().await?;
        let auth = identity.auth_store(&config, 600)?;
        let verifier = "01234567890123456789012345678901234567890123456789";
        let issued = auth
            .issue_authorization_code(OAuthAuthorizationCodeIssueRequest {
                client_id: "aegis-tool",
                redirect_uri: "http://127.0.0.1:1234/callback",
                provider_sub: "verified-google-subject",
                principal: "owner@example.org",
                pkce_challenge: &pkce_s256_code_challenge(verifier),
                pkce_challenge_method: PkceCodeChallengeMethod::S256,
                now_unix: 100,
                expires_unix: 400,
            })
            .await?;
        let grant = OAuthAuthorizationCodeGrantRequest {
            code: &issued.code,
            client_id: "aegis-tool",
            redirect_uri: "http://127.0.0.1:1234/callback",
            code_verifier: verifier,
            now_unix: 101,
        };
        assert!(
            auth.verify_identity_proof(OAuthAuthorizationCodeGrantRequest {
                code_verifier: "wrong",
                ..grant
            })
            .await?
            .is_none()
        );
        assert!(
            auth.verify_identity_proof(OAuthAuthorizationCodeGrantRequest {
                client_id: "wrong",
                ..grant
            })
            .await?
            .is_none()
        );
        assert!(
            auth.verify_identity_proof(OAuthAuthorizationCodeGrantRequest {
                redirect_uri: "http://127.0.0.1:9999",
                ..grant
            })
            .await?
            .is_none()
        );
        let proof = auth
            .verify_identity_proof(grant)
            .await?
            .context("identity proof missing")?;
        assert!(
            identity
                .authorize("https://accounts.google.com", &proof.provider_sub)
                .await?
                .is_none()
        );
        admin
            .add_user(
                UserRecord {
                    id: "owner".into(),
                    email: proof.principal,
                    disabled: false,
                    session_version: 1,
                },
                proof.provider_sub.clone(),
            )
            .await?;
        admin
            .set_membership(
                "personal".parse()?,
                "owner",
                Some(aegis_dto::NamespaceRole::Admin),
            )
            .await?;
        assert_eq!(
            admin.members("personal".parse()?).await?["owner"]["role"],
            "admin"
        );
        assert!(
            identity
                .authorize("https://another-issuer.example", &proof.provider_sub)
                .await?
                .is_none()
        );
        assert!(
            auth.verify_identity_proof(OAuthAuthorizationCodeGrantRequest {
                now_unix: 400,
                ..grant
            })
            .await?
            .is_none()
        );
        // Operator inspection leaves the code available for the ordinary, single-use OAuth exchange.
        assert!(auth.verify_identity_proof(grant).await?.is_some());
        let result = auth
            .exchange_authorization_code::<Value, _, _>(grant, |_| async {
                Err(phylax_core::OAuthAccessGrantError::access_denied(
                    anyhow::anyhow!("test denial"),
                ))
            })
            .await;
        assert!(result.is_err());
        assert!(auth.verify_identity_proof(grant).await?.is_none());
        admin.set_user_disabled("owner", true).await?;
        assert!(identity.user("owner").await?.unwrap().disabled);
        admin
            .set_membership("personal".parse()?, "owner", None)
            .await?;
        assert!(
            admin
                .members("personal".parse()?)
                .await?
                .as_object()
                .unwrap()
                .is_empty()
        );
        Ok(())
    }
}
