mod aegis_store;
mod config;
mod endpoint;
mod firestore;
mod identity;
mod path;
use axum::{Router, routing::get};
use std::sync::Arc;
#[derive(Default)]
pub struct ApplicationOptions {
    pub database: arche_firestore::DatabaseOptions,
    pub oidc_client_secret: String,
}

pub struct ApplicationConfig {
    database: arche_firestore::DatabaseConfig,
    oidc_client_secret: String,
}

impl ApplicationOptions {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            database: arche_firestore::DatabaseOptions::from_env(),
            oidc_client_secret: std::env::var(aegis_dto::identity::OIDC_SECRET_ENV).map_err(
                |_| anyhow::anyhow!("AEGIS_OIDC_CLIENT_SECRET must be supplied to the API runtime"),
            )?,
        })
    }

    pub fn validate(self) -> anyhow::Result<ApplicationConfig> {
        anyhow::ensure!(
            !self.oidc_client_secret.trim().is_empty(),
            "OIDC client secret must not be empty"
        );
        Ok(ApplicationConfig {
            database: self.database.validate()?,
            oidc_client_secret: self.oidc_client_secret,
        })
    }
}

impl ApplicationConfig {
    pub async fn connect(self) -> anyhow::Result<Router> {
        let db = self.database.connect().await?;
        application(db, self.oidc_client_secret).await
    }
}

async fn application(
    db: arche_firestore::Db,
    oidc_client_secret: String,
) -> anyhow::Result<Router> {
    let identity = identity::store(&db)?.load_config().await?;
    let identities = identity::store(&db)?;
    let login = identity::load_login(&db).await?;
    let jwt_issuer = Arc::new(phylax_core::JwtIssuer::from_config(
        &identity.api_token.jwt_config(),
    )?);
    let oauth = phylax_core::AuthorizationCodeOAuthEndpoint::new(
        identities.auth_store(&identity, login.login_session_ttl_seconds)?,
        phylax_oidc::OidcProvider::connect(
            phylax_oidc::OidcOptions {
                issuer_url: login.issuer_url.clone(),
                client_id: login.client_id.clone(),
                client_secret: oidc_client_secret,
                redirect_uri: login.redirect_uri.clone(),
            }
            .validate()?,
        )
        .await?,
        endpoint::oauth::OAuthAccessPolicy {
            identities: identities.clone(),
            provider: login.issuer_url.clone(),
            public_client_id: "aegis-tool".into(),
            audience: identity.api_token.audience.clone(),
            base_scopes: vec!["aegis:read".into(), "aegis:user".into()],
        },
        jwt_issuer.clone(),
        phylax_core::AuthorizationCodeOAuthConfig {
            public_client_id: "aegis-tool".into(),
            login_session_ttl_seconds: login.login_session_ttl_seconds,
            authorization_code_ttl_seconds: login.authorization_code_ttl_seconds,
            state_max_len: 512,
        },
    )?;
    let revoke = endpoint::oauth::UserRevokeTokenGrant {
        auth: identities.auth_store(&identity, login.login_session_ttl_seconds)?,
    };
    let info = serde_json::json!({"issuer":identity.api_token.iss,"protocol":2,"version":env!("CARGO_PKG_VERSION")});
    let mut namespace_routes = Router::new();
    for namespace in firestore::list_aegis_namespaces(&db).await? {
        let store = firestore::AegisDb::new(db.clone(), namespace.clone());
        let config = firestore::load_aegis_instance_config(&store).await?;
        let auth = store.auth_store(&identity.refresh_token, login.login_session_ttl_seconds)?;
        let audience = format!(
            "{}/aegis/namespaces/{namespace}",
            identity.api_token.audience
        );
        let state = endpoint::aegis::AegisState::new(endpoint::aegis::AegisStateParts {
            store: store.clone(),
            auth: Arc::new(auth.clone()),
            issuer: jwt_issuer.clone(),
            client_ca: &config.client_ca,
            direct_client_ca: &config.direct_client_ca,
            server_ca: &config.server_ca,
            tls: &config.tls,
            api_issuer: &format!(
                "{}/namespaces/{namespace}",
                identity.api_token.iss.trim_end_matches('/')
            ),
            api_audience: &audience,
            user_api_audience: &identity.api_token.audience,
            namespace: namespace.clone(),
            cfg: &config.config,
        })?;
        let grant = endpoint::aegis::AegisAgentTokenGrant {
            auth,
            store: store.clone(),
            issuer: jwt_issuer.clone(),
            api_audience: audience,
        };
        namespace_routes = namespace_routes.nest(
            &format!("/namespaces/{namespace}"),
            endpoint::aegis::router(state, grant),
        );
    }

    use phylax_core::oauth::path::*;
    let api = namespace_routes
        .route(
            "/info",
            get(move || {
                let info = info.clone();
                async move { axum::Json(info) }
            }),
        )
        .merge(phylax_core::authorization_code_oauth_router(
            OAUTH_AUTHORIZE,
            OAUTH_CALLBACK,
            OAUTH_TOKEN,
            oauth,
        ))
        .merge(phylax_core::form_revoke_token_router(OAUTH_REVOKE, revoke));
    Ok(Router::new()
        .route("/health", get(|| async { "OK" }))
        .nest("/v2", api))
}
