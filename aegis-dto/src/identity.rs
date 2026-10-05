use serde::{Deserialize, Serialize};

pub const IDENTITY_DOCUMENT: &str = "v2/aegis/identity/config";
pub const OIDC_SECRET_ENV: &str = "AEGIS_OIDC_CLIENT_SECRET";
pub const USER_TOKEN_PATH: &str = "/auth/token";
pub const USER_REVOKE_PATH: &str = "/auth/revoke";
pub const USER_CLIENT_ID: &str = "aegis-tool";

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationConfiguration {
    pub oauth: Option<LoginConfiguration>,
}

impl AuthenticationConfiguration {
    pub fn validate(&self) -> anyhow::Result<()> {
        if let Some(oauth) = &self.oauth {
            oauth.validate()?;
        }
        Ok(())
    }

    pub fn login_session_ttl_seconds(&self) -> u64 {
        self.oauth
            .as_ref()
            .map_or(600, |oauth| oauth.login_session_ttl_seconds)
    }
}

/// A single-client credential. Import exchanges it for a rotating local session.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserCredential {
    pub api_base: String,
    pub user_id: String,
    pub session_id: String,
    pub refresh_token: String,
    pub expires_unix: i64,
}

impl UserCredential {
    pub fn validate(&self) -> anyhow::Result<()> {
        let endpoint =
            crate::namespace::ApiEndpoint::parse(&self.api_base).map_err(anyhow::Error::msg)?;
        anyhow::ensure!(
            self.api_base.starts_with("https://")
                && endpoint.namespace().is_some()
                && endpoint.base_url() == self.api_base,
            "credential must contain a canonical HTTPS namespace endpoint"
        );
        anyhow::ensure!(
            !self.user_id.is_empty()
                && !self.user_id.contains(char::is_whitespace)
                && !self.user_id.contains('@')
                && !self.session_id.is_empty()
                && !self.refresh_token.trim().is_empty()
                && self.expires_unix > 0,
            "credential is incomplete"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LoginConfiguration {
    pub issuer_url: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub login_session_ttl_seconds: u64,
    pub authorization_code_ttl_seconds: u64,
}

impl LoginConfiguration {
    pub fn validate(&self) -> anyhow::Result<()> {
        for value in [&self.issuer_url, &self.redirect_uri] {
            let endpoint =
                crate::namespace::ApiEndpoint::parse(value).map_err(anyhow::Error::msg)?;
            anyhow::ensure!(
                endpoint.service_url().starts_with("https://"),
                "OIDC requires HTTPS"
            );
        }
        anyhow::ensure!(
            !self.client_id.trim().is_empty(),
            "OIDC client id is required"
        );
        for ttl in [
            self.login_session_ttl_seconds,
            self.authorization_code_ttl_seconds,
        ] {
            anyhow::ensure!(
                ttl > 0 && ttl <= 3600,
                "login lifetimes must be between 1 and 3600 seconds"
            );
        }
        Ok(())
    }
}
