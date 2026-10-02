use serde::{Deserialize, Serialize};

pub const IDENTITY_DOCUMENT: &str = "v2/aegis/identity/config";
pub const OIDC_SECRET_ENV: &str = "AEGIS_OIDC_CLIENT_SECRET";

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
