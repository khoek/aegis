use async_trait::async_trait;
use phylax_core::{
    AuthorizationCodeOAuthPolicy, FormRevokeTokenGrant, OAuthAccessGrant, OAuthAccessGrantError,
    OAuthVerifiedIdentity, ScopeSet, Subject,
};
use phylax_gcp::FirestoreAuthStore;
use phylax_gcp::identity::UserRecord;
use serde::Serialize;
use std::net::IpAddr;
use time::OffsetDateTime;
use url::Url;
#[derive(Clone)]
pub struct OAuthAccessPolicy {
    pub identities: phylax_gcp::identity::IdentityStore,
    pub provider: String,
    pub public_client_id: String,
    pub audience: String,
    pub base_scopes: Vec<String>,
}

impl OAuthAccessPolicy {
    fn scopes(&self) -> anyhow::Result<ScopeSet> {
        ScopeSet::new(self.base_scopes.iter().map(String::as_str))
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct OAuthTokenExtra {
    pub principal: String,
}

impl OAuthTokenExtra {
    fn for_user(user: &UserRecord) -> Self {
        Self {
            principal: user.id.clone(),
        }
    }
}

#[async_trait]
impl AuthorizationCodeOAuthPolicy for OAuthAccessPolicy {
    type Extra = OAuthTokenExtra;

    fn validate_redirect_uri(&self, redirect_uri: &Url) -> anyhow::Result<()> {
        validate_local_redirect(redirect_uri)
    }

    async fn access_grant(
        &self,
        identity: &OAuthVerifiedIdentity,
    ) -> Result<OAuthAccessGrant<Self::Extra>, OAuthAccessGrantError> {
        let user = require_authorized_user(
            self.identities
                .authorize(&self.provider, &identity.provider_sub)
                .await?,
        )?;
        if user.disabled {
            return Err(OAuthAccessGrantError::access_denied(anyhow::anyhow!(
                "OAuth principal is disabled"
            )));
        }
        Ok(OAuthAccessGrant {
            subject: oauth_user_subject(&user.id)?,
            client_id: self.public_client_id.clone(),
            audience: vec![self.audience.clone()],
            scope: self.scopes()?,
            extra: OAuthTokenExtra::for_user(&user),
        })
    }
}

fn require_authorized_user(user: Option<UserRecord>) -> Result<UserRecord, OAuthAccessGrantError> {
    user.ok_or_else(|| {
        OAuthAccessGrantError::access_denied(anyhow::anyhow!("OAuth principal is not authorized"))
    })
}

#[derive(Clone)]
pub struct UserRevokeTokenGrant {
    pub auth: FirestoreAuthStore,
}

#[async_trait]
impl FormRevokeTokenGrant for UserRevokeTokenGrant {
    async fn revoke_refresh_token(&self, token: &str) -> anyhow::Result<()> {
        self.auth
            .revoke_oauth_refresh_token_value(token, OffsetDateTime::now_utc().unix_timestamp())
            .await
    }
}

fn validate_local_redirect(url: &Url) -> anyhow::Result<()> {
    if url.scheme() != "http" {
        anyhow::bail!("redirect_uri must use http (loopback)");
    }
    if url.fragment().is_some() {
        anyhow::bail!("redirect_uri must not contain a fragment");
    }
    if !is_loopback_ip_literal(url) {
        anyhow::bail!("redirect_uri must use a loopback IP literal");
    }
    Ok(())
}

fn oauth_user_subject(user_id: &str) -> anyhow::Result<Subject> {
    anyhow::ensure!(
        !user_id.is_empty()
            && user_id.trim() == user_id
            && !user_id.contains(char::is_whitespace)
            && !user_id.contains('@'),
        "user id is invalid"
    );
    Subject::new(format!("user:{user_id}"))
}

fn is_loopback_ip_literal(url: &Url) -> bool {
    url.host_str()
        .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::{
        OAuthTokenExtra, oauth_user_subject, require_authorized_user, validate_local_redirect,
    };
    use phylax_core::OAuthAccessGrantError;
    use phylax_gcp::identity::UserRecord;
    use url::Url;

    #[test]
    fn loopback_http_redirect_is_allowed() {
        validate_local_redirect(&Url::parse("http://127.0.0.1:7777/callback").unwrap())
            .expect("loopback http should be allowed");
        validate_local_redirect(&Url::parse("http://127.0.0.2:7777/callback").unwrap())
            .expect("loopback http should be allowed");
        validate_local_redirect(&Url::parse("http://[::1]:7777/callback").unwrap())
            .expect("IPv6 loopback http should be allowed");
    }

    #[test]
    fn non_loopback_or_https_redirect_is_rejected() {
        validate_local_redirect(&Url::parse("http://example.com/callback").unwrap())
            .expect_err("non-loopback redirect should fail");
        validate_local_redirect(&Url::parse("http://localhost:7777/callback").unwrap())
            .expect_err("localhost redirect should fail");
        validate_local_redirect(&Url::parse("https://127.0.0.1/callback").unwrap())
            .expect_err("https loopback redirect should fail");
        validate_local_redirect(&Url::parse("http://127.0.0.1/callback#fragment").unwrap())
            .expect_err("fragment redirect should fail");
    }

    #[test]
    fn stable_user_ids_cannot_overlap_the_legacy_email_namespace() {
        oauth_user_subject("OpaqueUserID").expect("opaque stable id should validate");
        oauth_user_subject("user@example.com")
            .expect_err("stable id must not overlap the legacy email namespace");
    }

    #[test]
    fn token_extra_uses_the_stable_user_id() {
        assert_eq!(
            "user-1",
            OAuthTokenExtra::for_user(&UserRecord {
                id: "user-1".into(),
                email: "user@example.com".into(),
                disabled: false,
                session_version: 0,
            })
            .principal
        );
    }

    #[test]
    fn missing_user_record_is_denied() {
        let error = require_authorized_user(None).expect_err("missing user must be denied");
        match error {
            OAuthAccessGrantError::AccessDenied(error) => {
                assert_eq!("OAuth principal is not authorized", error.to_string());
            }
            OAuthAccessGrantError::Internal(error) => {
                panic!("missing user returned an internal error: {error}");
            }
        }
    }

    #[test]
    fn existing_identity_can_authenticate_without_namespace_permissions() {
        assert_eq!(
            require_authorized_user(Some(UserRecord {
                id: "user-1".into(),
                email: "user@example.com".into(),
                disabled: false,
                session_version: 0,
            }))
            .unwrap()
            .id,
            "user-1"
        );
    }
}
