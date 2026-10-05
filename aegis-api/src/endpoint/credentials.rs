use std::sync::Arc;

use aegis_dto::identity::USER_CLIENT_ID;
use async_trait::async_trait;
use phylax_core::{
    AccessTokenGrant, JsonRefreshTokenExchange, JsonRefreshTokenGrant,
    JsonRefreshTokenGrantRequest, JwtIssuer, RefreshTokenValidation, ScopeSet,
};
use phylax_gcp::{FirestoreAuthStore, RefreshTokenGrantRequest, identity::IdentityStore};

#[derive(Clone)]
pub struct UserTokenGrant {
    pub auth: FirestoreAuthStore,
    pub identities: IdentityStore,
    pub issuer: Arc<JwtIssuer>,
    pub audience: String,
}

#[async_trait]
impl JsonRefreshTokenGrant for UserTokenGrant {
    type Extra = super::oauth::OAuthTokenExtra;

    fn issuer(&self) -> Arc<JwtIssuer> {
        self.issuer.clone()
    }

    async fn exchange_refresh_token(
        &self,
        request: JsonRefreshTokenGrantRequest<'_>,
    ) -> anyhow::Result<RefreshTokenValidation<JsonRefreshTokenExchange<Self::Extra>>> {
        let request = RefreshTokenGrantRequest {
            refresh_token: request.refresh_token,
            client_id: USER_CLIENT_ID,
            now_unix: request.now_unix,
        };
        let RefreshTokenValidation::Valid(inspection) =
            self.auth.inspect_refresh_token(request).await?
        else {
            return Ok(RefreshTokenValidation::Invalid);
        };
        let Some(user_id) = inspection.subject.strip_kind("user") else {
            return Ok(RefreshTokenValidation::Invalid);
        };
        let Some(user) = self
            .identities
            .user(user_id)
            .await?
            .filter(|user| !user.disabled)
        else {
            return Ok(RefreshTokenValidation::Invalid);
        };
        let RefreshTokenValidation::Valid(exchange) =
            self.auth.exchange_refresh_token(request).await?
        else {
            return Ok(RefreshTokenValidation::Invalid);
        };
        anyhow::ensure!(
            exchange.subject == inspection.subject,
            "session identity changed during exchange"
        );
        Ok(RefreshTokenValidation::Valid(JsonRefreshTokenExchange {
            access_grant: AccessTokenGrant {
                subject: exchange.subject,
                client_id: USER_CLIENT_ID.into(),
                audience: vec![self.audience.clone()],
                scope: ScopeSet::new(["aegis:read", "aegis:user"])?,
                sid: Some(exchange.sid),
                refresh_expires_unix: exchange.expires_unix,
                extra: super::oauth::OAuthTokenExtra { principal: user.id },
            },
            refresh_token: exchange.refresh_token,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use phylax_core::{AccessClaims, Subject};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    async fn exchange(app: &Router, token: &str) -> (StatusCode, Value) {
        let response = app
            .clone()
            .oneshot(
                Request::post("/v2/auth/token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"grant_type":"refresh_token","refresh_token":token}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        (
            response.status(),
            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap(),
        )
    }

    #[tokio::test]
    #[ignore = "requires a loopback FIRESTORE_EMULATOR_HOST"]
    async fn emulator_credential_sessions_rotate_revoke_and_work_without_oauth()
    -> anyhow::Result<()> {
        anyhow::ensure!(
            std::env::var("FIRESTORE_EMULATOR_HOST")?.starts_with("127.0.0.1:"),
            "use a local emulator"
        );
        tokio::time::timeout(std::time::Duration::from_secs(60), exercise()).await??;
        Ok(())
    }

    async fn exercise() -> anyhow::Result<()> {
        let project = format!(
            "aegis-keys-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        );
        let db = arche_firestore::DatabaseOptions {
            project_id: Some(project),
            database_id: "aegis".into(),
            credentials: arche_firestore::Credentials::AccessToken("owner".into()),
            ..Default::default()
        }
        .validate()?
        .connect()
        .await?;
        let identities = crate::identity::store(&db)?;
        identities
            .bootstrap(
                phylax_gcp::identity::IdentityBootstrapOptions {
                    issuer_url: "https://fleet.example/v2".into(),
                    audience: "test-users".into(),
                    ..Default::default()
                }
                .validate()?,
            )
            .await?;
        arche_firestore::create_typed_at(
            db.inner(),
            identities.parent(),
            "settings",
            "authentication",
            &aegis_dto::identity::AuthenticationConfiguration::default(),
        )
        .await?;
        identities
            .create_user(
                &phylax_gcp::identity::UserRecord {
                    id: "owner".into(),
                    email: "owner@example.com".into(),
                    disabled: false,
                    session_version: 1,
                },
                None,
            )
            .await?;
        let config = identities.load_config().await?;
        let issuer = JwtIssuer::from_config(&config.api_token.jwt_config())?;
        let auth = identities.auth_store(&config, 600)?;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let issue = || phylax_gcp::RefreshTokenIssueRequest {
            subject: Subject::new("user:owner").unwrap(),
            client_id: USER_CLIENT_ID,
            now_unix: now,
        };
        let first = auth.issue_refresh_token(issue()).await?;
        let second = auth.issue_refresh_token(issue()).await?;
        let app = crate::application(db.clone(), None).await?;
        let info = app
            .clone()
            .oneshot(Request::get("/v2/info").body(Body::empty())?)
            .await?;
        let info: Value = serde_json::from_slice(&to_bytes(info.into_body(), 65536).await?)?;
        assert_eq!(
            info["authentication"],
            json!({"credentials":true,"oauth":false})
        );
        assert_eq!(
            app.clone()
                .oneshot(Request::get("/v2/oauth/authorize").body(Body::empty())?)
                .await?
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(exchange(&app, "invalid").await.0, StatusCode::UNAUTHORIZED);
        let (status, token) = exchange(&app, first.refresh_token()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(token["principal"], "owner");
        let claims: AccessClaims =
            issuer.decode_access(token["access_token"].as_str().unwrap(), "test-users")?;
        assert_eq!(claims.sid.as_deref(), Some(first.session_id()));
        assert!(identities.session_active(&claims, now).await?);
        assert_eq!(
            exchange(&app, first.refresh_token()).await.0,
            StatusCode::UNAUTHORIZED
        );
        let (status, rotated) = exchange(&app, token["refresh_token"].as_str().unwrap()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            auth.revoke_refresh_session(
                first.session_id(),
                &Subject::new("user:owner")?,
                USER_CLIENT_ID,
                now
            )
            .await?
        );
        assert!(!identities.session_active(&claims, now).await?);
        assert_eq!(
            exchange(&app, rotated["refresh_token"].as_str().unwrap())
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        identities.set_disabled("owner", true).await?;
        assert_eq!(
            exchange(&app, second.refresh_token()).await.0,
            StatusCode::UNAUTHORIZED
        );
        identities.set_disabled("owner", false).await?;
        let (status, second_token) = exchange(&app, second.refresh_token()).await;
        assert_eq!(status, StatusCode::OK);
        let revoked = app
            .clone()
            .oneshot(
                Request::post("/v2/auth/revoke")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "token={}",
                        second_token["refresh_token"].as_str().unwrap()
                    )))?,
            )
            .await?;
        assert_eq!(revoked.status(), StatusCode::OK);
        assert_eq!(
            exchange(&app, second_token["refresh_token"].as_str().unwrap())
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert!(
            crate::application(db, Some("unexpected-secret".into()))
                .await
                .is_err()
        );
        Ok(())
    }
}
