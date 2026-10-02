use std::fs;
use std::path::Path;

use aegis_types::v1::AegisPrincipalGrant;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub(crate) const PATH: &str = "/var/lib/aegis/principal-grants.toml";

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct PrincipalGrantStore {
    #[serde(default)]
    pub(crate) grants: Vec<AegisPrincipalGrant>,
}

impl PrincipalGrantStore {
    pub(crate) fn load() -> Result<Self> {
        let path = Path::new(PATH);
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let mut store: Self =
            toml::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))?;
        store.grants = normalize(std::mem::take(&mut store.grants))?;
        Ok(store)
    }

    pub(crate) fn persist(&self) -> Result<()> {
        let normalized = Self {
            grants: normalize(self.grants.clone())?,
        };
        let raw =
            toml::to_string(&normalized).context("failed to encode Aegis principal grants")?;
        capulus::store::atomic_write(Path::new(PATH), raw.as_bytes(), Some(0o600), Some(0o755))
            .with_context(|| format!("failed to update {PATH}"))
    }

    pub(crate) fn allow(
        &mut self,
        login_principal: &str,
        oauth_principal: &str,
    ) -> Result<AegisPrincipalGrant> {
        let grant = normalized_grant(login_principal, oauth_principal)?;
        if !self.grants.iter().any(|existing| existing == &grant) {
            self.grants.push(grant.clone());
            self.grants.sort();
        }
        Ok(grant)
    }

    pub(crate) fn revoke(
        &mut self,
        login_principal: &str,
        oauth_principal: &str,
    ) -> Result<AegisPrincipalGrant> {
        let grant = normalized_grant(login_principal, oauth_principal)?;
        self.grants.retain(|existing| existing != &grant);
        Ok(grant)
    }

    pub(crate) fn reconcile(&mut self, grants: Vec<AegisPrincipalGrant>) -> Result<bool> {
        let grants = normalize(grants)?;
        if self.grants == grants {
            return Ok(false);
        }
        self.grants = grants;
        Ok(true)
    }

    pub(crate) fn commit_validated_with<V, P>(mut self, validate: V, persist: P) -> Result<Self>
    where
        V: FnOnce(&[AegisPrincipalGrant]) -> Result<Vec<AegisPrincipalGrant>>,
        P: FnOnce(&Self) -> Result<()>,
    {
        self.reconcile(validate(&self.grants)?)?;
        persist(&self)?;
        Ok(self)
    }
}

pub(crate) fn validate_login_principal(value: &str) -> Result<()> {
    if value.is_empty() {
        bail!("login principal must not be empty");
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        bail!("login principal must use ascii letters, digits, '.', '-' or '_'");
    }
    Ok(())
}

pub(crate) fn validate_user_id(value: &str) -> Result<String> {
    if value.is_empty()
        || value != value.trim()
        || value.contains(char::is_whitespace)
        || value.contains('@')
    {
        bail!("aegis user ID must be non-empty, exact, and contain neither whitespace nor '@'");
    }
    Ok(value.to_string())
}

fn normalized_grant(login_principal: &str, oauth_principal: &str) -> Result<AegisPrincipalGrant> {
    let login_principal = login_principal.trim();
    validate_login_principal(login_principal)?;
    Ok(AegisPrincipalGrant {
        login_principal: login_principal.to_string(),
        oauth_principal: validate_user_id(oauth_principal)?,
    })
}

fn normalize(grants: Vec<AegisPrincipalGrant>) -> Result<Vec<AegisPrincipalGrant>> {
    let mut out = Vec::new();
    for grant in grants {
        let normalized = normalized_grant(&grant.login_principal, &grant.oauth_principal)?;
        if !out.iter().any(|existing| existing == &normalized) {
            out.push(normalized);
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{PrincipalGrantStore, validate_login_principal, validate_user_id};
    use anyhow::bail;
    use std::cell::Cell;

    #[test]
    fn allow_validates_and_deduplicates_grants() {
        let mut store = PrincipalGrantStore::default();
        store
            .allow("ubuntu", "OpaqueUserID")
            .expect("grant should validate");
        store
            .allow("ubuntu", "OpaqueUserID")
            .expect("duplicate should validate");

        assert_eq!(1, store.grants.len());
        assert_eq!("ubuntu", store.grants[0].login_principal);
        assert_eq!("OpaqueUserID", store.grants[0].oauth_principal);
    }

    #[test]
    fn principal_validation_rejects_shell_metacharacters_and_whitespace() {
        validate_login_principal("ubuntu").expect("ordinary login should validate");
        validate_login_principal("ops-user").expect("dash should validate");
        validate_login_principal("bad user").expect_err("whitespace must fail");
        validate_login_principal("bad;user").expect_err("shell punctuation must fail");
        validate_user_id(" ").expect_err("empty user ID must fail");
        validate_user_id("User@Example.COM").expect_err("email must fail");
        validate_user_id(" OpaqueUserID").expect_err("surrounding whitespace must fail");
        assert_eq!(
            "OpaqueUserID",
            validate_user_id("OpaqueUserID").expect("stable ID should validate")
        );
    }

    #[test]
    fn reconcile_replaces_grants_without_changing_stable_id_case() {
        let mut store = PrincipalGrantStore::default();
        store
            .allow("ubuntu", "OldUserID")
            .expect("existing grant should validate");
        assert!(
            store
                .reconcile(vec![aegis_types::v1::AegisPrincipalGrant {
                    login_principal: "ubuntu".to_string(),
                    oauth_principal: "OpaqueUserID".to_string(),
                }])
                .expect("canonical grants should validate")
        );
        assert_eq!("OpaqueUserID", store.grants[0].oauth_principal);
        assert!(
            !store
                .reconcile(store.grants.clone())
                .expect("unchanged grants should validate")
        );
    }

    #[test]
    fn rejected_grant_candidate_never_reaches_the_persistence_boundary() {
        let mut candidate = PrincipalGrantStore::default();
        candidate
            .allow("ubuntu", "UnknownUserID")
            .expect("candidate should be structurally valid");
        let persisted = Cell::new(false);

        candidate
            .commit_validated_with(
                |_| bail!("unknown aegis user"),
                |_| {
                    persisted.set(true);
                    Ok(())
                },
            )
            .expect_err("control-plane rejection must fail the mutation");

        assert!(!persisted.get());
    }
}
