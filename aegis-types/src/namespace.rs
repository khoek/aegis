use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct NamespaceId(String);

impl NamespaceId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for NamespaceId {
    type Error = InvalidNamespaceId;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty()
            || value.len() > 63
            || value.starts_with('-')
            || value.ends_with('-')
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(InvalidNamespaceId);
        }
        Ok(Self(value))
    }
}

impl FromStr for NamespaceId {
    type Err = InvalidNamespaceId;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value.to_owned().try_into()
    }
}

impl From<NamespaceId> for String {
    fn from(value: NamespaceId) -> Self {
        value.0
    }
}

impl fmt::Display for NamespaceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidNamespaceId;

impl fmt::Display for InvalidNamespaceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "namespace must contain 1–63 lowercase ASCII letters, digits or interior hyphens",
        )
    }
}

impl std::error::Error for InvalidNamespaceId {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceRole {
    Member,
    Admin,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceMembership {
    pub role: NamespaceRole,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NamespaceContext {
    pub namespace: NamespaceId,
    pub role: NamespaceRole,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiEndpoint {
    service: url::Url,
    namespace: Option<NamespaceId>,
}

impl ApiEndpoint {
    pub fn parse(value: &str) -> Result<Self, String> {
        let mut service = url::Url::parse(value).map_err(|error| error.to_string())?;
        if !matches!(service.scheme(), "https" | "http")
            || service.host_str().is_none()
            || !service.username().is_empty()
            || service.password().is_some()
            || service.query().is_some()
            || service.fragment().is_some()
        {
            return Err(
                "API endpoint must be an HTTP(S) URL without credentials, query or fragment".into(),
            );
        }
        let path = service.path().trim_end_matches('/').to_string();
        let namespace = match path.rsplit_once("/namespaces/") {
            Some((base, namespace)) => {
                let namespace = namespace
                    .parse::<NamespaceId>()
                    .map_err(|error| error.to_string())?;
                service.set_path(base);
                Some(namespace)
            }
            None => {
                service.set_path(&path);
                None
            }
        };
        Ok(Self { service, namespace })
    }

    pub fn with_namespace(mut self, namespace: NamespaceId) -> Self {
        self.namespace = Some(namespace);
        self
    }

    pub fn namespace(&self) -> Option<&NamespaceId> {
        self.namespace.as_ref()
    }

    pub fn require_namespace(&self) -> Result<&NamespaceId, String> {
        self.namespace.as_ref().ok_or_else(|| "select an Aegis namespace with --namespace NAME or `aegis manage namespace use NAME`".into())
    }

    pub fn service_url(&self) -> &str {
        self.service.as_str().trim_end_matches('/')
    }

    pub fn base_url(&self) -> String {
        match &self.namespace {
            Some(namespace) => format!("{}/namespaces/{namespace}", self.service_url()),
            None => self.service_url().to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ApiEndpoint, NamespaceId};

    #[test]
    fn namespace_selection_preserves_the_oauth_service_and_replaces_previous_context() {
        assert!(
            ApiEndpoint::parse("https://api.example/v2")
                .unwrap()
                .require_namespace()
                .is_err()
        );
        let endpoint = ApiEndpoint::parse("https://api.example/v2/namespaces/alice/").unwrap();
        assert_eq!(endpoint.require_namespace().unwrap().as_str(), "alice");
        assert_eq!(endpoint.service_url(), "https://api.example/v2");
        assert_eq!(
            endpoint.base_url(),
            "https://api.example/v2/namespaces/alice"
        );
        assert_eq!(
            endpoint.with_namespace("bob".parse().unwrap()).base_url(),
            "https://api.example/v2/namespaces/bob"
        );
        for invalid in [
            "https://api.example/v2/namespaces/alice/hosts",
            "https://user:secret@api.example/v2",
            "https://api.example/v2?namespace=alice",
        ] {
            assert!(ApiEndpoint::parse(invalid).is_err());
        }
    }

    #[test]
    fn namespace_ids_cannot_escape_document_or_url_paths() {
        for invalid in [
            "", ".", "..", "../hoek", "a/b", "a%2fb", "A", "-a", "a-", "a b", "a:b", "a?b", "a#b",
        ] {
            assert!(invalid.parse::<NamespaceId>().is_err(), "{invalid}");
            assert!(serde_json::from_value::<NamespaceId>(serde_json::json!(invalid)).is_err());
        }
        assert!("a".repeat(64).parse::<NamespaceId>().is_err());
        for valid in ["hoek", "alice", "alice-home", "123"] {
            assert_eq!(valid.parse::<NamespaceId>().unwrap().to_string(), valid);
        }
    }
}
