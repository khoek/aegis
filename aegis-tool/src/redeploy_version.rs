use std::fmt;

use anyhow::{Context, Result, bail};
use semver::Version;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RedeployVersion {
    value: Version,
}

impl RedeployVersion {
    pub(crate) fn explicit(version: &str) -> Result<Self> {
        let target_version = version.trim().trim_start_matches('v');
        if target_version.is_empty() {
            bail!("redeploy version cannot be empty");
        }
        Ok(Self {
            value: Version::parse(target_version)
                .context("redeploy version must be valid semver")?,
        })
    }

    pub(crate) fn latest() -> Result<Self> {
        Ok(Self {
            value: crate::release::latest_version()?,
        })
    }

    pub(crate) fn semver(&self) -> &Version {
        &self.value
    }
}

impl fmt::Display for RedeployVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value.fmt(formatter)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RedeployTarget {
    Latest,
    Exact(RedeployVersion),
}

impl RedeployTarget {
    pub(crate) fn requested(version: Option<&str>) -> Result<Self> {
        version
            .map(RedeployVersion::explicit)
            .transpose()
            .map(|version| version.map_or(Self::Latest, Self::Exact))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omitted_redeploy_version_requests_latest() {
        assert_eq!(
            RedeployTarget::Latest,
            RedeployTarget::requested(None).unwrap()
        );
    }

    #[test]
    fn explicit_redeploy_version_remains_exact() {
        let target = RedeployTarget::requested(Some("v1.2.3")).unwrap();
        assert_eq!(
            target,
            RedeployTarget::Exact(RedeployVersion::explicit("1.2.3").unwrap())
        );
        assert!(RedeployTarget::requested(Some("latest")).is_err());
    }
}
