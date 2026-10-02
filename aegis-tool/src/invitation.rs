use std::{
    fs,
    path::{Path, PathBuf},
};

use aegis_types::{
    AegisHostMode, HostAlias, HostAliases,
    v1::{AegisEnrollmentCreateRequest, AegisEnrollmentCredentialResponse, AegisEnrollmentSsh},
};
use anyhow::{Context, Result, ensure};

use crate::{api::AuthenticatedApiClient, config, ui};

pub(crate) fn read(path: &Path) -> Result<AegisEnrollmentCredentialResponse> {
    ensure!(
        fs::metadata(path)?.len() <= 64 * 1024,
        "enrollment invitation is too large"
    );
    let invitation: AegisEnrollmentCredentialResponse =
        serde_json::from_slice(&fs::read(path)?).context("invalid Aegis enrollment invitation")?;
    validate(&invitation)?;
    Ok(invitation)
}

pub(crate) fn validate(invitation: &AegisEnrollmentCredentialResponse) -> Result<()> {
    let endpoint = config::namespace_endpoint(&invitation.api_base)?;
    ensure!(
        endpoint.base_url() == invitation.api_base && invitation.api_base.starts_with("https://"),
        "enrollment invitation must contain a canonical HTTPS namespace endpoint"
    );
    ensure!(
        !invitation.refresh_token.trim().is_empty(),
        "enrollment invitation has no credential"
    );
    Ok(())
}

pub(crate) fn save(invitation: &AegisEnrollmentCredentialResponse, path: &Path) -> Result<()> {
    validate(invitation)?;
    capulus::store::atomic_write(
        path,
        &serde_json::to_vec_pretty(invitation)?,
        Some(0o600),
        Some(0o700),
    )
}

pub(crate) fn reserve(
    api: &mut AuthenticatedApiClient,
    alias: HostAlias,
    mode: AegisHostMode,
) -> Result<aegis_types::v1::AegisEnrollment> {
    api.require_user_admin("enroll a machine")?;
    api.create_enrollment(&AegisEnrollmentCreateRequest {
        aliases: HostAliases::new(vec![alias])?,
        network: "aegis".into(),
        mode,
        ssh: Some(AegisEnrollmentSsh {
            port: Some(22),
            external_principals: Vec::new(),
        }),
        transient: false,
        initial_oauth_principal: None,
        ttl_seconds: 24 * 60 * 60,
    })
}

pub(crate) fn issue(
    api: &mut AuthenticatedApiClient,
    host: &aegis_types::HostId,
) -> Result<(AegisEnrollmentCredentialResponse, PathBuf)> {
    let invitation = api.issue_enrollment_credential(host)?;
    ensure!(
        invitation.api_base == api.api_base() && invitation.enrollment.host_id == *host,
        "API returned an invitation for a different endpoint or host"
    );
    let path = path(host)?;
    save(&invitation, &path).with_context(|| format!("Enrollment {host} is retained, but its invitation could not be saved; issue a replacement credential"))?;
    ui::detail(&format!(
        "Enrollment invitation saved to {} (expires at Unix time {})",
        path.display(),
        invitation.enrollment.expires_unix
    ));
    Ok((invitation, path))
}

pub(crate) fn path(host: &aegis_types::HostId) -> Result<PathBuf> {
    Ok(config::app_dir()?
        .join("enrollments")
        .join(format!("{host}.json")))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_oversized_and_incomplete_invitations_before_network_access() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invitation.json");
        fs::write(&path, b"{}").unwrap();
        assert!(read(&path).is_err());
        fs::write(&path, vec![b' '; 65537]).unwrap();
        assert!(read(&path).unwrap_err().to_string().contains("too large"));
    }
}
