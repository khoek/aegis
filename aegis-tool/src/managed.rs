use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use capulus::managed::{
    AgentServiceOptions, JobId, ManagedProduct, ManagedProductOptions, ManagedProgramOptions,
    ManagedRedeployOptions, ManagementClient, ManagementClientOptions, ManagementError,
    ManagementRequest, ManagementResponse, RedeployJob, RedeployOutcome, ResolvedReleaseInfo,
    ServiceHardening, SocketOptions, VersionTarget,
};
use semver::Version;

#[cfg(target_os = "linux")]
pub(crate) const MANAGEMENT_SOCKET_PATH: &str = "/run/aegis/capulus.sock";
#[cfg(target_os = "macos")]
pub(crate) const MANAGEMENT_SOCKET_PATH: &str = "/private/var/run/aegis-capulus.sock";
pub(crate) const MANAGEMENT_SOCKET_NAME: &str = "aegis-capulus.socket";
pub(crate) const APPLICATION_SOCKET_NAME: &str = "aegis-agent.socket";
pub(crate) const ACCESS_GROUP: &str = "aegis";

pub(crate) fn product() -> Result<ManagedProduct> {
    ManagedProductOptions {
        product: "aegis".to_string(),
        package: "aegis-tool".to_string(),
        version: Version::parse(env!("CARGO_PKG_VERSION"))
            .context("aegis-tool package version is not semantic")?,
        program: ManagedProgramOptions {
            cargo_binary: "aegis".to_string(),
            installed_path: PathBuf::from(crate::platform::SYSTEM_BINARY_PATH),
            command_prefix: vec!["agent".to_string()],
        },
        service: AgentServiceOptions {
            description: "aegis mesh agent".to_string(),
            command: vec![
                "serve".to_string(),
                "--config".to_string(),
                aegis_dto::layout::AGENT_CONFIG_PATH.to_string(),
            ],
            restart_delay: Duration::from_secs(60),
            #[cfg(target_os = "linux")]
            network_required: true,
            state_directory_mode: 0o755,
            hardening: ServiceHardening::SystemNetworkController,
        },
        application_socket: SocketOptions {
            path: PathBuf::from(crate::config::AEGIS_AGENT_SOCKET_PATH),
            mode: 0o666,
            group: None,
        },
        management_socket: SocketOptions {
            path: PathBuf::from(MANAGEMENT_SOCKET_PATH),
            mode: 0o660,
            group: Some(ACCESS_GROUP.to_string()),
        },
        redeploy: ManagedRedeployOptions {
            build_timeout: Duration::from_secs(40 * 60),
            #[cfg(target_os = "linux")]
            maximum_tasks: ManagedRedeployOptions::default().maximum_tasks,
        },
    }
    .validate()
    .context("aegis managed-product declaration is invalid")
}

pub(crate) fn client() -> ManagementClient {
    let mut options = ManagementClientOptions::new(MANAGEMENT_SOCKET_PATH);
    options.timeout = Duration::from_secs(45);
    ManagementClient::new(options)
}

pub(crate) fn schedule(target: VersionTarget) -> Result<RedeployOutcome, ManagementError> {
    match client().request(ManagementRequest::Redeploy { target })? {
        ManagementResponse::Redeploy(outcome) => Ok(outcome),
        _ => Err(unexpected_response("redeploy scheduling")),
    }
}

pub(crate) fn resolve(target: VersionTarget) -> Result<ResolvedReleaseInfo, ManagementError> {
    match client().request(ManagementRequest::Resolve { target })? {
        ManagementResponse::Resolved(release) => Ok(release),
        _ => Err(unexpected_response("release resolution")),
    }
}

pub(crate) fn status(job: JobId) -> Result<RedeployJob, ManagementError> {
    match client().request(ManagementRequest::JobStatus { job })? {
        ManagementResponse::Job(status) => Ok(status),
        _ => Err(unexpected_response("redeploy status")),
    }
}

fn unexpected_response(operation: &str) -> ManagementError {
    ManagementError::Decode(format!(
        "aegis Capulus endpoint returned the wrong response for {operation}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn manifest_uses_one_launch_daemon_with_both_authenticated_sockets() {
        let product = product().unwrap();
        let manifest = product.installation_manifest();
        manifest.validate("aegis").unwrap();
        assert_eq!(manifest.enable_units, ["aegis-agent.plist"]);
        assert_eq!(manifest.files.len(), 2);
        let capulus::managed::ManagedFile::Text { contents, .. } = &manifest.files[1] else {
            panic!("launchd manifest")
        };
        assert!(contents.contains("/private/var/run/aegis-agent.sock"));
        assert!(contents.contains("/private/var/run/aegis-capulus.sock"));
        assert!(contents.contains("<integer>384</integer>"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn manifest_uses_the_single_program_and_both_systemd_sockets() {
        let product = product().unwrap();
        let manifest = product.installation_manifest();

        assert_eq!(
            product.program().installed_path(),
            std::path::Path::new(crate::platform::SYSTEM_BINARY_PATH)
        );
        assert!(manifest.files.iter().any(|file| matches!(
            file,
            capulus::managed::ManagedFile::Binary { source_name, .. }
                if source_name == "aegis"
        )));
        assert!(
            manifest
                .enable_units
                .contains(&MANAGEMENT_SOCKET_NAME.to_string())
        );
        assert!(
            manifest
                .enable_units
                .contains(&product.application_socket_name())
        );
        let service = manifest
            .files
            .iter()
            .find_map(|file| match file {
                capulus::managed::ManagedFile::Text {
                    destination,
                    contents,
                    ..
                } if destination
                    == std::path::Path::new("/etc/systemd/system/aegis-agent.service") =>
                {
                    Some(contents)
                }
                _ => None,
            })
            .expect("service unit should be present");
        assert!(
            service.contains("ExecStart=\"/usr/local/bin/aegis\" \"agent\" \"serve\" \"--config\"")
        );
    }
}
