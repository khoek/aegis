use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
#[cfg(unix)]
use std::{fs::Permissions, os::unix::fs::PermissionsExt};

use aegis_types::{HostId, v1::aegis_login_principal_from_user_cert_principal};
use anyhow::{Context, Result, anyhow, bail};
use ssh_key::{
    Algorithm, Certificate, HashAlg, LineEnding, PrivateKey, PublicKey, rand_core::OsRng,
};
use tempfile::NamedTempFile;

use crate::api::AuthenticatedApiClient;
use crate::command::{CommandOutput, require_success, run_capture};
use crate::config::{CachedHost, ensure_client_dirs};
use crate::ui;

use super::{host, known_hosts_target, line_with_newline};

pub(super) struct PreparedConnect {
    host: CachedHost,
    connect_host: String,
    login_principal: String,
    private_key_path: PathBuf,
    certificate_path: PathBuf,
    _private_key_owner: Option<NamedTempFile>,
    _certificate_owner: Option<NamedTempFile>,
    known_hosts: NamedTempFile,
    strict_server_cert: bool,
}

pub(super) struct PreparedConnectParts {
    pub(super) host: CachedHost,
    pub(super) connect_host: String,
    pub(super) login_principal: String,
    pub(super) private_key_path: PathBuf,
    pub(super) certificate_path: PathBuf,
    pub(super) private_key_owner: Option<NamedTempFile>,
    pub(super) certificate_owner: Option<NamedTempFile>,
    pub(super) known_hosts: NamedTempFile,
    pub(super) strict_server_cert: bool,
}

pub(super) trait ConnectStatus {
    fn set_status(&self, message: &str);
}

impl ConnectStatus for ui::Task {
    fn set_status(&self, message: &str) {
        self.set_phase(message);
    }
}

impl PreparedConnect {
    pub(super) fn new(parts: PreparedConnectParts) -> Self {
        Self {
            host: parts.host,
            connect_host: parts.connect_host,
            login_principal: parts.login_principal,
            private_key_path: parts.private_key_path,
            certificate_path: parts.certificate_path,
            _private_key_owner: parts.private_key_owner,
            _certificate_owner: parts.certificate_owner,
            known_hosts: parts.known_hosts,
            strict_server_cert: parts.strict_server_cert,
        }
    }

    pub(super) fn host(&self) -> &CachedHost {
        &self.host
    }

    pub(super) fn connect_host(&self) -> &str {
        &self.connect_host
    }

    pub(super) fn ssh_port(&self) -> u16 {
        host::host_ssh_port(&self.host)
            .expect("prepared SSH connections must target hosts with SSH access")
    }

    pub(super) fn ssh_user(&self) -> &str {
        &self.login_principal
    }

    pub(super) fn destination(&self) -> SshDestination<'_> {
        SshDestination::new(self.ssh_user(), &self.connect_host, self.ssh_port())
    }

    pub(super) fn destination_label(&self) -> String {
        self.destination().label()
    }

    pub(super) fn ssh_args(
        &self,
        extra_ssh_args: &[String],
        remote_command: Option<&str>,
        control_socket: Option<&Path>,
        master_only: bool,
    ) -> Vec<String> {
        let mut args = self.ssh_transport_args(extra_ssh_args, control_socket, master_only);
        args.push(self.destination().login());
        if let Some(remote_command) = remote_command {
            args.push(remote_command.to_string());
        }
        args
    }

    pub(super) fn ssh_transport_args(
        &self,
        extra_ssh_args: &[String],
        control_socket: Option<&Path>,
        master_only: bool,
    ) -> Vec<String> {
        let mut args = Vec::new();
        args.extend(
            [
                "-o",
                "BatchMode=yes",
                "-o",
                "PreferredAuthentications=publickey",
                "-o",
                "PubkeyAuthentication=yes",
                "-o",
                "PasswordAuthentication=no",
                "-o",
                "KbdInteractiveAuthentication=no",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "ForwardAgent=yes",
                "-o",
                "StrictHostKeyChecking=yes",
            ]
            .into_iter()
            .map(str::to_string),
        );
        args.push("-o".to_string());
        args.push(format!(
            "UserKnownHostsFile={}",
            self.known_hosts.path().display()
        ));
        args.extend(
            [
                "-o",
                "GlobalKnownHostsFile=/dev/null",
                "-o",
                "UpdateHostKeys=no",
                "-o",
                "HostbasedAuthentication=no",
                "-o",
                "VerifyHostKeyDNS=no",
                "-o",
            ]
            .into_iter()
            .map(str::to_string),
        );
        args.push(if self.strict_server_cert {
            "HostKeyAlgorithms=ssh-ed25519-cert-v01@openssh.com".to_string()
        } else {
            "HostKeyAlgorithms=ssh-ed25519".to_string()
        });
        args.push("-i".to_string());
        args.push(self.private_key_path.display().to_string());
        args.push("-o".to_string());
        args.push(format!(
            "CertificateFile={}",
            self.certificate_path.display()
        ));
        args.push("-p".to_string());
        args.push(self.ssh_port().to_string());

        if let Some(socket) = control_socket {
            args.push("-S".to_string());
            args.push(socket.display().to_string());
        }

        if master_only {
            args.extend(
                ["-M", "-o", "ControlPersist=no", "-N"]
                    .into_iter()
                    .map(str::to_string),
            );
        }

        args.extend(extra_ssh_args.iter().cloned());
        args
    }

    pub(super) fn ssh_command(
        &self,
        extra_ssh_args: &[String],
        remote_command: Option<&str>,
        control_socket: Option<&Path>,
        master_only: bool,
    ) -> Command {
        let mut command = Command::new("ssh");
        command.args(self.ssh_args(extra_ssh_args, remote_command, control_socket, master_only));
        command
    }

    pub(super) fn timed_ssh_command(
        &self,
        extra_ssh_args: &[String],
        remote_command: Option<&str>,
        control_socket: Option<&Path>,
        master_only: bool,
        timeout: Duration,
    ) -> Command {
        let mut command = Command::new("timeout");
        command.arg(format!("{}s", timeout.as_secs()));
        command.arg("ssh");
        command.args(self.ssh_args(extra_ssh_args, remote_command, control_socket, master_only));
        command
    }

    pub(super) fn run_remote_command(&self, remote_command: &str) -> Result<()> {
        let mut command = self.ssh_command(&[], Some(remote_command), None, false);
        let output = require_success("run strict ssh command", &mut command)?;
        if !output.stdout.trim().is_empty() {
            ui::detail(output.stdout.trim());
        }
        Ok(())
    }
}

pub(super) struct AssetPreparer<'a> {
    network: &'a str,
    host: &'a CachedHost,
    connect_host: String,
    presentation_host: Option<String>,
    requested_login_principal: Option<String>,
    strict_server_cert: bool,
}

impl<'a> AssetPreparer<'a> {
    pub(super) fn new(
        network: &'a str,
        host: &'a CachedHost,
        connect_host: String,
        requested_login_principal: Option<String>,
        no_server_cert: bool,
    ) -> Self {
        Self {
            network,
            host,
            connect_host,
            presentation_host: None,
            requested_login_principal,
            strict_server_cert: !no_server_cert,
        }
    }

    pub(super) fn with_presentation_host(mut self, presentation_host: String) -> Self {
        self.presentation_host = Some(presentation_host);
        self
    }

    pub(super) fn prepare_quiet(self, api: &mut AuthenticatedApiClient) -> Result<PreparedConnect> {
        self.prepare_inner(api, None)
    }

    pub(super) fn prepare_with_status(
        self,
        api: &mut AuthenticatedApiClient,
        status: &dyn ConnectStatus,
    ) -> Result<PreparedConnect> {
        self.prepare_inner(api, Some(status))
    }

    fn prepare_inner(
        self,
        api: &mut AuthenticatedApiClient,
        status: Option<&dyn ConnectStatus>,
    ) -> Result<PreparedConnect> {
        let identity = ClientIdentityCache::new(self.network, self.host.host_id, self.host.alias())
            .prepare(api, status)?;
        let login_principal = select_login_principal(
            self.host.alias().as_str(),
            self.requested_login_principal.as_deref(),
            &identity.login_principals,
        )?;
        let known_hosts = if self.strict_server_cert {
            self.known_hosts_with_server_ca(&ensure_server_ca_public_key(api)?, status)?
        } else {
            self.known_hosts_with_pinned_host_key(status)?
        };
        Ok(self.prepared_connect(identity, known_hosts, login_principal))
    }

    fn known_hosts_with_server_ca(
        &self,
        server_ca: &PublicKey,
        status: Option<&dyn ConnectStatus>,
    ) -> Result<NamedTempFile> {
        preflight_server_certificate(
            self.host,
            &self.connect_host,
            self.presentation_host(),
            server_ca,
            status,
        )?;
        let mut known_hosts = NamedTempFile::new()?;
        writeln!(
            known_hosts,
            "@cert-authority {} {}",
            known_hosts_target(&self.connect_host, host::host_ssh_port(self.host)?),
            server_ca.to_openssh()?
        )?;
        known_hosts.flush()?;
        Ok(known_hosts)
    }

    fn known_hosts_with_pinned_host_key(
        &self,
        status: Option<&dyn ConnectStatus>,
    ) -> Result<NamedTempFile> {
        preflight_pinned_host_key(
            self.host,
            &self.connect_host,
            self.presentation_host(),
            status,
        )?;
        let mut known_hosts = NamedTempFile::new()?;
        writeln!(
            known_hosts,
            "{} {}",
            known_hosts_target(&self.connect_host, host::host_ssh_port(self.host)?),
            cached_host_public_key(self.host)?.trim()
        )?;
        known_hosts.flush()?;
        Ok(known_hosts)
    }

    fn presentation_host(&self) -> &str {
        self.presentation_host
            .as_deref()
            .unwrap_or(&self.connect_host)
    }

    fn prepared_connect(
        self,
        identity: PreparedClientIdentitySnapshot,
        known_hosts: NamedTempFile,
        login_principal: String,
    ) -> PreparedConnect {
        PreparedConnect::new(PreparedConnectParts {
            host: self.host.clone(),
            connect_host: self.connect_host,
            login_principal,
            private_key_path: identity.private_key_path,
            certificate_path: identity.certificate_path,
            private_key_owner: Some(identity.private_key_owner),
            certificate_owner: Some(identity.certificate_owner),
            known_hosts,
            strict_server_cert: self.strict_server_cert,
        })
    }
}

struct ClientIdentityCache<'a> {
    network: &'a str,
    host_id: HostId,
    alias: &'a str,
}

impl<'a> ClientIdentityCache<'a> {
    fn new(network: &'a str, host_id: HostId, alias: &'a impl AsRef<str>) -> Self {
        Self {
            network,
            host_id,
            alias: alias.as_ref(),
        }
    }

    fn prepare(
        &self,
        api: &mut AuthenticatedApiClient,
        status: Option<&dyn ConnectStatus>,
    ) -> Result<PreparedClientIdentitySnapshot> {
        let _lock = crate::locks::host_shell_assets_lock(&self.host_id)?;
        ensure_client_dirs()?;
        let (private_key_path, public_key) = self.ensure_keypair(api.api_base(), status)?;
        let certificate = self.request_certificate(api, &public_key, status)?;
        PreparedClientIdentitySnapshot::new(
            &private_key_path,
            certificate.owner,
            certificate.login_principals,
        )
    }

    fn ensure_keypair(
        &self,
        api_base: &str,
        status: Option<&dyn ConnectStatus>,
    ) -> Result<(PathBuf, String)> {
        let private_path = crate::config::scoped_private_key_path(api_base, &self.host_id)?;
        let public_path = private_path.with_extension("pub");

        if let Some(public_key) = load_existing_keypair(&private_path, &public_path)? {
            return Ok((private_path, public_key));
        }

        if let Some(status) = status {
            status.set_status(&format!("Generating SSH keypair     {}", self.alias));
        }
        let private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .context("failed to generate ed25519 keypair")?;
        private_key
            .write_openssh_file(&private_path, LineEnding::LF)
            .with_context(|| format!("failed to write {}", private_path.display()))?;
        let mut public_key = private_key.public_key().to_openssh()?;
        public_key.push('\n');
        fs::write(&public_path, public_key.as_bytes())
            .with_context(|| format!("failed to write {}", public_path.display()))?;

        Ok((private_path, public_key.trim().to_string()))
    }

    fn request_certificate(
        &self,
        api: &mut AuthenticatedApiClient,
        public_key: &str,
        status: Option<&dyn ConnectStatus>,
    ) -> Result<PreparedClientCertificate> {
        if let Some(status) = status {
            status.set_status(&format!("Refreshing SSH cert       {}", self.alias));
        }
        let cert =
            api.request_network_member_client_cert(self.network, &self.host_id, public_key)?;
        let login_principals =
            client_certificate_login_principals(&self.host_id, &cert.certificate)?;
        let mut certificate = NamedTempFile::new().with_context(|| {
            format!(
                "failed to create temporary SSH certificate for {}",
                self.alias
            )
        })?;
        certificate.write_all(line_with_newline(&cert.certificate).as_bytes())?;
        certificate.flush()?;
        #[cfg(unix)]
        fs::set_permissions(certificate.path(), Permissions::from_mode(0o600))
            .with_context(|| format!("failed to chmod {}", certificate.path().display()))?;
        Ok(PreparedClientCertificate {
            owner: certificate,
            login_principals,
        })
    }
}

struct PreparedClientCertificate {
    owner: NamedTempFile,
    login_principals: Vec<String>,
}

struct PreparedClientIdentitySnapshot {
    private_key_path: PathBuf,
    private_key_owner: NamedTempFile,
    certificate_path: PathBuf,
    certificate_owner: NamedTempFile,
    login_principals: Vec<String>,
}

impl PreparedClientIdentitySnapshot {
    fn new(
        private_key_path: &Path,
        certificate_owner: NamedTempFile,
        login_principals: Vec<String>,
    ) -> Result<Self> {
        let (private_key_path, private_key_owner) = snapshot_locked_file(private_key_path, 0o600)?;
        let certificate_path = certificate_owner.path().to_path_buf();
        Ok(Self {
            private_key_path,
            private_key_owner,
            certificate_path,
            certificate_owner,
            login_principals,
        })
    }
}

fn snapshot_locked_file(path: &Path, mode: u32) -> Result<(PathBuf, NamedTempFile)> {
    let mut snapshot = NamedTempFile::new().with_context(|| {
        format!(
            "failed to create a temporary snapshot for {}",
            path.display()
        )
    })?;
    snapshot.write_all(
        &fs::read(path).with_context(|| format!("failed to read {}", path.display()))?,
    )?;
    snapshot
        .flush()
        .with_context(|| format!("failed to flush snapshot for {}", path.display()))?;
    #[cfg(unix)]
    fs::set_permissions(snapshot.path(), Permissions::from_mode(mode))
        .with_context(|| format!("failed to chmod {}", snapshot.path().display()))?;
    Ok((snapshot.path().to_path_buf(), snapshot))
}

pub(super) fn load_existing_keypair(
    private_path: &Path,
    public_path: &Path,
) -> Result<Option<String>> {
    if !private_path.exists() || !public_path.exists() {
        return Ok(None);
    }

    let private_key = match PrivateKey::read_openssh_file(private_path) {
        Ok(private_key) => private_key,
        Err(error) => {
            ui::warn(&format!(
                "discarding unreadable cached private key at {}: {error}",
                private_path.display()
            ));
            return Ok(None);
        }
    };
    let public_key_raw = fs::read_to_string(public_path)
        .with_context(|| format!("failed to read {}", public_path.display()))?;
    let public_key = match PublicKey::from_openssh(public_key_raw.trim()) {
        Ok(public_key) => public_key,
        Err(error) => {
            ui::warn(&format!(
                "discarding unreadable cached public key at {}: {error}",
                public_path.display()
            ));
            return Ok(None);
        }
    };
    if private_key.public_key() != &public_key {
        ui::warn(&format!(
            "discarding cached keypair because {} and {} do not match",
            private_path.display(),
            public_path.display()
        ));
        return Ok(None);
    }

    Ok(Some(public_key.to_openssh()?))
}

fn ensure_server_ca_public_key(api: &AuthenticatedApiClient) -> Result<PublicKey> {
    let response = api
        .get_server_ca_public_key()
        .context("failed to refresh the server CA public key from the API")?;
    PublicKey::from_openssh(&response.public_key)
        .context("server CA public key from the API is invalid")
}

fn client_certificate_login_principals(
    host_id: &HostId,
    certificate_line: &str,
) -> Result<Vec<String>> {
    let certificate = Certificate::from_openssh(certificate_line)
        .context("issued SSH client certificate from the API is invalid")?;
    let mut login_principals = certificate
        .valid_principals()
        .iter()
        .filter_map(|principal| aegis_login_principal_from_user_cert_principal(host_id, principal))
        .collect::<Vec<_>>();
    login_principals.sort();
    login_principals.dedup();
    if login_principals.is_empty() {
        bail!(
            "issued SSH client certificate for host `{host_id}` contains no Aegis login principals"
        );
    }
    Ok(login_principals)
}

fn select_login_principal(
    host_alias: &str,
    requested: Option<&str>,
    available: &[String],
) -> Result<String> {
    if let Some(requested) = requested.map(str::trim).filter(|value| !value.is_empty()) {
        host::validate_login_principal(requested)?;
        if available.iter().any(|principal| principal == requested) {
            return Ok(requested.to_string());
        }
        bail!(
            "requested login principal `{requested}` is not authorized by the issued SSH certificate for `{host_alias}`; available login principals: {}",
            login_principal_list(available)
        );
    }
    match available {
        [] => {
            bail!("issued SSH client certificate for `{host_alias}` contains no login principals")
        }
        [only] => Ok(only.clone()),
        _ => bail!(
            "issued SSH client certificate for `{host_alias}` authorizes multiple login principals: {}; specify one explicitly",
            login_principal_list(available)
        ),
    }
}

fn login_principal_list(principals: &[String]) -> String {
    principals
        .iter()
        .map(|principal| format!("`{principal}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

const SSH_KEYSCAN_ATTEMPT_TIMEOUT_SECONDS: u64 = 5;
const SSH_KEYSCAN_TOTAL_TIMEOUT: Duration = Duration::from_secs(20);
const SSH_KEYSCAN_RETRY_DELAY: Duration = Duration::from_millis(500);

fn preflight_server_certificate(
    host: &CachedHost,
    connect_host: &str,
    presentation_host: &str,
    server_ca: &PublicKey,
    status: Option<&dyn ConnectStatus>,
) -> Result<()> {
    let scanned = ssh_keyscan(
        connect_host,
        presentation_host,
        host::host_ssh_port(host)?,
        true,
        status,
    )?;
    let certificate = parse_scanned_certificate(&scanned)?;
    let fingerprint = server_ca.fingerprint(HashAlg::Sha256);
    certificate
        .validate([&fingerprint])
        .context("presented server certificate failed CA validation")?;
    if !certificate
        .valid_principals()
        .iter()
        .any(|principal| principal == connect_host)
    {
        bail!("presented server certificate does not authorize {connect_host}");
    }
    let cached_public_key = PublicKey::from_openssh(cached_host_public_key(host)?)
        .context("cached host public key is invalid")?;
    if cached_public_key.key_data() != certificate.public_key() {
        bail!(
            "presented server certificate was issued for a different host key than the pinned key for {}",
            host.alias()
        );
    }
    Ok(())
}

fn preflight_pinned_host_key(
    host: &CachedHost,
    connect_host: &str,
    presentation_host: &str,
    status: Option<&dyn ConnectStatus>,
) -> Result<()> {
    let scanned = ssh_keyscan(
        connect_host,
        presentation_host,
        host::host_ssh_port(host)?,
        false,
        status,
    )?;
    let scanned_public_key = parse_scanned_public_key(&scanned)?;
    let cached_public_key = PublicKey::from_openssh(cached_host_public_key(host)?)
        .context("cached host public key is invalid")?;
    if scanned_public_key.key_data() != cached_public_key.key_data() {
        bail!(
            "presented host key for {} does not match the pinned host key",
            host.alias()
        );
    }
    Ok(())
}

fn cached_host_public_key(host: &CachedHost) -> Result<&str> {
    host::host_registration_ssh_public_key(host)
        .ok_or_else(|| anyhow!("host `{}` has no pinned host public key", host.alias()))
}

fn ssh_keyscan(
    host: &str,
    presentation_host: &str,
    port: u16,
    request_cert: bool,
    status: Option<&dyn ConnectStatus>,
) -> Result<String> {
    if let Some(status) = status {
        status.set_status(&format!(
            "Verifying host identity   {presentation_host}:{port}"
        ));
    }
    let started = Instant::now();
    let mut attempts = 0;

    let last_failure = loop {
        attempts += 1;
        if let Some(status) = status {
            if attempts == 1 {
                status.set_status(&format!(
                    "Verifying host identity   {presentation_host}:{port}"
                ));
            } else {
                status.set_status(&format!(
                    "Verifying host identity   {presentation_host}:{port} attempt {attempts}"
                ));
            }
        }

        let output = run_ssh_keyscan(host, port, request_cert)?;
        if let Some(line) = keyscan_output_line(&output) {
            return Ok(line.to_string());
        }

        let failure = SshKeyscanAttemptFailure::from_output(output);
        if started.elapsed() >= SSH_KEYSCAN_TOTAL_TIMEOUT {
            break failure;
        }
        ui::sleep(
            SSH_KEYSCAN_RETRY_DELAY
                .min(SSH_KEYSCAN_TOTAL_TIMEOUT.saturating_sub(started.elapsed())),
        )?;
    };
    bail!(
        "{}",
        keyscan_failure_message(
            host,
            port,
            request_cert,
            attempts,
            started.elapsed(),
            &last_failure,
        )
    )
}

fn run_ssh_keyscan(host: &str, port: u16, request_cert: bool) -> Result<CommandOutput> {
    let mut command = Command::new("ssh-keyscan");
    command.arg("-T");
    command.arg(SSH_KEYSCAN_ATTEMPT_TIMEOUT_SECONDS.to_string());
    command.arg("-p");
    command.arg(port.to_string());
    command.arg("-t");
    command.arg("ed25519");
    if request_cert {
        command.arg("-c");
    }
    command.arg(host);
    run_capture(&mut command).context("failed to run ssh-keyscan")
}

fn keyscan_output_line(output: &CommandOutput) -> Option<&str> {
    output
        .stdout
        .lines()
        .find(|line| !line.trim().is_empty() && !line.starts_with('#'))
}

struct SshKeyscanAttemptFailure {
    status: String,
    stdout: String,
    stderr: String,
}

impl SshKeyscanAttemptFailure {
    fn from_output(output: CommandOutput) -> Self {
        Self {
            status: output.status.to_string(),
            stdout: output.stdout,
            stderr: output.stderr,
        }
    }
}

fn keyscan_failure_message(
    host: &str,
    port: u16,
    request_cert: bool,
    attempts: u32,
    elapsed: Duration,
    last_failure: &SshKeyscanAttemptFailure,
) -> String {
    let kind = if request_cert {
        "SSH host certificate"
    } else {
        "SSH host key"
    };
    let mut lines = vec![
        format!(
            "ssh-keyscan did not return a usable {kind} for {host}:{port} after {attempts} \
attempts over {:.1}s",
            elapsed.as_secs_f32()
        ),
        format!(
            "command: ssh-keyscan -T {SSH_KEYSCAN_ATTEMPT_TIMEOUT_SECONDS} -p {port} -t ed25519{} {host}",
            if request_cert { " -c" } else { "" }
        ),
    ];
    lines.push(format!("last exit status: {}", last_failure.status));
    lines.push(format!(
        "last stderr: {}",
        compact_process_stream(normalized_keyscan_stderr(&last_failure.stderr))
    ));
    lines.push(format!(
        "last stdout: {}",
        compact_process_stream(&last_failure.stdout)
    ));
    lines.join("\n")
}

fn normalized_keyscan_stderr(stderr: &str) -> &str {
    stderr
        .trim()
        .strip_prefix("getaddrinfo ")
        .unwrap_or(stderr.trim())
}

fn compact_process_stream(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "<empty>".to_string();
    }
    let line = trimmed
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" | ");
    truncate_chars(&line, 500)
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    let mut truncated = value.chars().take(max_chars).collect::<String>();
    if value.chars().count() > max_chars {
        truncated.push_str("...");
    }
    truncated
}

fn parse_scanned_certificate(line: &str) -> Result<Certificate> {
    let (algorithm, base64) = scanned_key_fields(line)?;
    let certificate = format!("{algorithm} {base64}");
    Certificate::from_openssh(&certificate).context("failed to parse scanned host certificate")
}

fn parse_scanned_public_key(line: &str) -> Result<PublicKey> {
    let (algorithm, base64) = scanned_key_fields(line)?;
    let public_key = format!("{algorithm} {base64}");
    PublicKey::from_openssh(&public_key).context("failed to parse scanned host public key")
}

pub(super) fn scanned_key_fields(line: &str) -> Result<(&str, &str)> {
    let mut fields = line.split_whitespace();
    let first = fields
        .next()
        .ok_or_else(|| anyhow!("missing algorithm field"))?;
    let second = fields
        .next()
        .ok_or_else(|| anyhow!("missing key data field"))?;
    let third = fields.next();

    match third {
        Some(base64) => Ok((second, base64)),
        None => Ok((first, second)),
    }
}

pub(super) struct SshDestination<'a> {
    user: &'a str,
    host: &'a str,
    port: u16,
}

impl<'a> SshDestination<'a> {
    pub(super) fn new(user: &'a str, host: &'a str, port: u16) -> Self {
        Self { user, host, port }
    }

    pub(super) fn label(&self) -> String {
        if self.port == 22 {
            format!("{}@{}", self.user, self.host_literal())
        } else {
            format!("{}@{}:{}", self.user, self.host_literal(), self.port)
        }
    }

    fn login(&self) -> String {
        format!("{}@{}", self.user, self.host)
    }

    fn host_literal(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.to_string()
        }
    }
}
