use aegis_types::AegisHostMode;
use anyhow::{Context, Result, anyhow, bail};

use crate::cli::{EnrollArgs, UnenrollArgs};

#[derive(Debug, Clone)]
pub(super) struct EnrollmentPlan {
    pub(super) target: EnrollTarget,
}

impl EnrollmentPlan {
    pub(super) fn parse(args: &EnrollArgs) -> Result<Self> {
        let target = if args.local {
            EnrollTarget::Local(LocalTarget)
        } else {
            let remote = args.remote.as_deref().ok_or_else(|| {
                anyhow!("`aegis manage enroll` requires either `--local` or `--remote`")
            })?;
            EnrollTarget::Remote(RemoteTarget::parse(
                remote,
                args.user.as_deref(),
                args.port,
            )?)
        };
        Ok(Self { target })
    }
}

#[derive(Debug, Clone)]
pub(super) struct LocalTarget;

#[derive(Debug, Clone)]
pub(super) struct RemoteTarget {
    pub(super) user: String,
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) login_principal: String,
}

impl RemoteTarget {
    pub(super) fn parse(
        target: &str,
        cli_user: Option<&str>,
        cli_port: Option<u16>,
    ) -> Result<Self> {
        let target = target.trim();
        if target.is_empty() {
            bail!("target must not be empty");
        }

        let target_user_count = target.matches('@').count();
        if target_user_count > 1 {
            bail!("target must not contain multiple `@` characters");
        }
        let (target_user, target_host_port) = match target.split_once('@') {
            Some((_user, _)) if cli_user.is_some() => {
                bail!("remote user was provided both in the target and via `--user`");
            }
            Some((user, host_port)) => (Some(user), host_port),
            None => (None, target),
        };

        let user = cli_user
            .or(target_user)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("remote user must be provided as USER@HOST or via `--user`"))?;
        if user.contains(char::is_whitespace) {
            bail!("remote user must not contain whitespace");
        }

        let (host, target_port) = parse_target_host_port(target_host_port)?;
        if target_port.is_some() && cli_port.is_some() {
            bail!("remote port was provided both in the target and via `--port`");
        }

        let user = user.to_string();
        let port = target_port.or(cli_port).unwrap_or(22);
        Ok(Self {
            login_principal: user.clone(),
            user,
            host,
            port,
        })
    }
}

#[derive(Debug, Clone)]
pub(super) enum EnrollTarget {
    Local(LocalTarget),
    Remote(RemoteTarget),
}

impl EnrollTarget {
    pub(super) fn parse_unenroll(args: &UnenrollArgs) -> Result<Self> {
        if args.local {
            return Ok(Self::Local(LocalTarget));
        }
        let remote = args.remote.as_deref().ok_or_else(|| {
            anyhow!("`aegis manage unenroll` requires either `--local` or `--remote`")
        })?;
        Ok(Self::Remote(RemoteTarget::parse(
            remote,
            args.user.as_deref(),
            args.port,
        )?))
    }

    pub(super) const fn label(&self) -> &'static str {
        match self {
            Self::Local(_) => "local",
            Self::Remote(_) => "remote",
        }
    }

    pub(super) fn wireguard_endpoints(&self, mode: AegisHostMode) -> Vec<String> {
        if mode != AegisHostMode::Hub {
            return Vec::new();
        }

        match self {
            Self::Local(_) => crate::metadata::gce_wireguard_endpoint_ips(),
            Self::Remote(_) => Vec::new(),
        }
    }
}

fn parse_target_host_port(input: &str) -> Result<(String, Option<u16>)> {
    let value = input.trim();
    if value.is_empty() {
        bail!("target host must not be empty");
    }

    if let Some(rest) = value.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| anyhow!("bracketed target host must end with `]`"))?;
        let host = rest[..end].trim();
        let suffix = rest[end + 1..].trim();
        if host.is_empty() {
            bail!("target host must not be empty");
        }
        if host.contains(char::is_whitespace) {
            bail!("target host must not contain whitespace");
        }
        if suffix.is_empty() {
            return Ok((host.to_string(), None));
        }
        let port = suffix
            .strip_prefix(':')
            .ok_or_else(|| anyhow!("unexpected trailing characters after bracketed target host"))?;
        return Ok((host.to_string(), Some(parse_target_port(port)?)));
    }

    let colon_count = value.matches(':').count();
    if colon_count > 1 {
        bail!("IPv6 targets must be bracketed like `[2001:db8::1]`");
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        let host = host.trim();
        if host.is_empty() {
            bail!("target host must not be empty");
        }
        if host.contains(char::is_whitespace) {
            bail!("target host must not contain whitespace");
        }
        return Ok((host.to_string(), Some(parse_target_port(port)?)));
    }
    if value.contains(char::is_whitespace) {
        bail!("target host must not contain whitespace");
    }
    Ok((value.to_string(), None))
}

fn parse_target_port(value: &str) -> Result<u16> {
    let value = value.trim();
    if value.is_empty() {
        bail!("target port must not be empty");
    }
    let port = value
        .parse::<u16>()
        .context("target port must be a valid integer between 1 and 65535")?;
    if port == 0 {
        bail!("target port must be between 1 and 65535");
    }
    Ok(port)
}
