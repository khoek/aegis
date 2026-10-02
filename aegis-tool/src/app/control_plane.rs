use std::{
    fs,
    io::{self, Read},
    path::Path,
};

use aegis_types::v1::{
    AegisDnsRecordKind, AegisDnsSyncRequest, AegisDnsSyncResponse, AegisEnrollmentCreateRequest,
    AegisSyncAction, AegisTlsDesiredState, AegisTlsSyncRequest, AegisTlsSyncResponse,
};
use anyhow::{Context, Result, bail};
use dialoguer::Password;

use crate::{
    api::AuthenticatedApiClient,
    cli::{
        AgentTokenIssueArgs, AgentTokenRevokeArgs, EnrollmentCancelArgs, EnrollmentCreateArgs,
        EnrollmentHostArgs, EnrollmentListArgs, SyncDnsArgs, SyncTlsArgs,
    },
    ui::{self, TaskOptions},
};

pub(super) fn issue_agent_token(
    api_base_override: Option<&str>,
    args: &AgentTokenIssueArgs,
) -> Result<i32> {
    let task = ui::task(TaskOptions {
        label: format!("Issuing an agent credential for `{}`", args.host),
        ..TaskOptions::default()
    })?;
    task.set_phase("loading administrator credentials");
    let mut api = admin_api(api_base_override, "aegis manage agent-token issue")?;
    task.set_phase("resolving host identity");
    let host_id = api.resolve_host_id(&args.host)?;
    task.set_phase("issuing credential");
    let response = api.issue_agent_token_response(&host_id)?;
    task.finish_and_clear();
    if args.json {
        println!("{}", serde_json::to_string(&response)?);
    } else {
        ui::success(&format!(
            "Issued an agent bootstrap token for `{}`.",
            response.aliases.primary()
        ));
        println!("{}", response.refresh_token);
    }
    Ok(0)
}

pub(super) fn revoke_agent_token(
    api_base_override: Option<&str>,
    args: &AgentTokenRevokeArgs,
) -> Result<i32> {
    let refresh_token = match args.token_file.as_deref() {
        Some(path) => read_input(path, "agent refresh token")?,
        None => prompt_refresh_token()?,
    };
    let refresh_token = refresh_token.trim();
    if refresh_token.is_empty() {
        bail!("agent refresh token must not be empty");
    }
    let task = ui::task(TaskOptions {
        label: "Revoking an agent credential".to_string(),
        ..TaskOptions::default()
    })?;
    task.set_phase("loading administrator credentials");
    let mut api = admin_api(api_base_override, "aegis manage agent-token revoke")?;
    task.set_phase("revoking credential");
    api.revoke_agent_token(refresh_token)?;
    task.finish_and_clear();
    ui::success("Revoked the agent bootstrap token.");
    Ok(0)
}

pub(super) fn create_enrollment(
    api_base_override: Option<&str>,
    args: &EnrollmentCreateArgs,
) -> Result<i32> {
    let input = read_input(&args.file, "enrollment create request")?;
    let request = serde_json::from_str::<AegisEnrollmentCreateRequest>(&input)
        .context("enrollment create request is not valid JSON")?;
    let task = ui::task(TaskOptions {
        label: format!(
            "Reserving Aegis host identity `{}`",
            request.aliases.primary()
        ),
        ..TaskOptions::default()
    })?;
    task.set_phase("loading administrator credentials");
    let mut api = admin_api(api_base_override, "aegis manage enrollment create")?;
    task.set_phase("committing enrollment reservation");
    let enrollment = api.create_enrollment(&request)?;
    task.finish_and_clear();
    if args.json {
        println!("{}", serde_json::to_string(&enrollment)?);
    } else {
        ui::success(&format!(
            "Reserved `{}` as host `{}` until {}.",
            enrollment.aliases.primary(),
            enrollment.host_id,
            enrollment.expires_unix
        ));
    }
    Ok(0)
}

pub(super) fn list_enrollments(
    api_base_override: Option<&str>,
    args: &EnrollmentListArgs,
) -> Result<i32> {
    let mut api = admin_api(api_base_override, "aegis manage enrollment list")?;
    let response = api.get_enrollments()?;
    if args.json {
        println!("{}", serde_json::to_string(&response)?);
    } else if response.enrollments.is_empty() {
        println!("No outstanding Aegis enrollments.");
    } else {
        println!("HOST ID\tALIAS\tPHASE\tEXPIRES");
        for (host_id, enrollment) in response.enrollments {
            println!(
                "{host_id}\t{}\t{:?}\t{}",
                enrollment.aliases.primary(),
                enrollment.phase,
                enrollment.expires_unix
            );
        }
    }
    Ok(0)
}

pub(super) fn get_enrollment(
    api_base_override: Option<&str>,
    args: &EnrollmentHostArgs,
) -> Result<i32> {
    let mut api = admin_api(api_base_override, "aegis manage enrollment get")?;
    let enrollment = api.get_enrollment(&args.host_id)?;
    if args.json {
        println!("{}", serde_json::to_string(&enrollment)?);
    } else {
        println!("Host: {}", enrollment.host_id);
        println!(
            "Aliases: {}",
            enrollment
                .aliases
                .iter()
                .map(aegis_types::HostAlias::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("Phase: {:?}", enrollment.phase);
        println!("Expires: {}", enrollment.expires_unix);
        println!("Credential issued: {}", enrollment.credential_issued);
    }
    Ok(0)
}

pub(super) fn issue_enrollment_credential(
    api_base_override: Option<&str>,
    args: &EnrollmentHostArgs,
) -> Result<i32> {
    let task = ui::task(TaskOptions {
        label: format!("Issuing enrollment credential for `{}`", args.host_id),
        ..TaskOptions::default()
    })?;
    task.set_phase("loading administrator credentials");
    let mut api = admin_api(api_base_override, "aegis manage enrollment credential")?;
    task.set_phase("replacing the enrollment credential");
    let response = api.issue_enrollment_credential(&args.host_id)?;
    task.finish_and_clear();
    println!(
        "{}",
        if args.json {
            serde_json::to_string(&response)?
        } else {
            serde_json::to_string_pretty(&response)?
        }
    );
    Ok(0)
}

pub(super) fn cancel_enrollment(
    api_base_override: Option<&str>,
    args: &EnrollmentCancelArgs,
) -> Result<i32> {
    let task = ui::task(TaskOptions {
        label: format!("Cancelling enrollment `{}`", args.host_id),
        ..TaskOptions::default()
    })?;
    task.set_phase("loading administrator credentials");
    let mut api = admin_api(api_base_override, "aegis manage enrollment cancel")?;
    task.set_phase("revoking the credential and releasing the reserved identity");
    api.delete_enrollment(&args.host_id)?;
    task.finish_and_clear();
    ui::success(&format!("Cancelled enrollment `{}`.", args.host_id));
    Ok(0)
}

pub(super) fn sync_dns(api_base_override: Option<&str>, args: &SyncDnsArgs) -> Result<i32> {
    let task = ui::task(TaskOptions {
        label: if args.dry_run {
            "Planning Aegis DNS reconciliation".to_string()
        } else {
            "Reconciling Aegis DNS".to_string()
        },
        ..TaskOptions::default()
    })?;
    task.set_phase("loading administrator credentials");
    let mut api = admin_api(api_base_override, "aegis manage sync-dns")?;
    task.set_phase("comparing desired and observed DNS records");
    let response = api.sync_dns(&AegisDnsSyncRequest {
        dry_run: args.dry_run,
    })?;
    task.finish_and_clear();
    if args.json {
        println!("{}", serde_json::to_string(&response)?);
    } else {
        print_dns_response(&response);
    }
    Ok(0)
}

pub(super) fn sync_tls(api_base_override: Option<&str>, args: &SyncTlsArgs) -> Result<i32> {
    let input = read_input(&args.file, "TLS desired state")?;
    let desired = serde_json::from_str::<AegisTlsDesiredState>(&input)
        .context("TLS desired state is not valid JSON")?;
    let task = ui::task(TaskOptions {
        label: if args.dry_run {
            "Planning Aegis TLS reconciliation".to_string()
        } else {
            "Reconciling Aegis TLS certificates".to_string()
        },
        ..TaskOptions::default()
    })?;
    task.set_phase("loading administrator credentials");
    let mut api = admin_api(api_base_override, "aegis manage sync-tls")?;
    task.set_phase("comparing desired and observed certificates");
    let response = api.sync_tls(&AegisTlsSyncRequest {
        desired,
        dry_run: args.dry_run,
    })?;
    task.finish_and_clear();
    if args.json {
        println!("{}", serde_json::to_string(&response)?);
    } else {
        print_tls_response(&response);
    }
    Ok(0)
}

fn admin_api(api_base_override: Option<&str>, command: &str) -> Result<AuthenticatedApiClient> {
    let mut api = AuthenticatedApiClient::load(api_base_override)?;
    api.require_user_admin(command)?;
    Ok(api)
}

fn read_input(path: &Path, description: &str) -> Result<String> {
    if path == Path::new("-") {
        if capulus::ui::stdin_is_interactive() {
            ui::current().info(format!(
                "Reading {description} from standard input; finish with Ctrl-D."
            ));
        }
        let mut input = String::new();
        io::stdin()
            .read_to_string(&mut input)
            .with_context(|| format!("failed to read {description} from standard input"))?;
        return Ok(input);
    }
    fs::read_to_string(path)
        .with_context(|| format!("failed to read {description} from {}", path.display()))
}

fn prompt_refresh_token() -> Result<String> {
    ui::require_interactive(
        "an agent refresh token is required; use --token-file PATH when running non-interactively",
    )?;
    ui::suspend(|| {
        Password::new()
            .with_prompt("Agent refresh token")
            .interact()
            .context("failed to read agent refresh token")
    })
}

fn print_dns_response(response: &AegisDnsSyncResponse) {
    for change in &response.changes {
        println!(
            "{} {} `{}` -> {}",
            action_label(change.action),
            dns_kind_label(change.kind),
            change.name,
            change.content
        );
    }
    let verb = if response.dry_run {
        "DNS plan"
    } else {
        "DNS sync"
    };
    ui::success(&format!(
        "{verb}: {} desired, {} created, {} updated, {} deleted.",
        response.desired, response.created, response.updated, response.deleted
    ));
}

fn print_tls_response(response: &AegisTlsSyncResponse) {
    for change in &response.changes {
        println!(
            "{} TLS certificate `{}`",
            action_label(change.action),
            change.label
        );
    }
    let verb = if response.dry_run {
        "TLS plan"
    } else {
        "TLS sync"
    };
    ui::success(&format!(
        "{verb}: {} desired, {} created, {} updated, {} deleted.",
        response.desired, response.created, response.updated, response.deleted
    ));
}

const fn action_label(action: AegisSyncAction) -> &'static str {
    match action {
        AegisSyncAction::Create => "create",
        AegisSyncAction::Update => "update",
        AegisSyncAction::Delete => "delete",
    }
}

const fn dns_kind_label(kind: AegisDnsRecordKind) -> &'static str {
    match kind {
        AegisDnsRecordKind::A => "A",
        AegisDnsRecordKind::AAAA => "AAAA",
    }
}
