use std::time::{Duration, Instant};

use crate::agent::AgentTunnelStatus;
use anyhow::{Context, Result, bail};

use super::local_agent;
use crate::{
    api::AuthenticatedApiClient,
    cli::{TunnelArgs, TunnelCommands, TunnelStatusArgs},
    tunnel_operation::{self as operation, Request, Snapshot, State},
    ui::{self, TaskOptions},
};

pub(super) fn run(api_base_override: Option<&str>, args: &TunnelArgs) -> Result<i32> {
    crate::platform::detect()?.require(aegis_dto::platform::Capability::InternetTunnel)?;
    anyhow::ensure!(
        crate::api::uses_local_agent(api_base_override)?,
        "Internet tunnel commands require the local agent's namespace"
    );
    match &args.command {
        TunnelCommands::Via(args) => change(
            api_base_override,
            Request {
                via: Some(args.alias.clone()),
                isolated: args.isolated,
            },
        ),
        TunnelCommands::Disable => change(
            api_base_override,
            Request {
                via: None,
                isolated: false,
            },
        ),
        TunnelCommands::Status(args) => status(api_base_override, args),
    }
}

fn change(api_base_override: Option<&str>, request: Request) -> Result<i32> {
    request.validate()?;
    let label = match &request.via {
        Some(via) if request.isolated => format!("Testing tunnel via {via}"),
        Some(via) => format!("Connecting to {via}"),
        None => "Disabling tunnel".into(),
    };
    let task = ui::task(TaskOptions {
        label,
        deadline: Some(operation::TIMEOUT + operation::RECOVERY_TIMEOUT),
        ..TaskOptions::default()
    })?;
    let mut api = AuthenticatedApiClient::load(api_base_override)?;
    api.require_user_admin("aegis tunnel")?;
    for refresh in [false, true] {
        let token = api.user_access_token(refresh)?;
        let result = local_agent::start_tunnel_operation(&token, &request)
            .and_then(|snapshot| wait(snapshot, &task));
        match result {
            Ok(message) => {
                task.finish(message);
                return Ok(0);
            }
            Err(error)
                if !refresh
                    && (error.is::<operation::Unauthorized>()
                        || local_agent::is_unauthorized(&error)) =>
            {
                continue;
            }
            Err(error) => {
                task.abandon("Tunnel operation failed");
                return Err(error);
            }
        }
    }
    unreachable!("the final authorization attempt returns")
}

fn wait(mut snapshot: Snapshot, task: &ui::Task) -> Result<String> {
    let deadline =
        Instant::now() + operation::TIMEOUT + operation::RECOVERY_TIMEOUT + Duration::from_secs(3);
    let mut interrupted = None;
    let mut last_error = None;
    let mut last_phase = String::new();
    let mut phase_changed = |phase: &str| {
        if last_phase != phase {
            task.set_phase(phase);
            last_phase = phase.to_string();
        }
    };
    loop {
        match &snapshot.state {
            State::Succeeded { message } => {
                // An interrupt racing with the commit still reports what actually happened.
                return match interrupted {
                    Some(error) => Err(error).context(message.clone()),
                    None => Ok(message.clone()),
                };
            }
            State::Failed {
                message,
                interrupted: agent_interrupted,
                unauthorized,
            } => {
                if *agent_interrupted || interrupted.is_some() {
                    return Err(anyhow::Error::new(capulus::Cancelled)).context(message.clone());
                }
                if *unauthorized {
                    return Err(anyhow::Error::new(operation::Unauthorized))
                        .context(message.clone());
                }
                bail!("{message}");
            }
            State::Running { phase } => {
                if last_error.is_none() {
                    phase_changed(phase);
                }
            }
        }
        if interrupted.is_none()
            && let Err(error) = ui::check_cancelled()
        {
            interrupted = Some(error);
            phase_changed("Cancelling");
        }
        if Instant::now() >= deadline {
            let _ = local_agent::cancel_tunnel_operation(snapshot.id);
            let detail = last_error.unwrap_or_else(|| "agent did not report completion".into());
            let message = format!(
                "local tunnel operation {} did not finish: {detail}; inspect `aegis tunnel status` for retained state",
                snapshot.id
            );
            return match interrupted {
                Some(error) => Err(error).context(message),
                None => Err(anyhow::anyhow!(message)),
            };
        }
        // Cancellation recovery must continue polling even after the UI's cancellation token fires.
        std::thread::sleep(Duration::from_millis(100));
        let result = if interrupted.is_some() {
            local_agent::cancel_tunnel_operation(snapshot.id)
        } else {
            local_agent::poll_tunnel_operation(snapshot.id)
        };
        match result {
            Ok(updated) => {
                snapshot = updated;
                last_error = None;
            }
            Err(error) => {
                phase_changed("Waiting for local agent");
                last_error = Some(format!("{error:#}"));
            }
        }
    }
}

fn status(api_base_override: Option<&str>, args: &TunnelStatusArgs) -> Result<i32> {
    let task = ui::task(TaskOptions {
        label: "Loading tunnel status".into(),
        ..TaskOptions::default()
    })?;
    let mut api = AuthenticatedApiClient::load(api_base_override)?;
    let token = api.user_access_token(false)?;
    let status = match local_agent::get_egress(&token) {
        Err(error) if local_agent::is_unauthorized(&error) => {
            local_agent::get_egress(&api.user_access_token(true)?)?
        }
        result => result?,
    };
    task.finish_and_clear();
    if args.json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        print_status(&status);
    }
    Ok(0)
}

fn print_status(status: &operation::Status) {
    let source = status
        .central
        .as_ref()
        .map(|central| central.aliases.primary().to_string())
        .or_else(|| status.aliases.get(&status.source).cloned())
        .unwrap_or_else(|| status.source.to_string());
    println!("source: {source}");
    match &status.local {
        AgentTunnelStatus::Unknown => println!("state: unknown"),
        AgentTunnelStatus::Unsupported => println!("state: unsupported"),
        AgentTunnelStatus::Disabled => println!("state: disabled"),
        AgentTunnelStatus::Enabled { via } => println!("state: enabled\nvia: {via}"),
        AgentTunnelStatus::Reconciling { active_via, .. } => println!(
            "state: changing\nvia: {}",
            active_via.as_deref().unwrap_or("direct")
        ),
    }
    if let Some(policy) = status
        .central
        .as_ref()
        .and_then(|central| central.policy.as_ref())
        && !policy.is_steady()
    {
        let requested = policy.desired_via.map(|id| {
            status
                .aliases
                .get(&id)
                .cloned()
                .unwrap_or_else(|| id.to_string())
        });
        println!("requested: {}", requested.as_deref().unwrap_or("direct"));
    }
    if let Some(operation) = &status.operation {
        match &operation.state {
            State::Running { phase } => {
                println!("operation: {phase} ({} ms elapsed)", operation.elapsed_ms)
            }
            State::Succeeded { message } => println!("last operation: {message}"),
            State::Failed { message, .. } => println!("last failure: {message}"),
        }
    }
    if status.recovery_pending {
        println!("recovery: journal pending; agent will reconcile the recorded result");
    }
    if let Some(error) = &status.central_error {
        println!("central status unavailable: {error}");
    }
}
