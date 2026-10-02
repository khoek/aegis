mod admin;
mod agent;
mod agent_credentials;
mod api;
mod app;
mod apparmor;
mod cli;
mod command;
mod config;
mod egress_probe;
mod invitation;
mod locks;
mod managed;
mod metadata;
mod principal_grants;
mod redeploy_version;
mod release;
mod system_user;
mod tunnel_operation;
mod ui;
mod wireguard_endpoint;

use std::sync::Arc;

use anyhow::{Result, bail};
use clap::Parser;

use crate::cli::{AgentCommands, Cli, Commands};

pub fn run_cli() -> capulus::CliTermination {
    let Cli {
        api_base,
        namespace,
        ui: ui_options,
        command,
    } = Cli::parse();
    if matches!(command, Commands::Agent(_)) && (api_base.is_some() || namespace.is_some()) {
        return capulus::CliTermination::without_ui(Err(anyhow::anyhow!(
            "agent commands use the enrolled context in their configuration; --api-base and --namespace apply to CLI operations"
        )));
    }
    let ui_configuration = ui_options.options(&command);
    match command {
        Commands::Agent(agent) => match agent.command {
            AgentCommands::DirectSsh => {
                if let Err(error) = ui::init(ui_configuration) {
                    return capulus::CliTermination::without_ui(Err(error));
                }
                capulus::CliTermination::with_ui(ui::current(), app::run_direct_ssh())
            }
            command => capulus::CliTermination::without_ui(run_agent(command).map(|()| 0)),
        },
        command => {
            if let Err(error) = ui::init(ui_configuration) {
                return capulus::CliTermination::without_ui(Err(error));
            }
            capulus::CliTermination::with_ui(
                ui::current(),
                app::run(Cli {
                    api_base,
                    namespace,
                    ui: ui_options,
                    command,
                }),
            )
        }
    }
}

fn run_agent(command: AgentCommands) -> Result<()> {
    match command {
        AgentCommands::Serve(args) => {
            require_agent_root()?;
            let status = agent::run(&args)?;
            if status == 0 {
                Ok(())
            } else {
                bail!("aegis-agent exited with status {status}")
            }
        }
        AgentCommands::DirectSsh => {
            unreachable!("the direct SSH endpoint is dispatched with the interactive UI")
        }
        AgentCommands::Lifecycle(command) => {
            let product = Arc::new(managed::product()?);
            let health_product = Arc::clone(&product);
            command.run(product, move || {
                app::application_agent_info(&health_product)
            })
        }
        AgentCommands::EgressProbeWorker => {
            require_agent_root()?;
            // The supervising agent receives stderr, so include the complete cause in
            // the worker's display message while preserving typed interruption.
            egress_probe::run_worker().map_err(|error| {
                let detail = format!("{error:#}");
                error.context(detail)
            })
        }
    }
}

fn require_agent_root() -> Result<()> {
    if rustix::process::geteuid().is_root() {
        Ok(())
    } else {
        bail!("aegis agent operations must run as root")
    }
}
