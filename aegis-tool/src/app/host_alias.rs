use std::time::{Duration, Instant};

use aegis_dto::{HostAlias, HostAliases, HostId, v1::AegisHost};
use anyhow::{Context, Result, anyhow, bail};

use crate::api::AuthenticatedApiClient;
use crate::cli::{
    HostAliasCommands, HostAliasWaitArgs, HostAliasesArgs, HostArgs, HostCommands, HostListArgs,
};
use crate::config::now_unix;
use crate::ui::{self, TaskKind, TaskOptions, TaskVisibility};

const AGENT_CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const POLL_INTERVAL: Duration = Duration::from_secs(2);

pub(super) fn run(api_base_override: Option<&str>, args: &HostArgs) -> Result<i32> {
    match &args.command {
        HostCommands::List(args) => list(api_base_override, args),
        HostCommands::Alias(args) => run_alias(api_base_override, args),
    }
}

fn list(api_base_override: Option<&str>, args: &HostListArgs) -> Result<i32> {
    let task = ui::task(TaskOptions {
        label: "Loading host aliases".to_string(),
        ..TaskOptions::default()
    })?;
    let mut api = AuthenticatedApiClient::load(api_base_override)?;
    let inventory = api.get_hosts()?;
    task.finish_and_clear();
    if args.json {
        println!("{}", serde_json::to_string(&inventory)?);
        return Ok(0);
    }
    for (host_id, host) in inventory.hosts {
        println!("{host_id}\t{}", aliases_text(&host.aliases));
    }
    Ok(0)
}

fn run_alias(api_base_override: Option<&str>, args: &HostAliasesArgs) -> Result<i32> {
    let task = ui::task(TaskOptions {
        label: "Preparing host alias change".to_string(),
        ..TaskOptions::default()
    })?;
    task.set_phase("loading OAuth credentials");
    let mut api = AuthenticatedApiClient::load(api_base_override)?;
    task.set_phase("checking administrator authorization");
    api.require_user_admin("aegis manage host alias")?;
    task.finish_and_clear();

    match &args.command {
        HostAliasCommands::Add(args) => mutate_alias(
            &mut api,
            AliasMutationRequest {
                mutation: AliasMutation::Add,
                alias: &args.alias,
                host: MutationHost::Explicit(&args.host),
                wait: &args.wait,
            },
        ),
        HostAliasCommands::Promote(args) => mutate_alias(
            &mut api,
            AliasMutationRequest {
                mutation: AliasMutation::Promote,
                alias: &args.alias,
                host: MutationHost::AliasOwner,
                wait: &args.wait,
            },
        ),
        HostAliasCommands::Remove(args) => mutate_alias(
            &mut api,
            AliasMutationRequest {
                mutation: AliasMutation::Remove,
                alias: &args.alias,
                host: MutationHost::AliasOwner,
                wait: &args.wait,
            },
        ),
    }
}

struct AliasMutationRequest<'a> {
    mutation: AliasMutation,
    alias: &'a HostAlias,
    host: MutationHost<'a>,
    wait: &'a HostAliasWaitArgs,
}

#[derive(Clone, Copy)]
enum MutationHost<'a> {
    Explicit(&'a str),
    AliasOwner,
}

impl MutationHost<'_> {
    fn resolve(self, api: &mut AuthenticatedApiClient, alias: &HostAlias) -> Result<HostId> {
        match self {
            Self::Explicit(host) => api.resolve_host_id(host),
            Self::AliasOwner => Ok(api.get_alias(alias)?.host_id),
        }
    }

    fn task_label(self, mutation: AliasMutation, alias: &HostAlias) -> String {
        match self {
            Self::Explicit(host) => format!(
                "{} alias `{alias}` on `{host}`",
                mutation.present_participle()
            ),
            Self::AliasOwner => {
                format!("{} alias `{alias}`", mutation.present_participle())
            }
        }
    }
}

#[derive(Clone, Copy)]
enum AliasMutation {
    Add,
    Promote,
    Remove,
}

impl AliasMutation {
    const fn present_participle(self) -> &'static str {
        match self {
            Self::Add => "Adding",
            Self::Promote => "Promoting",
            Self::Remove => "Removing",
        }
    }

    const fn noun(self) -> &'static str {
        match self {
            Self::Add => "alias addition",
            Self::Promote => "alias promotion",
            Self::Remove => "alias removal",
        }
    }

    fn apply(
        self,
        api: &mut AuthenticatedApiClient,
        host_id: &HostId,
        alias: &HostAlias,
    ) -> Result<AegisHost> {
        match self {
            Self::Add => api.add_host_alias(host_id, alias),
            Self::Promote => api.promote_host_alias(host_id, alias),
            Self::Remove => api.remove_host_alias(host_id, alias),
        }
    }

    fn completion(self, host_id: HostId, aliases: &HostAliases) -> String {
        match self {
            Self::Promote => format!(
                "Primary alias for host `{host_id}` is now `{}`.",
                aliases.primary()
            ),
            Self::Add | Self::Remove => {
                format!("Host `{host_id}` aliases: {}", aliases_text(aliases))
            }
        }
    }
}

fn mutate_alias(
    api: &mut AuthenticatedApiClient,
    request: AliasMutationRequest<'_>,
) -> Result<i32> {
    let mutation = request.mutation;
    let mutation_task = ui::task(TaskOptions {
        label: request.host.task_label(mutation, request.alias),
        visibility: TaskVisibility::Immediate,
        ..TaskOptions::default()
    })?;
    mutation_task.set_phase("resolving host identity");
    let host_id = request.host.resolve(api, request.alias)?;
    mutation_task.set_phase("committing control-plane alias and DNS state");
    let host = match mutation.apply(api, &host_id, request.alias) {
        Ok(host) => host,
        Err(error) => {
            mutation_task.abandon(
                "The control-plane response failed; alias state is unknown and must be inspected",
            );
            return Err(error).context(
                "alias mutation may have reached the control plane; inspect `aegis manage host list` before retrying",
            );
        }
    };
    let retained_state = format!("host `{host_id}` aliases [{}]", aliases_text(&host.aliases));
    mutation_task.finish(format!("Control-plane change committed: {retained_state}"));

    if request.wait.no_wait {
        ui::success(&format!(
            "{} Agent convergence was not requested.",
            mutation.completion(host_id, &host.aliases)
        ));
        return Ok(0);
    }

    wait_for_agent_and_propagation(
        api,
        host_id,
        &host.aliases,
        Duration::from_secs(request.wait.propagation_wait_secs),
        mutation.noun(),
        &retained_state,
    )?;
    ui::success(&mutation.completion(host_id, &host.aliases));
    Ok(0)
}

fn wait_for_agent_and_propagation(
    api: &mut AuthenticatedApiClient,
    host_id: HostId,
    desired: &HostAliases,
    propagation_wait: Duration,
    change: &str,
    retained_state: &str,
) -> Result<()> {
    let convergence_deadline = Instant::now() + AGENT_CONVERGENCE_TIMEOUT;
    loop {
        wait_for_agent(
            api,
            host_id,
            desired,
            convergence_deadline,
            change,
            retained_state,
        )?;
        if propagation_wait.is_zero() {
            return Ok(());
        }
        if hold_propagation_window(api, host_id, desired, propagation_wait, retained_state)? {
            return Ok(());
        }
        if Instant::now() >= convergence_deadline {
            bail!(
                "host `{host_id}` lost alias convergence after {change}; {retained_state} remains committed"
            );
        }
    }
}

fn wait_for_agent(
    api: &mut AuthenticatedApiClient,
    host_id: HostId,
    desired: &HostAliases,
    deadline: Instant,
    change: &str,
    retained_state: &str,
) -> Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        bail!(
            "host `{host_id}` did not converge before the alias deadline; {retained_state} remains committed"
        );
    }
    let task = ui::task(TaskOptions {
        label: format!("Waiting for `{host_id}` to apply its alias state"),
        deadline: Some(remaining),
        visibility: TaskVisibility::Immediate,
        ..TaskOptions::default()
    })?;
    loop {
        let host = match fetch_host(api, host_id, change) {
            Ok(host) => host,
            Err(error) => {
                task.abandon(format!(
                    "Agent status check failed; {retained_state} remains committed"
                ));
                return Err(error).with_context(|| {
                    format!("alias status check failed; {retained_state} remains committed")
                });
            }
        };
        task.set_detail(agent_alias_detail(&host));
        if applied_aliases(&host) == Some(desired) {
            task.finish(format!(
                "Host agent applied aliases [{}]",
                aliases_text(desired)
            ));
            return Ok(());
        }
        if Instant::now() >= deadline {
            let applied = applied_aliases(&host)
                .map(aliases_text)
                .unwrap_or_else(|| "not reported".to_string());
            task.abandon(format!(
                "Agent convergence timed out; {retained_state} remains committed"
            ));
            bail!(
                "host `{host_id}` did not apply aliases [{}] after {change}; last reported aliases: {applied}; {retained_state} remains committed",
                aliases_text(desired)
            );
        }
        if let Err(error) = ui::sleep(POLL_INTERVAL) {
            task.abandon(format!(
                "Interrupted while waiting for the host agent; {retained_state} remains committed"
            ));
            return Err(error).with_context(|| {
                format!("alias wait interrupted; {retained_state} remains committed")
            });
        }
    }
}

fn hold_propagation_window(
    api: &mut AuthenticatedApiClient,
    host_id: HostId,
    desired: &HostAliases,
    propagation_wait: Duration,
    retained_state: &str,
) -> Result<bool> {
    let total = propagation_wait.as_secs().max(1);
    let task = ui::task(TaskOptions {
        label: format!("Holding alias propagation window for `{host_id}`"),
        kind: TaskKind::Countdown { total },
        deadline: Some(propagation_wait + POLL_INTERVAL),
        visibility: TaskVisibility::Immediate,
    })?;
    let started = Instant::now();
    loop {
        let elapsed = started.elapsed();
        task.set_position(elapsed.as_secs().min(total));
        if elapsed >= propagation_wait {
            task.finish(format!(
                "Alias propagation window completed for `{host_id}`"
            ));
            return Ok(true);
        }

        let host = match fetch_host(api, host_id, "alias propagation") {
            Ok(host) => host,
            Err(error) => {
                task.abandon(format!(
                    "Propagation check failed; {retained_state} remains committed"
                ));
                return Err(error).with_context(|| {
                    format!("alias propagation check failed; {retained_state} remains committed")
                });
            }
        };
        task.set_detail(agent_alias_detail(&host));
        if applied_aliases(&host) != Some(desired) {
            task.abandon(
                "Propagation hold reset because the agent no longer reports the desired aliases",
            );
            return Ok(false);
        }

        let sleep_for = POLL_INTERVAL.min(propagation_wait.saturating_sub(elapsed));
        if let Err(error) = ui::sleep(sleep_for) {
            task.abandon(format!(
                "Interrupted during propagation; {retained_state} remains committed"
            ));
            return Err(error).with_context(|| {
                format!("alias propagation wait interrupted; {retained_state} remains committed")
            });
        }
    }
}

fn fetch_host(
    api: &mut AuthenticatedApiClient,
    host_id: HostId,
    change: &str,
) -> Result<AegisHost> {
    api.get_hosts()?
        .hosts
        .remove(&host_id)
        .ok_or_else(|| anyhow!("host `{host_id}` disappeared while waiting for {change}"))
}

fn applied_aliases(host: &AegisHost) -> Option<&HostAliases> {
    host.report
        .agent
        .as_ref()
        .and_then(|agent| agent.health.applied_aliases.as_ref())
}

fn agent_alias_detail(host: &AegisHost) -> String {
    let Some(agent) = host.report.agent.as_ref() else {
        return "no agent report yet".to_string();
    };
    let aliases = agent
        .health
        .applied_aliases
        .as_ref()
        .map(aliases_text)
        .unwrap_or_else(|| "not reported".to_string());
    let age = now_unix().saturating_sub(agent.reported_unix).max(0);
    format!("last aliases [{aliases}] · report {age}s ago")
}

fn aliases_text(aliases: &HostAliases) -> String {
    aliases
        .iter()
        .map(HostAlias::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}
