use anyhow::{Result, ensure};

use crate::{
    api::{AuthenticatedApiClient, installed_agent_api_base},
    cli::{NamespaceArgs, NamespaceCommands},
    config::{UserContext, resolve_api_base},
    ui::{self, TaskOptions},
};

pub(super) fn run(api_base_override: Option<&str>, args: &NamespaceArgs) -> Result<i32> {
    let base = resolve_api_base(api_base_override, installed_agent_api_base()?.as_deref())?;
    let endpoint = aegis_dto::namespace::ApiEndpoint::parse(&base).map_err(anyhow::Error::msg)?;
    let endpoint = match &args.command {
        NamespaceCommands::Use { namespace } => endpoint.with_namespace(namespace.clone()),
        NamespaceCommands::Show => endpoint,
    };
    let task = ui::task(TaskOptions {
        label: "Checking namespace membership".into(),
        ..TaskOptions::default()
    })?;
    let mut api = AuthenticatedApiClient::load(Some(&endpoint.base_url()))?;
    let context = api.namespace_context()?;
    ensure!(
        Some(&context.namespace) == endpoint.namespace(),
        "API returned a different namespace"
    );
    if matches!(args.command, NamespaceCommands::Use { .. }) {
        UserContext {
            api_base: endpoint.base_url(),
        }
        .persist()?;
        task.finish("Namespace selection saved");
    } else {
        task.finish_and_clear();
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "api_base": endpoint.base_url(), "namespace": context.namespace, "role": context.role,
        }))?
    );
    Ok(0)
}
