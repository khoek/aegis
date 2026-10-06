use anyhow::Result;

use crate::cli::{PrincipalArgs, PrincipalCommands};
use crate::ui::{self, TaskOptions};

use super::local_agent;

pub(super) fn run(args: &PrincipalArgs) -> Result<i32> {
    let task = ui::task(TaskOptions {
        label: match &args.command {
            PrincipalCommands::Allow(args) => {
                format!("Allowing Aegis user `{}`", args.user_id)
            }
            PrincipalCommands::Revoke(args) => {
                format!("Revoking Aegis user `{}`", args.user_id)
            }
            PrincipalCommands::List => "Loading allowed Aegis users".to_string(),
        },
        ..TaskOptions::default()
    })?;
    let response = match &args.command {
        PrincipalCommands::Allow(args) => local_agent::allow_principal_grant(&args.user_id)?,
        PrincipalCommands::Revoke(args) => local_agent::revoke_principal_grant(&args.user_id)?,
        PrincipalCommands::List => local_agent::list_principal_grants()?,
    };
    task.finish_and_clear();
    print_grants(&response);
    Ok(0)
}

fn print_grants(response: &local_agent::PrincipalGrantResponse) {
    ui::success(&format!(
        "Local login principal: {}",
        response.login_principal
    ));
    if response.grants.is_empty() {
        println!("No Aegis users are allowed.");
        return;
    }
    for grant in &response.grants {
        println!("{}", grant.user_id);
    }
}
