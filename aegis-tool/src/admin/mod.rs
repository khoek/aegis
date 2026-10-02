//! Local GCP administration. No administration credentials travel through the Aegis API.
mod certificates;
mod connection;
mod deployment;
mod gcloud;
mod hub;
mod identity;
mod store;

use std::{future::Future, path::PathBuf, time::Duration};

use aegis_types::{NamespaceId, NamespaceRole};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand, ValueEnum};
use phylax_core::OAuthAuthorizationCodeGrantRequest;
use phylax_gcp::identity::UserRecord;

use crate::{app::login, config, ui};
use connection::Connection;
use deployment::Deployment;

#[derive(Debug, Args)]
pub struct AdminArgs {
    #[command(subcommand)]
    command: AdminCommand,
}

#[derive(Debug, Subcommand)]
enum AdminCommand {
    /// Select an existing deployment using local GCP credentials.
    Connect {
        #[command(flatten)]
        project: ProjectArgs,
        #[arg(long)]
        database: String,
        #[arg(id = "admin_namespace", value_name = "NAMESPACE")]
        namespace: NamespaceId,
    },
    /// Deploy a complete Aegis installation using your local gcloud account.
    Setup(deployment::SetupArgs),
    /// Initialize an existing Firestore database for an API hosted outside setup's Cloud Run deployment.
    Configure(deployment::ConfigureArgs),
    /// Deploy an exact API image to an installation created by setup.
    Deploy {
        #[arg(long)]
        project: Option<String>,
        /// Container reference pinned with @sha256:…
        #[arg(long)]
        image: String,
    },
    /// Check the deployment, public endpoint, account and hub.
    Doctor(ProjectArgs),
    /// Authorize the account signing in through the browser.
    Authorize {
        #[command(flatten)]
        project: ProjectArgs,
        #[arg(long)]
        target_namespace: Option<NamespaceId>,
        #[arg(long, value_enum, default_value = "member")]
        role: Role,
        #[arg(long)]
        remote_auth: bool,
    },
    /// List accounts, change access, or grant namespace membership.
    User {
        #[command(flatten)]
        project: ProjectArgs,
        #[command(subcommand)]
        command: UserCommand,
    },
    /// Print a validated namespace configuration template.
    NamespaceTemplate,
    /// Create a namespace and its certificate authorities.
    NamespaceCreate {
        #[command(flatten)]
        project: ProjectArgs,
        name: NamespaceId,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        tls_dns_suffix: String,
    },
}

#[derive(Debug, Args)]
struct ProjectArgs {
    /// Defaults to the active gcloud project.
    #[arg(long)]
    project: Option<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Role {
    Member,
    Admin,
}
impl From<Role> for NamespaceRole {
    fn from(value: Role) -> Self {
        match value {
            Role::Member => Self::Member,
            Role::Admin => Self::Admin,
        }
    }
}

#[derive(Debug, Subcommand)]
enum UserCommand {
    List,
    Enable {
        user: String,
    },
    Disable {
        user: String,
    },
    Grant {
        user: String,
        #[arg(id = "admin_namespace", value_name = "NAMESPACE")]
        namespace: NamespaceId,
        #[arg(value_enum)]
        role: Role,
    },
    Revoke {
        user: String,
        #[arg(id = "admin_namespace", value_name = "NAMESPACE")]
        namespace: NamespaceId,
    },
    Members {
        #[arg(id = "admin_namespace", value_name = "NAMESPACE")]
        namespace: NamespaceId,
    },
}

pub(crate) fn run(args: AdminArgs) -> Result<i32> {
    match args.command {
        AdminCommand::Connect {
            project,
            database,
            namespace,
        } => Connection::attach(project.project, database, namespace)?,
        AdminCommand::Setup(args) => deployment::setup(args)?,
        AdminCommand::Configure(args) => deployment::configure_external(args)?,
        AdminCommand::Deploy { project, image } => {
            let mut deployment = Deployment::load(project)?;
            let _lock = crate::locks::deployment_lock(&deployment.config.project)?;
            deployment.deploy(&image)?;
        }
        AdminCommand::Doctor(args) => Deployment::load(args.project)?.doctor()?,
        AdminCommand::Authorize {
            project,
            target_namespace,
            role,
            remote_auth,
        } => {
            let connection = Connection::load(project.project)?;
            authorize(
                &connection,
                target_namespace.as_ref().unwrap_or(&connection.namespace),
                role.into(),
                remote_auth,
            )?;
        }
        AdminCommand::User { project, command } => {
            let connection = Connection::load(project.project)?;
            let admin = connection.open()?;
            let value = database("Updating account access", async {
                Ok(match command {
                    UserCommand::List => serde_json::to_value(admin.users().await?)?,
                    UserCommand::Members { namespace } => admin.members(namespace).await?,
                    UserCommand::Enable { user } => {
                        admin.set_user_disabled(&user, false).await?;
                        serde_json::json!({"user":user,"disabled":false})
                    }
                    UserCommand::Disable { user } => {
                        admin.set_user_disabled(&user, true).await?;
                        serde_json::json!({"user":user,"disabled":true})
                    }
                    UserCommand::Grant {
                        user,
                        namespace,
                        role,
                    } => {
                        admin
                            .set_membership(namespace, &user, Some(role.into()))
                            .await?;
                        serde_json::json!({"user":user})
                    }
                    UserCommand::Revoke { user, namespace } => {
                        admin.set_membership(namespace, &user, None).await?;
                        serde_json::json!({"user":user})
                    }
                })
            })?;
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
        AdminCommand::NamespaceTemplate => println!(
            "{}",
            serde_json::to_string_pretty(&store::namespace_template())?
        ),
        AdminCommand::NamespaceCreate {
            project,
            name,
            config,
            tls_dns_suffix,
        } => {
            let namespace = store::NamespaceOptions {
                namespace: name,
                configuration: serde_json::from_slice(&std::fs::read(config)?)?,
                tls_dns_suffix,
            }
            .validate()?;
            let connection = Connection::load(project.project)?;
            let admin = connection.open()?;
            database("Creating namespace", admin.create_namespace(namespace))?;
            ui::success(
                "Namespace and certificate authorities created; deploy a new API revision to load it",
            );
        }
    }
    Ok(0)
}

/// Bound Firestore work and preserve the shared invocation's typed interruption.
fn database<T>(label: &str, operation: impl Future<Output = Result<T>>) -> Result<T> {
    let timeout = Duration::from_secs(120);
    let task = ui::task(ui::TaskOptions {
        label: label.into(),
        deadline: Some(timeout),
        ..Default::default()
    })?;
    static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    if RUNTIME.get().is_none() {
        let _ = RUNTIME.set(tokio::runtime::Runtime::new()?);
    }
    let runtime = RUNTIME.get().expect("runtime initialized");
    let result = runtime.block_on(async {
        tokio::select! {
            result = tokio::time::timeout(timeout, operation) => result.context("Firestore operation timed out")?,
            result = async {
                loop {
                    if let Err(error) = ui::check_cancelled() { break Err(error); }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            } => result,
        }
    });
    task.finish_and_clear();
    result
}

fn authorize(
    connection: &Connection,
    namespace: &NamespaceId,
    role: NamespaceRole,
    remote: bool,
) -> Result<()> {
    let endpoint = aegis_types::namespace::ApiEndpoint::parse(&connection.endpoint)
        .map_err(anyhow::Error::msg)?
        .with_namespace(namespace.clone())
        .base_url();
    let proof = login::browser_proof(&endpoint, remote, Duration::from_secs(600))?;
    let admin = connection.open()?;
    let user_id = database("Authorizing verified account", async {
        let identities = identity::store(&admin.db)?;
        let login = identity::load_login(&admin.db).await?;
        let settings = identities.load_config().await?;
        let verified = identities
            .auth_store(&settings, login.login_session_ttl_seconds)?
            .verify_identity_proof(OAuthAuthorizationCodeGrantRequest {
                code: &proof.code,
                client_id: "aegis-tool",
                redirect_uri: proof.callback.as_str(),
                code_verifier: &proof.verifier,
                now_unix: config::now_unix(),
            })
            .await?
            .context("Browser identity proof expired or failed verification; sign in again")?;
        let user = match identities
            .authorize(&login.issuer_url, &verified.provider_sub)
            .await?
        {
            Some(user) => {
                ensure!(
                    !user.disabled,
                    "account {} is disabled; enable it explicitly before authorizing it",
                    user.id
                );
                user
            }
            None => {
                let user = UserRecord {
                    id: uuid::Uuid::new_v4().to_string(),
                    email: verified.principal,
                    disabled: false,
                    session_version: 1,
                };
                admin.add_user(user.clone(), verified.provider_sub).await?;
                user
            }
        };
        admin
            .set_membership(namespace.clone(), &user.id, Some(role))
            .await
            .context("Account is retained; namespace membership was not confirmed")?;
        Ok(user.id)
    })?;
    proof.finish(&endpoint).with_context(|| format!(
        "Account {user_id} and namespace membership are committed; run `aegis --api-base {endpoint} manage login` to retry sign-in"
    ))?;
    config::UserContext { api_base: endpoint }.persist()?;
    Ok(())
}
