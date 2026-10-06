//! Local GCP administration. No administration credentials travel through the Aegis API.
mod certificates;
mod connection;
mod credentials;
mod deployment;
mod gcloud;
mod hub;
mod identity;
mod store;

use std::{future::Future, path::PathBuf, time::Duration};

use aegis_dto::{NamespaceId, NamespaceRole};
use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand, ValueEnum};
use phylax_core::OAuthAuthorizationCodeGrantRequest;
use phylax_gcp::identity::UserRecord;

use aegis_tool::{
    client::{self, login},
    ui,
};
use connection::Connection;
use deployment::Deployment;

#[derive(Debug, Parser)]
#[command(
    name = "aegis-admin",
    version,
    about = "Deploy and administer Aegis with local GCP credentials."
)]
struct AdminCli {
    #[command(flatten)]
    ui: aegis_tool::ui::UiArgs,
    #[command(subcommand)]
    command: AdminCommand,
}

fn main() -> capulus::CliTermination {
    let args = AdminCli::parse();
    if let Err(error) = ui::init(args.ui.options()) {
        return capulus::CliTermination::without_ui(Err(error));
    }
    let result = run(args.command);
    let result = ui::check_cancelled().and(result);
    capulus::CliTermination::with_ui(ui::current(), result)
}

#[derive(Debug, Subcommand)]
enum AdminCommand {
    /// Select an existing deployment using local GCP credentials.
    Connect {
        #[command(flatten)]
        project: ProjectArgs,
        #[arg(long)]
        database: String,
        namespace: NamespaceId,
    },
    /// Deploy a complete Aegis installation using your local gcloud account.
    Setup(deployment::SetupArgs),
    /// Initialize an existing Firestore database for an API hosted outside setup's Cloud Run deployment.
    Configure(deployment::ConfigureArgs),
    /// Deploy this release's API to an installation created by setup.
    Deploy {
        #[arg(long)]
        project: Option<String>,
        /// Override the official image with a container pinned by @sha256:…
        #[arg(long)]
        image: Option<String>,
    },
    /// Check the deployment, public endpoint, account and hub.
    Doctor(ProjectArgs),
    /// Authorize and sign in using local GCP access, or opt into browser OAuth.
    Authorize {
        #[arg(long, conflicts_with = "user")]
        oauth: bool,
        #[arg(long)]
        user: Option<String>,
        #[command(flatten)]
        project: ProjectArgs,
        #[arg(long)]
        target_namespace: Option<NamespaceId>,
        #[arg(long, value_enum)]
        role: Option<Role>,
        #[arg(long)]
        remote_auth: bool,
    },
    /// Issue, inspect, or revoke user credentials.
    Credential {
        #[command(flatten)]
        project: ProjectArgs,
        #[command(subcommand)]
        command: credentials::CredentialCommand,
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
    Create {
        email: String,
    },
    List,
    Enable {
        user: String,
    },
    Disable {
        user: String,
    },
    Grant {
        user: String,
        namespace: NamespaceId,
        #[arg(value_enum)]
        role: Role,
    },
    Revoke {
        user: String,
        namespace: NamespaceId,
    },
    Members {
        namespace: NamespaceId,
    },
}

fn run(command: AdminCommand) -> Result<i32> {
    initialize_tls()?;
    match command {
        AdminCommand::Connect {
            project,
            database,
            namespace,
        } => Connection::attach(project.project, database, namespace)?,
        AdminCommand::Setup(args) => deployment::setup(args)?,
        AdminCommand::Configure(args) => deployment::configure_external(args)?,
        AdminCommand::Deploy { project, image } => {
            let project = deployment::project(project)?;
            let _lock = aegis_tool::client::deployment_lock(&project)?;
            let mut deployment = Deployment::load(Some(project))?;
            deployment.deploy(&deployment::resolve_image(image.as_deref())?)?;
        }
        AdminCommand::Doctor(args) => Deployment::load(args.project)?.doctor()?,
        AdminCommand::Authorize {
            oauth,
            user,
            project,
            target_namespace,
            role,
            remote_auth,
        } => {
            let connection = Connection::load(project.project)?;
            if oauth {
                authorize(
                    &connection,
                    target_namespace.as_ref().unwrap_or(&connection.namespace),
                    role.map(Into::into),
                    remote_auth,
                )?;
            } else {
                ensure!(!remote_auth, "--remote-auth requires --oauth");
                credentials::authorize_local(
                    &connection,
                    target_namespace.as_ref().unwrap_or(&connection.namespace),
                    role.map(Into::into),
                    user.as_deref(),
                )?;
            }
        }
        AdminCommand::Credential { project, command } => {
            credentials::run(&Connection::load(project.project)?, command)?;
        }
        AdminCommand::User { project, command } => {
            let connection = Connection::load(project.project)?;
            let admin = connection.open()?;
            let label = match &command {
                UserCommand::List => "Listing accounts",
                UserCommand::Members { .. } => "Listing namespace members",
                _ => "Updating account access",
            };
            let value = database(label, async {
                Ok(match command {
                    UserCommand::Create { email } => {
                        serde_json::to_value(credentials::create_user(&admin, email).await?)?
                    }
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

fn initialize_tls() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("TLS provider is already initialized"))
}

/// Bound Firestore work and preserve the shared invocation's typed interruption.
fn database<T>(label: &str, operation: impl Future<Output = Result<T>>) -> Result<T> {
    database_with_timeout(label, operation, Duration::from_secs(120))
}

fn database_with_timeout<T>(
    label: &str,
    operation: impl Future<Output = Result<T>>,
    timeout: Duration,
) -> Result<T> {
    ensure!(!timeout.is_zero(), "Firestore operation deadline exceeded");
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
    role: Option<NamespaceRole>,
    remote: bool,
) -> Result<()> {
    let endpoint = aegis_dto::namespace::ApiEndpoint::parse(&connection.endpoint)
        .map_err(anyhow::Error::msg)?
        .with_namespace(namespace.clone())
        .base_url();
    let admin = connection.open()?;
    let login = database(
        "Checking OAuth configuration",
        identity::load_authentication(&admin.db),
    )?
    .oauth
    .context("OAuth is not enabled; use local credential authorization")?;
    let proof = login::browser_proof(&endpoint, remote, Duration::from_secs(600))?;
    let user_id = database("Authorizing verified account", async {
        let identities = identity::store(&admin.db)?;
        let settings = identities.load_config().await?;
        let verified = identities
            .auth_store(&settings, login.login_session_ttl_seconds)?
            .verify_identity_proof(OAuthAuthorizationCodeGrantRequest {
                code: &proof.code,
                client_id: "aegis-tool",
                redirect_uri: proof.callback.as_str(),
                code_verifier: &proof.verifier,
                now_unix: client::now_unix(),
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
            .authorize_membership(namespace.clone(), &user.id, role)
            .await
            .context("Account is retained; namespace membership was not confirmed")?;
        Ok(user.id)
    })?;
    proof.finish(&endpoint).with_context(|| format!(
        "Account {user_id} and namespace membership are committed; run `aegis --api-base {endpoint} manage login` to retry sign-in"
    ))?;
    client::UserContext { api_base: endpoint }.persist()?;
    Ok(())
}

#[cfg(test)]
mod runtime_tests {
    #[test]
    fn firestore_tls_can_build_with_both_dependency_crypto_providers_enabled() {
        super::initialize_tls().unwrap();
        let _ = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
    }
}
