use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::PathBuf,
    time::Duration,
};

use aegis_dto::{NamespaceId, NamespaceRole, identity::LoginConfiguration, namespace::ApiEndpoint};
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{database, gcloud::Gcloud, store};
use aegis_tool::{client, ui};

const SERVICE: &str = "aegis-api";
const DATABASE: &str = "aegis";
const SECRET: &str = "aegis-oidc-client-secret";
const OWNER_LABEL: &str = "managed-by=aegis";

#[derive(Debug, Args)]
pub(super) struct SetupArgs {
    #[arg(long)]
    project: Option<String>,
    #[arg(long)]
    region: Option<String>,
    /// Public URL, including the proxy's path prefix. Defaults to Cloud Run /v2.
    #[arg(long)]
    endpoint: Option<String>,
    /// Service account allowed to invoke a private backend through your proxy.
    #[arg(long)]
    proxy_invoker: Option<String>,
    /// Enable browser sign-in and guide Google OAuth configuration.
    #[arg(long)]
    oauth: bool,
    /// Downloaded Google OAuth web application client JSON; enables OAuth.
    #[arg(long)]
    oauth_client: Option<PathBuf>,
    #[arg(long)]
    initial_namespace: Option<NamespaceId>,
    /// Exact API image (@sha256:…). Defaults to this release's official image.
    #[arg(long)]
    image: Option<String>,
    /// Desired hub regions. Repeat to keep multiple hubs; defaults to an interactive selector.
    #[arg(long = "hub-region")]
    hub_regions: Vec<String>,
    /// Skip enrolling this computer; the API, owner and hubs are still configured.
    #[arg(long)]
    no_enroll: bool,
    #[arg(long)]
    remote_auth: bool,
    /// Accept the displayed resource plan. OAuth authorization, when enabled, remains interactive.
    #[arg(long, short = 'y')]
    yes: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DeploymentConfig {
    pub project: String,
    pub region: String,
    pub endpoint: String,
    pub namespace: NamespaceId,
    backend: String,
    proxy_invoker: Option<String>,
    login: Option<LoginConfiguration>,
}

impl DeploymentConfig {
    fn validate(self) -> Result<Self> {
        Gcloud::new(self.project.clone())?;
        ensure!(valid_region(&self.region), "invalid GCP region");
        let endpoint = ApiEndpoint::parse(&self.endpoint).map_err(anyhow::Error::msg)?;
        ensure!(
            endpoint.namespace().is_none()
                && self.endpoint.starts_with("https://")
                && endpoint.service_url() == self.endpoint,
            "public endpoint must be a canonical HTTPS service URL"
        );
        let backend = url::Url::parse(&self.backend)?;
        let number = backend
            .host_str()
            .and_then(|host| host.strip_prefix("aegis-api-"))
            .and_then(|host| host.strip_suffix(&format!(".{}.run.app", self.region)));
        ensure!(
            backend.scheme() == "https"
                && backend.username().is_empty()
                && backend.password().is_none()
                && backend.port().is_none()
                && backend.path() == "/"
                && backend.query().is_none()
                && backend.fragment().is_none()
                && number.is_some_and(
                    |value| !value.is_empty() && value.bytes().all(|c| c.is_ascii_digit())
                ),
            "invalid Cloud Run backend URL"
        );
        if let Some(invoker) = &self.proxy_invoker {
            ensure!(
                invoker.ends_with(".iam.gserviceaccount.com")
                    && invoker
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"-@.".contains(&c)),
                "proxy invoker must be a service account email"
            );
            ensure!(
                self.endpoint != format!("{}/v2", self.backend),
                "private backends require a public proxy endpoint"
            );
        }
        store::SetupOptions {
            issuer_url: self.endpoint.clone(),
            audience: self.endpoint.clone(),
            login: self.login.clone(),
        }
        .validate()?;
        Ok(self)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Deployment {
    pub config: DeploymentConfig,
    image: String,
    secret_version: Option<String>,
    completed: Vec<String>,
    pub(super) hubs: BTreeMap<String, super::hub::Hub>,
    pub(super) hub_regions: BTreeSet<String>,
    local_host: Option<aegis_dto::HostId>,
}

#[derive(Deserialize)]
struct GoogleClient {
    web: GoogleWebClient,
}
#[derive(Deserialize)]
struct GoogleWebClient {
    client_id: String,
    client_secret: String,
    redirect_uris: Vec<String>,
}

#[derive(Debug, Args)]
pub(super) struct ConfigureArgs {
    #[arg(long)]
    project: Option<String>,
    #[arg(long)]
    database: String,
    #[arg(long)]
    endpoint: String,
    #[arg(long)]
    oauth_client: Option<PathBuf>,
    #[arg(long, default_value = "personal")]
    initial_namespace: NamespaceId,
}

pub(super) fn configure_external(args: ConfigureArgs) -> Result<()> {
    let ConfigureArgs {
        project: project_arg,
        database: database_id,
        endpoint,
        oauth_client,
        initial_namespace: namespace,
    } = args;
    let project = project(project_arg)?;
    let _lock = aegis_tool::client::deployment_lock(&project)?;
    let oauth = oauth_client
        .as_ref()
        .map(|path| GoogleWebClient::read(path, &endpoint))
        .transpose()?;
    let setup = store::SetupOptions {
        issuer_url: endpoint.clone(),
        audience: endpoint.clone(),
        login: oauth.as_ref().map(|oauth| oauth.login(&endpoint)),
    }
    .validate()?;
    let options = store::AdminOptions {
        project_id: project.clone(),
        database_id: database_id.clone(),
    }
    .validate()?;
    let namespace_options = store::NamespaceOptions {
        namespace: namespace.clone(),
        configuration: store::namespace_template(),
        tls_dns_suffix: "aegis.internal".into(),
    }
    .validate()?;
    let admin = database(
        "Connecting to existing Firestore database",
        options.connect(Gcloud::new(project.clone())?.token()?),
    )?;
    database("Initializing external API identity and namespace", async {
        admin.setup(setup).await?;
        admin.create_namespace(namespace_options).await
    }).context("committed identity, namespace and certificate records are retained; rerun the same configure command to finish")?;
    super::connection::Connection {
        project,
        database: database_id,
        endpoint,
        namespace,
    }
    .persist()?;
    ui::success(
        "API configuration and administration connection saved. Start the API, then run `aegis-admin authorize --role admin`.",
    );
    if oauth.is_some() {
        ui::detail(
            "Supply AEGIS_OIDC_CLIENT_SECRET to the API runtime; use `authorize --oauth` for browser sign-in.",
        );
    }
    Ok(())
}

impl GoogleWebClient {
    fn read(path: &std::path::Path, endpoint: &str) -> Result<Self> {
        let client: GoogleClient = serde_json::from_slice(
            &fs::read(path).with_context(|| format!("reading {}", path.display()))?,
        )
        .context("Expected downloaded Google OAuth Web application client JSON")?;
        ensure!(
            !client.web.client_id.trim().is_empty() && !client.web.client_secret.trim().is_empty(),
            "OAuth client credentials are empty"
        );
        ensure!(
            client
                .web
                .redirect_uris
                .contains(&format!("{endpoint}/oauth/callback")),
            "Add authorized redirect URI {endpoint}/oauth/callback to the Web client, then download its JSON again"
        );
        Ok(client.web)
    }

    fn login(&self, endpoint: &str) -> LoginConfiguration {
        LoginConfiguration {
            issuer_url: "https://accounts.google.com".into(),
            client_id: self.client_id.clone(),
            redirect_uri: format!("{endpoint}/oauth/callback"),
            login_session_ttl_seconds: 600,
            authorization_code_ttl_seconds: 300,
        }
    }
}

pub(super) fn setup(args: SetupArgs) -> Result<()> {
    let project = project(args.project.clone())?;
    let _lock = aegis_tool::client::deployment_lock(&project)?;
    if let Some(region) = &args.region {
        ensure!(valid_region(region), "invalid GCP region");
    }
    for region in &args.hub_regions {
        ensure!(valid_region(region), "invalid hub region: {region}");
    }
    ui::stage("Preparing GCP management APIs");
    Gcloud::new(project.clone())?.json(&[
        "services",
        "enable",
        "serviceusage.googleapis.com",
        "cloudresourcemanager.googleapis.com",
        "cloudbilling.googleapis.com",
    ])?;
    let path = receipt_path(&project)?;
    let mut client_secret = None;
    let mut deployment = if path.exists() {
        let deployment = Deployment::load(Some(project.clone()))?;
        ensure!(
            args.region
                .as_ref()
                .is_none_or(|value| value == &deployment.config.region)
                && args
                    .endpoint
                    .as_ref()
                    .is_none_or(|value| value.trim_end_matches('/') == deployment.config.endpoint)
                && args
                    .initial_namespace
                    .as_ref()
                    .is_none_or(|value| value == &deployment.config.namespace)
                && args
                    .proxy_invoker
                    .as_ref()
                    .is_none_or(|value| Some(value) == deployment.config.proxy_invoker.as_ref()),
            "setup options differ from the saved deployment; inspect {} before changing identity or routing",
            path.display()
        );
        if let Some(image) = &args.image {
            ensure!(
                image == &deployment.image,
                "use `aegis-admin deploy --image` to change the API release"
            );
        }
        deployment
    } else {
        let cloud = Gcloud::new(project.clone())?;
        let description = cloud.json(&["projects", "describe", &project])?;
        let number = text(&description, "projectNumber")?;
        let region = args.region.clone().unwrap_or_else(suggest_region);
        ensure!(valid_region(&region), "invalid GCP region");
        let backend = format!("https://{SERVICE}-{number}.{region}.run.app");
        let endpoint = match &args.endpoint {
            Some(value) => value.trim_end_matches('/').to_owned(),
            None if args.yes => format!("{backend}/v2"),
            None => {
                let answer: String = prompt(
                    "Custom public endpoint (leave blank for Cloud Run)",
                    Some(""),
                )?;
                if answer.trim().is_empty() {
                    format!("{backend}/v2")
                } else {
                    answer.trim_end_matches('/').into()
                }
            }
        };
        let login = if args.oauth || args.oauth_client.is_some() {
            let oauth = read_oauth_client(args.oauth_client.as_ref(), &project, &endpoint)?;
            let login = oauth.login(&endpoint);
            client_secret = Some(oauth.client_secret);
            Some(login)
        } else {
            None
        };
        let config = DeploymentConfig {
            project,
            region,
            endpoint: endpoint.clone(),
            backend,
            proxy_invoker: args.proxy_invoker.clone(),
            namespace: args
                .initial_namespace
                .clone()
                .unwrap_or("personal".parse()?),
            login,
        }
        .validate()?;
        let image = match &args.image {
            Some(image) => validate_image(image)?.into(),
            None => official_image()?,
        };
        Deployment {
            image,
            secret_version: None,
            completed: Vec::new(),
            hub_regions: BTreeSet::from([config.region.clone()]),
            hubs: BTreeMap::new(),
            local_host: None,
            config,
        }
    };
    ensure!(
        !(args.oauth || args.oauth_client.is_some()) || deployment.config.login.is_some(),
        "saved deployment uses credentials only; OAuth must be enabled through an explicit configuration change"
    );
    ensure!(
        !args.remote_auth || deployment.config.login.is_some(),
        "--remote-auth requires OAuth"
    );
    if deployment.config.login.is_some()
        && deployment.secret_version.is_none()
        && client_secret.is_none()
    {
        let oauth = read_oauth_client(
            args.oauth_client.as_ref(),
            &deployment.config.project,
            &deployment.config.endpoint,
        )?;
        ensure!(
            Some(&oauth.client_id)
                == deployment
                    .config
                    .login
                    .as_ref()
                    .map(|login| &login.client_id),
            "OAuth client differs from saved deployment"
        );
        client_secret = Some(oauth.client_secret);
    }
    ui::stage(&format!(
        "Project: {}\nRegion: {}\nEndpoint: {}\nNamespace: {}\nImage: {}\nResources: Firestore, Cloud Run and regional Ubuntu hub VMs{}",
        deployment.config.project,
        deployment.config.region,
        deployment.config.endpoint,
        deployment.config.namespace,
        deployment.image,
        if args.no_enroll {
            ""
        } else {
            "; then enroll this computer"
        }
    ));
    ui::detail(if deployment.config.login.is_some() {
        "Authentication: browser OAuth (Secret Manager enabled)"
    } else {
        "Authentication: administrator-issued credentials"
    });
    if !args.yes {
        ui::require_interactive("Use --yes to accept the setup plan without a terminal")?;
        let accepted = ui::suspend(|| {
            dialoguer::Confirm::new()
                .with_prompt(
                    "Create or resume this deployment? GCP usage is billed to your project",
                )
                .default(true)
                .interact()
        })?;
        ensure!(accepted, "Setup declined; no resources were changed");
    }
    if !args.no_enroll {
        aegis_tool::client::enrollment::check_local_enrollment_platform()?;
    }
    deployment.persist()?;
    let result = deployment.setup_steps(client_secret.as_deref(), &args);
    if let Err(error) = result {
        ui::warn(&format!(
            "Setup stopped. Completed phases: {}. Resources and keys are retained. Resume with `aegis-admin setup --project {}`. Receipt: {}",
            deployment.completed.join(", "),
            deployment.config.project,
            path.display()
        ));
        return Err(error.context("the current phase may have committed resources before its response was received; setup verifies them when resumed"));
    }
    ui::success(
        "Aegis is ready. Enroll another machine with `aegis manage enroll --remote USER@HOST`",
    );
    Ok(())
}

impl Deployment {
    pub fn load(project_arg: Option<String>) -> Result<Self> {
        let project = project(project_arg)?;
        let path = receipt_path(&project)?;
        let mut deployment: Self =
            serde_json::from_slice(&fs::read(&path).with_context(|| {
                format!(
                    "No saved deployment at {}; run aegis-admin setup",
                    path.display()
                )
            })?)?;
        ensure!(
            deployment.config.project == project,
            "deployment receipt project mismatch"
        );
        deployment.config = deployment.config.validate()?;
        validate_image(&deployment.image)?;
        super::hub::validate(&deployment)?;
        if let Some(version) = &deployment.secret_version {
            ensure!(
                !version.is_empty() && version.bytes().all(|c| c.is_ascii_digit()),
                "invalid secret version in receipt"
            );
        }
        Ok(deployment)
    }

    pub(super) fn cloud(&self) -> Result<Gcloud> {
        Gcloud::new(self.config.project.clone())
    }
    pub(super) fn persist(&self) -> Result<()> {
        capulus::store::atomic_write(
            &receipt_path(&self.config.project)?,
            &serde_json::to_vec_pretty(self)?,
            Some(0o600),
            Some(0o700),
        )
    }
    fn complete(&mut self, phase: &str) -> Result<()> {
        if !self.completed.iter().any(|value| value == phase) {
            self.completed.push(phase.into());
        }
        self.persist()?;
        ui::success(&format!("{phase} complete"));
        Ok(())
    }
    pub fn connect(&self) -> Result<store::Admin> {
        let token = self.cloud()?.token()?;
        database(
            "Connecting with local GCP credentials",
            store::AdminOptions {
                project_id: self.config.project.clone(),
                database_id: DATABASE.into(),
            }
            .validate()?
            .connect(token),
        )
    }
    fn setup_steps(&mut self, secret: Option<&str>, args: &SetupArgs) -> Result<()> {
        self.provision(secret)?;
        self.complete("GCP resources")?;
        let admin = self.connect()?;
        database("Initializing identity and namespace", async {
            admin
                .setup(
                    store::SetupOptions {
                        issuer_url: self.config.endpoint.clone(),
                        audience: self.config.endpoint.clone(),
                        login: self.config.login.clone(),
                    }
                    .validate()?,
                )
                .await?;
            admin
                .create_namespace(
                    store::NamespaceOptions {
                        namespace: self.config.namespace.clone(),
                        configuration: store::namespace_template(),
                        tls_dns_suffix: "aegis.internal".into(),
                    }
                    .validate()?,
                )
                .await
        })?;
        self.connection().persist()?;
        self.complete("Identity and certificate authorities")?;
        self.deploy(&self.image.clone())?;
        self.check_endpoint()?;
        if !self
            .completed
            .iter()
            .any(|phase| phase == "Owner authorization")
        {
            self.authorize(
                &self.config.namespace,
                NamespaceRole::Admin,
                args.remote_auth,
            )?;
            self.complete("Owner authorization")?;
        }
        super::hub::configure(self, &args.hub_regions, args.yes)?;
        self.complete("Regional hubs")?;
        if !args.no_enroll {
            self.enroll_current_machine()?;
            self.complete("Current machine")?;
        }
        self.doctor()
    }

    fn enroll_current_machine(&mut self) -> Result<()> {
        let _lock = aegis_tool::client::local_system_lock()?;
        let endpoint = self.namespace_endpoint()?;
        if aegis_tool::client::enrollment::local_machine_ready(&endpoint, self.local_host.as_ref())?
        {
            return Ok(());
        }
        let mut api = aegis_tool::client::AuthenticatedApiClient::load(Some(&endpoint))?;
        let host = match self.local_host {
            Some(host) => host,
            None => {
                let name = fs::read_to_string("/etc/hostname")?;
                let alias =
                    aegis_dto::HostAlias::parse(name.trim().split('.').next().unwrap_or_default())?;
                let enrollment = aegis_tool::client::enrollment::reserve(
                    &mut api,
                    alias,
                    aegis_dto::AegisHostMode::Leaf,
                )?;
                self.local_host = Some(enrollment.host_id);
                self.persist().context("machine reservation committed; save its host ID in the setup receipt before retrying")?;
                enrollment.host_id
            }
        };
        let path = aegis_tool::client::enrollment::path(&host)?;
        if !path.exists() {
            aegis_tool::client::enrollment::issue(&mut api, &host)?;
        }
        let invitation = aegis_tool::client::enrollment::read(&path)?;
        ensure!(
            invitation.enrollment.host_id == host && invitation.api_base == endpoint,
            "saved setup invitation does not match the deployment receipt"
        );
        aegis_tool::client::enrollment::enroll_local_machine(&endpoint, path)
    }
    fn provision(&mut self, secret: Option<&str>) -> Result<()> {
        let cloud = self.cloud()?;
        let billing = cloud.json(&["billing", "projects", "describe", &self.config.project])?;
        ensure!(
            billing["billingEnabled"] == true,
            "Enable billing for this GCP project before setup"
        );
        cloud.json(&[
            "services",
            "enable",
            "run.googleapis.com",
            "firestore.googleapis.com",
            "compute.googleapis.com",
            "iam.googleapis.com",
        ])?;
        let databases = cloud.json(&["firestore", "databases", "list"])?;
        let db_name = format!("projects/{}/databases/{DATABASE}", self.config.project);
        if let Some(db) = array(&databases)?.iter().find(|db| db["name"] == db_name) {
            ensure!(
                db["type"] == "FIRESTORE_NATIVE" && db["locationId"] == self.config.region,
                "existing aegis database differs in location or type; setup will not replace it"
            );
        } else {
            cloud.json(&[
                "firestore",
                "databases",
                "create",
                "--database",
                DATABASE,
                "--location",
                &self.config.region,
                "--type=firestore-native",
                "--delete-protection",
            ])?;
        }
        // Expiry is also checked during authorization; TTL is storage reclamation.
        for group in ["login_sessions", "codes", "grants", "refresh_tokens"] {
            let policies = cloud.json(&[
                "firestore",
                "fields",
                "ttls",
                "list",
                "--database",
                DATABASE,
                "--collection-group",
                group,
            ])?;
            if !array(&policies)?.iter().any(|p| {
                p["name"]
                    .as_str()
                    .is_some_and(|n| n.ends_with("/fields/expire_at"))
                    && matches!(
                        p["ttlConfig"]["state"].as_str(),
                        Some("ACTIVE" | "CREATING")
                    )
            }) {
                cloud.json(&[
                    "firestore",
                    "fields",
                    "ttls",
                    "update",
                    "expire_at",
                    "--collection-group",
                    group,
                    "--database",
                    DATABASE,
                    "--enable-ttl",
                    "--async",
                ])?;
            }
        }
        let email = self.runtime_account();
        let accounts = cloud.json(&["iam", "service-accounts", "list"])?;
        if !array(&accounts)?
            .iter()
            .any(|account| account["email"] == email)
        {
            cloud.json(&[
                "iam",
                "service-accounts",
                "create",
                SERVICE,
                "--display-name=Aegis API runtime",
            ])?;
        }
        cloud.json(&["projects", "add-iam-policy-binding", &self.config.project,
            "--member", &format!("serviceAccount:{email}"), "--role=roles/datastore.user",
            "--condition", &format!("expression=resource.name==\"projects/{}/databases/{DATABASE}\",title=aegis-database", self.config.project)])?;
        if self.config.login.is_none() {
            return Ok(());
        }
        cloud.json(&["services", "enable", "secretmanager.googleapis.com"])?;
        let secrets = cloud.json(&["secrets", "list"])?;
        if let Some(existing) = array(&secrets)?.iter().find(|s| {
            s["name"]
                .as_str()
                .is_some_and(|n| n.ends_with(&format!("/secrets/{SECRET}")))
        }) {
            ensure!(
                existing["labels"]["managed-by"] == "aegis",
                "existing OAuth secret is not managed by Aegis"
            );
        } else {
            cloud.json(&[
                "secrets",
                "create",
                SECRET,
                "--replication-policy=automatic",
                "--labels",
                OWNER_LABEL,
            ])?;
        }
        if self.secret_version.is_none() {
            let secret = secret.context("OAuth client secret is required")?;
            let versions = cloud.json(&[
                "secrets",
                "versions",
                "list",
                SECRET,
                "--filter=state:ENABLED",
            ])?;
            let versions = array(&versions)?
                .iter()
                .map(|value| {
                    text(value, "name")?
                        .rsplit('/')
                        .next()
                        .context("secret version missing")?
                        .parse::<u64>()
                        .context("invalid secret version")
                })
                .collect::<Result<Vec<_>>>()?;
            let version = if let Some(version) = versions.into_iter().max() {
                let version = version.to_string();
                let stored = cloud.run(
                    &[
                        "secrets", "versions", "access", &version, "--secret", SECRET,
                    ],
                    None,
                    Duration::from_secs(30),
                )?;
                ensure!(
                    stored == secret,
                    "existing OAuth secret differs; setup will not rotate it"
                );
                version
            } else {
                let value: Value = serde_json::from_str(&cloud.run(
                    &["secrets", "versions", "add", SECRET, "--data-file=-"],
                    Some(secret.as_bytes()),
                    Duration::from_secs(60),
                )?)?;
                text(&value, "name")?
                    .rsplit('/')
                    .next()
                    .context("secret version missing")?
                    .into()
            };
            self.secret_version = Some(version);
            self.persist()?;
        }
        cloud.json(&[
            "secrets",
            "add-iam-policy-binding",
            SECRET,
            "--member",
            &format!("serviceAccount:{email}"),
            "--role=roles/secretmanager.secretAccessor",
        ])?;
        Ok(())
    }
    fn runtime_account(&self) -> String {
        format!("{SERVICE}@{}.iam.gserviceaccount.com", self.config.project)
    }
    pub fn deploy(&mut self, image: &str) -> Result<()> {
        validate_image(image)?;
        ensure!(
            self.config.login.is_none() || self.secret_version.is_some(),
            "Complete OAuth secret setup before deploying the API"
        );
        let cloud = self.cloud()?;
        let services = cloud.json(&["run", "services", "list", "--region", &self.config.region])?;
        let existing = array(&services)?
            .iter()
            .find(|s| s["metadata"]["name"] == SERVICE);
        if let Some(existing) = existing {
            ensure!(
                existing["metadata"]["labels"]["managed-by"] == "aegis",
                "existing Cloud Run service is not managed by Aegis"
            );
        }
        let mut env = tempfile::NamedTempFile::new()?;
        serde_json::to_writer(
            &mut env,
            &json!({"GOOGLE_CLOUD_PROJECT":self.config.project, "FIRESTORE_DATABASE_ID":DATABASE}),
        )?;
        env.flush()?;
        let account = self.runtime_account();
        let secret = self
            .secret_version
            .as_ref()
            .map(|version| format!("AEGIS_OIDC_CLIENT_SECRET={SECRET}:{version}"));
        let mut args = vec![
            "run",
            "deploy",
            SERVICE,
            "--region",
            &self.config.region,
            "--image",
            image,
            "--service-account",
            &account,
            "--env-vars-file",
            env.path().to_str().context("invalid temporary file path")?,
            "--labels",
            OWNER_LABEL,
            "--port=8080",
            "--memory=512Mi",
            "--cpu=1",
            "--min=0",
            "--max=3",
            "--timeout=60s",
            "--startup-probe=httpGet.path=/health,httpGet.port=8080,initialDelaySeconds=0,timeoutSeconds=5,periodSeconds=10,failureThreshold=24",
            "--tag=aegis-candidate",
            if self.config.proxy_invoker.is_some() {
                "--invoker-iam-check"
            } else {
                "--no-invoker-iam-check"
            },
        ];
        if let Some(secret) = &secret {
            args.extend(["--set-secrets", secret]);
        } else {
            args.push("--clear-secrets");
        }
        if existing.is_some() {
            args.push("--no-traffic");
        }
        let service = cloud.json(&args)?;
        let revision = text(&service["status"], "latestReadyRevisionName")?;
        ensure!(
            service["status"]["latestCreatedRevisionName"] == revision,
            "new API revision is not ready; existing traffic is retained"
        );
        if let Some(invoker) = &self.config.proxy_invoker {
            cloud.json(&[
                "run",
                "services",
                "add-iam-policy-binding",
                SERVICE,
                "--region",
                &self.config.region,
                "--member",
                &format!("serviceAccount:{invoker}"),
                "--role=roles/run.invoker",
            ])?;
        }
        cloud.json(&["run", "services", "update-traffic", SERVICE, "--region", &self.config.region,
            "--to-revisions", &format!("{revision}=100"), "--remove-tags=aegis-candidate"])
            .context("API revision is ready but traffic cutover was not confirmed; inspect Cloud Run before retrying")?;
        self.image = image.into();
        self.complete("API deployment")?;
        ui::detail(&format!(
            "Backend: {}. Public endpoint: {}",
            self.config.backend, self.config.endpoint
        ));
        Ok(())
    }
    fn connection(&self) -> super::connection::Connection {
        super::connection::Connection {
            project: self.config.project.clone(),
            database: DATABASE.into(),
            endpoint: self.config.endpoint.clone(),
            namespace: self.config.namespace.clone(),
        }
    }
    pub fn authorize(
        &self,
        namespace: &NamespaceId,
        role: NamespaceRole,
        remote: bool,
    ) -> Result<()> {
        if self.config.login.is_some() {
            super::authorize(&self.connection(), namespace, Some(role), remote)
        } else {
            super::credentials::authorize_local(&self.connection(), namespace, Some(role), None)
        }
    }
    pub(super) fn namespace_endpoint(&self) -> Result<String> {
        Ok(ApiEndpoint::parse(&self.config.endpoint)
            .map_err(anyhow::Error::msg)?
            .with_namespace(self.config.namespace.clone())
            .base_url())
    }
    fn check_endpoint(&self) -> Result<()> {
        let task = ui::task(ui::TaskOptions {
            label: format!("Checking public endpoint {}", self.config.endpoint),
            deadline: Some(Duration::from_secs(120)),
            ..Default::default()
        })?;
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let deadline = std::time::Instant::now() + Duration::from_secs(120);
        loop {
            ui::check_cancelled()?;
            let result = client
                .get(format!("{}/info", self.config.endpoint))
                .send()
                .and_then(|r| r.error_for_status())
                .and_then(|r| r.json::<Value>());
            match result {
                Ok(info) => {
                    ensure!(
                        info["issuer"] == self.config.endpoint && info["protocol"] == 2,
                        "public endpoint answered for a different Aegis deployment or protocol"
                    );
                    task.finish_and_clear();
                    return Ok(());
                }
                Err(error) => {
                    task.set_phase(format!("Waiting for endpoint; last response: {error}"));
                    if std::time::Instant::now() >= deadline {
                        bail!(
                            "Public endpoint is not reachable. Backend {} is retained. Configure your proxy to forward {} to {}/v2, then rerun setup. Last error: {error}",
                            self.config.backend,
                            self.config.endpoint,
                            self.config.backend
                        );
                    }
                }
            }
            ui::sleep(Duration::from_secs(3))?;
        }
    }
    pub fn doctor(&self) -> Result<()> {
        let admin = self.connect()?;
        let status = database("Checking stored identity", admin.status())?;
        ensure!(
            status["issuer_url"] == self.config.endpoint,
            "stored issuer differs from deployment receipt"
        );
        self.check_endpoint()?;
        let mut api =
            aegis_tool::client::AuthenticatedApiClient::load(Some(&self.namespace_endpoint()?))?;
        let membership = api.namespace_context()?;
        let service = self.cloud()?.json(&[
            "run",
            "services",
            "describe",
            SERVICE,
            "--region",
            &self.config.region,
        ])?;
        ensure!(
            array(&service["status"]["conditions"])?
                .iter()
                .any(|c| c["type"] == "Ready" && c["status"] == "True"),
            "Cloud Run service is not ready"
        );
        super::hub::check_all(self, &mut api)?;
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"project":self.config.project,"endpoint":self.config.endpoint,
            "namespace":membership.namespace,"role":membership.role,"hubs":self.hubs,"image":self.image,"ready":true})
            )?
        );
        Ok(())
    }
}

fn project(value: Option<String>) -> Result<String> {
    let value = match value {
        Some(value) => Some(value),
        None => Gcloud::active_project()?,
    };
    let value = match value {
        Some(value) => value,
        None => prompt("GCP project ID", None)?,
    };
    Gcloud::new(value.clone())?;
    Ok(value)
}
fn receipt_path(project: &str) -> Result<PathBuf> {
    Gcloud::new(project.into())?;
    Ok(client::app_dir()?
        .join("deployments")
        .join(format!("{project}.json")))
}
fn prompt(label: &str, default: Option<&str>) -> Result<String> {
    ui::require_interactive(&format!(
        "{label} is required; provide the corresponding setup option"
    ))?;
    ui::suspend(|| {
        let mut input = dialoguer::Input::<String>::new().with_prompt(label);
        if let Some(default) = default {
            input = input.default(default.into()).allow_empty(true);
        }
        input.interact_text().map_err(Into::into)
    })
}
fn read_oauth_client(
    path: Option<&PathBuf>,
    project: &str,
    endpoint: &str,
) -> Result<GoogleWebClient> {
    if let Some(path) = path {
        return GoogleWebClient::read(path, endpoint);
    }
    let account = Gcloud::new(project.into())?.user_account()?;
    ui::stage(&format!(
        "Set up Google sign-in for project {project}:\n\
         Use {account} in the Google Cloud Console.\n\
         1. Open https://console.cloud.google.com/auth/overview?project={project}\n\
            If prompted, choose Get started, name the app Aegis, and select your email and audience.\n\
            For External / Testing, add yourself and other sign-in users under Audience → Test users.\n\
         2. Open https://console.cloud.google.com/auth/clients?project={project}\n\
            Create client → Web application → name Aegis. Add this authorized redirect URI:\n\
            {endpoint}/oauth/callback\n\
         3. Download the client JSON and enter its local path below. Keep this file private."
    ));
    ui::require_interactive(
        "Rerun setup in a terminal to continue, or provide --oauth-client FILE",
    )?;
    let started = std::time::Instant::now();
    loop {
        let path = PathBuf::from(prompt("Downloaded OAuth client JSON file", None)?);
        ui::check_cancelled()?;
        match GoogleWebClient::read(&path, endpoint) {
            Ok(client) => {
                ui::success("Google sign-in credentials validated");
                return Ok(client);
            }
            Err(error) => ui::warn(&format!(
                "{error:#}. Waiting for corrected credentials (elapsed {}). Reading credentials has not changed any resources.",
                ui::format_duration(started.elapsed())
            )),
        }
    }
}
fn suggest_region() -> String {
    let zone = std::env::var("TZ")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            fs::read_link("/etc/localtime").ok().and_then(|p| {
                p.to_str()
                    .and_then(|s| s.split("zoneinfo/").nth(1))
                    .map(str::to_owned)
            })
        })
        .or_else(|| fs::read_to_string("/etc/timezone").ok())
        .unwrap_or_default();
    region_for_timezone(zone.trim()).into()
}
fn region_for_timezone(zone: &str) -> &'static str {
    match zone {
        "Australia/Perth" => "australia-southeast1",
        z if z.starts_with("Australia/") || z.starts_with("Pacific/Auckland") => {
            "australia-southeast1"
        }
        "Asia/Tokyo" => "asia-northeast1",
        "Asia/Seoul" => "asia-northeast3",
        "Asia/Kolkata" | "Asia/Calcutta" => "asia-south1",
        z if z.starts_with("Asia/") => "asia-southeast1",
        "Europe/London" => "europe-west2",
        z if z.starts_with("Europe/") => "europe-west1",
        z if z.starts_with("Africa/") => "africa-south1",
        "America/Sao_Paulo" | "America/Argentina/Buenos_Aires" => "southamerica-east1",
        "America/Los_Angeles" | "America/Vancouver" => "us-west1",
        "America/New_York" | "America/Toronto" => "us-east1",
        _ => "us-central1",
    }
}
pub(super) fn valid_region(value: &str) -> bool {
    value.len() <= 40
        && value.contains('-')
        && value.ends_with(|c: char| c.is_ascii_digit())
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}
pub(super) fn array(value: &Value) -> Result<&Vec<Value>> {
    value
        .as_array()
        .context("gcloud returned an unexpected resource list")
}
pub(super) fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .filter(|s| !s.is_empty())
        .with_context(|| format!("gcloud response is missing {key}"))
}
fn validate_image(image: &str) -> Result<&str> {
    let (repository, digest) = image
        .split_once("@sha256:")
        .context("API image must be pinned by @sha256:digest")?;
    ensure!(
        repository.contains('/')
            && !repository.starts_with('-')
            && repository
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-._/:".contains(&c))
            && digest.len() == 64
            && digest.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid container image reference"
    );
    Ok(image)
}
fn official_image() -> Result<String> {
    let task = ui::task(ui::TaskOptions {
        label: "Resolving the official API release".into(),
        deadline: Some(Duration::from_secs(60)),
        ..Default::default()
    })?;
    let http = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let token: Value = http
        .get("https://ghcr.io/token")
        .query(&[
            ("service", "ghcr.io"),
            ("scope", "repository:khoek/aegis-api:pull"),
        ])
        .send()?
        .error_for_status()?
        .json()?;
    let response = http.get(format!("https://ghcr.io/v2/khoek/aegis-api/manifests/v{}", env!("CARGO_PKG_VERSION")))
        .bearer_auth(token["token"].as_str().context("GHCR did not return a public pull token")?)
        .header("Accept", "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json")
        .send()?.error_for_status().context("Official API image is not published; pass --image with an exact published digest")?;
    let digest = response
        .headers()
        .get("docker-content-digest")
        .context("GHCR response has no manifest digest")?
        .to_str()?;
    let image = format!("ghcr.io/khoek/aegis-api@{digest}");
    validate_image(&image)?;
    task.finish_and_clear();
    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauth_download_requires_a_web_client_with_the_exact_callback() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("client.json");
        let endpoint = "https://fleet.example/custom";
        for (document, valid) in [
            (json!({"installed": {"client_id": "desktop"}}), false),
            (
                json!({"web": {"client_id": "web", "client_secret": "secret",
                "redirect_uris": ["https://fleet.example/v2/oauth/callback"]}}),
                false,
            ),
            (
                json!({"web": {"client_id": "web", "client_secret": " ",
                "redirect_uris": ["https://fleet.example/custom/oauth/callback"]}}),
                false,
            ),
            (
                json!({"web": {"client_id": "web", "client_secret": "secret",
                "redirect_uris": ["https://fleet.example/custom/oauth/callback"]}}),
                true,
            ),
        ] {
            fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
            assert_eq!(GoogleWebClient::read(&path, endpoint).is_ok(), valid);
        }
    }

    #[test]
    fn image_pins_and_region_suggestions() {
        assert!(validate_image("ghcr.io/khoek/aegis-api:latest").is_err());
        assert!(
            validate_image(&format!(
                "ghcr.io/khoek/aegis-api@sha256:{}",
                "a".repeat(64)
            ))
            .is_ok()
        );
        assert_eq!(
            region_for_timezone("Australia/Sydney"),
            "australia-southeast1"
        );
        assert_eq!(region_for_timezone("Europe/London"), "europe-west2");
        assert!(!valid_region("--quiet"));
    }
}
