use super::{database, gcloud::Gcloud, identity, store};
use aegis_types::{NamespaceId, namespace::ApiEndpoint};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Connection {
    pub project: String,
    pub database: String,
    pub endpoint: String,
    pub namespace: NamespaceId,
}

impl Connection {
    pub fn load(project: Option<String>) -> Result<Self> {
        let project = match project {
            Some(project) => project,
            None => {
                Gcloud::active_project()?.context("Select a gcloud project or pass --project")?
            }
        };
        let path = path(&project)?;
        let connection: Self = serde_json::from_slice(&fs::read(&path).with_context(|| format!(
            "No Aegis administration connection for {project}; run `aegis admin setup` or `aegis admin connect NAMESPACE --project {project} --database DATABASE`"
        ))?)?;
        ensure!(
            connection.project == project,
            "administration connection project mismatch"
        );
        connection.validate()?;
        Ok(connection)
    }
    fn validate(&self) -> Result<()> {
        Gcloud::new(self.project.clone())?;
        store::AdminOptions {
            project_id: self.project.clone(),
            database_id: self.database.clone(),
        }
        .validate()?;
        let endpoint = ApiEndpoint::parse(&self.endpoint).map_err(anyhow::Error::msg)?;
        ensure!(
            self.endpoint.starts_with("https://")
                && endpoint.namespace().is_none()
                && endpoint.service_url() == self.endpoint,
            "administration endpoint must be a canonical HTTPS service URL"
        );
        Ok(())
    }
    pub fn persist(&self) -> Result<()> {
        self.validate()?;
        capulus::store::atomic_write(
            &path(&self.project)?,
            &serde_json::to_vec_pretty(self)?,
            Some(0o600),
            Some(0o700),
        )
    }
    pub fn open(&self) -> Result<store::Admin> {
        self.validate()?;
        let token = Gcloud::new(self.project.clone())?.token()?;
        let admin = database(
            "Connecting with local GCP credentials",
            store::AdminOptions {
                project_id: self.project.clone(),
                database_id: self.database.clone(),
            }
            .validate()?
            .connect(token),
        )?;
        let issuer = database("Checking deployment identity", async {
            Ok(identity::store(&admin.db)?
                .load_config()
                .await?
                .api_token
                .iss)
        })?;
        ensure!(
            issuer == self.endpoint,
            "stored issuer changed; inspect the deployment before reconnecting"
        );
        Ok(admin)
    }
    pub fn attach(
        project: Option<String>,
        database_id: String,
        namespace: NamespaceId,
    ) -> Result<()> {
        let project = match project {
            Some(project) => project,
            None => {
                Gcloud::active_project()?.context("Select a gcloud project or pass --project")?
            }
        };
        let options = store::AdminOptions {
            project_id: project.clone(),
            database_id: database_id.clone(),
        }
        .validate()?;
        let admin = database(
            "Opening existing deployment",
            options.connect(Gcloud::new(project.clone())?.token()?),
        )?;
        let issuer = database("Discovering deployment identity", async {
            ensure!(
                admin.namespaces().await?.contains(&namespace),
                "namespace does not exist in this database"
            );
            Ok(identity::store(&admin.db)?
                .load_config()
                .await?
                .api_token
                .iss)
        })?;
        let connection = Self {
            project,
            database: database_id,
            namespace,
            endpoint: issuer,
        };
        connection.persist()?;
        crate::config::UserContext {
            api_base: ApiEndpoint::parse(&connection.endpoint)
                .map_err(anyhow::Error::msg)?
                .with_namespace(connection.namespace)
                .base_url(),
        }
        .persist()?;
        crate::ui::success(
            "Administration connection and namespace saved; cloud configuration was not changed",
        );
        Ok(())
    }
}
fn path(project: &str) -> Result<PathBuf> {
    Gcloud::new(project.into())?;
    Ok(crate::config::app_dir()?
        .join("administration")
        .join(format!("{project}.json")))
}
