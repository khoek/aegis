use std::{io::Write, path::Path};

use aegis_dto::{
    NamespaceId, NamespaceRole,
    identity::{USER_CLIENT_ID, UserCredential},
    namespace::ApiEndpoint,
};
use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use phylax_core::Subject;
use phylax_gcp::identity::UserRecord;

use super::{connection::Connection, database, gcloud::Gcloud, identity, store::Admin};
use aegis_tool::{client, ui};

#[derive(Debug, Subcommand)]
pub(super) enum CredentialCommand {
    /// Issue a credential for one client. The file is consumed at first login.
    Issue {
        user: String,
        #[arg(long)]
        output: std::path::PathBuf,
    },
    /// List a user's sessions without revealing credentials.
    List { user: String },
    /// Revoke one session and all of its rotated credentials.
    Revoke { user: String, session: String },
}

pub(super) fn run(connection: &Connection, command: CredentialCommand) -> Result<()> {
    let admin = connection.open()?;
    match command {
        CredentialCommand::Issue { user, output } => issue(connection, &admin, &user, &output)?,
        CredentialCommand::List { user } => {
            let sessions = database("Listing credentials", async {
                let identities = identity::store(&admin.db)?;
                ensure!(identities.user(&user).await?.is_some(), "unknown user");
                let documents: Vec<firestore::FirestoreDocument> = admin
                    .db
                    .inner()
                    .fluent()
                    .select()
                    .from("grants")
                    .parent(identities.parent())
                    .filter(|q| q.field("subject").equal(format!("user:{user}")))
                    .query()
                    .await?;
                documents
                    .iter()
                    .map(|document| {
                        let value: serde_json::Value =
                            arche_firestore::deserialize_stored_document(document)?;
                        Ok(
                            serde_json::json!({"session":document.name.rsplit('/').next(),
                        "created_unix":value["created_unix"],"expires_unix":value["expires_unix"],
                        "revoked_unix":value["revoked_unix"]}),
                        )
                    })
                    .collect::<Result<Vec<_>>>()
            })?;
            println!("{}", serde_json::to_string_pretty(&sessions)?);
        }
        CredentialCommand::Revoke { user, session } => {
            ensure!(
                !session.is_empty() && !session.contains('/'),
                "invalid session id"
            );
            let revoked = database("Revoking credential", async {
                let identities = identity::store(&admin.db)?;
                let settings = identities.load_config().await?;
                identities
                    .auth_store(&settings, 600)?
                    .revoke_refresh_session(
                        &session,
                        &Subject::new(format!("user:{user}"))?,
                        USER_CLIENT_ID,
                        client::now_unix(),
                    )
                    .await
            })?;
            ensure!(
                revoked,
                "session does not belong to this user, is missing, or was already revoked"
            );
            ui::success("Credential revoked");
        }
    }
    Ok(())
}

pub(super) async fn create_user(admin: &Admin, email: String) -> Result<UserRecord> {
    ensure!(
        !email.trim().is_empty() && email.trim() == email,
        "account label is empty or padded"
    );
    let user = UserRecord {
        id: uuid::Uuid::new_v4().to_string(),
        email,
        disabled: false,
        session_version: 1,
    };
    identity::store(&admin.db)?.create_user(&user, None).await?;
    Ok(user)
}

fn issue(connection: &Connection, admin: &Admin, user: &str, output: &Path) -> Result<()> {
    // Reserve the destination before committing a credential; never replace another secret.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)
        .with_context(|| format!("create {}", output.display()))?;
    let issued = database("Issuing user credential", async {
        let identities = identity::store(&admin.db)?;
        let user = identities.user(user).await?.context("unknown user")?;
        ensure!(!user.disabled, "user is disabled");
        let membership = admin.members(connection.namespace.clone()).await?;
        ensure!(
            membership.get(&user.id).is_some(),
            "grant namespace membership before issuing a credential"
        );
        let settings = identities.load_config().await?;
        let session = identities
            .auth_store(&settings, 600)?
            .issue_refresh_token(phylax_gcp::RefreshTokenIssueRequest {
                subject: Subject::new(format!("user:{}", user.id))?,
                client_id: USER_CLIENT_ID,
                now_unix: client::now_unix(),
            })
            .await?;
        Ok(UserCredential {
            api_base: ApiEndpoint::parse(&connection.endpoint)
                .map_err(anyhow::Error::msg)?
                .with_namespace(connection.namespace.clone())
                .base_url(),
            user_id: user.id,
            session_id: session.session_id().into(),
            refresh_token: session.refresh_token().into(),
            expires_unix: session.expires_unix(),
        })
    });
    let credential = match issued {
        Ok(credential) => credential,
        Err(error) => {
            drop(file);
            std::fs::remove_file(output)
                .context("issuance failed; empty output file could not be removed")?;
            return Err(error.context("credential issuance was not confirmed; inspect the user's sessions before retrying"));
        }
    };
    let saved = (|| -> Result<()> {
        file.write_all(&serde_json::to_vec_pretty(&credential)?)?;
        file.sync_all()?;
        Ok(())
    })();
    saved.with_context(|| format!("session {} is committed; credential file may be incomplete. Revoke that session before retrying", credential.session_id))?;
    ui::success(&format!(
        "Credential saved to {} · session {}",
        output.display(),
        credential.session_id
    ));
    Ok(())
}

use std::os::unix::fs::OpenOptionsExt;

pub(super) fn authorize_local(
    connection: &Connection,
    namespace: &NamespaceId,
    role: Option<NamespaceRole>,
    requested_user: Option<&str>,
) -> Result<()> {
    let admin = connection.open()?;
    let user = if let Some(id) = requested_user {
        database("Checking account", identity::store(&admin.db)?.user(id))?
            .context("unknown user")?
    } else {
        let account = Gcloud::new(connection.project.clone())?.operator_account()?;
        database("Authorizing operator account", async {
            let mut matches = admin
                .users()
                .await?
                .into_iter()
                .filter(|user| user.email == account)
                .collect::<Vec<_>>();
            ensure!(
                matches.len() <= 1,
                "multiple accounts have this label; select one with --user"
            );
            match matches.pop() {
                Some(user) => Ok(user),
                None => create_user(&admin, account).await,
            }
        })?
    };
    ensure!(
        !user.disabled,
        "account is disabled; enable it explicitly first"
    );
    database(
        "Granting namespace membership",
        admin.authorize_membership(namespace.clone(), &user.id, role),
    )
    .context("account retained; membership was not confirmed")?;
    let selected = Connection {
        project: connection.project.clone(),
        database: connection.database.clone(),
        endpoint: connection.endpoint.clone(),
        namespace: namespace.clone(),
    };
    let directory = client::app_dir()?.join("credentials");
    capulus::store::ensure_directory(&directory, Some(0o700))?;
    let path = directory.join(format!("{}.json", uuid::Uuid::new_v4()));
    issue(&selected, &admin, &user.id, &path)?;
    client::login::import_credential_file(&path, None).with_context(|| {
        format!(
            "account and membership committed; credential retained at {} unless already imported",
            path.display()
        )
    })
}
