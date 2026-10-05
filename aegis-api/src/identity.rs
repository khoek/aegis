pub use aegis_dto::identity::AuthenticationConfiguration;
use arche_firestore::{Db, load_optional_typed_at};
use phylax_gcp::identity::{IdentityOptions, IdentityStore};

pub(crate) fn store(db: &Db) -> anyhow::Result<IdentityStore> {
    Ok(IdentityOptions {
        document_path: aegis_dto::identity::IDENTITY_DOCUMENT.into(),
    }
    .validate()?
    .connect(db.clone()))
}
pub(crate) async fn load_authentication(db: &Db) -> anyhow::Result<AuthenticationConfiguration> {
    let options = load_optional_typed_at::<AuthenticationConfiguration>(
        db.inner(),
        store(db)?.parent(),
        "settings",
        "authentication",
    )
    .await?
    .ok_or_else(|| {
        anyhow::anyhow!("Aegis authentication configuration is missing; run aegis-admin setup")
    })?;
    options.validate()?;
    Ok(options)
}
