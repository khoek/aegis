pub use aegis_types::identity::LoginConfiguration;
use arche_firestore::{Db, load_optional_typed_at};
use phylax_gcp::identity::{IdentityOptions, IdentityStore};

pub(crate) fn store(db: &Db) -> anyhow::Result<IdentityStore> {
    Ok(IdentityOptions {
        document_path: aegis_types::identity::IDENTITY_DOCUMENT.into(),
    }
    .validate()?
    .connect(db.clone()))
}
pub(crate) async fn load_login(db: &Db) -> anyhow::Result<LoginConfiguration> {
    let options = load_optional_typed_at::<LoginConfiguration>(
        db.inner(),
        store(db)?.parent(),
        "settings",
        "login",
    )
    .await?
    .ok_or_else(|| {
        anyhow::anyhow!("Aegis login configuration is missing; run aegis admin setup")
    })?;
    options.validate()?;
    Ok(options)
}
