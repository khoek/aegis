#[tokio::main]
async fn main() -> anyhow::Result<()> {
    arche_web::server::initialize()?;
    let config = arche_web::server::ServiceOptions::from_env()?.validate()?;
    let app = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        aegis_api::ApplicationOptions::from_env()?
            .validate()?
            .connect(),
    )
    .await??;
    arche_web::server::serve(config, app).await
}
