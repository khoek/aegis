//! Explicit temporary deployment bridge. Never merge into the strict release.
use std::{fs, io::Write, os::unix::fs::OpenOptionsExt, path::Path};

use anyhow::{Context, Result, ensure};

use crate::config::{AgentConfig, AgentConfigOptions};

pub(crate) fn parse(raw: &str) -> Result<AgentConfig> {
    let mut value: toml::Value = toml::from_str(raw)?;
    let table = value
        .as_table_mut()
        .context("agent config must be a table")?;
    if let Some(mut bird) = table.remove("bird") {
        ensure!(
            !table.contains_key("routing"),
            "both bird and routing are configured"
        );
        let fields = bird.as_table_mut().context("bird must be a table")?;
        ensure!(!fields.contains_key("backend"), "bird cannot set backend");
        fields.insert("backend".into(), "bird".into());
        table.insert("routing".into(), bird);
    }
    value.try_into::<AgentConfigOptions>()?.try_into()
}

// Token rotation must not implicitly commit the operator's schema transition.
pub(crate) fn encode_preserving_schema(path: &Path, config: &AgentConfig) -> Result<String> {
    let mut value = toml::Value::try_from(config)?;
    match fs::read_to_string(path) {
        Ok(raw) => {
            parse(&raw)?;
            let current: toml::Value = toml::from_str(&raw)?;
            if current.get("bird").is_some() {
                let table = value.as_table_mut().context("config table")?;
                let mut bird = table.remove("routing").context("routing config")?;
                ensure!(
                    bird.get("backend").and_then(toml::Value::as_str) == Some("bird"),
                    "cannot preserve bird schema for a different backend"
                );
                bird.as_table_mut().context("bird table")?.remove("backend");
                table.insert("bird".into(), bird);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(toml::to_string(&value)?)
}

pub(crate) fn commit(path: &Path, expected_host: aegis_dto::HostId) -> Result<&'static str> {
    let raw = fs::read_to_string(path)?;
    let config = parse(&raw)?;
    ensure!(
        config.host.host_id == expected_host,
        "persisted host identity changed"
    );
    let value: toml::Value = toml::from_str(&raw)?;
    if value.get("bird").is_none() {
        return Ok("routing config already current");
    }
    let backup = path.with_extension("toml.before-platform-transition");
    let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&backup)
        .context("creating exclusive platform transition backup; inspect existing backup before retrying")?;
    file.write_all(raw.as_bytes())?;
    file.sync_all()?;
    capulus::store::atomic_write(
        path,
        toml::to_string(&config)?.as_bytes(),
        Some(0o600),
        Some(0o755),
    )
    .context("config transition failed; private backup retained")?;
    Ok("routing config committed; private before-platform-transition backup retained")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw() -> String {
        toml::to_string(&crate::agent::tests::raw_agent_config())
            .unwrap()
            .replace("[routing]", "[bird]")
            .replace("backend = \"bird\"\n", "")
    }

    #[test]
    fn rotation_preserves_schema_until_explicit_commit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        fs::write(&path, raw()).unwrap();
        let mut config = parse(&raw()).unwrap();
        config.auth.refresh_token = "rotated-token".into();
        crate::config::persist_agent_config(&path, &config).unwrap();
        let rotated = fs::read_to_string(&path).unwrap();
        assert!(rotated.contains("[bird]"));
        assert_eq!(parse(&rotated).unwrap().auth.refresh_token, "rotated-token");
        commit(&path, config.host.host_id).unwrap();
        let strict = fs::read_to_string(&path).unwrap();
        let strict: AgentConfigOptions = toml::from_str(&strict).unwrap();
        assert_eq!(strict.auth.refresh_token, "rotated-token");
        assert_eq!(
            fs::read_to_string(path.with_extension("toml.before-platform-transition")).unwrap(),
            rotated
        );
        assert_eq!(
            commit(&path, config.host.host_id).unwrap(),
            "routing config already current"
        );
    }

    #[test]
    fn rejects_ambiguous_and_unknown_config_and_changed_identity() {
        assert!(
            parse(
                &(raw() + "\n[routing]\nbackend = 'bird'\nconfig_path = '/etc/bird/bird.conf'\n")
            )
            .is_err()
        );
        assert!(parse(&(raw() + "\nunexpected = true\n")).is_err());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        fs::write(&path, raw()).unwrap();
        assert!(
            commit(
                &path,
                "00000000-0000-4000-8000-000000000002".parse().unwrap()
            )
            .is_err()
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), raw());
    }
}
