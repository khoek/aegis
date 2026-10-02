use anyhow::{Context, Result};
use semver::Version;
use serde::Deserialize;
use std::{io::Read, time::Duration};

pub fn latest_version() -> Result<Version> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("aegis-tool/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let response = client
        .get("https://index.crates.io/ae/gi/aegis-tool")
        .send()?
        .error_for_status()?;
    let mut body = String::new();
    response
        .take(8 * 1024 * 1024 + 1)
        .read_to_string(&mut body)?;
    anyhow::ensure!(
        body.len() <= 8 * 1024 * 1024,
        "crates.io index response exceeds limit"
    );
    latest_from_index(&body)
}

fn latest_from_index(body: &str) -> Result<Version> {
    #[derive(Deserialize)]
    struct Entry {
        vers: Version,
        yanked: bool,
    }
    let versions = body
        .lines()
        .filter(|line| !line.is_empty())
        .map(serde_json::from_str::<Entry>)
        .collect::<Result<Vec<_>, _>>()?;
    versions
        .into_iter()
        .filter(|v| !v.yanked && v.vers.pre.is_empty())
        .map(|v| v.vers)
        .max()
        .context("crates.io has no non-yanked stable aegis-tool release")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn release_selection_rejects_yanked_prerelease_and_invalid_metadata() {
        let body = r#"{"vers":"0.2.1","yanked":false}
{"vers":"0.3.0","yanked":true}
{"vers":"0.4.0-rc.1","yanked":false}"#;
        assert_eq!(latest_from_index(body).unwrap(), Version::new(0, 2, 1));
        assert!(latest_from_index("{}").is_err());
        assert!(latest_from_index("").is_err());
    }
}
