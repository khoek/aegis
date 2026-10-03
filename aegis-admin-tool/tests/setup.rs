use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt, process::Command, time::Duration};

#[test]
fn fresh_setup_guides_sign_in_configuration_before_creating_resources() {
    let dir = tempfile::tempdir().unwrap();
    let executable = dir.path().join("gcloud");
    fs::write(&executable, include_str!("fixtures/gcloud.py")).unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let state = dir.path().join("cloud.json");
    let output = capulus::process::CaptureOptions::default()
        .validate()
        .unwrap()
        .run(
            Command::new(env!("CARGO_BIN_EXE_aegis-admin"))
                .env("HOME", dir.path())
                .env_remove("SUDO_USER")
                .env("AEGIS_TEST_CLOUD_STATE", &state)
                .env(
                    "PATH",
                    format!(
                        "{}:{}",
                        dir.path().display(),
                        std::env::var("PATH").unwrap()
                    ),
                )
                .args([
                    "--progress",
                    "plain",
                    "--color",
                    "never",
                    "setup",
                    "--project",
                    "aegis-fresh-test",
                    "--region",
                    "australia-southeast1",
                    "--yes",
                    "--no-enroll",
                ]),
            None,
        )
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.contains('\x1b'));
    for expected in [
        "https://console.cloud.google.com/auth/overview?project=aegis-fresh-test",
        "https://console.cloud.google.com/auth/clients?project=aegis-fresh-test",
        "Audience → Test users",
        "https://aegis-api-1234567890.australia-southeast1.run.app/v2/oauth/callback",
        "--oauth-client FILE",
    ] {
        assert!(output.stderr.contains(expected), "{}", output.stderr);
    }
    let cloud: Value = serde_json::from_slice(&fs::read(state).unwrap()).unwrap();
    let calls = cloud["calls"].as_array().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0][0], "projects");
    assert_eq!(calls[0][1], "describe");
    assert!(
        !dir.path()
            .join(".aegis/deployments/aegis-fresh-test.json")
            .exists()
    );
}

#[test]
fn administration_help_and_validation_do_not_require_a_saved_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    for args in [
        vec!["--help"],
        vec!["setup", "--help"],
        vec!["authorize", "--help"],
        vec!["configure", "--help"],
        vec!["namespace-template"],
    ] {
        let result = capulus::process::CaptureOptions::default()
            .validate()
            .unwrap()
            .run(
                Command::new(env!("CARGO_BIN_EXE_aegis-admin"))
                    .args(args)
                    .env("HOME", dir.path()),
                None,
            )
            .unwrap();
        assert!(result.status.success(), "{}", result.stderr);
        assert!(!result.stdout.contains("api.hoek.io"));
    }
}

#[test]
#[ignore = "requires a loopback FIRESTORE_EMULATOR_HOST"]
fn externally_hosted_configuration_and_discovery_do_not_provision_cloud_resources() {
    assert!(
        std::env::var("FIRESTORE_EMULATOR_HOST")
            .unwrap()
            .starts_with("127.0.0.1:")
    );
    let dir = tempfile::tempdir().unwrap();
    let executable = dir.path().join("gcloud");
    fs::write(&executable, include_str!("fixtures/gcloud.py")).unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let oauth = dir.path().join("oauth.json");
    fs::write(
        &oauth,
        serde_json::to_vec(&json!({"web": {
            "client_id": "external-client", "client_secret": "external-secret-never-log",
            "redirect_uris": ["https://fleet.example/custom/oauth/callback"]
        }}))
        .unwrap(),
    )
    .unwrap();
    let project = format!(
        "aegis-external-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    let state = dir.path().join("cloud.json");
    for discover in [false, false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_aegis-admin"));
        command
            .env("HOME", dir.path())
            .env_remove("SUDO_USER")
            .env("AEGIS_TEST_CLOUD_STATE", &state)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    dir.path().display(),
                    std::env::var("PATH").unwrap()
                ),
            )
            .args(["--progress", "plain"]);
        if discover {
            command.args(["connect", "personal"]);
        } else {
            command
                .args([
                    "configure",
                    "--endpoint",
                    "https://fleet.example/custom",
                    "--oauth-client",
                ])
                .arg(&oauth);
        }
        command.args(["--project", &project, "--database", "custom-database"]);
        let output = capulus::process::CaptureOptions::default()
            .validate()
            .unwrap()
            .run(&mut command, None)
            .unwrap();
        assert!(output.status.success(), "{}", output.stderr);
        assert!(!output.stderr.contains("external-secret-never-log"));
        assert!(output.stdout.is_empty());
    }
    let cloud: Value = serde_json::from_slice(&fs::read(state).unwrap()).unwrap();
    assert!(
        cloud["calls"]
            .as_array()
            .unwrap()
            .iter()
            .all(|call| call[0] == "auth" && call[1] == "print-access-token")
    );
    let context = fs::read_to_string(dir.path().join(".aegis/context.toml")).unwrap();
    assert!(context.contains("https://fleet.example/custom/namespaces/personal"));
}

#[test]
#[ignore = "requires a loopback FIRESTORE_EMULATOR_HOST"]
fn setup_resumes_after_deploy_failure_without_replacing_keys_or_secrets() {
    assert!(
        std::env::var("FIRESTORE_EMULATOR_HOST")
            .unwrap()
            .starts_with("127.0.0.1:")
    );
    let dir = tempfile::tempdir().unwrap();
    let executable = dir.path().join("gcloud");
    fs::write(&executable, include_str!("fixtures/gcloud.py")).unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let oauth = dir.path().join("oauth.json");
    fs::write(
        &oauth,
        serde_json::to_vec(
            &json!({"web": {"client_id":"test-client", "client_secret":"test-secret-never-log",
        "redirect_uris":["https://fleet.example/custom/oauth/callback"]}}),
        )
        .unwrap(),
    )
    .unwrap();
    let project = format!(
        "aegis-wizard-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    let image = format!("ghcr.io/khoek/aegis-api@sha256:{}", "a".repeat(64));
    let state = dir.path().join("cloud.json");
    for attempt in 0..3 {
        let mut command = Command::new(env!("CARGO_BIN_EXE_aegis-admin"));
        command
            .env("HOME", dir.path())
            .env_remove("SUDO_USER")
            .env("AEGIS_TEST_CLOUD_STATE", &state)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    dir.path().display(),
                    std::env::var("PATH").unwrap()
                ),
            )
            .args([
                "--progress",
                "plain",
                "--color",
                "never",
                "setup",
                "--project",
                &project,
                "--yes",
                "--no-enroll",
            ]);
        if attempt == 0 {
            command
                .args([
                    "--region",
                    "us-central1",
                    "--endpoint",
                    "https://fleet.example/custom",
                    "--image",
                    &image,
                    "--oauth-client",
                ])
                .arg(&oauth);
        } else if attempt == 2 {
            command.arg("--oauth-client").arg(&oauth);
        }
        let output = capulus::process::CaptureOptions {
            timeout: Duration::from_secs(90),
            ..Default::default()
        }
        .validate()
        .unwrap()
        .run(&mut command, None)
        .unwrap();
        assert!(!output.status.success());
        assert!(
            output.stderr.contains("simulated image pull failure"),
            "{}",
            output.stderr
        );
        assert!(output.stderr.contains("Resources and keys are retained"));
        assert!(!output.stderr.contains("test-secret-never-log"));
        assert!(!output.stderr.contains('\x1b'));
        assert!(output.stdout.is_empty(), "{}", output.stdout);
        let receipt = dir
            .path()
            .join(".aegis/deployments")
            .join(format!("{project}.json"));
        let mut receipt_value: Value =
            serde_json::from_slice(&fs::read(&receipt).unwrap()).unwrap();
        assert_eq!(receipt_value["secret_version"], "1");
        assert_eq!(
            receipt_value["completed"],
            json!(["GCP resources", "Identity and certificate authorities"])
        );
        if attempt == 1 {
            // Model a process dying after Secret Manager committed but before its receipt was saved.
            receipt_value["secret_version"] = Value::Null;
            fs::write(receipt, serde_json::to_vec(&receipt_value).unwrap()).unwrap();
        }
    }
    let state: Value = serde_json::from_slice(&fs::read(state).unwrap()).unwrap();
    assert_eq!(state["secret_versions"], 1);
}
