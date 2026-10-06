use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt, process::Command, time::Duration};

struct Fixture(tempfile::TempDir);

impl Fixture {
    fn new(options: Value) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("gcloud");
        fs::write(&executable, include_str!("fixtures/gcloud.py")).unwrap();
        fs::set_permissions(executable, fs::Permissions::from_mode(0o700)).unwrap();
        let mut state = json!({"calls": [], "secret_versions": 0});
        state
            .as_object_mut()
            .unwrap()
            .extend(options.as_object().unwrap().clone());
        fs::write(
            dir.path().join("cloud.json"),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
        Self(dir)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_aegis-admin"));
        command
            .env("HOME", self.0.path())
            .env_remove("SUDO_USER")
            .env("AEGIS_TEST_CLOUD_STATE", self.0.path().join("cloud.json"))
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.0.path().display(),
                    std::env::var("PATH").unwrap()
                ),
            );
        command
    }

    fn run(&self, args: &[&str]) -> capulus::process::CommandOutput {
        capulus::process::CaptureOptions::default()
            .validate()
            .unwrap()
            .run(
                self.command()
                    .args([
                        "--progress",
                        "plain",
                        "--color",
                        "never",
                        "setup",
                        "--no-enroll",
                    ])
                    .args(args),
                None,
            )
            .unwrap()
    }

    fn calls(&self) -> Vec<Value> {
        serde_json::from_slice::<Value>(&fs::read(self.0.path().join("cloud.json")).unwrap())
            .unwrap()["calls"]
            .as_array()
            .unwrap()
            .clone()
    }
}

#[test]
fn missing_cloud_cli_explains_installation_without_mutation() {
    let fixture = Fixture::new(json!({}));
    let empty_path = fixture.0.path().join("empty-path");
    fs::create_dir(&empty_path).unwrap();
    let output = capulus::process::CaptureOptions::default()
        .validate()
        .unwrap()
        .run(
            fixture
                .command()
                .env("PATH", empty_path)
                .args(["setup", "--no-enroll", "--yes"]),
            None,
        )
        .unwrap();
    assert!(!output.status.success());
    assert!(
        output
            .stderr
            .contains("https://cloud.google.com/sdk/docs/install"),
        "{}",
        output.stderr
    );
    assert!(output.stderr.contains("Open a new terminal"));
    assert!(output.stdout.is_empty());
    assert!(fixture.calls().is_empty());
}

#[test]
fn missing_sign_in_is_actionable_and_never_waits_unattended() {
    for args in [vec!["--yes"], vec![]] {
        let fixture = Fixture::new(json!({"signed_out": true}));
        let output = fixture.run(&args);
        assert!(!output.status.success());
        assert!(
            output.stderr.contains("gcloud auth login"),
            "{}",
            output.stderr
        );
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.contains('\x1b'));
        assert!(
            fixture
                .calls()
                .iter()
                .all(|call| ["version", "auth"].contains(&call[0].as_str().unwrap()))
        );
    }
}

#[test]
fn expired_credentials_explain_reauthentication_before_mutation() {
    let fixture = Fixture::new(json!({"expired_auth": true}));
    let output = fixture.run(&["--yes", "--project", "aegis-fresh-test"]);
    assert!(!output.status.success());
    assert!(
        output.stderr.contains("gcloud auth login"),
        "{}",
        output.stderr
    );
    assert!(output.stderr.contains("Reauthentication required"));
    assert!(
        fixture
            .calls()
            .iter()
            .all(|call| ["version", "auth"].contains(&call[0].as_str().unwrap()))
    );
}

#[test]
fn missing_project_explains_selection_without_enabling_apis() {
    let fixture = Fixture::new(json!({}));
    let output = fixture.run(&["--yes"]);
    assert!(!output.status.success());
    assert!(
        output.stderr.contains("--project PROJECT_ID"),
        "{}",
        output.stderr
    );
    assert!(fixture.calls().iter().all(|call| call[0] != "services"));
}

#[test]
fn missing_billing_explains_activation_and_retained_state() {
    let fixture =
        Fixture::new(json!({"billing_enabled": false, "active_project": "aegis-fresh-test"}));
    let output = fixture.run(&["--yes"]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        output.stderr.contains(
            "https://console.cloud.google.com/billing/linkedaccount?project=aegis-fresh-test"
        ),
        "{}",
        output.stderr
    );
    assert!(output.stderr.contains("GCP management APIs remain enabled"));
    assert!(fixture.calls().iter().all(|call| {
        ["version", "auth", "config", "services", "billing"].contains(&call[0].as_str().unwrap())
    }));
    assert!(
        !fixture
            .0
            .path()
            .join(".aegis/deployments/aegis-fresh-test.json")
            .exists()
    );
}

#[test]
fn interactive_prerequisites_resume_after_external_repairs() {
    for scenario in ["select", "create", "interrupt", "interrupt-billing"] {
        let fixture = Fixture::new(json!({"signed_out": true, "billing_enabled": false}));
        let script = fixture.0.path().join("walkthrough.py");
        fs::write(&script, include_str!("fixtures/prerequisites.py")).unwrap();
        let output = capulus::process::CaptureOptions {
            timeout: Duration::from_secs(60),
            ..Default::default()
        }
        .validate()
        .unwrap()
        .run(
            Command::new("python3")
                .arg(script)
                .arg(env!("CARGO_BIN_EXE_aegis-admin"))
                .arg(fixture.0.path())
                .arg(scenario),
            None,
        )
        .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            output.stdout,
            output.stderr
        );
        assert!(fixture.calls().iter().all(|call| {
            [
                "version", "auth", "config", "projects", "services", "billing",
            ]
            .contains(&call[0].as_str().unwrap())
        }));
        if scenario == "interrupt" {
            assert!(!fixture.calls().iter().any(|call| call[0] == "services"));
        } else {
            assert!(
                fixture
                    .calls()
                    .iter()
                    .any(|call| call[0] == "config" && call[1] == "set")
            );
        }
    }
}
