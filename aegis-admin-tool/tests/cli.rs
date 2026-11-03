use std::process::Command;

fn invoke(binary: &str, args: &[&str]) -> capulus::process::CommandOutput {
    capulus::process::CaptureOptions::default()
        .validate()
        .unwrap()
        .run(Command::new(binary).args(args), None)
        .unwrap()
}

#[test]
fn administration_is_a_separate_versioned_cli() {
    let admin = env!("CARGO_BIN_EXE_aegis-admin");
    let version = invoke(admin, &["--version"]);
    assert!(version.status.success());
    assert_eq!(
        version.stdout.trim(),
        concat!("aegis-admin ", env!("CARGO_PKG_VERSION"))
    );
    let help = invoke(admin, &["--help"]);
    assert!(help.status.success());
    assert!(help.stdout.contains("setup"));
    assert!(!help.stdout.contains("--api-base"));
    assert!(help.stderr.is_empty());
    for args in [
        &["ssh"][..],
        &["agent", "serve"],
        &["--api-base", "https://example.com"],
    ] {
        assert_eq!(invoke(admin, args).status.code(), Some(2));
    }
    let template = invoke(
        admin,
        &[
            "--progress",
            "plain",
            "--color",
            "never",
            "namespace-template",
        ],
    );
    assert!(template.status.success());
    serde_json::from_str::<serde_json::Value>(&template.stdout).unwrap();
    assert!(!template.stderr.contains('\x1b'));
}

#[test]
fn setup_accepts_a_validated_local_alias() {
    let admin = env!("CARGO_BIN_EXE_aegis-admin");
    let help = invoke(admin, &["setup", "--help"]);
    assert!(help.stdout.contains("--name <NAME>"));
    for name in ["Invalid Name", "a9b0c1d2-0000-4000-8000-000000000000", ""] {
        let output = invoke(admin, &["setup", "--name", name]);
        assert_eq!(output.status.code(), Some(2), "{}", output.stderr);
        assert!(output.stderr.contains("host alias must use lowercase"));
    }
    let output = invoke(admin, &["setup", "--name", "laptop", "--no-enroll"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.contains("cannot be used with"));
}
