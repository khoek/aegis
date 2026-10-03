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
