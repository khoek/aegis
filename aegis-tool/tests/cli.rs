use std::process::Command;

fn invoke(binary: &str, args: &[&str]) -> capulus::process::CommandOutput {
    capulus::process::CaptureOptions::default()
        .validate()
        .unwrap()
        .run(Command::new(binary).args(args), None)
        .unwrap()
}

#[test]
fn ordinary_cli_has_no_deployment_commands() {
    let binary = env!("CARGO_BIN_EXE_aegis");
    let help = invoke(binary, &["--help"]);
    assert!(help.status.success());
    assert!(help.stdout.contains("manage"));
    assert!(!help.stdout.contains("setup"));
    assert!(help.stderr.is_empty());
    for command in ["admin", "setup", "authorize"] {
        let result = invoke(binary, &[command]);
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stderr.contains("unrecognized subcommand"));
    }
}

#[test]
fn invalid_endpoint_is_a_command_error_instead_of_a_panic() {
    let directory = tempfile::tempdir().unwrap();
    let output = capulus::process::CaptureOptions::default()
        .validate()
        .unwrap()
        .run(
            Command::new(env!("CARGO_BIN_EXE_aegis"))
                .env("HOME", directory.path())
                .args([
                    "--progress",
                    "plain",
                    "--color",
                    "never",
                    "--api-base",
                    "invalid",
                    "list",
                ]),
            None,
        )
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", output.stderr);
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.contains("panicked"));
}
