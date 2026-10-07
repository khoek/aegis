use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=native/babeld");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo output directory"));
    fs::write(
        output.join("version.h"),
        "#define BABELD_VERSION \"1.14\"\n",
    )
    .expect("write Babel version header");
    let compiler = cc::Build::new().get_compiler();
    let mut command: Command = compiler.to_command();
    command
        .args(["-O2", "-Wall", "-Inative/babeld", "-I"])
        .arg(&output)
        .arg("-o")
        .arg(output.join("aegis-babeld"));
    for source in [
        "babeld.c",
        "net.c",
        "kernel.c",
        "util.c",
        "interface.c",
        "source.c",
        "neighbour.c",
        "route.c",
        "xroute.c",
        "message.c",
        "resend.c",
        "configuration.c",
        "local.c",
        "hmac.c",
        "rfc6234/sha224-256.c",
        "BLAKE2/ref/blake2s-ref.c",
    ] {
        command.arg(PathBuf::from("native/babeld").join(source));
    }
    let mut child = command.spawn().expect("start bundled Babel compilation");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    loop {
        if let Some(status) = child.try_wait().expect("wait for bundled Babel compiler") {
            assert!(status.success(), "bundled Babel helper compilation failed");
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().expect("stop timed-out Babel compiler");
            let kill_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while child.try_wait().expect("reap Babel compiler").is_none() {
                assert!(
                    std::time::Instant::now() < kill_deadline,
                    "Babel compiler did not exit after SIGKILL"
                );
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            panic!("bundled Babel compilation exceeded five minutes");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}
