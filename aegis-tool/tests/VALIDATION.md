# Validation

Run `cargo test --workspace` for protocol, enrollment, authorization, configuration
and UI tests. Firestore and deployment recovery tests use a local emulator; see
[releasing](../../docs/releasing.md).

On Linux with OpenSSH installed, exercise the generated lockdown configuration
against the actual SSH server parser:

```sh
cargo test -p aegis-tool --lib app::lockdown::tests::lockdown_dropin_is_accepted_by_installed_sshd \
  -- --exact --ignored --nocapture
```

Run this on an OpenSSH build without GSSAPI support to catch unsupported-option
warnings. It uses a temporary configuration and host key, checks the effective
authentication settings for IPv4 and IPv6, and does not modify the running server.

Run `cargo test -p aegis-tool` to exercise the client independently of the API
and administration packages. CLI tests cover the executable boundary.

Kernel tests are opt-in and require Ubuntu, WireGuard, nftables, and root. Build
as your normal user, then run `sudo tests/run-isolated.sh TEST_BINARY AEGIS_BINARY`
from this crate. The runner creates private network and mount namespaces and
checks that the host default routes and policy rules remain unchanged.

On an Ubuntu host with AppArmor and `aa-exec`, the private-stdin regression can
also be run from the library test binary printed by
`cargo test -p aegis-tool --lib --no-run`:

```sh
sudo /path/to/aegis_tool-HASH apparmor::tests::confined_wireguard_reads_private_stdin \
  --exact --ignored --nocapture --test-threads=1
```

It loads a uniquely named AppArmor profile with the generated WireGuard rules,
applies configuration through private stdin in a separate network namespace, and
removes the test profile afterward. It does not change the installed `wg` profile.
