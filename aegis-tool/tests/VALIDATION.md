# Validation

Run `cargo test --workspace` for protocol, enrollment, authorization, configuration
and UI tests. Firestore and deployment recovery tests use a local emulator; see
[releasing](../../docs/releasing.md).

Run `cargo test -p aegis-tool` to exercise the client independently of the API
and administration packages. CLI tests cover the executable boundary.

Kernel tests are opt-in and require Ubuntu, WireGuard, nftables, and root. Build
as your normal user, then run `sudo tests/run-isolated.sh TEST_BINARY AEGIS_BINARY`
from this crate. The runner creates private network and mount namespaces and
checks that the host default routes and policy rules remain unchanged.
