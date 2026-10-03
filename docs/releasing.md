# Releasing

Publish the shared dependencies first: Capulus 0.6.9 and the five Rete crates.
Rete's order is `phylax-core`, `phylax-oidc`, `arche-firestore`, `phylax-gcp`,
then `arche-web`. The Aegis workspace deliberately uses path dependencies only
within its own workspace; local development patches stay in ignored `.cargo/`.

After those releases are available:

```sh
python3 tools/prepare-lockfile.py
cargo fmt --all -- --check
cargo test --workspace --locked
```

The lockfile preparation runs in a clean temporary checkout with an isolated Cargo
home. Review and commit its result, then tag the shared workspace version.
Publish `aegis-dto`, `aegis-api`, `aegis-tool`, then `aegis-admin-tool`, using
`cargo publish --locked -p PACKAGE`. Wait for each dependency to appear in the
crates.io index before publishing its consumers.

Install `aegis-tool` and `aegis-admin-tool` independently to verify their package
boundaries. The client must build without Firestore, GCP identity, or
certificate-authority generation dependencies. Neither package needs feature flags.

The `API image` workflow builds `aegis-api/Dockerfile` on version tags or manual
dispatch and publishes `ghcr.io/khoek/aegis-api:vVERSION`. Make the GHCR package
publicly readable on its first publication. Record the workflow's digest with the
release. Setup resolves that tag once and deploys its immutable digest; operators
can supply another pinned image with `--image`.

The first release requires publishing the new shared dependencies before the
clean crates.io build can run. Development lockfiles resolved with local patches
must pass through `prepare-lockfile.py` before release.

Tests requiring Firestore use a loopback emulator, never a production project:

```sh
FIRESTORE_EMULATOR_HOST=127.0.0.1:8791 cargo test -p aegis-admin-tool emulator -- --ignored
FIRESTORE_EMULATOR_HOST=127.0.0.1:8791 cargo test -p aegis-admin-tool --test setup -- --include-ignored
FIRESTORE_EMULATOR_HOST=127.0.0.1:8791 cargo test -p aegis-api namespace_subtrees -- --ignored
```

Fleet upgrades remain a separate operator action. Retire temporary transition
images and private packaging after every enrolled machine has reached the strict
public release. Never bypass the agent-managed installation channel.
