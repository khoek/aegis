# Releasing

Publish the shared dependencies first: Capulus 0.6.9 and the five Rete crates.
Rete's order is `phylax-core`, `phylax-oidc`, `arche-firestore`, `phylax-gcp`,
then `arche-web`. The Aegis workspace deliberately has no sibling path dependencies
except its own `aegis-types`; local development patches stay in ignored `.cargo/`.

After those releases are available:

```sh
python3 tools/prepare-lockfile.py
cargo fmt --all -- --check
cargo test --workspace --locked
```

The lockfile preparation runs in a clean temporary checkout with an isolated Cargo
home. Review and commit its result, then tag the shared workspace version.
Publish `aegis-types`, `aegis-api`, and `aegis-tool`, in that order, using
`cargo publish --locked -p PACKAGE`. Wait for each dependency to appear in the
crates.io index before publishing its consumers.

Build `aegis-api/Dockerfile` from this repository root. Publish the image as
`ghcr.io/khoek/aegis-api:vVERSION` and make the GHCR package publicly readable.
Record its digest with the release. Setup resolves that tag once and deploys its
immutable digest; operators can supply another pinned image with `--image`.

The first release requires publishing the new shared dependencies before the
clean crates.io build can run. Development lockfiles resolved with local patches
must pass through `prepare-lockfile.py` before release.

Tests requiring Firestore use a loopback emulator, never a production project:

```sh
FIRESTORE_EMULATOR_HOST=127.0.0.1:8791 cargo test -p aegis-tool emulator -- --ignored
FIRESTORE_EMULATOR_HOST=127.0.0.1:8791 cargo test -p aegis-tool --test setup -- --include-ignored
FIRESTORE_EMULATOR_HOST=127.0.0.1:8791 cargo test -p aegis-api namespace_subtrees -- --ignored
```

Fleet upgrades remain a separate operator action. Retire temporary transition
images and private packaging after every enrolled machine has reached the strict
public release. Never bypass the agent-managed installation channel.
