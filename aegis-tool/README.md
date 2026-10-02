# aegis-tool

The `aegis` CLI and managed host agent.

```sh
cargo install --locked aegis-tool
aegis admin setup
aegis manage enroll --remote alice@server
aegis ssh server
```

Setup uses local `gcloud` credentials. Everyday access uses scoped Aegis credentials.
Enrollment invitations carry their endpoint and namespace:

```sh
aegis manage enroll --local --invitation machine.json
```

Use `aegis --help`, `aegis admin --help`, and `aegis manage --help` for commands.
Progress goes to stderr; JSON and generated credentials go to stdout.
`--progress plain --color never` gives stable log output.

[Setup](../docs/setup.md) · [Validation](tests/VALIDATION.md)

Licensed under [AGPL-3.0-only](LICENSE).
