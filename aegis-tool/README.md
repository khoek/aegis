# aegis-tool

The `aegis` client and managed host agent.

```sh
cargo install --locked aegis-tool
aegis manage enroll --local --invitation machine.json
aegis ssh server
```

Enrollment invitations carry their endpoint and namespace. The client library
shares authentication and enrollment workflows with [`aegis-admin-tool`](../aegis-admin-tool);
GCP and Firestore administration dependencies stay in that separate package.

Use `aegis --help` and `aegis manage --help` for commands. Progress goes to stderr;
JSON and credentials go to stdout. `--progress plain --color never` gives stable logs.

[Setup](../docs/setup.md) · [Validation](tests/VALIDATION.md)

Licensed under [AGPL-3.0-only](LICENSE).
