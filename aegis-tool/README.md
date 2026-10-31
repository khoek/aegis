# aegis-tool

The `aegis` client and managed host agent.

```sh
cargo install --locked aegis-tool
aegis manage enroll --local --invitation machine.json
aegis
aegis ssh server
```

Enrollment invitations carry their endpoint and namespace. The client library
shares authentication and enrollment workflows with [`aegis-admin-tool`](../aegis-admin-tool);
GCP and Firestore administration dependencies stay in that separate package.

Run `aegis` or `aegis pick` to choose a host and open SSH. The picker shares the
satellite login UI and displays the same host details as `aegis list`, with live
reachability checks and a highlighted selection. Use ↑/↓ (or j/k) and Enter;
Esc, q, or Ctrl-C cancels. Recent SSH choices appear first within the leaf and hub
groups, with leaves before hubs, and are remembered across invocations.
`aegis pick --refresh` refreshes inventory first; `--network` and `--user` select
the network and login name. Multiple authorized login names prompt for a choice.
Use `aegis ssh HOST` when running without an interactive terminal.

Use `aegis --help` and `aegis manage --help` for commands. Progress goes to stderr;
JSON and credentials go to stdout. `--progress plain --color never` gives stable logs.

[Setup](../docs/setup.md) · [Platforms](../docs/platforms.md) · [Validation](tests/VALIDATION.md)

Licensed under [AGPL-3.0-only](LICENSE).
