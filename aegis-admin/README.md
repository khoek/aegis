# aegis-admin

Deploy and administer Aegis with local `gcloud` credentials.

```sh
cargo install --locked aegis-admin
aegis-admin setup
aegis-admin authorize
```

Setup provisions the API and first hub, authorizes the owner, and enrolls the
current machine. Use `--no-enroll` for an operator-only computer. Administration
uses local GCP access; no administration credentials travel through the Aegis API.

Use `aegis-admin --help` for account, namespace, deployment, and recovery commands.
Everyday access uses the separate [`aegis-tool`](../aegis-tool) package.

[Setup](../docs/setup.md) · [Releasing](../docs/releasing.md)

Licensed under [AGPL-3.0-only](LICENSE).
