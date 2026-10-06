# aegis-admin-tool

Deploy and administer Aegis with local `gcloud` credentials.

```sh
cargo install --locked aegis-admin-tool
aegis-admin setup
aegis-admin authorize
```

Setup guides missing GCP prerequisites, provisions the API and first hub,
authorizes the owner, and enrolls the current machine. Credentials are issued through local GCP access; browser OAuth is
opt-in with `setup --oauth`. Use `--no-enroll` for an operator-only computer. Administration
uses local GCP access; no administration credentials travel through the Aegis API.

Use `aegis-admin --help` for account, namespace, deployment, and recovery commands.
Everyday access uses the separate [`aegis-tool`](../aegis-tool) package.

[Setup](../docs/setup.md) · [Releasing](../docs/releasing.md)

Licensed under [AGPL-3.0-only](LICENSE).
