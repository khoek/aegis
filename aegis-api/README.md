# aegis-api

Standalone Aegis control plane built with Tokio and Axum.

```sh
cargo install --locked aegis-api
GOOGLE_CLOUD_PROJECT=my-project FIRESTORE_DATABASE_ID=aegis aegis-api
```

Initialize identity, accounts, namespaces, and certificate authorities with
`aegis-admin setup`, or `aegis-admin configure` for an existing database and your
own hosting. The service uses Application Default Credentials; Cloud Run
uses its attached service account. `PORT` defaults to 8080. Supply
`AEGIS_OIDC_CLIENT_SECRET` only when browser OAuth is configured.

Routes live under `/v2`; `/health` reports successful initialization. A proxy may
map any public path prefix to `/v2`. The configured public issuer and callback URL
remain independent of the backend hostname and Cloud Run invocation audience.

From the repository root:

```sh
docker build -f aegis-api/Dockerfile -t aegis-api .
```

[Setup](../docs/setup.md) · [Architecture](../docs/architecture.md)

Licensed under [AGPL-3.0-only](LICENSE).
