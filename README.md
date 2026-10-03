# aegis

Authenticated SSH, WireGuard networking, and fleet management.

- [`aegis-types`](aegis-types): protocol and configuration types
- [`aegis-api`](aegis-api): standalone Tokio/Axum control plane
- [`aegis-tool`](aegis-tool): `aegis` client and host agent
- [`aegis-admin`](aegis-admin): deployment and account administration

```sh
cargo install --locked aegis-tool aegis-admin
aegis-admin setup
```

[Setup](docs/setup.md) · [Architecture](docs/architecture.md) · [Releasing](docs/releasing.md)

Licensed under [AGPL-3.0-only](LICENSE).
