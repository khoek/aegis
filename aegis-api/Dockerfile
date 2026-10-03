# syntax=docker/dockerfile:1
FROM rust:slim-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock LICENSE ./
COPY aegis-types ./aegis-types
COPY aegis-api ./aegis-api
COPY aegis-tool ./aegis-tool
COPY aegis-admin ./aegis-admin
RUN cargo build --locked --release --package aegis-api && strip target/release/aegis-api

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/aegis-api /usr/local/bin/aegis-api
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/aegis-api"]
