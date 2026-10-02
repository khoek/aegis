Use Rust 2024 and named, validated configuration options. Keep crate boundaries
small and explicit. No compatibility aliases, silent migrations, or deployment
specific constants in product code.

Progress belongs on stderr through the shared invocation UI. Preserve typed
interruption, bound network/subprocess operations, suspend rendering for prompts
and streaming children, and report committed state after a failed mutation.

Publishing and deployment require explicit authorization. Existing agents upgrade
through `aegis advanced redeploy` or `aegis advanced fleet redeploy`; never replace
managed binaries through another channel. Plan incompatible fleet transitions as
explicit temporary releases and operator-run migrations. Remove transitional
behavior from the final product.
