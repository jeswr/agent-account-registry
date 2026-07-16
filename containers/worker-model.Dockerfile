# [GPT-5.6] REG-3 model sandbox: pinned Node runtime for the routed CLIs plus the target's Rust
# toolchain/generic build utilities. The live script bind-mounts the CLI and target; no secrets are
# baked into this image.
FROM node:20.19.4-bookworm-slim@sha256:6db5e436948af8f0244488a1f658c2c8e55a3ae51ca2e1686ed042be8f25f70a AS node

FROM rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0
COPY --from=node /usr/local/bin/node /usr/local/bin/node
