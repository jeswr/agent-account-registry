# [SPARQ agent] REG-3 model sandbox: pinned Node runtime for the routed CLIs plus the target's Rust
# toolchain/generic build utilities. The live script bind-mounts the CLI and target; no secrets are
# baked into this image.
FROM node:20.19.4-bookworm-slim@sha256:6db5e436948af8f0244488a1f658c2c8e55a3ae51ca2e1686ed042be8f25f70a AS node

FROM rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0
COPY --from=node /usr/local/bin/node /usr/local/bin/node

# [issue #1342] The offline `--self-test` suites AGENTS.md requires the AUTHOR to keep green — and
# to run mutation experiments against — execute INSIDE this sandbox, and they shell out to jq and
# import PyYAML. `SELFTEST_ENV_REQUIREMENTS` in scripts/worker-live.sh is the ONE list of those
# dependencies; `_assert_dockerfile_provisions_selftest_deps` re-reads that list and fails the gate
# closed if this stanza stops proving any row of it, so the two cannot drift.
# Before this the image carried only node on top of rust, so e.g. dashboard-gen.py's suite could
# only report its jq dependency as a NAMED red row no author could clear from in here, and the only
# workaround was an author-invented `jq` stub on PATH — a home-made measurement instrument that
# reddens 16 unrelated rows, which is exactly what the pre-flight warns against.
# The probes on the last two lines are load-bearing, not decoration: an apt resolution that stops
# shipping one of these must break the BUILD, rather than leave a sandbox that is quietly missing a
# tool and an author measuring a truncated suite.
RUN set -eux; \
    apt-get update; \
    apt-get install --no-install-recommends --yes jq python3 python3-yaml; \
    rm -rf /var/lib/apt/lists/*; \
    jq --version; \
    python3 -c 'import yaml'
