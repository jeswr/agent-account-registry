# [SPARQ agent] REG-3 model sandbox: pinned Node runtime for the routed CLIs plus the target's Rust
# toolchain/generic build utilities. The live script bind-mounts the CLI and target; no secrets are
# baked into this image.
FROM node:20.19.4-bookworm-slim@sha256:6db5e436948af8f0244488a1f658c2c8e55a3ae51ca2e1686ed042be8f25f70a AS node

FROM rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0
COPY --from=node /usr/local/bin/node /usr/local/bin/node

# [issue #1507] The self-test toolchain an AUTHOR needs to satisfy AGENTS.md's pre-flight from
# INSIDE this container. worker-live.sh's SELFTEST_ENV_REQUIREMENTS is the single declaration of
# what the enrolled suite EXECUTES; `ubuntu-latest` ships both, so the gate never noticed that this
# image shipped neither. Measured on the pre-#1507 image: `dashboard-gen.py --self-test` printed 19
# red rows for purely environmental reasons (the #922 hermetic keepalive harness shells out to
# `jq`), and `metrics.py --self-test` ABORTED outright at its workflow-seam block. A noisy or
# unrunnable baseline is exactly what makes a real regression invisible to the author who is
# supposed to catch it.
#
# This ADDS the dependency; it does not relax the check that names it. #922's row stays fail-closed
# ("a missing dependency must be NAMED, never silently skipped into a green run"), and
# `_selftest_env_blocked` still refuses a host without these rather than reporting a partial suite
# as a pass.
#
# NOT version-pinned, deliberately, and that is a different call from pr-gate.yml's hash-locked
# `pyyaml==6.0.2`. These packages come from the digest-pinned base image's own Debian-signed
# archive, and NOTHING here decides a verdict: this container only runs the untrusted model, while
# every gate row is re-run host-side on `ubuntu-latest`. An exact `=<version>` pin would instead
# break every worker run the moment Debian point-releases either package out of the mirror, which
# is a strictly worse failure for a sandbox whose contents are not evidence. Stated the other way
# round, as #1575 put it: this trades byte-for-byte rebuilds for not breaking after a Debian
# point-release replacement.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends jq python3-yaml \
    && rm -rf /var/lib/apt/lists/*
