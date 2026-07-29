# [OPUS-5 #242] REG-3 POLICY-GATE sandbox — the containment boundary for target-controlled code.
#
# `cargo clippy` / `cargo test` execute the TARGET repository's OWN build scripts and tests: arbitrary
# target-controlled code that the model, which has just written it, can steer. Until now that ran
# unsandboxed as the runner user, with read access to the whole runner checkout (including the sibling
# registry checkout holding the mutable publisher script) and to the runner temp tree that carries the
# account credential and the sealed publish bundle. Purging those trees and CONTENT-SCANNING the
# target's changes for token shapes is a tripwire, not containment — a steered model can base64/split/
# compress a credential into the writable target tree and walk straight past a pattern scan. The
# enforceable boundary is this image plus the `docker run` argv `_gate_sandbox_args` builds in
# scripts/worker-live.sh: only the target checkout and a scratch cache are mounted, no host
# environment is inherited, and there is no credential inside the sandbox to take in the first place.
#
# TOOLCHAIN PROVISIONING MOVES IN HERE. This image replaces the runner-side "Ensure a Rust toolchain
# for the crate-scoped gate" step in .github/workflows/worker.yml (which ran `rustup default stable`
# + `rustup component add` on the host). The official rust image installs the `minimal` rustup
# profile, which ships NEITHER clippy NOR rustfmt — the two components every cargo gate profile is
# built on — so they are added at build time here, pinned to the base image's toolchain.
#
# WHAT THIS BUILD CANNOT DO, and where the rest of it lives. These components are added to the ONE
# toolchain that exists at build time (the base image's). A target that pins another channel through
# rust-toolchain.toml selects a toolchain that does not exist yet, which rustup then installs with
# this image's `minimal` profile — so `cargo fmt` / `cargo clippy` would be missing for exactly the
# toolchain the gate is about to use, and all three cargo profiles invoke one or both. The build
# context here is deliberately EMPTY (no target tree, no pin to read), so the pinned toolchain and
# its components are provisioned at gate time instead, inside this sandbox, by worker-live.sh's
# `_gate_sandbox_prepare` — before any target-controlled command runs, and with no host fallback.
#
# That provisioning has to SURVIVE the container: every gate command is its own `docker run --rm`, so
# anything written to /usr/local/rustup is discarded and the next command would re-install from
# scratch. `_gate_sandbox_args` therefore points RUSTUP_HOME at the mounted scratch cache, seeded
# once from the tree below. That is also why this image no longer chmods the toolchain tree writable:
# pins now materialize in the mount, and nothing in the container layer needs to be written at all.
# The sandbox still does not pass `--read-only` for its root filesystem (cargo and rustup touch
# assorted paths outside the mounts), but nothing in that layer is load-bearing and `--rm` disposes
# of it; the sandbox runs as the UNPRIVILEGED invoking uid:gid, never as the image's root.
#
# The base image is digest-pinned, and worker-live.sh's `_assert_dockerfile_pinned` enforces that on
# every touched container definition: a mutable tag here would let a benign-looking PR repoint the
# gate sandbox at an attacker-controlled image. Keep it identical to containers/worker-model.Dockerfile
# so the model sandbox and the gate sandbox share one reviewed, cached base layer.
FROM rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0
RUN rustup component add clippy rustfmt \
 && cargo clippy --version \
 && cargo fmt --version
