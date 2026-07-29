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
# The toolchain tree is left group/world-writable on purpose: the sandbox runs as the UNPRIVILEGED
# invoking uid:gid (never the image's root), and a target that pins its toolchain via
# rust-toolchain.toml must still be able to materialize that pin at gate time — that is gate
# SEMANTICS, not a convenience, and it is why the sandbox does not use `--read-only` for its root
# filesystem. Nothing sensitive lives in the container layer, and `--rm` disposes of it.
#
# The base image is digest-pinned, and worker-live.sh's `_assert_dockerfile_pinned` enforces that on
# every touched container definition: a mutable tag here would let a benign-looking PR repoint the
# gate sandbox at an attacker-controlled image. Keep it identical to containers/worker-model.Dockerfile
# so the model sandbox and the gate sandbox share one reviewed, cached base layer.
FROM rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0
RUN rustup component add clippy rustfmt \
 && cargo clippy --version \
 && cargo fmt --version \
 && chmod -R a+w "$RUSTUP_HOME"
