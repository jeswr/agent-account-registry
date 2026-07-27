#!/usr/bin/env bash
# QUARANTINED reproducer for registry issue #879. Run only by worker-live.sh's self-test.
#
# `produce` emits a needle and then ~4 MiB of tail — 64x the 64 KiB pipe buffer — written with real
# per-line work. At that size the producer MUST block on a write, which means the consumer MUST
# already have been scheduled, matched, and exited; the SIGPIPE is forced, not merely permitted.
# A small fixture lets the producer finish into the pipe buffer and the whole demonstration passes
# on the BROKEN shape too, which is the "assertion satisfied by a weaker input" trap this repo has
# been bitten by. The size is the assertion.
#
# `probe` runs THE BROKEN SHAPE (`producer | grep -Fq`) over that same stream and prints the
# pipeline's status. The needle is the FIRST line, so grep always matches; a non-zero status
# therefore means the assertion was INVERTED — a real match reported as no match — which is the
# whole defect. worker-live.sh asserts that inversion first, then asserts its own capture-then-test
# idiom reports the match on the identical stream.
#
# Deliberately NOT named `*.sh`: _sigpipe_shape_hits scans scripts/*.sh for exactly the pipeline on
# the `probe` line below, and a guard that has to exempt its own evidence is a guard with a bypass.
set -o pipefail

produce() { printf '%s\n' "$1"; awk 'BEGIN { l = sprintf("%063d", 0); for (i = 0; i < 65536; i++) print l }'; }

case "${1:?usage: sigpipe-repro-879.bash <produce|probe> <needle>}" in
  produce) produce "${2:?needle}" ;;
  probe)   produce "${2:?needle}" | grep -Fq "${2}"; printf '%s' "$?" ;;
  *)       printf 'unknown mode: %s\n' "$1" >&2; exit 2 ;;
esac
