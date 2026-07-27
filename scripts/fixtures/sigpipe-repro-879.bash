#!/usr/bin/env bash
# QUARANTINED reproducer for registry issue #879. Run only by worker-live.sh's self-test.
#
# `produce` emits a needle and then ~4 MiB of tail — 64x the 64 KiB pipe buffer — from a SINGLE
# process. Both properties are load-bearing:
#
#   * SIZE. Under one stdio flush the producer hands over everything and exits before the consumer
#     can act, so nothing is signalled. Above the pipe buffer the producer MUST block on a write,
#     which means the consumer MUST already have been scheduled, matched and exited: the SIGPIPE is
#     forced, not merely permitted. MEASURED, single-process producer: 0/60 inversions at 16 lines,
#     60/60 at 65536. Shrink the loop and worker-live.sh's first assertion goes red — that is what
#     makes the size an assertion rather than a decoration.
#
#   * ONE process. An earlier draft of this fixture used `printf; awk` — two sequential writers —
#     and inverted 53/60 even at 16 lines, because the consumer can exit in the gap BETWEEN them.
#     That version passed the "large enough" assertion on a 1 KiB input, i.e. it was satisfied by a
#     weaker input and proved nothing about size. A mutation run caught it; do not reintroduce a
#     second writer here.
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

produce() { awk -v n="$1" 'BEGIN { print n; l = sprintf("%063d", 0); for (i = 0; i < 65536; i++) print l }'; }

case "${1:?usage: sigpipe-repro-879.bash <produce|probe> <needle>}" in
  produce) produce "${2:?needle}" ;;
  probe)   produce "${2:?needle}" | grep -Fq "${2}"; printf '%s' "$?" ;;
  *)       printf 'unknown mode: %s\n' "$1" >&2; exit 2 ;;
esac
