#!/usr/bin/env python3
"""Shared cron expansion and derived workflow schedule map.

[SPARQ agent] This module is the single owner of registry cron-minute derivation.
"""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

try:
    import yaml
except ImportError as _exc:  # pragma: no cover - fail loud rather than omit lanes
    yaml = None
    _YAML_IMPORT_ERROR = _exc


WORKFLOWS_DIR = ".github/workflows"

# A floor on the evidence, not a copy of the map. It detects a thin checkout or broken parse
# that would make a consumer's collision assertion vacuously green.
MIN_SCHEDULED_LANES = 10


class CronMapError(RuntimeError):
    """The workflow tree cannot be converted into a trustworthy schedule map."""


class CronError(ValueError):
    """A cron expression cannot be expanded without guessing."""


def expand_field(spec: str, lo: int, hi: int) -> set[int]:
    """Expand one cron field to the set of values it matches.

    OUT OF RANGE IS A REFUSAL, NOT A FILTER (#1279). This used to expand every atom and then
    drop whatever fell outside `lo..hi`, which reads as fail-closed and is not: it only ever
    raises when the WHOLE field is out of range, so `3,13,23,33,43,53,60` — the dispatch
    schedule plus one impossible minute — came back as exactly the six valid minutes. A caller
    asking "how many times an hour does this fire" then gets a truthful-looking six for a cron
    that GitHub will not run at all, and every count it derives is green on a broken schedule.
    Rejecting the atom (and each range ENDPOINT) instead means a malformed field can never be
    silently rounded down to a plausible one.

    The emptiness refusal below is DEAD under this grammar once the range check is in place —
    an accepted part has `a <= b` and `step >= 1`, so it contributes at least `a` — and it is
    kept anyway, declared unreachable, as the structural backstop for a future term form that
    does not hold that property. It is a refusal, so the honest thing is to say it cannot
    execute rather than to leave an empty set reaching a consumer that reads it as "fires
    never".
    """
    if not spec:
        raise CronError("empty field")
    out: set[int] = set()
    for item in spec.split(","):
        if not item:
            raise CronError(f"empty list element in {spec!r}")
        part = item
        step = 1
        if "/" in part:
            part, raw = part.split("/", 1)
            if not raw.isdigit():
                raise CronError(f"bad step in {spec!r}")
            step = int(raw)
            if step <= 0:
                raise CronError(f"non-positive step in {spec!r}")
        if part in ("*", "?"):
            start, end = lo, hi
        elif "-" in part:
            lhs, rhs = part.split("-", 1)
            if not (lhs.isdigit() and rhs.isdigit()):
                raise CronError(f"bad range in {spec!r}")
            start, end = int(lhs), int(rhs)
            if start > end:
                raise CronError(f"inverted range in {spec!r}")
        else:
            if not part.isdigit():
                raise CronError(f"not a number: {part!r}")
            start = end = int(part)
        if start < lo or end > hi:
            raise CronError(f"value outside {lo}-{hi} in {spec!r}")
        out.update(range(start, end + 1, step))
    if not out:  # unreachable under the grammar above - see the docstring
        raise CronError(f"field matches nothing: {spec!r}")
    return out


def cron_minutes(expr: str) -> set[int]:
    """The minutes past the hour `expr` can fire at. THE definition of that expansion (#1046).

    Hour/day/month restrictions are deliberately IGNORED, and that is the fail-closed
    direction for the one question this answers — *is this minute already taken?*
    `41 6 * * 1` (pat-validity, weekly) therefore still holds :41. Over-reporting a taken
    minute costs a schedule author one alternative; under-reporting it hands them a collision.
    """
    if not isinstance(expr, str):
        raise CronError(f"not a string: {expr!r}")
    fields = expr.split()
    if len(fields) != 5:
        raise CronError(f"expected 5 fields, got {len(fields)}: {expr!r}")
    return expand_field(fields[0], 0, 59)


def workflow_triggers(text: str) -> dict:
    """Return the parsed `on:` mapping; YAML 1.1 parses the key as boolean true."""
    if yaml is None:  # pragma: no cover
        raise CronMapError(f"PyYAML unavailable: {_YAML_IMPORT_ERROR}")
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise CronMapError(f"unparseable workflow YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise CronMapError("workflow YAML is not a mapping")
    triggers = doc.get(True, doc.get("on"))
    return triggers if isinstance(triggers, dict) else {}


def workflow_crons(triggers: dict) -> list[str]:
    """Return string cron declarations from a parsed workflow trigger mapping."""
    schedule = triggers.get("schedule") or []
    return [entry.get("cron") for entry in schedule
            if isinstance(entry, dict) and isinstance(entry.get("cron"), str)]


def _workflow_crons(path: Path) -> list[str]:
    try:
        return workflow_crons(workflow_triggers(path.read_text(encoding="utf-8")))
    except CronMapError as exc:
        raise CronMapError(f"{exc} at {path}") from exc


def schedule_minute_map(root) -> dict[str, set[int]]:
    """THE registry cron-minute map — which minute is taken by which workflow — DERIVED (#1046).

    Before this existed the map was hand-copied into five places, and one copy was already
    stale: `regate-sweep` asserted :00/:15/:30/:45 was dashboard's after dashboard had moved,
    which would have walked the next schedule author straight into a collision. That is the
    #958 shape (one literal, N definitions, consumers blind to a repoint) applied to a
    schedule. A consumer that needs the map READS THE TREE through this function; prose that
    names other lanes' minutes is a copy waiting to go stale.

    -> {".github/workflows/<name>.yml": {minutes}} for every workflow carrying a schedule.
    FAIL CLOSED in both directions a caller could be misled by: a missing workflows directory
    raises, and an unparseable cron raises rather than dropping the lane from the map. A lane
    silently absent from this map reads to a collision check as a free minute.
    """
    workflow_dir = Path(root) / WORKFLOWS_DIR
    if not workflow_dir.is_dir():
        raise CronMapError(f"no workflows directory at {workflow_dir}")
    result: dict[str, set[int]] = {}
    paths = sorted(workflow_dir.glob("*.yml")) + sorted(workflow_dir.glob("*.yaml"))
    for path in paths:
        crons = _workflow_crons(path)
        if not crons:
            continue
        minutes: set[int] = set()
        for expression in crons:
            minutes.update(cron_minutes(expression))
        result[f"{WORKFLOWS_DIR}/{path.name}"] = minutes
    return result


def _self_test() -> int:
    failures: list[str] = []

    def check(name, got, want):
        if got != want:
            failures.append(f"{name}: {got!r} (want {want!r})")

    def raises(error, thunk):
        try:
            thunk()
        except error:
            return True
        except Exception:
            return False
        return False

    check("step starts at range start", cron_minutes("7-59/15 * * * *"), {7, 22, 37, 52})
    check("weekly cron still holds its minute", cron_minutes("41 6 * * 1"), {41})
    check("refusal probe has both polarities",
          (raises(CronError, lambda: cron_minutes("3,60 * * * *")),
           raises(CronError, lambda: cron_minutes("3 * * * *"))), (True, False))
    check("wrong field count refuses", raises(CronError, lambda: cron_minutes("3 * * *")), True)
    invalid = (None, "  * * * *", ",3 * * * *", "*/x * * * *", "*/0 * * * *",
               "x-y * * * *", "9-3 * * * *", "x * * * *")
    check("malformed minute forms all refuse with CronError",
          [raises(CronError, lambda value=value: cron_minutes(value)) for value in invalid],
          [True] * len(invalid))
    check("wildcard and range forms expand",
          (cron_minutes("*/20 * * * *"), cron_minutes("5-8 * * * *")),
          ({0, 20, 40}, {5, 6, 7, 8}))
    triggers = workflow_triggers(
        "on:\n  schedule:\n    - cron: '11 * * * *'\n    - ignored: true\n  push: {}\n")
    check("shared trigger parser accepts mapping and cron extractor filters entries",
          (sorted(triggers), workflow_crons(triggers)), (["push", "schedule"], ["11 * * * *"]))
    check("shared trigger parser rejects malformed YAML and non-mapping documents",
          (raises(CronMapError, lambda: workflow_triggers("on: [\n")),
           raises(CronMapError, lambda: workflow_triggers("- not-a-workflow\n"))),
          (True, True))
    check("shared trigger parser treats non-mapping on as no triggers",
          workflow_triggers("on: [push]\n"), {})

    with tempfile.TemporaryDirectory() as tmp:
        workflow_dir = Path(tmp) / WORKFLOWS_DIR
        workflow_dir.mkdir(parents=True)
        (workflow_dir / "a.yml").write_text(
            "on:\n  schedule:\n    - cron: '4,24,44 * * * *'\n    - cron: '7 1 * * *'\n",
            encoding="utf-8")
        (workflow_dir / "push.yml").write_text("on: [push]\n", encoding="utf-8")
        check("scheduled lanes mapped and cron minutes unioned", schedule_minute_map(tmp),
              {f"{WORKFLOWS_DIR}/a.yml": {4, 7, 24, 44}})
        (workflow_dir / "bad.yml").write_text(
            "on:\n  schedule:\n    - cron: '3,60 * * * *'\n", encoding="utf-8")
        check("malformed lane refuses instead of disappearing",
              raises(CronError, lambda: schedule_minute_map(tmp)), True)
        (workflow_dir / "bad.yml").write_text("on: [\n", encoding="utf-8")
        check("malformed YAML refuses instead of disappearing",
              raises(CronMapError, lambda: schedule_minute_map(tmp)), True)
        (workflow_dir / "bad.yml").write_text("- not-a-workflow\n", encoding="utf-8")
        check("non-mapping workflow refuses instead of disappearing",
              raises(CronMapError, lambda: schedule_minute_map(tmp)), True)
    check("missing workflow tree refuses instead of returning an empty map",
          raises(CronMapError, lambda: schedule_minute_map(tmp)), True)

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        print(f"cron_map self-test: {len(failures)} failure(s)")
        return 1
    print("cron_map self-test: all checks passed")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    parser.error("only --self-test is supported")


if __name__ == "__main__":
    raise SystemExit(main())
