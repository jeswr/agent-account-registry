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


def _expand_field(spec: str, lo: int, hi: int) -> set[int]:
    """Expand one cron field, refusing every malformed or out-of-range atom."""
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
    if not out:  # structural backstop for future grammar forms
        raise CronError(f"field matches nothing: {spec!r}")
    return out


def cron_minutes(expr: str) -> set[int]:
    """Return every minute past the hour held by a five-field cron expression."""
    if not isinstance(expr, str):
        raise CronError(f"not a string: {expr!r}")
    fields = expr.split()
    if len(fields) != 5:
        raise CronError(f"expected 5 fields, got {len(fields)}: {expr!r}")
    return _expand_field(fields[0], 0, 59)


def _workflow_crons(path: Path) -> list[str]:
    if yaml is None:  # pragma: no cover
        raise CronMapError(f"PyYAML unavailable: {_YAML_IMPORT_ERROR}")
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise CronMapError(f"unparseable workflow YAML at {path}: {exc}") from exc
    if not isinstance(doc, dict):
        raise CronMapError(f"workflow YAML is not a mapping: {path}")
    triggers = doc.get(True, doc.get("on"))
    if not isinstance(triggers, dict) or "schedule" not in triggers:
        return []
    schedule = triggers.get("schedule") or []
    return [entry.get("cron") for entry in schedule
            if isinstance(entry, dict) and isinstance(entry.get("cron"), str)]


def schedule_minute_map(root) -> dict[str, set[int]]:
    """Derive ``{workflow path: held minutes}`` from every scheduled workflow."""
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
