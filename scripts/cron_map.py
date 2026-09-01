#!/usr/bin/env python3
"""THE registry cron map — which minute past the hour is taken by which workflow lane.

🤖 SPARQ agent. Extracted from `ci-latency-alert.py` (#1280); the expansion and the map are
unchanged from what #1046 and #1279 built there.

WHY THIS IS ITS OWN MODULE. #1046 put the expansion inside the CI-latency watchdog because that
script already globbed every workflow and already carried a 5-field cron expander, so hosting it
there produced ONE definition for the smallest change. Then two more consumers appeared —
`regate-sweep.py`'s collision assertion and `dispatch-tick-floor.py`'s per-hour budget invariant —
and each had to import a 3000-line watchdog to ask one question, and each had to add that watchdog
to its job's sparse-checkout. This repo's convention for shared logic is a small snake_case module
with its own `--self-test` (`gh_retry.py`, `ledger_retry.py`, `park_policy.py`, `lease_schema.py`,
`run_name_grammar.py`); this is that module. A consumer now checks out one small file.

WHAT LIVES HERE, and what deliberately does not. This module owns the question *which minutes does
this tree's cron schedule claim* — field expansion, the minute set of one expression, and the
per-lane map derived from the workflow directory. It does NOT own `expected_firings` (how many
times does this cron fire in a window), which is the CI-latency watchdog's own detection variable
and needs all five fields plus a calendar walk; that stays in `ci-latency-alert.py` and imports
`_expand_field` from here, so there is still exactly one expander.

FAIL CLOSED, in both directions a caller can be misled by:
  * an unreadable cron RAISES (`CronError`) rather than expanding to the empty set — an empty set
    reads to a collision check as "claims no minute" and to a rate invariant as "fires never",
    and both are vacuously green;
  * an out-of-range atom is a REFUSAL, not a filter (#1279) — see `_expand_field`;
  * a missing/unparseable workflow tree RAISES (`CronMapError`) rather than returning a partial
    map — a lane silently absent from the map reads as a FREE minute.

Usage:
  cron_map.py --self-test          # the only standalone mode; this is an import-first helper
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import yaml
except ImportError as _exc:  # pragma: no cover - fail loud rather than derive a partial map
    yaml = None
    _YAML_IMPORT_ERROR = _exc

# Where the lanes live. Written HERE, and every consumer cross-checks its own copy against this
# one by name, so a repoint cannot leave a consumer reading an empty directory.
WORKFLOWS_DIR = ".github/workflows"

# A FLOOR ON THE EVIDENCE, not a copy of the map: this repo carries 13+ scheduled lanes today, and
# the failure this guards is a map derived from a thin checkout or a broken parse, which yields
# 0-1 lanes and makes every collision assertion built on it vacuously green. A floor survives
# retiring a lane; it does not survive the derivation reading nothing.
MIN_SCHEDULED_LANES = 10


class CronError(ValueError):
    """An unparseable cron. Fail-safe QUIET, but COUNTED in the census."""


class CronMapError(RuntimeError):
    """The DERIVATION itself is broken — no tree, no parser, no mapping. Never mask it."""


# ---------------------------------------------------------------------------------
# cron expansion
# ---------------------------------------------------------------------------------
def _expand_field(spec: str, lo: int, hi: int) -> set[int]:
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
    does not hold that property (the same call dashboard-gen.py's own expander makes for the
    same reason). It is a refusal, so the honest thing is to say it cannot execute rather than
    to delete it and leave an empty set reaching a consumer that reads it as "fires never".
    """
    if not spec:
        raise CronError("empty field")
    out: set[int] = set()
    for part in spec.split(","):
        if not part:
            raise CronError(f"empty list element in {spec!r}")
        step = 1
        if "/" in part:
            part, raw = part.split("/", 1)
            if not raw.isdigit():
                raise CronError(f"bad step in {spec!r}")
            step = int(raw)
            if step <= 0:
                raise CronError(f"non-positive step in {spec!r}")
        if part in ("*", "?"):
            a, b = lo, hi
        elif "-" in part:
            lhs, rhs = part.split("-", 1)
            if not (lhs.isdigit() and rhs.isdigit()):
                raise CronError(f"bad range in {spec!r}")
            a, b = int(lhs), int(rhs)
            if a > b:
                raise CronError(f"inverted range in {spec!r}")
        else:
            if not part.isdigit():
                raise CronError(f"not a number: {part!r}")
            a = b = int(part)
        if a < lo or b > hi:
            raise CronError(f"value outside {lo}-{hi} in {spec!r}")
        out |= set(range(a, b + 1, step))
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
    return _expand_field(fields[0], 0, 59)


# ---------------------------------------------------------------------------------
# the tree
# ---------------------------------------------------------------------------------
def workflow_triggers(text: str) -> dict:
    """-> the parsed `on:` mapping. `on` is YAML 1.1 `true`, hence the two-key lookup.

    Raises `CronMapError` rather than returning {} for a document this cannot read: {} is what
    an unscheduled workflow returns, so collapsing a parse failure into it would drop a lane
    from the map and hand a collision check a minute it cannot see is taken.
    """
    if yaml is None:  # pragma: no cover
        raise CronMapError(f"PyYAML unavailable: {_YAML_IMPORT_ERROR}")
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise CronMapError(f"unparseable workflow YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise CronMapError("workflow YAML is not a mapping")
    on = doc.get(True, doc.get("on"))
    return on if isinstance(on, dict) else {}


def schedule_crons(on: dict) -> list[str]:
    """-> the cron expressions this `on:` mapping declares, in declaration order.

    [] for a lane that declares no schedule. A `schedule:` entry that is not a mapping, or whose
    `cron` is not a string, is skipped HERE rather than raising: it is not a cron this repo can
    read, and GitHub will not run it either — the callers that need "this lane declared something
    unreadable" to be loud get that from `cron_minutes` refusing the expression itself.

    The per-entry filter is also what makes a `schedule:` that is not a LIST at all come back
    empty: iterating a bare string yields characters and iterating a mapping yields keys, and
    neither is a mapping carrying a string `cron`. A separate not-a-list guard above it was
    tried and removed — it could not be killed by any input, because the filter already
    answers every case it would have (AGENTS.md pre-flight item 4, equivalent survivor).
    """
    return [entry["cron"] for entry in (on.get("schedule") or [])
            if isinstance(entry, dict) and isinstance(entry.get("cron"), str)]


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
    wf_dir = Path(root) / WORKFLOWS_DIR
    if not wf_dir.is_dir():
        raise CronMapError(f"no workflows directory at {wf_dir}")
    out: dict[str, set[int]] = {}
    for path in sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml")):
        crons = schedule_crons(workflow_triggers(path.read_text(encoding="utf-8")))
        if not crons:
            continue
        minutes: set[int] = set()
        for expr in crons:
            minutes |= cron_minutes(expr)
        out[f"{WORKFLOWS_DIR}/{path.name}"] = minutes
    return out


# ---------------------------------------------------------------------------------
# self-test
# ---------------------------------------------------------------------------------
def _self_test() -> int:  # noqa: C901 - a flat table of named assertions reads best flat
    import tempfile

    failures: list[str] = []

    def chk(name, cond):
        if not cond:
            failures.append(name)

    def _raises(exc_type, thunk):
        """Did `thunk` raise EXACTLY this class? A different exception is not this refusal."""
        try:
            thunk()
        except exc_type:
            return True
        except Exception:  # noqa: BLE001 - the point is that the wrong error is not a pass
            return False
        return False

    # THE PROBE ITSELF, first: every refusal row below reads `_raises(...) is True`, so a probe
    # that could only ever answer True would satisfy all of them while proving nothing.
    chk("the refusal probe answers False for a call that does not raise, and False for a call "
        "that raises something else — it can say no",
        (_raises(CronError, lambda: cron_minutes("3 * * * *")),
         _raises(CronError, lambda: 1 / 0)) == (False, False))

    # --- cron_minutes. Every expected value is hand-computed; writing it as `_expand_field(...)`
    # would read the expectation out of the code under test (AGENTS.md pre-flight 2b). ---
    chk("cron_minutes */15 -> :00/:15/:30/:45", cron_minutes("*/15 * * * *") == {0, 15, 30, 45})
    chk("cron_minutes 7-59/15 -> :07/:22/:37/:52 — a stepped RANGE does not restart at :00, "
        "and reading it as */15 is exactly how a hand-copied map lies about a taken minute",
        cron_minutes("7-59/15 * * * *") == {7, 22, 37, 52})
    chk("cron_minutes 3,13,23,33,43,53 -> the six explicit minutes",
        cron_minutes("3,13,23,33,43,53 * * * *") == {3, 13, 23, 33, 43, 53})
    chk("cron_minutes ignores the hour/day fields — a weekly 06:41 lane still HOLDS :41, "
        "because the question this answers is `is this minute taken`",
        cron_minutes("41 6 * * 1") == {41})
    chk("cron_minutes a range with no step expands to every minute in it",
        cron_minutes("5-8 * * * *") == {5, 6, 7, 8})

    # --- OUT OF RANGE IS REFUSED, NOT FILTERED (#1279) ---
    # A WHOLLY invalid field is caught even by a post-hoc filter, by emptying the set. The
    # fail-open case is the MIXED field, and it needs its own rows.
    chk("cron_minutes REFUSES a minute list that is valid except for one out-of-range atom — "
        "filtering :60 away would answer with the six real dispatch minutes and read as green",
        _raises(CronError, lambda: cron_minutes("3,13,23,33,43,53,60 * * * *")))
    chk("cron_minutes REFUSES a range whose END runs past :59 instead of truncating it to :59",
        _raises(CronError, lambda: cron_minutes("55-70 * * * *")))
    # ...and the refusal is about what cron cannot fire at, not about largeness: the boundary
    # values still expand, so a mutant that rejected the whole field would red here.
    chk("cron_minutes still accepts the boundary minutes :00 and :59",
        cron_minutes("0,59 * * * *") == {0, 59})
    for bad in ("", "* * * *", "* * * * * *", "60 * * * *", "*/0 * * * *", "5-1 * * * *",
                ", * * * *", "abc * * * *", "*/a * * * *", "1-b * * * *", 41, None):
        chk(f"cron_minutes {bad!r} raises CronError, and not some other error",
            _raises(CronError, lambda e=bad: cron_minutes(e)))
    # The EMPTY field, which no 5-field expression can present: `cron_minutes` splits on
    # whitespace, so "" arrives as a wrong FIELD COUNT and never reaches this guard. It is
    # reachable from any other caller passing a field straight through, and without a row here
    # deleting it leaves an empty spec falling through to `field matches nothing` — a different
    # message for a different defect.
    chk("_expand_field REFUSES an empty field outright, not by running out of values",
        _raises(CronError, lambda: _expand_field("", 0, 59)))

    # --- _expand_field: the BOUND IS PER FIELD, which cron_minutes alone cannot show. The only
    # bound it ever passes is 0-59, so a hard-coded :59 would satisfy every row above.
    # `expected_firings` (ci-latency-alert.py) is the consumer that passes the other four. ---
    chk("_expand_field REFUSES an HOUR list that is valid except for the impossible 24",
        _raises(CronError, lambda: _expand_field("1,24", 0, 23)))
    chk("...while the same hour list with 24 replaced by a real hour still expands (the hour "
        "bound refuses 24, it does not refuse lists)", _expand_field("1,23", 0, 23) == {1, 23})
    chk("_expand_field honours a NON-ZERO low bound too — day-of-month 0 does not exist",
        (_raises(CronError, lambda: _expand_field("0", 1, 31)),
         _expand_field("1,31", 1, 31)) == (True, {1, 31}))
    chk("_expand_field expands `*` to the whole band it was given, not to 0-59",
        _expand_field("*", 1, 12) == set(range(1, 13)))

    # --- workflow_triggers: `on` is YAML 1.1 `true`, and an unreadable document must RAISE
    # rather than collapse into the {} an UNSCHEDULED lane returns. ---
    chk("workflow_triggers reads the YAML-1.1 boolean `on:` key",
        workflow_triggers("on:\n  schedule:\n    - cron: '4 * * * *'\njobs: {}\n")
        == {"schedule": [{"cron": "4 * * * *"}]})
    chk("workflow_triggers reads a QUOTED `\"on\":` key as well",
        workflow_triggers('"on":\n  push:\njobs: {}\n') == {"push": None})
    chk("workflow_triggers returns {} for a workflow whose `on:` is not a mapping — that is "
        "'declares no schedule', which is a real answer",
        workflow_triggers("on: push\njobs: {}\n") == {})
    chk("workflow_triggers RAISES on unparseable YAML rather than reading it as unscheduled — "
        "a lane dropped from the map reads to a collision check as a FREE minute",
        _raises(CronMapError, lambda: workflow_triggers("on: [\njobs:\n")))
    chk("workflow_triggers RAISES on a document that is not a mapping at all",
        _raises(CronMapError, lambda: workflow_triggers("- just\n- a list\n")))

    # --- schedule_crons ---
    chk("schedule_crons returns every cron a lane declares, in order",
        schedule_crons({"schedule": [{"cron": "1 * * * *"}, {"cron": "2 * * * *"}]})
        == ["1 * * * *", "2 * * * *"])
    chk("schedule_crons returns [] for a lane with no schedule at all",
        schedule_crons({"push": None}) == [])
    chk("schedule_crons returns [] for an EMPTY or null schedule key",
        (schedule_crons({"schedule": None}), schedule_crons({"schedule": []})) == ([], []))
    chk("schedule_crons skips a malformed schedule entry rather than crashing the whole map",
        schedule_crons({"schedule": ["3 * * * *", {"cron": 7}, {"cron": "3 * * * *"}]})
        == ["3 * * * *"])
    chk("schedule_crons returns [] for a `schedule:` that is not a LIST at all — iterating a "
        "bare string would hand the map one cron per CHARACTER",
        schedule_crons({"schedule": "3 * * * *"}) == [])

    # --- schedule_minute_map on a HERMETIC tree. The live-tree rows below can only exercise the
    # POSITIVE direction (this repo has no malformed cron and no missing workflows directory),
    # and the whole fail-closed claim lives in the negative one. ---
    with tempfile.TemporaryDirectory() as _tmp:
        _wf = Path(_tmp) / WORKFLOWS_DIR
        _wf.mkdir(parents=True)
        (_wf / "a.yml").write_text("on:\n  schedule:\n    - cron: '4,24,44 * * * *'\njobs: {}\n")
        (_wf / "b.yml").write_text("on:\n  schedule:\n    - cron: '*/15 * * * *'\n"
                                   "    - cron: '7 1 * * *'\njobs: {}\n")
        (_wf / "c.yml").write_text("on:\n  push:\njobs: {}\n")
        chk("schedule map: one entry per SCHEDULED lane, minutes UNIONED across that lane's "
            "crons, unscheduled lanes absent",
            schedule_minute_map(_tmp) == {f"{WORKFLOWS_DIR}/a.yml": {4, 24, 44},
                                          f"{WORKFLOWS_DIR}/b.yml": {0, 7, 15, 30, 45}})
        (_wf / "d.yml").write_text("on:\n  schedule:\n    - cron: 'every 5 min'\njobs: {}\n")
        chk("schedule map: an UNPARSEABLE cron RAISES — dropping that lane would hand a "
            "collision check a minute it cannot see is taken",
            _raises(CronError, lambda: schedule_minute_map(_tmp)))
        (_wf / "d.yml").unlink()
        (_wf / "e.yml").write_text("on: [\njobs:\n")
        chk("schedule map: an UNPARSEABLE workflow RAISES too — the lane whose YAML broke is "
            "exactly the one whose minute nobody can see",
            _raises(CronMapError, lambda: schedule_minute_map(_tmp)))
    # The directory is gone with the context manager: an absent tree must not read as "no lane
    # is scheduled", which is a clean bill from every consumer of this map.
    chk("schedule map: a MISSING workflows directory raises rather than returning {}",
        _raises(CronMapError, lambda: schedule_minute_map(_tmp)))

    # --- MIN_SCHEDULED_LANES. Same trap as the map itself: a floor of 0 or 1 has no teeth,
    # because the case it exists to catch is a sparse checkout yielding exactly the ONE lane its
    # consumer already knows about. Bounded above by the lanes this repo actually carries, so it
    # cannot be raised into a permanent red either. ---
    chk("MIN_SCHEDULED_LANES is a floor with teeth (strictly above the one-lane thin checkout) "
        "and stays reachable by this repo's real lane count", 2 <= MIN_SCHEDULED_LANES <= 13)

    # --- THE LIVE TREE. A map is only worth reading if it saw every scheduled lane, so the YAML
    # derivation is cross-checked against an INDEPENDENT raw-text oracle — two unrelated readings
    # of the tree must agree on the lane SET. (Pinning the MINUTES here instead would re-create
    # the very hand-copy this module exists to delete; pinning them from the map would be the
    # tautology AGENTS.md pre-flight 2b names.) ---
    root = Path(__file__).resolve().parents[1]
    wf_dir = root / WORKFLOWS_DIR
    if not wf_dir.is_dir():
        chk(f"live tree: {WORKFLOWS_DIR} is checked out (without it every row below is "
            "unreachable, which is worse than failing here)", False)
    else:
        import re

        _map = schedule_minute_map(root)
        _textual = {f"{WORKFLOWS_DIR}/{p.name}"
                    for p in sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml"))
                    if re.search(r"^\s*-\s+cron:", p.read_text(encoding="utf-8"), re.M)}
        chk(f"live tree: the schedule map covers every lane a raw `- cron:` scan finds "
            f"(yaml-derived {sorted(_map)} vs text-derived {sorted(_textual)})",
            set(_map) == _textual)
        chk(f"live tree: the map clears the evidence floor of {MIN_SCHEDULED_LANES} lanes "
            f"(saw {len(_map)}) — a thin checkout or a broken parse yields one lane or none, "
            "and a collision check built on an empty map is vacuously green",
            len(_map) >= MIN_SCHEDULED_LANES)
        chk("live tree: every lane in the schedule map holds at least one minute",
            all(minutes for minutes in _map.values()))
        # Enrolled in the suite the gate actually runs, so this module cannot silently leave CI.
        suite = (root / "scripts" / "selftest-suite.txt").read_text(encoding="utf-8").split()
        chk("live tree: enrolled in scripts/selftest-suite.txt", "cron_map.py" in suite)

    # THE ENTRY POINT. `main` with no mode must REFUSE, not fall through to a zero exit: the
    # suite runner reads the exit status, and a helper that exits 0 on an unrecognised
    # invocation would report a pass for a run that asserted nothing. argparse writes the
    # refusal to stderr, which is CAPTURED here — an `error:` line in a passing gate log reads
    # as a failure to every human and half the log scrapers.
    import contextlib
    import io

    _stderr = io.StringIO()
    try:
        with contextlib.redirect_stderr(_stderr):
            main([])
        chk("main() with no --self-test REFUSES rather than exiting 0", False)
    except SystemExit as exc:
        chk("main() with no --self-test refuses with a NON-ZERO exit, naming this module as "
            "import-first", (exc.code not in (0, None),
                             "import-first" in _stderr.getvalue()) == (True, True))

    if failures:
        for name in failures:
            print(f"FAIL: {name}")
        print(f"::error::cron_map self-test: {len(failures)} failure(s)")
        return 1
    print("cron_map self-test: all checks passed")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    parser.error("cron_map.py is an import-first helper module; only --self-test runs standalone")
    return 2


if __name__ == "__main__":
    sys.exit(main())
