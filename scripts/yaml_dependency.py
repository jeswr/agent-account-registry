#!/usr/bin/env python3
"""Actionable, fail-closed loading of the workflow-seam YAML parser.

[SPARQ agent] PyYAML is deliberately a lazy dependency for many registry self-tests.  Keeping the
failure shape here makes a bare container say what the dependency is for and how to install it.
"""

import importlib


class PyYAMLUnavailable(RuntimeError):
    """The workflow seam cannot be measured because PyYAML is unavailable."""


def require_yaml(role="workflow YAML", importer=importlib.import_module):
    """Return the PyYAML module or raise an actionable, fail-closed error."""
    try:
        return importer("yaml")
    except ModuleNotFoundError as exc:
        if exc.name != "yaml":
            raise
        raise PyYAMLUnavailable(
            f"PyYAML is required to parse {role}, but it is not installed ({exc}). "
            "Install it with `python3 -m pip install pyyaml`; the registry CI installs a "
            "version-and-hash-locked copy before running workflow-seam self-tests."
        ) from None


def self_test():
    rows = []

    sentinel = object()
    rows.append(("available module is returned", require_yaml(importer=lambda name: sentinel)
                 is sentinel))

    def missing(name):
        raise ModuleNotFoundError("No module named 'yaml'", name="yaml")

    try:
        require_yaml("the mint workflow seam", importer=missing)
        missing_result = "no refusal"
    except PyYAMLUnavailable as exc:
        missing_result = str(exc)
    rows.append(("missing PyYAML names dependency, role, and install command",
                 "PyYAML" in missing_result
                 and "mint workflow seam" in missing_result
                 and "python3 -m pip install pyyaml" in missing_result))

    def nested_missing(name):
        raise ModuleNotFoundError("No module named 'yaml._broken'", name="yaml._broken")

    try:
        require_yaml(importer=nested_missing)
        nested_result = "wrongly swallowed"
    except ModuleNotFoundError as exc:
        nested_result = exc.name
    rows.append(("a broken installed package is not mislabeled as absent", nested_result ==
                 "yaml._broken"))

    failed = False
    for name, ok in rows:
        print(("ok" if ok else "FAIL") + f": {name}")
        failed |= not ok
    return 1 if failed else 0


if __name__ == "__main__":
    import sys
    if "--self-test" in sys.argv and sys.argv[1:] == ["--self-test"]:
        raise SystemExit(self_test())
    raise SystemExit("usage: yaml_dependency.py --self-test")
