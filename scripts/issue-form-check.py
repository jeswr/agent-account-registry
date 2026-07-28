#!/usr/bin/env python3
"""issue-form-check.py — schema-check every GitHub issue-form template, fail closed.

WHY THIS EXISTS (registry #855). The issue FORMS are part of the same trust surface as the
workflows that consume the issues they open (set-up-account.yml's broker, the account enrollment
lane), but pr-gate.yml's yaml-parse loop only ever swept `.github/workflows/`. So a YAML syntax
error — or a form GitHub itself rejects — merged green and surfaced only as a silently broken "New
issue" template, with no gate anywhere in between. scripts/grant-account.py's --self-test reads
set-up-account.yml as TEXT, so it catches shape regressions in the label contract but never
malformed YAML and never a structurally invalid element.

WHY IT IS A SCRIPT RATHER THAN INLINE WORKFLOW PYTHON (PR #893 review r1). A validator that
asserts "GitHub's render-time minimum" is only worth its claim if something proves it REJECTS the
forms GitHub rejects. Inline `run:` Python cannot host that proof — nothing executes it but the
gate itself, and the gate only ever feeds it forms that already pass. Here the rules live beside a
--self-test that drives a negative fixture through EVERY required shape, so a rule that stopped
rejecting goes red.

FAIL-CLOSED, THE THREE DIRECTIONS THAT MATTER:

  * SWEEPING ZERO FORMS IS A FAILURE. A rename, a deletion, or a bad directory must break this
    check loudly rather than turn it into a vacuous pass. The counter is over ACTUAL FORMS, not
    over files: `config.yml` is the issue-chooser config (blank_issues_enabled/contact_links), not
    a form, so it is parsed and then skipped — counting it would let a tree whose every real form
    was deleted or renamed report a green "1 template checked" (PR #893 review r1, finding 1).
  * AN UNPARSEABLE OR UNREADABLE FILE IS AN ERROR, never a skip. A template we cannot read is a
    template we cannot vouch for.
  * A MISSING REQUIRED FIELD IS AN ERROR, never a default. This never rewrites, normalizes or
    repairs a form; it only refuses.

WHAT "GITHUB'S MINIMUM" MEANS HERE (GitHub's documented form schema). Required top level: `name`,
`description`, non-empty `body`. Per element: a recognized `type`, an `attributes` mapping, and
that type's required attributes — `value` for `markdown`, `label` for every fillable type, plus
non-empty `options` for `dropdown` (distinct, non-empty strings) and for `checkboxes` (mappings
each carrying a non-empty `label`). A form whose every element is `markdown` collects nothing and
is rejected by GitHub, so it is rejected here.

`id` IS OPTIONAL IN GITHUB'S SCHEMA — deliberately not required here (raised again as PR #893
review r2, and declined again on the same grounds). GitHub's form-schema reference lists `id` as
OPTIONAL for `input`, `textarea`, `dropdown` and `checkboxes` alike — per element only `type` and
`attributes` are Required — because an `id` exists to be REFERENCED (template default values), not
to make a field valid. What the schema does mandate about `id` is its SYNTAX (alphanumerics plus
`-` and `_`) and its UNIQUENESS within a form, and both of those ARE enforced below. See
docs.github.com, "Syntax for GitHub's form schema". So requiring an `id` would refuse forms GitHub
renders fine — a stricter gate is not automatically a sounder one, and refusing valid input is
itself the bug. The self-test row asserting that a labelled field WITHOUT an id is accepted is what
holds that line; it is a rule, not an oversight. The markdown-specific exception: a `markdown`
element is decoration, not a field, so it carries no field id and takes part in neither rule.

USAGE
  python3 scripts/issue-form-check.py <template-directory>
  python3 scripts/issue-form-check.py --self-test
"""
import os
import pathlib
import sys
import tempfile


# Module level, unlike the lazy `import yaml` every other script here uses. Those import it only
# inside a --self-test, so the lazy shape keeps their PRODUCTION paths free of the dependency.
# Parsing YAML is this script's entire production job, so a lazy import would only relocate the
# same failure; PyYAML is already a hard suite dependency (resolve-conflicts.py) and pr-gate.yml
# installs it version- and hash-locked before anything here runs.
import yaml

# GitHub's issue-form element types. Every type except `markdown` is fillable, and a form with no
# fillable element collects nothing — GitHub renders it as a broken template.
TYPES = ("markdown", "input", "textarea", "dropdown", "checkboxes")
FILLABLE = tuple(kind for kind in TYPES if kind != "markdown")
# The issue-chooser config, not a form: parsing it is the whole check it gets.
CHOOSER = ("config.yml", "config.yaml")
# Documented `id` grammar: alphanumerics, `-` and `_`. Spelled out rather than a regex import so
# the rule reads as the docs state it.
ID_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")


def _text(value):
    """True when `value` is a non-empty, non-blank string. Anything else (None, 0, True, a list)
    is NOT a usable label/value — YAML makes all of those easy to produce by accident."""
    return isinstance(value, str) and bool(value.strip())


def _attribute_errors(prefix, kind, attributes):
    """The required `attributes:` shape for one element type. Returns a list of complaints."""
    if not isinstance(attributes, dict):
        return [f"{prefix} (`{kind}`) needs an `attributes:` mapping"]
    errors = []
    if kind == "markdown":
        if not _text(attributes.get("value")):
            errors.append(f"{prefix} (`markdown`) needs a non-empty `attributes.value:`")
        return errors
    if not _text(attributes.get("label")):
        errors.append(f"{prefix} (`{kind}`) needs a non-empty `attributes.label:`")
    if kind not in ("dropdown", "checkboxes"):
        return errors
    options = attributes.get("options")
    if not isinstance(options, list) or not options:
        errors.append(f"{prefix} (`{kind}`) needs a non-empty `attributes.options:` list")
        return errors
    if kind == "dropdown":
        if not all(_text(option) for option in options):
            errors.append(f"{prefix} (`dropdown`) options must all be non-empty strings")
        elif len(set(options)) != len(options):
            errors.append(f"{prefix} (`dropdown`) options must be distinct")
        return errors
    for index, option in enumerate(options):
        if not isinstance(option, dict) or not _text(option.get("label")):
            errors.append(f"{prefix} (`checkboxes`) options[{index}] needs a non-empty `label:`")
    return errors


def check_form(label, doc):
    """PURE: every reason `doc` is not a valid GitHub issue form, as a list of strings. Empty
    list == valid. `label` is the caller's name for the document (a path, in production)."""
    if not isinstance(doc, dict):
        return [f"{label}: top level must be a mapping, got {type(doc).__name__}"]
    errors = []
    for key in ("name", "description"):
        if not _text(doc.get(key)):
            errors.append(f"{label}: `{key}:` is required and must be a non-empty string")
    body = doc.get("body")
    if not isinstance(body, list) or not body:
        errors.append(f"{label}: `body:` is required and must be a non-empty list")
        return errors
    kinds, seen = [], set()
    for index, element in enumerate(body):
        prefix = f"{label}: body[{index}]"
        if not isinstance(element, dict):
            errors.append(f"{prefix} must be a mapping, got {type(element).__name__}")
            continue
        kind = element.get("type")
        if kind not in TYPES:
            errors.append(f"{prefix} has no valid `type:` (one of {', '.join(sorted(TYPES))})")
            continue
        kinds.append(kind)
        errors.extend(_attribute_errors(prefix, kind, element.get("attributes")))
        # A `markdown` element is decoration, not a field: it carries no field id, so it is
        # exempt from both the syntax and the uniqueness rule.
        if kind == "markdown" or "id" not in element:
            continue
        ident = element["id"]
        if not _text(ident) or set(ident) - ID_CHARS:
            errors.append(f"{prefix}: `id:` must be a non-empty string of alphanumerics, "
                          f"`-` and `_` (got {ident!r})")
        elif ident in seen:
            errors.append(f"{prefix}: duplicate `id: {ident}` — ids must be unique within a form")
        else:
            seen.add(ident)
    if kinds and not set(FILLABLE).intersection(kinds):
        errors.append(f"{label}: `body:` has no fillable field (every element is `markdown`) — "
                      "GitHub rejects this form")
    return errors


def check_directory(directory):
    """Check every issue-form template in `directory`. Returns (errors, forms_checked).

    `forms_checked` counts REAL FORMS only — the chooser config is parsed and then skipped, so it
    can never stand in for a form and make the zero-form guard vacuous."""
    root = pathlib.Path(directory)
    if not root.is_dir():
        return ([f"{directory}: issue-template directory is missing (fail closed)"], 0)
    errors, forms = [], 0
    for path in sorted(p for p in root.iterdir()
                       if p.is_file() and p.suffix in (".yml", ".yaml")):
        print(f"== yaml-parse {path} ==")
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            errors.append(f"{path}: not valid YAML — {exc}")
            continue
        except OSError as exc:
            errors.append(f"{path}: unreadable — {exc}")
            continue
        if path.name in CHOOSER:
            continue
        forms += 1
        errors.extend(check_form(str(path), doc))
    if not forms:
        errors.append(f"{directory}: swept zero issue FORMS (fail closed) — the chooser config "
                      "alone does not satisfy this check")
    return (errors, forms)


def _self_test():
    ok = True

    def check(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    def form(**overrides):
        """A minimal VALID form; overrides mutate exactly the field under test."""
        doc = {"name": "n", "description": "d",
               "body": [{"type": "input", "id": "who",
                         "attributes": {"label": "Who"}}]}
        doc.update(overrides)
        return doc

    def rejects(doc):
        return bool(check_form("f", doc))

    def body(*elements):
        return form(body=list(elements))

    # ---- THE BASELINE. If this ever goes red the negative rows below prove nothing: they would
    # be "rejected" by whatever breaks the valid case, not by the rule each one targets.
    check("the minimal valid form is accepted", check_form("f", form()), [])
    check("a form with every element type is accepted", check_form("f", body(
        {"type": "markdown", "attributes": {"value": "hi"}},
        {"type": "input", "id": "a", "attributes": {"label": "A"}},
        {"type": "textarea", "id": "b", "attributes": {"label": "B"}},
        {"type": "dropdown", "id": "c", "attributes": {"label": "C", "options": ["x", "y"]}},
        {"type": "checkboxes", "id": "d",
         "attributes": {"label": "D", "options": [{"label": "yes", "required": True}]}})), [])
    # NOT an oversight — the rule itself. GitHub's schema marks `id` Optional on every fillable
    # type (only `type`+`attributes` are Required), so refusing these would refuse valid forms.
    for kind in FILLABLE:
        extra = {"options": ["x"]} if kind == "dropdown" else (
            {"options": [{"label": "x"}]} if kind == "checkboxes" else {})
        check(f"`id` is OPTIONAL — a labelled `{kind}` without one is accepted (GitHub's schema)",
              rejects(body({"type": kind, "attributes": dict(extra, label="A")})), False)

    # ---- TOP LEVEL.
    check("a non-mapping document is refused", rejects(["not", "a", "form"]), True)
    for key in ("name", "description"):
        for value in (None, "", "   ", 7, True, ["n"]):
            check(f"`{key}: {value!r}` is refused", rejects(form(**{key: value})), True)
    for value in (None, [], "", {}, "text"):
        check(f"`body: {value!r}` is refused", rejects(form(body=value)), True)

    # ---- ELEMENT TYPE.
    for element in (None, "str", 7, [], {}, {"type": "html"}, {"type": None}, {"type": True}):
        check(f"body element {element!r} is refused", rejects(body(element)), True)
    check("an all-`markdown` body collects nothing and is refused",
          rejects(body({"type": "markdown", "attributes": {"value": "hi"}},
                       {"type": "markdown", "attributes": {"value": "there"}})), True)

    # ---- REQUIRED ATTRIBUTES, ONE ROW PER TYPE (the finding-2 class: a form GitHub rejects must
    # not pass here merely because its `type:` was spelled correctly).
    for kind in TYPES:
        for attributes in (None, "label", [], 7):
            check(f"`{kind}` with `attributes: {attributes!r}` is refused",
                  rejects(body({"type": kind, "attributes": attributes})), True)
        check(f"`{kind}` with an EMPTY attributes mapping is refused",
              rejects(body({"type": kind, "attributes": {}})), True)
    for value in (None, "", "  ", 7, ["v"]):
        check(f"`markdown` with `value: {value!r}` is refused",
              rejects(body({"type": "input", "id": "a", "attributes": {"label": "A"}},
                           {"type": "markdown", "attributes": {"value": value}})), True)
    for kind in FILLABLE:
        extra = {"options": ["x"]} if kind == "dropdown" else (
            {"options": [{"label": "x"}]} if kind == "checkboxes" else {})
        for value in (None, "", "  ", 7, ["l"]):
            check(f"`{kind}` with `label: {value!r}` is refused",
                  rejects(body({"type": kind, "attributes": dict(extra, label=value)})), True)
    for options in (None, [], "x", 7, {"a": 1}, ["x", ""], ["x", None], ["x", 7], ["x", "x"]):
        check(f"`dropdown` with `options: {options!r}` is refused",
              rejects(body({"type": "dropdown",
                            "attributes": {"label": "C", "options": options}})), True)
    for options in (None, [], "x", 7, ["plain"], [{"required": True}], [{"label": ""}],
                    [{"label": None}], [{"label": "ok"}, "plain"]):
        check(f"`checkboxes` with `options: {options!r}` is refused",
              rejects(body({"type": "checkboxes",
                            "attributes": {"label": "D", "options": options}})), True)

    # ---- ID SYNTAX AND UNIQUENESS.
    for ident in ("a b", "a.b", "a/b", "a!", "", "  ", 7, True, None, ["a"]):
        check(f"`id: {ident!r}` is refused",
              rejects(body({"type": "input", "id": ident, "attributes": {"label": "A"}})), True)
    for ident in ("a-b", "a_b", "AB9"):
        check(f"`id: {ident!r}` is accepted",
              rejects(body({"type": "input", "id": ident, "attributes": {"label": "A"}})), False)
    check("a duplicate `id` across two fields is refused",
          rejects(body({"type": "input", "id": "dup", "attributes": {"label": "A"}},
                       {"type": "textarea", "id": "dup", "attributes": {"label": "B"}})), True)
    check("...and distinct ids on the same two fields are accepted",
          rejects(body({"type": "input", "id": "one", "attributes": {"label": "A"}},
                       {"type": "textarea", "id": "two", "attributes": {"label": "B"}})), False)
    check("the markdown exception: a `markdown` carrying an unusable id is not a field error",
          rejects(body({"type": "markdown", "id": "not a field", "attributes": {"value": "v"}},
                       {"type": "input", "id": "who", "attributes": {"label": "A"}})), False)

    # ---- DIRECTORY SWEEP: the finding-1 class. `config.yml` is NOT a form, so a directory
    # holding nothing else must refuse rather than report a green "1 template checked".
    valid = yaml.safe_dump(form())
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        (root / "config.yml").write_text("blank_issues_enabled: false\n", encoding="utf-8")
        errors, forms = check_directory(root)
        check("a directory holding ONLY the chooser config refuses", bool(errors), True)
        check("...and reports ZERO forms checked, not one file", forms, 0)
        (root / "real.yml").write_text(valid, encoding="utf-8")
        errors, forms = check_directory(root)
        check("...adding one real form makes the same directory pass", (errors, forms), ([], 1))
        (root / "extra.yaml").write_text(valid, encoding="utf-8")
        check("a `.yaml` form is swept too", check_directory(root)[1], 2)
        (root / "notes.md").write_text("name: not-a-template\n", encoding="utf-8")
        check("a non-YAML file in the directory is not counted as a form",
              check_directory(root)[1], 2)
        (root / "broken.yml").write_text("body: [\n", encoding="utf-8")
        check("a YAML syntax error in one form fails the sweep",
              bool(check_directory(root)[0]), True)
        os.remove(root / "broken.yml")
        (root / "invalid.yml").write_text(yaml.safe_dump(form(name="")), encoding="utf-8")
        check("a schema-invalid form fails the sweep even when its siblings are fine",
              bool(check_directory(root)[0]), True)
    with tempfile.TemporaryDirectory() as tmp:
        empty = pathlib.Path(tmp) / "nothing"
        check("an EMPTY template directory refuses", bool(check_directory(pathlib.Path(tmp))[0]),
              True)
        check("a MISSING template directory refuses", check_directory(empty),
              ([f"{empty}: issue-template directory is missing (fail closed)"], 0))

    # ---- THE LIVE TREE. The rules must accept the templates this repo actually ships: a rule
    # stricter than GitHub's schema refuses valid forms, which is a different bug, not a gate.
    root = pathlib.Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    errors, forms = check_directory(root / ".github/ISSUE_TEMPLATE")
    check("this repo's own issue forms pass", errors, [])
    check("...and there is at least one of them to check", forms > 0, True)

    print("issue-form-check self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    if "--self-test" in sys.argv:
        return _self_test()
    if len(sys.argv) != 2:
        print("usage: issue-form-check.py <template-directory> | --self-test", file=sys.stderr)
        return 2
    errors, forms = check_directory(sys.argv[1])
    for entry in errors:
        print(f"::error::issue-form template invalid — {entry}")
    if errors:
        return 1
    print(f"issue-form check OK: {forms} form(s) parsed and schema-checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
