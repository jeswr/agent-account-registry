#!/usr/bin/env python3
# [OPUS-4.8] Registry self-management: static (no-LLM) issue triage for jeswr/agent-account-registry.
# Modeled on the sparq target's scripts/triage.py, adjusted for the registry's area:* sections and
# its trust-surface soundness lane. Applied by .github/workflows/triage-issue.yml.
"""triage.py — the deterministic, no-LLM part of issue triage.

Given an issue's labels + type, decide the labels to ADD/REMOVE and whether it is triage-complete:
  * role     — from a `kind:*` label or the issue type; a trust-surface area forces the
               trust-plane role (see TRUST_PLANE_ROLE).
  * priority — kept if a valid single `priority:P0..P4` is present; else triage is incomplete.
  * package  — the existing `area:<section>` labels are the package. A NO-area issue is parked
               `needs:area` (it would otherwise reserve the serializing __global__ partition).
  * ready    — `status:ready` iff a valid single priority AND a role AND an `area:<section>` AND
               NOT gated (`needs:*` incl. `needs:design`/`needs:user`, `trust:untrusted`) and not
               an epic. Otherwise `status:untriaged` (or `needs:area`-parked).

Fail-closed: ambiguity, missing role/priority, or ANY `needs:*` gate (INCLUDING `needs:design`,
the B2 design-hold) yields NOT-ready. `needs:design` is never auto-cleared here — a human/architect
removes it after the design pass, then the retriage path promotes.

THE ROLE INVARIANT (registry #582 / #225 — a LIVE defect, not a hypothetical):
    An issue must NEVER leave triage with `status:ready` and no `role:*` label.
A role-less `status:ready` issue is SILENTLY UNDISPATCHABLE and TERMINAL: ready-issues.py requires
`role:*` for readiness (`has_role`), so the dispatcher never sees it; retriage.py only reconsiders
`status:untriaged` issues, so it never sees it either; curate/groom skip it for their own reasons.
Nothing recovers it — it has to be repaired by hand.

The live defect that motivated this module's fail-closed machinery: the role transition emitted
`role:soundness` for trust-plane keyword matches, a label that DOES NOT EXIST in this repository's
label set (it exists in sparq-org/sparq, from which this file was copied — the registry's label set
was never given it). The applier added the role label and stripped the old one INDEPENDENTLY, with
`|| true` on each, so the add failed, the strip SUCCEEDED, and the issue landed `status:ready` with
no role at all. 7 of 13 issues created in one curate wave landed in that state.

Two layers now enforce the invariant:
  * triage() itself refuses to plan a strip whose replacement label is not known to exist, and
    _assert_role_invariant() rejects any plan whose PROJECTED post-state is ready-and-role-less;
  * apply_triage() sequences the live mutation so the replacement label is added AND VERIFIED
    PRESENT before anything is stripped, then re-reads the issue and asserts exactly one `role:*`
    remains — restoring the previous role label (or demoting `status:ready`) and failing loudly if
    the post-condition is violated.
"""
import json
import re
import subprocess
import sys

# ---------------------------------------------------------------------------------------------------
# TRUST-PLANE ROLE — INTERIM MAPPING (TODO: registry #582 / #225).
#
# The maintainer has an OPEN decision (#582): either `role:soundness` becomes a real label in this
# repository, or triage stops writing it. This constant is the SINGLE place that decision lands —
# it is deliberately NOT `soundness` today because that label does not exist here, and triage must
# never write a label it cannot verify.
#
# Interim value `impl`, chosen so the SOUNDNESS POSTURE IS UNCHANGED. orchestration/routing.toml
# resolves an issue in TWO phases (route-resolve.resolve / policy-resolve.resolve): EVERY
# `match_labels` security rule is evaluated before ANY role route. The security rule's keyword list
# is IDENTICAL to SEC_KEYWORDS below (asserted by the self-test), so every issue this branch fires
# on is — by construction — matched by the Phase-1 security override and routed to
# model_chain ["opus5", "opus"] / agent registry-reviewer / escalate=true, and its eventual PR is
# HUMAN-armed (worker-pr.py / dispatch-claim.py read the same match_labels keywords). The role
# label's own chain is NEVER consulted for these issues, so the role label only has to (a) exist
# and (b) be a configured role route so route-resolve does not raise UnknownRoleError.
#
# Among the role labels that EXIST in this repository today — role:impl, role:ci, role:docs,
# role:research, role:site — `impl` is the honest description of trust-plane work items and has a
# configured route. `role:review`/`role:soundness` exist in sparq-org/sparq but NOT here, so
# neither is usable. No label is invented and none is created by this change.
#
# TODO(#582): if the maintainer creates `role:soundness`, flip this ONE constant to "soundness";
# routing.toml already carries the matching `role = "soundness"` route, and the existence check in
# triage() means the flip is safe even if the label lands later than the code.
TRUST_PLANE_ROLE = "impl"

ROLE_BY_KIND = {"docs": "docs", "research": "research", "ci": "ci", "site": "site",
                "security": TRUST_PLANE_ROLE}
ROLE_BY_TYPE = {"feature": "impl", "bug": "impl", "task": "impl", "chore": "ci",
                "spike": "research", "epic": "impl"}
# The registry IS the orchestration trust plane: an issue touching these sections is a soundness
# surface (mirrors orchestration/routing.toml's match_labels — the self-test asserts the two lists
# are IDENTICAL, which is what makes TRUST_PLANE_ROLE's posture argument above hold). A substring
# match forces the trust-plane lane so the review of its eventual PR is human-armed, never
# auto-armed.
SEC_KEYWORDS = ("dispatch", "worker", "set-up-account", "review-loop", "groom",
                "zk", "mpc", "crypto", "auth", "e2ee")
# [FABLE-5] STANDING RULE (maintainer decision 2026-07-17): UI/front-end surfaces route role:site
# -> the openai/codex chain in orchestration/routing.toml (original-builder ownership: GPT-5.6
# codex built the registry dashboard, e4098b9). EXACT labels, not substrings — UI keywords must
# not enter SEC_KEYWORDS/match_labels semantics (that would human-arm every UI PR).
UI_SURFACE_LABELS = ("area:dashboard", "dashboard", "surface:frontend")
# [FABLE-5] STANDING RULE — frontier-tier CI/infrastructure authorship (maintainer decision
# 2026-07-17, same pattern as the UI rule above): infra-surface labels derive role:ci so CI
# plumbing reaches the FRONTIER-ONLY sol-led ci chain in orchestration/routing.toml (sol/fable —
# terra and sonnet are docs-only, 2026-07-18; sonnet/haiku no longer author infra). EXACT labels, and NOT routing match_labels
# (the arm-side security classifier unions those keywords). NOTE the trust-plane infra surfaces
# (dispatch/worker/set-up-account/review-loop/groom — incl. scripts/dispatch*, scripts/worker*,
# scripts/groom*, scripts/select-and-claim* issues, which carry those area labels) are ALREADY
# forced to the trust-plane lane by SEC_KEYWORDS above, which WINS — opus + human arm is stricter
# than the frontier floor. role:ci covers the residual: .github/workflows + non-trust CI plumbing.
INFRA_SURFACE_LABELS = ("area:ci", "area:workflows")
_PRIO = re.compile(r"^priority:P([0-4])$")
ROLE_PREFIX = "role:"


class RoleInvariantError(RuntimeError):
    """A triage PLAN whose projected post-state is `status:ready` with no `role:*` label.

    Raised by _assert_role_invariant BEFORE any mutation is attempted, so the ready-and-role-less
    state (#582) cannot be reached even by a future edit to the label arithmetic above. Fail-closed
    by construction: the caller dies loudly instead of silently stranding an issue.
    """


def _roles_of(labels):
    return {lb for lb in labels if lb.startswith(ROLE_PREFIX)}


def _valid_priority(labels):
    ps = {m.group(1) for lb in labels for m in [_PRIO.match(lb)] if m}
    return len(ps) == 1


def _role(labels, issue_type):
    # a trust-surface keyword forces the trust-plane lane regardless of kind/type/explicit role.
    if any(k in lb for lb in labels for k in SEC_KEYWORDS):
        return TRUST_PLANE_ROLE
    # respect an EXPLICIT single role:* label (a seeded/migrated issue already carrying its role).
    explicit = sorted(lb[5:] for lb in labels if lb.startswith(ROLE_PREFIX))
    if len(explicit) == 1:
        return explicit[0]
    for lb in labels:
        if lb.startswith("kind:") and lb[5:] in ROLE_BY_KIND:
            return ROLE_BY_KIND[lb[5:]]
    # [FABLE-5] UI-surface labels derive role:site (codex-led chain) before the generic type map,
    # after kind (docs about the dashboard stay docs) and after an explicit role:* label.
    if any(lb in UI_SURFACE_LABELS for lb in labels):
        return "site"
    # [FABLE-5] infra-surface labels derive role:ci (the frontier-only sol/fable chain) in the
    # same precedence slot: after security (the trust-plane role wins), explicit role:*, and kind.
    if any(lb in INFRA_SURFACE_LABELS for lb in labels):
        return "ci"
    return ROLE_BY_TYPE.get(issue_type)


def _assert_role_invariant(current, add, remove, ready):
    """THE #582 INVARIANT: an issue must never leave triage with status:ready and no role:*.

    Checked on the PROJECTED post-state of the plan, before any mutation. Raises
    RoleInvariantError rather than returning a plan that strands the issue.
    """
    post = (set(current) | set(add)) - set(remove)
    if ("status:ready" in post or ready) and not _roles_of(post):
        raise RoleInvariantError(
            "triage plan would leave the issue status:ready with NO role:* label "
            f"(current={sorted(current)} add={sorted(add)} remove={sorted(remove)}) — "
            "registry #582: that state is silently undispatchable and terminal")


def triage(labels, issue_type="task", trusted=True, known_labels=None):
    """Return {add:set, remove:set, ready:bool, role:str|None, warnings:list}.

    Untrusted -> a no-op (the trust layer quarantines/notifies; content is never inspected here).

    `known_labels` (optional): the repository's ACTUAL label set. When supplied, the role
    transition is FAIL-CLOSED (#582): a target `role:*` label that does not exist in the repo is
    NEVER written, and — critically — the existing role label is NEVER stripped for it. The issue
    keeps the role it has (or, if it has none, stays `status:untriaged`, which retriage can still
    recover) and a loud warning names the issue's missing label. `None` means "label set unknown"
    and keeps the pure-logic behaviour; the applier below always supplies it.
    """
    labels = set(labels)
    if not trusted or "trust:untrusted" in labels:
        return {"add": set(), "remove": set(), "ready": False, "role": None, "warnings": []}
    role = _role(labels, issue_type)
    add, remove, warnings = set(), set(), []
    existing = _roles_of(labels)
    if role:
        target = f"{ROLE_PREFIX}{role}"
        if known_labels is not None and target not in set(known_labels):
            # FAIL-CLOSED (#582): the replacement does not exist, so the strip must not happen.
            # Keeping a stale-but-valid role beats a role-less, silently undispatchable issue.
            keep = sorted(existing)
            warnings.append(
                f"target role label {target!r} does not exist in the repository label set — "
                f"KEEPING the existing role {keep or ['(none)']} and refusing to strip it "
                f"(registry #582); create the label or fix TRUST_PLANE_ROLE/ROLE_BY_KIND")
            # exactly one existing role -> keep it verbatim; zero or ambiguous -> stay role-less,
            # which _assert_role_invariant then forces to NOT-ready rather than ready-without-role.
            role = keep[0][5:] if len(keep) == 1 else None
        else:
            add.add(target)
            # single-role invariant: strip any OTHER role:* so resolve() never sees an ambiguous
            # set. Safe here only because `target` is known to exist (or the label set is unknown
            # and the applier verifies the add landed before performing this strip).
            remove |= {lb for lb in existing if lb != target}
    has_area = any(lb.startswith("area:") for lb in labels)
    # ANY needs:* gate (needs:design B2, needs:user, needs:area) blocks ready. kind:epic too.
    gated = any(lb.startswith("needs:") for lb in labels)
    ready = (bool(role) and _valid_priority(labels) and has_area and not gated
             and "kind:epic" not in labels)
    if ready:
        add.add("status:ready")
        remove.add("status:untriaged")
        remove.add("needs:area")
    else:
        add.add("status:untriaged")
        remove.add("status:ready")
        # a triage-complete-but-no-area, non-gated, non-epic issue parks needs:area (actionable).
        if (bool(role) and _valid_priority(labels) and not has_area
                and "kind:epic" not in labels and not gated):
            add.add("needs:area")
    add, remove = add - labels, remove & labels
    _assert_role_invariant(labels, add, remove, ready)
    return {"add": add, "remove": remove, "ready": ready, "role": role, "warnings": warnings}


# ---------------------------------------------------------------------------------------------------
# LIVE APPLICATION — the fail-closed, order-controlled mutation (#582).

def apply_triage(current, result, edit, view, warn=None):
    """Apply a triage `result` to a live issue FAIL-CLOSED. Returns {"ok":bool,"warnings":[...]}.

    `edit(add, remove)` performs ONE label mutation and MUST RAISE on failure (never `|| true`);
    `view()` re-reads and returns the issue's live label set. Both are injected so the self-test
    drives the whole sequence against a fake GitHub.

    Sequence — the invariant is enforced by ORDER plus VERIFICATION, not by hope:
      1. the target `role:*` label is added FIRST and its presence VERIFIED by a re-read;
      2. no `role:*` strip is issued unless the target is verifiably in place — otherwise the
         strips are dropped from the plan and, if the projected post-state has no role at all,
         `status:ready` is withheld (the issue stays `status:untriaged`, which retriage recovers);
      3. the remaining adds/removes are applied;
      4. POST-CONDITION: the issue is re-read and must carry exactly one `role:*`. A role-less
         `status:ready` post-state restores the previous role label (or demotes to
         `status:untriaged` when there is none to restore) and reports ok=False, loudly.
    """
    warns = list(result.get("warnings", ()))
    warn = warn or (lambda _m: None)
    for message in warns:
        warn(message)
    current = set(current)
    prev_roles = _roles_of(current)
    add, remove = set(result["add"]), set(result["remove"])
    role_rm = _roles_of(remove)
    target = f"{ROLE_PREFIX}{result['role']}" if result.get("role") else None
    ok = True

    # 1. the replacement role label must be PRESENT (already, or newly added AND verified) before
    #    any strip. `result["add"]` has the target subtracted when it is already on the issue.
    target_ok = bool(target) and target in current
    if target and not target_ok:
        try:
            edit([target], [])
        except Exception as exc:                                  # noqa: BLE001 — report, never die
            message = (f"role label add {target!r} FAILED ({exc}) — refusing to strip the existing "
                       f"role (registry #582)")
            warns.append(message)
            warn(message)
        else:
            if target in view():
                target_ok = True
            else:
                message = (f"role label add {target!r} reported success but did NOT land — "
                           f"refusing to strip the existing role (registry #582)")
                warns.append(message)
                warn(message)
        add.discard(target)

    # 2. never strip the last/only role without a verified replacement.
    if role_rm and not target_ok:
        message = (f"refusing to strip {sorted(role_rm)}: replacement {target!r} is not in place "
                   f"(registry #582)")
        warns.append(message)
        warn(message)
        remove -= role_rm
        role_rm = set()
        ok = False
    projected_roles = (prev_roles - remove) | ({target} if target_ok else set())
    if not projected_roles:
        # THE INVARIANT: never status:ready with no role. Withhold the promotion instead.
        if "status:ready" in add or "status:ready" in current:
            message = ("withholding status:ready: the issue would have NO role:* label "
                       "(registry #582) — leaving it status:untriaged for retriage")
            warns.append(message)
            warn(message)
            ok = False
        add.discard("status:ready")
        remove.discard("status:untriaged")
        remove.add("status:ready")
        if "status:untriaged" not in current:
            add.add("status:untriaged")

    # 3. apply the rest in ONE mutation so a partial failure is loud rather than half-applied.
    if add or remove:
        try:
            edit(sorted(add), sorted(remove))
        except Exception as exc:                                  # noqa: BLE001
            message = f"label mutation failed ({exc}); post-condition check follows"
            warns.append(message)
            warn(message)
            ok = False

    # 4. POST-CONDITION — re-read and assert exactly one role:*; restore + fail loudly otherwise.
    live = view()
    live_roles = _roles_of(live)
    if not live_roles and "status:ready" in live:
        message = ("POST-CONDITION VIOLATED (registry #582): issue is status:ready with NO role:* "
                   f"label; restoring {sorted(prev_roles) or 'status:untriaged'}")
        warns.append(message)
        warn(message)
        ok = False
        try:
            if prev_roles:
                edit(sorted(prev_roles), [])
            else:
                edit(["status:untriaged"], ["status:ready"])
        except Exception as exc:                                  # noqa: BLE001
            message = f"RESTORE FAILED ({exc}) — issue needs manual repair (registry #582)"
            warns.append(message)
            warn(message)
    elif len(live_roles) > 1:
        message = (f"POST-CONDITION: ambiguous role set {sorted(live_roles)} survives triage — "
                   "route-resolve will reject this issue (AmbiguousRoleError)")
        warns.append(message)
        warn(message)
        ok = False
    return {"ok": ok, "warnings": warns}


def _gh_read(args):
    """Run an IDEMPOTENT `gh` READ through the shared bounded-retry layer (gh_retry's hard scope
    rule: reads only — the label MUTATIONS below are single-attempt and fail loud)."""
    try:
        import importlib.util
        import os
        spec = importlib.util.spec_from_file_location(
            "registry_gh_retry", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                              "gh_retry.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        proc = module.run_gh(args)
    except Exception:                                             # noqa: BLE001 — plain read
        proc = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args)} failed: {(proc.stderr or '').strip()}")
    return proc.stdout


def repo_label_set(repo):
    """The repository's ACTUAL label names — the existence oracle for the role transition."""
    out = _gh_read(["label", "list", "-R", repo, "--limit", "500", "--json", "name"])
    return {item["name"] for item in json.loads(out)}


def _apply_cli(repo, number, issue_type):
    """`--apply`: read the live issue + label set, plan, and mutate fail-closed. Exit 1 loudly on
    any invariant/post-condition failure so the workflow step turns red instead of silently
    stranding the issue (the `|| true` per-label loop this replaces is exactly how #582 happened).
    """
    def view():
        out = _gh_read(["issue", "view", str(number), "-R", repo, "--json", "labels"])
        return {lb["name"] for lb in json.loads(out)["labels"]}

    def edit(add, remove):
        args = ["issue", "edit", str(number), "-R", repo]
        for label in add:
            args += ["--add-label", label]
        for label in remove:
            args += ["--remove-label", label]
        if len(args) == 4:
            return
        proc = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or "").strip() or f"gh exited {proc.returncode}")

    def warn(message):
        print(f"::warning title=triage #{number}::{message}")

    current = view()
    known = repo_label_set(repo)
    try:
        result = triage(current, issue_type, trusted=True, known_labels=known)
    except RoleInvariantError as exc:
        print(f"::error title=triage #{number}::{exc}")
        return 1
    outcome = apply_triage(current, result, edit, view, warn)
    print(f"triage #{number}: role={result['role']} ready={result['ready']} "
          f"add={sorted(result['add'])} remove={sorted(result['remove'])}")
    return 0 if outcome["ok"] else 1


def _self_test():
    ok = True

    def chk(n, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {n}: {got} (want {want})")

    # complete NON-trust issue: priority + derivable role + area -> ready.
    r = triage(["priority:P2", "kind:docs", "area:docs"], "task")
    chk("docs ready", (r["ready"], "role:docs" in r["add"], "status:ready" in r["add"]),
        (True, True, True))
    # missing priority -> untriaged.
    r = triage(["area:usage"], "feature")
    chk("no priority -> untriaged", (r["ready"], "status:untriaged" in r["add"]), (False, True))
    # ambiguous priority -> untriaged.
    chk("ambiguous priority", triage(["priority:P1", "priority:P2"], "feature")["ready"], False)
    # trust-surface area forces the trust-plane role.
    chk("trust surface -> trust-plane role",
        triage(["priority:P1", "area:worker"], "feature")["role"], TRUST_PLANE_ROLE)
    chk("dispatch -> trust-plane role", triage(["priority:P1", "area:dispatch"], "feature")["role"],
        TRUST_PLANE_ROLE)
    # [FABLE-5] UI-surface ownership: dashboard work derives role:site (codex-led chain, e4098b9);
    # kind:docs about the dashboard stays docs.
    chk("dashboard -> site", triage(["priority:P2", "area:dashboard"], "feature")["role"], "site")
    chk("dashboard docs stay docs",
        triage(["priority:P3", "kind:docs", "area:dashboard"], "task")["role"], "docs")
    # [FABLE-5] frontier-tier infra authorship: an infra-surface label derives role:ci (the
    # frontier-only sol/fable chain); kind (docs) and trust-surface keywords still win.
    chk("infra surface -> ci", triage(["priority:P2", "area:ci"], "feature")["role"], "ci")
    chk("workflows surface -> ci", triage(["priority:P2", "area:workflows"], "task")["role"], "ci")
    chk("infra docs stay docs",
        triage(["priority:P3", "kind:docs", "area:ci"], "task")["role"], "docs")
    chk("infra+trust surface -> trust-plane role",
        triage(["priority:P1", "area:ci", "area:dispatch"], "feature")["role"], TRUST_PLANE_ROLE)
    # B2: a needs:design issue is NOT ready even with a full role+priority+area label-set.
    r = triage(["priority:P2", "role:impl", "area:review-loop", "needs:design"], "task")
    chk("needs:design not ready (B2)", r["ready"], False)
    chk("needs:design not promoted (B2)", "status:ready" in r["add"], False)
    # needs:user -> not ready.
    chk("needs:user gated", triage(["priority:P1", "kind:docs", "needs:user"], "task")["ready"],
        False)
    # untrusted -> no-op.
    chk("untrusted no-op", triage(["priority:P1", "trust:untrusted"], "feature"),
        {"add": set(), "remove": set(), "ready": False, "role": None, "warnings": []})
    # respect an explicit role:* on a NON-trust area — do NOT derive a second (ambiguity broke
    # autonomous dispatch upstream).
    r = triage(["priority:P2", "role:research", "area:usage"], "feature")
    chk("explicit role respected", (r["role"], "role:impl" in r["add"]), ("research", False))
    # an epic is never dispatchable even with a full label-set.
    chk("epic not ready", triage(["priority:P1", "role:impl", "kind:epic", "area:usage"],
                                 "epic")["ready"], False)
    # no-area guard: parks needs:area.
    r = triage(["priority:P1", "kind:docs"], "task")
    chk("no-area not ready", r["ready"], False)
    chk("no-area parks needs:area", "needs:area" in r["add"], True)
    # a needs:design no-area issue is not double-parked with needs:area (already gated).
    chk("gated no-area no needs:area",
        "needs:area" in triage(["priority:P1", "role:impl", "needs:design"], "task")["add"], False)

    # -----------------------------------------------------------------------------------------------
    # [#582] THE TRUST-PLANE ROLE ROUTES TO A LABEL THAT EXISTS, and the posture argument holds.
    # The registry's REAL role labels (gh label list, 2026-07-25). `role:soundness`/`role:review`
    # exist in sparq-org/sparq but NOT here — writing either strands the issue.
    REAL = {"role:impl", "role:ci", "role:docs", "role:research", "role:site",
            "priority:P0", "priority:P1", "priority:P2", "priority:P3", "priority:P4",
            "status:ready", "status:untriaged", "needs:area", "needs:design", "needs:user",
            "area:dispatch", "area:worker", "area:usage", "area:docs", "area:ci",
            "area:workflows", "area:dashboard", "area:review-loop", "area:groom",
            "trust:untrusted"}
    chk("trust-plane role label EXISTS in the registry label set",
        f"role:{TRUST_PLANE_ROLE}" in REAL, True)
    chk("role:soundness is NOT a registry label (the #582 root cause)",
        "role:soundness" in REAL, False)
    # a trust-plane match under the REAL label set: exactly one role label, and it is a real one.
    r = triage(["priority:P1", "area:dispatch", "role:impl"], "task", known_labels=REAL)
    chk("[#582] trust-plane match routes to an EXISTING label",
        (r["role"], f"role:{r['role']}" in REAL, r["remove"], r["ready"]),
        (TRUST_PLANE_ROLE, True, set(), True))
    # every derivable role must be a REAL label — otherwise triage can still strand an issue.
    chk("every derivable role is a real label",
        sorted({f"role:{v}" for v in list(ROLE_BY_KIND.values()) + list(ROLE_BY_TYPE.values())
                + [TRUST_PLANE_ROLE, "site", "ci"]} - REAL), [])
    # POSTURE: TRUST_PLANE_ROLE is only safe because routing.toml's Phase-1 security keywords are
    # IDENTICAL to SEC_KEYWORDS, so every trust-plane match is human-armed/opus-routed regardless
    # of which role label it carries. If someone edits either list, this check goes red.
    try:
        import tomllib
    except ModuleNotFoundError:                                   # pragma: no cover
        import tomli as tomllib
    doc = tomllib.load(open("orchestration/routing.toml", "rb"))
    sec_rules = [route for route in doc.get("route", []) if "match_labels" in route]
    chk("SEC_KEYWORDS == routing.toml security match_labels (posture invariant)",
        sorted(SEC_KEYWORDS), sorted({k for rule in sec_rules for k in rule["match_labels"]}))
    chk("the security route human-escalates + runs the soundness chain",
        [(rule["model_chain"], rule["agent"], bool(rule.get("escalate"))) for rule in sec_rules],
        [(["opus5", "opus"], "registry-reviewer", True)])
    chk("TRUST_PLANE_ROLE has a configured role route in routing.toml",
        TRUST_PLANE_ROLE in {route.get("role") for route in doc.get("route", [])
                             if "match_labels" not in route}, True)

    # -----------------------------------------------------------------------------------------------
    # [#582] (1) TARGET LABEL MISSING => the existing role is PRESERVED + a warning; never role-less.
    # `known_labels` deliberately omits role:soundness, exactly as the live repo does. Non-vacuous:
    # the pre-fix code planned remove={"role:impl"} with add={"role:soundness"} here.
    r = triage(["priority:P1", "role:impl", "area:dispatch"], "task",
               known_labels=REAL - {"role:soundness"})
    chk("[#582] no churn when the derived label is real and already present",
        (r["role"], r["remove"], r["warnings"]), ("impl", set(), []))
    # Force the missing-target branch with a DIFFERENT incumbent role (role:docs), so a blind
    # strip-then-add would VISIBLY remove it. Non-vacuous by construction: the pre-fix order planned
    # add={role:<target>} / remove={role:docs} here and, since the add fails live, that is exactly
    # the sequence that left 7 of 13 issues in one wave role-less.
    fixture = {"priority:P1", "role:docs", "area:dispatch"}
    r = triage(fixture, "task", known_labels=REAL - {f"role:{TRUST_PLANE_ROLE}"})
    chk("[#582] missing target label => existing role PRESERVED, nothing stripped",
        (r["role"], sorted(r["remove"]), sorted(r["add"] & {f"role:{TRUST_PLANE_ROLE}"})),
        ("docs", [], []))
    warning = r["warnings"][0] if r["warnings"] else ""    # index-safe: a mutant emits none
    chk("[#582] missing target label => LOUD warning naming the label",
        (len(r["warnings"]), f"role:{TRUST_PLANE_ROLE}" in warning, "#582" in warning),
        (1, True, True))
    chk("[#582] missing target label still leaves exactly one role on the issue",
        _roles_of((fixture | r["add"]) - r["remove"]), {"role:docs"})
    # missing target AND no existing role -> NOT ready (recoverable untriaged), never ready+roleless.
    r = triage(["priority:P1", "area:dispatch"], "task",
               known_labels=REAL - {f"role:{TRUST_PLANE_ROLE}"})
    chk("[#582] missing target + no existing role => untriaged, not ready",
        (r["role"], r["ready"], "status:ready" in r["add"], "status:untriaged" in r["add"]),
        (None, False, False, True))

    # (2) a SUCCESSFUL transition leaves EXACTLY ONE role label.
    r = triage(["priority:P1", "role:docs", "area:usage", "status:untriaged"], "task",
               known_labels=REAL)
    post = ({"priority:P1", "role:docs", "area:usage", "status:untriaged"} | r["add"]) - r["remove"]
    chk("[#582] successful transition => exactly one role label", (r["ready"], _roles_of(post)),
        (True, {"role:docs"}))
    r = triage(["priority:P1", "role:docs", "area:dispatch", "status:untriaged"], "task",
               known_labels=REAL)
    post = ({"priority:P1", "role:docs", "area:dispatch", "status:untriaged"}
            | r["add"]) - r["remove"]
    chk("[#582] trust-plane re-route swaps, never zeroes, the role",
        (sorted(r["add"] & {f"role:{TRUST_PLANE_ROLE}"}), sorted(r["remove"]), _roles_of(post)),
        ([f"role:{TRUST_PLANE_ROLE}"], ["role:docs", "status:untriaged"],
         {f"role:{TRUST_PLANE_ROLE}"}))

    # (3) the PLAN-level invariant rejects a ready-and-role-less projection outright.
    try:
        _assert_role_invariant({"priority:P1", "role:impl", "area:usage"},
                               {"status:ready"}, {"role:impl"}, True)
    except RoleInvariantError:
        chk("[#582] plan invariant rejects ready-without-role", True, True)
    else:
        chk("[#582] plan invariant rejects ready-without-role", False, True)

    # (3b) the LIVE post-condition catches an INDUCED zero-role state and RESTORES it.
    class FakeGh:
        """A GitHub that drops adds of labels outside `known` — the live #582 failure mode."""

        def __init__(self, labels, known):
            self.labels, self.known, self.calls = set(labels), set(known), []

        def edit(self, add, remove):
            self.calls.append(("edit", sorted(add), sorted(remove)))
            for label in add:
                if label not in self.known:
                    raise RuntimeError(f"'{label}' not found")
                self.labels.add(label)
            self.labels -= set(remove)

        def view(self):
            self.calls.append(("view",))
            return set(self.labels)

    # the exact live wave: role:impl + area:dispatch, repo has NO role:soundness. A plan that (as
    # the pre-fix code did) adds role:soundness and strips role:impl must NOT strand the issue.
    start = {"priority:P1", "role:impl", "area:dispatch", "status:untriaged"}
    gh = FakeGh(start, REAL - {"role:soundness"})
    bad_plan = {"add": {"role:soundness", "status:ready"}, "remove": {"role:impl",
                "status:untriaged"}, "ready": True, "role": "soundness", "warnings": []}
    out = apply_triage(start, bad_plan, gh.edit, gh.view)
    chk("[#582] applier refuses to strip when the add fails",
        (out["ok"], _roles_of(gh.labels), "status:ready" in gh.labels),
        (False, {"role:impl"}, True))
    chk("[#582] applier warns loudly about the failed add",
        any("role:soundness" in w and "refusing to strip" in w for w in out["warnings"]), True)
    # induced ZERO-role state, layer 2: a plan that strips the only role with NO replacement at
    # all. The strip is dropped from the plan, so the previous role survives.
    gh = FakeGh(start, REAL)
    zero_plan = {"add": {"status:ready"}, "remove": {"role:impl", "status:untriaged"},
                 "ready": True, "role": None, "warnings": []}
    out = apply_triage(start, zero_plan, gh.edit, gh.view)
    chk("[#582] a role strip with no replacement is dropped, role survives",
        (out["ok"], _roles_of(gh.labels), "status:ready" in gh.labels), (False, {"role:impl"}, True))
    # induced ZERO-role state, layer 3 — THE POST-CONDITION ITSELF. Both earlier layers are bypassed
    # by a plan they consider valid (target already present, nothing to verify, no role strip
    # planned) against a GitHub whose edit ALSO drops every role label — a concurrent triage run, an
    # over-broad remove, or a future edit to the arithmetic above. Phase 4 must re-read, see
    # status:ready with zero roles, RESTORE the previous role label, and report ok=False.
    class RoleEatingGh(FakeGh):
        def edit(self, add, remove):
            super().edit(add, remove)
            if "role:impl" not in add:           # the restore call must be allowed to succeed
                self.labels -= {lb for lb in self.labels if lb.startswith(ROLE_PREFIX)}

    gh = RoleEatingGh(start, REAL)
    good_plan = triage(start, "task", known_labels=REAL)
    chk("[#582] layer-3 fixture uses a plan the earlier layers accept",
        (good_plan["ready"], sorted(_roles_of(good_plan["remove"])), good_plan["warnings"]),
        (True, [], []))
    out = apply_triage(start, good_plan, gh.edit, gh.view)
    chk("[#582] post-condition catches an induced zero-role state and RESTORES",
        (out["ok"], _roles_of(gh.labels)), (False, {"role:impl"}))
    chk("[#582] post-condition failure is reported loudly",
        any("POST-CONDITION VIOLATED" in w and "#582" in w for w in out["warnings"]), True)
    # and a HOSTILE applier path: the plan looks fine but GitHub silently loses the role add.
    class LossyGh(FakeGh):
        def edit(self, add, remove):
            self.calls.append(("edit", sorted(add), sorted(remove)))
            self.labels -= set(remove)          # strips land, adds vanish (the #582 asymmetry)

    gh = LossyGh({"priority:P1", "role:docs", "area:dispatch", "status:ready"}, REAL)
    plan = triage(gh.labels, "task", known_labels=REAL)
    out = apply_triage(set(gh.labels), plan, gh.edit, gh.view)
    chk("[#582] silently-lost role add is detected and the old role kept",
        (out["ok"], _roles_of(gh.labels)), (False, {"role:docs"}))

    # (4) a HAPPY-path live application: one mutation, exactly one role, promoted to ready.
    gh = FakeGh({"priority:P1", "area:dispatch", "status:untriaged", "role:docs"}, REAL)
    plan = triage(gh.labels, "task", known_labels=REAL)
    out = apply_triage(set(gh.labels), plan, gh.edit, gh.view)
    chk("[#582] happy path: one role, ready, ok",
        (out["ok"], _roles_of(gh.labels), "status:ready" in gh.labels,
         "status:untriaged" in gh.labels),
        (True, {f"role:{TRUST_PLANE_ROLE}"}, True, False))

    print("triage self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--labels", default="", help="comma-separated current labels")
    ap.add_argument("--type", default="task")
    ap.add_argument("--untrusted", action="store_true")
    ap.add_argument("--apply", action="store_true",
                    help="read + mutate the live issue FAIL-CLOSED (needs --repo/--number)")
    ap.add_argument("--repo", default="")
    ap.add_argument("--number", default="")
    ap.add_argument("--known-labels", default="",
                    help="comma-separated repo label set; enables the #582 existence check")
    a = ap.parse_args()
    if a.self_test:
        return _self_test()
    if a.apply:
        if not a.repo or not a.number:
            ap.error("--apply requires --repo and --number")
        return _apply_cli(a.repo, a.number, a.type)
    labels = [x for x in a.labels.split(",") if x.strip()]
    known = [x for x in a.known_labels.split(",") if x.strip()] or None
    r = triage(labels, a.type, trusted=not a.untrusted, known_labels=known)
    for message in r["warnings"]:
        print(f"::warning title=triage::{message}", file=sys.stderr)
    print("ADD: " + " ".join(sorted(r["add"])))
    print("REMOVE: " + " ".join(sorted(r["remove"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
