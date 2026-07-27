#!/usr/bin/env python3
# Registry self-management: static (no-LLM) issue triage for jeswr/agent-account-registry.
# Modeled on the sparq target's scripts/triage.py, adjusted for the registry's area:* sections and
# its trust-surface soundness lane. Applied by .github/workflows/triage-issue.yml.
"""triage.py — the deterministic, no-LLM part of issue triage.

Given an issue's labels + type, decide the labels to ADD/REMOVE and whether it is triage-complete:
  * role     — from a `kind:*` label, the issue type, or (last resort, issue #225) the issue's
               `area:*` default; a trust-surface area forces the trust-plane role (see
               TRUST_PLANE_ROLE).
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

ROLE_LABELS = frozenset({"docs", "impl", "ci", "research", "site"})

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
# model_chain ["opus5"] / agent registry-reviewer / escalate=true, and its eventual PR is
# HUMAN-armed (worker-pr.py / dispatch-claim.py read the same match_labels keywords). The role
# label's own chain is NEVER consulted for these issues, so the role label only has to (a) exist
# and (b) be a configured role route so route-resolve does not raise UnknownRoleError.
#
# THE ARGUMENT IS ONLY TRUE IF *EVERY* PRODUCER OF THIS CONSTANT IS PHASE-1 MATCHED — PR #595
# review finding 1 found a producer that was NOT. `ROLE_BY_KIND["security"]` mapped `kind:security`
# to TRUST_PLANE_ROLE while `security` was NOT a SEC_KEYWORD, so an issue labelled
# {priority:P1, area:usage, kind:security} matched no Phase-1 rule and BOTH resolvers returned the
# plain impl route — model_chain ["sol", "opus5", "fable", "opus"], agent registry-impl,
# escalate=FALSE — i.e. trust-plane work on a non-escalated, AUTO-ARMABLE chain. The fix makes the
# argument true rather than weakening it: every kind that denotes trust-plane work
# (TRUST_PLANE_KINDS below) is now a Phase-1 keyword in BOTH SEC_KEYWORDS and routing.toml's
# `match_labels`, and the self-test ENUMERATES every producer of TRUST_PLANE_ROLE (each
# TRUST_PLANE_KINDS entry and each SEC_KEYWORD) and asserts each one resolves to the escalated
# soundness chain through route-resolve AND policy-resolve — so a new kind added without Phase-1
# coverage turns the enrolled suite RED.
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

# The `kind:*` values that DENOTE TRUST-PLANE WORK (as opposed to the generic implementation work
# ROLE_BY_TYPE derives). Declaring them explicitly — instead of inferring "trust-plane" from the
# mapped role — matters because TRUST_PLANE_ROLE is currently the same string as the generic impl
# role, so `value == TRUST_PLANE_ROLE` cannot discriminate. INVARIANT (self-test enforced, PR #595
# finding 1): every entry here MUST be matched by Phase 1, i.e. `kind:<entry>` must contain some
# SEC_KEYWORD as a substring, and the set of ROLE_BY_KIND keys mapped to TRUST_PLANE_ROLE must be
# EXACTLY this tuple — adding a trust-plane kind without Phase-1 coverage fails the suite.
TRUST_PLANE_KINDS = ("security",)
ROLE_BY_KIND = {"docs": "docs", "research": "research", "ci": "ci", "site": "site",
                **{kind: TRUST_PLANE_ROLE for kind in TRUST_PLANE_KINDS}}
ROLE_BY_TYPE = {"feature": "impl", "bug": "impl", "task": "impl", "chore": "ci",
                "spike": "research", "epic": "impl"}
# The registry IS the orchestration trust plane: an issue touching these sections is a soundness
# surface (mirrors orchestration/routing.toml's match_labels — the self-test asserts the two lists
# are IDENTICAL, which is what makes TRUST_PLANE_ROLE's posture argument above hold). A substring
# match forces the trust-plane lane so the review of its eventual PR is human-armed, never
# auto-armed.
# `security` (PR #595 finding 1) covers the OTHER producer of TRUST_PLANE_ROLE — the
# `kind:security` label in ROLE_BY_KIND/TRUST_PLANE_KINDS. Without it that label derived the
# trust-plane role but matched NO Phase-1 rule, so the issue resolved to the plain, non-escalated,
# auto-armable impl chain. Every keyword here is also a `match_labels` keyword in
# orchestration/routing.toml (equality asserted by the self-test), so it is ALSO read by the
# arm-side security classifier (worker-pr.py live_security_flagged / dispatch-claim.py
# _security_flagged) — a matched issue's PR is HUMAN-armed, never auto-armed.
SEC_KEYWORDS = ("dispatch", "worker", "set-up-account", "review-loop", "groom",
                "zk", "mpc", "crypto", "auth", "e2ee", "security")
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
# [OPUS-5] issue #225 — the DEFAULT role for each of the registry's OWN areas: the LAST fallback
# in _role(), consulted only when the security/UI/infra lanes, an explicit `role:*`, a `kind:*` AND
# the type map have all come up empty. `ROLE_BY_TYPE.get()` returns None for an issue with no
# GitHub type or a type outside its keys, and a ROLELESS issue is INVISIBLE to the dispatch
# enumerator (ready-issues.has_role requires `role:.+`, so the frontier drops it with no signal):
# 117 `status:ready` issues sat silently undrainable. Keys are area VALUES matched EXACTLY — never
# substrings; substring semantics belong to SEC_KEYWORDS / routing match_labels, which human-arm
# whatever they match. Every value MUST be a role configured in orchestration/routing.toml, else
# the row this enables is rejected by the planner (route-resolve.RoleResolutionError).
# The first three groups are REDUNDANT today — an earlier lane short-circuits before the fallback
# is reached — and are listed anyway so a future narrowing of SEC_KEYWORDS/UI/INFRA cannot silently
# reopen the roleless hole.
# WHAT "COMPLETE" DOES AND DOES NOT MEAN (#597 review round 2). The first form of this comment
# called the table "the one complete registry-area map"; nothing established that, and nothing in
# this repository can — the authoritative `area:*` inventory is the live repo's label set, which a
# pure self-test cannot read. So the claim is scoped to what IS verified: every area named by an
# AUTHORITATIVE in-repo source (SEC_KEYWORDS — asserted identical to routing.toml's trust-surface
# match_labels — plus UI_SURFACE_LABELS and INFRA_SURFACE_LABELS) is a key here with the role that
# source implies, cross-checked both ways by `_self_test`. That covers 8 of the 10 rows. The two
# residual rows (`usage`, `docs`) are reachable ONLY through this table and have no other source, so
# for them the pinned literal in `_self_test` IS the contract. An area outside the table fails
# closed either way (see _area_default), so an unlisted surface is never silently mis-routed — it
# simply is not derivable, which is the safe direction.
# `_self_test`
# asserts each entry AGREES with the lane that actually wins, so the redundancy can never drift, and
# (#597 review finding 3) pins this map — keys and values — to an INDEPENDENT literal plus a
# per-area lane attribution, so neither an added/removed row nor a re-pointed value can pass by
# supplying its own expectation. An area OUTSIDE this map makes the whole derivation fail closed
# (see _area_default): a surface the map cannot classify is unresolved, not absent.
# Trust-plane entries reference TRUST_PLANE_ROLE rather than a literal: #582 established that
# `role:soundness` DOES NOT EXIST in this repository, and that constant is the single place that
# decision lands. Hard-coding the literal here would let this table write a nonexistent label and
# reopen the very stranding hole #582 closed.
AREA_ROLE_DEFAULT = {
    # trust-plane script surfaces — SEC_KEYWORDS already forces the trust-plane role (stricter,
    # and it wins)
    "dispatch": TRUST_PLANE_ROLE, "worker": TRUST_PLANE_ROLE, "groom": TRUST_PLANE_ROLE,
    "review-loop": TRUST_PLANE_ROLE, "set-up-account": TRUST_PLANE_ROLE,
    # workflow/CI plumbing — INFRA_SURFACE_LABELS already derives `ci`
    "ci": "ci", "workflows": "ci",
    # the UI surface — UI_SURFACE_LABELS already derives `site`
    "dashboard": "site",
    # the residual registry surfaces, reachable ONLY through this table
    "usage": "impl", "docs": "docs",
}
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


def _area_default(labels):
    """The role ALL of the issue's `area:<value>` labels agree on; None whenever that cannot be
    established — the mapped areas disagree, no `area:*` label is present, or ANY `area:*` label is
    OUTSIDE the table.

    FAIL-CLOSED ON PARTIAL CLASSIFICATION TOO (#597 cross-provider review finding 1). The first
    form of this predicate SILENTLY DROPPED unmapped `area:*` labels and let the single mapped role
    win, so `["area:usage", "area:mystery"]` derived `impl`: an issue spanning one understood surface
    and one this map does not describe was admitted to `status:ready` under a role nobody chose for
    the unknown half. That is an admission predicate failing toward the PERMISSIVE side, which is
    the opposite of the posture the rest of this module holds — and it is the direction that hurts,
    because the fail-closed outcome (stay `status:untriaged` until a human labels it) is cheap and
    reversible while a mis-routed dispatch is not. An area this table cannot classify is an
    UNRESOLVED area, not an absent one."""
    areas = [lb[len("area:"):] for lb in labels if lb.startswith("area:")]
    if not areas:
        return None
    roles = set()
    for area in areas:
        if area not in AREA_ROLE_DEFAULT:
            return None
        roles.add(AREA_ROLE_DEFAULT[area])
    return next(iter(roles)) if len(roles) == 1 else None


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
    # [OPUS-5] issue #225: the area-derived default is the LAST resort, so an issue with no GitHub
    # type (or a type outside ROLE_BY_TYPE) still derives a role instead of silently becoming
    # undispatchable. Strictly a WIDENING — it fires only where the type map returned None, so no
    # existing derivation changes.
    return ROLE_BY_TYPE.get(issue_type) or _area_default(labels)


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

def apply_triage(current, result, edit, view, warn=None, read_state=None):
    """Apply a triage `result` to a live issue FAIL-CLOSED. Returns {"ok":bool,"warnings":[...]}.

    `edit(add, remove)` performs ONE label mutation and MUST RAISE on failure (never `|| true`);
    `view()` re-reads and returns the issue's live label set; optional `read_state()` returns
    ``(labels, revision)`` — the issue's label set AND an opaque revision token (its `updatedAt`).
    All are injected so the self-test drives the whole sequence against a fake GitHub.

    Sequence — the invariant is enforced by ORDER plus VERIFICATION, not by hope:
      1. the target `role:*` label is added FIRST and its presence VERIFIED by a re-read;
      2. no `role:*` strip is issued unless the target is verifiably in place — otherwise the
         strips are dropped from the plan and, if the projected post-state has no role at all,
         `status:ready` is withheld (the issue stays `status:untriaged`, which retriage recovers);
      3. the remaining adds/removes are applied;
      4. POST-CONDITION (REVISION-BOUND): the issue is re-read and must carry EXACTLY ONE `role:*`.

    Phase 4 is where PR #595 findings 3 + 4 land:
      * REVISION-BOUND verification. The old check verified ONE unbound snapshot, so a role
        deletion landing immediately after the read passed GREEN. The snapshot is now confirmed by
        a second read; if the labels or the revision token moved, the NEWER snapshot governs.
      * NO TERMINAL STATE. A violated post-condition is REPAIRED, never merely reported: zero roles
        restores the incumbent role; an AMBIGUOUS role set (e.g. a concurrent actor injecting
        `role:ci` during a docs->impl transition) is repaired down to the single intended role. If
        the intended role cannot be determined safely — or the repair does not land — `status:ready`
        is DEMOTED to `status:untriaged` so retriage (which only revisits `status:untriaged`) owns
        the issue. An ambiguous `status:ready` issue is otherwise terminal: route-resolve rejects it
        (AmbiguousRoleError), ready-issues keeps it ready, and retriage never looks at it.
    ok=False is returned on every violation, so the caller's exit status turns the workflow RED.
    """
    warns = list(result.get("warnings", ()))
    emit = warn or (lambda _m: None)

    def note(message):
        warns.append(message)
        emit(message)

    for message in warns:
        emit(message)
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
            note(f"role label add {target!r} FAILED ({exc}) — refusing to strip the existing "
                 f"role (registry #582)")
        else:
            if target in view():
                target_ok = True
            else:
                note(f"role label add {target!r} reported success but did NOT land — "
                     f"refusing to strip the existing role (registry #582)")
        add.discard(target)

    # 2. never strip the last/only role without a verified replacement.
    if role_rm and not target_ok:
        note(f"refusing to strip {sorted(role_rm)}: replacement {target!r} is not in place "
             f"(registry #582)")
        remove -= role_rm
        role_rm = set()
        ok = False
    projected_roles = (prev_roles - remove) | ({target} if target_ok else set())
    if not projected_roles:
        # THE INVARIANT: never status:ready with no role. Withhold the promotion instead.
        if "status:ready" in add or "status:ready" in current:
            note("withholding status:ready: the issue would have NO role:* label "
                 "(registry #582) — leaving it status:untriaged for retriage")
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
            note(f"label mutation failed ({exc}); post-condition check follows")
            ok = False

    # 4. POST-CONDITION — revision-bound re-read, then REPAIR (never leave a terminal state).
    reader = read_state if read_state else (lambda: (view(), None))

    def snapshot():
        """A CONFIRMED (labels, revision) reading: a second read decides whether the issue moved
        under us, and the NEWER state governs the verdict (PR #595 finding 4 — a single unbound
        snapshot let a post-read role deletion pass green)."""
        labels, revision = reader()
        labels2, revision2 = reader()
        if (revision2, sorted(labels2)) != (revision, sorted(labels)):
            note(f"issue moved during verification ({sorted(labels)} @{revision} -> "
                 f"{sorted(labels2)} @{revision2}); verifying against the NEWER snapshot")
            labels, revision = labels2, revision2
        return labels, revision

    def violation(labels):
        roles = _roles_of(labels)
        if not roles and "status:ready" in labels:
            return "zero-role"
        if len(roles) > 1:
            return "ambiguous-role"
        return None

    def repair_plan(problem, labels, attempt):
        """(add, remove) for ONE repair mutation. Attempt 1 repairs PRECISELY — restore the
        incumbent role, or drop the roles that are not the intended target. Attempt 2, and any case
        where the intended role is not determinable, DEMOTES status:ready -> status:untriaged so
        retriage revisits the issue instead of it sitting ready-and-undispatchable forever."""
        roles = _roles_of(labels)
        if problem == "zero-role" and attempt == 1 and prev_roles:
            note(f"POST-CONDITION VIOLATED (registry #582): status:ready with NO role:* label; "
                 f"restoring {sorted(prev_roles)}")
            return sorted(prev_roles), []
        if problem == "ambiguous-role" and attempt == 1 and target_ok and target in roles:
            note(f"POST-CONDITION VIOLATED (registry #582): ambiguous role set {sorted(roles)} "
                 f"survives triage (route-resolve would raise AmbiguousRoleError); REPAIRING to "
                 f"the single intended role {target!r}")
            return [], sorted(roles - {target})
        note(f"POST-CONDITION VIOLATED (registry #582): {problem} {sorted(roles)} cannot be "
             "repaired safely; DEMOTING status:ready -> status:untriaged so retriage owns it")
        return ["status:untriaged"], ["status:ready"]

    live, _revision = snapshot()
    for attempt in (1, 2):
        problem = violation(live)
        if problem is None:
            break
        ok = False
        fix_add, fix_remove = repair_plan(problem, live, attempt)
        fix_add = [lb for lb in fix_add if lb not in live]
        fix_remove = [lb for lb in fix_remove if lb in live]
        if not fix_add and not fix_remove:
            # Nothing left to mutate: the issue is already NOT status:ready, so it is retriageable
            # (retriage revisits status:untriaged) rather than terminal. Still ok=False.
            note(f"{problem} {sorted(_roles_of(live))} remains but the issue is not status:ready — "
                 "retriage will revisit it; no repair mutation is possible here")
            break
        try:
            edit(fix_add, fix_remove)
        except Exception as exc:                                  # noqa: BLE001
            note(f"REPAIR FAILED ({exc}) — issue needs manual repair (registry #582)")
            break
        live, _revision = snapshot()
    else:
        if violation(live) is not None:
            note(f"REPAIR DID NOT HOLD: {sorted(live)} still violates the single-role invariant — "
                 "issue needs manual repair (registry #582)")
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


def live_gh(repo, number, title="triage"):
    """Return the (read_state, view, edit, warn) quadruple bound to ONE live issue.

    SHARED by `triage.py --apply` and `retriage.py --apply` (PR #595 finding 3) so both mutate
    through the exact same fail-closed sequence in apply_triage. retriage used to send its adds AND
    removals through one opaque `gh issue edit` in the workflow shell — no add-first verification,
    no incumbent-role protection, and a post-read the shell could short-circuit past.

    READS go through the shared bounded-retry layer (gh_retry); the label MUTATION is
    SINGLE-ATTEMPT and FAIL-LOUD (gh_retry's hard scope rule: never replay a mutation).
    `read_state` returns (labels, revision) — the `updatedAt` token that makes apply_triage's
    post-condition revision-bound.
    """
    def read_state():
        out = _gh_read(["issue", "view", str(number), "-R", repo, "--json", "labels,updatedAt"])
        doc = json.loads(out)
        return {lb["name"] for lb in doc["labels"]}, doc.get("updatedAt")

    def view():
        return read_state()[0]

    def edit(add, remove):
        # A flag-less `gh issue edit <n> -R <repo>` is a USAGE ERROR, so an empty mutation must not
        # be issued at all. (The old `len(args) == 4` guard could never fire — the base argv is 5
        # tokens — so an empty edit would have raised a spurious mutation failure. apply_triage
        # happens to guard every call site, but the invariant belongs here; self-test pinned.)
        if not add and not remove:
            return
        args = ["issue", "edit", str(number), "-R", repo]
        for label in add:
            args += ["--add-label", label]
        for label in remove:
            args += ["--remove-label", label]
        proc = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or "").strip() or f"gh exited {proc.returncode}")

    def warn(message):
        print(f"::warning title={title} #{number}::{message}")

    return read_state, view, edit, warn


def _apply_cli(repo, number, issue_type):
    """`--apply`: read the live issue + label set, plan, and mutate fail-closed. Exit 1 loudly on
    any invariant/post-condition failure so the workflow step turns red instead of silently
    stranding the issue (the `|| true` per-label loop this replaces is exactly how #582 happened).
    """
    read_state, view, edit, warn = live_gh(repo, number)
    current = view()
    known = repo_label_set(repo)
    try:
        result = triage(current, issue_type, trusted=True, known_labels=known)
    except RoleInvariantError as exc:
        print(f"::error title=triage #{number}::{exc}")
        return 1
    outcome = apply_triage(current, result, edit, view, warn, read_state=read_state)
    print(f"triage #{number}: role={result['role']} ready={result['ready']} "
          f"add={sorted(result['add'])} remove={sorted(result['remove'])}")
    return 0 if outcome["ok"] else 1


def _repo_root():
    import os
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_sibling(filename, name):
    """Import a hyphenated sibling script (route-resolve.py, policy-resolve.py) by path."""
    import importlib.util
    import os
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(os.path.dirname(os.path.abspath(__file__)), filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# WORKFLOW/CLI SIGNATURE PINNING (PR #595 finding 2 — the TEST-VACUITY class). retriage.yml passed
# `--known-labels` to a parser that never declared it: a workflow-shaped invocation exited 2 with
# "unrecognized arguments", yet the enrolled suite was GREEN because every self-test called plan()
# DIRECTLY. The fix is not just the missing option — it is deriving the argument list under test
# from the WORKFLOW FILE, so a future workflow/CLI drift cannot hide behind a direct-call test.
# A bare `<` stdin redirect ends the argv too (#605 review round 2). It was missing, so
# `retriage.py --snapshot ... < pages.json > issues.jsonl` yielded an argv carrying the literal
# tokens `<` and the path — harmless for a "which flags are passed" assertion, fatal for a self-test
# that wants to REPLAY the workflow's own argv through main(). `<<<`/`<<` stay listed first so the
# heredoc forms still win at the same position.
_SHELL_STOP = re.compile(r"<<<|<<|<|\||>|;|&&|\)")


def workflow_argvs(workflow_path, script, subst=None):
    """Every ARGV a workflow passes to `scripts/<script>`, read from the workflow FILE.

    Shell line-continuations are joined, quotes stripped, and `$VAR` / `${VAR}` references replaced
    from `subst` (default: a `<var>` placeholder) so the list can be fed straight to a parser.
    Returns a list of token lists — one per invocation site. Used by BOTH triage.py's and
    retriage.py's self-tests.
    """
    import shlex
    subst = subst or {}
    # COMMENT lines are dropped first: this must read the workflow's EXECUTABLE invocations, and
    # both YAML and shell comments in these files legitimately quote example command lines.
    text = "\n".join(line for line in open(workflow_path, encoding="utf-8").read().splitlines()
                     if not line.strip().startswith("#")).replace("\\\n", " ")
    argvs = []
    for match in re.finditer(rf"scripts/{re.escape(script)}\s+([^\n]*)", text):
        tail = match.group(1)
        stop = _SHELL_STOP.search(tail)
        if stop:
            tail = tail[:stop.start()]
        tokens = []
        for token in shlex.split(tail, posix=True):
            for name in re.findall(r"\$\{?(\w+)\}?", token):
                token = re.sub(rf"\$\{{?{name}\}}?", subst.get(name, f"<{name.lower()}>"), token)
            tokens.append(token)
        argvs.append(tokens)
    return argvs


def declared_options(parser):
    """Every option string an argparse parser accepts — the other half of the pinning check."""
    return {option for action in parser._actions for option in action.option_strings}  # noqa: SLF001


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
    # The shared catalog pins every role this planner may derive. Every derivation source must
    # remain representable.
    derived_roles = set(ROLE_BY_KIND.values()) | set(ROLE_BY_TYPE.values()) | {
        _role([label], "task") for label in UI_SURFACE_LABELS + INFRA_SURFACE_LABELS
    } | set(AREA_ROLE_DEFAULT.values())
    chk("all derived roles have labels", derived_roles <= set(ROLE_LABELS), True)
    # Exact regression: applying the plan for a trust-surface issue which starts at role:impl
    # leaves exactly one representable role, never a transiently planned roleless end state.
    labels = {"role:impl", "area:worker", "priority:P2", "from:agent"}
    r = triage(labels)
    final_labels = (labels | r["add"]) - r["remove"]
    final_roles = {lb for lb in final_labels if lb.startswith("role:")}
    chk("trust role replacement is exactly-one", final_roles, {f"role:{TRUST_PLANE_ROLE}"})
    chk("trust role replacement plans no churn when the target is already present",
        (f"role:{TRUST_PLANE_ROLE}" in r["add"], "role:impl" in r["remove"]), (False, False))
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
    # [OPUS-5] issue #225: EVERY registry area derives a role even when the issue TYPE is unknown
    # (an untyped issue fell through `ROLE_BY_TYPE.get(...)` to None, and a roleless issue is
    # invisible to the dispatch enumerator).
    #
    # #597 review finding 3: the inventory AND the expectations used to come from AREA_ROLE_DEFAULT
    # itself — deleting an entry deleted its own test, and changing a value changed actual and
    # expected together — so it substantiated neither "the one complete registry-area map" nor the
    # redundancy claim in the table's comment. The map is therefore PINNED to an INDEPENDENT literal
    # here: adding, removing or re-pointing an area now requires editing this test deliberately.
    # (The trust-plane rows are pinned to TRUST_PLANE_ROLE by NAME on purpose — #582 established
    # that `role:soundness` does not exist and that constant is the single place that decision
    # lands; the "every derivable role is a real label" check below is what proves it names a label
    # this repository actually has.)
    chk("[#225] AREA_ROLE_DEFAULT is exactly this map (pinned independently of the table)",
        dict(sorted(AREA_ROLE_DEFAULT.items())),
        {"ci": "ci", "dashboard": "site", "dispatch": TRUST_PLANE_ROLE, "docs": "docs",
         "groom": TRUST_PLANE_ROLE, "review-loop": TRUST_PLANE_ROLE,
         "set-up-account": TRUST_PLANE_ROLE, "usage": "impl", "workflows": "ci",
         "worker": TRUST_PLANE_ROLE})

    # The table's comment claims the first three groups are REDUNDANT TODAY (an earlier lane
    # short-circuits before the fallback is reached) and that only the residual surfaces are
    # reachable THROUGH the table. That claim is now asserted, not asserted-about: this is which
    # lane actually decides each area for an untyped issue. A future narrowing of
    # SEC_KEYWORDS/UI/INFRA moves a row here and flips this check red — which is precisely the
    # drift the comment says the redundancy guards against.
    def _lane(area):
        label = f"area:{area}"
        if any(keyword in label for keyword in SEC_KEYWORDS):
            return "trust"
        if label in UI_SURFACE_LABELS:
            return "ui"
        if label in INFRA_SURFACE_LABELS:
            return "infra"
        return "fallback"

    # #597 review round 2: "the one complete registry-area map" was unsubstantiated — no
    # authoritative `area:*` inventory was compared, so the pinned literal above only proved the
    # table equals itself-as-written. There IS no in-repo inventory of every live label (the
    # authoritative source is the repo's label set, unreadable from a pure self-test), so the claim
    # is scoped in the table's comment AND the strongest available cross-reference is asserted here:
    # every area named by an authoritative in-repo source must be a KEY of the table carrying the
    # role that source implies, and — the other direction — the table must not claim a trust-plane
    # default for an area the trust-surface source does not name. SEC_KEYWORDS is itself asserted
    # IDENTICAL to routing.toml's trust-surface match_labels elsewhere in this suite, so this chains
    # to a real config file rather than to a duplicated expectation.
    # Keyed on the AREA, never on the role STRING: TRUST_PLANE_ROLE is currently the same literal
    # as the generic impl role (see the constant's own comment), so `value == TRUST_PLANE_ROLE`
    # cannot discriminate `area:usage` -> impl from a trust-plane row.
    _REGISTRY_TRUST_AREAS = ("dispatch", "worker", "set-up-account", "review-loop", "groom")
    chk("[#597 r2] every trust-surface AREA keyword is a mapped key, on the trust-plane role",
        (sorted(set(_REGISTRY_TRUST_AREAS) - set(SEC_KEYWORDS)),
         {area: AREA_ROLE_DEFAULT.get(area, "UNMAPPED") for area in _REGISTRY_TRUST_AREAS}),
        ([], {area: TRUST_PLANE_ROLE for area in _REGISTRY_TRUST_AREAS}))
    # ...and the OTHER direction, which is what actually detects drift: the partition of
    # SEC_KEYWORDS into registry AREAS vs crypto/domain keywords is pinned, so adding a new
    # trust-surface registry area to SEC_KEYWORDS (or to routing.toml, which SEC_KEYWORDS is
    # asserted identical to) turns this red until it is given a row above.
    chk("[#597 r2] SEC_KEYWORDS' non-area half is pinned, so a NEW trust area cannot slip past",
        sorted(set(SEC_KEYWORDS) - set(_REGISTRY_TRUST_AREAS)),
        ["auth", "crypto", "e2ee", "mpc", "security", "zk"])
    chk("[#597 r2] every UI/INFRA surface LABEL is a mapped area with that lane's role",
        {label[len("area:"):]: AREA_ROLE_DEFAULT.get(label[len("area:"):], "UNMAPPED")
         for label in UI_SURFACE_LABELS + INFRA_SURFACE_LABELS if label.startswith("area:")},
        {"dashboard": "site", "ci": "ci", "workflows": "ci"})
    chk("[#597 r2] ...and only `usage`/`docs` rest on the pinned literal alone",
        sorted(set(AREA_ROLE_DEFAULT)
               - set(_REGISTRY_TRUST_AREAS)
               - {label[len("area:"):] for label in UI_SURFACE_LABELS + INFRA_SURFACE_LABELS
                  if label.startswith("area:")}),
        ["docs", "usage"])
    chk("[#225] exactly which areas REACH the fallback (the rest short-circuit earlier)",
        {area: _lane(area) for area in sorted(AREA_ROLE_DEFAULT)},
        {"ci": "infra", "dashboard": "ui", "dispatch": "trust", "docs": "fallback",
         "groom": "trust", "review-loop": "trust", "set-up-account": "trust",
         "usage": "fallback", "workflows": "infra", "worker": "trust"})
    # Every row exercises the TABLE itself (not just the two rows that reach the fallback in
    # _role()), so a wrong value cannot hide behind an earlier lane...
    for _area, _want in sorted(AREA_ROLE_DEFAULT.items()):
        chk(f"_area_default resolves area:{_area} through the table",
            _area_default([f"area:{_area}"]), _want)
    # ...and each area still derives the SAME role end to end through triage(), so the table can
    # never disagree with the lane that actually wins.
    for _area, _want in sorted(AREA_ROLE_DEFAULT.items()):
        chk(f"area:{_area} derives a role when untyped",
            triage(["priority:P2", f"area:{_area}"], "")["role"], _want)
    # the consequence that matters: such an issue is now READY (it was parked status:untriaged and
    # never entered any dispatch plan).
    r = triage(["priority:P2", "area:usage"], "")
    chk("untyped registry issue becomes ready", (r["ready"], "role:impl" in r["add"]), (True, True))
    # AMBIGUOUS area defaults -> no role at all (fail closed), never an arbitrary pick.
    chk("conflicting area defaults -> no role",
        triage(["priority:P2", "area:usage", "area:docs"], "")["role"], None)
    # #597 review finding 1: a MIXED mapped/unmapped area set is ALSO ambiguous. The first form let
    # the one mapped role win here (`impl`) — an admission predicate failing toward the permissive
    # side on PARTIAL classification. Non-vacuous: it derived "impl" before the fix, and the issue
    # therefore went `status:ready` under a role nobody chose for its unknown surface.
    chk("[#597] mapped + UNMAPPED area -> no role (partial classification fails closed)",
        (triage(["priority:P2", "area:usage", "area:mystery"], "")["role"],
         triage(["priority:P2", "area:usage", "area:mystery"], "")["ready"]),
        (None, False))
    chk("[#597] and _area_default itself refuses the mixed set, in both label orders",
        (_area_default(["area:usage", "area:mystery"]),
         _area_default(["area:mystery", "area:usage"]),
         _area_default(["area:usage", "area:usage"]),
         _area_default(["area:"]), _area_default([])),
        (None, None, "impl", None, None))
    # the area default is LAST: an explicit role, a kind, the UI/infra lanes and the type map win.
    chk("type map wins over area default",
        triage(["priority:P3", "area:usage"], "spike")["role"], "research")
    chk("explicit role wins over area default",
        triage(["priority:P2", "role:research", "area:usage"], "")["role"], "research")
    chk("kind wins over area default",
        triage(["priority:P2", "kind:docs", "area:usage"], "")["role"], "docs")
    # an unknown area is NOT invented into a role — an untyped, unmapped issue stays untriaged.
    chk("unknown area derives nothing", triage(["priority:P2", "area:mystery"], "")["role"], None)
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
    chk("catalog == the pinned live role labels",
        {f"role:{role}" for role in ROLE_LABELS},
        {label for label in REAL if label.startswith("role:")})
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
    # AREA_ROLE_DEFAULT (#225) is a THIRD producer of role labels, so it belongs in this existence
    # check alongside the kind/type maps — a table entry naming a label the repo lacks strands the
    # issue exactly as the #582 root cause did. Non-vacuous: with the pre-merge literal
    # `"soundness"` entries restored, this goes red.
    chk("every derivable role is a real label",
        sorted({f"role:{v}" for v in list(ROLE_BY_KIND.values()) + list(ROLE_BY_TYPE.values())
                + list(AREA_ROLE_DEFAULT.values())
                + [TRUST_PLANE_ROLE, "site", "ci"]} - REAL), [])
    # POSTURE: TRUST_PLANE_ROLE is only safe because routing.toml's Phase-1 security keywords are
    # IDENTICAL to SEC_KEYWORDS, so every trust-plane match is human-armed/opus-routed regardless
    # of which role label it carries. If someone edits either list, this check goes red.
    try:
        import tomllib
    except ModuleNotFoundError:                                   # pragma: no cover
        import tomli as tomllib
    import os
    root = _repo_root()                     # cwd-independent: the gate runs from the repo root, a
    doc = tomllib.load(open(os.path.join(root, "orchestration/routing.toml"), "rb"))  # dev may not
    sec_rules = [route for route in doc.get("route", []) if "match_labels" in route]
    chk("SEC_KEYWORDS == routing.toml security match_labels (posture invariant)",
        sorted(SEC_KEYWORDS), sorted({k for rule in sec_rules for k in rule["match_labels"]}))
    chk("the security route human-escalates + runs the soundness chain",
        [(rule["model_chain"], rule["agent"], bool(rule.get("escalate"))) for rule in sec_rules],
        [(["opus5"], "registry-reviewer", True)])
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
    # An explicit role on a NON-trust surface reaches the same live-label check. It is preserved
    # verbatim and diagnosed when the repository does not have that label; a static catalog must
    # never silently pre-empt this fail-closed path.
    fixture = {"priority:P2", "role:soundness", "area:docs"}
    r = triage(fixture, "task", known_labels=REAL)
    warning = r["warnings"][0] if r["warnings"] else ""
    chk("[#582] missing explicit role is preserved and warned on a non-trust surface",
        (r["role"], _roles_of((fixture | r["add"]) - r["remove"]), len(r["warnings"]),
         "role:soundness" in warning),
        ("soundness", {"role:soundness"}, 1, True))
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
        """A GitHub that drops adds of labels outside `known` — the live #582 failure mode.

        `rev` models the issue's `updatedAt` revision token (bumped by every mutation) so the
        revision-bound post-condition (PR #595 finding 4) can be driven from a fixture.
        """

        def __init__(self, labels, known):
            self.labels, self.known, self.calls = set(labels), set(known), []
            self.rev = 0

        def edit(self, add, remove):
            self.calls.append(("edit", sorted(add), sorted(remove)))
            before = set(self.labels)
            for label in add:
                if label not in self.known:
                    raise RuntimeError(f"'{label}' not found")
                self.labels.add(label)
            self.labels -= set(remove)
            if self.labels != before:
                self.rev += 1

        def read_state(self):
            self.calls.append(("read_state",))
            return set(self.labels), self.rev

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
    out = apply_triage(set(gh.labels), plan, gh.edit, gh.view, read_state=gh.read_state)
    chk("[#582] happy path: one role, ready, ok",
        (out["ok"], _roles_of(gh.labels), "status:ready" in gh.labels,
         "status:untriaged" in gh.labels),
        (True, {f"role:{TRUST_PLANE_ROLE}"}, True, False))

    # -----------------------------------------------------------------------------------------------
    # [PR #595 finding 4] A CONCURRENT EDIT MUST NOT STRAND A TERMINAL AMBIGUOUS ISSUE.
    # Injecting role:ci during a docs->impl transition used to leave {status:ready, role:impl,
    # role:ci}: apply_triage reported failure but the issue stayed LIVE and undispatchable —
    # route-resolve raises AmbiguousRoleError on it, ready-issues keeps it ready, and retriage only
    # revisits status:untriaged, so NOTHING recovers it. The post-condition must now REPAIR it down
    # to the single intended role. Non-vacuous: the pre-fix phase 4 only warned, so gh.labels kept
    # BOTH roles here.
    class InjectingGh(FakeGh):
        """A concurrent actor adds `role:ci` the moment the role transition lands."""

        def __init__(self, labels, known):
            super().__init__(labels, known)
            self.injected = False

        def edit(self, add, remove):
            super().edit(add, remove)
            if not self.injected and any(lb.startswith(ROLE_PREFIX) for lb in add):
                self.injected = True
                self.labels.add("role:ci")
                self.rev += 1

    start = {"priority:P1", "role:docs", "area:dispatch", "status:untriaged"}
    gh = InjectingGh(start, REAL)
    plan = triage(start, "task", known_labels=REAL)
    out = apply_triage(set(start), plan, gh.edit, gh.view, read_state=gh.read_state)
    chk("[#595 f4] a concurrently injected role is REPAIRED to the single intended role",
        (out["ok"], _roles_of(gh.labels), "status:ready" in gh.labels),
        (False, {f"role:{TRUST_PLANE_ROLE}"}, True))
    chk("[#595 f4] the ambiguity repair is reported loudly",
        any("ambiguous role set" in w and "REPAIRING to the single intended role" in w
            for w in out["warnings"]), True)
    # ... and when the intended role CANNOT be determined safely, the issue is DEMOTED to
    # status:untriaged (which retriage revisits) instead of being left ready-and-ambiguous.
    ambiguous = {"priority:P1", "role:docs", "role:research", "area:usage", "status:ready"}
    gh = FakeGh(ambiguous, REAL)
    out = apply_triage(set(ambiguous), {"add": set(), "remove": set(), "ready": True, "role": None,
                                        "warnings": []}, gh.edit, gh.view,
                       read_state=gh.read_state)
    chk("[#595 f4] an unrepairable ambiguity DEMOTES status:ready -> status:untriaged",
        (out["ok"], _roles_of(gh.labels), "status:ready" in gh.labels,
         "status:untriaged" in gh.labels),
        (False, {"role:docs", "role:research"}, False, True))
    # the demoted issue is genuinely retriageable: triage() now plans it down to ONE role.
    demoted = triage(gh.labels, "task", known_labels=REAL)
    chk("[#595 f4] the demoted issue is repairable by the next triage/retriage pass",
        _roles_of((set(gh.labels) | demoted["add"]) - demoted["remove"]), {"role:impl"})

    # [PR #595 finding 4] the final verification is REVISION-BOUND: a role deletion landing right
    # AFTER the snapshot must not pass green. Non-vacuous: with a single unbound read (the pre-fix
    # code) this fixture returns ok=True with NO role label on a status:ready issue — the exact #582
    # terminal state, certified green.
    class RacyGh(FakeGh):
        """A concurrent actor deletes every role label immediately AFTER the verification read."""

        def __init__(self, labels, known):
            super().__init__(labels, known)
            self.reads = 0

        def read_state(self):
            self.reads += 1
            state = (set(self.labels), self.rev)
            if self.reads == 1:                  # lands between the read and the verdict
                self.labels -= _roles_of(self.labels)
                self.rev += 1
            return state

    gh = RacyGh(start, REAL)
    plan = triage(start, "task", known_labels=REAL)
    out = apply_triage(set(start), plan, gh.edit, gh.view, read_state=gh.read_state)
    chk("[#595 f4] a post-snapshot role deletion is CAUGHT (revision-bound) and restored",
        (out["ok"], _roles_of(gh.labels)), (False, {"role:docs"}))
    chk("[#595 f4] the moved revision is reported",
        any("moved during verification" in w for w in out["warnings"]), True)

    # -----------------------------------------------------------------------------------------------
    # [PR #595 finding 1] EVERY PRODUCER OF TRUST_PLANE_ROLE RESOLVES TO AN ESCALATED CHAIN.
    # The posture argument for TRUST_PLANE_ROLE = "impl" (see the constant's comment) is only true
    # if the label expression that FORCED the trust-plane role is itself matched by Phase 1 of the
    # resolvers. `kind:security` was NOT: it mapped to TRUST_PLANE_ROLE via ROLE_BY_KIND while
    # matching no SEC_KEYWORD, so {priority:P1, area:usage, kind:security} resolved to
    # (["sol","opus5","fable","opus"], registry-impl, escalate=FALSE) in BOTH resolvers — security
    # work on an auto-armable chain, and the old pinning test never looked at this consumer.
    # Enumerated PROGRAMMATICALLY from the mappings, end-to-end through triage -> the post-triage
    # label set -> route-resolve.resolve AND policy-resolve.resolve, so a new trust-plane kind (or a
    # widened SEC_KEYWORDS) that Phase 1 does not cover turns this RED.
    route_resolve = load_sibling("route-resolve.py", "registry_route_resolve")
    policy_resolve = load_sibling("policy-resolve.py", "registry_policy_resolve")
    policy_doc = tomllib.load(open(os.path.join(root, "policy/repos.toml"), "rb"))
    SELF_REPO = "jeswr/agent-account-registry"
    SOUNDNESS = (["opus5"], "registry-reviewer", True)

    def resolved(labels):
        """(derived role, route-resolve verdict, policy-resolve verdict) for a POST-TRIAGE label
        set — the real consumer chain: triage writes the labels, both resolvers read them."""
        result = triage(labels, "task", known_labels=REAL)
        post = (set(labels) | result["add"]) - result["remove"]
        row = policy_resolve.resolve(SELF_REPO, post, policy_doc, doc)
        return (result["role"], route_resolve.resolve(post, doc),
                (row["model_chain"], row["agent"], row["escalate"]))

    # the review's EXACT fixture: a trust-plane KIND on a non-trust area.
    chk("[#595 f1] {P1, area:usage, kind:security} escalates in BOTH resolvers",
        resolved(["priority:P1", "area:usage", "kind:security"]),
        (TRUST_PLANE_ROLE, SOUNDNESS, SOUNDNESS))
    # the ROLE_BY_KIND entries that denote trust-plane work are EXACTLY TRUST_PLANE_KINDS, so a new
    # kind mapped to TRUST_PLANE_ROLE cannot escape the enumeration below.
    chk("[#595 f1] TRUST_PLANE_KINDS == the ROLE_BY_KIND entries mapped to the trust-plane role",
        sorted(kind for kind, value in ROLE_BY_KIND.items() if value == TRUST_PLANE_ROLE),
        sorted(TRUST_PLANE_KINDS))
    for kind in sorted(TRUST_PLANE_KINDS):
        label = f"kind:{kind}"
        chk(f"[#595 f1] {label} is a Phase-1 trigger (a SEC_KEYWORD is a substring of it)",
            any(keyword in label for keyword in SEC_KEYWORDS), True)
        chk(f"[#595 f1] {label} derives the trust-plane role AND escalates in both resolvers",
            resolved(["priority:P1", "area:usage", label]),
            (TRUST_PLANE_ROLE, SOUNDNESS, SOUNDNESS))
    # the OTHER producer of TRUST_PLANE_ROLE: every SEC_KEYWORD, on a representative area label.
    for keyword in sorted(SEC_KEYWORDS):
        chk(f"[#595 f1] area:{keyword} derives the trust-plane role AND escalates in both resolvers",
            resolved(["priority:P1", f"area:{keyword}"]),
            (TRUST_PLANE_ROLE, SOUNDNESS, SOUNDNESS))
    # DISCRIMINATION: the enumeration above is not vacuously true — a NON-trust-plane kind must NOT
    # escalate (otherwise the check would pass even if every issue were force-escalated).
    # [OPUS-5] `kind:research` was the second sample here and now escalates BY DESIGN: the
    # 2026-07-26 deprecation collapsed role=research to a single rung (opus5), and a one-rung
    # chain with no `escalate` has no exit at all — on an opus5 outage it could only defer
    # forever with no human notified. It is replaced by `kind:site`, which is still a genuine
    # non-escalating route, so the discrimination remains real rather than being dropped.
    chk("[#595 f1] a non-trust-plane kind is NOT escalated (the enumeration discriminates)",
        [resolved(["priority:P1", "area:usage", "kind:docs"])[1][2],
         resolved(["priority:P1", "area:usage", "kind:site"])[1][2]], [False, False])
    # ...and research DOES escalate now — asserted so the change above is a pinned decision, not
    # an unnoticed side effect of the deprecation.
    chk("[OPUS-5] role:research escalates (single-rung chain must have a human exit)",
        resolved(["priority:P1", "area:usage", "kind:research"])[1][2], True)

    # -----------------------------------------------------------------------------------------------
    # [PR #595 finding 2] THE ARGV ENTRYPOINT IS PINNED TO THE WORKFLOW'S OWN ARGUMENT LIST.
    # Every check above calls triage()/apply_triage() DIRECTLY, so a CLI/workflow signature drift is
    # invisible to them — exactly how retriage.yml shipped `--known-labels` against a parser that
    # never declared it (exit 2 live, enrolled suite green). Derived from the workflow FILE so it
    # cannot drift back.
    triage_wf = os.path.join(root, ".github/workflows/triage-issue.yml")
    argvs = workflow_argvs(triage_wf, "triage.py", {"REPO": "o/r", "NUM": "7"})
    options = declared_options(build_parser())
    chk("[#595 f2] triage-issue.yml invokes scripts/triage.py at least once", len(argvs) >= 1, True)
    chk("[#595 f2] every flag triage-issue.yml passes is DECLARED by the parser",
        sorted({token for argv in argvs for token in argv
                if token.startswith("--")} - options), [])
    apply_argv = next((argv for argv in argvs if "--apply" in argv), None)
    chk("[#595 f2] the workflow's --apply invocation is present", apply_argv is not None, True)
    dispatched = {}
    real_apply_cli = globals()["_apply_cli"]
    globals()["_apply_cli"] = lambda repo, number, issue_type: dispatched.update(
        repo=repo, number=number, type=issue_type) or 0
    try:
        code = main(list(apply_argv or []))
    finally:
        globals()["_apply_cli"] = real_apply_cli
    chk("[#595 f2] the workflow-shaped ARGV parses and reaches _apply_cli with its values",
        (code, dispatched), (0, {"repo": "o/r", "number": "7", "type": "task"}))
    # the pure (non---apply) CLI path also round-trips, --known-labels included.
    import contextlib
    import io
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(["--labels", "priority:P1,role:docs,area:dispatch",
                     "--known-labels", ",".join(sorted(REAL)), "--type", "task"])
    chk("[#595 f2] the --labels/--known-labels ARGV path exits 0 and plans the swap",
        (code, "ADD: " in buffer.getvalue(),
         f"role:{TRUST_PLANE_ROLE}" in buffer.getvalue()), (0, True, True))

    # -----------------------------------------------------------------------------------------------
    # [PR #595 finding 5] THE QUARANTINE LABEL WRITE IS FAIL-LOUD. `gh issue edit ... || true` on the
    # trust:untrusted/status:untriaged write meant a failed mutation left third-party content
    # UN-QUARANTINED while the job reported success — the worst failure mode on this surface, and
    # invisible to retriage (which only revisits status:untriaged). Pinned statically so it cannot
    # regress: the label mutation carries no `|| true`, the step runs under `set -e`, and a post-read
    # proves both labels landed. (Only the courtesy comment may be best-effort.)
    quarantine = re.search(r"\n {6}- name: Quarantine.*?(?=\n {6}- name: |\Z)",
                           "\n".join(line for line in open(triage_wf, encoding="utf-8").read()
                                     .splitlines() if not line.strip().startswith("#")), re.S)
    quarantine_body = quarantine.group(0) if quarantine else ""
    chk("[#595 f5] the quarantine step exists and runs under set -e",
        bool(quarantine_body) and "set -euo pipefail" in quarantine_body, True)
    chk("[#595 f5] no `|| true` on the quarantine LABEL mutation",
        [line.strip() for line in quarantine_body.splitlines()
         if "issue edit" in line and "|| true" in line], [])
    chk("[#595 f5] the quarantine labels are verified by a post-read before success",
        all(token in quarantine_body for token in ("--json labels", "trust:untrusted",
                                                   "refusing to report success")), True)

    # -----------------------------------------------------------------------------------------------
    # THE LIVE `gh` ARGV live_gh builds (shared by triage --apply and retriage --apply): an EMPTY
    # mutation must issue NO call at all — `gh issue edit <n> -R <repo>` with no flags is a usage
    # error, so emitting it would report a spurious mutation failure and drive the post-condition's
    # repair path over a healthy issue. Stubbed subprocess; no live gh.
    calls = []
    real_run = subprocess.run
    try:
        subprocess.run = lambda cmd, **kwargs: calls.append(list(cmd)) or (
            __import__("subprocess").CompletedProcess(cmd, 0, stdout="", stderr=""))
        _rs, _view, live_edit, _warn = live_gh("o/r", 7)
        live_edit([], [])
        chk("an empty label mutation issues NO gh call", calls, [])
        live_edit(["role:impl"], ["role:docs"])
    finally:
        subprocess.run = real_run
    chk("the label mutation argv is one `gh issue edit` with per-label flags",
        calls, [["gh", "issue", "edit", "7", "-R", "o/r", "--add-label", "role:impl",
                 "--remove-label", "role:docs"]])

    print("triage self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def build_parser():
    """The CLI contract. Built by a named function so the self-test can assert that every flag
    .github/workflows/triage-issue.yml passes is actually DECLARED here (PR #595 finding 2)."""
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
    return ap


def main(argv=None):
    ap = build_parser()
    a = ap.parse_args(argv)
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
