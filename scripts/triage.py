#!/usr/bin/env python3
# Registry self-management: static (no-LLM) issue triage for jeswr/agent-account-registry.
# Modeled on the sparq target's scripts/triage.py, adjusted for the registry's area:* sections and
# its trust-surface soundness lane. Applied by .github/workflows/triage-issue.yml.
"""triage.py — the deterministic, no-LLM part of issue triage.

Given an issue's labels + type, decide the labels to ADD/REMOVE and whether it is triage-complete:
  * role     — from a `kind:*` label, the issue type, or (last resort, issue #225) the issue's
               `area:*` default; a trust-surface area forces the trust-plane role (see
               TRUST_PLANE_ROLE).
  * priority — a stated valid single `priority:P0..P4` is authoritative and never touched;
               otherwise one is DERIVED at the BOTTOM of the range (`derive_priority`), so a
               derived priority can never outrank a stated one. An issue carrying an UNREADABLE
               stated priority (two labels, or one out of range) is declined, not overwritten.
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
# STATUSES TRIAGE DOES NOT OWN — the `status:ready` promotion is WITHHELD while one is live.
#
# `status:ready` carries TWO meanings that this repository never separated:
#   (a) triage's CLASSIFICATION attestation — "this issue has a role, a priority and an area";
#   (b) the dispatcher's ORCHESTRATION posture — "no lane is holding this issue".
# triage() is the sole author of (a) and has no business asserting (b): `status:deferred` belongs
# to dispatch-claim's bounded retry lane, the in-progress pair to a live claim/lease, and
# `status:parked` to park_policy. While any of them is live, (b) is FALSE, so writing the label
# does not attest anything — it manufactures a contradictory pair.
#
# MEASURED (registry #1054, 2026-07-28, live board, 460 open issues): 30 of the 32 open
# `status:ready` issues ALSO carried `status:deferred`, and the census of the LAST `status:ready`
# addition on each of those 30 says 30/30 were created by adding `status:ready` to an issue that
# ALREADY carried `status:deferred` — 24 of them by `github-actions[bot]` (this workflow) on that
# one day, 6 by the maintainer on 2026-07-18. Not one arose the other way round.
#
# The trigger is `triage-issue.yml`'s `[labeled, unlabeled]` types (#607). The dispatcher defers an
# issue as three App-token writes (+status:deferred, -status:in-progress, -status:ready); the App's
# token is NOT the repository GITHUB_TOKEN, so those events DO start a run, and 18-21s later this
# classifier — which reads only role/priority/area/needs/kind — re-stamps `status:ready` over the
# defer that just happened. Verbatim from #1037's timeline:
#     16:27:04 labeled   status:deferred    by sparq-orchestrator[bot]
#     16:27:06 unlabeled status:ready       by sparq-orchestrator[bot]
#     16:27:27 labeled   status:ready       by github-actions[bot]      <- here
#
# The resulting pair is invisible to BOTH lanes — `status:deferred` is in `ready-issues.BUSY_STATUS`
# so the ready lane refuses it, and dispatch.yml's deferred-retry candidate filter skipped any row
# already carrying `status:ready` on the (false) premise that the ready lane owned it. Each lane
# excluded it believing the other had it, so the board's dispatchable frontier was EMPTY.
#
# WITHHOLD, never STRIP. This branch declines to ADD the label; it never removes one that is
# already there. Removing it would silently revert a deliberate human gesture (the 6 rows above are
# exactly that: the maintainer re-attesting readiness on a stuck deferred issue), and a classifier
# firing on an unrelated `labeled` event is the wrong actor to retract someone else's attestation.
# The pair that a human writes is instead HANDLED, by the deferred-retry lane in dispatch.yml.
#
# `status:untriaged` is deliberately ABSENT: it is triage's OWN label, the assertion that nothing
# has classified this issue yet, and clearing it is in scope precisely because triage wrote it.
# The `else` (not-classification-complete) branch is untouched — it was implicated in 0 of the 30.
DISPATCHER_OWNED_STATUS = frozenset({
    "status:deferred",            # dispatch-claim bounded retry lane (locked decision 20)
    "status:in-progress",         # a live claim/lease
    "status:in-progress-review",  # a published worker PR cycling through review
    "status:parked",              # park_policy.py machine capacity park
    "status:blocked",             # groom/curator hold
})

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
# [#598] The type assumed when a CALLER SAYS NOTHING AT ALL — the `triage()` signature default and
# the `--type` CLI default, i.e. hand-runs and direct in-process calls. It is NOT what an issue
# GitHub reports as untyped resolves to: that is `""`, which `_role` deliberately falls through to
# the area map (#225's decided semantics; `normalize_issue_type`).
#
# THE #598 DEFECT this names: both triage callers used to pass this string as a LITERAL —
# `triage-issue.yml` ran `--type task`, `retriage.plan()` called `classify(labels, "task", ...)` —
# so `ROLE_BY_TYPE["task"]` ALWAYS resolved, whatever the issue's real type was, and
# AREA_ROLE_DEFAULT (#225) was defence-in-depth that could not fire in production. Both callers now
# pass the issue's REAL GitHub type, so an untyped issue and a type outside ROLE_BY_TYPE both reach
# the area map, which is what #225 built it for.
DEFAULT_ISSUE_TYPE = "task"


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


# ---------------------------------------------------------------------------------------------------
# [OPUS-5] PRIORITY DERIVATION — the classifier's own missing input (sparq#4809).
#
# THE DEFECT. `_role` has a five-rung derivation ladder ending in a type/area default, so a role is
# almost always produced. Priority had NO derivation at all: it was read, never written. That
# asymmetry is the whole bug. `triage()` declares `ready` only when a valid `priority:P0..P4` is
# ALREADY present, and it is the only writer `retriage.py --apply` has, so an issue opened without
# one was TERMINAL — and `status:untriaged` is itself a busy state in both engines
# (`ready-issues.BUSY_STATUS`, dispatch-claim), so such an issue is not merely unlabelled, it is
# excluded from the frontier entirely. scripts/triage-stock-alert.py already names this exactly:
# `classifier-incomplete` is a FIXED POINT, "the classifier cannot produce its own missing input",
# measured at 263 of 274 stuck issues missing `priority:*`. retriage.yml has reported success on
# every scheduled run for two weeks while that population grew.
#
# THE TENSION, AND WHY THE VALUE IS P4 AND NOT P3. A blanket mid-range default really does destroy
# prioritisation: `ready-issues.compute_ready` sorts candidates by `(priority, number)`, so a
# default that lands ABOVE the bottom rung displaces hand-triaged work and P0 loses its lane. The
# resolution is not to classify more cleverly, it is to pick the one value that CANNOT displace
# anything. `DERIVED_PRIORITY` is the bottom of the range, so:
#
#     A DERIVED PRIORITY CAN NEVER OUTRANK A STATED ONE.
#
# That is an ordering invariant, checked directly in `_self_test`, not a heuristic that happens to
# behave. It also means P4 here is NOT a guess about urgency — guessing is what a mid-range default
# does. It is the true statement "no human has prioritised this", rendered in the only vocabulary
# the frontier reads, and ordered last accordingly. A derived-P4 issue can only ever be selected
# when its partition is otherwise idle, i.e. when the alternative was dispatching nothing at all.
#
# DELIBERATELY NOT A `needs:priority` GATE. The obvious alternative — mark the absence loud with a
# new `needs:*` label — is the one shape that is definitely wrong here, and this repo has already
# paid for learning it. `retriage.plan()` skips every `needs:*`-gated issue BEFORE it classifies,
# so minting such a gate would strand the issue behind a door the sweep itself refuses to open;
# retriage.py declines to mint `needs:area` for precisely that reason ("re-creating the exact hole
# #586 closes"). A gate would convert silent invisibility into loud invisibility, which is not the
# outcome being bought.
#
# WHAT IS DECLINED. Exactly one class, and it is the class where writing would DESTROY information:
# an issue that already carries a `priority:*` label the engine cannot read — two of them, or one
# out of range. There a human HAS expressed intent and the machine simply cannot recover it, so
# overwriting it with the floor would silently discard a possible P0. Those keep their labels
# untouched and stay out of the frontier, and the contradiction is visible on the issue itself.
# This is a small population by construction, and that is the honest outcome, not a hedge: with a
# bottom-of-range floor there is no OTHER class where declining beats ordering-last, because the
# floor makes no claim that could be wrong.
DERIVED_PRIORITY = "priority:P4"


def derive_priority(labels):
    """(label_to_add | None, reason, labels_to_remove). Never overrides a stated priority.

    reason ∈ {"stated", "floor-retracted", "stated-unreadable", "ready-attested-regression",
    "unprioritised-floor"}. Only the last one writes; only `floor-retracted` removes.
    """
    if _valid_priority(labels):
        return None, "stated", frozenset()          # a human's priority is authoritative
    valid = {lb for lb in labels if _PRIO.match(lb)}
    if DERIVED_PRIORITY in valid and len(valid) == 2:
        # ---- THE RETRACT RUNG (PR #1053 review) — WITHOUT THIS, THE FLOOR CREATES THE CLASS IT
        # ---- FIXES, ON THE MAJORITY PATH.
        # `triage-issue.yml` fires on `opened`, so the floor lands within a second or two of
        # creation. But a priority usually arrives LATER: measured on this board, 16 of the 30 most
        # recent prioritised open issues (53%) were priority-labelled more than 90s after creation,
        # almost all by `sparq-orchestrator[bot]` — which will not strip a floor it did not write.
        # Two valid priorities make `_valid_priority` return False, so without this rung that
        # perfectly ordinary sequence (open -> floored -> labelled P1) DEMOTED the issue off the
        # frontier and left it there until a human manually removed `priority:P4`.
        #
        # The ordering invariant was never wrong — a derived priority still cannot OUTRANK a stated
        # one — but the argument was about outranking and the effect was about BLOCKING. Those are
        # different failures and only the first was guarded.
        #
        # So: exactly the floor plus exactly ONE other valid rank means the floor is ours and the
        # other is authoritative. Retract the floor and keep theirs. This converges in one tick and
        # cannot oscillate: the post-state has a single valid priority, which returns "stated"
        # above and derives nothing further.
        #
        # DELIBERATELY NOT EXTENDED to a pair with no floor in it (P1+P2): that ambiguity is
        # genuine, is a human's to resolve, and stays declined below. The residual case this rung
        # DOES decide against a human is a deliberate `priority:P4` plus a second actor's
        # `priority:P1` — indistinguishable from ours, since the floor carries no provenance. That
        # pair was already ambiguous-and-stuck before this change, so resolving it toward the
        # non-floor value is strictly better than the status quo, not a new loss.
        return None, "floor-retracted", frozenset({DERIVED_PRIORITY})
    if any(lb.startswith("priority:") for lb in labels):
        return None, "stated-unreadable", frozenset()   # DECLINE: ambiguous/out-of-range, human's
    if "status:ready" in labels:
        # DECLINE — THE LABEL-REGRESSION LANE (#586), and the one rung this derivation cannot go
        # without. `triage()` only ever attests `status:ready` on an issue that HAD a valid
        # priority, so a `status:ready` issue with no readable priority did not arrive here
        # unprioritised: it LOST one. Flooring it would overwrite a human's P0..P3 with P4 and,
        # worse, is not even stable — retriage's re-park lane exists so a human restores the real
        # value, and a restored `priority:P2` landing next to a derived `priority:P4` is an
        # AMBIGUOUS pair, i.e. permanently stuck. This decline is what keeps the #586 re-park lane
        # intact; the "lost priority is re-parked" and "ROUND TRIP" fixtures in retriage.py's
        # self-test fail without it, which is how it was found.
        return None, "ready-attested-regression", frozenset()
    return DERIVED_PRIORITY, "unprioritised-floor", frozenset()


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
    # [#598] `issue_type` is now the issue's REAL type (normalized by `normalize_issue_type` in
    # `triage()`), not the literal `task` both callers used to hard-code — which is what makes this
    # line reachable in production at all. It fires for an UNTYPED issue (`""`) and for any type
    # GitHub reports that ROLE_BY_TYPE does not name; a mapped type still short-circuits above it.
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


def normalize_issue_type(raw):
    """GitHub's issue-type NAME -> a ROLE_BY_TYPE key. THE one definition (#598).

    GitHub renders the type as a DISPLAY name (`"Bug"`, `"Documentation"`) while ROLE_BY_TYPE is
    keyed lower-case, so this lower-cases and strips. Every shape carrying no usable name — `None`
    (how GitHub renders an issue with NO type), `""`, whitespace, and any non-string (a raw
    `{"name": …}` object handed in by mistake, schema drift) — collapses to `""`, which `_role`
    already treats as "no type": `ROLE_BY_TYPE.get("")` is None, so the derivation falls through to
    the area map. That is #225's decided semantics, unchanged here — #598 changes the CALLERS, not
    this contract.

    The case fold is a FIX, not cosmetics: before #598 nothing lower-cased, so a real GitHub `Bug`
    would have missed `ROLE_BY_TYPE["bug"]` and silently derived its role from the area map instead
    — a typed issue treated as untyped. Both directions are pinned by `_self_test`.
    """
    return raw.strip().lower() if isinstance(raw, str) else ""


def triage(labels, issue_type=DEFAULT_ISSUE_TYPE, trusted=True, known_labels=None):
    """Return {add:set, remove:set, ready:bool, role:str|None, warnings:list}.

    `issue_type` is the issue's RAW GitHub type NAME (#598) — display-cased, `""`/None when the
    issue has no type. Normalized here, ONCE, by `normalize_issue_type`, so every caller (the
    `--type` CLI, retriage's planner, a direct call) gets the same mapping and no caller has to
    remember to lower-case. An untyped issue derives its role from its `area:*` (issue #225).

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
        return {"add": set(), "remove": set(), "ready": False, "role": None, "warnings": [],
                "priority_reason": "untrusted"}
    role = _role(labels, normalize_issue_type(issue_type))
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
    # The derived priority is part of the label set the rest of this function reasons over, exactly
    # as a derived `role:*` is — `effective`, not `labels`, is what "does this issue have a
    # priority" now means. Deriving it but testing the UNDERIVED set is the vacuous shape: the
    # value would be written and the readiness verdict would not move, which is the status quo
    # with an extra API call. `kind:epic` is excluded because an epic is a tracking umbrella that
    # is never dispatchable, so writing a priority onto one is pure churn.
    derived, priority_reason, retract = ((None, "epic", frozenset()) if "kind:epic" in labels
                                         else derive_priority(labels))
    effective = (labels | ({derived} if derived else set())) - retract
    ready = (bool(role) and _valid_priority(effective) and has_area and not gated
             and "kind:epic" not in labels)
    if derived:
        add.add(derived)
    remove |= retract
    if ready:
        # [registry #1054] `ready` stays the CLASSIFICATION verdict — retriage.py and
        # triage-stock-alert.py both read it as exactly that ("is the classifier done with this
        # issue"), and flipping it here would make them call a fully-classified issue incomplete.
        # What is withheld is only the LABEL WRITE, because the label additionally asserts an
        # orchestration posture that a live dispatcher status contradicts. See
        # DISPATCHER_OWNED_STATUS for the measured census.
        held = sorted(labels & DISPATCHER_OWNED_STATUS)
        if held:
            warnings.append(
                f"withholding status:ready: {', '.join(held)} is live and is owned by the "
                f"dispatcher/worker/park lane, not by triage (registry #1054) — adding the "
                f"readiness attestation here would strand the issue in a ready+busy pair that "
                f"NEITHER the ready lane nor the deferred-retry lane can select")
        else:
            add.add("status:ready")
        remove.add("status:untriaged")
        remove.add("needs:area")
    else:
        add.add("status:untriaged")
        remove.add("status:ready")
        # a triage-complete-but-no-area, non-gated, non-epic issue parks needs:area (actionable).
        if (bool(role) and _valid_priority(effective) and not has_area
                and "kind:epic" not in labels and not gated):
            add.add("needs:area")
    add, remove = add - labels, remove & labels
    _assert_role_invariant(labels, add, remove, ready)
    return {"add": add, "remove": remove, "ready": ready, "role": role, "warnings": warnings,
            # Reported so a caller can COUNT the decline population instead of inferring it from
            # the absence of a write — scripts/triage-stock-alert.py keys its worklist on this.
            "priority_reason": priority_reason}


# ---------------------------------------------------------------------------------------------------
# THE LABEL-VOCABULARY DRIFT GUARD (#582 acceptance 4) — a STANDING check, not a per-issue one.
#
# Everything above is per-ISSUE and REACTIVE: `triage()` refuses to strip a role for a replacement
# the repo does not define, `retriage.validate_labels` drops an unknown suggestion before the write,
# and `apply_triage` repairs a violated post-condition. Each fires only once an issue has already
# reached the hole, one issue at a time, and only for the labels THAT issue's plan happens to name.
# None of them can answer the question #582 actually asked: *can this planner emit a label this
# repository does not define at all?* `role:soundness` was emittable for months — by every
# trust-plane area, i.e. the whole orchestration surface — and nothing said so until issues had
# already been stranded role-less and ready.
#
# So the vocabulary is CERTIFIED against the repository's live label set on a schedule
# (`.github/workflows/retriage.yml`, job `label-drift`), independently of whether any issue is
# being triaged. It fails closed in both directions: an emittable label the repo does not define
# is a non-zero exit with the label NAMED, and an EMPTY/unreadable repo label set is also a
# non-zero exit — "I could not read the label set" must never read as "no drift".
#
# COMPUTED FROM THE DERIVATION TABLES, never from a hand-listed literal: the whole point is that
# re-pointing a table at a new role (the #582 edit that would flip TRUST_PLANE_ROLE to
# `"soundness"`) moves this set with it, so the guard sees the new label the moment the code can
# emit it — before an issue does. The self-test proves that by re-pointing a table and asserting
# the drift report follows.

def derivable_roles():
    """Every role VALUE `_role` can return — the union of EVERY rung of its derivation ladder.

    A rung missing here is a role label this guard would never certify, so each is taken from the
    table the ladder actually reads: the trust-plane constant, the kind map, the type map, the
    UI/infra surface lanes (evaluated through `_role` itself, since those lanes derive rather than
    map), and the #225 area defaults.
    """
    roles = ({TRUST_PLANE_ROLE} | set(ROLE_BY_KIND.values()) | set(ROLE_BY_TYPE.values())
             | set(AREA_ROLE_DEFAULT.values())
             | {_role([label], "") for label in UI_SURFACE_LABELS + INFRA_SURFACE_LABELS})
    return {role for role in roles if role}


# The non-role labels the triage SURFACE writes. `status:ready`/`status:untriaged` are the two lane
# attestations, `needs:area` is the park, `DERIVED_PRIORITY` is the floor (sparq#4809) — all four
# planned by `triage()` — and `trust:untrusted` is written by triage-issue.yml's quarantine step,
# which is part of the same surface and fails its own post-read if the label does not exist. The
# self-test cross-checks this tuple against BOTH producers: the labels `triage()` really plans over
# a branch-covering corpus, and the `--add-label` tokens in the workflow's quarantine step.
NON_ROLE_VOCABULARY = ("status:ready", "status:untriaged", "needs:area", DERIVED_PRIORITY,
                       "trust:untrusted")


class LabelVocabularyError(RuntimeError):
    """The planner's vocabulary could not be certified — e.g. an empty/unreadable repo label set."""


def emittable_labels():
    """EVERY label the triage surface can write, derived from the tables it writes from."""
    return frozenset({f"{ROLE_PREFIX}{role}" for role in derivable_roles()}
                     | set(NON_ROLE_VOCABULARY))


def label_drift(known_labels):
    """The emittable labels the repository does NOT define, sorted. Fail-closed on an empty set.

    An empty `known_labels` is the shape a failed/garbled label-set read produces, and it would
    otherwise report EVERY label as drifted or (worse, if inverted) nothing at all. It raises
    instead, so the caller cannot mistake an unread label set for a clean one.
    """
    known = set(known_labels)
    if not known:
        raise LabelVocabularyError(
            "the repository label set is EMPTY or unreadable — refusing to certify the triage "
            "vocabulary against nothing (registry #582)")
    return sorted(emittable_labels() - known)


def _label_drift_cli(known_labels):
    """`--label-drift`: certify the vocabulary against a repo label set. 0 clean, 1 drifted."""
    vocabulary = sorted(emittable_labels())
    try:
        missing = label_drift(known_labels)
    except LabelVocabularyError as exc:
        print(f"::error title=triage label drift::{exc}")
        return 1
    # The census emits on EVERY run, including the healthy zero row (AGENTS.md pre-flight 8): a
    # guard that is silent when clean gives an operator no way to tell "certified" from "never ran".
    print(f"triage label vocabulary: {len(vocabulary)} emittable labels checked against "
          f"{len(set(known_labels))} repository labels; missing={len(missing)}")
    if missing:
        print(f"::error title=triage label drift::the triage planner can emit "
              f"{len(missing)} label(s) this repository does not define: {', '.join(missing)} — "
              "create them or fix the derivation tables in scripts/triage.py; an issue triaged "
              "with one of these lands mislabelled or role-less-and-ready (registry #582)")
        return 1
    return 0


# ---------------------------------------------------------------------------------------------------
# QUARANTINE AUTHORIZATION — who may clear `trust:untrusted` (#607; PR #998 round 1 finding 1).
#
# `triage-issue.yml` fires on label events (#607) so a lost triage label is reclassified at the
# moment of the regression. That trigger also means the workflow now SEES a `trust:untrusted`
# removal, and it has to decide what to do about one. The first cut decided by EVENT TYPE — label
# events were exempted from the quarantine write, on the premise that only a triage/write actor can
# label an issue so no third party could emit one. That premise contradicts the workflow's own trust
# rule: trust there is write+ (admin/maintain/write) exactly as in scripts/trust-gate.py, so a
# `triage`-role collaborator is UNTRUSTED — and `triage` is precisely the permission that manages
# labels. Under an event-type exemption such an actor could strip `trust:untrusted` off a
# third-party issue and nothing would restore it, clearing the hard gate that ready-issues.py,
# curate-frontier.py and dispatch-claim.py all read off that one label.
#
# So authorization is bound to the ACTOR that emitted the event, not to the event's type.

# The events on which a WRITE+ actor is asserting the label set deliberately — the only place a
# maintainer's un-quarantine can be honoured. Every other event re-asserts quarantine.
TRUSTED_ACTOR_LABEL_EVENTS = ("labeled", "unlabeled")


def _trust_flag(value):
    """A trust flag is TRUE only for the exact string ``'1'`` (or a real ``True``).

    Fail-closed coercion, and it lives in the pure function rather than in an untested CLI line:
    an empty/unset shell variable, ``'true'``, ``'none'`` or any other spelling reads as UNTRUSTED,
    which can only ever ADD quarantine.
    """
    return value is True or str(value).strip() == "1"


def quarantine_required(action, author_trusted, actor_trusted):
    """Must this event (re-)apply the `trust:untrusted` + `status:untriaged` quarantine? FAIL-CLOSED.

    `action` is the issue event's `action` (opened/edited/reopened/labeled/unlabeled/...);
    `author_trusted` is the ISSUE AUTHOR's write+ verdict; `actor_trusted` is the write+ verdict for
    the login that emitted THIS event. The two are independent probes — the author's trust says
    nothing about who just moved the labels.

    True unless one of exactly two things holds:
      * the AUTHOR is trusted — there is nothing to quarantine; or
      * a TRUSTED ACTOR asserted the label set on a label event — the deliberate maintainer
        un-quarantine, the one path that may clear the gate.

    Everything else — an untrusted actor's `unlabeled`, an unknown/new event type, an unreadable
    trust flag — returns True, i.e. RESTORES the quarantine. The caller's write is `--add-label`,
    which is idempotent: it re-adds a stripped label and is a no-op when the label is still there,
    so this same answer covers both "keep quarantined" and "put the gate back".
    """
    if _trust_flag(author_trusted):
        return False
    return not (str(action).strip() in TRUSTED_ACTOR_LABEL_EVENTS and _trust_flag(actor_trusted))


# ---------------------------------------------------------------------------------------------------
# LIVE APPLICATION — the fail-closed, order-controlled mutation (#582).
#
# THE UNKNOWN-LABEL REDUCTION IS DEFINED ONCE, HERE (registry #1490), and BOTH appliers on this
# surface run it: `triage.py --apply` below and `retriage.py --apply`, whose `validate_labels` /
# `drop_is_safe` are now thin action-shape adapters over these two functions. It shipped for
# retriage first (registry #510); `triage.py --apply` validated only the target `role:*` (#582) and
# sent `status:ready`, `status:untriaged`, `needs:area` and the derived `priority:P4` floor to the
# API unchecked. Copying the reduction into a second applier is the #958 shape — two definitions,
# one of which silently stops matching the other — so it moved here instead, to the module retriage
# already imports (the dependency runs retriage -> triage; the reverse would be a cycle).

# The two lane attestations every applier on this surface moves an issue between. Exactly one of
# them must survive ANY write: an issue on NEITHER lane is invisible to the readiness engine AND to
# retriage's own board queries, i.e. terminally stranded. `retriage.LANE_LABELS` IS this object.
LANE_LABELS = frozenset({"status:ready", "status:untriaged"})
# The verdict a plan is downgraded to when its unknown-label reduction cannot be applied safely.
# One spelling, read by both appliers' logs and by retriage's `skip` reason.
UNSAFE_DROP_REASON = "unknown-label-unsafe-drop"


def validate_plan(plan, known_labels):
    """Reduce a planned write to the labels the target repo ACTUALLY has. Returns (plan, dropped).

    `plan` is any mapping carrying `add` / `remove` / `role` — a `triage()` result or a
    `retriage.plan()` decision. GitHub fails the WHOLE `gh issue edit` when any single
    `--add-label` names a label the repository does not define, so one unknown suggestion loses the
    entire mutation — the add-first role verification included — exits the applier 1, and re-trips
    identically on every following tick because nothing about the issue has changed (measured: run
    29883925637, `'role:soundness' not found`, cleared only by a manual relabel). Validating here,
    against the label set the run already fetched once, converts that permanent red run into a
    named, per-label log line.

    WHAT IS VALIDATED, and what deliberately is not:
      * `add` — every label, because each one is an API-level CREATE-OR-FAIL of the whole edit.
      * the intended `role` — validated even though it is usually already in `add`, because
        `apply_triage` writes the target INDEPENDENTLY of `add` (its add-before-strip phase 1 fires
        whenever the target is not already on the issue). Dropping it here also withdraws every
        `role:*` STRIP from the plan: that is #582's rule read from the other side — an incumbent
        role is never stripped for a replacement this run has refused to write.
      * `remove` is NOT validated. Removals are drawn from the issue's own live label set
        (`triage()` intersects them with it), and a label ON an issue exists in the repository by
        construction; filtering removals could only ever fail to strip something that must go.

    `known_labels is None` means "label set unknown" and validates nothing — the same contract
    `triage(known_labels=...)` uses. Neither applier passes None (both fall back to a live
    `repo_label_set` read), so the tolerance exists for direct/plan-only callers.
    """
    if known_labels is None:
        return plan, []
    known = set(known_labels)
    add = list(plan.get("add", ()))
    remove = list(plan.get("remove", ()))
    role = plan.get("role")
    target = f"{ROLE_PREFIX}{role}" if role else None
    unknown_target = bool(target) and target not in known
    dropped = sorted({label for label in add if label not in known}
                     | ({target} if unknown_target else set()))
    if not dropped:
        return plan, []
    reduced = dict(plan)
    reduced["add"] = sorted(label for label in add if label in known)
    if unknown_target:
        reduced["role"] = None
        reduced["remove"] = sorted(label for label in remove
                                   if not label.startswith(ROLE_PREFIX))
    else:
        reduced["remove"] = sorted(remove)
    return reduced, dropped


def reduced_write_is_safe(plan, live_labels, issue_type, known_labels, attests_ready):
    """Is a plan REDUCED by `validate_plan` still the transition it claims to be?

    "Drop the unknown label and apply the rest" is only safe while the rest still stands on its
    own, and for this classifier it frequently does not — every label it suggests is load-bearing
    for the verdict that produced it. The measured case: an unprioritised issue is ready only
    BECAUSE the derived `priority:P4` floor makes it triage-complete. Write `status:ready` without
    that floor and the post-state is a ready issue with no readable priority, which
    `derive_priority` declines to floor a second time (`ready-attested-regression`, the #586 lane)
    — so the very next tick re-parks it, the tick after that promotes it again, and the surface
    oscillates with two writes forever. Refusing is strictly better AND agrees with the classifier:
    without the label the issue is not triage-complete, and the correct action for an incomplete
    issue is to leave it parked.

    `attests_ready` is what the plan CLAIMS: `triage()`'s own `ready` verdict for `triage.py
    --apply`, and `action != "repark"` for retriage — the same conversion retriage's
    `_decision_to_result` already makes when it hands a decision to `apply_triage`.

    Two named invariants, checked against the post-state the REDUCED write would produce:

      * LANE — exactly one of `status:ready` / `status:untriaged` survives. A half-applied status
        transition (the attestation dropped, its opposite still stripped) puts the issue on NEITHER
        lane, where the readiness engine cannot see it and retriage's board queries cannot select
        it again: terminal, and precisely the stranding #586 exists to undo.
      * PREMISE — a plan that ATTESTS `status:ready` must still classify READY without the dropped
        labels. A park attests nothing, so it needs only to land on the park lane, from which the
        promotion lane re-admits it the moment the label set is fixed.

    Fail-closed: a classifier that raises here means the premise is unproven, which is a refusal.
    """
    post = (set(live_labels) | set(plan.get("add", ()))) - set(plan.get("remove", ()))
    lanes = post & LANE_LABELS
    if len(lanes) != 1:
        return False
    if not attests_ready:
        return "status:untriaged" in lanes
    if "status:ready" not in lanes:
        return False
    try:
        return bool(triage(post, issue_type, trusted=True, known_labels=known_labels)["ready"])
    except Exception:                                     # noqa: BLE001 — unproven means refused
        return False


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
    # registry #1490: the LAST gate before the API, and the one `retriage.py --apply` has run since
    # #510. `triage()` above refuses to DERIVE a `role:*` this repo lacks (#582) — but that is one
    # label family out of several, and `status:ready`, `status:untriaged`, `needs:area` and the
    # derived `priority:P4` floor all reached `gh issue edit` unchecked. One missing taxonomy label
    # therefore lost the WHOLE edit, turned this workflow red for the issue, and re-tripped on
    # every subsequent issue event. The scheduled `label-drift` job makes such a label visible; this
    # is what the per-issue applier does when one is already missing.
    result, dropped = validate_plan(result, known)
    for label in dropped:
        print(f"::warning title=triage #{number}::classifier suggested unknown label {label} — "
              f"dropped (it does not exist in {repo}'s label set, and GitHub fails the WHOLE label "
              f"edit on one unknown name; registry #1490)")
    if dropped and not reduced_write_is_safe(result, current, issue_type, known,
                                             attests_ready=result["ready"]):
        # Applying what survives would strand or oscillate the issue (see reduced_write_is_safe):
        # write NOTHING this tick. Deliberately NOT an error exit — a repository missing one of its
        # own taxonomy labels is a config defect the `label-drift` job names, not a reason to redden
        # every issue event forever, and a red run is exactly what registry #510/#1490 exist to end.
        print(f"::warning title=triage #{number}::the plan depended on {', '.join(dropped)}; "
              f"applying only the labels that survive would leave the issue worse, so this tick "
              f"writes NOTHING (registry #1490 — a no-op with a log, not a red run). Create the "
              f"missing label(s) to unblock it")
        print(f"triage #{number}: role={result['role']} ready={result['ready']} "
              f"add=[] remove=[] dropped={dropped} {UNSAFE_DROP_REASON}")
        return 0
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
    # [sparq#4809] A MISSING priority is now DERIVED at the floor, so this issue is ready and the
    # priority label is written. This assertion used to read `(False, True)` — that WAS the defect:
    # the classifier could not produce its own missing input, so the issue was terminal.
    r = triage(["area:usage"], "feature")
    chk("no priority -> DERIVED at the floor, and ready",
        (r["ready"], DERIVED_PRIORITY in r["add"], "status:untriaged" in r["add"]),
        (True, True, False))
    # ...but deriving a priority does NOT relax any other gate: no area is still not ready.
    chk("derived priority does not substitute for a missing area",
        (triage(["role:impl"], "feature")["ready"],
         "needs:area" in triage(["role:impl"], "feature")["add"]), (False, True))
    # ambiguous priority -> untriaged, AND the floor is NOT written over it (the DECLINE exit).
    r = triage(["priority:P1", "priority:P2", "area:usage"], "feature")
    chk("ambiguous priority", r["ready"], False)
    chk("[sparq#4809] a STATED-but-unreadable priority is DECLINED, never overwritten",
        (any(lb.startswith("priority:") for lb in r["add"]), r["priority_reason"]),
        (False, "stated-unreadable"))
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

    # -----------------------------------------------------------------------------------------------
    # [#598] THE TYPE NORMALIZER. The single definition every caller routes through, so nobody has
    # to remember to lower-case a GitHub DISPLAY name. Each row is a distinct shape and each one
    # dies on a different mutation: dropping `.lower()`, dropping `.strip()`, dropping the
    # `isinstance` guard, or "helpfully" defaulting an empty type to DEFAULT_ISSUE_TYPE (which
    # would silently re-close the #225 area fallback this issue exists to open).
    for _raw, _want in (("bug", "bug"), ("Bug", "bug"), ("  Task  ", "task"),
                        ("Documentation", "documentation"), ("", ""), ("   ", ""), (None, ""),
                        ({"name": "Bug"}, ""), (7, "")):
        chk(f"[#598] normalize_issue_type({_raw!r})", normalize_issue_type(_raw), _want)
    # ...and the case fold is LOAD-BEARING, not cosmetic: an un-folded `Bug` misses ROLE_BY_TYPE and
    # a TYPED issue would be derived as if it were untyped. `area:docs` is the one area whose
    # fallback role differs from `ROLE_BY_TYPE["bug"]`, so it is the only fixture that can tell the
    # two apart — this row reads `impl` and goes RED the moment the fold is removed.
    chk("[#598] a DISPLAY-cased type still resolves through ROLE_BY_TYPE, not the area map",
        triage(["priority:P2", "area:docs"], "Bug")["role"], "impl")
    # The #598 payoff, both directions on the SAME label set, so neither can be faked by a constant:
    # a type ROLE_BY_TYPE names wins; a type it does not name (and no type at all) falls through to
    # the area map. Before #598 both callers passed the literal `task`, so only the first row was
    # ever reachable in production.
    chk("[#598] a MAPPED type wins over the area default",
        triage(["priority:P2", "area:docs"], "task")["role"], "impl")
    chk("[#598] an UNMAPPED type falls through to the area default",
        triage(["priority:P2", "area:docs"], "Documentation")["role"], "docs")
    chk("[#598] ...and so does an UNTYPED issue (the #225 semantics, unchanged)",
        triage(["priority:P2", "area:docs"], "")["role"], "docs")
    # The fallback is still FAIL-CLOSED for an area the map cannot classify: an unmapped type does
    # NOT invent a role, it leaves the issue parked. (Kills "widen the fallback to a default role".)
    _unmapped = triage(["priority:P2", "area:nonesuch"], "Documentation")
    chk("[#598] an unmapped type + an unmapped area derives NO role and is not ready",
        (_unmapped["role"], _unmapped["ready"]), (None, False))
    # WHO CAN WRITE WHAT THIS READS (AGENTS.md pre-flight 5). #598 turns a previously-constant
    # input into one an issue AUTHOR influences: any author can pick the issue's type from the
    # org's list. Org owners define the names, so an author cannot invent one — but it must not
    # matter either way, because a trust-surface label makes the trust-plane lane UNCONDITIONAL
    # (`_role` tests SEC_KEYWORDS first, before kind/UI/infra/type/area). Asserted over the whole
    # type space the classifier can see — every ROLE_BY_TYPE key, plus untyped and an off-list
    # name — so no type an author selects can route trust-plane work off the human-armed chain.
    # The fixture is a DOCS issue about the WORKER, deliberately: `area:dispatch` alone could not
    # discriminate, because AREA_ROLE_DEFAULT["dispatch"] is itself TRUST_PLANE_ROLE, so the row
    # would read `impl` even with the SEC_KEYWORDS short-circuit deleted (a value-identical
    # survivor, AGENTS.md pre-flight 4). With two areas whose defaults DISAGREE, the area map
    # returns None and only the trust-surface lane can produce a role at all.
    chk("[#598] NO issue type can move a trust-surface issue off the trust-plane lane",
        {triage(["priority:P1", "area:docs", "area:worker"], _t)["role"]
         for _t in list(ROLE_BY_TYPE) + ["", "Documentation", "  DOCS  ", None]},
        {TRUST_PLANE_ROLE})
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
        {"add": set(), "remove": set(), "ready": False, "role": None, "warnings": [],
         "priority_reason": "untrusted"})
    # ...and the derivation must not become a way IN for untrusted content either: an untrusted
    # issue with NO priority is still a total no-op, not a floor write.
    chk("[sparq#4809] untrusted + no priority is still a no-op — the derivation writes nothing",
        triage(["area:usage", "trust:untrusted"], "feature")["add"], set())
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
    # `ISSUE_TYPE` is substituted with a type ROLE_BY_TYPE does NOT name (#598), so the replay below
    # is an EXACT-MATCH assertion on what the workflow really passes: a step that goes back to the
    # literal `--type task` — the defect #598 names — dispatches `"task"` and turns this row RED.
    argvs = workflow_argvs(triage_wf, "triage.py",
                           {"REPO": "o/r", "NUM": "7", "ISSUE_TYPE": "Documentation"})
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
        (code, dispatched), (0, {"repo": "o/r", "number": "7", "type": "Documentation"}))
    # [#598] ...and the value it forwards really comes from the EVENT PAYLOAD. The replay above
    # substitutes `$ISSUE_TYPE` from a dict, so it would stay green for a workflow that passes an
    # env var nothing ever defines — the argv would be `--type ""` live, and every issue would look
    # untyped. Assert the binding in the YAML itself, exact-match, on the comment-stripped body.
    chk("[#598] triage-issue.yml BINDS ISSUE_TYPE to the issue event's own type name",
        f"ISSUE_TYPE: ${{{{ github.event.issue.type.name }}}}" in "\n".join(
            line.strip() for line in open(triage_wf, encoding="utf-8").read().splitlines()
            if not line.strip().startswith("#")), True)
    # [#598] ...and `_apply_cli` FORWARDS it to the classifier. Every row above stubs `_apply_cli`
    # out, so its own body is never executed by the replay (measured with `python3 -m trace --count
    # --missing`: the whole function unexecuted) and a `triage(current, "task", …)` one layer down
    # would have survived the entire suite — "the fix landed one layer short of the binding layer"
    # (AGENTS.md pre-flight 11). So drive the REAL `_apply_cli` with `live_gh`/`repo_label_set`
    # stubbed and spy on what the classifier is handed. The expected value is UN-normalized on
    # purpose: this row asserts the FORWARD, and `triage()` owns the normalization.
    forwarded = {}
    fake_labels, fake_rev = {"priority:P2", "area:docs"}, [0]

    def _fake_edit(add, remove):
        fake_labels.update(add)
        fake_labels.difference_update(remove)
        fake_rev[0] += 1

    real_triage, real_live_gh, real_label_set = triage, live_gh, repo_label_set
    try:
        globals()["live_gh"] = lambda repo, number, title="triage": (
            lambda: (set(fake_labels), fake_rev[0]), lambda: set(fake_labels),
            _fake_edit, lambda message: None)
        globals()["repo_label_set"] = lambda repo: set(REAL) | {"role:docs"}
        globals()["triage"] = lambda labels, issue_type=DEFAULT_ISSUE_TYPE, **kw: (
            forwarded.update(type=issue_type) or real_triage(labels, issue_type, **kw))
        apply_code = _apply_cli("o/r", "7", "Documentation")
    finally:
        globals()["triage"] = real_triage
        globals()["live_gh"] = real_live_gh
        globals()["repo_label_set"] = real_label_set
    # Both halves matter: the type reaches the classifier UNCHANGED, and the label the applier
    # actually wrote is the one that type derives. `area:docs` is the fixture that discriminates —
    # with the pre-#598 literal `task` this lands `role:impl`.
    chk("[#598] _apply_cli forwards --type through to the classifier, and writes the role it "
        "derives",
        (apply_code, forwarded, sorted(lb for lb in fake_labels if lb.startswith("role:"))),
        (0, {"type": "Documentation"}, ["role:docs"]))
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
    # [registry #1490] `--apply` VALIDATES EVERY LABEL IT WRITES, NOT JUST THE ROLE.
    # `triage()` refuses to DERIVE a `role:*` this repo lacks (#582) — but that is ONE label family.
    # `status:ready`, `status:untriaged`, `needs:area` and the derived `priority:P4` floor reached
    # `gh issue edit` unchecked, and GitHub fails the WHOLE edit on a single unknown `--add-label`:
    # one missing taxonomy label therefore reddened triage-issue.yml for that issue and
    # re-tripped on every subsequent issue event — exactly the recurrence #510 measured on the
    # retriage side. The reduction is now ONE implementation — `validate_plan` +
    # `reduced_write_is_safe` — and BOTH appliers run it (`retriage.validate_labels`/`drop_is_safe`
    # are action-shape adapters over these, pinned by retriage's own #510 rows).
    #
    # Every plan below is a REAL `triage()` result, never a hand-built dict: a plan assembled here
    # would measure the fixture rather than the classifier (AGENTS.md pre-flight 2b/2c). The missing
    # label is spelled as a LITERAL on purpose — deriving it from `DERIVED_PRIORITY` would make the
    # row agree with the code whatever the code emits.
    # -----------------------------------------------------------------------------------------------
    _p4_missing = REAL - {"priority:P4"}
    _floored = {"area:dispatch", "role:impl", "status:untriaged"}
    _reduced1490, _dropped1490 = validate_plan(triage(_floored, "task", known_labels=_p4_missing),
                                               _p4_missing)
    chk("[#1490] a NON-ROLE label this repository does not define is dropped BY NAME while every "
        "label that does exist survives",
        (_dropped1490, sorted(_reduced1490["add"]), sorted(_reduced1490["remove"])),
        (["priority:P4"], ["status:ready"], ["status:untriaged"]))
    # NEGATIVE CONTROL, and the row that stops the one above from being satisfied by a reducer that
    # simply drops things: against the COMPLETE label set the same plan passes through untouched.
    _whole1490, _nodrop1490 = validate_plan(triage(_floored, "task", known_labels=REAL), REAL)
    chk("[#1490] NEGATIVE CONTROL: against the COMPLETE label set the SAME plan is unchanged and "
        "nothing is reported dropped",
        (_nodrop1490, sorted(_whole1490["add"]), sorted(_whole1490["remove"])),
        ([], ["priority:P4", "status:ready"], ["status:untriaged"]))
    chk("[#1490] PREMISE INVARIANT: the reduced write still attests status:ready, but the "
        "post-state no longer classifies READY without the dropped floor — refused, because "
        "applying it "
        "oscillates promote<->repark, two writes per two ticks, forever",
        reduced_write_is_safe(_reduced1490, _floored, "task", _p4_missing,
                              attests_ready=_reduced1490["ready"]), False)
    # ...and the invariant refuses an UNSAFE write, not every write. A park attests nothing, so a
    # dropped `needs:area` still lands the issue on exactly one lane and IS applied.
    _na_missing = REAL - {"needs:area"}
    _arealess = {"role:impl", "priority:P2"}
    _park1490, _pdropped1490 = validate_plan(triage(_arealess, "task", known_labels=_na_missing),
                                             _na_missing)
    chk("[#1490] ...and a reduction that still lands on exactly ONE lane is SAFE (the guard "
        "refuses unsafe writes, not all writes)",
        (_pdropped1490, sorted(_park1490["add"]),
         reduced_write_is_safe(_park1490, _arealess, "task", _na_missing,
                               attests_ready=_park1490["ready"])),
        (["needs:area"], ["status:untriaged"], True))
    # LANE INVARIANT: the attestation dropped while its opposite is still stripped leaves the issue
    # on NEITHER lane — invisible to the readiness engine AND to retriage's board queries, i.e.
    # terminal. Reached through the real reducer, from a repository that has no `status:ready`.
    _sr_missing = REAL - {"status:ready"}
    _lane1490, _ldropped1490 = validate_plan(triage(_floored, "task", known_labels=_sr_missing),
                                             _sr_missing)
    chk("[#1490] LANE INVARIANT: a reduction that would leave the issue on NEITHER lane is refused",
        (_ldropped1490, sorted(_lane1490["remove"]),
         reduced_write_is_safe(_lane1490, _floored, "task", _sr_missing,
                               attests_ready=_lane1490["ready"])),
        (["status:ready"], ["status:untriaged"], False))

    # THE REST OF THE SHARED CONTRACT — the branches `triage()`'s own producer cannot reach, so
    # their plans are written out. They are NOT hypothetical: `retriage.plan()` emits exactly these
    # shapes (a decision carrying a `role` that is not in `add`; a promote that attests readiness
    # without stripping `status:untriaged`), and retriage's #510 rows pin them against that real
    # producer. Measured with `python3 -m trace --count --missing` BEFORE they were written: these
    # were the only never-executed lines of the shared region under either suite — and three of them
    # are fail-closed refusals, which is the worst place to have an unexecuted line.
    chk("[#1490] no label set means no validation — the documented `None` contract, shared "
        "verbatim with `triage(known_labels=None)`",
        validate_plan({"add": ["role:soundness"], "remove": [], "role": "soundness"}, None),
        ({"add": ["role:soundness"], "remove": [], "role": "soundness"}, []))
    chk("[#1490] an unknown ROLE clears the role AND withdraws every role:* strip — #582's rule "
        "read from the other side: never strip an incumbent for a replacement this run refuses to "
        "write (apply_triage writes the target INDEPENDENTLY of `add`)",
        validate_plan({"add": ["status:ready"], "remove": ["role:docs", "status:untriaged"],
                       "role": "soundness"}, REAL),
        ({"add": ["status:ready"], "remove": ["status:untriaged"], "role": None},
         ["role:soundness"]))
    chk("[#1490] a plan that ATTESTS readiness but whose post-state sits on the PARK lane is "
        "refused (one lane survives, but not the one the plan claims)",
        reduced_write_is_safe({"add": [], "remove": []},
                              {"status:untriaged", "role:impl", "area:dispatch", "priority:P2"},
                              "task", REAL, attests_ready=True), False)
    # ...and the OTHER half of `len(lanes) != 1`, which is the ONLY half that guard uniquely
    # decides. MEASURED: with a ZERO-lane post-state, deleting the lane check changes no answer —
    # the attested-lane check below returns the same False — so `if len(lanes) != 1` survived every
    # assertion in BOTH suites until this row existed. A post-state on BOTH lanes is a real,
    # already-corrupt issue, and confirming a write against it is how it stays corrupt: the
    # readiness engine and the sweep would each see a different, contradictory answer.
    _bothlanes = {"status:ready", "status:untriaged", "role:impl", "area:dispatch", "priority:P2"}
    chk("[#1490] LANE INVARIANT, the half only IT decides: a post-state on BOTH lanes is refused "
        "in either direction — without the guard the ready side re-classifies READY and the park "
        "side sees its lane label, so both would be applied",
        (reduced_write_is_safe({"add": [], "remove": []}, _bothlanes, "task", REAL,
                               attests_ready=True),
         reduced_write_is_safe({"add": [], "remove": []}, _bothlanes, "task", REAL,
                               attests_ready=False)),
        (False, False))
    # FAIL-CLOSED: an unproven premise is a refusal, never an exception that reaches the caller.
    # Captured rather than asserted directly so that DELETING the try/except reds this row cleanly
    # instead of aborting the suite (AGENTS.md pre-flight 4, crash-after-partial-run).
    _real_triage1490 = triage
    try:
        globals()["triage"] = lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("classifier"))
        try:
            _premise1490 = reduced_write_is_safe(
                {"add": ["status:ready"], "remove": ["status:untriaged"]},
                {"status:untriaged", "role:impl", "area:dispatch"}, "task", REAL,
                attests_ready=True)
        except Exception as exc:                                  # noqa: BLE001
            _premise1490 = f"RAISED {type(exc).__name__}"
    finally:
        globals()["triage"] = _real_triage1490
    chk("[#1490] a classifier that RAISES means the premise is unproven, which is a refusal — not "
        "an exception the applier propagates", _premise1490, False)

    # THE ENTRY POINT, END TO END. Every row above calls the reducers DIRECTLY, so an `_apply_cli`
    # that never invokes them keeps all of them green — entry points are where a fabricating bug
    # survives (AGENTS.md pre-flight 1) and this fix is worth nothing one layer short of the API
    # call (pre-flight 11). So drive the REAL `_apply_cli` against a fake GitHub whose `edit` raises
    # on an unknown `--add-label` exactly as the API does.
    # MUTATION TRIPWIRE: delete the `validate_plan` call from `_apply_cli` and the fake raises,
    # `apply_triage` reports ok=False, and the first row below goes red on BOTH `code == 0` and
    # `calls == []`. Make the refusal unconditional instead and the two ACCEPT rows go red.
    #
    # The no-op reason is spelled as a LITERAL, never read back from `UNSAFE_DROP_REASON`: an
    # assertion that compares what the applier printed against the constant it printed FROM cannot
    # fail whatever that constant becomes (AGENTS.md pre-flight 2b — measured, not hypothetical: a
    # mutant that repointed the constant survived every row here until this was written out).
    _reason1490 = "unknown-label-unsafe-drop"

    def run_apply(start, known, issue_type="task"):
        live, revision, calls = set(start), [0], []

        def fake_edit(add, remove):
            unknown = sorted(set(add) - set(known))
            if unknown:              # GitHub fails the WHOLE edit on one unknown name
                raise RuntimeError(f"'{unknown[0]}' not found")
            calls.append((sorted(add), sorted(remove)))
            live.update(add)
            live.difference_update(remove)
            revision[0] += 1

        saved_gh, saved_labels = live_gh, repo_label_set
        out = io.StringIO()
        try:
            globals()["live_gh"] = lambda repo, number, title="triage": (
                lambda: (set(live), revision[0]), lambda: set(live), fake_edit,
                lambda message: print(f"::warning::{message}"))
            globals()["repo_label_set"] = lambda repo: set(known)
            with contextlib.redirect_stdout(out):
                status = _apply_cli("o/r", "7", issue_type)
        finally:
            globals()["live_gh"], globals()["repo_label_set"] = saved_gh, saved_labels
        return status, calls, live, out.getvalue()

    _code, _calls, _live, _out = run_apply(_floored, _p4_missing)
    chk("[#1490] THE LIVE FAILURE: --apply drops the unknown label with a per-issue log line, "
        "writes NOTHING, leaves the issue byte-identical, and stays GREEN (before this it exited 1 "
        "and did so again on every following issue event)",
        (_code, _calls, _live == _floored,
         "classifier suggested unknown label priority:P4" in _out, _reason1490 in _out),
        (0, [], True, True, True))
    # ...and re-running is the SAME no-op with the same log. Nothing about the issue changed, so
    # this is exactly what the next `labeled`/`edited` event does to it.
    _code2, _calls2, _live2, _out2 = run_apply(_live, _p4_missing)
    chk("[#1490] re-running on the SAME issue is a no-op-with-log — the recurrence cannot recur",
        (_code2, _calls2, _live2 == _floored, _reason1490 in _out2), (0, [], True, True))
    # THE ACCEPT DIRECTION. An applier that refused on ANY drop would pass both rows above.
    _code3, _calls3, _live3, _out3 = run_apply(_arealess, _na_missing)
    chk("[#1490] a SAFE reduction is APPLIED: the surviving labels are written in one edit and "
        "only the unknown one is withheld",
        (_code3, _calls3, sorted(_live3), _reason1490 in _out3),
        (0, [(["status:untriaged"], [])], ["priority:P2", "role:impl", "status:untriaged"], False))
    # ...and the UNREDUCED path is untouched: a complete label set still writes the whole plan.
    _code4, _calls4, _live4, _out4 = run_apply(_floored, REAL)
    chk("[#1490] NEGATIVE CONTROL: against the COMPLETE label set --apply writes the FULL plan, "
        "derived priority floor included, and reports no drop",
        (_code4, _calls4, sorted(_live4), _reason1490 in _out4),
        (0, [(["priority:P4", "status:ready"], ["status:untriaged"])],
         ["area:dispatch", "priority:P4", "role:impl", "status:ready"], False))

    # -----------------------------------------------------------------------------------------------
    # [PR #595 finding 5] THE QUARANTINE LABEL WRITE IS FAIL-LOUD. `gh issue edit ... || true` on the
    # trust:untrusted/status:untriaged write meant a failed mutation left third-party content
    # UN-QUARANTINED while the job reported success — the worst failure mode on this surface, and
    # invisible to retriage (which only revisits status:untriaged). Pinned statically so it cannot
    # regress: the label mutation carries no `|| true`, the step runs under `set -e`, and a post-read
    # proves both labels landed. (Only the courtesy comment may be best-effort.)
    wf_body = "\n".join(line for line in open(triage_wf, encoding="utf-8").read().splitlines()
                        if not line.strip().startswith("#"))

    def wf_step(step_name):
        """The EXECUTABLE body of one workflow step, comment lines already dropped."""
        found = re.search(r"\n {6}- name: " + re.escape(step_name) + r".*?(?=\n {6}- name: |\Z)",
                          wf_body, re.S)
        return found.group(0) if found else ""

    def step_if(body):
        """The step's `if:` expression VERBATIM (empty string when the step has none)."""
        return next((line.split("if:", 1)[1].strip() for line in body.splitlines()
                     if line.strip().startswith("if:")), "")

    quarantine_body = wf_step("Quarantine + notify (untrusted author)")
    chk("[#595 f5] the quarantine step exists and runs under set -e",
        bool(quarantine_body) and "set -euo pipefail" in quarantine_body, True)
    chk("[#595 f5] no `|| true` on the quarantine LABEL mutation",
        [line.strip() for line in quarantine_body.splitlines()
         if "issue edit" in line and "|| true" in line], [])
    chk("[#595 f5] the quarantine labels are verified by a post-read before success",
        all(token in quarantine_body for token in ("--json labels", "trust:untrusted",
                                                   "refusing to report success")), True)

    # -----------------------------------------------------------------------------------------------
    # [#607] THE TRIGGER LIST IS THE PREVENTION MECHANISM, so it is pinned by EXACT SET, never by
    # containment. `labeled`/`unlabeled` are distinct issue event types: without them, stripping a
    # `priority:*` / `role:*` / `area:*` label off a `status:ready` issue re-ran no classifier at all
    # (the original #178 mechanism) and left it stranded until retriage's sweep (#586). A dropped
    # token here is exactly the regression #607 fixed and a substring check would not see it.
    # The parse is deliberately FAIL-CLOSED, not tolerant: a trigger list this regex cannot read
    # (e.g. reformatted to block style) yields the empty set and reds this row rather than passing
    # on evidence it never found — keep the flow-style list, or teach the regex the new shape.
    trigger = re.search(r"\non:\n  issues:\n    types: \[([^\]]*)\]", wf_body)
    trigger_types = sorted(t.strip() for t in (trigger.group(1) if trigger else "").split(",")
                           if t.strip())
    chk("[#607] triage-issue.yml fires on the LABEL events too — exact trigger set",
        trigger_types, ["edited", "labeled", "opened", "reopened", "unlabeled"])
    # THE MARQUEE CLAIM, checked at the step that actually delivers it (AGENTS.md pre-flight 9/11):
    # a trigger that reaches a classifier step gated on the event type would be inert. The
    # classifier's ONLY condition is trust — exact match, so `&& false` or a re-added event-type
    # exclusion goes red here.
    chk("[#607] the classifier step is gated by TRUST ALONE (no event-type condition), so it DOES "
        "run on labeled/unlabeled",
        step_if(wf_step("Static triage (trusted author)")), "steps.trust.outputs.trusted == '1'")
    # -----------------------------------------------------------------------------------------------
    # [PR #998 round 1, findings 1+2] QUARANTINE REMOVAL IS AUTHORIZED BY THE **ACTOR**, NEVER BY THE
    # EVENT TYPE. #607's first cut exempted `labeled`/`unlabeled` from the quarantine write because
    # "only a triage/write actor can label an issue". That premise contradicts the trust rule three
    # steps up: trust is write+ (admin/maintain/write), so a `triage`-role collaborator is UNTRUSTED
    # here — and `triage` is exactly the permission that manages labels. Under the exemption such an
    # actor could strip `trust:untrusted` off a THIRD-PARTY issue and nothing would restore it,
    # clearing the hard gate ready-issues.py / curate-frontier.py / dispatch-claim.py read. Round 1
    # finding 2 is why this section exists at all: the shipped checks pinned the trigger list, the
    # `if:` strings and `triage()` fixed points, and NEVER constructed the case the change created —
    # an external author with a DISTINCT label-event actor. These rows do.
    trust_body = wf_step("Trust-gate the AUTHOR and the label-event ACTOR")
    chk("[#998 f1] the job binds ACTOR to the event SENDER (never the issue author) and ACTION to "
        "the event action",
        (bool(re.search(r"\n      ACTOR: \$\{\{ github\.event\.sender\.login \}\}", wf_body)),
         bool(re.search(r"\n      ACTION: \$\{\{ github\.event\.action \}\}", wf_body))), (True, True))
    chk("[#998 f1] the trust step probes the ACTOR's permission SEPARATELY from the author's — the "
        "author's trust says nothing about who just moved the labels",
        (bool(re.search(r'author_trusted=\$\(trust_of "\$AUTHOR"\)', trust_body)),
         bool(re.search(r'actor_trusted=\$\(trust_of "\$ACTOR"\)', trust_body))), (True, True))
    # EXACT SET, not containment: adding `triage|` here is the whole vulnerability and a substring
    # check would not see it.
    perm_arm = re.search(r'case "\$perm" in\n\s*([a-z|]+)\) echo 1', trust_body)
    chk("[#998 f1] WRITE+ ONLY: the permissions that grant trust are EXACTLY admin/maintain/write — "
        "`triage` (which CAN move labels) and `read` are not among them",
        sorted(perm_arm.group(1).split("|")) if perm_arm else [], ["admin", "maintain", "write"])
    chk("[#998 f1] the trust step emits the `quarantine` output the gate below reads, and computes "
        "it by CALLING this module — ONE definition of the rule, no YAML copy no test could kill",
        (bool(re.search(r'quarantine=\$\(python3 scripts/triage\.py --quarantine-decision\b',
                        trust_body)),
         'echo "quarantine=$quarantine" >> "$GITHUB_OUTPUT"' in trust_body), (True, True))
    # Pinned as the WHOLE expression: a substring check survives `&& false`, and the second row
    # kills a re-introduced event-type allowlist (the exact defect round 1 found) by name.
    quarantine_if = step_if(quarantine_body)
    chk("[#998 f1] the quarantine step's `if:` is EXACTLY the module's decision",
        quarantine_if, "steps.trust.outputs.quarantine == '1'")
    chk("[#998 f1] the gate names NO event type — an event-type allowlist here would be a second, "
        "untestable copy of the rule",
        ("github.event.action" in quarantine_if, "contains(" in quarantine_if), (False, False))
    chk("[#998 f1] the quarantine write RESTORES a stripped gate: an idempotent `--add-label` of "
        "BOTH labels, so the same decision covers keep-quarantined and put-the-gate-back",
        bool(re.search(r"gh issue edit .*--add-label trust:untrusted --add-label status:untriaged",
                       quarantine_body)), True)

    # THE DECISION, EXECUTED over the full matrix. Every expected value below is written out BY HAND
    # (AGENTS.md pre-flight 2b): none of it is computed from TRUSTED_ACTOR_LABEL_EVENTS or from
    # quarantine_required(), so widening that constant — or inverting the rule — cannot move the code
    # and its expectation together. The ACTIONS are cross-checked against the workflow's OWN trigger
    # list read above, so a new trigger type that nobody judged reds the coverage row.
    quarantine_table = {
        # untrusted AUTHOR + untrusted ACTOR — EVERY event re-asserts the gate, label events included.
        # `("unlabeled", "0", "0")` IS the reported hole: a triage-role actor stripping the label.
        ("opened", "0", "0"): "1", ("edited", "0", "0"): "1", ("reopened", "0", "0"): "1",
        ("labeled", "0", "0"): "1", ("unlabeled", "0", "0"): "1",
        # untrusted AUTHOR + WRITE+ ACTOR — only a LABEL event is the deliberate un-quarantine; a
        # content event still quarantines (a maintainer editing a third-party issue approves nothing).
        ("opened", "0", "1"): "1", ("edited", "0", "1"): "1", ("reopened", "0", "1"): "1",
        ("labeled", "0", "1"): "0", ("unlabeled", "0", "1"): "0",
        # trusted AUTHOR — there is nothing to quarantine, whoever the actor is.
        ("opened", "1", "0"): "0", ("edited", "1", "0"): "0", ("reopened", "1", "0"): "0",
        ("labeled", "1", "0"): "0", ("unlabeled", "1", "0"): "0",
        ("opened", "1", "1"): "0", ("edited", "1", "1"): "0", ("reopened", "1", "1"): "0",
        ("labeled", "1", "1"): "0", ("unlabeled", "1", "1"): "0",
    }
    chk("[#998 f2] the truth table judges EVERY trigger type the workflow subscribes to",
        sorted({row[0] for row in quarantine_table}), trigger_types)
    chk("[#998 f2] ...crossed with both trust axes independently — 4 rows per event, none missing",
        len(quarantine_table), 4 * len(trigger_types))
    chk("[#998 f2] quarantine_required() matches the hand-written truth table on every row",
        sorted(row for row, want in quarantine_table.items()
               if ("1" if quarantine_required(*row) else "0") != want), [])
    # The two headline rows, named so a regression says WHICH direction broke (pre-flight 9).
    chk("[#998 f1] THE HOLE: external author, `trust:untrusted` stripped by a TRIAGE-role actor -> "
        "the quarantine is RESTORED, so the removal never clears the downstream hard gate",
        quarantine_required("unlabeled", "0", "0"), True)
    chk("[#998 f1] ...and the genuinely authorized path still works: a WRITE+ actor's removal stands",
        quarantine_required("unlabeled", "0", "1"), False)
    chk("[#998 f1] those two differ ONLY in the ACTOR's permission — the decision is actor-bound, "
        "not event-bound",
        quarantine_required("unlabeled", "0", "0") == quarantine_required("unlabeled", "0", "1"),
        False)
    for why, action, author_trust, actor_trust in (
            ("an event type nobody judged", "deleted", "0", "1"),
            ("a missing action (unset shell variable)", "", "0", "1"),
            ("an unreadable ACTOR flag", "unlabeled", "0", "true"),
            ("an unreadable AUTHOR flag", "opened", "yes", "1"),
            ("an empty AUTHOR flag", "labeled", "", "0")):
        chk(f"[#998 f1] FAIL-CLOSED: {why} still quarantines",
            quarantine_required(action, author_trust, actor_trust), True)

    # END-TO-END on the workflow's OWN argv (pre-flight 9/11: check the evidence path, not the
    # object it names). The tokens come from the workflow FILE with the shell variables substituted,
    # so a renamed flag, a dropped `--actor-trusted`, or a swapped argument order lands here.
    def decide_via_cli(action, author_trust, actor_trust):
        argv = next((a for a in workflow_argvs(
            triage_wf, "triage.py",
            {"ACTION": action, "author_trusted": author_trust, "actor_trusted": actor_trust,
             "REPO": "o/r", "NUM": "7"}) if "--quarantine-decision" in a), None)
        if argv is None:
            return "NO --quarantine-decision INVOCATION IN THE WORKFLOW"
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(list(argv))
        return (code, buffer.getvalue().strip())
    chk("[#998 f2] END-TO-END on the workflow's argv: external author, triage-role actor strips "
        "`trust:untrusted` -> the CLI says QUARANTINE",
        decide_via_cli("unlabeled", "0", "0"), (0, "1"))
    chk("[#998 f2] END-TO-END on the workflow's argv: external author, WRITE+ maintainer removes it "
        "-> the CLI says LEAVE IT REMOVED",
        decide_via_cli("unlabeled", "0", "1"), (0, "0"))
    chk("[#998 f2] END-TO-END on the workflow's argv: a triage-role actor cannot clear the gate by "
        "ADDING a label either",
        decide_via_cli("labeled", "0", "0"), (0, "1"))
    # The two ASYMMETRIC rows. Every case above happens to agree under a SWAP of the two trust
    # arguments at the call site — 0/0 is symmetric and `unlabeled` 0/1 reads the same either way, a
    # value-identical survivor (AGENTS.md pre-flight 4), measured surviving before these were added.
    # These two DISAGREE under the swap, so `--author-trusted "$actor_trusted" --actor-trusted
    # "$author_trusted"` dies here.
    chk("[#998 f2] END-TO-END: a WRITE+ maintainer touching a THIRD-PARTY issue's CONTENT approves "
        "nothing — the author is still untrusted, so it quarantines",
        decide_via_cli("opened", "0", "1"), (0, "1"))
    chk("[#998 f2] END-TO-END: a trusted author's issue is never quarantined, whoever the actor is",
        decide_via_cli("opened", "1", "0"), (0, "0"))
    # THE DEFAULTS ARE THE UNTRUSTED SPELLING. The workflow passes every flag today, so a fail-OPEN
    # default is invisible to every row above — but it is what a dropped argument falls back on, and
    # a `default="1"` on either flag was measured SURVIVING before these two rows existed. Each row
    # omits exactly the flag it pins.
    def decide_bare(*argv):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(["--quarantine-decision", *argv])
        return (code, buffer.getvalue().strip())
    chk("[#998 f1] FAIL-CLOSED DEFAULT: with no trust flags at all, the decision is QUARANTINE",
        decide_bare(), (0, "1"))
    chk("[#998 f1] FAIL-CLOSED DEFAULT: a dropped `--actor-trusted` on a label event does NOT "
        "authorize the removal",
        decide_bare("--action", "unlabeled", "--author-trusted", "0"), (0, "1"))

    # NO SELF-TRIGGER LOOP. The primary reason is GitHub's own rule — a write made with the
    # repository's GITHUB_TOKEN starts no workflow run (the rule dispatch.yml's dead `workflow_run`
    # doorbell measured on 2026-07-17), and this workflow's `gh` calls all run on `github.token`.
    # These rows are the INDEPENDENT second reason, and the one this module owns: `triage()` is a
    # FIXED POINT, so replaying it over its own post-state plans NOTHING — and an empty plan issues
    # no `gh` call at all (asserted below) — so a triage-emitted label event terminates the cascade
    # after one step even if that suppression rule ever changed. The first-pass plan is asserted
    # NON-EMPTY in the same row: over a settled label set the fixed-point claim is vacuously true.
    for case, seed in (("promotes to ready", ["priority:P1", "area:docs", "kind:docs"]),
                       # the only seed whose FIRST pass plans a real REMOVAL (role swap + the
                       # untriaged->ready demotion); without it every planned `remove` is filtered
                       # away by the seed itself and the remove half of the fixed point is untested.
                       ("role swap", ["priority:P1", "area:docs", "kind:docs", "role:impl",
                                      "status:untriaged"]),
                       ("gated by needs:user", ["priority:P1", "area:docs", "needs:user"]),
                       ("lost-role repair", ["priority:P1", "area:worker", "status:ready"]),
                       ("no area -> needs:area", ["priority:P1", "kind:docs"])):
        first = triage(seed, "task")
        settled = sorted((set(seed) | first["add"]) - first["remove"])
        replay = triage(settled, "task")
        chk(f"[#607] triage() is a FIXED POINT ({case}): the first pass mutates, the replay over "
            "its own post-state plans nothing",
            (bool(first["add"] or first["remove"]), sorted(replay["add"]), sorted(replay["remove"])),
            (True, [], []))

    # -----------------------------------------------------------------------------------------------
    # [registry #1054] THE READY+BUSY PAIR — triage must not re-mint `status:ready` over a live
    # defer. The fixture below is the VERBATIM label set registry #1037 held at 2026-07-28T16:27:06Z,
    # the instant `sparq-orchestrator[bot]` finished deferring it; 21 seconds later this classifier
    # stamped `status:ready` back on, and the issue has been undispatchable ever since.
    deferred_1037 = ["area:dispatch", "priority:P1", "role:impl", "self-improvement",
                     "status:deferred"]
    r = triage(deferred_1037, "task")
    post = (set(deferred_1037) | r["add"]) - r["remove"]
    chk("[#1054] a freshly-DEFERRED, classification-complete issue is NOT re-promoted to ready",
        ("status:ready" in r["add"], "status:ready" in post,
         {"status:ready", "status:deferred"} <= post),
        (False, False, False))
    # `ready` is the CLASSIFICATION verdict and MUST stay true — retriage.py (`classifier-incomplete`)
    # and triage-stock-alert.py (`machine_owed`) both read it as "has the classifier finished with
    # this issue", and a withheld LABEL is not an unfinished classification. Flipping the field
    # instead of the write would silently re-open registry #799's untriaged deadlock.
    chk("[#1054] ...but the classification VERDICT retriage/stock-alert consume is unchanged",
        (r["ready"], r["role"], len(r["warnings"])), (True, "impl", 1))
    # `any(...)` over the list, never `warnings[0]`: a mutant that suppresses the warning entirely
    # must be killed by THIS NAMED ROW, not by an IndexError that aborts every row after it.
    chk("[#1054] ...and the withholding is NAMED in a warning, not silent",
        any("withholding status:ready" in w and "status:deferred" in w for w in r["warnings"]),
        True)
    # The CONTROL, and the half that kills an inverted guard: with no dispatcher-owned status live,
    # the promotion is unchanged. Without this row, `if not held` passes every assertion above.
    chk("[#1054] CONTROL: with no dispatcher status live the promotion still fires",
        sorted(triage(["area:dispatch", "priority:P1", "role:impl", "status:untriaged"],
                      "task")["add"]), ["status:ready"])
    # Every member of the set, individually — a guard that keeps the CONSTANT but drops one member
    # is the mutation a whole-set assertion cannot see (`status:deferred` is 30/30 of the measured
    # population, but the in-progress pair was re-minted on the same timelines).
    for held_label in sorted(DISPATCHER_OWNED_STATUS):
        seed = ["area:dispatch", "priority:P1", "role:impl", held_label]
        chk(f"[#1054] ...for each dispatcher-owned status individually: {held_label}",
            "status:ready" in triage(seed, "task")["add"], False)
    # Still a FIXED POINT under the new branch: the withheld plan must be EMPTY, not oscillating.
    chk("[#1054] the withheld plan is a fixed point (no add, no remove, no churn)",
        (sorted(r["add"]), sorted(r["remove"])), ([], []))
    # [#1054 round 2] THE SECOND ROUTE OUT OF THE FRONTIER. The `status:untriaged` strip is
    # DELIBERATELY outside the withhold: `status:untriaged` is triage's OWN label, and clearing it
    # is exactly what leaves a clean lone-`status:deferred` row the retry lane can select. Move the
    # strip inside the guard and the issue lands `status:untriaged` + `status:deferred` instead —
    # which `dispatch.yml`'s `retry_gated` refuses — re-stranding it by a DIFFERENT route while
    # every row above stays green. Found by review; it survived the first round of mutants.
    _du = ["area:dispatch", "priority:P1", "role:impl", "status:deferred", "status:untriaged"]
    _rdu = triage(_du, "task")
    _post_du = (set(_du) | _rdu["add"]) - _rdu["remove"]
    chk("[#1054] a DEFERRED+UNTRIAGED complete issue is left as a CLEAN lone-deferred row "
        "(untriaged stripped, ready still withheld) — the retry lane's only admissible shape",
        (sorted(_post_du), "status:untriaged" in _rdu["remove"]),
        (["area:dispatch", "priority:P1", "role:impl", "status:deferred"], True))

    # MUTATION. Every row above passes against a guard that is present but INERT, so the guard is
    # re-derived from this file's own source with the behaviour broken and the STRUCTURE those rows
    # inspect left intact — the constant still exists, `held` is still computed, the branch is still
    # there. Each mutant must be killed by a NAMED assertion below, never by an exception.
    import os as _os  # noqa: PLC0415 — this suite imports os function-locally throughout
    _self_path = _os.path.abspath(__file__)
    with open(_self_path, encoding="utf-8") as _fh:
        _src = _fh.read()

    def _mutant(old, new, label):
        mutated = _src.replace(old, new)
        assert mutated != _src, f"[#1054] mutation target moved ({label}) — refusing to pass"
        namespace = {"__name__": "triage_mutant", "__file__": _self_path}
        exec(compile(mutated, f"<mutant:{label}>", "exec"), namespace)  # noqa: S102
        return namespace["triage"]

    # (m1) the constant survives by NAME but is emptied — the "name inside a zero-valued counter"
    # shape: every structural check for DISPATCHER_OWNED_STATUS still finds it.
    _m1 = _mutant('DISPATCHER_OWNED_STATUS = frozenset({\n    "status:deferred",',
                  'DISPATCHER_OWNED_STATUS = frozenset({\n    ' + '"__never__",', "emptied-set")
    chk("[#1054] MUTANT emptied-set (constant present, membership gone) RE-MINTS the pair",
        "status:ready" in _m1(deferred_1037, "task")["add"], True)
    # (m2) the guard is computed and the warning still raised — but the write happens anyway. This
    # is the mutant a warnings-only or `ready`-only assertion cannot distinguish.
    _m2 = _mutant("        if held:\n", "        if False:\n", "guard-never-fires")
    chk("[#1054] MUTANT guard-never-fires RE-MINTS the pair",
        "status:ready" in _m2(deferred_1037, "task")["add"], True)
    # (m3) inverted: withholds on the CLEAN issue and promotes on the deferred one. Killed only by
    # the CONTROL row's mirror below, which is why the control exists.
    _m3 = _mutant("        if held:\n", "        if not held:\n", "inverted-guard")
    chk("[#1054] MUTANT inverted-guard RE-MINTS the pair",
        "status:ready" in _m3(deferred_1037, "task")["add"], True)
    chk("[#1054] MUTANT inverted-guard ALSO breaks the clean promotion (the control's mirror)",
        "status:ready" in _m3(["area:dispatch", "priority:P1", "role:impl"], "task")["add"], False)
    # (m4) the set keeps four of its five members and loses only `status:deferred` — structurally
    # identical, non-empty, and the exact 30/30 measured population walks straight through it.
    _m4 = _mutant('    "status:deferred",            # dispatch-claim bounded retry lane',
                  '    # (removed by mutation)       # dispatch-claim bounded retry lane',
                  "one-member-dropped")
    chk("[#1054] MUTANT one-member-dropped (4 of 5 members intact) RE-MINTS the measured pair",
        "status:ready" in _m4(deferred_1037, "task")["add"], True)
    chk("[#1054] ...while its surviving members still withhold — so only the per-member rows kill it",
        "status:ready" in _m4(["area:dispatch", "priority:P1", "role:impl",
                               "status:in-progress"], "task")["add"], False)
    # (m5) THE REVIEW-FOUND SURVIVOR: the guard fires, `status:ready` is correctly withheld, and the
    # issue is STILL stranded — because the `status:untriaged` strip moved inside the guard, so a
    # deferred+untriaged row keeps a label `retry_gated` refuses. Withholding the promotion is not
    # sufficient; the row also has to be left in a shape the retry lane can take.
    _m5 = _mutant("            add.add(\"status:ready\")\n        remove.add(\"status:untriaged\")\n"
                  "        remove.add(\"needs:area\")\n",
                  "            add.add(\"status:ready\")\n            remove.add(\"status:untriaged\")\n"
                  "            remove.add(\"needs:area\")\n", "strip-inside-guard")
    _r5 = _m5(_du, "task")
    chk("[#1054] MUTANT strip-inside-guard withholds ready CORRECTLY but re-strands the row as "
        "untriaged+deferred, which retry_gated refuses",
        sorted((set(_du) | _r5["add"]) - _r5["remove"]),
        ["area:dispatch", "priority:P1", "role:impl", "status:deferred", "status:untriaged"])
    chk("[#1054] ...and it leaves the CLEAN promotion untouched — so only the deferred+untriaged "
        "row above can kill it",
        sorted(_m5(["area:dispatch", "priority:P1", "role:impl", "status:untriaged"],
                   "task")["add"]), ["status:ready"])

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

    # ---------------------------------------------------------------------------------------------
    # [sparq#4809] THE HEADLINE GUARD: A DERIVED PRIORITY CAN NEVER OUTRANK A STATED ONE.
    #
    # This is the property the whole change rests on. If it does not hold, deriving a priority
    # really does destroy prioritisation — hand-triaged P0..P3 work starts losing its lane to
    # issues nobody ranked — and the right answer would have been to leave the backlog invisible.
    # So it is asserted twice: once about the CONSTANT, and once about the CONSEQUENCE, executed
    # through the real frontier engine rather than restated as a fact about the source.
    _ranks = {f"priority:P{n}": n for n in range(5)}
    chk("[sparq#4809] the derived priority is READABLE by the engine that consumes it — a typo "
        "here writes a label `_valid_priority` rejects, and nothing is ever ready again",
        _valid_priority({DERIVED_PRIORITY}), True)
    chk("[sparq#4809] the derived priority is the numerically LOWEST rank the engine accepts — "
        "the entire reason supplying the missing input does not displace triaged work",
        _ranks[DERIVED_PRIORITY], max(_ranks.values()))
    # `derive_priority` may return the floor or NOTHING — never any other rank. Exhaustive over the
    # stated-priority shapes a label set can take, so a future rung that returns P0/P1/P2 for some
    # signal is caught even where no hand-written case covers that signal.
    _returned = {derive_priority(set(extra) | {"area:usage"})[0] for extra in (
        (), ("priority:P0",), ("priority:P3",), ("priority:P4",), ("priority:P7",),
        ("priority:P1", "priority:P2"), ("priority:",), ("kind:epic",), ("needs:user",),
        ("role:impl", "from:agent", "self-improvement"))}
    chk("[sparq#4809] derive_priority returns ONLY the floor or nothing, never another rank",
        _returned - {None, DERIVED_PRIORITY}, set())

    # THE CONSEQUENCE, EXECUTED. The two rows below contest ONE package, so the frontier must pick
    # exactly one of them. The derived row's labels are produced by RUNNING triage() — this consumes
    # the real derivation, so a test that still passed after the derivation was deleted or re-ranked
    # would have to be lying about something it actually ran.
    _ready_mod = load_sibling("ready-issues.py", "registry_ready_issues_selftest_priority")
    _quiet = lambda *_a, **_k: None                                            # noqa: E731
    _derived_labels = sorted({"role:impl", "area:usage"} | triage(["role:impl", "area:usage"],
                                                                  "task")["add"])
    _derived_row = {"number": 900, "state": "OPEN", "labels": _derived_labels, "open_blockers": 0}
    _stated_row = {"number": 100, "state": "OPEN", "open_blockers": 0,
                   "labels": ["status:ready", "role:impl", "area:usage", "priority:P1"]}
    chk("[sparq#4809] HEADLINE: a DERIVED-priority issue never displaces a STATED-priority one on "
        "a contested package (run through the real ready-issues frontier)",
        [i["number"] for i in _ready_mod.compute_ready([_derived_row, _stated_row], log=_quiet)],
        [100])
    # ...and the mirror image, which is what makes the guard above a TRADE-OFF rather than a no-op:
    # the derived row IS dispatchable when nothing stated contests its package. Without this, the
    # change could buy visibility while dispatching nothing — the status quo with extra writes.
    chk("[sparq#4809] HEADLINE: a DERIVED-priority issue IS selected when its package is idle",
        [i["number"] for i in _ready_mod.compute_ready([_derived_row], log=_quiet)], [900])

    # ---------------------------------------------------------------------------------------------
    # [OPUS-5 #1053 review] THE COLLISION THE FLOOR ITSELF CREATES — the majority path, not an edge.
    #
    # The ordering invariant above ("a derived priority can never OUTRANK a stated one") is true and
    # was never the problem. The problem is that the argument is about outranking and the damage is
    # about BLOCKING: a floor written at `opened` and a priority stated 90s later are TWO valid
    # priorities, `_valid_priority` returns False for the pair, and the issue leaves the frontier.
    # Measured on this board, 53% of recently-prioritised issues are labelled >90s after creation,
    # so without the retract rung this change MANUFACTURES the stuck state it exists to remove.
    #
    # Driven as a real loop to a fixed point rather than as three hand-written expectations: the
    # bound is the claim, so a rung that re-derives on the next tick has to fail here.
    _labels = {"role:impl", "area:groom"}
    _trace, _injected = [], False
    for _tick in range(6):
        _r = triage(_labels, "task")
        _trace.append(_r["priority_reason"])
        _next = (_labels | _r["add"]) - _r["remove"]
        if not _injected:                       # the actor states the real priority, post-floor
            _next |= {"priority:P1"}
            _injected = True
        if _next == _labels:
            break
        _labels = _next
    chk("[#1053] open-without-priority -> floor -> a stated P1 arrives -> CONVERGES on the stated "
        "value, floor retracted, in BOUNDED ticks with no oscillation",
        (_labels == {"role:impl", "area:groom", "priority:P1", "status:ready"}, len(_trace),
         _trace), (True, 3, ["unprioritised-floor", "floor-retracted", "stated"]))
    chk("[#1053] the retract is a REMOVE of the floor, not an overwrite of the stated value",
        (triage({"role:impl", "area:groom", "priority:P4", "priority:P1"}, "task")["remove"],
         triage({"role:impl", "area:groom", "priority:P4", "priority:P1"}, "task")["ready"]),
        ({DERIVED_PRIORITY}, True))
    # THE LINE THE RETRACT MUST NOT CROSS. A pair with no floor in it is a GENUINE ambiguity and is
    # a human's to resolve — retracting there would be the machine picking a winner between two
    # stated values. Asserted for every unordered P0..P3 pair, not just one example.
    for _a in range(4):
        for _b in range(_a + 1, 4):
            _pair = {f"priority:P{_a}", f"priority:P{_b}", "role:impl", "area:groom"}
            chk(f"[#1053] P{_a}+P{_b} (no floor) still DECLINES untouched — not the machine's to "
                f"resolve", (derive_priority(_pair)[1], derive_priority(_pair)[2],
                             triage(_pair, "task")["ready"]),
                ("stated-unreadable", frozenset(), False))
    # ...and three-way sets, including ones containing the floor, are ambiguous too: "exactly one
    # other rank" is the whole precondition, so a floor + two stated values must not retract.
    chk("[#1053] floor + TWO stated ranks is still ambiguous — the retract needs exactly one",
        derive_priority({"priority:P4", "priority:P1", "priority:P2"})[1], "stated-unreadable")
    chk("[#1053] a LONE floor is authoritative — nothing to retract against",
        derive_priority({DERIVED_PRIORITY})[1], "stated")

    # ---- guards that were correct but unasserted (#1053 review: surviving mutants N1/N2/N7/N9) ----
    chk("[#1053/N2] a lone OUT-OF-RANGE priority declines — it is a human's typo, not a vacancy",
        (derive_priority({"priority:P7"})[1], derive_priority({"priority:P7"})[0]),
        ("stated-unreadable", None))
    chk("[#1053/N9] an epic is never given a priority — a tracking umbrella is not dispatchable",
        (triage(["kind:epic", "role:impl", "area:groom"], "task")["priority_reason"],
         any(lb.startswith("priority:")
             for lb in triage(["kind:epic", "role:impl", "area:groom"], "task")["add"])),
        ("epic", False))
    chk("[#1053/N1] RUNG ORDER: an unreadable stated priority is decided BEFORE the ready-attested "
        "regression rung, so a doubly-broken issue reports the human-owned reason",
        derive_priority({"status:ready", "priority:P1", "priority:P2"})[1], "stated-unreadable")
    # [#1053/N7] PINNED DECISION, not an accident: the floor IS written to an issue that cannot
    # become ready (here, `needs:user`-gated). It is deliberate — the value is correct the moment
    # the gate lifts, and the retract rung means a later stated priority is not a trap. What must
    # NOT happen is the gate being bypassed.
    _gated = triage(["role:impl", "area:groom", "needs:user"], "task")
    chk("[#1053/N7] a gated issue IS floored (deliberate) but is NEVER made ready by it",
        (DERIVED_PRIORITY in _gated["add"], _gated["ready"], "status:ready" in _gated["add"]),
        (True, False, False))

    # -----------------------------------------------------------------------------------------------
    # [#582 acceptance 4] THE LABEL-VOCABULARY DRIFT GUARD.
    #
    # The per-issue controls above are all REACTIVE — they fire once an issue has already reached
    # the hole, for the labels that issue's plan happens to name. This section pins the STANDING
    # question: can the planner emit a label the repository does not define AT ALL?
    # -----------------------------------------------------------------------------------------------
    import os as _os_vocab  # noqa: PLC0415 — this suite imports os function-locally throughout
    import shutil
    import subprocess as _subprocess_vocab
    import tempfile
    import types

    # The vocabulary, pinned to an INDEPENDENT literal (AGENTS.md pre-flight 2b). Every element is
    # written out by hand rather than read back from ROLE_LABELS/NON_ROLE_VOCABULARY/
    # DERIVED_PRIORITY, so adding a derivable role or a new emitted label — the exact edit that
    # created #582 — cannot move the code and its expectation together. `role:soundness` is
    # ABSENT here because this repository does not define it; that absence is the decision #582
    # took, and this row is where a re-introduction is caught.
    chk("[#582] the certified vocabulary is EXACTLY this set (pinned independently of the tables)",
        sorted(emittable_labels()),
        ["needs:area", "priority:P4", "role:ci", "role:docs", "role:impl", "role:research",
         "role:site", "status:ready", "status:untriaged", "trust:untrusted"])
    # ...and it is COMPUTED from the derivation tables, not hard-coded: re-point one table at the
    # historical `soundness` value and the guard must report it as drift. This is the row that
    # makes the flip contemplated in TRUST_PLANE_ROLE's TODO safe — the vocabulary follows the code
    # the moment the code can emit the label, BEFORE any issue is triaged with it.
    _repo_labels = set(emittable_labels()) | {"area:docs", "priority:P1", "kind:bug"}
    chk("[#582] a repo that defines the whole vocabulary shows NO drift",
        label_drift(_repo_labels), [])
    # THE OFFLINE HALF OF THE SAME QUESTION. The scheduled job answers it against the LIVE label
    # set; this answers it here, in the gate, against `REAL` — the label snapshot pinned above
    # (gh label list, 2026-07-25). So a vocabulary addition that this repository does not define is
    # caught by the author's own `--self-test`, before the change is even pushed, and the workflow
    # remains the authority on drift the snapshot cannot see (a label deleted on the live board).
    chk("[#582] every emittable label exists in the pinned live registry label snapshot — the "
        "scheduled guard is GREEN on today's board",
        label_drift(REAL), [])
    _saved_area = dict(AREA_ROLE_DEFAULT)
    try:
        AREA_ROLE_DEFAULT["worker"] = "soundness"
        chk("[#582] THE HISTORICAL DEFECT: a derivation table re-pointed at `role:soundness` — a "
            "label this repository does not define — is reported as drift by NAME, before any "
            "issue is stranded role-less-and-ready",
            (label_drift(_repo_labels), _role(["area:worker"], "task")),
            (["role:soundness"], TRUST_PLANE_ROLE))
    finally:
        AREA_ROLE_DEFAULT.clear()
        AREA_ROLE_DEFAULT.update(_saved_area)
    chk("[#582] ...and the re-point is undone, so the rows below judge the real tables",
        label_drift(_repo_labels), [])
    # FAIL-CLOSED ON AN UNREADABLE LABEL SET: an empty read is what a failed/garbled `gh label
    # list` produces, and reporting it as "no drift" is the same silence #582 was made of.
    _empty = "no drift reported"
    try:
        label_drift([])
    except LabelVocabularyError as exc:
        _empty = str(exc)
    chk("[#582] an EMPTY/unreadable repo label set is REFUSED, never read as clean",
        ("refusing to certify" in _empty, "EMPTY or unreadable" in _empty), (True, True))

    # CLOSURE — the vocabulary really covers what `triage()` plans. The corpus is pinned by the set
    # of adds it produces, so a corpus that silently stops planning anything (or a `triage()` that
    # stops adding) reds the FIRST row rather than making the second one vacuously true.
    _corpus = [(["priority:P2", "kind:docs", "area:docs"], "task"),          # role:docs + ready
               (["priority:P1", "area:worker"], "feature"),                  # trust-plane role
               (["priority:P2", "area:ci"], "feature"),                      # role:ci
               (["priority:P2", "area:dashboard"], "feature"),               # role:site
               (["priority:P3", "kind:research", "area:usage"], "task"),     # role:research
               (["area:usage"], "feature"),                                  # the derived floor
               (["role:impl"], "feature"),                                   # needs:area park
               (["priority:P1", "area:docs", "needs:user"], "task")]         # gated -> untriaged
    _planned = set().union(*(triage(labels, kind)["add"] for labels, kind in _corpus))
    chk("[#582] the closure corpus really exercises the emitters (a corpus that plans nothing "
        "proves nothing)",
        sorted(_planned),
        ["needs:area", "priority:P4", "role:ci", "role:docs", "role:impl", "role:research",
         "role:site", "status:ready", "status:untriaged"])
    chk("[#582] every label triage() plans to ADD is in the certified vocabulary",
        sorted(_planned - emittable_labels()), [])
    # ...and the OTHER producer on this surface: the quarantine step's own label writes. It is part
    # of the triage surface and its post-read fails the step if a label does not exist, so those
    # labels must be certified by the same guard.
    _quarantine_writes = sorted(re.findall(r"--add-label (\S+)", quarantine_body))
    chk("[#582] the quarantine step writes exactly these labels (input pinned, not inferred)",
        _quarantine_writes, ["status:untriaged", "trust:untrusted"])
    chk("[#582] ...and every one of them is in the certified vocabulary",
        sorted(set(_quarantine_writes) - emittable_labels()), [])

    # THE CLI CONTRACT, exercised through main() — 0 clean, 1 drifted, 1 unreadable. Each row
    # asserts the EXIT CODE and the message, because the workflow step below reads only the exit
    # code and an operator reads only the annotation.
    def _drift_cli(*argv):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(["--label-drift", *argv])
        return code, buffer.getvalue()

    _clean_code, _clean_out = _drift_cli("--known-labels", ",".join(sorted(_repo_labels)))
    chk("[#582] --label-drift exits 0 on a complete label set, and CENSUSES the zero row (a silent "
        "clean run is indistinguishable from one that never ran)",
        (_clean_code, "missing=0" in _clean_out, "::error" in _clean_out), (0, True, False))
    _red_code, _red_out = _drift_cli(
        "--known-labels", ",".join(sorted(_repo_labels - {"role:impl"})))
    chk("[#582] --label-drift exits 1 and NAMES the missing label",
        (_red_code, "::error" in _red_out, "role:impl" in _red_out, "missing=1" in _red_out),
        (1, True, True, True))
    _bare_code, _bare_out = _drift_cli()
    chk("[#582] --label-drift with NO label set exits 1 (fail closed), never 0",
        (_bare_code, "::error" in _bare_out), (1, True))

    # -----------------------------------------------------------------------------------------------
    # THE YAML SEAM — the guard's step body is EXECUTED, not pattern-matched (AGENTS.md pre-flight
    # 6: "the YAML seam is where the vacuity lives"). The step is run twice against a stubbed
    # `gh_retry` that serves a label set from the environment: a COMPLETE set must exit 0 and a set
    # with one vocabulary label missing must exit non-zero. Between them they kill a dropped
    # `--known-labels` (the complete run would then exit 1 on the empty-set refusal), a `|| true`
    # or dropped `--label-drift` (the deficient run would exit 0), and a hard-coded label list in
    # the shell (the deficient run would exit 0).
    # -----------------------------------------------------------------------------------------------
    _retriage_wf = _os_vocab.path.join(root, ".github/workflows/retriage.yml")
    # The step extractor lives in retriage.py (ONE definition — it is retriage.yml's own file), so
    # it is imported rather than re-spelled here. `sys.modules["triage"]` is seeded with THIS
    # module's own namespace first, because retriage.py does `import triage`: under
    # `python3 scripts/triage.py --self-test` that would exec this file a SECOND time as a distinct
    # module object, which silently breaks `python3 -m trace --count` — the import copy's zero
    # counts overwrite the running copy's, so every executed line in this file reports as
    # never-executed and AGENTS.md pre-flight 1 becomes unusable on the module that needs it most.
    # Measured before the seed: `labels = set(labels)` in `triage()` read `>>>>>>` instead of 119.
    # The alias is built from `globals()` rather than from `sys.modules[__name__]` because under
    # `-m trace` this script has NO sys.modules entry at all (`__main__` is trace's own module).
    _alias = types.ModuleType("triage")
    _alias.__dict__.update(globals())
    _alias.__name__ = "triage"
    sys.modules.setdefault("triage", _alias)
    _step = load_sibling("retriage.py", "registry_retriage_for_seam").workflow_step_script(
        open(_retriage_wf, encoding="utf-8").read(), "label-drift")
    chk("[#582] retriage.yml carries the label-drift step, and it runs under `set -e` with no "
        "`|| true` on the certification",
        (bool(_step.strip()), "set -euo pipefail" in _step,
         [line.strip() for line in _step.splitlines() if "|| true" in line]),
        (True, True, []))
    _GH_RETRY_LABEL_STUB = '''import os, sys
args = sys.argv[1:]
if args[:2] != ["read", "label"]:
    sys.exit(f"stub gh_retry refuses {args}")
print(os.environ["STUB_LABELS"])
'''

    def _run_drift_step(labels):
        """Execute the workflow's OWN step body against a stubbed label-set read."""
        with tempfile.TemporaryDirectory() as directory:
            scripts = _os_vocab.path.join(directory, "scripts")
            _os_vocab.makedirs(scripts)
            with open(_os_vocab.path.join(scripts, "gh_retry.py"), "w",
                      encoding="utf-8") as handle:
                handle.write(_GH_RETRY_LABEL_STUB)
            shutil.copy(_os_vocab.path.abspath(__file__),
                        _os_vocab.path.join(scripts, "triage.py"))
            environment = dict(_os_vocab.environ, REPO="o/r",
                               STUB_LABELS=",".join(sorted(labels)))
            proc = _subprocess_vocab.run(
                ["bash", "-c", _step], cwd=directory, env=environment, capture_output=True,
                text=True, timeout=120, check=False)
            return proc.returncode, proc.stdout + proc.stderr

    _step_ok, _step_ok_out = _run_drift_step(_repo_labels)
    chk("[#582] EXECUTED: the workflow step certifies a complete label set and exits 0",
        (_step_ok, "missing=0" in _step_ok_out), (0, True))
    _step_red, _step_red_out = _run_drift_step(_repo_labels - {"role:impl"})
    chk("[#582] EXECUTED: the workflow step FAILS on a repository missing an emittable label, and "
        "names it — the #582 shape caught before an issue is triaged with it",
        (_step_red != 0, "role:impl" in _step_red_out, "::error" in _step_red_out),
        (True, True, True))
    # The flag the step passes must be one the parser DECLARES (PR #595 finding 2's class), read
    # out of the workflow FILE so a renamed flag lands here rather than live.
    _drift_argvs = [argv for argv in workflow_argvs(_retriage_wf, "triage.py", {"REPO": "o/r"})
                    if "--label-drift" in argv]
    chk("[#582] retriage.yml's drift invocation exists and every flag it passes is DECLARED",
        (len(_drift_argvs), sorted({token for argv in _drift_argvs for token in argv
                                    if token.startswith("--")} - declared_options(build_parser()))),
        (1, []))

    print("triage self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def build_parser():
    """The CLI contract. Built by a named function so the self-test can assert that every flag
    .github/workflows/triage-issue.yml passes is actually DECLARED here (PR #595 finding 2)."""
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--labels", default="", help="comma-separated current labels")
    # The issue's REAL GitHub type NAME (#598), passed verbatim by triage-issue.yml from
    # `github.event.issue.type.name` and EMPTY when the issue has no type — which stays empty and
    # derives the role from the area (#225). The default applies only when a caller omits the flag
    # entirely (a hand-run), so it keeps that invocation behaving as it always did.
    ap.add_argument("--type", default=DEFAULT_ISSUE_TYPE)
    ap.add_argument("--untrusted", action="store_true")
    ap.add_argument("--apply", action="store_true",
                    help="read + mutate the live issue FAIL-CLOSED (needs --repo/--number)")
    ap.add_argument("--repo", default="")
    ap.add_argument("--number", default="")
    ap.add_argument("--known-labels", default="",
                    help="comma-separated repo label set; enables the #582 existence check")
    # The standing vocabulary certification retriage.yml's `label-drift` job runs (#582). Reads the
    # SAME `--known-labels` oracle the per-issue existence check uses, so there is one spelling of
    # "the repository's label set" across this CLI.
    ap.add_argument("--label-drift", action="store_true",
                    help="exit 1 if the planner can emit a label --known-labels does not define")
    # The quarantine authorization decision triage-issue.yml gates its quarantine step on. Prints
    # `1` (apply/restore the quarantine) or `0`. Defaults are the UNTRUSTED spelling on every flag,
    # so a dropped argument fails closed to `1` rather than silently un-quarantining.
    ap.add_argument("--quarantine-decision", action="store_true",
                    help="print 1/0: must this issue event (re-)apply the quarantine labels?")
    ap.add_argument("--action", default="", help="the issue event action (opened/unlabeled/...)")
    ap.add_argument("--author-trusted", default="0", help="1 if the issue AUTHOR is write+")
    ap.add_argument("--actor-trusted", default="0", help="1 if the event ACTOR is write+")
    return ap


def main(argv=None):
    ap = build_parser()
    a = ap.parse_args(argv)
    if a.self_test:
        return _self_test()
    if a.quarantine_decision:
        print("1" if quarantine_required(a.action, a.author_trusted, a.actor_trusted) else "0")
        return 0
    if a.label_drift:
        return _label_drift_cli([x for x in a.known_labels.split(",") if x.strip()])
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
