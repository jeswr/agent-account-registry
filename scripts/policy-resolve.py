#!/usr/bin/env python3
# [GPT-5.6] REG-1 pure resolver for the private per-repository worker policy. It performs no
# network access, account claims, dispatches, secret reads, or token handling.
"""policy-resolve — combine registry policy with a target repository's routing table.

The pure ``resolve`` core accepts a target repo, a role or label collection, and already-parsed
policy and routing TOML documents. It returns the account pool, model fallback chain, agent, gate
profile, auto-merge posture, and named concurrency/timeout/retry caps. The account allocator later
intersects ``account_pool`` with ``model_chain``; this resolver intentionally knows no live account
state.

Routing precedence is deterministic: security-label override > explicit role > defaults, with the
first matching security rule winning. Defaults apply only when no role label is present. Unknown,
disabled, malformed, or ambiguously labelled repositories/roles fail closed.
"""
import argparse
import copy
import importlib.util
import re
import pathlib
import json
from pathlib import Path, PurePosixPath
import sys
import tomllib


def _import_sibling(module_name, filename):
    """Import a sibling script by path. These scripts are invoked standalone (and loaded by
    dispatch-claim via importlib), so there is no package to import from — but a SHARED rule must
    still be imported rather than re-declared (the #715 idiom)."""
    path = Path(__file__).resolve().with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# [OPUS-5] The CHAIN-ORDER PREFERENCE mechanism, imported — never re-declared. The rule itself
# (which labels, which lead) lives in the TARGET's protected routing table, so PLAN's resolver and
# this CLAIM-side resolver read the same declaration and cannot disagree about it.
_chain_preference = _import_sibling("registry_chain_preference", "chain_preference.py")
ChainPreferenceError = _chain_preference.ChainPreferenceError


POLICY_PATH = "policy/repos.toml"
# [OPUS-4.8] "registry-selftest" is the python/actions gate profile for a self-managed target
# (the registry itself) — the crate-scoped cargo gate does not fit a python repo. worker-live.sh
# run_gate implements it: run every touched script's --self-test, the full recent-wave suite, and
# bash -n / actionlint on touched shell + workflow files. Fail-closed.
GATE_PROFILES = {"none", "lint-only", "crate-scoped", "workspace", "registry-selftest"}
TRUST_MODES = {"collaborators"}
# DOCS-ONLY model aliases (maintainer directive 2026-07-18): terra + sonnet may appear ONLY in a
# docs-role route. Any OTHER resolved route (defaults, a security override, or a non-docs role)
# carrying one is a routing-document defect and fails CLOSED at validation time — structural
# enforcement for ROUTING (sol r2 f3), mirroring the review-loop exclusion in worker-pr.py
# ESCALATION_LADDERS / dispatch-claim.py REVIEW_CHAIN+FIX_CHAIN / review-fix.yml.
#
# [OPUS-5] IMPORTED, never re-declared. `chain_preference` re-applies this same rule to an INJECTED
# chain lead — the one thing that can put a model into a resolved chain that `_reject_docs_only`
# below never saw, because injection happens AFTER validation. Two copies of the list would put the
# CLAIM-side control and the injection bound either side of the very seam the bound closes: add a
# third docs-only alias to one copy and the bypass silently returns. The self-test asserts these are
# the SAME objects, so re-declaring them here reds.
DOCS_ONLY_MODELS = _chain_preference.DOCS_ONLY_MODELS
# Roles whose routes may legitimately carry the docs-only aliases.
DOCS_ROLES = _chain_preference.DOCS_ROLES
POLICY_FIELDS = {
    "enabled",
    "routing",
    "account_pool",
    "max_concurrent",
    "worker_timeout_minutes",
    "gate_profile",
    "arm_auto_merge",
    "max_attempts",
    "trust",
}
# [OPUS-4.8] Optional usage-aware-dispatch controls (default off / 0.10 -> backward compatible):
#   require_usage       = bool  — when true, a TOTAL usage-probe failure HOLDS the repo (fail-closed)
#                                 rather than falling back to the ungated static cap.
#   usage_safety_margin = float in [0,1) — fraction of EACH rate-limit window that must remain free to
#                                 admit a worker (point-in-time headroom; burn-rate caveat in
#                                 select-and-claim.py).
# Optional cross-provider review-loop controls (defaults 3 / 30 / False -> backward compatible):
#   max_review_rounds        = positive int — BASE bound on the review<->fix loop; on exhaustion
#                              worker-pr.py decide_budget may extend to a hard cap of 6 total
#                              rounds (fix-model-tier escalation / improving progress, 2026-07-17)
#                              before needs-user.
#   review_queue_ttl_minutes = positive int — how long a PR may sit review:needs before alerting.
#   cross_provider_fallback  = bool — opt-in same-provider degrade when the opposite provider is
#                              starved; default False = stay queued + alert (the honest default).
# [OPUS-4.8] security_paths (B3 / defects #2,#4): the additive FILE-level trust-surface control
# for the review lane. A worker PR whose diff touches ANY listed path/prefix routes its ARM to a
# HUMAN even for a benign-labelled PR — CONSUMED by review-fix.yml (review-outcome + ready-and-arm
# pass it to worker-pr.trust_surface_paths_touched). NOT a dead tier: [issue #166] this list is
# UNIONED onto the mandatory worker-pr.py DEFAULT_TRUST_SURFACE_PATHS (resolve_trust_surface_paths)
# — it EXTENDS the built-in floor, it never replaces it, so a non-empty list only ADDS per-target
# surfaces and an empty/absent one leaves the defaults in force (the guard is never silently off).
# trusted_bots (registry issue #111): the EXACT, policy-controlled allowlist of trusted App bot
# logins (or App-derived login strings) that the dispatcher admits as issue authors ALONGSIDE the
# `trust = "collaborators"` associations (OWNER/MEMBER/COLLABORATOR). It exists to give the declared
# `trust` field teeth: without it the dispatcher suffix-matched any "<x>[bot]" login and admitted
# unrelated or compromised GitHub Apps. CLAIM unions this list with the RUNTIME-resolved worker App
# bot login (dispatch-claim `bot_login`) so an empty/absent list still trusts our own App bot; it is
# for ADDITIONAL known bots. Absent => empty (fail-closed: no bot is trusted by suffix).
# allow_actions_bot_issues (registry issue #487): per-repo opt-in for ONLY the exact
# `github-actions[bot]` issue-author login. It defaults false. Fork-PR workflows receive read-only
# tokens and cannot create issues, so that login can author an issue in one of our own repositories
# only through a workflow controlled by that repository; this does not broaden any other bot or
# author class.
# [FABLE-5] Observability-only sub-tables consumed by scripts/metrics.py (throughput alert
# thresholds + the per-target readiness-engine selector). policy-resolve accepts-and-ignores them
# so the dispatch/groom resolver never rejects a policy augmented for the metrics collector; the
# collector does its own strict validation of their contents.
OPTIONAL_POLICY_FIELDS = {"require_usage", "usage_safety_margin", "max_review_rounds",
                          "review_queue_ttl_minutes", "cross_provider_fallback", "security_paths",
                          "trusted_bots", "allow_actions_bot_issues", "throughput", "readiness"}


# Slots whose underlying account is dead and which must never appear in an account_pool again.
# Retiring an account removes it from policy/repos.toml; this is the guard that keeps it out.
# Each entry is permanent — set-up-account's slot-allocation union counts acctNN issues in ANY
# state, so a retired name can never be legitimately re-enrolled, and a reappearance in a pool is
# always an error rather than a re-enrolment.
# The canonical account-handle form. Same shape as grant-account.HANDLE_RE — deliberately
# duplicated rather than imported, since these scripts are invoked standalone.
ACCOUNT_HANDLE_RE = re.compile(r"acct[0-9a-z]{2,}")

RETIRED_ACCOUNTS = frozenset({
    "acct03",  # amydouglas1@hotmail.com — cancelled 2026-07-25
    "acct06",  # jwrightwho — expired 2026-07-25
})


class PolicyError(ValueError):
    """A fail-closed policy or routing error suitable for a concise CLI diagnostic."""


def _positive_int(value):
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _policy_row(target_repo, policy_doc):
    if not isinstance(target_repo, str) or not target_repo.strip():
        raise PolicyError("target repo must be a non-empty owner/name string")
    repos = policy_doc.get("repos") if isinstance(policy_doc, dict) else None
    if not isinstance(repos, dict) or target_repo not in repos:
        raise PolicyError(f"unknown target repo {target_repo!r}")
    row = repos[target_repo]
    if not isinstance(row, dict):
        raise PolicyError(f"policy for {target_repo!r} must be a table")

    missing = sorted(POLICY_FIELDS - row.keys())
    extra = sorted(row.keys() - POLICY_FIELDS - OPTIONAL_POLICY_FIELDS)
    if missing:
        raise PolicyError(f"policy for {target_repo!r} is missing fields: {', '.join(missing)}")
    if extra:
        raise PolicyError(f"policy for {target_repo!r} has unknown fields: {', '.join(extra)}")
    if not isinstance(row["enabled"], bool):
        raise PolicyError(f"policy enabled flag for {target_repo!r} must be boolean")
    if not row["enabled"]:
        raise PolicyError(f"target repo {target_repo!r} is disabled")

    routing = row["routing"]
    if not isinstance(routing, str) or not routing.strip():
        raise PolicyError(f"routing path for {target_repo!r} must be a non-empty string")
    routing_path = PurePosixPath(routing)
    if routing_path.is_absolute() or ".." in routing_path.parts:
        raise PolicyError(f"routing path for {target_repo!r} must stay inside the target repo")

    pool = row["account_pool"]
    if (not isinstance(pool, list) or not pool
            or any(not isinstance(account, str) or not account.strip() for account in pool)):
        raise PolicyError(f"account_pool for {target_repo!r} must be a non-empty string list")
    # CANONICAL FORM IS AN INVARIANT, enforced here at the boundary rather than normalised at
    # each comparison site. Cross-provider review round 3 on #660: the retirement guard below
    # intersected the RAW values while this validation only required `.strip()` to be non-empty,
    # so `" acct03"` passed as a legal handle AND evaded the retirement intersection. The
    # consequence went further than a bypass — select-and-claim STRIPS before matching, so the
    # padded entry became eligible, a CAS lease was created, the raw post-claim comparison then
    # failed before publishing `acquired`, and the release job (gated on `acquired == 'true'`)
    # never ran: the lease LEAKED until its 4200/6300s TTL.
    #
    # Rejecting non-canonical handles fixes the whole family at once. Normalising instead would
    # leave every present and future comparison site obliged to remember, and one that forgets
    # reintroduces exactly this bug. Pattern matches grant-account.HANDLE_RE.
    noncanonical = [a for a in pool if ACCOUNT_HANDLE_RE.fullmatch(a) is None]
    if noncanonical:
        raise PolicyError(
            f"account_pool for {target_repo!r} contains non-canonical handle(s) "
            f"{noncanonical!r} — handles must match {ACCOUNT_HANDLE_RE.pattern} exactly, with "
            f"no surrounding whitespace or case variation, so that every downstream comparison "
            f"(retirement, claim, secret lookup) operates on the same value")
    if len(set(pool)) != len(pool):
        raise PolicyError(f"account_pool for {target_repo!r} contains duplicates")
    # A RETIRED slot must never reappear in a pool. Retirement removes the account from
    # policy/repos.toml, but nothing structurally stopped a later edit — or a revert — from
    # putting it back, at which point dispatch burns claims on a dead credential and the review
    # lane stalls. Cross-provider review of the acct06 retirement (#660) named exactly this gap:
    # "the unchanged baseline already contained acct06, so the self-tests evidently do not
    # enforce its retirement; re-adding it would not be caught."
    #
    # This is deliberately a HARD refusal rather than a warning: the failure mode it prevents is
    # silent, and the slot names are permanently reserved anyway (set-up-account counts acctNN
    # issues in ANY state, so a retired slot can never be legitimately re-enrolled under the same
    # name — a reappearance is always a mistake).
    retired = sorted(set(pool) & RETIRED_ACCOUNTS)
    if retired:
        raise PolicyError(
            f"account_pool for {target_repo!r} names RETIRED account(s) {retired} — "
            f"these credentials are dead and their slot names are permanently reserved; "
            f"enrol a NEW slot instead of reusing one")

    for field in ("max_concurrent", "worker_timeout_minutes", "max_attempts"):
        if not _positive_int(row[field]):
            raise PolicyError(f"{field} for {target_repo!r} must be a positive integer")
    if row["gate_profile"] not in GATE_PROFILES:
        raise PolicyError(f"unknown gate_profile {row['gate_profile']!r} for {target_repo!r}")
    if not isinstance(row["arm_auto_merge"], bool):
        raise PolicyError(f"arm_auto_merge for {target_repo!r} must be boolean")
    if row["trust"] not in TRUST_MODES:
        raise PolicyError(f"unknown trust mode {row['trust']!r} for {target_repo!r}")
    if "require_usage" in row and not isinstance(row["require_usage"], bool):
        raise PolicyError(f"require_usage for {target_repo!r} must be boolean")
    if "usage_safety_margin" in row:
        margin = row["usage_safety_margin"]
        if not isinstance(margin, (int, float)) or isinstance(margin, bool) or not (0.0 <= margin < 1.0):
            raise PolicyError(f"usage_safety_margin for {target_repo!r} must be a float in [0, 1)")
    for field in ("max_review_rounds", "review_queue_ttl_minutes"):
        if field in row and not _positive_int(row[field]):
            raise PolicyError(f"{field} for {target_repo!r} must be a positive integer")
    if "cross_provider_fallback" in row and not isinstance(row["cross_provider_fallback"], bool):
        raise PolicyError(f"cross_provider_fallback for {target_repo!r} must be boolean")
    if ("allow_actions_bot_issues" in row
            and not isinstance(row["allow_actions_bot_issues"], bool)):
        raise PolicyError(f"allow_actions_bot_issues for {target_repo!r} must be boolean")
    if "security_paths" in row:
        paths = row["security_paths"]
        if (not isinstance(paths, list)
                or any(not isinstance(p, str) or not p.strip() or "\n" in p or "\r" in p
                       for p in paths)):
            raise PolicyError(
                f"security_paths for {target_repo!r} must be a list of non-empty strings")
        if len(set(paths)) != len(paths):
            raise PolicyError(f"security_paths for {target_repo!r} contains duplicates")
    if "trusted_bots" in row:
        bots = row["trusted_bots"]
        if (not isinstance(bots, list)
                or any(not isinstance(b, str) or not b.strip() or "\n" in b or "\r" in b
                       for b in bots)):
            raise PolicyError(
                f"trusted_bots for {target_repo!r} must be a list of non-empty login strings")
        if len(set(bots)) != len(bots):
            raise PolicyError(f"trusted_bots for {target_repo!r} contains duplicates")
    # Return the same validated policy shape every consumer sees. In particular, CLAIM reads this
    # row directly before route resolution, so the security-sensitive #487 default must live in
    # this shared loader rather than be independently guessed at each call site.
    normalized = dict(row)
    normalized.setdefault("allow_actions_bot_issues", False)
    return normalized


def _normalise_labels(role_or_labels):
    """Return a stable label tuple. A lone bare string is the convenient role form (``impl``)."""
    if isinstance(role_or_labels, str):
        labels = [label.strip() for label in role_or_labels.split(",") if label.strip()]
        if len(labels) == 1 and ":" not in labels[0]:
            labels[0] = f"role:{labels[0]}"
    else:
        try:
            labels = [label.strip() for label in role_or_labels]
        except (TypeError, AttributeError) as exc:
            raise PolicyError("role/labels must be a string or an iterable of strings") from exc
        if any(not label for label in labels):
            raise PolicyError("labels must be non-empty strings")
    return tuple(dict.fromkeys(labels))


def _route_value(route, where, model_catalog):
    chain = route.get("model_chain")
    agent = route.get("agent")
    if (not isinstance(chain, list) or not chain
            or any(not isinstance(model, str) or not model.strip() for model in chain)):
        raise PolicyError(f"{where} model_chain must be a non-empty string list")
    if len(set(chain)) != len(chain):
        raise PolicyError(f"{where} model_chain contains duplicates")
    unknown_models = [model for model in chain if model not in model_catalog]
    if unknown_models:
        raise PolicyError(f"{where} references unknown models: {', '.join(unknown_models)}")
    if not isinstance(agent, str) or not agent.strip():
        raise PolicyError(f"{where} agent must be a non-empty string")
    escalate = route.get("escalate", False)
    if not isinstance(escalate, bool):
        raise PolicyError(f"{where} escalate flag must be boolean")
    return list(chain), agent, escalate


def _reject_docs_only(chain, where):
    """Fail closed when a NON-docs route resolves to a docs-only alias (sol r2 f3)."""
    banned = sorted(set(chain) & DOCS_ONLY_MODELS)
    if banned:
        raise PolicyError(
            f"{where} routes a non-docs surface to docs-only model(s): {', '.join(banned)} — "
            "terra/sonnet are docs-only (maintainer directive 2026-07-18)")


def _validated_routing(routing_doc):
    if not isinstance(routing_doc, dict):
        raise PolicyError("routing document must be a table")
    models = routing_doc.get("models")
    if (not isinstance(models, dict) or not models
            or any(not isinstance(name, str) or not name.strip() for name in models)):
        raise PolicyError("routing models catalog must be a non-empty table")
    defaults = routing_doc.get("defaults")
    if not isinstance(defaults, dict):
        raise PolicyError("routing defaults table is required")
    default_value = _route_value(defaults, "routing defaults", models)
    _reject_docs_only(default_value[0], "routing defaults")

    routes = routing_doc.get("route", [])
    if not isinstance(routes, list):
        raise PolicyError("routing route entries must be an array of tables")
    security_routes = []
    role_routes = {}
    for index, route in enumerate(routes):
        where = f"routing route #{index + 1}"
        if not isinstance(route, dict):
            raise PolicyError(f"{where} must be a table")
        has_labels = "match_labels" in route
        has_role = "role" in route
        if has_labels == has_role:
            raise PolicyError(f"{where} must define exactly one of match_labels or role")
        value = _route_value(route, where, models)
        if has_labels:
            keywords = route["match_labels"]
            if (not isinstance(keywords, list) or not keywords
                    or any(not isinstance(keyword, str) or not keyword for keyword in keywords)):
                raise PolicyError(f"{where} match_labels must be a non-empty string list")
            _reject_docs_only(value[0], where)
            security_routes.append((tuple(keywords), value))
        else:
            role = route["role"]
            if not isinstance(role, str) or not role.strip():
                raise PolicyError(f"{where} role must be a non-empty string")
            if role in role_routes:
                raise PolicyError(f"routing has duplicate role {role!r}")
            if role not in DOCS_ROLES:
                _reject_docs_only(value[0], f"{where} (role {role!r})")
            role_routes[role] = value
    # [OPUS-5] Chain-order preferences, declared BY THE TARGET in its protected routing table and
    # validated here against that table's own [models] catalog. A malformed declaration is raised
    # as a PolicyError so every caller keeps ONE fail-closed error class: silently ignoring it
    # would make CLAIM resolve a chain PLAN did not plan — which is not a lost preference but a
    # permanent per-item defer.
    try:
        preferences = _chain_preference.parse_preferences(routing_doc, set(models))
    except ChainPreferenceError as exc:
        raise PolicyError(f"routing chain_preference is invalid: {exc}") from exc
    return default_value, security_routes, role_routes, preferences


def resolve(target_repo, role_or_labels, policy_doc, routing_doc):
    """Resolve parsed policy + routing documents without filesystem, network, or global state.

    ``role_or_labels`` may be a bare role string (``"impl"``), a comma-separated label string, or
    an iterable of complete labels. The returned cap fields retain their policy-table names.
    """
    policy = _policy_row(target_repo, policy_doc)
    labels = _normalise_labels(role_or_labels)
    defaults, security_routes, role_routes, preferences = _validated_routing(routing_doc)

    roles = sorted({label[5:] for label in labels if label.startswith("role:")})
    if any(not role for role in roles):
        raise PolicyError("role labels must have a non-empty value")
    if len(roles) > 1:
        raise PolicyError(f"ambiguous role labels: {', '.join(roles)}")
    role = roles[0] if roles else None
    if role is not None and role not in role_routes:
        raise PolicyError(f"unknown role {role!r} for target repo {target_repo!r}")

    routed = None
    for keywords, value in security_routes:
        if any(keyword in label for label in labels for keyword in keywords):
            routed = value
            break
    if routed is not None:
        # A SECURITY surface is returned UNMODIFIED. An implementor-preference rule must never
        # re-order a soundness chain: `area:gui` + `area:sparq-zk` is a ZK issue first. This
        # matches the target-side resolver, which also returns its security route untouched.
        model_chain, agent, escalate = routed
    else:
        routed = role_routes[role] if role is not None else defaults
        model_chain, agent, escalate = routed
        # `role` is passed so a preference's `inject_roles` allow-list can be evaluated: adding the
        # lead to a chain that lacks it is legal only for the roles the DECLARATION names. `role` is
        # None for a ROLELESS issue (the defaults branch), which can never be injected into.
        model_chain = _chain_preference.apply_preferences(labels, model_chain, preferences,
                                                         role=role)

    return {
        "target_repo": target_repo,
        "routing": policy["routing"],
        "account_pool": list(policy["account_pool"]),
        "model_chain": list(model_chain),
        "agent": agent,
        "escalate": escalate,
        "gate_profile": policy["gate_profile"],
        "arm_auto_merge": policy["arm_auto_merge"],
        "max_concurrent": policy["max_concurrent"],
        "require_usage": bool(policy.get("require_usage", False)),
        "usage_safety_margin": float(policy.get("usage_safety_margin", 0.10)),
        "max_review_rounds": int(policy.get("max_review_rounds", 3)),
        "review_queue_ttl_minutes": int(policy.get("review_queue_ttl_minutes", 30)),
        "cross_provider_fallback": bool(policy.get("cross_provider_fallback", False)),
        "security_paths": list(policy.get("security_paths", [])),
        "trusted_bots": list(policy.get("trusted_bots", [])),
        "allow_actions_bot_issues": policy["allow_actions_bot_issues"],
        "worker_timeout_minutes": policy["worker_timeout_minutes"],
        "max_attempts": policy["max_attempts"],
        "trust": policy["trust"],
    }


def routing_security_keywords(target_repo, policy_file=POLICY_PATH, target_root="."):
    """FAIL-CLOSED union of every `[[route]].match_labels` keyword in TARGET_REPO's routing.

    [#153 / #325 round 2] This is the keyword source for the arm-side live security-label
    classifier (review-fix.yml resolve -> worker-pr.live_security_flagged). Any inability to
    load the policy row, resolve the routing pointer, parse the routing file, or validate its
    structure RAISES PolicyError — it must never return a reduced set: a silently dropped
    target keyword (e.g. the registry's own worker/dispatch) would let a security label added
    during review classify as benign and auto-arm without the trust-surface audit.
    """
    policy = _policy_row(target_repo, _load_toml(policy_file, "policy file"))
    routing_file = Path(target_root).joinpath(*PurePosixPath(policy["routing"]).parts)
    _, security_routes, _, _ = _validated_routing(_load_toml(routing_file, "routing file"))
    keywords = set()
    for match_keywords, _value in security_routes:
        keywords.update(match_keywords)
    return sorted(keywords)


def _self_test():
    policy = tomllib.loads('''
[repos."sparq-org/sparq"]
enabled = true
routing = "orchestration/routing.toml"
account_pool = ["acct01", "acct02"]
max_concurrent = 2
worker_timeout_minutes = 90
gate_profile = "crate-scoped"
arm_auto_merge = true
max_attempts = 2
trust = "collaborators"

[repos."example/disabled"]
enabled = false
routing = "routing.toml"
account_pool = ["acct01"]
max_concurrent = 1
worker_timeout_minutes = 30
gate_profile = "lint-only"
arm_auto_merge = false
max_attempts = 1
trust = "collaborators"
''')
    # The role route intentionally precedes the security rule: precedence must not depend on that.
    routing = tomllib.loads('''
[models.haiku]
provider = "anthropic"
[models.fable]
provider = "anthropic"
[models.opus]
provider = "anthropic"

[defaults]
model_chain = ["fable"]
agent = "default-agent"

[[route]]
role = "impl"
model_chain = ["fable", "haiku"]
agent = "impl-agent"

[[route]]
match_labels = ["zk", "crypto"]
model_chain = ["opus"]
agent = "security-agent"
escalate = true

[[route]]
role = "docs"
model_chain = ["haiku", "fable"]
agent = "docs-agent"
''')
    policy_before = copy.deepcopy(policy)
    routing_before = copy.deepcopy(routing)
    ok = True

    def check(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got} (want {want})")

    def rejects(name, message, fn):
        nonlocal ok
        try:
            fn()
        except PolicyError as exc:
            good = message in str(exc)
            detail = str(exc)
        else:
            good = False
            detail = "accepted"
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {detail}")

    impl = resolve("sparq-org/sparq", "impl", policy, routing)
    check("bare role resolves model fallback", impl["model_chain"], ["fable", "haiku"])
    check("role resolves agent", impl["agent"], "impl-agent")
    check("account pool preserved", impl["account_pool"], ["acct01", "acct02"])
    check("gate and arm policy", (impl["gate_profile"], impl["arm_auto_merge"]),
          ("crate-scoped", True))
    check("named caps", (impl["max_concurrent"], impl["worker_timeout_minutes"],
                         impl["max_attempts"]), (2, 90, 2))
    check("usage controls default off/0.10", (impl["require_usage"], impl["usage_safety_margin"]),
          (False, 0.10))
    check("review-loop controls default 3/30/False",
          (impl["max_review_rounds"], impl["review_queue_ttl_minutes"],
           impl["cross_provider_fallback"]), (3, 30, False))
    review_over = tomllib.loads('[repos."o/r"]\nenabled=true\nrouting="r.toml"\naccount_pool=["acct01"]\n'
                                'max_concurrent=1\nworker_timeout_minutes=30\ngate_profile="lint-only"\n'
                                'arm_auto_merge=false\nmax_attempts=1\ntrust="collaborators"\n'
                                'max_review_rounds=5\nreview_queue_ttl_minutes=45\ncross_provider_fallback=true\n')
    review_impl = resolve("o/r", "impl", review_over, routing)
    check("review-loop controls overridable",
          (review_impl["max_review_rounds"], review_impl["review_queue_ttl_minutes"],
           review_impl["cross_provider_fallback"]), (5, 45, True))
    # security_paths (B3 / defects #2,#4): validated + surfaced (consumed by review-fix.yml).
    check("security_paths default empty", impl["security_paths"], [])
    sec_paths = tomllib.loads('[repos."o/r"]\nenabled=true\nrouting="r.toml"\naccount_pool=["acct01"]\n'
                              'max_concurrent=1\nworker_timeout_minutes=30\ngate_profile="lint-only"\n'
                              'arm_auto_merge=false\nmax_attempts=1\ntrust="collaborators"\n'
                              'security_paths=["scripts/worker-pr.py", ".github/workflows/"]\n')
    sec_impl = resolve("o/r", "impl", sec_paths, routing)
    check("security_paths surfaced",
          sec_impl["security_paths"], ["scripts/worker-pr.py", ".github/workflows/"])
    bad_paths = tomllib.loads('[repos."o/r"]\nenabled=true\nrouting="r.toml"\naccount_pool=["acct01"]\n'
                              'max_concurrent=1\nworker_timeout_minutes=30\ngate_profile="lint-only"\n'
                              'arm_auto_merge=false\nmax_attempts=1\ntrust="collaborators"\n'
                              'security_paths=["ok", ""]\n')
    # A RETIRED slot reappearing in a pool must be a HARD refusal (#660 review finding 1: the
    # retirement was enforced by nothing, so re-adding acct06 would have gone unnoticed). Both
    # halves are asserted: the retired name is refused, AND the otherwise-identical live pool is
    # accepted — without the second, the check would also pass if resolve() rejected everything.
    def _policy_with_pool(pool):
        doc = copy.deepcopy(policy)
        doc["repos"]["sparq-org/sparq"]["account_pool"] = pool
        return doc

    # Pinned explicitly. The loop below iterates OVER the registry, so emptying the registry
    # would silently reduce it to zero assertions and stay green — found by mutation, and the
    # same "test derives its cases from the implementation" shape as the #659 r2 finding.
    check("the retired registry holds the known retirements (emptying it must not silently "
          "disable every check below)",
          sorted(RETIRED_ACCOUNTS), ["acct03", "acct06"])
    # NON-CANONICAL handles are refused outright (#660 review r3). Padding is the case that
    # bit us: `" acct03"` was a legal handle to the old validation AND invisible to the raw
    # retirement intersection, and downstream select-and-claim strips before matching, so it
    # became claimable and leaked a CAS lease to its TTL. Every variant that could reach a
    # different value at a different comparison site is pinned here.
    for bad in (" acct03", "acct03 ", "\tacct03", "acct03\n", "ACCT03", "Acct03",
                " acct02", "acct02 ", "ACCT02", "acct 02", "acct03;acct01"):
        rejects(f"non-canonical handle {bad!r} is refused", "non-canonical",
                lambda h=bad: resolve("sparq-org/sparq", "impl",
                                      _policy_with_pool(["acct01", h]), routing))
    # "" is refused too, but by the EARLIER non-empty check with a different message — asserted
    # separately so this does not read as a gap in the canonical-handle check.
    rejects("an empty handle is refused (by the non-empty guard, not the shape guard)",
            "non-empty string list",
            lambda: resolve("sparq-org/sparq", "impl", _policy_with_pool(["acct01", ""]), routing))
    check("a canonical pool is still accepted (the handle check is a shape check, not a "
          "blanket refusal)",
          resolve("sparq-org/sparq", "impl",
                  _policy_with_pool(["acct01", "acct2css"]), routing)["account_pool"],
          ["acct01", "acct2css"])
    # The shipped config must itself be canonical, or the retirement intersection below is
    # comparing against values that may not be what downstream sees.
    check("every account in the SHIPPED policy/repos.toml is canonical",
          sorted({a for row in tomllib.loads(
                      pathlib.Path(__file__).resolve().parent.parent
                      .joinpath("policy/repos.toml").read_text(encoding="utf-8"))["repos"].values()
                  for a in row.get("account_pool", [])
                  if ACCOUNT_HANDLE_RE.fullmatch(a) is None}),
          [])

    for retired_slot in sorted(RETIRED_ACCOUNTS):
        rejects(f"a RETIRED slot ({retired_slot}) in an account_pool is refused", "RETIRED",
                lambda slot=retired_slot: resolve(
                    "sparq-org/sparq", "impl", _policy_with_pool(["acct01", slot]), routing))
    check("the same pool WITHOUT a retired slot is accepted (the refusal is specific, not a "
          "blanket rejection)",
          resolve("sparq-org/sparq", "impl",
                  _policy_with_pool(["acct01", "acct02"]), routing)["account_pool"],
          ["acct01", "acct02"])
    # The guard is worthless if the SHIPPED configuration still names a dead account.
    _live = tomllib.loads(pathlib.Path(__file__).resolve().parent.parent
                          .joinpath("policy/repos.toml").read_text(encoding="utf-8"))
    check("the SHIPPED policy/repos.toml names no retired account",
          sorted({a for row in _live["repos"].values()
                  for a in row.get("account_pool", [])} & RETIRED_ACCOUNTS),
          [])

    rejects("security_paths rejects empty entry", "security_paths",
            lambda: resolve("o/r", "impl", bad_paths, routing))
    # trusted_bots (issue #111): validated exact-login allowlist, default empty, surfaced.
    check("trusted_bots default empty", impl["trusted_bots"], [])
    tb = tomllib.loads('[repos."o/r"]\nenabled=true\nrouting="r.toml"\naccount_pool=["acct01"]\n'
                       'max_concurrent=1\nworker_timeout_minutes=30\ngate_profile="lint-only"\n'
                       'arm_auto_merge=false\nmax_attempts=1\ntrust="collaborators"\n'
                       'trusted_bots=["reg-app[bot]", "groom[bot]"]\n')
    check("trusted_bots surfaced", resolve("o/r", "impl", tb, routing)["trusted_bots"],
          ["reg-app[bot]", "groom[bot]"])
    bad_bots = tomllib.loads('[repos."o/r"]\nenabled=true\nrouting="r.toml"\naccount_pool=["acct01"]\n'
                             'max_concurrent=1\nworker_timeout_minutes=30\ngate_profile="lint-only"\n'
                             'arm_auto_merge=false\nmax_attempts=1\ntrust="collaborators"\n'
                             'trusted_bots=["ok", ""]\n')
    rejects("trusted_bots rejects empty entry", "trusted_bots",
            lambda: resolve("o/r", "impl", bad_bots, routing))
    dup_bots = tomllib.loads('[repos."o/r"]\nenabled=true\nrouting="r.toml"\naccount_pool=["acct01"]\n'
                             'max_concurrent=1\nworker_timeout_minutes=30\ngate_profile="lint-only"\n'
                             'arm_auto_merge=false\nmax_attempts=1\ntrust="collaborators"\n'
                             'trusted_bots=["dup[bot]", "dup[bot]"]\n')
    rejects("trusted_bots rejects duplicates", "trusted_bots",
            lambda: resolve("o/r", "impl", dup_bots, routing))
    # Issue #487: the exact actions-bot exception is a validated, per-repo opt-in. Missing means
    # false so a newly onboarded repository cannot inherit this author class accidentally.
    check("allow_actions_bot_issues defaults false", impl["allow_actions_bot_issues"], False)
    actions_opt_in = tomllib.loads(
        '[repos."o/r"]\nenabled=true\nrouting="r.toml"\naccount_pool=["acct01"]\n'
        'max_concurrent=1\nworker_timeout_minutes=30\ngate_profile="lint-only"\n'
        'arm_auto_merge=false\nmax_attempts=1\ntrust="collaborators"\n'
        'allow_actions_bot_issues=true\n')
    check("allow_actions_bot_issues surfaced",
          resolve("o/r", "impl", actions_opt_in, routing)["allow_actions_bot_issues"], True)
    bad_actions_opt_in = tomllib.loads(
        '[repos."o/r"]\nenabled=true\nrouting="r.toml"\naccount_pool=["acct01"]\n'
        'max_concurrent=1\nworker_timeout_minutes=30\ngate_profile="lint-only"\n'
        'arm_auto_merge=false\nmax_attempts=1\ntrust="collaborators"\n'
        'allow_actions_bot_issues="yes"\n')
    rejects("allow_actions_bot_issues requires a boolean", "allow_actions_bot_issues",
            lambda: resolve("o/r", "impl", bad_actions_opt_in, routing))
    bad_rounds = tomllib.loads('[repos."o/r"]\nenabled=true\nrouting="r.toml"\naccount_pool=["acct01"]\n'
                               'max_concurrent=1\nworker_timeout_minutes=30\ngate_profile="lint-only"\n'
                               'arm_auto_merge=false\nmax_attempts=1\ntrust="collaborators"\n'
                               'max_review_rounds=0\n')
    rejects("max_review_rounds range validated", "max_review_rounds",
            lambda: resolve("o/r", "impl", bad_rounds, routing))
    over = tomllib.loads('[repos."o/r"]\nenabled=true\nrouting="r.toml"\naccount_pool=["acct01"]\n'
                         'max_concurrent=1\nworker_timeout_minutes=30\ngate_profile="lint-only"\n'
                         'arm_auto_merge=false\nmax_attempts=1\ntrust="collaborators"\n'
                         'require_usage=true\nusage_safety_margin=0.2\n')
    over_impl = resolve("o/r", "impl", over, routing)
    check("usage controls overridable", (over_impl["require_usage"], over_impl["usage_safety_margin"]),
          (True, 0.2))
    bad = tomllib.loads('[repos."o/r"]\nenabled=true\nrouting="r.toml"\naccount_pool=["acct01"]\n'
                        'max_concurrent=1\nworker_timeout_minutes=30\ngate_profile="lint-only"\n'
                        'arm_auto_merge=false\nmax_attempts=1\ntrust="collaborators"\n'
                        'usage_safety_margin=1.5\n')
    try:
        resolve("o/r", "impl", bad, routing)
        check("usage_safety_margin range validated", "accepted", "rejected")
    except PolicyError:
        check("usage_safety_margin range validated", "rejected", "rejected")
    secure = resolve("sparq-org/sparq", ["role:impl", "area:sparq-zk"], policy, routing)
    check("security label overrides role", (secure["model_chain"], secure["agent"],
                                             secure["escalate"]),
          (["opus"], "security-agent", True))
    fallback = resolve("sparq-org/sparq", ["area:docs"], policy, routing)
    check("no role uses deterministic defaults", (fallback["model_chain"], fallback["agent"]),
          (["fable"], "default-agent"))
    rejects("unknown repo fails closed", "unknown target repo",
            lambda: resolve("unknown/repo", "impl", policy, routing))
    rejects("disabled repo fails closed", "is disabled",
            lambda: resolve("example/disabled", "impl", policy, routing))
    rejects("unknown role fails closed", "unknown role",
            lambda: resolve("sparq-org/sparq", "destroy", policy, routing))
    rejects("multiple roles fail closed", "ambiguous role labels",
            lambda: resolve("sparq-org/sparq", ["role:impl", "role:docs"], policy, routing))
    bad_policy = copy.deepcopy(policy)
    bad_policy["repos"]["sparq-org/sparq"]["concurrency"] = 2
    rejects("unknown policy field fails closed", "unknown fields",
            lambda: resolve("sparq-org/sparq", "impl", bad_policy, routing))
    bad_routing = copy.deepcopy(routing)
    bad_routing["route"][0]["model_chain"] = ["unlisted"]
    rejects("unknown model fails closed", "unknown models",
            lambda: resolve("sparq-org/sparq", "impl", policy, bad_routing))
    # DOCS-ONLY structural rule (sol r2 f3): terra/sonnet in any NON-docs resolved route is a
    # hard validation error; a docs route may carry them.
    docs_ok = copy.deepcopy(routing)
    docs_ok["models"]["terra"] = {"provider": "openai"}
    docs_ok["models"]["sonnet"] = {"provider": "anthropic"}
    docs_ok["route"][2]["model_chain"] = ["haiku", "terra", "sonnet"]  # the docs role route
    check("docs route may use docs-only aliases",
          resolve("sparq-org/sparq", "docs", policy, docs_ok)["model_chain"],
          ["haiku", "terra", "sonnet"])
    bad_impl_docs = copy.deepcopy(docs_ok)
    bad_impl_docs["route"][0]["model_chain"] = ["fable", "terra"]  # the impl role route
    rejects("non-docs role route rejects a docs-only alias", "docs-only",
            lambda: resolve("sparq-org/sparq", "impl", policy, bad_impl_docs))
    bad_defaults_docs = copy.deepcopy(docs_ok)
    bad_defaults_docs["defaults"]["model_chain"] = ["sonnet", "fable"]
    rejects("routing defaults reject a docs-only alias", "docs-only",
            lambda: resolve("sparq-org/sparq", ["area:misc"], policy, bad_defaults_docs))
    bad_security_docs = copy.deepcopy(docs_ok)
    bad_security_docs["route"][1]["model_chain"] = ["opus", "terra"]  # the security override
    rejects("security override rejects a docs-only alias", "docs-only",
            lambda: resolve("sparq-org/sparq", ["role:impl", "area:sparq-zk"], policy,
                            bad_security_docs))
    # [#153 / #325 round 2] routing_security_keywords feeds the ARM-time live label audit; it
    # must fail CLOSED — a missing/unknown policy row or a missing/malformed/invalid routing
    # RAISES instead of degrading to a reduced (permissive) keyword set that would let a
    # security label added mid-review classify as benign and reach the arm step unaudited.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        tmp_root = Path(tmp)
        tmp_policy = tmp_root / "repos.toml"
        tmp_policy.write_text(
            '[repos."o/r"]\nenabled=true\nrouting="orchestration/routing.toml"\n'
            'account_pool=["acct01"]\nmax_concurrent=1\nworker_timeout_minutes=30\n'
            'gate_profile="lint-only"\narm_auto_merge=false\nmax_attempts=1\n'
            'trust="collaborators"\n', encoding="utf-8")
        tmp_target = tmp_root / "target"
        (tmp_target / "orchestration").mkdir(parents=True)
        tmp_routing = tmp_target / "orchestration" / "routing.toml"
        tmp_routing.write_text(
            '[models.fable]\nprovider = "anthropic"\n\n[defaults]\n'
            'model_chain = ["fable"]\nagent = "default-agent"\n\n[[route]]\n'
            'match_labels = ["worker", "dispatch"]\nmodel_chain = ["fable"]\n'
            'agent = "security-agent"\n', encoding="utf-8")
        check("routing security keywords surfaced for the arm-side classifier",
              routing_security_keywords("o/r", tmp_policy, tmp_target),
              ["dispatch", "worker"])
        rejects("unknown repo yields NO keyword set (fail closed)", "unknown target repo",
                lambda: routing_security_keywords("other/repo", tmp_policy, tmp_target))
        rejects("missing routing file yields NO keyword set (fail closed)",
                "cannot load routing file",
                lambda: routing_security_keywords("o/r", tmp_policy, tmp_root / "empty"))
        tmp_routing.write_text("not = valid = toml", encoding="utf-8")
        rejects("malformed routing TOML yields NO keyword set (fail closed)",
                "cannot load routing file",
                lambda: routing_security_keywords("o/r", tmp_policy, tmp_target))
        tmp_routing.write_text('[models.fable]\nprovider = "anthropic"\n', encoding="utf-8")
        rejects("structurally invalid routing yields NO keyword set (fail closed)",
                "routing defaults table is required",
                lambda: routing_security_keywords("o/r", tmp_policy, tmp_target))
    # ---- [OPUS-5] CHAIN-ORDER PREFERENCES (sparq PR #4211 / the area:gui carve-out).
    # THIS resolver is the CLAIM side. PLAN runs the TARGET's route-resolve.py and
    # dispatch-claim._route_matches then demands EXACT equality of the chain, so a preference this
    # resolver does not implement is a permanent `route-policy-failed` defer for every issue it
    # selects — 34 of sparq's 35 open `area:gui` issues, on every tick, forever. The rule is read
    # from the TARGET's protected routing table (data), never hard-coded here.
    pref_routing = copy.deepcopy(routing)
    pref_routing["models"]["opus5"] = {"provider": "anthropic"}
    pref_routing["models"]["sol"] = {"provider": "openai"}
    pref_routing["defaults"]["model_chain"] = ["opus5", "sol"]
    pref_routing["route"][0]["model_chain"] = ["opus5", "sol"]        # role = impl
    pref_routing["route"][1]["model_chain"] = ["opus5"]               # the security override
    pref_routing["route"].append({"role": "research", "model_chain": ["opus5"],
                                  "agent": "research-agent", "escalate": True})
    pref_routing["route"].append({"role": "perf", "model_chain": ["opus5", "sol"],
                                  "agent": "impl-agent"})
    pref_routing["route"].append({"role": "site", "model_chain": ["opus5", "sol"],
                                  "agent": "site-agent"})
    pref_routing["chain_preference"] = [
        {"labels": ["area:gui"], "lead": "sol", "requires": ["sol", "opus5"]}]

    def pref_chain(labels):
        return resolve("sparq-org/sparq", labels, policy, pref_routing)["model_chain"]

    check("area:gui + role:impl -> SOL-first at CLAIM (the 33-issue case)",
          pref_chain(["area:gui", "role:impl", "priority:P2"]), ["sol", "opus5"])
    check("area:gui + role:perf -> SOL-first at CLAIM (the 34th issue)",
          pref_chain(["area:gui", "role:perf"]), ["sol", "opus5"])
    check("area:gui with NO role -> defaults, SOL-first",
          pref_chain(["area:gui", "priority:P2"]), ["sol", "opus5"])
    check("PREFERENCE, NOT EXCLUSION: opus5 stays reachable behind sol",
          "opus5" in pref_chain(["area:gui", "role:impl"]), True)
    check("the carve-out re-orders the chain and NEVER re-routes the agent",
          resolve("sparq-org/sparq", ["area:gui", "role:impl"], policy, pref_routing)["agent"],
          "impl-agent")
    check("area:gui + role:research is UNTOUCHED (both-implementors condition declines, so a "
          "single-provider escalating route is not silently made cross-provider)",
          (pref_chain(["area:gui", "role:research"]),
           resolve("sparq-org/sparq", ["area:gui", "role:research"], policy,
                   pref_routing)["escalate"]),
          (["opus5"], True))
    check("area:gui + a SECURITY surface -> soundness route, UNMODIFIED",
          (pref_chain(["area:gui", "role:impl", "area:sparq-zk"]),
           resolve("sparq-org/sparq", ["area:gui", "role:impl", "area:sparq-zk"], policy,
                   pref_routing)["agent"]),
          (["opus5"], "security-agent"))
    # ...AND THE SAME EXEMPTION WITH A CROSS-PROVIDER SOUNDNESS CHAIN. Found by mutation: with
    # today's single-model security chain (["opus5"]) the `requires` condition declines anyway, so
    # applying the preference to the security branch was an UNDETECTABLE mutation — the exemption
    # was defence-in-depth with no red test, exactly the shape a reviewer flagged as "worth an
    # assertion if a security route ever becomes cross-provider". This fixture makes it one now,
    # rather than after some future edit makes the soundness lane cross-provider.
    xprov_sec = copy.deepcopy(pref_routing)
    xprov_sec["route"][1]["model_chain"] = ["opus5", "sol"]
    check("a CROSS-PROVIDER security route is STILL returned unmodified under area:gui (the "
          "exemption is the ROUTE CLASS, not an accident of that chain being single-model)",
          resolve("sparq-org/sparq", ["area:gui", "role:impl", "area:sparq-zk"], policy,
                  xprov_sec)["model_chain"], ["opus5", "sol"])
    check("...and the same table still applies the preference on the ROLE branch, so the check "
          "above is an exemption and not a dead fixture",
          resolve("sparq-org/sparq", ["area:gui", "role:impl"], policy,
                  xprov_sec)["model_chain"], ["sol", "opus5"])
    for outside in ("area:site", "area:site-specs", "area:site-papers", "area:sitemap",
                    "surface:frontend", "dashboard", "area:guide", "area:guidance"):
        check(f"{outside} is OUTSIDE the carve-out (opus5-first)",
              pref_chain([outside, "role:impl"]), ["opus5", "sol"])
    check("a plain crate area is unaffected", pref_chain(["area:sparq-core", "role:impl"]),
          ["opus5", "sol"])
    # THE SAFE-TO-DEPLOY-FIRST PROPERTY, asserted rather than asserted-in-prose: against a routing
    # table with NO declaration this resolver returns exactly what it returned before this change,
    # which is what makes landing the registry side ahead of the target side a strict no-op.
    no_decl = copy.deepcopy(pref_routing)
    del no_decl["chain_preference"]
    check("NO declaration in the target's table -> the pre-change chain, unchanged",
          resolve("sparq-org/sparq", ["area:gui", "role:impl"], policy, no_decl)["model_chain"],
          ["opus5", "sol"])
    # Fail-closed: a malformed declaration must REFUSE, not resolve past it. A dropped preference
    # is precisely a PLAN/CLAIM divergence.
    bad_pref = copy.deepcopy(pref_routing)
    bad_pref["chain_preference"] = [
        {"labels": ["area:gui"], "lead": "sol", "requires": ["opus5"]}]
    rejects("a lead outside requires REFUSES to resolve (it could INJECT a model)",
            "chain_preference is invalid",
            lambda: resolve("sparq-org/sparq", ["area:gui", "role:impl"], policy, bad_pref))
    ghost_pref = copy.deepcopy(pref_routing)
    ghost_pref["chain_preference"] = [
        {"labels": ["area:gui"], "lead": "ghost", "requires": ["ghost"]}]
    rejects("a preference naming an uncatalogued model REFUSES to resolve",
            "chain_preference is invalid",
            lambda: resolve("sparq-org/sparq", ["area:gui", "role:impl"], policy, ghost_pref))
    # ---- [OPUS-5] THE DOCS-ONLY BOUND ON `inject_roles`, END TO END THROUGH resolve().
    # `_reject_docs_only` above inspects STATICALLY DECLARED chains only. `inject_roles` writes the
    # lead into the chain AFTER that validation, so without the parse-time bound in
    # chain_preference a table could lead `role:impl` with `terra` — a route the very same
    # `_reject_docs_only` refuses outright when it is DECLARED — and, because the target's PLAN
    # resolver reads the identical declaration, both sides would AGREE on it and no divergence
    # check would fire. Asserted here, on the CLAIM side, and mirrored in route-resolve (PLAN) and
    # cross-resolver-agreement (symmetry).
    check("the docs-only tier rule is the SAME OBJECT as the shared mechanism's, not a second copy "
          "(re-declaring it here would let the two drift either side of the injection bound)",
          (DOCS_ONLY_MODELS is _chain_preference.DOCS_ONLY_MODELS,
           DOCS_ROLES is _chain_preference.DOCS_ROLES), (True, True))
    docs_lead = copy.deepcopy(pref_routing)
    docs_lead["models"]["terra"] = {"provider": "openai"}
    docs_lead["route"][0]["model_chain"] = ["opus5"]      # role = impl, single-rung (registry #738)
    statically_declared = copy.deepcopy(docs_lead)
    statically_declared["route"][0]["model_chain"] = ["terra", "opus5"]
    rejects("BASELINE — a STATICALLY declared docs-only lead on role:impl is refused (this is the "
            "control `inject_roles` must not be able to route around)", "docs-only",
            lambda: resolve("sparq-org/sparq", ["role:impl"], policy, statically_declared))
    injected = copy.deepcopy(docs_lead)
    injected["chain_preference"] = [{"labels": ["area:gui"], "lead": "terra",
                                     "requires": ["terra", "opus5"], "inject_roles": ["impl"]}]
    rejects("an INJECTED docs-only lead on role:impl is refused too, at PARSE time — the same "
            "outcome as the statically declared form, which is the whole point",
            "chain_preference is invalid",
            lambda: resolve("sparq-org/sparq", ["area:gui", "role:impl"], policy, injected))
    rejects("...and the table is refused for EVERY issue that reads it, not only the selected "
            "ones — a bad DECLARATION is a table defect, not a per-issue routing surprise",
            "chain_preference is invalid",
            lambda: resolve("sparq-org/sparq", ["area:sparq-core", "role:impl"], policy, injected))
    docs_target = copy.deepcopy(docs_lead)
    docs_target["chain_preference"] = [{"labels": ["area:gui"], "lead": "terra",
                                        "requires": ["terra", "opus5"], "inject_roles": ["docs"]}]
    docs_target["route"][2]["model_chain"] = ["opus5"]    # the docs role route, single-rung
    check("a docs-only lead injected into role:docs still RESOLVES (the bound is the "
          "_reject_docs_only exemption, mirrored — not a blanket ban on docs-only leads)",
          resolve("sparq-org/sparq", ["area:gui", "role:docs"], policy,
                  docs_target)["model_chain"], ["terra", "opus5"])
    # THE LIVE DECLARATION IS UNTOUCHED. `lead = "sol"` + `inject_roles = ["impl"]` is the shape
    # sparq ships for the area:gui carve-out; the bound must not perturb it.
    live_shape = copy.deepcopy(docs_lead)
    live_shape["chain_preference"] = [{"labels": ["area:gui"], "lead": "sol",
                                       "requires": ["sol", "opus5"], "inject_roles": ["impl"]}]
    check("the LIVE area:gui declaration (lead = sol) resolves sol-first, unchanged by the bound",
          (resolve("sparq-org/sparq", ["area:gui", "role:impl"], policy,
                   live_shape)["model_chain"],
           resolve("sparq-org/sparq", ["area:sparq-core", "role:impl"], policy,
                   live_shape)["model_chain"]),
          (["sol", "opus5"], ["opus5"]))

    check("pure core leaves fixtures unchanged",
          policy == policy_before and routing == routing_before, True)
    print("policy-resolve self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def _load_toml(path, description):
    try:
        with open(path, "rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise PolicyError(f"cannot load {description} {str(path)!r}: {exc}") from exc


def main():
    ap = argparse.ArgumentParser(
        description="Resolve private repo policy plus target routing without network access.")
    ap.add_argument("--self-test", action="store_true", help="run offline fixture tests")
    ap.add_argument("--target-repo", help="target owner/name from the policy table")
    ap.add_argument("--role", help="bare role name or role:<name> label")
    ap.add_argument("--label", action="append", default=[], help="issue label (repeatable)")
    ap.add_argument("--policy-file", default=POLICY_PATH, help="parsed private policy TOML source")
    ap.add_argument("--routing-file", help="target routing TOML; defaults to the policy pointer")
    ap.add_argument("--target-root", default=".", help="root used for a relative routing pointer")
    args = ap.parse_args()
    if args.self_test:
        return _self_test()
    if not args.target_repo:
        ap.error("--target-repo is required unless --self-test is used")

    try:
        policy_doc = _load_toml(args.policy_file, "policy file")
        policy = _policy_row(args.target_repo, policy_doc)
        routing_file = args.routing_file
        if routing_file is None:
            routing_file = Path(args.target_root).joinpath(*PurePosixPath(policy["routing"]).parts)
        routing_doc = _load_toml(routing_file, "routing file")
        labels = list(args.label)
        if args.role:
            labels.append(args.role if args.role.startswith("role:") else f"role:{args.role}")
        result = resolve(args.target_repo, labels, policy_doc, routing_doc)
    except PolicyError as exc:
        print(f"policy-resolve: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
