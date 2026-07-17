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
import json
from pathlib import Path, PurePosixPath
import sys
import tomllib


POLICY_PATH = "policy/repos.toml"
# [OPUS-4.8] "registry-selftest" is the python/actions gate profile for a self-managed target
# (the registry itself) — the crate-scoped cargo gate does not fit a python repo. worker-live.sh
# run_gate implements it: run every touched script's --self-test, the full recent-wave suite, and
# bash -n / actionlint on touched shell + workflow files. Fail-closed.
GATE_PROFILES = {"none", "lint-only", "crate-scoped", "workspace", "registry-selftest"}
DISPATCH_MODES = {"cron", "cron+doorbell"}
TRUST_MODES = {"collaborators"}
POLICY_FIELDS = {
    "enabled",
    "routing",
    "account_pool",
    "max_concurrent",
    "worker_timeout_minutes",
    "gate_profile",
    "arm_auto_merge",
    "max_attempts",
    "dispatch",
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
# pass it to worker-pr.trust_surface_paths_touched). NOT a dead tier: an empty/absent list simply
# means the worker-pr.py DEFAULT_TRUST_SURFACE_PATHS applies (the guard is never silently off).
OPTIONAL_POLICY_FIELDS = {"require_usage", "usage_safety_margin", "max_review_rounds",
                          "review_queue_ttl_minutes", "cross_provider_fallback", "security_paths"}


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
    if len(set(pool)) != len(pool):
        raise PolicyError(f"account_pool for {target_repo!r} contains duplicates")

    for field in ("max_concurrent", "worker_timeout_minutes", "max_attempts"):
        if not _positive_int(row[field]):
            raise PolicyError(f"{field} for {target_repo!r} must be a positive integer")
    if row["gate_profile"] not in GATE_PROFILES:
        raise PolicyError(f"unknown gate_profile {row['gate_profile']!r} for {target_repo!r}")
    if not isinstance(row["arm_auto_merge"], bool):
        raise PolicyError(f"arm_auto_merge for {target_repo!r} must be boolean")
    if row["dispatch"] not in DISPATCH_MODES:
        raise PolicyError(f"unknown dispatch mode {row['dispatch']!r} for {target_repo!r}")
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
    if "security_paths" in row:
        paths = row["security_paths"]
        if (not isinstance(paths, list)
                or any(not isinstance(p, str) or not p.strip() or "\n" in p or "\r" in p
                       for p in paths)):
            raise PolicyError(
                f"security_paths for {target_repo!r} must be a list of non-empty strings")
        if len(set(paths)) != len(paths):
            raise PolicyError(f"security_paths for {target_repo!r} contains duplicates")
    return row


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
            security_routes.append((tuple(keywords), value))
        else:
            role = route["role"]
            if not isinstance(role, str) or not role.strip():
                raise PolicyError(f"{where} role must be a non-empty string")
            if role in role_routes:
                raise PolicyError(f"routing has duplicate role {role!r}")
            role_routes[role] = value
    return default_value, security_routes, role_routes


def resolve(target_repo, role_or_labels, policy_doc, routing_doc):
    """Resolve parsed policy + routing documents without filesystem, network, or global state.

    ``role_or_labels`` may be a bare role string (``"impl"``), a comma-separated label string, or
    an iterable of complete labels. The returned cap fields retain their policy-table names.
    """
    policy = _policy_row(target_repo, policy_doc)
    labels = _normalise_labels(role_or_labels)
    defaults, security_routes, role_routes = _validated_routing(routing_doc)

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
    if routed is None:
        routed = role_routes[role] if role is not None else defaults
    model_chain, agent, escalate = routed

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
        "worker_timeout_minutes": policy["worker_timeout_minutes"],
        "max_attempts": policy["max_attempts"],
        "dispatch": policy["dispatch"],
        "trust": policy["trust"],
    }


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
dispatch = "cron"
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
dispatch = "cron"
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
                                'arm_auto_merge=false\nmax_attempts=1\ndispatch="cron"\ntrust="collaborators"\n'
                                'max_review_rounds=5\nreview_queue_ttl_minutes=45\ncross_provider_fallback=true\n')
    review_impl = resolve("o/r", "impl", review_over, routing)
    check("review-loop controls overridable",
          (review_impl["max_review_rounds"], review_impl["review_queue_ttl_minutes"],
           review_impl["cross_provider_fallback"]), (5, 45, True))
    # security_paths (B3 / defects #2,#4): validated + surfaced (consumed by review-fix.yml).
    check("security_paths default empty", impl["security_paths"], [])
    sec_paths = tomllib.loads('[repos."o/r"]\nenabled=true\nrouting="r.toml"\naccount_pool=["acct01"]\n'
                              'max_concurrent=1\nworker_timeout_minutes=30\ngate_profile="lint-only"\n'
                              'arm_auto_merge=false\nmax_attempts=1\ndispatch="cron"\ntrust="collaborators"\n'
                              'security_paths=["scripts/worker-pr.py", ".github/workflows/"]\n')
    sec_impl = resolve("o/r", "impl", sec_paths, routing)
    check("security_paths surfaced",
          sec_impl["security_paths"], ["scripts/worker-pr.py", ".github/workflows/"])
    bad_paths = tomllib.loads('[repos."o/r"]\nenabled=true\nrouting="r.toml"\naccount_pool=["acct01"]\n'
                              'max_concurrent=1\nworker_timeout_minutes=30\ngate_profile="lint-only"\n'
                              'arm_auto_merge=false\nmax_attempts=1\ndispatch="cron"\ntrust="collaborators"\n'
                              'security_paths=["ok", ""]\n')
    rejects("security_paths rejects empty entry", "security_paths",
            lambda: resolve("o/r", "impl", bad_paths, routing))
    bad_rounds = tomllib.loads('[repos."o/r"]\nenabled=true\nrouting="r.toml"\naccount_pool=["acct01"]\n'
                               'max_concurrent=1\nworker_timeout_minutes=30\ngate_profile="lint-only"\n'
                               'arm_auto_merge=false\nmax_attempts=1\ndispatch="cron"\ntrust="collaborators"\n'
                               'max_review_rounds=0\n')
    rejects("max_review_rounds range validated", "max_review_rounds",
            lambda: resolve("o/r", "impl", bad_rounds, routing))
    over = tomllib.loads('[repos."o/r"]\nenabled=true\nrouting="r.toml"\naccount_pool=["acct01"]\n'
                         'max_concurrent=1\nworker_timeout_minutes=30\ngate_profile="lint-only"\n'
                         'arm_auto_merge=false\nmax_attempts=1\ndispatch="cron"\ntrust="collaborators"\n'
                         'require_usage=true\nusage_safety_margin=0.2\n')
    over_impl = resolve("o/r", "impl", over, routing)
    check("usage controls overridable", (over_impl["require_usage"], over_impl["usage_safety_margin"]),
          (True, 0.2))
    bad = tomllib.loads('[repos."o/r"]\nenabled=true\nrouting="r.toml"\naccount_pool=["acct01"]\n'
                        'max_concurrent=1\nworker_timeout_minutes=30\ngate_profile="lint-only"\n'
                        'arm_auto_merge=false\nmax_attempts=1\ndispatch="cron"\ntrust="collaborators"\n'
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
