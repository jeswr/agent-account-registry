#!/usr/bin/env python3
"""Shared ops-alert destination router (issue #577).

Every ops-alert emitter answers the same question: which repo, under which token, does this alert
issue get written to? The answer is a locked decision (22c, issue #39): a maintainer-set PRIVATE
`ALERT_REPO` is the destination ONLY when an `ALERT_TOKEN` that can write there is also configured;
a HALF-configured deployment (repo set, token missing) falls back to the registry repo under the
ambient token rather than silently failing the private write and losing the alert entirely.

This module exists so a new emitter reuses that decision instead of copy-pasting it. It is
deliberately PURE and env-free: callers read their own environment and pass the three values in, so
the routing decision is testable without touching `os.environ` (issue #436 covers hardening the
env-reading side; it is NOT folded in here).

MIGRATION NOTE: the pre-existing emitters — `plan-alert.py`, `groom-alert.py`, `usage-alert.py`,
`pat-validity.py`, `worker-pr.py` — still carry their own private `_alert_route` copies. They are
NOT migrated here: each alert job sparse-checks-out exactly ONE script file, so migrating any of
them also means editing its workflow's `sparse-checkout` list, and `usage-alert.py` /
`pat-validity.py` additionally carry a `confirmed_private` redaction variant whose semantics differ.
That consolidation is filed as follow-up work; this module is the destination for it.
"""
import sys


def alert_route(alert_repo, alert_token, registry_repo):
    """Return `(repo, token)` for an ops-alert write.

    `token=None` means "use the ambient GH_TOKEN". The private route requires BOTH a repo and a
    token: a repo with no token is a half-configured deployment and falls back to the registry
    repo, because a private write under the ambient token would fail and the alert would vanish.
    """
    if alert_repo and alert_token:
        return alert_repo, alert_token
    return registry_repo, None


def _self_test():
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got} (want {want})")

    # The audited routing matrix (mirrors the copies in plan-alert.py / groom-alert.py, which this
    # module is the shared successor to). Each row flips red if the private/fallback boundary moves.
    chk("repo + token -> private repo under the alert token",
        alert_route("org/private", "tok", "org/registry"), ("org/private", "tok"))
    chk("repo, EMPTY token -> registry fallback under the ambient token",
        alert_route("org/private", "", "org/registry"), ("org/registry", None))
    chk("repo, None token -> registry fallback under the ambient token",
        alert_route("org/private", None, "org/registry"), ("org/registry", None))
    chk("no repo, token set -> registry (a token alone routes nowhere)",
        alert_route("", "tok", "org/registry"), ("org/registry", None))
    chk("neither configured -> registry under the ambient token",
        alert_route("", "", "org/registry"), ("org/registry", None))
    chk("both None -> registry under the ambient token",
        alert_route(None, None, "org/registry"), ("org/registry", None))
    # The private route must never substitute the ambient token for a configured one, and the
    # fallback must never leak the private repo name as the destination.
    chk("private route does NOT downgrade the token to ambient",
        alert_route("org/private", "tok", "org/registry")[1] is None, False)
    chk("fallback route does NOT keep the private repo as the destination",
        alert_route("org/private", "", "org/registry")[0] == "org/private", False)
    print("alert_route self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    print("alert_route is a library module; run with --self-test", file=sys.stderr)
    sys.exit(2)
