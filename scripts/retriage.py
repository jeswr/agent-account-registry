#!/usr/bin/env python3
"""Plan one safe, idempotent retriage mutation from an issue JSON document."""
import argparse
import json
import sys

import triage as static_triage


HOLD_MARKER = "<!-- orchestration:hold -->"
TRUSTED_PERMISSIONS = {"admin", "maintain", "write"}


def plan(issue, maintainer, app_bot, permission, classify=static_triage.triage):
    labels = {item["name"] if isinstance(item, dict) else item
              for item in issue.get("labels", [])}
    author = (issue.get("author") or {}).get("login", "")
    trusted = (author in {maintainer, app_bot} or permission in TRUSTED_PERMISSIONS)
    if not trusted:
        return {"action": "skip", "reason": "untrusted-author"}
    gates = sorted(label for label in labels
                   if label.startswith("needs:") or label == "trust:untrusted")
    if gates:
        return {"action": "skip", "reason": "gated:" + ",".join(gates)}
    if HOLD_MARKER in (issue.get("body") or ""):
        return {"action": "skip", "reason": "explicit-hold"}
    # status:deferred is owned exclusively by the dispatcher's bounded retry path. Retriage must
    # not consume it or it would reset that path's retry/escalation state.
    if "status:untriaged" not in labels or "status:deferred" in labels:
        return {"action": "skip", "reason": "not-retriageable"}
    try:
        result = classify(labels, "task", trusted=True)
    except Exception:
        return {"action": "skip", "reason": "classifier-failure"}
    if not result["ready"]:
        return {"action": "skip", "reason": "classifier-incomplete"}
    remove = set(result["remove"])
    remove.update(labels.intersection({"status:untriaged"}))
    return {"action": "promote", "add": sorted(result["add"]), "remove": sorted(remove)}


def _self_test():
    base = {"author": {"login": "owner"}, "body": "",
            "labels": [{"name": "priority:P2"}, {"name": "area:workflows"}]}

    def issue(status, *extra, body=""):
        value = dict(base)
        value["body"] = body
        value["labels"] = base["labels"] + [{"name": status}] + [
            {"name": label} for label in extra]
        return value

    checks = []
    got = plan(issue("status:untriaged"), "owner", "app[bot]", "none")
    checks.append(("status:untriaged promotion",
                   got["action"] == "promote" and "status:ready" in got["add"]
                   and "status:untriaged" in got["remove"]))
    checks.append(("dispatcher-owned deferred rejected",
                   plan(issue("status:deferred"), "owner", "app[bot]", "none")
                   == {"action": "skip", "reason": "not-retriageable"}))
    checks.append(("mixed untriaged and deferred rejected",
                   plan(issue("status:untriaged", "status:deferred"),
                        "owner", "app[bot]", "none")
                   == {"action": "skip", "reason": "not-retriageable"}))
    checks.append(("needs gate rejected",
                   plan(issue("status:untriaged", "needs:design"), "owner", "app[bot]", "none")
                   == {"action": "skip", "reason": "gated:needs:design"}))
    checks.append(("hold marker rejected",
                   plan(issue("status:untriaged", body=HOLD_MARKER), "owner", "app[bot]", "none")
                   == {"action": "skip", "reason": "explicit-hold"}))

    def broken(*_args, **_kwargs):
        raise RuntimeError("fixture")

    checks.append(("classifier failure is idempotent",
                   plan(issue("status:untriaged"), "owner", "app[bot]", "none", broken)
                   == {"action": "skip", "reason": "classifier-failure"}))
    foreign = issue("status:untriaged")
    foreign["author"] = {"login": "outsider"}
    checks.append(("trust rejection",
                   plan(foreign, "owner", "app[bot]", "read")
                   == {"action": "skip", "reason": "untrusted-author"}))
    checks.append(("write collaborator accepted",
                   plan(foreign, "owner", "app[bot]", "write")["action"] == "promote"))
    ok = all(result for _, result in checks)
    for name, result in checks:
        print(f"  {'ok  ' if result else 'FAIL'} {name}")
    print("retriage self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--maintainer", default="")
    parser.add_argument("--app-bot", default="")
    parser.add_argument("--permission", default="none")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
    issue = json.load(sys.stdin)
    print(json.dumps(plan(issue, args.maintainer, args.app_bot, args.permission), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
