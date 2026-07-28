# Should the stuck-escalation adjudicator ever get an explicit `override-arm` authority? (#967)

> 🤖 **SPARQ agent** — design record, 2026-07-28. Maintainer-review document.
> **This record changes no behaviour.** It answers a design question raised as a follow-up while
> implementing #446 and records the answer, its evidence, and its cost, so the two-disposition
> shape is a *decided* thing rather than an undocumented omission the next author "fixes".
>
> **Recommendation: NO — the adjudicator gets no arming authority of any kind.** §5 is the
> maintainer's confirm-or-overrule; §6 is what an overrule obliges before any code is written.

## 1. The question

Issue #446 specified **three** adjudication dispositions for the stuck-escalation sweep. Two of
them decide re-entry; the third, `override-arm`, decides *correctness* — "finding
spurious/vacuous/arm-race-artifact → arm". The sweep as designed implements only the first two —
`return-to-loop` and `genuinely-human` — and cannot arm, cannot label `review:pass`, and cannot
merge. #967 asks whether that omission should stand.

**State of the tree, stated plainly:** at the time of writing, `scripts/adjudicate-stuck.py` is
**not on `master`** — the sweep lands with #446 and is still in flight. So this record decides a
shape, not a diff. The decision binds whenever that module lands, and it binds any later sweep
that would grow the same authority under a different name.

## 2. What an `override-arm` authority actually is

Not "a third enum member". It is a **second arm authority in the trust plane**, and its evidence
base is strictly weaker than the one it would bypass:

| | the existing arm authority | the proposed `override-arm` |
|---|---|---|
| what it reads | the **diff under gate**, on the opposite provider, at orchestrator tier | a **recorded verdict + a park rationale** — prose *about* a diff |
| who wrote its input | a reviewer bound to a reviewed SHA | the reviewer whose finding it is overruling, plus a sweep's own park marker |
| what it decides | correctness of the change | that someone else's correctness finding was wrong |

A judge that reads the rationale rather than the artefact cannot distinguish *"this finding is
spurious"* from *"this finding is inconveniently worded"*. Every case where the override would be
**right** is a case where a fresh read of the diff would also be right — and a case where it would
be **wrong** is one only a fresh read of the diff could catch. So the authority adds no evidence;
it adds only the power to skip the party that has some.

This is also the exact shape #446's own guardrail forbids — *never weaken a test or a gate in
order to arm*. An authority whose whole function is to nullify a recorded blocking verdict is that
rule's central case, not an exception to it. Standing it up inside the sweep would additionally
make it reachable from `review:needs-user`, the **human-owned** terminal
(`park_policy.HUMAN_PR_PARK_LABEL`, `scripts/park_policy.py:93-98` — "the human-owned terminal
(genuine human questions only)" and its PR-side twin; label-ownership invariant 1 in the same
file's header) — i.e. the machine would gain an arm path out of the label that exists precisely to
mean "a human decides this one".

## 3. The `override-arm` OUTCOME is already reachable — through the gate, not around it

This is the load-bearing half of the recommendation. Refusing the disposition does **not** strand a
PR whose blocking finding really was spurious. `return-to-loop` re-admits it to `review:needs`,
which buys a **real cross-provider, orchestrator-tier review round** on the live diff
(`.github/workflows/review-fix.yml` — mode `review` is the "opposite provider, read-only" side,
line 49; the claim step's fail-closed cross-provider assertions, ~line 721). If that round
approves with no blockers, the existing gate arms it:

```python
# scripts/worker-pr.py:1399-1407  (decide_review)
if verdict == "approve" and not has_blockers:
    # Decision 7 REVISED (maintainer 2026-07-18) ...
    return "arm"
```

Three properties of that path matter here, and each is checkable in the tree:

1. **Budget does not veto an approve.** `decide_review`'s round-budget clause is on the
   `request_changes` path only (`worker-pr.py:1409`) — the `approve`/no-blockers return above it
   is unconditional on `round_n`/`budget_action`. A re-admitted PR that earns an approve arms even
   though earlier rounds were spent. The self-test pins it:
   `check("approve arms", decide_review("approve", False, False, 1, 3, False), "arm")`
   (`worker-pr.py:7191`).
2. **Trust surfaces keep their audit trail, not a pre-merge park.** The arm re-derives the touched
   surfaces from the live diff and applies the SHA-bound post-merge trail — `trust-surface` label
   plus one idempotent audit comment (`_apply_trust_surface_audit`, `worker-pr.py:5197`), over the
   fail-closed floor `DEFAULT_TRUST_SURFACE_PATHS` that a target's `security_paths` may only
   extend, never subtract (`resolve_trust_surface_paths`, `worker-pr.py:1167`).
3. **The human stops stay human.** Injection/tamper evidence short-circuits to `needs-user` above
   every other branch (`worker-pr.py:1391-1392`), and the self-attested orchestrator class can
   never reach `arm` (`:1393-1398`).

So the disposition's *effect* survives; only its *shortcut* is refused. The sweep decides the one
question the review lane genuinely cannot ask for itself — **may this PR re-enter the loop at
all** — and hands the correctness question back to the party equipped to answer it.

## 4. The honest cost of this recommendation

A design record that only lists the wins is not evidence. Refusing `override-arm` costs:

- **A whole review round per spurious finding.** The cheap outcome ("the reviewer was wrong, arm
  it") is not available; the PR pays a real cross-provider round to reach the same merge. That is
  the price of the arm decision resting on a diff read. It is the right price, but it is not zero.
- **A hard ceiling of two.** Re-admission is charged against `AUTO_READMISSION_MAX = 2`
  (`park_policy.py:179`), shared with every other automatic re-admission so the two can never
  drift, and `PARK_MACHINE_TERMINAL_GENERATIONS` is deliberately equal to it (`:188`). A PR that
  burns both slots on rounds that keep producing spurious findings stays human — permanently. An
  `override-arm` would have had no such cap, which is an argument *against* it, not for it, but
  the asymmetry is real and the maintainer should see it.
- **It does not fix a reviewer that is systematically wrong.** If spurious findings are frequent
  enough that the round cost bites, the defect is in the review lane and an override would only
  hide it. That is a reason to measure the rate, not to add the bypass.

If the measured population ever shows re-admitted PRs approving on the very next round at a high
rate, that is evidence the first verdict was wrong — and the correct response is still to fix the
reviewer, or to raise the cap deliberately, not to let a rationale-reader arm.

## 5. Recommendation — maintainer confirm or overrule

**Confirm:** the disposition set stays closed at two. `return-to-loop` and `genuinely-human` are
the whole of it; the sweep never arms, never writes `review:pass`, never merges, and never touches
a test, a gate, or a verdict. #446's module keeps the closed-set assertion in its own `--self-test`
so the set cannot grow silently, and this record is the *why* that assertion points at.

**Overrule** and §6 applies: an override is a new trust-plane authority and gets designed as one.

## 6. If the maintainer wants a true override, this is what it owes first

A judge that can arm over a **live `request_changes`** is not an extension of an existing sweep,
and it must not arrive as one. It needs its own design record clearing the `needs:design` gate
(`scripts/ready-issues.py:29` — a `needs:*` design-hold that keeps the issue out of `ready` until a
human clears it), answering, at minimum:

1. **Who may overrule a recorded verdict** — which tier, which provider relative to *both* the
   implementer and the overruled reviewer, and why that party is not simply a third implementer.
2. **What evidence is required.** If the answer is not "a fresh read of the diff under gate", say
   what weaker evidence suffices and why the failure mode in §2 does not apply.
3. **How the override is receipted** — durably, bot-authored, bound to the reviewed SHA, and
   readable by the next sweep, in the style the re-admission receipt already uses
   (`AUTO_READMIT_MARKER`, `worker-pr.py:235`). An override with no receipt is an unauditable merge.
4. **Whether the arm-side `trust_surface_paths_touched` classifier still binds**
   (`worker-pr.py:1142`) — and it must, on the union floor, with the post-merge audit trail intact.
5. **What bound replaces `AUTO_READMISSION_MAX`.** An unbounded override is a treadmill with an
   arm at the end of it.
6. **Which human stops survive** — injection, tamper, and the self-attested class must remain
   terminal, or the override is a bypass of those too.

An override design that cannot answer (2) without restating (1) has found the same wall this record
did, and the answer is the one in §3: send it back through the gate.

## 7. What this record does not decide

It does not decide #446's implementation, its park-reason taxonomy, or its write-transaction
ordering — those are that PR's to defend. It does not propose changing `AUTO_READMISSION_MAX`, and
it does not claim the review lane's verdicts are reliable enough to make an override unnecessary in
principle — only that the sweep is the wrong place to correct them and a rationale is the wrong
evidence to correct them with.
