# Can groom's per-issue comments fan-out be narrowed further? (#1739 — the #1120 follow-through)

> 🤖 **SPARQ agent** — **INTERIM** decision record, 2026-09-01. Maintainer-review document.
> **This record changes no behaviour.** #1739 asks for a DECISION whose stated input is live
> measurement, and the measurement is not in the tree (§2). So this record does what
> `research/1122-groom-http-cache-retention.md` did for #1088: it decides a **shape** and a
> **rule**, not a diff, states plainly what it is missing, and leaves the issue OPEN for the part
> it cannot decide.
>
> **This record does NOT discharge #1739.** #1739's actual question — *is the restructure worth
> doing?* — is answerable only from the two censuses in §6 and §7, and neither exists in this
> tree (§2). What is decided here is narrower, and holds without them: **hold both narrowings,
> declined FOR NOW**, on the §5 fail-open (a refusal that stands on its own — the cheap version is
> a wrong mutation at any traffic level) and on the **partial** ceiling in §4 (it bounds the
> `live_by_issue` half by shipped policy and only estimates the `admitted` half from pre-#1303
> notes). Recording "measured and rejected" for something nobody has measured is the one outcome
> #1120 was raised to prevent — and closing the issue that asked for the measurement is the same
> failure one level up. So **#1739 stays OPEN until §6's census line and §7's K/N counter have
> both landed and been read** (§9.1). §6 is the rule that settles it mechanically once the census
> exists; §7 is the cheap, zero-risk counter that must come *before* any restructuring, because
> the census #1120 specifies **cannot distinguish narrowable fan-out from irreducible fan-out**.

## 1. What #1739 asks

#1120 asked two things: MEASURE groom's per-issue `/issues/{n}/comments` fan-out against the
installation budget, and THEN decide whether it can be narrowed further. #1739 is the second
half. The two candidate narrowings it names are the two `attempts_fetch_needed`
(`scripts/groom.py:626`) deliberately declined under #1303: skip the comments GET for an issue
where `key in live_by_issue`, and skip it where `number in admitted[repo]`.

## 2. State of the tree, stated plainly

**At `master` = `a64c279c0`, the #1120 census line is NOT in this repository.** #1739's premise
sentence — "the measurement half landed" — does not hold for the tree an agent is handed. Four
greps, all offline, all re-runnable:

| what | command | result |
|---|---|---|
| the census line | `grep -rn 'fan-out' scripts/groom.py` | no match |
| any request counter | `grep -rn 'SWEEP \|CENSUS ' scripts/groom.py` | only `SWEEP attempt-budget reads:` (`:4043`, the #1303 saving) and `CENSUS stranded worker PRs` (`:4053`, #1598) |
| any budget header read | `grep -rn 'x-ratelimit' scripts/groom.py` | no match |
| the line's history | `git log --all -S'comments fan-out' -- scripts/groom.py` | no commit, on any ref |

The mechanism agrees with the greps: `GitHubAPI.request` (`scripts/groom.py:1360`) consumes the
response inside `with urlopen(...) as response: raw = response.read()` and returns parsed JSON
only. **The response headers — where `x-ratelimit-used` lives — are discarded at that line**, so
groom currently has no way to state an installation-budget denominator at all. Nor can anything
else supply it: `scripts/ratelimit-alert.py`'s own scope note says the per-owner App
**installation** tokens groom mints for target repos are a SEPARATE bucket set that it does not
cover, because reading them would need the App signing key in a watchdog job.

So #1739 is filed against an instrument that does not exist yet on `master`. The likeliest
explanation is the ordinary one — #1739 was filed *from* #1120's implementation PR ("Discovered
by the SPARQ worker while implementing #1120"), and that PR has not merged. This record does not
assert that PR's state; it asserts the tree's, which is checkable offline.

## 3. The two narrowings are SOUND — that was never the question

Both are genuinely unreachability arguments, and both hold on today's code. For an issue whose
key is in `live_by_issue`, or whose number is in `admitted[repo]`:

* the exhaustion park (`scripts/groom.py:3676`) requires `key not in live_by_issue and number
  not in admitted[repo]` — it cannot fire;
* the orphan repair is unreachable too, because the guard immediately below
  (`scripts/groom.py:3701`) `continue`s on exactly `key in live_by_issue or number in links or
  number in admitted[repo]`.

Those are the only two consumers of `used`. So the comments GET for such an issue is provably
spent on a value nothing reads. #1303 did not decline these because they were wrong; it declined
them because of WHEN the sets are known and WHICH WAY the predicate fails (§5).

## 4. The ceiling on what they could save, from shipped policy

The saving is not "issues with a live lease or an admitted PR". It is the INTERSECTION of that
set with the set that currently fetches — and `attempts_fetch_needed` has already removed most
of the population:

* **`live_by_issue`.** A live lease is bounded per repo by `max_concurrent`
  (`policy/repos.toml:98` — sparq 40; `:195` — this repo 3; `jeswr/solid-sdk` is
  `enabled = false`), enforced at claim time as `max_holder_concurrent=effective_cap`
  (`scripts/dispatch-claim.py`, `effective_cap` capped by `absolute_cap=resolved["max_concurrent"]`).
  **≤ 43 issues per tick across both enabled targets, by policy, today.** And most of those do
  not fetch anyway: a dispatched issue wears `status:in-progress`, which `attempts_fetch_needed`
  excludes from the orphan-repair branch outright, so a live-leased issue reaches a fetch only
  via `comment_count >= max_attempts` (3).
* **`admitted[repo]`.** Bounded by the open PRs the review loop admits, which policy does NOT
  cap. This is the bigger and more interesting half: an admitted PR's source issue typically
  wears `status:in-progress-review`, which `attempts_fetch_needed` deliberately keeps
  fetchable, and it goes stale precisely when the review lane is slow — i.e. it fetches EVERY
  tick, for the whole time its PR sits in review, and every one of those fetches is provably
  unread. Order of magnitude from this repo's own shipped notes: ~30 of 34 open non-draft sparq
  PRs were worker-class on 2026-07-27 (`policy/repos.toml`, the enrolment block), and 17
  orchestrator-class pulls were open here for #1115.

Against #1303's measured pre-skip cost — 500 of ~650 sweep requests, both enabled targets,
2026-07-29 — the ceiling is order-tens against order-hundreds. **That is enough to say the two
narrowings cannot be the dominant term, and not enough to say whether they are worth a
restructure**, because the comparison that matters is against the POST-#1303 fetch count, which
is exactly what nothing has printed yet.

**And this ceiling is PARTIAL — say so rather than lean on it.** Only the `live_by_issue` half is
bounded by shipped policy (≤ 43, re-checkable in the tree today). The `admitted` half is bounded
by nothing, and the figures above for it are historical, order-of-magnitude notes dated
2026-07-27 — i.e. **before** #1303 changed which issues fetch at all. So §4 cannot answer whether
the admitted subset is material post-#1303; that number is exactly §7's K. This is why the
declension below rests primarily on §5, which does not depend on any count, and why §4 alone
would not be grounds to close the question.

## 5. What re-opening this costs, and the constraint it must satisfy

`attempts_fetch_needed`'s docstring records the reason #1303 declined: both sets "are not known
this early in the sweep, and an error in this predicate has to point at FETCHING, never at
skipping". Both halves are load-bearing, and the second is the sharp one.

**The fail direction is not a style preference — it is a live fail-OPEN.** The skip branch
records the BOUND, not a zero (`scripts/groom.py:3991`, `attempts[(repo, number)] = count`).
Today that is safe because the branch is only reached when `count < max_attempts`, so the bound
answers both guards exactly as the true count would. A live/admitted narrowing breaks that
invariant on purpose: it would skip issues with `count >= max_attempts`, recording an
OVER-count as `used`. That is fine *only* while the skip predicate consumes exactly the same
sets `_plan_actions` consumes. Feed it a cheaper SUPERSET — say, "has any non-dead lease",
available right after the ledger read at `scripts/groom.py:3842`, before the snapshot loop — and
an issue skipped as live but classified dead by the lease loop inside `_plan_actions` arrives at
the exhaustion guard carrying `used = count >= max_attempts` with the suppression gone. **Groom
parks an issue whose real attempt count is below the cap**, on a value it never read. A cheap
approximation here is not a smaller saving; it is a wrong mutation.

So any re-opening is bound by three things, together:

1. **ONE derivation, passed in — never recomputed.** `live_by_issue` is built inside
   `_plan_actions` from `leases` + `lease_states` + `_terminal_non_pr_claims(issues, pulls, ...)`.
   Hoisting it to before the fetch loop is *feasible* (it needs the snapshot, not the comments),
   but a second derivation that drifts from the first is the exact hazard the sweep's own
   stale-PR loop already names for the #1598 census: "Deriving it twice would let the two
   disagree about who is unowned." The hoisted set must be the ONLY set, threaded into
   `_plan_actions`.
2. **`admitted` is the cheap half.** `_admitted_review_prs` reads provenance records from the
   checkout (`registry_root` / `ledger_root`), not over HTTP, and needs only `pulls[repo]` — it
   is already computed at `scripts/groom.py:4077` from data the snapshot loop has in hand. Moving
   it above the issue loop costs no requests.
3. **A self-test that reds on the superset mistake**, not merely on the happy path: an issue that
   is skipped-as-live and then classified dead must still not be parked. Without that assertion
   the restructure ships the §5 fail-open with a green suite.

## 6. The rule that settles it — pre-committed, so the next ticks decide it, not an argument

Once the #1120 census prints `SWEEP comments fan-out: N of the M request(s) this sweep issued
(P%) …`, read a few ticks and apply this, in order:

* **P is small (say < 25 %), or the installation budget shows no pressure** → the declension in
  §5 becomes a MEASURED won't-fix: cite the ticks in this record and leave
  `attempts_fetch_needed` untouched. This is the outcome §4's ceiling makes most likely and it
  is a legitimate result: the point of measuring first was to be allowed to reach it.
* **P is large (the fan-out is still the dominant term) AND the budget is under pressure** →
  do NOT restructure yet. Go to §7 first. N/M says the fan-out is dominant; it says **nothing**
  about how much of N is narrowable, and §4's ceiling says the narrowable part may be a small
  slice of a dominant N. Restructuring the sweep's ordering to chase an unmeasured slice is the
  trade #1303 refused.
* **The census does not print, or prints only when non-zero** → that is the #938 defect
  (AGENTS.md pre-flight item 8), and it is a bug in the measurement, not evidence about the
  fan-out.

## 7. The measurement that must come before any restructure — and why it is free

The narrowable share is measurable **without changing a single fetch decision**, because both
sets ARE known by the end of the sweep even though they are not known at the fetch. Count, after
planning, how many of the tick's `attempts_fetched` issues turned out to be in
`live_by_issue ∪ admitted[repo]`, and print it as its own census row beside the #1303 line
(unconditionally, zero row included).

That counter is a strictly safe experiment in the sense §5 demands: **a counter cannot skip
anything**, so the predicate's error direction still points at fetching. It converts "P % of the
sweep is comments" into "K of the N fetches were provably unread", which is the number #1739
actually needs and the only one that can justify the ordering change in §5.1. It is also the
honest scoping of the restructure: if K is single-digit, the restructure is dead on arrival
whatever P says.

## 8. What this record does NOT say

* It does not say the narrowings are unsound. §3 says they are sound; §4–§5 say they are
  cheap-looking and structurally expensive.
* It does not authorise consulting `live_by_issue`/`admitted` in `attempts_fetch_needed` on any
  approximation of those sets. §5 is a refusal, not a caution.
* It does not claim to have MEASURED anything about the fan-out — and therefore it does not
  discharge #1739. A won't-fix with no measurement behind it reads, later, exactly like a
  measured rejection, and the whole complaint in #1120 was that the fan-out had never been
  measured; closing #1739 on this record would reproduce that failure one level up, settling the
  issue that asked for the measurement with a document whose own §2 says it has none. The
  measurement question therefore stays attached to an OPEN issue (§9.1), not to prose here.
* It does not decide anything about the OTHER users of the sweep's request budget. #1303's
  numerator is the comments fan-out alone; the ~150 non-comments requests in the 2026-07-29
  measurement are out of scope here.

## 9. Maintainer confirm-or-overrule

1. **Do NOT close #1739 on this record — it is interim.** If the pull request carrying this record
   auto-closes #1739, re-open it, or open a successor issue whose acceptance is exactly §6's
   census line plus §7's K/N counter and link it from here. The measurement has to stay owned by
   an open issue: a promise in a merged file is the carrier #1120 already demonstrated does not
   survive.
2. **Declined FOR NOW on the §5 fail-open and the partial §4 ceiling — not on measurement**, and
   this record says so in its own headline rather than letting a closed issue imply otherwise.
3. **The §6 rule** settles it from ticks rather than from argument, including the won't-fix leg,
   once the #1120 census is on `master` (§2: it is not).
4. **The §7 counter comes before any restructure**, and the §5 constraints bind that restructure
   if it is ever taken.
