# Is #1353 step 3's PR-time `workflow_dispatch` probe safely implementable? (#1373)

> 🤖 **SPARQ agent** — design record, 2026-09-01. Maintainer-review document.
> **This record changes no behaviour.** #1353 step 3 asked for *"one `workflow_dispatch` at the
> PR's ref asserting `jobs.total_count > 0`, required on any PR touching `.github/workflows/**`"*.
> It was deliberately not implemented while #1353's detection half shipped. This is the record of
> **why**, re-measured against the tree rather than re-asserted from the issue, so the next attempt
> starts from evidence instead of rediscovering it.
>
> **Recommendation: DO NOT implement the probe as specified.** §2 shows all four blockers the issue
> named still hold; §3 adds two more that only appear when you count the actual lanes; §5 states
> what a safe design would have to satisfy. §4 states what is covered today and what is not — the
> residual gap is real, and it is **not** the gap the probe would have closed.

## 1. What was asked for, and the state of the tree

The proposal is a required PR check that, for any PR touching `.github/workflows/**`, dispatches
the touched workflow at the PR's ref and asserts the resulting run executed at least one job. The
signal it is after is genuine: GitHub can *accept* a trigger, *create* a run, and execute **no
job** — conclusion `action_required`, `jobs.total_count == 0`, about one second — leaving a lane
dead while its run list still shows fresh runs. That is the failure `scripts/ci-latency-alert.py`
calls `M4-workflow-ingestion-rejected` (`:281-311`), and it cost this estate an 18-hour dispatcher
outage (#1313) and a ~90-minute `dashboard.yml` outage (c67c7cdf6 → #1352). Both reached `master`
through review; both were found by a human, not by a check.

**State of the tree.** No probe exists. `pr-gate.yml` is the required check and contains no
`workflow_dispatch` call, no `actions:` permission, and no path filter. What *did* ship is
after-the-fact detection, in two independent places — see §4.

## 2. The four blockers, re-measured

### 2.1 Dispatching a touched workflow RUNS it, and most of this repo's lanes mutate production

Not a hazard in the abstract: **26 of this repo's 29 workflows carry `workflow_dispatch`**, and the
set a workflow-touching PR would fire includes every lane that moves production state — dispatch of
real workers, ledger CAS writes, issue/PR labelling, and the arming path.

The sharp part is the input arity, which decides how *easy* the misfire is:

| lane | `workflow_dispatch` inputs | what a bare dispatch does |
|---|---|---|
| `dispatch.yml` | **none** (`:21`) | fires the real dispatcher tick |
| `groom-core.yml` | **none** (`:12`) | fires the real groom tick (ledger writes, park/unpark) |
| `curate.yml` | **none** (`:7`) | fires the real frontier curator |
| `worker.yml` | 3 required, no default (`:18-28`) | cannot fire without a fabricated target repo/issue/account |
| `review-fix.yml` | 4 required, no default (`:40-76`) | cannot fire without a fabricated target repo + PR number |

The three input-free lanes are the three most destructive, and they are the ones a probe fires with
zero friction. **This alone disqualifies the literal proposal**: a check that runs the dispatcher on
every workflow-touching PR is a larger hazard than the bug it detects.

### 2.2 Structurally blind to a NEW workflow

The dispatch API resolves a workflow only if it already exists **with a `workflow_dispatch`
trigger on the default branch**; the `ref` selects which *code* runs, not which *file exists*. A
workflow file **added** by the PR therefore cannot be probed at all — and a newly added file is
precisely the case with no prior evidence of ingestibility. The probe is weakest exactly where the
need is strongest.

⚠️ **Platform behaviour, and the one claim in this record not verifiable from inside the offline
worker container** — same caveat `research/1122` §2 carries for the cache model. Confirm it against
a live dispatch before relying on it. It is not load-bearing for the recommendation: §2.1, §2.4 and
§3.1 each disqualify the literal proposal on their own, from facts read out of this tree.

This is not a corner case here. `park-stock-alert.yml:10-12` and `ledger-identity-watch.yml:25`
both record the standing recommendation that a **new** workflow file is the preferred shape for
change *because* it has zero blast radius on existing lanes. The repo's own convention pushes work
into the one class the probe cannot see.

### 2.3 Permissions, and a required check some PRs could never satisfy

`pr-gate.yml` grants `contents: read` and nothing else (`:60-61`), and its `gate` job (`:68-69`) is
the **required** status check the arm latch and `dispatch-claim.py`'s `CI_GATE_CHECK` both read by
name. A dispatch call needs `actions: write`.

Two independent problems, and the second is the one that cannot be engineered away:

- Widening the required gate's token to `actions: write` widens the blast radius of *every* PR that
  runs through it, on a public repo, for a diagnostic. That is a trust-surface change, not a CI
  convenience.
- A `pull_request` event from a **fork** gets a read-only `GITHUB_TOKEN` regardless of the
  `permissions:` block (⚠️ platform behaviour, unverifiable offline — see the caveat in §2.2). The
  probe cannot run there at all, so making it required creates a check a class of PRs can never
  satisfy: an unmergeable-by-construction lane, not a gate. Note `pr-gate.yml` carries **no fork
  guard** — nothing in it conditions on `head.repo.full_name == github.repository`, as
  `research/1122` §2 also observed — so fork pulls do reach this job.

### 2.4 "Required on any PR touching `.github/workflows/**`" is a repository setting

Path-conditional requirement is a ruleset property, not a workflow property. `pr-gate.yml:9-10`
states the constraint directly: the ruleset is applied by the orchestrator after push, with
`required_status_checks` context `gate` and no require-pull-request rule, and — *"Do NOT create the
ruleset here."* So the "required on any PR touching …" half of the specification is not
implementable from this repo at all, by an existing and deliberate rule.

The workaround (one always-required job that self-skips on non-workflow PRs) is available, but it
inherits 2.3 whole: the job that must report is the one that needs the widened token.

## 3. Two further blockers, visible only after counting

### 3.1 The probe's own failure signal is ambiguous — and biased toward FALSE ALARM

`jobs.total_count > 0` presupposes a run to count jobs on. Every way the probe can fail to get one
is a different fact:

| observation | actual meaning |
|---|---|
| 422 from the dispatch call | required inputs missing (2.1's `worker.yml`/`review-fix.yml` shape) |
| 404 from the dispatch call | workflow absent from the default branch (2.2) |
| 403 | fork token, or `actions:` not granted (2.3) |
| run created, `jobs == 0` | **the condition being tested** |
| no run resolvable within the poll window | queueing, concurrency-group supersession, or rejection |

Only the fourth row is the finding. The first three are properties of the *probe*, and the fifth is
genuinely indeterminate — this repo runs `cancel-in-progress` and singleton concurrency groups on
most lanes (e.g. `pr-gate.yml:63-65`), so a dispatched run being superseded is normal. A required
check that reds on rows 1, 2, 3 and 5 blocks merges for reasons that are not the defect, and
"resolve the indeterminate row to green" is how a probe silently stops testing anything.

`find_ingestion_rejections` (`ci-latency-alert.py:734-787`) has the same asymmetry and resolves it
in the opposite direction *because it can afford to*: an unreadable job count counts as rejected and
says so, since "a false alarm costs one maintainer glance … a miss costs the 18 hours #1313 cost".
That trade is available to a cron alarm and **not** to a required merge gate.

### 3.2 The population arithmetic does not favour the probe

Of 29 workflows: 26 carry `workflow_dispatch` (probe-eligible in principle), and **3 do not** —
`pr-gate.yml`, `set-up-account.yml`, `triage-issue.yml`. The probe cannot cover a PR that touches
only those. One of them *is the required gate itself*, and another is issue intake.

Adding a `workflow_dispatch:` trigger to a lane purely so a probe can fire it is not a neutral fix
either: it is a new manually-invocable entry point on a lane that deliberately has none.

## 4. What is covered today, and what is not

Two independent detectors ship, and they were built for the same failure from opposite directions:

- **`ci-latency-alert.py` M4** (`:281-311`, `:734-787`) — population is `event=schedule` runs, at
  zero extra request cost, keyed on the observable outcome rather than on a mechanism. Its
  documented gap is stated in-file: a lane rejected while carrying only `workflow_dispatch` is
  censused `not-scheduled`, outside the population, never counted healthy.
- **`ingestion-alarm.yml`** (#1706) — a dependency-free lane that reads the newest completed run's
  `jobs.total_count` for `dispatch.yml groom-core.yml worker.yml review-fix.yml` (`:48`). It exists
  because M4's host was itself ingestion-rejected on 2026-08-01, and *"an alarm whose availability
  correlates with the fault is worse than none"* (`:5-9`).

For a lane either of them watches, detection is bounded by one tick of the watching lane —
`groom-core.yml` every 15 min (`:14`), `ingestion-alarm.yml` every 30 (`:25`) — against the 18 h and
~90 min the two real outages actually ran.

**The residual gap, stated so it is not mistaken for coverage.** Nine lanes carry neither a
`schedule:` (so M4 never samples them) nor membership in `ingestion-alarm.yml`'s critical set:
`account-whoami`, `fingerprint-accounts`, `ledger-identity-watch`, `migrate-secrets-to-env`,
`mint-provenance`, `pr-gate`, `set-up-account`, `triage-issue`, `verify-app`. The load-bearing ones
are `pr-gate.yml` and `triage-issue.yml`.

⚠️ **The probe would not have closed this gap.** `pr-gate.yml` and `triage-issue.yml` are two of the
three lanes from §3.2 that carry no `workflow_dispatch` at all. Closing the residual gap is an
extension of the *alarm* population, not a PR-time probe — filed separately, not decided here.

## 5. What a safe design would have to satisfy

Acceptance conditions for a next attempt. A design that cannot meet all five is the proposal this
record already declined:

1. **No production side effect, proved structurally.** Either an explicit allow-list of lanes with
   no production writes, or a dispatch input that makes the run provably no-op. "The lane looks
   harmless" is not the standard — the allow-list must be asserted at the YAML seam by exact
   membership, or it silently grows into `dispatch.yml`.
2. **A stated, non-empty coverage claim.** Say which PRs it can catch, and say it in the design, not
   after. #1373's own framing already concedes that the most obvious safe restriction — probe only
   what already exists on `master` — *"would have caught neither #1313 nor c67c7cdf6 in the general
   case"*, and §2.2 adds that an **added** workflow can never be probed at all. A design that does
   not state this out loud will be read as covering the two outages that motivated it.
3. **No widening of the required gate's token.** If the probe needs `actions: write`, it belongs in
   a separate, non-required lane with its own least-privilege block — never in `gate`.
4. **Fork-safe, or not required.** A required check a fork PR cannot satisfy is an unmergeable
   lane. Pick one.
5. **Every non-finding outcome from §3.1 classified and censused, never resolved to green.** With a
   zero row, so "would this alarm fire if this branch took 100 % of the population?" has an answer.

## 6. What this record must NOT be read as licensing

- Not a rejection of PR-time verification generally — only of *dispatching the touched workflow*.
  A static PR-time check of a workflow file (parse, `actionlint`, SHA-pin assertions) already runs
  in `gate` and is not affected.
- Not a claim the mechanism is understood. It is not: `ingestion-alarm.yml:88` records the class as
  unexplained across 9+ instances (#1566), with a 10-candidate elimination table on #1706. Both
  detectors deliberately key on the *outcome* so they fire for any cause.
- Not permission to add `actions: write` to `pr-gate.yml` for a narrower probe. §2.3 is the
  blocker regardless of how small the probe is.

## 7. Recommendation

Retire step 3 of #1353 as **not implementable as specified**, keep the compensating detectors, and
treat §5 as the acceptance bar for any future attempt. Extending the ingestion alarm's population to
the §4 residual lanes is the cheaper way to buy most of what the probe was after, and it needs no
new permission and no repository setting.
