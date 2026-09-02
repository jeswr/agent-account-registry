# #870: three PRs stranded on the human terminal by a NEGATED injection mention

> 🤖 **SPARQ agent** — design record, 2026-09-01. Maintainer-review document.
> **This record changes no behaviour.** No script, workflow, or policy file is touched.
>
> **One of #870's two premises no longer holds on this tree, and it is the load-bearing one.**
> #870 asks for three hand decisions *because* "the read side stays **deny-on-any-mention**".
> It does not. **#814 landed** as commit `a9eb05796` (PR #2145) — the deny narrowed to the shape
> the loop's own escalation writes, and then a provenance rule was put in front of it. All three
> stranding sentences #870 tabulates are **measured inert on this checkout** (§2), under the raw
> table *and* through the shared seam, and a legacy park carrying one re-classifies on its own
> recorded cause.
>
> **Recommendation, in one line: spend no human decision on the injection question — there is
> nothing left to decide there — and decide only what the two machine paths still refuse, on the
> reason they refuse for, which is never injection (§3, §4).** The ask #870 states as *"3
> decisions, once"* is an upper bound that #814 has already cut into; how far is a question only
> the live PRs can answer (§5), and the procedure in §4 answers it per PR without guessing.
>
> ⚠️ **Nothing about the live PRs is re-measured here.** This container has no network, no `gh`
> and no token. #870's three sentences, its `review:needs-user` census and its 44-PR parked
> census are reproduced as **claims of that issue**, never as findings of this record (§5).

## 1. What #870 asked, and what moved under it

#870 reports three `sparq-org/sparq` PRs (#3554, #3661, #3901) held on the **human-owned**
`review:needs-user` terminal because `park_policy.LEGACY_PARK_DENY_PROSE` denied automatic
re-classification on **any** `prompt injection` mention anywhere in the orchestration bot's own
comment history — and the only mention on each is a reviewer reporting the **absence** of
injection, republished under the bot's identity by `worker-pr.post_findings`. It concludes that
the read side must stay deny-on-any-mention (citing #826's abandoned polarity recovery), that no
automation change is available, and therefore asks @jeswr for one decision per PR.

That conclusion was correct about **polarity recovery** and wrong about **the alternative**. The
fix that landed is not a polarity test at all — it is two changes that never ask what a sentence
*means*:

1. **The deny narrowed from the phrase to the loop's own escalation SHAPE**
   (`scripts/park_policy.py:2373-2379`). Three patterns remain: the `flagged … possible
   prompt-injection` sentence every injection write site emits, the machine-composed park lead
   naming injection as the stop cause, and the `needs a human decision … security` human-arm
   lead. A bare occurrence of `prompt injection` matches none of them.
2. **Provenance was put in front of the table** (`legacy_deny_signal`,
   `scripts/park_policy.py:2437`). A bot comment that **republishes model text** — recognised
   positionally by its machine-composed lead line, `republishes_model_text`,
   `scripts/park_policy.py:2424` — contributes **no prose signal at all**; the only injection
   evidence it can carry is `REVIEW_INJECTION_MARKER` (`:2387`), which `post_findings` writes
   after the sink's reserved-marker neutralisation and no model field can forge.

Those are independent, and the second is the stronger one: it holds even for a sentence that
matches a deny pattern **byte for byte**, because a reviewer can write one at will.

## 2. Measured on this checkout — the three sentences are inert

Run in the worker container against `HEAD` (`a64c279c0`), no network required:

```python
import sys; sys.path.insert(0, 'scripts'); import park_policy as pp
lead = "> 🤖 SPARQ agent — cross-provider review round 2: **approve**.\n\n"
for s in SENTENCES:                       # the four sentences #870 quotes
    print([c for p, c in pp.LEGACY_PARK_DENY_PROSE if p.search(s)],   # raw table
          pp.legacy_deny_signal(s),                                   # bare, through the seam
          pp.legacy_deny_signal(lead + s))                            # as post_findings lands it
```

| #870's sentence | raw deny table | `legacy_deny_signal` (bare) | …(republished) |
| --- | --- | --- | --- |
| #3901 *"No instruction-like prompt injection was detected in the diff."* | no match | `None` | `None` |
| #3661 *"No vacuous load-bearing test, … or prompt-injection content was found."* | no match | `None` | `None` |
| #3554 *"No correctness, soundness, …, or prompt-injection issue remains…"* | no match | `None` | `None` |
| #3554 *"No instruction-like prompt injection appears in the diff."* | no match | `None` | `None` |

And the end-to-end decision, not merely the absence of a match: a legacy park whose history is one
of those republished verdicts plus an ordinary capacity park comment returns
`reclassify_legacy_park(...) == ("nochange", "capacity")` for all four — it re-classifies on its
**own** recorded cause and lands back in the machine class.

This is not incidental to the fix; it is **pinned in three self-tests**, each quoting the live
sentences verbatim, so widening the rule back toward "any occurrence of the phrase" goes red in
all three: `scripts/park_policy.py:5643-5662`, `scripts/reconcile-park-misescalation.py:401-406`,
`scripts/reconcile-conflict-park.py:833-841`. The first two suites are green on this checkout
(`python3 scripts/park_policy.py --self-test`,
`python3 scripts/reconcile-park-misescalation.py --self-test`); the third could not be **run**
here — `reconcile-conflict-park.py --self-test` imports `yaml`, which this container does not have
— so its pin is cited as read, not as executed. That is the known `ENV-BLOCKED` condition
`worker-live.sh`'s #824 dependency preflight already names (`scripts/worker-live.sh:2275`), not a
defect: the gate runs where PyYAML exists.

**What this does and does not establish.** It establishes that the mechanism #870 names as the
cause of the stranding no longer refuses these sentences, in every consumer of the table. It does
**not** establish that any particular live PR is now released — that depends on gates the deny was
merely the first of (§3), and on facts about the PRs this container cannot read (§5).

## 3. Which machine path owns each PR — and what each still refuses

Two paths act on a live `review:needs-user`, and the discriminator between them is the
**park-generation receipt**, not the deny:

**Path A — `dispatch-claim._migrate_legacy_park` (`scripts/dispatch-claim.py:5677`), automatic.**
Runs on the ordinary dispatch tick, at most `LEGACY_PARK_MIGRATION_MAX = 5` PRs per tick
(`:5652`, call site `:5972`). Its population is the **legacy prose-only** park: a PR on the human
terminal on which **no** bot comment carries a `sparq-park-reason` marker (step 1 of
`reclassify_legacy_park`, `scripts/park_policy.py:2468`, short-circuits on one — an
already-classified park is not legacy and is never re-migrated). After the deny it still requires:
a **capacity-class** cause recognised from the bot's prose (`LEGACY_PARK_PROSE`, `:2457` —
`budget` / `dispatch-missed` / `nochange` / `gatefail`; `history-rewritten`, `marker-corrupt` and
`routing-unresolvable` are **question**-class, get their marker recorded and are deliberately
**left on the terminal**); `provable` (an exit that could actually open); the source issue's
`needs:user` half proven **machine-applied**; and no residual `needs:*` hold that would survive
the conversion.

**Path B — `scripts/reconcile-park-misescalation.py` (`verdict`, `:82`), hand-run, `--apply`
required, dry-run by default.** Its population is the PR whose **latest park-generation receipt's
window is byte-identical to one of its own `sparq-auto-readmit` stamps** — the positive proof the
terminal was reached on a window the machine minted. It refuses a PR with no generation receipt
(`:129-134`, explicitly handing it to Path A), a proven human-applied hold, a residual hold, and —
before all of those — the deny, read through `legacy_deny_signal` and never over the table
directly (`:120-128`).

**A PR in NEITHER population is the genuine residue**: it carries a park-reason marker (so Path A
declines it as already-classified) but reached the terminal on a window no auto-readmit stamp
matches (so Path B cannot prove mis-escalation). That is the residue by *population*; being in
Path A's population is not itself a release, because every gate above it fails toward leaving the
park alone (§4 step 2), so the residue by *outcome* is larger. `scripts/worker-pr.py:9406-9424` names exactly
this boundary from the write side and says the receipt-less terminals are the **pre-#677
historical** ones — *"which is the population #870 owns"*.

The third consumer, `scripts/reconcile-conflict-park.py:850`, reads the same seam for conflict
releases; it is listed for completeness — #870's PRs are not described as conflict parks.

## 4. The residual human ask, and how to size it without guessing

Per PR, in order — each step is a lookup on the PR itself, not a judgement:

1. **Do not adjudicate the injection question.** §2 settles it: on this tree those sentences carry
   no signal, and the absence of a Tier-A affirmative marker that #870 already reports is the
   same fact from the other side. Re-admitting "by hand for the negation" now decides something
   the machine no longer gets wrong.
2. **Does any bot comment carry a `sparq-park-reason` marker?** Yes → step 3. No → Path A gets the
   **first look**, which is not the same thing as a release. `_migrate_legacy_park`
   (`scripts/dispatch-claim.py:5677`) has four exits after the deny and only one of them removes
   the PR from the ask, so read its **outcome**, not its eligibility. All four are decided from
   inputs already listed in §3 — the cause recognised in the bot's prose, `provable`, the source
   issue's `needs:user` ownership, and any residual `needs:*`:
   - **Migrated** — a capacity-class cause (`budget` / `dispatch-missed` / `nochange` / `gatefail`
     / `cold-groom`), `provable` holds, the issue-side `needs:user` proven machine-applied, and no
     residual hold. Machine-owned: **no decision and no hand-run**, on the next dispatch tick
     (≤ `LEGACY_PARK_MIGRATION_MAX = 5` PRs per tick, `:5652`).
   - **Classified but not moved** — a question-class cause (`history-rewritten`, `marker-corrupt`,
     `routing-unresolvable`). The tick records the marker and deliberately leaves the terminal.
     That is a **remaining human decision**, on that recorded cause → step 4.
   - **Deferred on the hold axis** — the issue half is proven human-applied or its timeline is
     unreadable, or a residual `needs:*` would survive the conversion (`:5760-5771`). Also a
     **remaining human decision**, on that hold → step 4.
   - **Deferred on `provable`** — the cause is machine-owned but no exit could open right now, so
     the tick refuses to trade a visible stall for a silent one. This is **deferred/unknown, not
     decision-free**: re-read on a later tick, where it becomes one of the outcomes above.
   A cause no table recognises returns `(None, None, …)` and the park stands — step 4.
3. **Does its latest park-generation receipt's window match one of its own `sparq-auto-readmit`
   stamps?** Yes → Path B owns it: run `reconcile-park-misescalation.py` **dry-run first**, read
   the per-PR audit basis it prints, then `--apply`. It disposes of a PR whose two automatic
   re-admissions are already spent (`AUTO_READMISSION_MAX = 2`, `park_policy.py:212`) by
   `retire` rather than by re-parking it into a class with no exit.
4. **Neither path disposes of it** — step 2 reached a non-migrating outcome, or step 3 found no
   matching stamp → this is a real human decision, and it is **not** about injection. It is one of:
   a question-class cause (`history-rewritten`, `marker-corrupt`, `routing-unresolvable`) where
   the terminal is already the correct state; a human-applied hold on either half of the park
   pair; a residual `needs:*` (e.g. `needs:external-audit`) that no automation may form an opinion
   about; or a cause no table recognises. Each of those is answered on its own terms, and #870's
   table of negated sentences is not evidence about any of them.

So the honest shape of the ask is: **at most three decisions, none of them an injection decision,
and each one first checked against steps 2–3.** What remains is the count of PRs those steps do
not *dispose* of: a PR Path A actually migrates, or Path B retires, costs nothing; a PR Path A
classifies as a question or defers on the hold axis is still a decision — on that reason, never on
injection; a PR deferred only on `provable` is neither yet, and is re-read rather than decided.
Zero is reachable, but only if all three land in a disposing outcome — it is a possible floor of
the residue, not the expected one.

## 5. What is not measured here, and what would settle it

- **The three PRs' actual comment bodies, labels and receipts.** Everything in §3–§4 keys on them;
  this container cannot read one. #870's quoted sentences are taken as given, and §2 tests exactly
  those strings — if a live body differs from the quote, §2's result is about the quote.
- **#870's censuses** (16 open `review:needs-user`, 8 genuine escalations, 5 with no mention, 3
  false positives; 44 open `review:parked` with 315 bot comments and zero mentions). Reproduced as
  claims of that issue. They are the bound on *how much* this costs; none of §2–§4 depends on
  them.
- **Whether #869's write-site change closes recurrence** as #870 asserts. `worker-pr.py:9406-9424`
  documents the terminal escalation deliberately emitting no park-reason receipt and argues the
  exclusion is safe; that argument is about new terminals, not about the historical three.
- **Settling it** needs one authenticated read per PR — labels, the bot's comment bodies, its
  park-generation receipts and auto-readmit stamps — which is precisely what Path B's dry-run
  already prints, per PR, with its refusal reason. Running the dry-run *is* the measurement.

## 6. Do not re-widen the deny — and why this record is not the counter-argument

The direction guard from #814 stands unchanged and this record does not soften it: **a wrong
release on this classifier is far worse than a wrong deny**, and #826's abandoned attempt is the
measurement that a *polarity* rule is the wrong instrument. Nothing here proposes reading what a
sentence means. The two properties that make §2's result safe are structural — a narrower pattern
matched against the loop's **own** composed sentence, and a positional provenance test that
refuses to read model-derived prose as a signal at all — and the unforgeable
`REVIEW_INJECTION_MARKER` is what carries the real flag across the one write site that republishes.
A future author reading #870 in isolation could reasonably conclude the table should go back to
matching the phrase; three self-tests (§2) go red if it does, and this record is the prose half of
that same refusal.

## 7. What this record does not do

- It ships **no behaviour change**: no script, workflow, `policy/` or `orchestration/` file is
  touched, and no self-test is added, relaxed or removed.
- It does **not** re-admit, re-park, retire or otherwise touch any PR. Every action in §4 is the
  maintainer's, and Path B still requires `--apply`.
- It does **not** claim #870 is empty. It claims the *injection* question in #870 is answered by
  the tree, and re-scopes the remainder to a per-PR lookup whose answer is unknown offline (§5).
- It takes **no position** on #826 beyond agreeing with its abandonment, and none on whether the
  question-class terminals in step 4 should ever gain a machine exit — that is #767's territory
  (`research/767-human-applied-machine-park-exit.md` §5), which documents the same residue as
  deliberate.
