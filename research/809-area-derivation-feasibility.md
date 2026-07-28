# Can the curator derive `area:` itself? — measured answer

> 🤖 **SPARQ agent** — design record, 2026-07-28. Maintainer-review document.

`triage-stock-alert.census()` reports an `unattributable` bucket: machine-owed `status:untriaged`
issues for which `curate-frontier.derive_area` returns no area. `area:` is the one label neither
the curator nor `triage.triage()` can manufacture, so the alert asks whether it could be derived.

**Answer: it already is, at 92.5% precision on held-out data, and no additional signal clears that
bar — though the margin over the best rival is not statistically separated.** The residual is not a
missing rule; it is the class of issues that genuinely span several surfaces.

## What was measured

Ground truth is this repository's issues carrying **exactly one** `area:*` label (n=556, open and
closed, at the 2026-07-28T13:07:14Z snapshot). The shipped deriver was evaluated with the area
labels **stripped from its input**, otherwise it answers `"existing"` and measures nothing.

**The corpus is partly self-graded, and the headline figure must be read on the hold-out.**
`curate-frontier` writes its own derived area back when it stages an issue (`desired = (…, area)`
→ `gh issue edit --add-label`), so some ground-truth labels were authored by the rule being
graded. Measured, not assumed: exactly two identities have ever applied an `area:*` label here —
`jeswr` (529 events) and the curator App bot `sparq-orchestrator` (50 events) — and `derive_area`
has exactly one mutating caller, so bot-authored ⇔ curator-authored. **38 of the 186 firing rows
(20.4%) are self-graded.** The contamination behaves exactly as circularity predicts: of the
curator-authored rows written *after* the current rule landed (`6bea6cc2b`), 27 of 28 fire and
**27/27 are "correct"** — the rule agreeing with itself.

| signal | fires | precision | source |
|---|---|---|---|
| **shipped `derive_area`, HELD OUT** (curator-authored rows removed; n=503) | **147** | **92.5%** (136/147) | this record |
| shipped `derive_area`, full corpus (self-graded rows included; n=556) | 186 | 93.0% (173/186) | this record |
| — of which, self-graded subset only (n=50) | 38 | 94.7% (36/38) | this record |
| parent-issue inheritance via the `sparq-followup` provenance link | 239 | **56.1%** | this record |
| declared file→area map, as a marginal fallback on the 370 declines | 38 (10.3% of declines) | **86.8%** (33/38) | this record |
| body+title token scan | — | 40.0–50.0% | #809, recorded in `derive_area` |
| directory path hints | 145 | 37.9% combined, **12.9% on this repository** | #809, removed |

Removing every self-graded row costs 0.5pp, so the **decline conclusion survives** — but the
comparison it rests on was never statistically separated: 136/147 vs 33/38 is Fisher two-sided
**p = 0.33**, and the held-out 95% Wilson interval (87.1–95.8%) clears the file map's 86.8% by
0.3pp. "No rival clears the bar" is accurate; "the shipped rule is measurably better" is not.

### The hold-out is the control this record originally had

The `derive_area` comment block records the #809 measurement against *"the held-out 83 that the
curator did NOT itself stage"*. An earlier draft of this record dropped that control and asserted
non-circularity instead. That sentence was wrong, and the number it defended was inflated.

### Two provenance caveats on the ground truth itself

1. **It is dominated by one recent bulk pass.** 315 of the 523 `jeswr`-authored area labels (60%)
   were applied in scripted bursts on 2026-07-28 — 285 inside a single 45-minute window, ~2.5h
   before this snapshot — and the corpus more than doubled (264 → 556) in it. That backfill is
   legitimately held out (`derive_area` was byte-identical throughout and its firing rows there
   disagree 9 times, which self-graded rows cannot), but it is a bulk labelling pass of unstated
   provenance, not accumulated independent judgment. The era split is visible: rows written before
   the rule landed agree at 97.4% (76/78); the backfill agrees at 87.0% (60/69).
2. **3 issues carry an area label with no `labeled` event at all** (#571, #588, #589 — labels
   applied at creation emit none). They are reported as UNKNOWN, never folded into either side.

### The aggregate hides a branch that fails the record's own test

Split per rule on held-out rows only:

| branch | held-out | self-graded |
|---|---|---|
| title topic prefix names a declared area | **104/106 = 98.1%** | 21/21 = 100.0% |
| gated title scan | **32/41 = 78.0%** | 15/17 = 88.2% |

The 92.5% aggregate is carried entirely by the topic-prefix branch. The gated title-scan branch
sits at **78.0%** — *below* the 86.8% file→area map this record rejects for being "below the rule
it would extend". Applied per-branch, that argument rejects the title-scan branch too. (n=41,
p=0.38 vs the map, so this is a direction to investigate, not a settled result; 9 of the 11
held-out errors come from this branch, most of them `review-fix.yml` work scanned to `area:worker`.)

**Open question, deliberately not answered here:** whether the gated title-scan branch should be
narrowed or dropped. Narrowing a live classifier changes what the frontier stages and is a separate
change from fixing the creation path; this record's decline conclusion does not depend on it either
way, since dropping the branch would *raise* the shipped rule's precision, not lower it.

### Parent inheritance is refuted, and structurally so

40% of this repository's issues (267 of 658) are machine-minted follow-ups naming the parent they
were discovered in. The parent usually has an area, so inheritance looks free. It is not: **105 of
239 disagree**. The mechanism is not noise — a follow-up exists *precisely because it is out of
scope of its parent*, and out-of-scope very often means a different surface. `#1013` says so in its
own body ("out of scope for the dispatch-area PR that found it") while being about
`backfill-provenance.yml`; `#1014` says "this is triage/migration work on the target repo, not
dispatch work". Inheriting would have mislabelled both.

### The declared file map does not pay for itself

Built only from the `area:*` labels' own descriptions (an independent source from the issue
corpus), it reaches 86.8% (33/38) — **below** the 92.5% held-out rule it would extend, though as
noted above that gap is not statistically separated (p = 0.33) — while covering just 10.3% of
declines. 3 of its 5 errors share one shape: the title names a file (`worker-live.sh`) but the work
is toolchain (`area:ci`). Naming a file is not the same claim as the work living in that surface,
which is the same failure that killed the path-hint rule at 12.9%. It is declined on the combination
of *no measured improvement* and *added surface*, not on a demonstrated difference.

**A wrong `area:` costs more than a missing one.** `area:` is the conflict-partition key:
`plan_repository` skips any candidate whose area is already reserved, so a misattributed issue is
staged, reserves a partition its work never touches, and blocks the correct candidate for it. On
the live board 9 of 10 areas are already busy (`frontier: area-limited at 3/12`), so a wrong key is
expensive immediately.

## What the residual actually is

After attribution (2026-07-28) the census reports 11, and every one is a genuine multi-surface item:
rollups (`#76` a repo-wide throughput programme, `#223` an audit across six areas), cross-cutting
refactors (`#404`, `#436`, `#591`, `#1021` — the `_alert_route` cluster spanning five scripts),
repo-wide comment sweeps (`#672`), and `#592`, which already carries *two* correct area labels and
is refused for that reason. No single partition key represents these correctly; a `needs:` gate or
an explicit multi-area partition model would, and both are policy changes, not classifier changes.

## So the fix is at creation, not at classification

The agent filing a follow-up has just read the code and knows the surface; it is simply never asked,
and `create_followups` accepts `labels` from the model already. Two defects there, both fixed in the
PR accompanying this record:

1. **The unknown-label retry went label-free immediately.** `gh issue create` fails the whole create
   when any one `--label` does not exist, and the recovery re-issued it with *no* labels — so one
   typo'd label discarded a correct `area:` too. The create then SUCCEEDS, so nothing goes red and
   the loss is invisible: `#971`'s "a failure that removes items from a population rather than
   marking them bad" shape. The recovery is now a ladder — the labels the target *declares*, then
   (if the vocabulary could not be read) the declared set unchanged, and only if every labelled
   attempt fails, a bare create that is announced and carries the intended labels in its body.
   The last rung is kept deliberately: an item that is never created is absent from *every* census,
   including the `unattributable` bucket, which is a worse instance of the same shape than an item
   created unattributable and therefore counted.
2. **A follow-up minted with no `area:` said nothing.** It now emits a `::warning::` naming the
   issue, at the point where the model that knows the answer is still in the loop. The signal reads
   the labels that actually **landed**, not those declared — a model that typo'd the area itself
   (`area:dsipatch`) declares a label starting `area:`, so a declared-set test stayed silent on the
   one path where the created issue really is born unattributable.
3. **One follow-up failing destroyed the rest of the batch.** The vocabulary read added by the
   first fix for (1) raises, mid-loop, and both call sites swallow the exit with `|| true`. Each
   line is independent work, so a per-entry failure is now contained and annotated. This was found
   in review of that first fix, not by the measurement above.

Deliberately **not** done: minting `needs:area`. `triage.triage()` parks on it and `retriage.py:262`
strips it right back out, because `#606` measured that a `needs:area` park is never cleared once the
area lands — retriage skips every `needs:*` gate. Adding a park with no exit would rebuild the loop
this alert exists to measure.
