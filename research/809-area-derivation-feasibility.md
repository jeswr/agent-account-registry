# Can the curator derive `area:` itself? — measured answer

> 🤖 **SPARQ agent** — design record, 2026-07-28. Maintainer-review document.

`triage-stock-alert.census()` reports an `unattributable` bucket: machine-owed `status:untriaged`
issues for which `curate-frontier.derive_area` returns no area. `area:` is the one label neither
the curator nor `triage.triage()` can manufacture, so the alert asks whether it could be derived.

**Answer: it already is, at 93.0% precision, and no additional signal clears that bar.** The
residual is not a missing rule — it is the class of issues that genuinely span several surfaces.

## What was measured

Ground truth is this repository's issues carrying **exactly one** `area:*` label (n=556). Those
labels were applied by a human or another lane, so agreement is not tautological. The shipped
deriver was evaluated with the area labels **stripped from its input**, otherwise it answers
`"existing"` and measures nothing.

| signal | fires | precision | source |
|---|---|---|---|
| **shipped `derive_area`** (existing label / title crate / topic prefix / gated title scan) | 186/556 | **93.0%** | this record |
| parent-issue inheritance via the `sparq-followup` provenance link | 239 | **56.1%** | this record |
| declared file→area map, as a marginal fallback on the 370 declines | 38 (10.3% of declines) | **86.8%** | this record |
| body+title token scan | — | 40.0–50.0% | #809, recorded in `derive_area` |
| directory path hints | 145 | 37.9% combined, **12.9% on this repository** | #809, removed |

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
corpus), it reaches 86.8% — **below** the 93.0% rule it would extend — while covering just 10.3% of
declines. 3 of its 5 errors share one shape: the title names a file (`worker-live.sh`) but the work
is toolchain (`area:ci`). Naming a file is not the same claim as the work living in that surface,
which is the same failure that killed the path-hint rule at 12.9%.

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

1. **The unknown-label retry went label-free.** `gh issue create` fails the whole create when any
   one `--label` does not exist, and the recovery re-issued it with *no* labels — so one typo'd
   label discarded a correct `area:` too. The create then SUCCEEDS, so nothing goes red and the loss
   is invisible: `#971`'s "a failure that removes items from a population rather than marking them
   bad" shape. The retry now keeps every label the target declares.
2. **A follow-up minted with no `area:` said nothing.** It now emits a `::warning::` naming the
   issue, at the point where the model that knows the answer is still in the loop.

Deliberately **not** done: minting `needs:area`. `triage.triage()` parks on it and `retriage.py:262`
strips it right back out, because `#606` measured that a `needs:area` park is never cleared once the
area lands — retriage skips every `needs:*` gate. Adding a park with no exit would rebuild the loop
this alert exists to measure.
