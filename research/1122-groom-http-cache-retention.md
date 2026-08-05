# May the groom HTTP cache persist target issue/PR bodies? (#1122)

> 🤖 **SPARQ agent** — design record, 2026-08-02. Maintainer-review document.
> **This record changes no behaviour.** #1122 was raised by the #1088 implementation for
> sign-off rather than decided silently; this answers it, shows the evidence, and states what an
> acceptance obliges *before* the code that would rely on it is written.
>
> **Recommendation: YES — accept, but only for content already proven public, and only with the
> three obligations in §5 landing in the SAME PR as #1088** — plus §8's explicit answer on
> platform-controlled *storage* retention, which no cache key can bound. §6 is the plan if the
> answer is no, §7 is what an acceptance must NOT be read as covering, and §8 is the maintainer's
> confirm-or-overrule.
>
> ⚠️ **The issue's own justification contains a factual error that inverts part of it** (§2): the
> registry repo is **public**, not private. The recommendation survives the correction, but only
> because the obligations do the work the "private repo" premise was doing.

## 1. The question, and the state of the tree

#1088 replaces unconditional GETs with conditional ones. A `304` carries **no body**, so a
conditional request is only useful to a caller that needs the body if the cached *representation*
is kept — not just the ETag. #1088 therefore persists `.groom-http-cache.json` through
`actions/cache`, holding GitHub API payloads for the enabled targets: open issue and PR objects
(including each `user.login`) and, once the comments fan-out warms, issue comment bodies.

**State of the tree, stated plainly.** At the time of writing, **#1088 is not on `master`.**
There is no `--http-cache` flag, no `.groom-http-cache.json`, no ETag/`If-None-Match` handling in
`scripts/groom.py`, and **no `actions/cache` step in any workflow in `.github/workflows/`**
(`grep -rn 'actions/cache' .github/workflows/` returns nothing). So this record decides a
**shape**, not a diff — as `research/967-adjudicator-override-arm-authority.md` did for #446. It
binds whenever #1088 lands, and it binds any later cache that would retain the same class of
content under a different name.

## 2. Correcting the premise: this repo is PUBLIC

#1122 argues the retention is probably fine because "the cache is scoped to the private registry
repo". It is not private. `README.md:1` — *"# agent-account-registry (public)"*; `README.md:4` —
*"This repo is **public** so its GitHub Actions run on free unlimited minutes"*; `README.md:373`
— *"which is **public** (see the header), so treat everything you write there as world-readable"*.

Two consequences follow, and both are why "the delta is retention, not access" needs a
qualifier:

- **`permissions:` does not gate the cache write.** `groom-sweep.yml`'s job block is deliberately
  least-privilege (`actions: read`, `contents: write`, `issues: write`, `.github/workflows/groom-sweep.yml:29-32`).
  A cache save is understood to run against the Actions cache service on the runner's runtime
  token rather than on that block's `GITHUB_TOKEN` scopes — ⚠️ **unverified from inside the
  offline worker container; confirm before citing it as a fact.** The conclusion does not depend
  on the mechanism either way: no line of that `permissions:` block names caching, so nothing
  there bounds what a cache step writes. Whatever bounds the cache has must be written into the
  cache step itself.
- **A cache entry's audience is wider than the sweep's.** GitHub's documented cache model lets a
  run restore entries from its own branch **and the default branch**, and `pr-gate.yml` triggers on
  `pull_request` (`.github/workflows/pr-gate.yml:25-26`) with **no fork guard** — no
  `head.repo.full_name == github.repository` condition anywhere in that file. On a public repo, a
  pull request from a fork runs the fork's copy of the workflow file, so a step that fork controls
  is in the same cache-read scope as the base branch.
  ⚠️ **This bullet is UNVERIFIED from inside the worker container** (offline; no network to
  confirm against GitHub's docs). It is stated as the reason the audience question cannot simply
  be waved away — **not** as a measured fact, and the recommendation below is deliberately built
  so that it does **not depend on resolving it**: obligation 1 makes the cached content public
  either way.

Under the correction, the honest statement of the delta is: **retention, plus a widening of the
audience from "holders of the registry App token" to "readers of a public repository" — which is
a real change only for content that is not already public.**

## 3. The test this repo already applies to durable Actions storage

The precedent is inside `groom-sweep.yml` itself, and it is not the fingerprint rule — it is a
**publicity** rule. groom already writes to Actions durable storage: it uploads a per-tick
mint-outcome marker (`.github/workflows/groom-sweep.yml:225-263`) whose **name** carries raw owner
logins (`groom-mint-tick.ok-sparq-org.skip-jeswr`). The step's own comment states the test it
passed (`.github/workflows/groom-sweep.yml:212-215`):

> Owner logins are not secret: policy/repos.toml is public, the resolve step above already tees
> them into this log, and groom.py prints the same skip line. Nothing token-derived is readable
> here — the name keys on `steps.<mint>.outcome`, NEVER on `.outputs.token`.

and its retention is **chosen and then asserted**, not defaulted: `retention-days: 1`
(`.github/workflows/groom-sweep.yml:263`), pinned from the reader's side by
`groom-mint-alert.py --self-test`, which parses the upload step's `retention-days` out of the YAML
and asserts a *relationship* to the live cron period and page size rather than a duplicated
literal (`scripts/groom-mint-alert.py:1700-1711`).

So the four-part test this repo has already applied to exactly this question is:

1. is the content **already public**?
2. is **nothing token-derived** in it?
3. is retention **bounded**?
4. is that bound **asserted by a self-test**, not trusted?

The HTTP-body cache passes (1) *today* and (2) *by construction*, and fails (3)/(4) unless #1088
adds them. It also cannot pass (3)/(4) the way the artifact did (§5 obligation 3): a cache key
bounds which entry a run may **restore**, and nothing in this repo deletes a superseded one — so
physical retention stays platform-controlled. §5 turns that
into three obligations plus the one question §5's obligation 3 cannot answer and §8 asks outright.

## 4. Locked decision 22a — adjacent, and NOT violated

#1122 is right that this is adjacency rather than a violation, and it is worth writing down
*why*, so the next author does not "fix" a cache into fingerprints and lose the ETag key.

`README.md:878-893` states 22a and then states its **scope**, explicitly: each *ledger record,
health record, dashboard payload and identity diagnostic* names an account by the salted
fingerprint only — and *"its scope is exactly them: there is no repo-wide 'no generated handle
anywhere' invariant, and this README cannot create one — only code with a seam test can."*

An HTTP transport cache is none of the four. It is read by `groom.py` and by nothing else; it is
never rendered, never emitted, and never an operator-facing document. The bodies it would hold are
**the same bytes groom already holds in memory on every tick** — the emission surfaces
(alert bodies, comments, the health record) are composed from those bytes today and would be
composed from them identically with the cache present. The cache changes *how long the bytes
exist*, not *what is emitted from them*, and 22a governs emission.

The line that would move this from adjacent to violating is precise, and it is the one to guard
in review: **if any future code composes an emitted artefact by copying a cached field through
rather than by re-deriving it** — a cached `user.login` reaching an alert body, a dashboard
payload, or a ledger record — that is a 22a matter regardless of where the byte came from. That is
already true of the live fetch, and it stays true; the cache neither creates nor excuses it.

## 5. If YES — the three obligations, in #1088's own PR

Acceptance is conditional, and the conditions are load-bearing rather than tidy-ups.

**1. Prove publicity, fail closed — do not key the decision on today's config value.**
Both currently-enabled targets are public (`policy/repos.toml:88-89` `sparq-org/sparq`,
`policy/repos.toml:185-186` `jeswr/agent-account-registry`), which is the entire reason (1) above
passes today. But `policy/repos.toml:153-154` carries `jeswr/solid-sdk` at `enabled = false` —
**one line from `true`** — and the sweep reads targets through a per-owner target-scoped App
token, which can read that owner's *private* repositories. Accepting on the basis that "the
enabled targets happen to be public right now" is accepting nothing enforceable: it makes a
security property a config edit away from silently false, which is the shape this repo refuses
everywhere else. So groom must **refuse to cache a body it cannot prove came from a public
repository**, with unknown treated as not-public (defer/skip caching, never cache-and-hope), and a
self-test that exercises **both** directions — public → cached, and private/unknown → refused —
because a one-direction test cannot distinguish the guard from its absence.

**2. Reuse the existing token-shape *pattern* — as a boolean, not through the log formatter.**
`_TOKEN_SHAPE` (`scripts/groom.py:1179`) is the module's single killable definition of "this text
is credential-shaped", and the cache-write refusal must decide on **that one definition** rather
than restate the pattern — AGENTS.md pre-flight item 4: two copies of one guard make **each copy
individually unkillable** (#945).

What it must **not** do is call `_masked_detail` (`scripts/groom.py:1182-1190`). That helper is a
*lossy diagnostic formatter*: it collapses all whitespace, replaces matches with `***`, and
truncates at `GH_DETAIL_LIMIT = 400`. Three consequences, each of which is a defect if it reaches
a cache:

- its **output cannot be the stored representation** — a replayed 304 would serve a
  whitespace-collapsed, 400-character-truncated body *as if it were the real one*, which is worse
  than no cache;
- comparing its output against the source as a "did it change?" test refuses **every** payload
  over 400 characters or containing a newline or a double space — i.e. essentially every real
  issue body — while proving nothing about credential shape;
- and if the implementer notices that and writes their own detector instead, obligation 2 has been
  "followed" into exactly the second copy it exists to prevent.

So the seam is a **boolean predicate over the exact bytes about to be stored**, no normalisation
and no truncation — `_is_credential_shaped(raw) -> bool` returning
`bool(_TOKEN_SHAPE.search(raw))`, applied to the complete serialized representation (body **and**
any retained headers). A match **refuses the entire cache write** — never masks-and-stores,
because a masked body is a corrupted representation that a later 304 cannot distinguish from a
genuine one. `_masked_detail` keeps its existing job of formatting the *log line* that reports the
refusal.

Pin it with tests in **both** directions, and note the second one is what kills a
"mask through `_masked_detail`" implementation as well as a missing guard:

- token-shaped content anywhere in the representation → **nothing is written** (no entry, and no
  partially-masked entry);
- a safe payload that is longer than `GH_DETAIL_LIMIT`, contains newlines and runs of whitespace,
  and includes a near-miss like `ghp_short ` (five characters after the prefix, under
  `_TOKEN_SHAPE`'s `{8,}` floor) → written and restored **byte-identical**.

Plus the two mutants item 3 requires: the predicate **deleted**, and the predicate made
**conditionally inert** in a non-crashing form.

**3. Bound *reachability* deliberately and assert it at the YAML seam — and do not call that
retention.**
The 7-day cache LRU cited in #1122 is a platform default nobody chose; the artifact precedent
chose `retention-days: 1` and had a reader assert it. But the artifact analogy stops here rather
than completing: the cache has no `retention-days` equivalent to choose — the LRU/inactivity
eviction #1122 itself cites is the *only* deletion, and it is the platform's, not the caller's.
⚠️ **Unverified offline; confirm against the `actions/cache` inputs before citing it.**

Two properties have to be kept apart, because conflating them is precisely how this obligation
could be recorded as met while nothing was actually bounded:

- **Reachability — enforceable in this repo, therefore the obligation.** Give the cache key a
  rotating component (a UTC day stamp or equivalent) so a run can restore only an entry minted
  inside the current window, and pin the workflow seam by **exact match** — tokenise `key:` /
  `restore-keys:` and assert membership, never a substring: AGENTS.md pre-flight item 6, where
  every uncaught mutant measured on 2026-07-27/28 lived. A
  `--http-cache`-vs-`--http-cache-DROPPED` substring check is the exact defect #956 shipped. State
  what this buys without inflating it: an old entry becomes **unreachable** under the new exact
  key, and **still exists**. A restore-key prefix that falls back to a previous window silently
  undoes even that, so the seam test must assert the fallback list too.
- **Physical retention — NOT bounded by any key, therefore a maintainer decision and not something
  #1088 can discharge.** Rotation leaves a *sequence* of superseded body caches on the platform,
  deleted only by the same unchosen LRU/inactivity eviction §3 exists to refuse to trust. So on
  rotation alone, §3's requirements (3) and (4) are **unproved for stored bytes**, and writing
  otherwise here would be the "guess and proceed" this record objects to everywhere else. There
  are only two honest endings, and §8 asks for one of them in its own line rather than folding it
  into a general CONFIRM: an **authenticated cleanup** that enumerates cache entries and deletes
  the expired ones, fails closed, and is pinned by its own seam test (the Actions cache delete API
  — ⚠️ **unverified from inside the offline worker container**; note it would need
  `actions: write`, widening `groom-sweep.yml`'s least-privilege block, which is a real cost to weigh
  against a body cache); or the maintainer **explicitly accepting** platform-controlled retention
  as the bound, with this record naming it as accepted-not-proved.

**Cheap hygiene, same PR:** add `.groom-http-cache.json` to `.gitignore`. The worker commits an
agent's checkout with `git add -A -- .` (`scripts/worker-live.sh:2306`), and the untracked
sidecars this repo does not want committed are lifted out of the tree explicitly
(`.worker-followups.jsonl`, `.worker-no-diff.json` — `scripts/worker-live.sh:592-595,629-631`).
A cache file in the repo root has no such handling, and a commit is **permanent** retention in a
public history — the one retention class this decision is not about and should not accidentally
authorise. The likelihood is low (the worker container is offline and token-free, so a real sweep
cannot run there); the cost of the line is lower.

## 6. If NO — what the budget plan actually is

#1122 says a rejection "needs a different plan for the budget". It largely already has one, and
that matters to the decision: a NO is not the outage it sounds like.

The dominant cost is measured and named in the tree: *"One `/issues/{n}/comments` GET per
commented issue, every tick, is 500 of the ~650 requests a sweep of the two enabled targets
issues (measured 2026-07-29)"*, spent on the **contended** rate-limit partition that every
`issues`/`pulls`/`contents` read shares (`scripts/groom.py:612-628`). The lever already landed for
it is **fetch avoidance, not retention**: `attempts_fetch_needed` (#1303) skips the comments GET
whenever neither guard that consumes the attempt count can still fire. That lever retains nothing
and generalises — the next increment is more call sites that can prove a fetch cannot change an
outcome, not a longer-lived copy of the answer.

What a NO genuinely costs, stated without softening: ETags **alone** only help where a "nothing
changed" answer is *by itself* sufficient to decide (skip a repair, skip a re-read). Wherever the
sweep needs the body, a 304 forces a refetch, so the conditional request saves nothing there.
That is a real loss on the paths where the sweep must read content — it is just a smaller loss
than "#1088's saving is lost", because the largest single line item has a non-retaining fix
already in flight.

## 7. What this record does NOT decide

Stated because an over-broad reading of an acceptance is how scope creeps into a trust plane:

- It does **not** authorise caching anything but **target issue/PR/comment payloads proven
  public**. Not `data/`, not the `ledger` branch, not lease or provenance state, not any
  account-bearing record.
- It does **not** authorise a persistent cache in any other workflow. Each one is its own call
  against §3's four-part test.
- It does **not** widen locked decision 22/22a/22b by a millimetre. §4 explains why it does not
  need to; `README.md:895-896` is unchanged — *"widening what an operational surface may carry is
  a locked decision, reopened by a maintainer only."*
- It does **not** approve #1088. It answers the retention question #1088 raised; the diff still
  faces its own review, and the §5 obligations are part of what that review should check.

## 8. Maintainer confirm-or-overrule

- [ ] **CONFIRM** — persisting public target issue/PR/comment bodies in the groom Actions cache is
      acceptable retention, subject to §5's three obligations landing with #1088.
- [ ] **OVERRULE** — no body cache; #1088 lands with `--http-cache` omitted (or does not land) and
      the budget follows §6's fetch-avoidance path.

A CONFIRM is incomplete without one of these, because §5's obligation 3 can bound reachability and
**cannot** bound stored bytes — leaving §3's requirements (3)/(4) unproved for storage unless this
is answered rather than assumed:

- [ ] **Platform retention ACCEPTED as-is** — superseded entries persist until GitHub's
      LRU/inactivity eviction removes them, no self-test proves that bound, and this record names
      it accepted-not-proved.
- [ ] **Cleanup REQUIRED** — #1088 must also land an authenticated, fail-closed cache-cleanup that
      deletes expired entries, with its own seam test and the `actions: write` widening it needs.

Either answer — with the retention line answered too if it is CONFIRM — is a decision this record
exists to make explicit. Silence is the one outcome #1122 was opened to prevent.
