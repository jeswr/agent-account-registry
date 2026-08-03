# #1174: may `gh api graphql` carrying a *query* be admitted as an idempotent read?

> 🤖 **SPARQ agent** — design record, 2026-08-03. Maintainer-review document.
>
> Unlike the other records in this directory, **this one accompanies a behaviour change** — the
> `gh_retry.py` diff in the same PR — because #1174 was dispatched as an implementation task, not
> as a `needs:design` hold. #1174's own body asked for the record anyway ("*it needs a design
> record, not a drive-by*"), and it asked for the sketch to be **rejected if it is not sound**. So
> this states what was accepted, what was **rejected**, what could not be measured in this
> container, and what an acceptance must not be read as covering.
>
> **Recommendation, in one line: ACCEPT the admission, on a document proof rather than a flag
> proof — but the sketch's "first executable definition" rule is REJECTED and replaced by an
> every-definition rule (§3.1), and the admission could not have been sound at all without §5,
> a pre-existing fail-open in the same parser that admitted a multi-line `-f` POST as a GET.**
>
> ⚠️ **§4's question — "does a replayed GraphQL query have any observable side effect?" — was NOT
> settled by measurement.** This container has no `gh`, no token and no network. It is answered by
> derivation from the GraphQL grammar plus the argv this layer can see, and §4.1 gives the two
> commands that would settle the residue empirically.

## 1. The question, and the state of the tree before the change

`gh` sends `-f`/`-F` fields with no explicit `-X` as a **POST body** (measured for registry #731
against gh 2.94.0 with a local echo server; that measurement is not re-litigated here). So
`read_cli_reject` classified **every** `gh api graphql …` call as a non-GET, and `run_gh` gave it
exactly one attempt plus a `GH-RETRY-SCOPE-REFUSED` line.

That verdict is correct for `enablePullRequestAutoMerge` and wrong for a read, and the two are
indistinguishable at the flag level — both are `-f query=…`. The live cost sits in
`scripts/latch-watchdog.py`:

- `list_open_prs` (`:429-465`) issues `["api", "graphql", "-f", "query=" + OPEN_PR_QUERY, …]`
  through `_default_read` → `gh_retry.run_gh` (`:415-422`);
- it is the **fan-out** read: every PR the watchdog then considers comes out of it, and it raises
  `RuntimeError` on any non-zero rc, so one transient 502 or secondary-403 reds the whole
  scheduled run;
- `re_arm` (`:557-561`) issues the `enablePullRequestAutoMerge` mutation through `_default_write`,
  which execs `subprocess.run` directly and never touches this layer.

#1137 masked the exposure completely (the read failed 100 % of the time for an unrelated reason —
a doubled `gh` binary), so it only starts now that the read works.

## 2. Why the discriminator has to be the DOCUMENT

Three candidate discriminators were considered; two are rejected outright.

| candidate | verdict | why |
|---|---|---|
| admit the `graphql` **endpoint** | **REJECTED** | it is the endpoint every mutation in this fleet already uses (`worker-pr.py:5438`, `latch-watchdog.py:558`). It admits the arm primitive. |
| admit on an explicit caller opt-in (a `read_only=True` kwarg) | **REJECTED** | it moves the trust decision to the call site, i.e. exactly the "one adopter away" hazard registry #731 named. A guard the caller can assert its way past is not a guard. |
| admit on a proof read off the **document** | **accepted** | the document is in the argv, this layer can parse it, and the property it needs is a property of the *grammar*. |

The grammar property is the whole load-bearing claim, so it is stated precisely. In an
**executable** GraphQL document every top-level definition is either an *operation definition* —
which begins with the keyword `query`, `mutation` or `subscription`, or is the anonymous `{ … }`
shorthand that the spec defines as a **query** — or a *fragment definition*, which begins
`fragment` and cannot execute on its own. There is no other spelling for a side-effecting request,
and no way to nest an operation inside another definition. Therefore:

> a document whose every top-level definition begins `query`, `fragment` or `{` cannot mutate —
> **whatever schema is behind it.**

That independence from the schema is why this is admissible as a *scope rule* at all. A check that
had to know GitHub's schema would be a check that goes stale silently.

## 3. The sketch, clause by clause

#1174 sketched: *admit `api graphql` only when every `-f query=`/`-F query=` value parses as a
GraphQL document whose first executable definition is `query`/anonymous, refuse on the first
`mutation`/`subscription` token, and refuse anything ambiguous.*

### 3.1 REJECTED: "whose **first** executable definition is `query`/anonymous"

`gh api graphql` accepts an `operationName` field, and GraphQL requires one whenever a document
carries more than one operation. So a document whose *first* operation is a query and whose
*second* is `enablePullRequestAutoMerge` is a **mutation request** if `operationName` selects the
second one — and `operationName` may arrive as `-F operationName=…`, a value this layer would have
had to interpret in order to know which operation actually runs.

Positional rules invite exactly that class of bug. The implemented rule is therefore
**every-definition, not first-definition**: *all* top-level definitions must begin `query`,
`fragment` or `{`, and at least one must be an operation. `operationName` then becomes
irrelevant — every operation it could name is a query. (Fixture:
`GRAPHQL_READ_DOCUMENT + "\n" + GRAPHQL_WRITE_DOCUMENT` is refused.)

### 3.2 Accepted, with the ordering made explicit: "refuse on the first `mutation`/`subscription` token"

Kept, and it runs on the document with **string literals and comments removed first**. Order is
load-bearing in both directions:

- a raw scan **over-refuses**: `query Q { search(query: """a { mutation } b""") { issueCount } }`
  is a perfectly ordinary GitHub search read, and a block string may legally contain `{`, `}` and
  the word `mutation`;
- a raw scan also **mis-counts brace depth** for the same reason, which would corrupt the
  every-definition walk that is the actual proof.

This scan and the definition walk **deliberately overlap** — for a real top-level mutation both
refuse. AGENTS.md pre-flight 4 is explicit that a duplicated guard can make each copy individually
unkillable, so the overlap is declared in the source and measured: each is killable alone
(`query Q { mutation }` is refused only by the scan; `query Q { id } type Foo { bar: Int }` only
by the walk), and deleting **both at once** is its own mutant, which reds. The overlap is kept on
purpose: the walk's soundness rests on this module's own brace arithmetic, and the keyword scan is
the backstop for a bug in that arithmetic.

### 3.3 Accepted and widened: "refuse anything ambiguous"

The sketch listed *unterminated, templated, read from `@file`, or supplied via `--input`*. All
refuse, plus four the sketch did not name:

| refused | why |
|---|---|
| unterminated string / block string | whatever follows the opening quote was never understood, so **nothing** about the document is proven. `graphql_strip_literals` returns `None`, never a best effort. |
| unbalanced braces/brackets, or a definition that never closed | the walk did not reach the end, so "every definition" was never established. |
| `--input=…` | gh reads the body at request time; the bytes that would be replayed are not in the argv. |
| `@file` / `-` (stdin) as the `query=` value | same reason. Needs **no branch of its own**: neither is a GraphQL definition, so both fail the walk. A second branch here would have been a duplicate guard of exactly the shape §3.2 declares. |
| an explicit `--method` of **any** kind, including `-X GET` | narrower than before the change: `gh api -X GET graphql -f query=<mutation>` used to be admitted as a plain GET read. It could not actually write (GitHub's GraphQL endpoint is POST-only), but it is a hole in the *rule*, and one rule per endpoint is cheaper to reason about than two that could disagree. |
| more than one, or zero, `query=` fields | with two, which document would be replayed? With none, there is nothing to prove. |
| a field argument that does not parse as `key=value` | the fields the call would send cannot be enumerated, so neither can the document. |
| an endpoint that is not the token **immediately** after `api` | `gh api -H … graphql …` is legal gh, and locating the positional robustly means knowing which of gh's ~20 flags take values. That parser would be fragile, and a fragile parser at this seam is worse than a narrow one. This form simply keeps today's refusal. |

**"Templated" is the one clause that cannot be honoured as written**, and saying so matters. By the
time an argv reaches this layer the shell has already expanded it; there is no residue of a
template to detect. What covers the case is §2's grammar property: an expanded mutation still
carries the `mutation` keyword and still starts a top-level definition with it. A caller that
interpolates *untrusted* text into a GraphQL document has a much larger problem than retry scope,
and this layer does not claim to solve it (§7).

## 4. "Does a replayed GraphQL query have any observable side effect?"

**Not settled by measurement — settled by derivation, and the residue is named.**

What the derivation gives: the admitted request is an HTTP POST to `/graphql` whose body is
`{"query": <document>, "variables": {…}}`, where every operation in `<document>` is a `query`. A
`query` operation is defined by the spec as a read; GitHub's GraphQL API exposes no
side-effecting field outside `Mutation`, which is unreachable from a `query` root. Variables
cannot introduce an operation, so no variable value — including one gh would read from `@file` —
can change this, which is why §3.3 admits indirect values for *variables* while refusing them for
the *document*.

The one observable effect that **does** exist, which the issue itself set aside, is **rate-limit
point accounting**: each replay spends the query's points again. It is bounded by `MAX_ATTEMPTS`
(5) and it is the same cost the REST reads already routed through this layer pay, so it does not
change the class of the exposure. It is worth stating rather than waving away, because the failure
this admission exists to survive — a secondary-403 — is itself a throttle signal, and a retry into
a throttle is only safe because the backoff is exponential and capped.

### 4.1 What would settle the residue empirically

Two commands, neither runnable here (no `gh`, no token, no network):

```
# 1. does a repeated identical query change anything observable beyond rate-limit points?
gh api graphql -f query='query { viewer { login } }' --include   # x3, diff the X-RateLimit-* headers
# 2. does GitHub accept a GET on /graphql at all (the -X GET hole §3.3 closes)?
gh api -X GET graphql -f query='query { viewer { login } }'
```

If (2) ever returns 200 rather than a 404/405, the `-X GET` refusal stops being belt-and-braces and
becomes load-bearing — the record should be revisited, not the code quietly relaxed.

## 5. The fail-open found while doing this, and why the admission could not be sound without it

`_ATTACHED_FIELD_RE` / `_ATTACHED_METHOD_RE` / `_INPUT_FLAG_RE` were compiled **without**
`re.DOTALL`. `.` therefore does not match a newline, so `(.+)$` **cannot match an attached flag
whose value spans lines**. Measured on the pristine tree, before any part of this change:

```
argv:   ["api", "repos/o/r/issues/7/comments", "-fbody=line one\nline two"]
shape:  effective_method = 'GET'          # fields == [] — the field was invisible
verdict: read_cli_reject(...) is None     # ADMITTED as an idempotent read
```

A comment POST, admitted for replay by the guard that exists to prevent exactly that, through the
retry layer, up to five times. That is incident #559's class — a duplicated comment — reachable
today by any caller whose body contains a newline, which for a PR comment is the normal case.

It is fixed in the same PR (`re.S`, and `\Z` rather than `$` so a value ending in a newline cannot
be truncated by `$`'s before-final-newline match) because #1174's admission is **unreachable
without it**: a GraphQL document is multi-line, so `gh api graphql -fquery=<document>` was
invisible to the parser too. Fixing it is a tightening, not a widening: it moves argvs from
*admitted* to *refused*.

This is the item in this record most worth a second reader's attention. It is not a GraphQL
question, it long predates #1174, and it was found only because widening a rule forced someone to
read the parser that implements it.

## 6. What the change does NOT do

- **It does not touch the write path.** `latch-watchdog._default_write` and `worker-pr`'s
  `_run_gh` mutations exec directly and never consult this module. The re-arm mutation's argv is
  refused by the predicate as well (asserted), but that is a backstop, not the mechanism.
- **It does not give the ledger CAS writers a transparent replay.** Unchanged, and unchangeable
  here: `ledger_retry.py` and each writer's own re-read loop still own that (#558/#179).
- **It does not admit `gh api graphql` from any new caller.** The only production argv it changes
  the verdict for is `latch-watchdog.list_open_prs`, which gains the bounded backoff every other
  read in the fleet already had.
- **It is not an input-sanitiser and must not be cited as one.** It answers exactly one question —
  *may this argv be re-executed?* — and it answers it fail-closed. It says nothing about whether a
  document was safe to *construct*.

## 7. Evidence

- `python3 scripts/gh_retry.py --self-test` — **180** checks green, up from **127** on `master`;
  **53** of them named `#1174`, asserting both directions (admit **and** refuse) at three layers:
  the document policy, the argv policy, and the real `run_gh` loop counted at the subprocess
  boundary.
- **Mutation sweep: 29 mutants, 27 killed**, one per pristine copy, tree-change asserted, kills
  extracted line-anchored (`^  FAIL `), and every mutant run required to produce the **same total
  check count** as the pristine run — which caught one operator error in the harness itself rather
  than reporting phantom kills.
- **Two declared survivors, neither a coverage hole:**
  - *mutually-masking duplicate* — making the keyword scan inert **only** for documents containing
    `clientMutationId` survives, because the definition walk refuses those same documents. The
    mutant's own predicate names a token that appears in the harness's write fixture, which
    AGENTS.md pre-flight 4 calls out as a badly-chosen mutant value. Deleting **both** guards
    together is the correct experiment for this shape, and it reds (§3.2).
  - *equivalent* — `$` in place of `\Z` under `re.S` with a greedy `(.+)`. Verified directly: for
    every value tried, including ones ending in one or more newlines, the two regexes capture the
    same group, because a greedy `.+` always reaches true end-of-string and `$` matches there.
    `\Z` is kept for explicit intent, not for behaviour.
- **Line coverage** (`trace --count --missing`, instrument validated against a deliberately
  never-called function first): every line added by this change executes. Three escape paths in
  the lexer — the `\"""` block-string escape, the `\"` line-string escape, and the raw newline
  that makes a line string illegal — had **zero** coverage on the first pass and got fixtures
  written so that the wrong answer is *admitting a `mutation` token that leaked out of a literal*,
  not merely a different message.
- Not run here: the self-tests of `latch-watchdog`, `worker-pr`, `ci-latency-alert`,
  `ratelimit-alert` and `regate-sweep` all abort on `ModuleNotFoundError: No module named 'yaml'`
  in this container. That is `worker-live.sh`'s ENV-BLOCKED condition, not a failure — verified by
  running each against the **pristine** `gh_retry.py` and getting byte-identical tails and
  identical check counts (86 / 278 / 0 / 111 / 215, zero FAIL rows on both sides). The
  `gh_retry`-dependent assertions in those suites were additionally exercised directly: every argv
  in `worker-pr`'s GUARD 7 mutation list is still refused, `ratelimit-alert`'s read is still
  admitted, and `latch-watchdog`'s real `OPEN_PR_QUERY` (read out of the source file, not a copy)
  is admitted while its real re-arm mutation is refused. **PyYAML is preinstalled on
  `ubuntu-latest`, where the gate runs.**
