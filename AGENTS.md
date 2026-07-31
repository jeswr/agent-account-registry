# AGENTS.md — agent-account-registry

> 🤖 **SPARQ agent** — @jeswr runs multiple agents under one account; this file is written by
> the SPARQ agent. Identify yourself with this blockquote in every issue/PR/comment you author.

`README.md` is the reference for what this repo **does** — the ledger, the lease protocol, the
selection logic, the routing rules, the runbooks. **This file is how you work ON it**: the
standing rules an authoring agent follows, defined here **once** so a role brief can point at
them instead of copying them. The role briefs under `.claude/agents/` carry their own lane
deltas and cite this file; if a brief and this file disagree, **this file wins** — fix the brief.

A rule that is copied into several briefs drifts. This repo has a live bug of exactly that shape
(#958: the literal `review:parked` has **four** independent definitions and two consumers are
blind to a repoint, one of them fail-open). So: one definition, plus pointers.

## AUTHOR pre-flight — run these on your OWN diff before your final message

On 2026-07-27/28 essentially every PR that went through independent adversarial review here
**failed its first review** — not on design, on this small repeating set. The checks that catch
them lived only in the reviewer's brief, so every PR paid a whole review round to discover a
defect its author could have found pre-flight. Run them yourself. Each cites the PR that earned
it; all of them run **offline**, inside the worker container, with no GitHub token.

⚠️ **This list exists in FULL in two repos with no shared owner** — here and in `sparq-org/sparq`'s
`AGENTS.md`, which is the **canonical** copy. This one cannot be a pointer: this repo has no
`CLAUDE.md` to auto-load anything, and the worker container is offline, so the text has to be here.
Change a rule in one and mirror it in the other in the same wave, or say why not. The two have
already diverged on lane-specific detail. That is the **#958** shape applied to prose, and **#945**
measured the cost of duplication directly — two copies of one guard make each individually
unkillable.

1. **Line coverage FIRST — and read it LINE-granular, not function-granular.** Run the module's own
   `--self-test` under `python3 -m trace --count` (stdlib; nothing to install) and list the
   **never-executed LINES** before you mutate anything. Four for four as a predictor of where
   mutants survive: **#756** (`cmd_record` + `_read_json` never executed → the shipped tree
   printed `planned_rows=4` where the mutant printed `0`), **#956** (the module's **only two write
   methods** had never executed anywhere), **#937** (`main` + `_gh_readers` at 0 % → **13 of 13**
   one-line edits there survived a **248**-check suite, including an `apply=false` "census-only
   preview" that writes real ledger records), **sparq #4743** (**17 of 29** functions at 0 %;
   `main()` at 55 % with its whole `sweep` branch unexecuted, so `return 1 if …sweep() else 0`
   → `return 0` survived all **111** tests). Helpers get tested because they are easy to call;
   **entry points get skipped because the test has to construct the real world — which is exactly
   where a *fabricating* bug survives.** ⚠️ **"Nothing at 0 %" does NOT clear you.** The
   function-granular headline is the weak form and it misses the worst regions: **#956**'s `main`
   is at **8/18**, not 0 %, and a fresh sweep of exactly that region found **10 survivors out of
   10**; **#941**'s `_escalate_two_head` had **1 of 3 call sites covered at 3/3 confidence**, which
   **#945** re-derived as **3 of 4 site lines never executed while the enclosing functions read
   75 %**. ⚠️ **Validate the coverage instrument against a function you know is never called**:
   #756's counted docstring lines as covered, scored a never-called function at 6.2 %, and printed
   *"no code unit is entirely unexecuted"*; #956's reported zero uncovered lines from a mode that
   **cannot emit one**. An instrument that cannot fail has told you nothing.

   ⚠️ **`trace --count` marks a never-executed line by OMITTING the count prefix — NOT with
   `>>>>>>`** (#1073). This is the named instance of #956's "mode that cannot emit one", and the
   vacuous detector is the one you would naturally reach for. In a `.cover` file from `python3 -m
   trace --count --coverdir=<dir>`, an executed line carries a `"%5d: "` prefix and an unexecuted
   line carries **seven blanks**; the `>>>>>>` marker is `trace --missing` and coverage.py, and
   stdlib `trace` does not even *compute* the marker set unless `--missing` is passed (`lnotab = {}`
   otherwise). So `[l for l in cover if l.lstrip().startswith('>>>>>>')]` returns **0 uncovered lines
   for every file, always** — it read `scripts/park_policy.py` as fully covered by its own
   `--self-test`, which in fact never executes **71** statement lines.

   The detector that works is **"no count prefix", intersected with statement START lines from the
   AST** — `stmts = {n.lineno for n in ast.walk(tree) if isinstance(n, ast.stmt)}`, then report `i`
   where `i in stmts and not re.match(r"\s*\d+:", cover[i-1])`. The intersection is what keeps
   comments, blank lines and a multi-line statement's continuation lines out of the count. **Subtract
   docstrings** — they are `ast.Expr` statements that never execute, and leaving them in inflates
   that same file from 71 to **130** phantom dead lines, which is #756's error with the sign flipped.

   ⚠️ **The probe is what licenses the number — the detector code above does not.** Append a function
   you never call, re-run the self-test under `trace`, assert its **body** lines come back REPORTED,
   then restore the pristine file. Assert the **body**, never the `def`: the `def` line executes at
   import and is always counted `1:`, which is precisely how a function-granular reading certifies a
   never-called function as covered. **A detector that reports nothing on that probe has not measured
   your module — discard the run, do not proceed to mutation.**

   Then cross-check against a second instrument instead of trusting one: `--count --missing` marks
   **83** lines on that same file, agreeing with the AST form on 70. They disagree only where they
   must — `--missing` counts a multi-line statement's continuation lines where the AST form counts
   its one start line, and the AST form over-reports `nonlocal`, which compiles to no bytecode.
   **Non-zero and explainable is the pass condition; exact agreement between the two is not.**
   (#1073 reported this region as 74 never-executed lines; re-measured with docstrings excluded it is
   **71** — item 10.)
2. **Ask FOUR independent questions of every assertion** — none subsumes another, and each found
   holes the others swept past (#941). (a) Does the **call site** recompute or re-wire this
   value? (#937 `Z6`: dropping one argument at the single production call site bound the wrong
   issue with a 219-check suite green.) (b) Does my **expected** value come from the same place
   the code reads it? (#958: every assertion compared what a module wrote against the constant it
   writes from — a tautology that cannot fail.) (c) Does my **input** derive from the same
   constant the code reads? (#941: every over-cap input derived from `STUCK_UNPARK_MAX`, so
   setting `STUCK_UNPARK_MAX = 999` left 76/76 green.) (d) Does this control ever **execute**, and
   does the check test the flag's **value** or merely its **presence**? (#941:
   `--stuck-grace-hours 6` → `100000` survived 76/76.)
3. **Two mutants per guard: DELETE it, and separately make it conditionally inert** — in a
   **non-crashing** form. They are different experiments. #938: deleting a census emission was
   caught; wrapping it in `if census.get("total")` was **not**, so it would have vanished on
   exactly the quiet tick an operator interrogates. ⚠️ **One-at-a-time is structurally blind to a
   DUPLICATED guard** — see item 4's fourth outcome; that experiment needs both copies gone at once.
4. **FIVE false mutation outcomes — say which one you have.** *False kill*: an exception raised
   **by the mutated line itself** is malformedness, not detection (#956: two mutants "died" to an
   `IndexError` that aborted the suite before any row printed). *Equivalent survivor*: declare it
   and show it unreachable (#937 `D1-default`). *Value-identical survivor*: the substituted value
   collides with one the fixture already uses (#941 pins a fixture head as `'b'*40`) — **choose
   mutant values that appear nowhere in the harness.** *Mutually-masking duplicates*: two copies of
   one guard make **each copy individually unkillable** — three of **#945**'s four survivors were a
   single `MIN_ARG_TOKEN` floor written at both the producer (`_arg_literals`) and the consumer
   (`site_fingerprints`), where *"removing either copy alone left the suite green."* Item 3's
   one-at-a-time protocol **cannot see this**: find it by asking whether the value is written twice,
   and by deleting **both** copies as one mutant. *Crash-after-partial-run*: a mutant that reds some
   rows and then **aborts** the suite records as KILLED while every check below it never ran (#945:
   an emission block raising `IndexError` after three named `FAIL` rows). Require the mutant run's
   **total check count** to equal the pristine run's before you call it a kill.
5. **Ask of every control: WHO can write the thing this reads?** Three arm-capable holes in one
   night, all from evidence read out of **author-controlled** text with no author filter: **#681**
   (per-provider review markers parsed from `pull["body"]` → the required-review count goes
   **2 → 1** and the surviving lone review arms it), **#937** (closing-reference declarations from
   title/body), **sparq #4743** (a marker in **any** comment, with no `login` /
   `author_association` check, on a **public** repo → a drive-by comment forges `route=preserve`
   and re-arms). Evidence *about* a review must be written by the party that did it, filtered by
   author, and read with **quoted contexts stripped** — a marker inside a fenced block otherwise
   self-marks (#937 `Z1`–`Z5`).
6. **The YAML seam is where the vacuity lives** — every uncaught mutant measured that night sat at
   a workflow `if:`, a step, or a call site, never in the Python. **Pin exact-match, not
   containment**: #956's `--apply-DROPPED` and `--reconcile-max-DROPPED` both survived a substring
   check; #941's `if: false` on the resolver **step** and on the whole **job** each survived
   76/76; sparq #4743's `route != 'preserve' && false` satisfies a substring assertion while
   killing the lane. Tokenise the flag list and assert exact membership plus adjacency.
7. **Never substring-grep for a kill.** These suites print each row's name on the **pass** path
   too — extract kills line-anchored (`^FAIL:` / `^\s+FAIL\b`) or from the traceback frame.
   Measured on one real 6100-line gate log: **62** lines contained `FAIL` as a substring, **44 of
   them passing `ok` rows**; the anchored form extracted **1** (#949).
8. **A census must always emit, including a zero row.** Ask: *would this alarm fire if this branch
   took 100 % of the population?* (#938: the reservation census never zero-sealed.) And **a
   residual computed from rows that ENTERED a pipeline cannot see a loss that prevented entry** —
   #756's `chain_unaccounted` read 0 in both the shipped and the mutant tree, so its own
   missing-edge detector was structurally blind to the break.
9. **Verify the marquee claim against the EVIDENCE path, not the object it names.** #681's
   headline held for the *record* and failed for the *review-set evidence* it is actually enforced
   through. The feature in the **title** is disproportionately the one with no red test — mutate
   it first.
10. **Publish corrected counts.** Four headline numbers moved that night once someone asked a
    specific question of every row: #941 22/22 → **21/22** then 26/26 → **25/26**; #937 48/48 →
    **48/56**; #956's "52 mutants, 52 killed, 0 survivors" → six reproducible survivors. **A
    downward correction is what makes the rest of the report trustworthy** — the counts that never
    moved are the ones a reviewer rejects.
11. **Check what the transition DELIVERS INTO.** A park exit that re-admits into an unchanged
    tree, a mint that yields no review, or a fix that lands one layer short of the binding layer
    has produced nothing (#956; #937's root cause was swept only as far as `sweep()`'s call sites
    and stopped one layer short).
12. **Do not "re-run your sweep" — ask a NAMED question.** A re-sweep returns the same answer. One
    precise question — *"which of my assertions reads its expected value from the code under
    test?"* — is what turned up real defects in the same authors' own patches that night,
    including one author catching its **own fix** one layer short.

13. **Declare the source issue your PR closes.** The cross-provider review lane can only enumerate a
    PR that has a provenance record, and `auto-mint-provenance.py` derives its one hard input — the
    source issue — from the PR's own closing reference. Measured on the live board the night
    **#937** merged: of **15** enrolled-class pulls, **12** refused `no-issue-reference` and **1**
    resolved its reference to a pull request rather than an issue. Every body this repo composes
    **in code** already declares one; **every refusal was a body composed by hand.**

    **What is required is one closing keyword, then one or more spaces or tabs, then `#<n>`** —
    that is the whole rule. (Every example on this page writes the number as `<n>` on purpose:
    `#<n>` cannot match the reader's `#[1-9][0-9]*`, so an example pasted verbatim into a PR body
    declares nothing instead of silently binding that PR to an issue named in this file.)

    ⚠️ **The separator is the hazard, and it is the ONLY part that is fragile**, because two
    consumers read these bodies with grammars where *neither contains the other* — so a form one
    accepts can be invisible to the other. Measured against both regexes and GitHub's live renderer:

    | separator | `auto-mint` | `groom` | binds |
    |---|---|---|---|
    | `Closes #n` — space(s) or tab | yes | yes | **yes** |
    | `Closes: #n` — colon | yes | **no** | yes |
    | `Closes\n#n` — newline | **no** | yes | no |
    | `Closes#n` — nothing | yes | **no** | no |

    **What is NOT constrained** — stated because an over-tight rule gets followed anyway and then
    cited as a reason to rework something that was always fine. The **keyword is free**:
    close/closes/closed/fix/fixes/fixed/resolve/resolves/resolved, any case, all work —
    `worker-live.sh` emits `Fixes #<n>` and is 24/24 compliant. **Placement is free**: inline
    mid-sentence, ending a sentence, in a list item, bold-wrapped, or alone in a paragraph all bind.

    Two things still bite. A **second** closing pair anywhere — including inside a fenced block,
    which the raw side does **not** strip — refuses the whole PR as `ambiguous-issue-reference`. And
    a body ending inside an **unterminated fence or unclosed HTML comment** swallows an appended
    reference: it reads correctly and binds to nothing. `scripts/pr-body-ref.py compose --issue <n>
    --repo <owner/name> --body-file <f>` handles both — it verifies its output against the reader's
    *imported* grammar and writes nothing if the reader would not bind it.

    ⚠️ **The number is the issue you were DISPATCHED against — never the branch name, never a number
    the body happens to mention.** If you cannot prove one, declare **nothing**: a missing reference
    is a visible, censused, one-edit-recoverable refusal; a wrong one silently binds your PR to
    someone else's issue, mis-partitions the review lease, and points the human-hold at the wrong
    object.

    **You do not have to remember any of this.** `pr-gate` runs `pr-body-ref.py check` on every
    pull and annotates yours with the refusal by name when it is CERTAIN of one — declaring none,
    or declaring two. It is advisory, it never fails the gate, and it stays quiet when it cannot be
    certain, so **a clean run is not proof that you bound**; only the mint census is.

    **And your PR must not be a DRAFT.** Re-measured for #1115: 6 of the 17 orchestrator-class open
    pulls were drafts, and the lane refuses every one of them —
    `is_enumerable_provenance` has no orchestrator opt-in, so a minted draft would be terminally
    `needs:user`-parked by age instead of reviewed. That is a deliberate scope decision, not a bug
    to route around (`research/657-orchestrator-provenance-minting.md` §10.3); mark the pull ready
    for review.

### Mutation-run hygiene (these have destroyed whole measurement runs)

- **`__pycache__` serves stale bytecode.** A mutate/restore cycle inside one mtime second re-runs
  the OLD code and reports phantom kills or phantom survivors. Always `python3 -B` with
  `PYTHONDONTWRITEBYTECODE=1`.
- **Mutate by LINE, and verify the tree actually changed.** A whole-file `str.replace(old, new, 1)`
  hits the wrong occurrence — a comment, a fixture — and reports a phantom survivor. Assert the
  anchor occurs exactly N times **and** that `git status --porcelain` is non-empty afterwards.
- **One mutant per pristine copy**, restored and byte-verified between mutants.
