# #1051: auto-restoring a clobbered account-record body (the write half of #320)

> 🤖 **SPARQ agent** — design record, 2026-08-03. Maintainer-review document.
> **This record changes no behaviour.** No script, workflow, or policy file is touched.
>
> #1051 gates #320's auto-restore on three questions. **Items 1 and 2 could NOT be verified here**
> — this container has no `gh`, no token, and its web tools are permission-gated in a
> non-interactive run (§3 gives the two commands that settle them, and §3.1 what to do with each
> answer). The record is filed anyway because **item 3 is dispositive without them**, and because
> two things that *are* checkable in this checkout came back differently from how #1051 states
> them (§2, §5).
>
> **Recommendation, in one line: WONTFIX the automated restore — and do not stop there.** The
> restore is refused on item 3. But the *reason* it is refused (§4) is that `persist_limits` writes
> the fleet's highest-trust record to populate a dashboard fallback (§5), and that asymmetry points
> at a better cure than either half of #320: **move the `limits:` line off the mutable issue body
> entirely** (§6), which dissolves the window instead of repairing after it. #320's *naming* half
> (§7) stays worth building either way.

## 1. The question

`persist_limits` (`scripts/account-usage.py:717`) writes one `limits:` line into each account
issue's front matter. `gh issue edit --body` replaces the **whole** body and GitHub's issue API
has no conditional (If-Match / CAS) write, so a foreign edit landing inside the read→write window
is replaced by ours. `_persist_one` (`:665`) detects that with a version stamp — the body-edit
count from `userContentEdits.totalCount` (`_ISSUE_READ_QUERY`, `:630-633`; `_issue_view`, `:636`)
— and when the count shape proves a foreign edit landed *inside* the window it refuses: returns
`False` without retrying (`:711-713`), and the caller raises `WRITE_FAILURE_WARNING` (`:590-593`),
whose text points the operator at the issue's edit history.

#320 asked to close that loop automatically: read the replaced revision out of the edit trail and
re-apply it. #1051 asks whether that is (1) possible, (2) reliable, and (3) wanted.

## 2. Premise corrections — two, both checkable in this tree

**2.1 There is no `_edit_trail` in `master`.** #1051 describes #320's PR as having shipped "a
best-effort, failure-path-only `_edit_trail` read (scripts/account-usage.py)". It did not, or it
did not land: `git log -S _edit_trail --all` matches exactly one commit, `1e1303c8d`, on the
unmerged branch `origin/sparq-agent/issue-1051-...`, and there it appears only in prose. The only
edit-trail surface in `master` is the `totalCount` version stamp plus the claim inside
`WRITE_FAILURE_WARNING`. Consequences: #1051's fallback instruction ("record the negative in
`_edit_trail`'s header comment") has **no target site** — §8 relocates it — and §7's naming half is
not a refinement of shipped code but the whole of it.

**2.2 #1051 miscites `research/329-pre-migration-writer-recovery.md`, and so does the prior
attempt.** #1051 offers 329 as precedent for "the fail-closed refusal plus a named revision may be
the terminal answer". 329 §7 opens with the literal sentence **"The refusal is not the terminal
answer."** It specifies a mechanism (C) and recommends building it.

This is worth getting right rather than merely correcting, because 329's actual shape is a
*stronger* argument for this record's conclusion than the misreading was. Mechanism C is a **read**
— widen two jq projections to carry `updated_at` (`research/329...md:147-161`) — and what it buys
is that the loss becomes "named, repairable, fail-closed" (§7). 329 did **not** propose an
automated repair write; it kept the refusal and invested in the signal that makes the refusal
*informative*. Restated as a rule the trust plane already follows:

> Where there is no conditional write, spend effort on the READ that names the hazard. Do not spend
> it on an unattended write that repairs after the fact.

That rule refuses #320's restore half and funds #320's naming half — which is exactly the split
§7 lands on. It is precedent for the split, not for terminality.

## 3. Items 1 and 2 — NOT verified, and why

The believed answers (`UserContentEdit` carries `id` / `editedAt` / `editor` / `diff` and no prior
body; `diff` is viewer-restricted and null for most tokens; its format is undocumented) are
**unchanged and still unverified**. This record adds no evidence either way. This container has no
`gh` and no token, and `WebFetch`/`WebSearch` are permission-gated with no interactive approver, so
even the public schema reference was out of reach. Following `research/329...md:377-384`, which
handled the same constraint by naming the assumption and its fallback rather than guessing: item 1
is pure introspection and needs no corrupted issue.

```sh
# item 1: does UserContentEdit expose ANY field carrying a prior body?
gh api graphql -f query='{__type(name:"UserContentEdit"){fields(includeDeprecated:true){
  name description type{kind name ofType{kind name}}}}}'

# item 2: is `diff` populated for the identity the workflow actually runs as?
gh api graphql -f query='query($o:String!,$n:String!,$i:Int!){repository(owner:$o,name:$n){
  issue(number:$i){userContentEdits(first:10){nodes{id editedAt diff editor{login}}}}}}' \
  -f o=jeswr -f n=agent-account-registry -F i=<an edited account issue>
```

Run item 2 **as the App the workflow authenticates as**, not as a maintainer PAT — `diff` is
reportedly viewer-restricted, so a maintainer seeing it says nothing about the workflow's identity.

### 3.1 What each answer changes — decided in advance, so the result is not re-litigated

| result | effect on §7 (naming half) | effect on the restore |
|---|---|---|
| item 1 negative (no body field) | none — naming needs only `editedAt`/`editor` | unchanged: still refused, on §4 |
| item 1 **positive** (a body field exists) | none | §4.2 dissolves; §4.1/4.3/4.4 stand → **still refused** |
| item 2 negative (`diff` null for the App) | none | reinforces the refusal |
| item 2 positive (`diff` populated + stable) | none | §4.2 weakens; §4.1/4.3/4.4 stand → **still refused** |

No cell flips the decision. That is §5's point, and it is why this record does not wait on §3.

## 4. Item 3 is dispositive on its own

An automatic restore is a **write**, issued on a path that has already detected corruption, to the
record that binds an account to a credential. Four properties, none of which depend on §3.

**4.1 The repair carries exactly the risk that caused the loss.** There is still no conditional
write. A restore is a *second* unconditional `gh issue edit --body` against a record we have just
**proven** is concurrently edited — the detection condition is precisely "a foreign writer wrote
inside our seconds-wide window". The prior probability that the restore write itself lands inside a
foreign window is therefore *higher*, not lower, than for the write that caused the loss.

**4.2 It is a merge, and the confirm can only count edits, never certify content.** Writing the
reconstructed revision back plainly would drop our own `limits:` line, so the restore is really
"re-run the merge against a reconstructed base". The existing guard is sound on the normal path
because the base came from a first-party read (`_issue_view`) and the confirm proves *ours was the
only edit in the window* (`:703-706`). It proves nothing about **content fidelity** — and under a
restore, fidelity is the entire load-bearing assumption, sourced from the trail §3 could not
verify. The one thing the guard cannot check is the one thing the restore depends on.

**4.3 The write guard is structural, so a wrong restore fails SILENTLY.** *(Verified against
`master` for this record, not inherited.)* `_persist_one` validates every replacement body through
`account_record_schema_errors` before writing (`scripts/account-usage.py:693`). That function
(`scripts/select-and-claim.py:1313` → `_account_schema_errors`, `:1266-1310`) checks only:
a non-empty handle; `provider ∈ KNOWN_ACCOUNT_PROVIDERS`; `credential_format ∈
KNOWN_CREDENTIAL_FORMATS`; a non-empty `secret_ref` matching `ACCOUNT_SECRET_REF_RE`, which is
`re.compile(r"[A-Z][A-Z0-9_]*")` (`:1257`) — a **name-shape** test, never a check against the live
secrets subset; a non-empty model list; and a `harness` consistent with the provider. A **stale but
well-formed** `secret_ref` or `credential_format` from an older revision passes with **zero
violations**.

That is not hypothetical: `_persist_one`'s own docstring names the clobber class as "a provider /
credential-format / secret-reference / notes edit" (`:669`). Those are credential rotations. So the
failure mode of a restore that writes the wrong revision is not a loud malformed record — it is an
account silently rebound to a **superseded** secret, an unattended automated reversal of a human
credential rotation, with every gate green. Under §4.1 this needs no reconstruction error at all: a
*correct* restore whose write clobbers a third, newer rotation reverts it just as effectively.

**4.4 There is no fixed point.** If the restore write is itself clobbered, the same detector fires
on it. A bounded retry lands back where we already are — refusal plus a surfaced warning — having
issued N extra unreviewed writes to a record known to be contended. An unbounded retry is a write
loop against a live human editor. Neither terminates anywhere better than the refusal.

## 5. What the write actually protects — measured, because it bounds what any cure may cost

`research/389-reviewed-sha-binding-store.md:22-30` sets the house rule for this class: state the
residual damage at its real size first, because a cure that trades a small visible loss for a large
invisible one is a bad trade. #320 and the prior attempt both skipped this measurement. Taken:

**The sole consumer of the persisted `limits:` line is the dashboard, and only as a fallback.**

- `scripts/dashboard-gen.py:390-408` (`_front_matter`) parses `limits:` into a dict; `:440`
  (`_catalog`) attaches it to each account.
- `:676-678` is the only read: `limit = entry.get(f"{prefix}_limit")` — the **live probe** value —
  and the persisted catalog value is consulted *only when the live probe reported none*.
- It feeds `window["limit_remaining"]` / `limits_known`, a dashboard capacity **aggregate**.
- No allocator, dispatcher, or gate reads it. `grep` over `select-and-claim.py`,
  `dispatch-claim.py`, `dispatch-plan.py` finds no consumer, matching `persist_limits`' own
  docstring ("`_parse_account` ignores unknown keys, so the extra line is inert for the allocator",
  `:723-724`). `ratelimit-alert.py`'s `*_limit` matches are GitHub's `/rate_limit` endpoint,
  unrelated.

So the asymmetry, stated plainly:

| | |
|---|---|
| **what the lane writes to** | the account record — the account→credential binding, the highest-trust body in the catalog |
| **what the write buys** | a fallback input to one dashboard statistic, used only when the live probe was silent |
| **damage when a clobber happens** | one foreign catalog edit lost — **detected**, loudly warned, operator re-applies. No gate bypassed. Bounded and visible. |
| **damage a wrong restore can do (§4.3)** | an account silently rebound to a superseded credential. Unbounded and invisible. |

An automated restore spends an *invisible unbounded* risk to protect a *visible bounded* loss, on
behalf of a dashboard fallback. That is the trade 389 §1 says not to make, and it is the whole
decision.

## 6. The option neither #320 nor the prior attempt considered: dissolve the window

Both halves of #320 assume the `limits:` line must live in the issue body. It need not. The
constraint driving every hazard above is that machine-written state shares a mutable, human-edited
field with high-trust configuration and there is no CAS. **This repo has already ruled on that
exact class**: `research/389-reviewed-sha-binding-store.md` recommends moving the reviewed-sha
binding off the mutable PR body onto a per-record store on the `ledger` data-plane branch, and
commit `eff35a82d` ("reviewed-sha bind: migrate off the mutable PR body onto a CAS/immutable
store") landed it. A git ref update *is* a compare-and-swap, which is the primitive the issue API
lacks.

Applying that precedent here is unusually cheap **because of §5**: one consumer, fallback-only, no
gate. `persist_limits` would write a data-plane record instead of `gh issue edit --body`;
`dashboard-gen` would read it there. `_persist_one`, `_issue_view`, `_ISSUE_READ_QUERY`,
`PERSIST_ATTEMPTS` and the entire count-shape guard become unnecessary, and #198, #320 and #1051
all cease to exist rather than being answered.

**Stated honestly, this is a recommendation to open the question, not a costed migration.** What is
established here is that the option exists, that the repo has an adopted precedent and a live
implementation to copy, and that §5's consumer count makes it far cheaper than the analogous 389
migration (5 writers, 3 scripts, 2 workflows). What is **not** established: the data-plane write
path's own contention and failure modes under the account-usage workflow's identity; whether the
dashboard should fail-closed or degrade when the record is absent; and whether the capacity
fallback justifies any persistence at all — deleting the lane outright is a real fourth option, and
§5 does not obviously rule it out. Those belong in a sibling design record (filed as follow-up),
not in this one.

## 7. Decision

**WONTFIX the automated restore**, on §4, independently of §3. The refusal shipped in
`_persist_one` stays exactly as it is.

**Do build #320's naming half.** Reading `userContentEdits` `editedAt` / `editor` best-effort on
the already-decided failure path, and naming the window's revisions in `WRITE_FAILURE_WARNING`,
converts "check the edit history" into "this revision, by this editor, at this time". It is a read,
it happens after the refusal, it needs only ordinary fields and not the restricted `diff`, and it
is precisely the shape §2.2 shows 329 chose. Per §2.1 it is not in `master`.

**Open the store question (§6) before investing further in the guard.** If the `limits:` line moves
off the body, the naming half becomes dead code too — so if §6 is going to be taken up soon, build
the naming half only if the operator needs it in the interim.

## 8. Where the negative belongs in code — and why this record does not write it

#1051 asks for the negative to be recorded in `_edit_trail`'s header comment. Per §2.1 that site
does not exist. The correct site is the refusal branch itself — `scripts/account-usage.py:711-713`,
the `return False` after the count-shape checks — because that is the line a future author edits
when they reach for auto-restore. The comment should carry: WONTFIX per this record; the reason is
§4 (a property of the *write*, so it holds whatever the trail exposes); and that §3's two questions
remain open but are not decision-relevant (§3.1).

This record does **not** make that edit: the authoring role here is doc-only and must not touch
`scripts/`. It is filed as a follow-up for an implementer, deliberately as a comment-only change.

## 9. What this record does not do

- It ships **no behaviour change** and weakens no guard: the count-shape refusal, the schema write
  guard, and `WRITE_FAILURE_WARNING`'s loudness are untouched.
- It does **not** answer #1051 items 1-2. §3 has the commands, §3.1 has the pre-committed
  consequences of each answer.
- **Unverified and load-bearing on the operator:** `WRITE_FAILURE_WARNING` tells the operator the
  prior revision "is recoverable from the issue's edit history". If item 1 is negative, GraphQL
  cannot reconstruct it — the promise then rests entirely on GitHub's *web UI* edit-history view
  being a different surface with different exposure. That is believed, not checked here, and it is
  shipped operator-facing text. Filed as a follow-up; if it is false, the warning misleads on the
  exact path where the operator needs it.
- It does not cost the §6 migration, and it takes no position on which of (move the store) or
  (delete the lane) is right — only that the question outranks refining the guard.
