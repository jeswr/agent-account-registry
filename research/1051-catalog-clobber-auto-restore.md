# #1051: auto-restoring a clobbered account-record body (the write half of #320)

> 🤖 **SPARQ agent** — design record, 2026-08-02. Maintainer-review document.
> **This record changes no behaviour.** #320 asked for automatic restore of the account-record
> revision `_persist_one` replaces inside its write window, and #1051 gated that on verifying what
> GitHub's `UserContentEdit` trail exposes. **The verification asked for in #1051 items 1-2 was NOT
> performed** — this container has no `gh`, no token, and no permitted web tool (§3 gives the one
> command that settles it). It is filed anyway because **item 3 is dispositive on its own**: the
> objection to the restore is a property of the **write**, not of the read, so it stands whatever
> the trail turns out to expose.
>
> **Recommendation, in one line: WONTFIX the automated restore.** The fail-closed refusal already
> shipped in `_persist_one` is the terminal answer, and recovery stays an operator step — the same
> shape `research/329-pre-migration-writer-recovery.md` reached for this class of problem. The half
> that is still worth building is #320's *naming* half (§7), which is a read on a failure path and
> carries none of this.

## 1. The question

`persist_limits` writes one `limits:` line into each account issue's front matter.
`gh issue edit --body` replaces the **whole** body and GitHub's issue API has no conditional
(If-Match / CAS) write (`scripts/account-usage.py:486-489`), so a foreign edit landing inside the
read→write window is replaced by our write. `_persist_one` detects that with a version stamp — the
body-edit count from `userContentEdits.totalCount` (`scripts/account-usage.py:449-452`) — and, when
the count proves a foreign edit landed **inside** the window, refuses: it returns `False` rather
than retrying, and the caller raises `WRITE_FAILURE_WARNING` (`scripts/account-usage.py:409-412`),
whose text points the operator at the issue's edit history.

#320 asked to close the loop automatically: read the replaced revision back out of the edit trail
and re-apply it. #1051 asks whether that is (1) possible, (2) reliable, and (3) wanted.

## 2. Premise correction — what is actually in the tree

#1051 describes #320 as having shipped "a best-effort, failure-path-only `_edit_trail` read
(scripts/account-usage.py)". **There is no `_edit_trail` in `master`.** `git log -S _edit_trail --
scripts/account-usage.py` returns nothing on any ref in this checkout, and the only edit-trail
surface in the file is the `totalCount` version stamp plus the prose in `WRITE_FAILURE_WARNING`
and the `_persist_one` docstring. So either #320's PR is unmerged or the naming half was dropped
from it. This matters twice: #1051's fallback instruction ("record the negative in `_edit_trail`'s
header comment") has no target site — §6 records it at the refusal branch instead — and §7's
"still worth building" is not a refinement of shipped code but the whole of it. That verification
needs GitHub and is filed as a follow-up rather than guessed at here.

## 3. Items 1 and 2 — not verified here

The believed answers (`UserContentEdit` carries `id` / `editedAt` / `editor` / `diff` and no prior
body; `diff` is restricted and null for most viewers; its format is undocumented) are **unchanged
and still unverified**. This record does not add evidence either way, and nothing below depends on
them. Two commands settle both, for anyone holding a token — item 1 is pure introspection and does
not even need a corrupted issue:

```sh
# item 1: does UserContentEdit expose ANY field carrying a prior body?
gh api graphql -f query='{__type(name:"UserContentEdit"){fields(includeDeprecated:true){
  name description type{kind name ofType{kind name}}}}}'

# item 2: is `diff` populated for the token the workflow actually runs as?
gh api graphql -f query='query($o:String!,$n:String!,$i:Int!){repository(owner:$o,name:$n){
  issue(number:$i){userContentEdits(first:10){nodes{id editedAt diff editor{login}}}}}}' \
  -f o=jeswr -f n=agent-account-registry -F i=<an edited account issue>
```

Run item 2 **as the App the workflow authenticates as**, not as a maintainer PAT: `diff` is
reportedly viewer-restricted, so a maintainer seeing it says nothing about the workflow's identity.

## 4. Item 3 is dispositive on its own

An automatic restore is a **write**, issued on a path that has already detected corruption, to the
record that binds an account to a credential. Four properties, none of which depend on §3:

### 4.1 The repair carries exactly the risk that caused the loss

There is no conditional write. A restore is therefore a *second* unconditional
`gh issue edit --body` against a record we have just **proven** is being concurrently edited — the
detection condition is precisely "a foreign writer wrote inside our seconds-wide window". The
foreign editor demonstrably had the record open moments ago, so the prior probability that the
restore write itself lands inside a foreign window is *higher*, not lower, than for the write that
lost the revision. The mechanism repairs a clobber by taking the same clobber risk against a
writer known to be active.

### 4.2 It is a merge, and the confirm can only count edits, not certify content

Writing the reconstructed revision back plainly would drop our own `limits:` line, so the restore
is really "re-run the merge against a reconstructed base". The existing guard is sound for the
normal path because the base body came from a first-party read (`_issue_view`) and the confirm
proves *ours was the only edit in the window*. It proves nothing about **content fidelity** — and
under a restore, content fidelity is the entire load-bearing assumption, sourced from the trail
§3 could not verify. The one thing the guard cannot check is the one thing the restore depends on.

### 4.3 The write guard checks structure, so the failure mode is silent

`_persist_one` validates every replacement body through `account_record_schema_errors` before the
write (`scripts/account-usage.py:512`). That guard is **structural**: it requires a handle, a known
`provider`, a known `credential_format`, a `secret_ref` matching `[A-Z][A-Z0-9_]*`, a model list,
and a `harness` consistent with the provider (`scripts/select-and-claim.py:1266-1310`). A **stale
but well-formed** `secret_ref` or `credential_format` — a value that was correct at an earlier
revision — passes it with zero violations.

That is not hypothetical: `_persist_one`'s own docstring names the clobber class as "a provider /
credential-format / secret-reference / notes edit". Those are credential rotations. So the failure
mode of a restore that writes the wrong revision is not a loud malformed record; it is an account
silently rebound to a **superseded** secret — an unattended automated reversal of a human
credential rotation, on an already-corrupted record, with every gate green. Under §4.1 this needs
no reconstruction error at all: a correct restore whose write clobbers a *third*, newer rotation
reverts it just as effectively.

### 4.4 There is no fixed point

If the restore write is itself clobbered, the same detector fires on it. A bounded retry lands
back where we already are — refusal plus a surfaced warning — having issued N extra unreviewed
writes to a record known to be contended. An unbounded retry is a write loop against a live human
editor. Neither terminates anywhere better than the refusal does.

## 5. Why a positive answer to item 1 would not reopen this

If `UserContentEdit` turned out to expose a prior body verbatim, §4.2's fidelity objection would
largely dissolve — and §4.1, §4.3 and §4.4 would stand untouched, because they are properties of
issuing an unguardable write to a credential-binding record on a corruption path. A perfect read
does not make an unconditional write safe. So item 1 changes the *cost* of building the restore,
not the *decision* about wanting it, which is why §6 does not wait on §3.

## 6. Decision

**WONTFIX the automated restore.** The refusal shipped in `_persist_one` is the terminal answer for
this class, exactly as `research/329-pre-migration-writer-recovery.md` §7 concluded for the
pre-migration writer: where the repair is a write that re-enters the unguardable window it is
meant to fix, the correct behaviour for a system with no conditional write is to detect, refuse,
and name — not to attempt an unattended fix.

Recovery stays an **operator** step, which is also the right gate on its own merits: the record
being repaired decides which credential a worker is handed, so a human confirming the intended
revision is proportionate, not friction.

The negative is recorded in code at the refusal branch itself (`scripts/account-usage.py`, the
`return False` after the count-shape checks), because that is the line a future author edits when
they reach for auto-restore. #1051's instruction to record it in `_edit_trail`'s header comment
could not be followed literally — see §2.

## 7. What is still worth building

#320's other half — **naming** the window's revisions in the warning (`editedAt` / `editor` from
`userContentEdits`, read best-effort on the failure path only) — is unaffected by all of the above.
It is a read, it happens after the refusal has already been decided, and it converts "check the
edit history" into "this revision, by this editor, at this time". It needs `editedAt` / `editor`
only, which are ordinary fields, not the restricted `diff`. Per §2 it does not appear to be in
`master`; establishing whether #320 landed it is filed as a follow-up.

## 8. What this record does not do

- It ships **no behaviour change**, and it weakens no guard: the count-shape refusal, the schema
  write guard, and `WRITE_FAILURE_WARNING`'s loudness are all untouched.
- It does **not** answer #1051 items 1-2. §3 has the two commands; the answers are worth recording
  when someone with a token runs them, but §5 is why they do not gate the decision.
- It does not revisit the write window itself. Making the write conditional would dissolve this
  whole class, and GitHub not offering that is the root constraint; nothing here is a claim that
  the current guard is the best achievable, only that automated restore is not the improvement.
