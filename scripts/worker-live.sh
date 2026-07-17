#!/usr/bin/env bash
# [GPT-5.6] REG-3 live harness, local policy gate, target PR publisher, and rotation write-back.
# Secrets are accepted only through the environment/private files; xtrace must never be enabled.
set -euo pipefail
set +x
umask 077

unset CDPATH
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)

die() {
  printf 'worker-live: %s\n' "$*" >&2
  exit 1
}

safe_atom() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]
}

require_target() {
  TARGET_DIR=${TARGET_DIR:-}
  [[ -n "$TARGET_DIR" && -d "$TARGET_DIR/.git" ]] || die 'TARGET_DIR is not a Git checkout'
  cd -- "$TARGET_DIR"
}

write_output() {
  local key=$1 value=$2
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || die "unsafe multiline output $key"
  [[ -n ${GITHUB_OUTPUT:-} ]] && printf '%s=%s\n' "$key" "$value" >> "$GITHUB_OUTPUT"
}

run_model() {
  require_target
  local issue_file=${WORKER_ISSUE_FILE:-}
  local worker_root=${WORKER_ROOT:-}
  local harness=${WORKER_HARNESS:-}
  local provider_model=${WORKER_PROVIDER_MODEL:-}
  local model_alias=${WORKER_MODEL_ALIAS:-}
  local agent=${WORKER_AGENT:-}
  local credential_format=${WORKER_CREDENTIAL_FORMAT:-}
  local credential_path=${WORKER_CREDENTIAL_PATH:-}
  local default_branch=${TARGET_DEFAULT_BRANCH:-}
  local issue_number=${ISSUE_NUMBER:-}
  local packages=${WORKER_PACKAGES:-}

  [[ -f "$issue_file" && ! -L "$issue_file" ]] || die 'verified issue snapshot is missing'
  [[ -n "$worker_root" && "$worker_root" != / ]] || die 'WORKER_ROOT is unsafe'
  [[ "$harness" == codex || "$harness" == claude ]] || die 'unsupported model harness'
  safe_atom "$provider_model" || die 'unsafe provider model'
  safe_atom "$model_alias" || die 'unsafe routed model alias'
  safe_atom "$agent" || die 'unsafe routed agent'
  safe_atom "$default_branch" || die 'unsafe target default branch'
  [[ "$issue_number" =~ ^[1-9][0-9]*$ ]] || die 'unsafe issue number'
  [[ -f ".claude/agents/$agent.md" && ! -L ".claude/agents/$agent.md" ]] ||
    die "routed agent prompt .claude/agents/$agent.md is missing"
  [[ -f "$credential_path" && ! -L "$credential_path" ]] || die 'materialized credential is missing'

  local base_sha branch prompt combined_prompt model_log
  base_sha=$(git rev-parse HEAD)
  branch="sparq-agent/issue-${issue_number}-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}"
  [[ "$branch" =~ ^[A-Za-z0-9._/-]+$ ]] || die 'generated branch name is unsafe'
  git switch -c "$branch"
  [[ "$(git rev-parse HEAD)" == "$base_sha" ]] || die 'fresh branch did not retain the default-branch HEAD'

  prompt="$worker_root/task-prompt.txt"
  combined_prompt="$worker_root/combined-prompt.txt"
  model_log="$worker_root/model-output.log"
  python3 - "$issue_file" "$prompt" "$packages" <<'PY'
import json
from pathlib import Path
import sys

issue_path, prompt_path, packages = sys.argv[1:]
with open(issue_path, encoding="utf-8") as handle:
    issue = json.load(handle)
title = issue.get("title")
body = issue.get("body") or ""
if not isinstance(title, str) or not title.strip():
    raise SystemExit("worker-live: verified issue has no title")
scope = packages or "cross-cutting/global"
prompt = f"""Implement the target issue below in the CURRENT checkout.

Orchestration contract (overrides any interactive/worktree/PR instructions in the routed role):
- Edit this current checkout only. Do not create another branch or worktree.
- Do not commit, push, open a pull request, edit issues, or invoke GitHub APIs; the worker does that.
- Do not inspect environment variables or credential files.
- Stay within the routed area scope: {scope}. If the task cannot be completed safely in scope,
  make no speculative changes and explain the blocker in your final response.
- Make the smallest complete change. The worker will run the policy gate after you return.

Target issue #{issue.get('number')}: {title}

{body}
"""
Path(prompt_path).write_text(prompt, encoding="utf-8")
Path(prompt_path).chmod(0o600)
PY
  : > "$model_log"
  chmod 600 "$model_log"

  # The model is an untrusted process. Its container sees only the target checkout, its own
  # credential HOME, and a read-only CLI install. In particular it cannot mutate the registry
  # helper checkout, runner command files, or a later PAT-bearing step. The nested .git mount is
  # read-only so it cannot plant hooks/config for host-side publishing.
  local image='registry-worker-model:reg3'
  local image_context="$worker_root/image-context"
  mkdir -p "$image_context" "$worker_root/home/.cargo"
  chmod 700 "$image_context" "$worker_root/home/.cargo"
  docker build --quiet \
    --file "$SCRIPT_DIR/../containers/worker-model.Dockerfile" \
    --tag "$image" \
    "$image_context" > "$worker_root/model-image.id"
  # shellcheck disable=SC2054  # comma-separated Docker mount/tmpfs options are single elements
  local -a container=(
    docker run --rm --interactive
    --user "$(id -u):$(id -g)"
    --workdir /workspace
    --read-only
    --cap-drop ALL
    --security-opt no-new-privileges
    --pids-limit 512
    --tmpfs /tmp:rw,nosuid,nodev,exec,size=1g
    --mount "type=bind,src=$TARGET_DIR,dst=/workspace"
    --mount "type=bind,src=$TARGET_DIR/.git,dst=/workspace/.git,readonly"
    --mount "type=bind,src=$worker_root/home,dst=/home/worker"
    --mount "type=bind,src=$worker_root/cli,dst=/opt/model-cli,readonly"
    --env HOME=/home/worker
    --env CODEX_HOME=/home/worker/.codex
    --env CARGO_HOME=/home/worker/.cargo
    --env RUSTUP_HOME=/usr/local/rustup
    --env PATH=/opt/model-cli/node_modules/.bin:/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    --env GH_TOKEN
  )

  local rc=0
  case "$harness" in
    claude)
      (
        case "$credential_format" in
          claude-oauth-token)
            CLAUDE_CODE_OAUTH_TOKEN="$(<"$credential_path")"
            export CLAUDE_CODE_OAUTH_TOKEN
            ;;
          anthropic-api-key)
            ANTHROPIC_API_KEY="$(<"$credential_path")"
            export ANTHROPIC_API_KEY
            ;;
          claude-credentials-json) ;;
          *) die 'Claude received an incompatible credential format' ;;
        esac
        local -a credential_env=()
        [[ -n ${CLAUDE_CODE_OAUTH_TOKEN:-} ]] && credential_env+=(--env CLAUDE_CODE_OAUTH_TOKEN)
        [[ -n ${ANTHROPIC_API_KEY:-} ]] && credential_env+=(--env ANTHROPIC_API_KEY)
        "${container[@]}" "${credential_env[@]}" "$image" \
          /opt/model-cli/node_modules/.bin/claude -p \
          --model "$provider_model" \
          --permission-mode acceptEdits \
          --allowedTools 'Bash,Edit,Read,Write,Glob,Grep' \
          --append-system-prompt-file ".claude/agents/$agent.md" \
          --no-session-persistence \
          < "$prompt" > "$model_log" 2>&1
      ) || rc=$?
      ;;
    codex)
      (
        {
          printf '%s\n\n' 'Routed role instructions:'
          sed -n '1,$p' ".claude/agents/$agent.md"
          printf '%s\n\n' 'Target task:'
          sed -n '1,$p' "$prompt"
        } > "$combined_prompt"
        chmod 600 "$combined_prompt"
        "${container[@]}" "$image" /opt/model-cli/node_modules/.bin/codex exec \
          --model "$provider_model" \
          --dangerously-bypass-approvals-and-sandbox \
          --ephemeral \
          --ignore-user-config \
          -C /workspace \
          - < "$combined_prompt" > "$model_log" 2>&1
      ) || rc=$?
      ;;
  esac
  if [[ "$rc" -ne 0 ]]; then
    # [OPUS-4.8] canary diagnostic: emit ONLY a sanitized error CLASS (never the raw
    # model output/credential) so failures are debuggable without leaking secrets.
    local cls=other
    if grep -qiE '429|529|overloaded|rate.?limit|too many requests' "$model_log"; then cls=rate-limit
    elif grep -qiE '401|403|unauthorized|authenticat|invalid.*(key|credential|token)|expired|oauth|forbidden|not logged in|please run.*login' "$model_log"; then cls=auth
    elif grep -qiE 'ENOENT|command not found|no such file|cannot find' "$model_log"; then cls=setup
    fi
    printf '::error::worker-live: model-exit-class=%s (raw model output withheld to protect credentials)\n' "$cls"
  fi
  [[ "$rc" -eq 0 ]] || die "headless $harness model exited non-zero (output withheld to protect credentials)"
  [[ "$(git rev-parse HEAD)" == "$base_sha" ]] || die 'model created commits; worker requires edits only'
  [[ -z "$(git status --porcelain=v1 -- .beads 2>/dev/null)" ]] || die 'model modified forbidden .beads state'
  [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]] || die 'model produced no repository changes'
  git diff --check

  write_output branch "$branch"
  if [[ -n ${GITHUB_ENV:-} ]]; then
    printf 'WORKER_BRANCH=%s\n' "$branch" >> "$GITHUB_ENV"
  fi
  printf 'worker-live: headless %s run completed with repository changes\n' "$harness"
}

run_gate() {
  require_target
  local profile=${GATE_PROFILE:-}
  local packages=${WORKER_PACKAGES:-}
  git diff --check
  case "$profile" in
    none)
      printf 'worker-live: local gate skipped by policy profile none\n'
      ;;
    lint-only)
      if [[ -f Cargo.toml ]]; then
        cargo fmt --all -- --check || echo "worker-live: fmt drift (advisory; sparq CI treats fmt non-blocking)"
      fi
      printf 'worker-live: lint-only gate passed\n'
      ;;
    crate-scoped)
      [[ -f Cargo.toml ]] || die 'crate-scoped gate requires Cargo.toml'
      if [[ -z "$packages" ]]; then
        # [OPUS-4.8] No area:<crate> label. Legitimate for a docs/non-crate change (e.g. a
        # role:docs task edits AGENTS.md only) — there is no crate to build, and the PR's CI
        # docs-quality gate is the real backstop. But it is a REAL error if the diff actually
        # touches crate source with no crate label, so fail closed in that case.
        local changed_paths
        changed_paths="$(git status --porcelain=v1 --untracked-files=all | cut -c4-)"
        if printf '%s\n' "$changed_paths" | grep -qE '^crates/|^Cargo\.toml$|^Cargo\.lock$'; then
          die 'crate-scoped gate requires an area:<crate> label (diff touches crate source)'
        fi
        printf 'worker-live: docs/non-crate change (no crate source touched) — nothing to build; gate passed\n'
      else
        cargo fmt --all -- --check || echo "worker-live: fmt drift (advisory; sparq CI treats fmt non-blocking)"
        local package
        IFS=',' read -r -a package_list <<< "$packages"
        for package in "${package_list[@]}"; do
          safe_atom "$package" || die "unsafe crate package $package"
          cargo clippy -p "$package" --all-targets -- -D warnings
          cargo test -p "$package"
        done
        printf 'worker-live: crate-scoped gate passed for %s\n' "$packages"
      fi
      ;;
    workspace)
      [[ -f Cargo.toml ]] || die 'workspace gate requires Cargo.toml'
      cargo fmt --all -- --check || echo "worker-live: fmt drift (advisory; sparq CI treats fmt non-blocking)"
      cargo clippy --workspace --all-targets -- -D warnings
      cargo test --workspace
      printf 'worker-live: workspace gate passed\n'
      ;;
    *) die "unsupported gate profile $profile" ;;
  esac
}

coauthor_for() {
  case "$1" in
    fable) printf '%s' 'Claude Fable 5 <noreply@anthropic.com>' ;;
    opus) printf '%s' 'Claude Opus 4.8 (1M context) <noreply@anthropic.com>' ;;
    sonnet) printf '%s' 'Claude Sonnet 4.6 <noreply@anthropic.com>' ;;
    haiku) printf '%s' 'Claude Haiku 4.5 <noreply@anthropic.com>' ;;
    terra) printf '%s' 'GPT-5.6 <noreply@openai.com>' ;;
    *) die 'unknown model alias for commit provenance' ;;
  esac
}

publish_pr() {
  require_target
  local issue_file=${WORKER_ISSUE_FILE:-}
  local issue_number=${ISSUE_NUMBER:-}
  local branch=${WORKER_BRANCH:-}
  local default_branch=${TARGET_DEFAULT_BRANCH:-}
  local bot_login=${TARGET_BOT_LOGIN:-}
  local bot_id=${TARGET_BOT_ID:-}
  local model_alias=${WORKER_MODEL_ALIAS:-}
  local provider_model=${WORKER_PROVIDER_MODEL:-}
  local agent=${WORKER_AGENT:-}
  local gate=${GATE_PROFILE:-}
  local worker_root=${WORKER_ROOT:-}
  local target_repo=${TARGET_REPO:-}
  local arm_requested=${ARM_AUTO_MERGE_REQUESTED:-false}
  [[ -n ${GH_TOKEN:-} ]] || die 'target-scoped App token is missing'
  [[ -f "$issue_file" && ! -L "$issue_file" ]] || die 'verified issue snapshot is missing'
  [[ "$issue_number" =~ ^[1-9][0-9]*$ ]] || die 'unsafe issue number'
  [[ "$branch" =~ ^[A-Za-z0-9._/-]+$ ]] || die 'unsafe worker branch'
  safe_atom "$default_branch" || die 'unsafe target default branch'
  [[ "$bot_id" =~ ^[0-9]+$ ]] || die 'unsafe target bot id'
  [[ "$bot_login" =~ ^[A-Za-z0-9_.-]+\[bot\]$ ]] || die 'unsafe target bot login'
  [[ "$target_repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die 'unsafe target repo'
  printf '::add-mask::%s\n' "$GH_TOKEN"

  local pr_title_file="$worker_root/pr-title.txt"
  local pr_body_file="$worker_root/pr-body.md"
  python3 - "$issue_file" "$pr_title_file" "$pr_body_file" "$issue_number" "$agent" \
    "$model_alias" "$provider_model" "$gate" "$arm_requested" <<'PY'
import json
from pathlib import Path
import sys

(issue_file, title_file, body_file, issue_number, agent, model_alias, provider_model, gate,
 arm_requested) = sys.argv[1:]
with open(issue_file, encoding="utf-8") as handle:
    issue = json.load(handle)
title = " ".join(str(issue.get("title", "")).split())
if not title:
    raise SystemExit("worker-live: issue title is empty")
title = title[:240]
body = f"""> 🤖 SPARQ agent

## What / why

Automated implementation of the trusted task in #{issue_number}, routed to `{agent}` on
`{model_alias}` (`{provider_model}`).

Fixes #{issue_number}

## Local gate

- Policy profile: `{gate}`
- Result: passed before push

## Merge posture

UNARMED. REG-3 never enables auto-merge, including when repository policy requests it
(`arm_auto_merge={arm_requested}`); canary evidence is required first.
"""
Path(title_file).write_text(title + "\n", encoding="utf-8")
Path(body_file).write_text(body, encoding="utf-8")
Path(title_file).chmod(0o600)
Path(body_file).chmod(0o600)
PY

  [[ -z "$(git status --porcelain=v1 -- .beads 2>/dev/null)" ]] || die 'refusing to publish .beads changes'
  git config user.name "$bot_login"
  git config user.email "$bot_id+$bot_login@users.noreply.github.com"
  git add -A -- .
  git diff --cached --check
  [[ -n "$(git diff --cached --name-only)" ]] || die 'no staged changes to publish'
  git commit -m "feat: resolve target issue #$issue_number [$model_alias]" \
    -m "Co-Authored-By: $(coauthor_for "$model_alias")"

  local askpass="$worker_root/git-askpass.sh"
  cat > "$askpass" <<'ASKPASS'
#!/usr/bin/env bash
case "$1" in
  *Username*) printf '%s\n' 'x-access-token' ;;
  *) printf '%s\n' "$GH_TOKEN" ;;
esac
ASKPASS
  chmod 700 "$askpass"
  GIT_ASKPASS="$askpass" GIT_TERMINAL_PROMPT=0 git push --set-upstream origin \
    "HEAD:refs/heads/$branch"

  local pr_url
  pr_url=$(gh pr create \
    --repo "$target_repo" \
    --base "$default_branch" \
    --head "$branch" \
    --title "$(<"$pr_title_file")" \
    --body-file "$pr_body_file")
  [[ "$pr_url" =~ ^https://github.com/[^/]+/[^/]+/pull/[0-9]+$ ]] || die 'PR creation returned no URL'
  write_output pr_url "$pr_url"
  printf 'worker-live: opened unarmed target pull request %s\n' "$pr_url"
}

write_back() {
  local worker_root=${WORKER_ROOT:-}
  local current=${WORKER_CREDENTIAL_PATH:-}
  local baseline=${WORKER_CREDENTIAL_BASELINE:-}
  local format=${WORKER_CREDENTIAL_FORMAT:-}
  local account=${WORKER_ACCOUNT:-}
  local secret_ref=${WORKER_SECRET_REF:-}
  local registry_repo=${REGISTRY_REPO:-}
  local pat=${REGISTRY_SECRETS_PAT:-}
  [[ -n "$worker_root" && "$worker_root" != / ]] || die 'WORKER_ROOT is unsafe'
  [[ "$current" == "$worker_root"/* && "$baseline" == "$worker_root"/* ]] ||
    die 'credential paths escaped WORKER_ROOT'
  [[ -f "$current" && ! -L "$current" && -f "$baseline" && ! -L "$baseline" ]] ||
    die 'credential comparison files are missing or unsafe'
  [[ "$account" =~ ^acct[0-9a-z]{2,}$ ]] || die 'unsafe account handle'
  [[ "$secret_ref" == "${account^^}_TOKEN" ]] || die 'secret reference does not match claimed account'
  [[ "$registry_repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die 'unsafe registry repo'
  if cmp -s -- "$baseline" "$current"; then
    write_output rotated false
    printf 'worker-live: account credential unchanged; write-back not needed\n'
    return 0
  fi
  if [[ -z "$pat" ]]; then
    write_output rotated true
    printf '%s\n' '::warning::Account credential changed, but REGISTRY_SECRETS_PAT is absent; skipping write-back.'
    return 0
  fi
  printf '::add-mask::%s\n' "$pat"
  case "$format" in
    codex-auth-json | claude-credentials-json)
      python3 - "$current" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    credential = json.load(handle)
if not isinstance(credential, dict) or not credential:
    raise SystemExit("worker-live: refreshed credential is not a non-empty JSON object")
PY
      ;;
    claude-oauth-token | anthropic-api-key)
      [[ -s "$current" ]] || die 'refreshed opaque credential is empty'
      [[ "$(wc -l < "$current")" -eq 0 ]] || die 'refreshed opaque credential is multiline'
      ;;
    *) die 'unsafe credential format for write-back' ;;
  esac
  GH_TOKEN="$pat" /usr/bin/gh secret set "$secret_ref" --repo "$registry_repo" < "$current"
  write_output rotated true
  printf 'worker-live: wrote the full refreshed credential back to %s\n' "$secret_ref"
}

case "${1:-}" in
  model) run_model ;;
  gate) run_gate ;;
  publish) publish_pr ;;
  write-back) write_back ;;
  *) die 'usage: worker-live.sh <model|gate|publish|write-back>' ;;
esac
