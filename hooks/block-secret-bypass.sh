#!/usr/bin/env bash
# Claude Code PreToolUse hook (Bash): steer agents off paths that decrypt a whole
# vault or touch a master key, so every secret goes through agent-secret-broker.
#
# Extra rules: $AGENT_SECRET_BROKER_HOOK_RULES, else ~/.config/agent-secret-broker/hook-rules.
# One rule per line, "REGEX<TAB>REASON"; {cmd} in REGEX matches the start of a
# command (see at_cmd). Blank lines and lines starting with # are skipped.
set -euo pipefail

cmd="$(jq -r '.tool_input.command // empty')"
[[ -z "$cmd" ]] && exit 0

# Only where the tool is the command being run, so mentions inside strings pass.
# Backtick substitution is deliberately not a command position: markdown in
# commit messages and PR bodies uses backticks constantly.
at_cmd='(^|[;&|(]|\$\()[[:space:]]*([A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*[[:space:]]+)*(sudo[[:space:]]+|exec[[:space:]]+|command[[:space:]]+)*([^[:space:];&|]*/)?'
reason=""
if grep -qE "${at_cmd}sops[[:space:]]+([^;&|]*[[:space:]])?(-d|--decrypt|decrypt|edit|exec-env|exec-file)([[:space:]]|$)" <<<"$cmd"; then
  reason="sops decrypt prints every secret in the vault"
elif grep -qE '\$\{?SOPS_AGE_KEY|/Library/AgentSecretBroker/(key|state)|sops/age/keys\.txt' <<<"$cmd"; then
  reason="that touches a master decryption key"
fi

rules="${AGENT_SECRET_BROKER_HOOK_RULES:-$HOME/.config/agent-secret-broker/hook-rules}"
if [[ -z "$reason" && -f "$rules" ]]; then
  while IFS=$'\t' read -r re why; do
    [[ -z "$re" || "$re" == \#* ]] && continue
    # Not ${re//\{cmd\}/$at_cmd}: bash 5.2 expands & in the replacement, and
    # quoting it to stop that breaks bash 3.2, which macOS ships.
    pat="" rest="$re"
    while [[ "$rest" == *"{cmd}"* ]]; do
      pat+="${rest%%\{cmd\}*}$at_cmd"
      rest="${rest#*\{cmd\}}"
    done
    if grep -qE "$pat$rest" <<<"$cmd"; then
      reason="${why:-matched a rule in $rules}"
      break
    fi
  done <"$rules"
fi
[[ -z "$reason" ]] && exit 0

jq -n --arg r "Blocked: $reason. Use agent-secret-broker instead: \`agent-secret-broker keys\` to find the key name, then \`agent-secret-broker exec VAR=<key> --reason \"<why>\" -- <cmd>\` (or \`agent-secret-broker get <key> --reason ...\` if you must see it, which marks it for rotation)." \
  '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: $r}}'
