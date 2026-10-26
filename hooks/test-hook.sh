#!/usr/bin/env bash
# Table test for block-secret-bypass.sh: "deny|allow<TAB>command" per line.
set -uo pipefail
hook="$(dirname "$0")/block-secret-bypass.sh"
rules="$(mktemp)"
trap 'rm -f "$rules"' EXIT
printf '# sample extra rules\n{cmd}bin/vault-helper[[:space:]]+(show|export)\tvault-helper prints the whole vault\nop[[:space:]]+read[^;&|]*master key\tthat reads the master key\n' >"$rules"
export AGENT_SECRET_BROKER_HOOK_RULES="$rules"
fails=0
while IFS=$'\t' read -r want cmd; do
  [[ -z "$want" || "$want" == \#* ]] && continue
  got="$(jq -n --arg c "$cmd" '{tool_input:{command:$c}}' | "$hook" | jq -r '.hookSpecificOutput.permissionDecision // "allow"')"
  got="${got:-allow}"
  if [[ "$got" != "$want" ]]; then
    echo "FAIL want=$want got=$got: $cmd"
    fails=$((fails + 1))
  fi
done <<'CASES'
deny	/opt/homebrew/bin/sops -d secrets/secrets.yaml
deny	FOO=1 sops decrypt x.yaml
deny	x=$(sops -d a.yaml)
deny	sops --input-type yaml -d a.yaml
deny	echo $SOPS_AGE_KEY
deny	cat ~/.config/sops/age/keys.txt
deny	sudo cat /Library/AgentSecretBroker/key/age.key
deny	bin/vault-helper show
deny	cd repo && ./bin/vault-helper export -- foo
deny	true & bin/vault-helper show
deny	op read "op://Private/master key/private key"
allow	echo "never bin/vault-helper show" >> MEMORY.md
allow	git commit -m "sops -d is blocked now"
allow	agent-secret-broker exec CF=cloudflare.x -- wrangler deploy
allow	/opt/homebrew/bin/sops updatekeys -y secrets/secrets.yaml
allow	grep -n sops README.md
allow	gh pr create --body "humans use `sops -d`"
CASES
[[ $fails -eq 0 ]] && echo "hook OK" || exit 1
