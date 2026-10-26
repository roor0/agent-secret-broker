#!/usr/bin/env bash
# End-to-end run against a throwaway root, key and vault, with the daemon running
# as the current user. Nothing touches /Library/AgentSecretBroker.
set -euo pipefail

SOPS="${SOPS_BIN:-$(command -v sops)}"
here="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
dpid=
trap 'kill $dpid 2>/dev/null || true; rm -rf "$work"' EXIT

(cd "$here" && go build -o "$work/agent-secret-broker" .)
bin="$work/agent-secret-broker"
root="$work/root"
mkdir -p "$root"/{key,state,log,run}
age-keygen -o "$root/key/age.key" 2>/dev/null
age-keygen -y "$root/key/age.key" > "$root/recipient.txt"
printf '{"allowed_uids":[%d],"sops":"%s"}\n' "$(id -u)" "$SOPS" > "$root/config.json"

repo="$work/repo"
mkdir -p "$repo/secrets"
cat > "$repo/secrets/secrets.yaml" <<'YAML'
cloudflare:
  account_id: acct-1234567890
  deployApiToken: tok-SUPERSECRET-abcdef
span: span-token-xyz
YAML
"$SOPS" encrypt -i --age "$(cat "$root/recipient.txt")" "$repo/secrets/secrets.yaml"
echo "secrets/secrets.yaml" > "$repo/.agent-secret-broker"

export AGENT_SECRET_BROKER_ROOT="$root"
"$bin" daemon --root "$root" 2>"$work/daemon.err" &
dpid=$!
for _ in $(seq 50); do [[ -S "$root/run/agent.sock" ]] && break; sleep 0.1; done

cd "$repo"
export CLAUDE_CODE_SESSION_ID=test-session-1 CLAUDE_PID=$$
fail() { echo "FAIL: $*"; cat "$work/daemon.err"; exit 1; }

[[ "$("$bin" keys)" == $'cloudflare.account_id\ncloudflare.deployApiToken\nspan' ]] || fail "keys"

"$bin" get span 2>/dev/null && fail "get without a reason should be refused"
o="$("$bin" get cloudflare --reason "testing a group lookup" 2>&1 || true)"; [[ "$o" == *"is a group"* ]] || fail "group refused: $o"

out="$("$bin" exec CF=cloudflare.deployApiToken -- sh -c 'echo "token is $CF"; echo "err $CF" >&2' 2>&1)"
[[ "$out" == *"***cloudflare.deployApiToken***"* && "$out" != *SUPERSECRET* ]] || fail "exec redaction: $out"

"$bin" exec cloudflare.account_id -- sh -c 'test "$CLOUDFLARE_ACCOUNT_ID" = acct-1234567890' || fail "derived env name"
set +e; "$bin" exec span -- sh -c 'exit 7'; rc=$?; set -e
[[ $rc == 7 ]] || fail "exit code passthrough, got $rc"

[[ "$("$bin" get span 2>/dev/null)" == span-token-xyz ]] || fail "get value"
"$bin" exposed | grep -q "^  span " || fail "span should be exposed"

printf 'span-token-rotated\n' | "$bin" set span 2>/dev/null
grep -q "span-token-rotated" "$repo/secrets/secrets.yaml" && fail "set wrote plaintext"
"$bin" exposed | grep -q "rotated since exposure, cleared: span" || fail "rotation detection"

printf 'new-esphome-key' | "$bin" set esphome.fan.api_key 2>/dev/null
"$bin" keys esphome | grep -qx esphome.fan.api_key || fail "set should create a new key"
"$bin" exec K=esphome.fan.api_key -- sh -c 'test "$K" = new-esphome-key' || fail "new key round-trip"

requests="$(grep -c '"event":"request"' "$root/log/access.jsonl")"
uses="$(grep -c '"event":"use"' "$root/log/access.jsonl")"
[[ "$requests" == 1 ]] || fail "expected one request for the session, got $requests"
[[ "$uses" == 5 ]] || fail "expected 5 deduped uses, got $uses"

export CLAUDE_CODE_SESSION_ID=test-session-2
"$bin" exec span -- true 2>/dev/null && fail "new session must state its own reason"
printf 'no-reason-value' | "$bin" set span 2>/dev/null || fail "set should not need a reason"
"$bin" exec span -- true 2>/dev/null && fail "a reasonless set must not open a request for reads"

"$bin" log
echo "e2e OK"
