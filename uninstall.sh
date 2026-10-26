#!/usr/bin/env bash
# Remove the daemon. Keeps the access log unless --purge is given.
set -euo pipefail

ROOT=/Library/AgentSecretBroker
SVC=_agentsecretbroker
LABEL=com.agent-secret-broker.daemon

sudo launchctl bootout "system/$LABEL" 2>/dev/null || true
sudo rm -f "/Library/LaunchDaemons/$LABEL.plist"
rm -f "$HOME/bin/agent-secret-broker"
if [[ "${1:-}" == "--purge" ]]; then
  sudo rm -rf "$ROOT"
  sudo dscl . -delete "/Users/$SVC" 2>/dev/null || true
  sudo dscl . -delete "/Groups/$SVC" 2>/dev/null || true
  echo "removed everything, including the log and the daemon's key"
else
  sudo rm -rf "$ROOT/key" "$ROOT/state" "$ROOT/run" "$ROOT/bin"
  echo "removed the daemon and its key; the log is still at $ROOT/log/access.jsonl"
fi
echo "remove the daemon's recipient from any .sops.yaml and run sops updatekeys"
