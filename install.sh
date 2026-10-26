#!/usr/bin/env bash
# Install (or upgrade) the agent-secret-broker daemon. Run as yourself in a terminal;
# it calls sudo for the privileged steps.
set -euo pipefail

ROOT=/Library/AgentSecretBroker
SVC=_agentsecretbroker
LABEL=com.agent-secret-broker.daemon
PLIST=/Library/LaunchDaemons/$LABEL.plist
SOPS_SRC="${SOPS_BIN:-$(command -v sops || true)}"
AGE_KEYGEN="${AGE_KEYGEN:-$(command -v age-keygen || true)}"
here="$(cd "$(dirname "$0")" && pwd)"

if [[ $EUID -eq 0 ]]; then
  echo "run as yourself, not root: the installer needs your uid for the allowlist" >&2
  exit 2
fi
for t in go "${SOPS_SRC:-sops}" "${AGE_KEYGEN:-age-keygen}"; do
  command -v "$t" >/dev/null || { echo "missing $t (brew install go sops age)" >&2; exit 2; }
done

(cd "$here" && go build -o "$here/agent-secret-broker" .)
me_uid="$(id -u)"
sudo -v

if ! dscl . -read "/Users/$SVC" >/dev/null 2>&1; then
  used="$( (dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID) | awk '{print $2}')"
  sid=""
  for n in $(seq 450 499); do
    grep -qx "$n" <<<"$used" || { sid=$n; break; }
  done
  [[ -n "$sid" ]] || { echo "no free id in 450-499" >&2; exit 1; }
  sudo dscl . -create "/Groups/$SVC" PrimaryGroupID "$sid"
  sudo dscl . -create "/Groups/$SVC" RealName "agent-secret-broker daemon"
  sudo dscl . -create "/Users/$SVC" UniqueID "$sid"
  sudo dscl . -create "/Users/$SVC" PrimaryGroupID "$sid"
  sudo dscl . -create "/Users/$SVC" UserShell /usr/bin/false
  sudo dscl . -create "/Users/$SVC" NFSHomeDirectory /var/empty
  sudo dscl . -create "/Users/$SVC" RealName "agent-secret-broker daemon"
  sudo dscl . -create "/Users/$SVC" IsHidden 1
  sudo dscl . -create "/Users/$SVC" Passwd '*'
  echo "created service account $SVC (uid $sid)"
fi

sudo install -d -o root -g wheel -m 755 "$ROOT" "$ROOT/bin"
sudo install -d -o "$SVC" -g "$SVC" -m 700 "$ROOT/key" "$ROOT/state"
sudo install -d -o "$SVC" -g "$SVC" -m 755 "$ROOT/log" "$ROOT/run"
# Both binaries the daemon executes are root-owned copies: if it ran the
# Homebrew sops, anything running as you could replace it and read the key.
sudo install -o root -g wheel -m 755 "$here/agent-secret-broker" "$ROOT/bin/agent-secret-broker"
sudo install -o root -g wheel -m 755 "$(realpath "$SOPS_SRC")" "$ROOT/bin/sops"

new_key=
if ! sudo test -f "$ROOT/key/age.key"; then
  new_key=1
  (cd / && sudo -u "$SVC" "$AGE_KEYGEN" -o "$ROOT/key/age.key" 2>/dev/null)
  echo "generated the daemon's age key"
fi
(cd / && sudo -u "$SVC" "$AGE_KEYGEN" -y "$ROOT/key/age.key") | sudo tee "$ROOT/recipient.txt" >/dev/null
sudo chmod 644 "$ROOT/recipient.txt"

printf '{\n  "allowed_uids": [%s],\n  "sops": "%s/bin/sops",\n  "request_idle_hours": 12\n}\n' "$me_uid" "$ROOT" \
  | sudo tee "$ROOT/config.json" >/dev/null
sudo chown root:wheel "$ROOT/config.json"
sudo chmod 644 "$ROOT/config.json"

sudo tee "$PLIST" >/dev/null <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$ROOT/bin/agent-secret-broker</string>
    <string>daemon</string>
    <string>--root</string>
    <string>$ROOT</string>
  </array>
  <key>UserName</key><string>$SVC</string>
  <key>GroupName</key><string>$SVC</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>$ROOT/log/daemon.log</string>
</dict>
</plist>
PLIST
sudo chown root:wheel "$PLIST"
sudo chmod 644 "$PLIST"
sudo launchctl bootout "system/$LABEL" 2>/dev/null || true
sudo launchctl bootstrap system "$PLIST"

mkdir -p "$HOME/bin"
ln -sf "$ROOT/bin/agent-secret-broker" "$HOME/bin/agent-secret-broker"
# Poll the daemon, not the socket file: on upgrade the old daemon's socket is
# still on disk before the new one listens.
for _ in $(seq 100); do
  "$ROOT/bin/agent-secret-broker" status >/dev/null 2>&1 && break
  sleep 0.1
done
if ! "$ROOT/bin/agent-secret-broker" status; then
  echo "daemon did not come up within 10s; last lines of $ROOT/log/daemon.log:" >&2
  sudo tail -n 20 "$ROOT/log/daemon.log" >&2
  exit 1
fi

[[ -n "$new_key" ]] || exit 0
cat <<EOF

Next: make each vault decryptable by the daemon. Add this recipient to the vault's
.sops.yaml age list, then run  sops updatekeys <vault>  once with your usual key:

  $(cat "$ROOT/recipient.txt")
EOF
