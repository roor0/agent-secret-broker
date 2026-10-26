# agent-secret-broker

Give coding agents the secrets their tools need, with a recorded reason for access and less risk of leaking values into chat histories.

Agents can discover key names without decrypting a vault. When a tool needs a secret, the broker supplies the requested values, records the purpose of access, and masks those values in the command’s output. A separate macOS service account holds the broker’s decryption key.

```bash
agent-secret-broker keys cloudflare
agent-secret-broker exec CLOUDFLARE_API_TOKEN=cloudflare.deployApiToken \
  --reason "deploy the DNS worker for the docs PR" -- wrangler deploy
agent-secret-broker log
```

Built for macOS and integrated with Claude Code. Other agents and scripts can use the same command-line interface.

## What the broker does

- **Discover without revealing.** List key names directly from encrypted vault files.
- **Explain access once per task context.** The first read in a session, repository, and branch requires a reason. Later reads reuse that reason until the context changes or is idle for 12 hours.
- **Pass secrets to tools.** `exec` injects selected values into a child process’s environment and redacts matching values from its stdout and stderr.
- **Keep an access record.** Record the reason, keys used, execution mode, and available agent, repository, branch, and pull request context. Repeated uses of the same key in the same mode are recorded once per request.
- **Track explicit exposure.** `get` prints one value and marks it exposed. `exposed` tracks printed secrets until their values change or are removed.
- **Make setting secrets straightforward.** `set` accepts hidden terminal input or piped stdin and updates the encrypted vault through the daemon. Writes do not require a reason.

## How it works

Vaults remain ordinary [SOPS](https://github.com/getsops/sops) files encrypted with [age](https://github.com/FiloSottile/age). The broker is an additional age recipient; your existing recipient keys keep working.

```text
Agent / CLI                         Broker daemon
(your system account)               (_agentsecretbroker)

Lists plaintext key names
Sends encrypted vault + context ──► Checks caller UID
                                    Requires a reason for reads
                                    Decrypts using its own age key
Receives selected values       ◄──  Records key use
Runs tool with environment vars
Redacts matching output
```

The daemon’s age key and state belong to the service account. Its installed binaries belong to root. An ordinary process running as your account cannot read that key or replace those binaries. Requests travel over a local Unix socket, and the daemon checks the caller against its configured UID allowlist.

The daemon decrypts the vault internally, but returns only requested scalar values. Requests for an entire group or list are rejected. `exec` can request multiple individual keys; `get` prints one key per call.

## Install

Requirements: macOS, Go 1.26 or newer, SOPS, and age.

```bash
brew install go sops age
git clone git@github.com:roor0/agent-secret-broker.git
cd agent-secret-broker
./install.sh
```

Run the installer as your normal user in a terminal. It prompts for sudo to create the hidden `_agentsecretbroker` account, install files under `/Library/AgentSecretBroker`, and register the `com.agent-secret-broker.daemon` LaunchDaemon. It links the CLI at `~/bin/agent-secret-broker`; make sure `~/bin` is on your `PATH`.

The installer prints the daemon’s public age recipient. Add it to the vault’s `.sops.yaml` age recipients and run:

```bash
sops updatekeys path/to/secrets.yaml
```

Use your existing age key for that step. Your private key is never copied to the broker.

Rerun `./install.sh` to upgrade. `SOPS_BIN` and `AGE_KEYGEN` override the tool locations used by the installer.

## Choose a vault

The CLI uses the first available setting:

1. `--vault <path>`
2. `$AGENT_SECRET_BROKER_VAULT`
3. The nearest `.agent-secret-broker` file, searching upward from the current directory.

The pointer file contains a vault path, relative to the pointer file:

```text
secrets/secrets.yaml
```

A `~/.agent-secret-broker` file provides a default for projects under your home directory. A project can override it with its own pointer file. Supported vault formats are YAML, JSON, and dotenv, selected by file extension.

## Commands

```text
agent-secret-broker keys [pattern]
agent-secret-broker request --reason "what you are doing and why"
agent-secret-broker exec [VAR=]<key>... [--reason "..."] -- <command> [args...]
agent-secret-broker get <key> [--reason "..."]
agent-secret-broker set <key>
agent-secret-broker exposed
agent-secret-broker log [-n N] [--key K] [--session ID] [--since 24h] [--json]
agent-secret-broker status
```

Options `--reason` and `--vault` can appear anywhere before `--`.

### Run a command with secrets

```bash
agent-secret-broker exec GITHUB_TOKEN=github.deploy_token \
  --reason "publish the release for this branch" -- gh release list
```

Without an explicit variable name, the CLI derives one from the key: `cloudflare.account_id` becomes `CLOUDFLARE_ACCOUNT_ID`.

### Add or replace a secret

```bash
agent-secret-broker set github.deploy_token
```

The terminal prompt hides input. Piped stdin is also supported. Avoid placing a literal secret in a command that will be saved in a shell or chat history.

### Review access and exposure

```bash
agent-secret-broker log --since 24h
agent-secret-broker log --key github.deploy_token --json
agent-secret-broker exposed
```

The access log is stored at `/Library/AgentSecretBroker/log/access.jsonl`. It is owned by the service account and readable by your account.

The daemon verifies the connecting system UID. It also records whether the supplied Claude PID is an ancestor of the calling process. Account, session, repository, branch, and pull request metadata are client-reported context, not independently authenticated identities.

## Claude Code hook

The optional `hooks/block-secret-bypass.sh` PreToolUse hook blocks recognized whole-vault decryption commands and attempts to access age private keys. It directs the agent to the broker instead. Requires `jq`.

Register it in `.claude/settings.json`, using the actual absolute path to your checkout:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/agent-secret-broker/hooks/block-secret-bypass.sh"
          }
        ]
      }
    ]
  }
}
```

Add custom rules at `~/.config/agent-secret-broker/hook-rules`, or set `$AGENT_SECRET_BROKER_HOOK_RULES`. Each line contains a regular expression, a literal tab, and a reason. `{cmd}` matches the beginning of a command:

```text
{cmd}bin/vault-helper[[:space:]]+(show|export)	vault-helper prints the whole vault
op[[:space:]]+read[^;&|]*age key	that reads the age private key
```

## Security boundaries

This broker reduces accidental exposure and records access; it does not prevent an authorized agent from deliberately revealing a secret it can fetch. `get` intentionally prints values. With `exec`, the child process receives the values and can write them to files or send them elsewhere. Output masking matches literal values of at least four bytes; transformed values are not covered.

The account separation protects the daemon’s key from ordinary user processes. Passwordless sudo or access to another recipient’s private key can bypass that boundary. Keep your own age key outside the agent’s reach if the broker must be its only decryption route. The optional shell hook is an additional guard against common bypass commands.

Reasons are recorded explanations, not policy approvals. Access logging is best effort: a log write failure is reported in the daemon log but does not block secret access.

## Remove

```bash
./uninstall.sh
```

This removes the daemon and its key while retaining the access log. Use `./uninstall.sh --purge` to remove all broker files and the service account. Remove the daemon’s recipient from your vault configuration and run `sops updatekeys` afterwards.

## Development

```bash
go test ./...
hooks/test-hook.sh
test/e2e.sh
```

The end-to-end test creates a temporary vault, age key, and daemon running as the current user. It does not modify the installed service under `/Library`.

## License

MIT. See [LICENSE](LICENSE).
