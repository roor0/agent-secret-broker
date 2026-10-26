package main

import (
	"fmt"
	"os"
)

const usage = `agent-secret-broker — one-key-at-a-time secrets for agents, with a reason log

  agent-secret-broker keys [pattern]                         list key names (no decryption)
  agent-secret-broker request --reason "..."                 state why, once per session/branch
  agent-secret-broker exec [VAR=]<key>... [--reason "..."] -- <cmd>
                                                       run cmd with secrets in its env; output is redacted
  agent-secret-broker get <key> [--reason "..."]             print one value (recorded as exposed)
  agent-secret-broker set <key>                              add or change one secret; prompts
                                                       with input hidden, or reads stdin
  agent-secret-broker exposed                                printed keys not rotated since
  agent-secret-broker log [-n N] [--key K] [--session ID] [--since 24h] [--json]
  agent-secret-broker status

The vault is --vault, else $AGENT_SECRET_BROKER_VAULT, else the nearest .agent-secret-broker file.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	args := os.Args[2:]
	var err error
	switch os.Args[1] {
	case "keys", "ls":
		err = cmdKeys(args)
	case "request", "why":
		err = cmdRequest(args)
	case "get":
		err = cmdGet(args)
	case "exec", "run":
		err = cmdExec(args)
	case "set":
		err = cmdSet(args)
	case "exposed":
		err = cmdExposed(args)
	case "log":
		err = cmdLog(args)
	case "status":
		err = cmdStatus()
	case "daemon":
		root := defaultRoot
		if len(args) == 2 && args[0] == "--root" {
			root = args[1]
		}
		err = runDaemon(root)
	case "help", "-h", "--help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent-secret-broker:", err)
		os.Exit(1)
	}
}
