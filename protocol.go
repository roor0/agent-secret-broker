package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

const defaultRoot = "/Library/AgentSecretBroker"

// Context is what the client says about who is asking. The daemon trusts it
// only as a claim, except for what it can check itself (peer uid/pid, and
// whether ClaudePID really is an ancestor of the peer).
type Context struct {
	SessionID     string `json:"session_id,omitempty"`
	ClaudePID     int    `json:"claude_pid,omitempty"`
	BridgeSession string `json:"bridge_session,omitempty"`
	Agent         string `json:"agent,omitempty"`
	ConfigDir     string `json:"config_dir,omitempty"`
	AccountEmail  string `json:"account_email,omitempty"`
	AccountName   string `json:"account_name,omitempty"`
	AccountOrg    string `json:"account_org,omitempty"`
	Cwd           string `json:"cwd,omitempty"`
	Repo          string `json:"repo,omitempty"`
	Branch        string `json:"branch,omitempty"`
	PRNumber      int    `json:"pr_number,omitempty"`
	PRTitle       string `json:"pr_title,omitempty"`
	PRURL         string `json:"pr_url,omitempty"`
}

type Request struct {
	Op         string   `json:"op"`
	Vault      string   `json:"vault,omitempty"`
	VaultType  string   `json:"vault_type,omitempty"`
	Ciphertext string   `json:"ciphertext,omitempty"`
	Keys       []string `json:"keys,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	Mode       string   `json:"mode,omitempty"`
	Cmd        string   `json:"cmd,omitempty"`
	Value      string   `json:"value,omitempty"`
	Ctx        Context  `json:"ctx"`
}

type ExposedEntry struct {
	Vault        string    `json:"vault"`
	Key          string    `json:"key"`
	FirstExposed time.Time `json:"first_exposed"`
	Requests     []string  `json:"requests"`
}

type Response struct {
	OK         bool              `json:"ok"`
	Error      string            `json:"error,omitempty"`
	Request    string            `json:"request,omitempty"`
	NewRequest bool              `json:"new_request,omitempty"`
	Values     map[string]string `json:"values,omitempty"`
	Exposed    []ExposedEntry    `json:"exposed,omitempty"`
	Rotated    []string          `json:"rotated,omitempty"`
	Recipient  string            `json:"recipient,omitempty"`
	Ciphertext string            `json:"ciphertext,omitempty"`
}

func socketPath() string {
	if p := os.Getenv("AGENT_SECRET_BROKER_SOCKET"); p != "" {
		return p
	}
	return rootDir() + "/run/agent.sock"
}

func rootDir() string {
	if p := os.Getenv("AGENT_SECRET_BROKER_ROOT"); p != "" {
		return p
	}
	return defaultRoot
}

func call(req Request) (*Response, error) {
	conn, err := net.DialTimeout("unix", socketPath(), 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("agent-secret-broker daemon not reachable at %s (%v); is it installed? see install.sh", socketPath(), err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}
	var resp Response
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("reading daemon response: %v", err)
	}
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return &resp, fmt.Errorf("%s", resp.Error)
	}
	return &resp, nil
}
