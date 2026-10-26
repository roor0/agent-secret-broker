package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type daemonConfig struct {
	AllowedUIDs      []int   `json:"allowed_uids"`
	Sops             string  `json:"sops"`
	RequestIdleHours float64 `json:"request_idle_hours"`
}

type openRequest struct {
	ID       string
	Reason   string
	LastUsed time.Time
	Used     map[string]bool
}

type exposure struct {
	Vault        string    `json:"vault"`
	Key          string    `json:"key"`
	MAC          string    `json:"mac"`
	FirstExposed time.Time `json:"first_exposed"`
	Requests     []string  `json:"requests"`
}

type daemon struct {
	root     string
	cfg      daemonConfig
	macKey   []byte
	mu       sync.Mutex
	requests map[string]*openRequest
	exposed  map[string]*exposure
}

type peer struct {
	UID int
	PID int
}

func runDaemon(root string) error {
	d := &daemon{root: root, requests: map[string]*openRequest{}, exposed: map[string]*exposure{}}
	b, err := os.ReadFile(filepath.Join(root, "config.json"))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &d.cfg); err != nil {
		return fmt.Errorf("config.json: %v", err)
	}
	if d.cfg.Sops == "" {
		d.cfg.Sops = filepath.Join(root, "bin", "sops")
	}
	if d.cfg.RequestIdleHours == 0 {
		d.cfg.RequestIdleHours = 12
	}
	if err := d.loadState(); err != nil {
		return err
	}
	sock := filepath.Join(root, "run", "agent.sock")
	os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	// Access control is the uid allowlist checked per connection, not the
	// socket mode, so the socket can stay world-connectable.
	if err := os.Chmod(sock, 0o666); err != nil {
		return err
	}
	log.Printf("agent-secret-broker daemon listening on %s", sock)
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go d.serve(c.(*net.UnixConn))
	}
}

func (d *daemon) loadState() error {
	state := filepath.Join(d.root, "state")
	keyFile := filepath.Join(state, "hmac.key")
	k, err := os.ReadFile(keyFile)
	if os.IsNotExist(err) {
		k = make([]byte, 32)
		rand.Read(k)
		if err := os.WriteFile(keyFile, k, 0o600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	d.macKey = k
	if b, err := os.ReadFile(filepath.Join(state, "exposures.json")); err == nil {
		json.Unmarshal(b, &d.exposed)
	}
	return nil
}

func (d *daemon) saveExposures() {
	b, _ := json.MarshalIndent(d.exposed, "", "  ")
	tmp := filepath.Join(d.root, "state", "exposures.json.tmp")
	if os.WriteFile(tmp, b, 0o600) == nil {
		os.Rename(tmp, filepath.Join(d.root, "state", "exposures.json"))
	}
}

func peerOf(c *net.UnixConn) (peer, error) {
	var p peer
	raw, err := c.SyscallConn()
	if err != nil {
		return p, err
	}
	var ierr error
	raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			ierr = err
			return
		}
		p.UID = int(cred.Uid)
		p.PID, ierr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	})
	return p, ierr
}

func parentPID(pid int) int {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0
	}
	return int(kp.Eproc.Ppid)
}

func isAncestor(ancestor, pid int) bool {
	for i := 0; i < 64 && pid > 1; i++ {
		if pid == ancestor {
			return true
		}
		pid = parentPID(pid)
	}
	return false
}

func (d *daemon) serve(c *net.UnixConn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	enc := json.NewEncoder(c)
	p, err := peerOf(c)
	if err != nil {
		enc.Encode(Response{Error: "cannot identify caller: " + err.Error()})
		return
	}
	if !d.allowed(p.UID) {
		d.logEvent(map[string]any{"event": "denied", "uid": p.UID, "peer_pid": p.PID, "error": "uid not allowed"})
		enc.Encode(Response{Error: fmt.Sprintf("uid %d is not allowed", p.UID)})
		return
	}
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		return
	}
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		enc.Encode(Response{Error: "bad request"})
		return
	}
	resp := d.handle(p, req)
	enc.Encode(resp)
}

func (d *daemon) allowed(uid int) bool {
	for _, u := range d.cfg.AllowedUIDs {
		if u == uid {
			return true
		}
	}
	return false
}

func (d *daemon) handle(p peer, req Request) Response {
	switch req.Op {
	case "status":
		rec, _ := os.ReadFile(filepath.Join(d.root, "recipient.txt"))
		return Response{OK: true, Recipient: strings.TrimSpace(string(rec))}
	case "request":
		d.mu.Lock()
		defer d.mu.Unlock()
		r, isNew, err := d.openRequest(p, req, false)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{OK: true, Request: r.ID, NewRequest: isNew}
	case "get":
		return d.get(p, req)
	case "exposed":
		return d.checkExposed(p, req)
	case "set":
		return d.set(p, req)
	}
	return Response{Error: "unknown op " + req.Op}
}

// requestKey scopes a stated reason to one session on one branch, so moving
// to another feature in the same session needs a fresh reason.
func requestKey(p peer, ctx Context) string {
	who := ctx.SessionID
	if who == "" && ctx.ClaudePID > 0 {
		who = fmt.Sprintf("claude-pid:%d", ctx.ClaudePID)
	}
	if who == "" {
		who = fmt.Sprintf("shell:%d", parentPID(p.PID))
	}
	return fmt.Sprintf("uid:%d|%s|%s|%s", p.UID, who, ctx.Repo, ctx.Branch)
}

// openRequest returns nil with no error when optional is set and there is
// neither an open request nor a reason to open one.
func (d *daemon) openRequest(p peer, req Request, optional bool) (*openRequest, bool, error) {
	key := requestKey(p, req.Ctx)
	idle := time.Duration(d.cfg.RequestIdleHours * float64(time.Hour))
	r := d.requests[key]
	if r != nil && time.Since(r.LastUsed) > idle {
		r = nil
	}
	reason := strings.TrimSpace(req.Reason)
	if r != nil && (reason == "" || reason == r.Reason) {
		r.LastUsed = time.Now()
		return r, false, nil
	}
	if reason == "" && optional {
		return nil, false, nil
	}
	if len(reason) < 8 {
		if reason == "" {
			return nil, false, fmt.Errorf("no open request for this session/branch; rerun with --reason \"<what you are doing and why you need it>\"")
		}
		return nil, false, fmt.Errorf("reason %q is too short to be useful in the log; say what you are doing", reason)
	}
	id := make([]byte, 4)
	rand.Read(id)
	r = &openRequest{ID: "r-" + hex.EncodeToString(id), Reason: reason, LastUsed: time.Now(), Used: map[string]bool{}}
	d.requests[key] = r
	c := req.Ctx
	ev := map[string]any{
		"event":    "request",
		"request":  r.ID,
		"reason":   reason,
		"account":  map[string]any{"email": c.AccountEmail, "name": c.AccountName, "org": c.AccountOrg, "config_dir": c.ConfigDir},
		"session":  map[string]any{"id": c.SessionID, "claude_pid": c.ClaudePID, "claude_pid_verified": c.ClaudePID > 0 && isAncestor(c.ClaudePID, p.PID), "bridge": c.BridgeSession, "agent": c.Agent},
		"repo":     c.Repo,
		"branch":   c.Branch,
		"cwd":      c.Cwd,
		"uid":      p.UID,
		"peer_pid": p.PID,
	}
	if c.PRNumber > 0 {
		ev["pr"] = map[string]any{"number": c.PRNumber, "title": c.PRTitle, "url": c.PRURL}
	}
	d.logEvent(ev)
	return r, true, nil
}

func (d *daemon) get(p peer, req Request) Response {
	if len(req.Keys) == 0 {
		return Response{Error: "no key named"}
	}
	if req.Mode != "exec" && len(req.Keys) != 1 {
		return Response{Error: "printing is one key per call; use exec to inject several"}
	}
	d.mu.Lock()
	r, isNew, err := d.openRequest(p, req, false)
	d.mu.Unlock()
	if err != nil {
		return Response{Error: err.Error()}
	}
	doc, err := d.decrypt(req)
	if err != nil {
		return Response{Error: err.Error()}
	}
	values := map[string]string{}
	for _, k := range req.Keys {
		v, err := lookupLeaf(doc, k)
		if err != nil {
			return Response{Error: err.Error()}
		}
		values[strings.TrimPrefix(k, ".")] = v
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	changed := false
	for k, v := range values {
		// One log line per key per mode per request: the request carries the
		// why, repeated uses under it add nothing.
		used := req.Vault + "#" + k + "#" + req.Mode
		if !r.Used[used] {
			r.Used[used] = true
			d.logEvent(map[string]any{"event": "use", "request": r.ID, "vault": req.Vault, "key": k, "mode": req.Mode, "cmd": req.Cmd})
		}
		if req.Mode == "print" {
			id := req.Vault + "#" + k
			mac := d.mac(v)
			e := d.exposed[id]
			if e == nil || e.MAC != mac {
				e = &exposure{Vault: req.Vault, Key: k, MAC: mac, FirstExposed: time.Now()}
				d.exposed[id] = e
			}
			if !contains(e.Requests, r.ID) {
				e.Requests = append(e.Requests, r.ID)
			}
			changed = true
		}
	}
	if changed {
		d.saveExposures()
	}
	return Response{OK: true, Request: r.ID, NewRequest: isNew, Values: values}
}

func (d *daemon) set(p peer, req Request) Response {
	if len(req.Keys) != 1 {
		return Response{Error: "set takes exactly one key"}
	}
	key := strings.TrimPrefix(req.Keys[0], ".")
	// Writing a value reveals nothing, so set needs no reason; one given, or an
	// open request, still ties the write to it in the log.
	d.mu.Lock()
	r, isNew, err := d.openRequest(p, req, true)
	d.mu.Unlock()
	if err != nil {
		return Response{Error: err.Error()}
	}
	doc, err := d.decrypt(req)
	if err != nil {
		return Response{Error: err.Error()}
	}
	_, lookupErr := lookupLeaf(doc, key)
	if lookupErr != nil && !strings.HasPrefix(lookupErr.Error(), "no key") {
		return Response{Error: lookupErr.Error()}
	}
	var idx strings.Builder
	for _, seg := range splitPath(key) {
		if _, err := strconv.Atoi(seg); err == nil {
			idx.WriteString("[" + seg + "]")
		} else {
			q, _ := json.Marshal(seg)
			idx.WriteString("[" + string(q) + "]")
		}
	}
	tmp, err := d.writeTemp(req)
	if err != nil {
		return Response{Error: err.Error()}
	}
	defer os.Remove(tmp)
	val, _ := json.Marshal(req.Value)
	if out, err := d.sops(bytes.NewReader(val), "set", "--input-type", req.VaultType, "--output-type", req.VaultType, "--value-stdin", tmp, idx.String()); err != nil {
		return Response{Error: "sops set failed: " + out}
	}
	b, err := os.ReadFile(tmp)
	if err != nil {
		return Response{Error: err.Error()}
	}
	ev := map[string]any{"event": "set", "vault": req.Vault, "key": key, "created": lookupErr != nil}
	resp := Response{OK: true, NewRequest: isNew, Ciphertext: string(b)}
	if r != nil {
		ev["request"], resp.Request = r.ID, r.ID
	} else {
		c := req.Ctx
		ev["session"] = map[string]any{"id": c.SessionID, "claude_pid": c.ClaudePID, "agent": c.Agent}
		ev["repo"], ev["branch"], ev["cwd"], ev["uid"], ev["peer_pid"] = c.Repo, c.Branch, c.Cwd, p.UID, p.PID
	}
	d.mu.Lock()
	d.logEvent(ev)
	d.mu.Unlock()
	return resp
}

func (d *daemon) checkExposed(p peer, req Request) Response {
	doc, err := d.decrypt(req)
	if err != nil {
		return Response{Error: err.Error()}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []ExposedEntry
	var rotated []string
	for id, e := range d.exposed {
		if e.Vault != req.Vault {
			continue
		}
		v, err := lookupLeaf(doc, e.Key)
		if err != nil || d.mac(v) != e.MAC {
			rotated = append(rotated, e.Key)
			delete(d.exposed, id)
			d.logEvent(map[string]any{"event": "rotated", "vault": e.Vault, "key": e.Key})
			continue
		}
		out = append(out, ExposedEntry{Vault: e.Vault, Key: e.Key, FirstExposed: e.FirstExposed, Requests: e.Requests})
	}
	if len(rotated) > 0 {
		d.saveExposures()
	}
	return Response{OK: true, Exposed: out, Rotated: rotated}
}

func (d *daemon) mac(v string) string {
	m := hmac.New(sha256.New, d.macKey)
	m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil))
}

// decrypt works on ciphertext the client sends, because this account cannot
// read the user's home directory. The ciphertext is not sensitive; only this
// daemon's age key can open it.
func (d *daemon) decrypt(req Request) (any, error) {
	tmp, err := d.writeTemp(req)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp)
	out, err := d.sops(nil, "decrypt", "--input-type", req.VaultType, "--output-type", "json", tmp)
	if err != nil {
		if strings.Contains(out, "no identity matched") || strings.Contains(out, "Error getting data key") {
			rec, _ := os.ReadFile(filepath.Join(d.root, "recipient.txt"))
			return nil, fmt.Errorf("vault %s is not encrypted for this daemon; add recipient %s to its .sops.yaml and run sops updatekeys", req.Vault, strings.TrimSpace(string(rec)))
		}
		return nil, fmt.Errorf("sops decrypt failed: %s", out)
	}
	var doc any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// writeTemp stages client-sent ciphertext, because this account cannot read
// the user's home directory. The ciphertext is not sensitive; only this
// daemon's age key can open it.
func (d *daemon) writeTemp(req Request) (string, error) {
	if req.Ciphertext == "" {
		return "", fmt.Errorf("no vault contents sent")
	}
	if req.VaultType == "" {
		req.VaultType = "yaml"
	}
	tmp, err := os.CreateTemp(filepath.Join(d.root, "state"), "vault-*")
	if err != nil {
		return "", err
	}
	defer tmp.Close()
	if _, err := tmp.WriteString(req.Ciphertext); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

// sops returns stdout on success and trimmed stderr on failure.
func (d *daemon) sops(stdin io.Reader, args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(d.cfg.Sops, args...)
	cmd.Env = []string{
		"SOPS_AGE_KEY_FILE=" + filepath.Join(d.root, "key", "age.key"),
		"HOME=" + filepath.Join(d.root, "state"),
		"PATH=/usr/bin:/bin",
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return strings.TrimSpace(stderr.String()), err
	}
	return stdout.String(), nil
}

func (d *daemon) logEvent(ev map[string]any) {
	ev["ts"] = time.Now().Format(time.RFC3339)
	b, _ := json.Marshal(ev)
	f, err := os.OpenFile(filepath.Join(d.root, "log", "access.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("log write failed: %v", err)
		return
	}
	f.Write(append(b, '\n'))
	f.Close()
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
