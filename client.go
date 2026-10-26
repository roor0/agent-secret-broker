package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func gatherContext() Context {
	c := Context{
		SessionID:     os.Getenv("CLAUDE_CODE_SESSION_ID"),
		BridgeSession: os.Getenv("CLAUDE_CODE_BRIDGE_SESSION_ID"),
		Agent:         os.Getenv("AI_AGENT"),
		ConfigDir:     os.Getenv("CLAUDE_CONFIG_DIR"),
	}
	c.ClaudePID, _ = strconv.Atoi(os.Getenv("CLAUDE_PID"))
	c.Cwd, _ = os.Getwd()
	home, _ := os.UserHomeDir()
	accountFile := filepath.Join(home, ".claude.json")
	if c.ConfigDir != "" {
		accountFile = filepath.Join(c.ConfigDir, ".claude.json")
	} else if c.SessionID != "" {
		c.ConfigDir = filepath.Join(home, ".claude")
	}
	if c.SessionID != "" {
		var acct struct {
			OAuthAccount struct {
				EmailAddress     string `json:"emailAddress"`
				DisplayName      string `json:"displayName"`
				OrganizationName string `json:"organizationName"`
			} `json:"oauthAccount"`
		}
		if b, err := os.ReadFile(accountFile); err == nil && json.Unmarshal(b, &acct) == nil {
			c.AccountEmail = acct.OAuthAccount.EmailAddress
			c.AccountName = acct.OAuthAccount.DisplayName
			c.AccountOrg = acct.OAuthAccount.OrganizationName
		}
	}
	top := gitOut("rev-parse", "--show-toplevel")
	if top == "" {
		return c
	}
	c.Repo = repoSlug(gitOut("remote", "get-url", "origin"))
	if c.Repo == "" {
		c.Repo = filepath.Base(top)
	}
	c.Branch = gitOut("branch", "--show-current")
	if c.Branch != "" && c.Branch != "main" && c.Branch != "master" {
		c.PRNumber, c.PRTitle, c.PRURL = lookupPR(c.Repo, c.Branch)
	}
	return c
}

func gitOut(args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "git", args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

var slugRE = regexp.MustCompile(`[:/]([^/:]+/[^/]+?)(\.git)?$`)

func repoSlug(remote string) string {
	if m := slugRE.FindStringSubmatch(remote); m != nil {
		return m[1]
	}
	return ""
}

type prCache struct {
	At     time.Time `json:"at"`
	Number int       `json:"number"`
	Title  string    `json:"title"`
	URL    string    `json:"url"`
}

// lookupPR is cached because gh takes ~0.5s and every get/exec gathers context.
func lookupPR(repo, branch string) (int, string, string) {
	dir, _ := os.UserCacheDir()
	dir = filepath.Join(dir, "agent-secret-broker")
	f := filepath.Join(dir, "pr-"+strings.NewReplacer("/", "_", ":", "_").Replace(repo+"@"+branch)+".json")
	var pc prCache
	if b, err := os.ReadFile(f); err == nil && json.Unmarshal(b, &pc) == nil && time.Since(pc.At) < 10*time.Minute {
		return pc.Number, pc.Title, pc.URL
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "gh", "pr", "view", "--json", "number,title,url").Output()
	pc = prCache{At: time.Now()}
	if err == nil {
		json.Unmarshal(out, &pc)
	}
	os.MkdirAll(dir, 0o700)
	if b, err := json.Marshal(pc); err == nil {
		os.WriteFile(f, b, 0o600)
	}
	return pc.Number, pc.Title, pc.URL
}

type opts struct {
	reason string
	vault  string
	rest   []string
	after  []string
}

// parseOpts accepts --reason/--vault anywhere before "--"; everything after
// "--" is the command for exec.
func parseOpts(args []string) (opts, error) {
	var o opts
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			o.after = args[i+1:]
			return o, nil
		case a == "--reason" || a == "-r" || a == "--vault":
			if i+1 >= len(args) {
				return o, fmt.Errorf("%s needs a value", a)
			}
			if a == "--vault" {
				o.vault = args[i+1]
			} else {
				o.reason = args[i+1]
			}
			i++
		case strings.HasPrefix(a, "--reason="):
			o.reason = strings.TrimPrefix(a, "--reason=")
		case strings.HasPrefix(a, "--vault="):
			o.vault = strings.TrimPrefix(a, "--vault=")
		default:
			o.rest = append(o.rest, a)
		}
	}
	return o, nil
}

func baseRequest(op string, o opts) (Request, error) {
	path, err := findVault(o.vault)
	if err != nil {
		return Request{}, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Request{}, err
	}
	return Request{Op: op, Vault: path, VaultType: vaultType(path), Ciphertext: string(b), Reason: o.reason, Ctx: gatherContext()}, nil
}

func cmdKeys(args []string) error {
	o, err := parseOpts(args)
	if err != nil {
		return err
	}
	path, err := findVault(o.vault)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	keys, err := listKeys(b)
	if err != nil {
		return err
	}
	pat := ""
	if len(o.rest) > 0 {
		pat = strings.ToLower(o.rest[0])
	}
	for _, k := range keys {
		if pat == "" || strings.Contains(strings.ToLower(k), pat) {
			fmt.Println(k)
		}
	}
	return nil
}

func cmdRequest(args []string) error {
	o, err := parseOpts(args)
	if err != nil {
		return err
	}
	if o.reason == "" && len(o.rest) > 0 {
		o.reason = strings.Join(o.rest, " ")
	}
	if o.reason == "" {
		return errors.New(`usage: agent-secret-broker request --reason "<what you are doing and why>"`)
	}
	req := Request{Op: "request", Reason: o.reason, Ctx: gatherContext()}
	resp, err := call(req)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "open request %s for this session/branch\n", resp.Request)
	return nil
}

func cmdGet(args []string) error {
	o, err := parseOpts(args)
	if err != nil {
		return err
	}
	if len(o.rest) != 1 {
		return errors.New(`usage: agent-secret-broker get <key> [--reason "..."]   (one key per call)`)
	}
	req, err := baseRequest("get", o)
	if err != nil {
		return err
	}
	req.Keys, req.Mode = o.rest, "print"
	resp, err := call(req)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "agent-secret-broker: %s printed under %s and recorded as exposed; prefer `agent-secret-broker exec` so the value never reaches the transcript\n", o.rest[0], resp.Request)
	for _, v := range resp.Values {
		fmt.Println(v)
	}
	return nil
}

var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func envNameFor(key string) string {
	return strings.ToUpper(regexp.MustCompile(`[^A-Za-z0-9]+`).ReplaceAllString(strings.TrimPrefix(key, "."), "_"))
}

func cmdExec(args []string) error {
	o, err := parseOpts(args)
	if err != nil {
		return err
	}
	if len(o.rest) == 0 || len(o.after) == 0 {
		return errors.New(`usage: agent-secret-broker exec [ENV_VAR=]<key> ... [--reason "..."] -- <command> [args...]`)
	}
	envFor := map[string]string{}
	var keys []string
	for _, spec := range o.rest {
		name, key := "", spec
		if i := strings.Index(spec, "="); i > 0 {
			name, key = spec[:i], spec[i+1:]
		}
		key = strings.TrimPrefix(key, ".")
		if name == "" {
			name = envNameFor(key)
		}
		if !envNameRE.MatchString(name) {
			return fmt.Errorf("%q is not a valid environment variable name", name)
		}
		envFor[name] = key
		keys = append(keys, key)
	}
	req, err := baseRequest("get", o)
	if err != nil {
		return err
	}
	req.Keys, req.Mode, req.Cmd = keys, "exec", strings.Join(o.after, " ")
	resp, err := call(req)
	if err != nil {
		return err
	}
	env := os.Environ()
	for name, key := range envFor {
		env = append(env, name+"="+resp.Values[key])
	}
	cmd := exec.Command(o.after[0], o.after[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	outR := newRedactor(os.Stdout, resp.Values)
	errR := newRedactor(os.Stderr, resp.Values)
	cmd.Stdout, cmd.Stderr = outR, errR
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		for s := range sigs {
			cmd.Process.Signal(s)
		}
	}()
	err = cmd.Wait()
	outR.Flush()
	errR.Flush()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		os.Exit(ee.ExitCode())
	}
	return err
}

func cmdSet(args []string) error {
	o, err := parseOpts(args)
	if err != nil {
		return err
	}
	if len(o.rest) != 1 {
		return errors.New(`usage: agent-secret-broker set <key>   (prompts with input hidden, or reads stdin)`)
	}
	req, err := baseRequest("set", o)
	if err != nil {
		return err
	}
	val, err := readValue(o.rest[0])
	if err != nil {
		return err
	}
	if val == "" {
		return errors.New("empty value; nothing set")
	}
	req.Keys, req.Value = o.rest, val
	resp, err := call(req)
	if err != nil {
		return err
	}
	st, err := os.Stat(req.Vault)
	if err != nil {
		return err
	}
	tmp := req.Vault + ".agent-secret-broker.tmp"
	if err := os.WriteFile(tmp, []byte(resp.Ciphertext), st.Mode().Perm()); err != nil {
		return err
	}
	if err := os.Rename(tmp, req.Vault); err != nil {
		return err
	}
	if resp.Request != "" {
		fmt.Fprintf(os.Stderr, "set %s in %s under %s\n", o.rest[0], req.Vault, resp.Request)
	} else {
		fmt.Fprintf(os.Stderr, "set %s in %s\n", o.rest[0], req.Vault)
	}
	return nil
}

// readValue prompts with echo off when stdin is a terminal, else reads stdin.
// Raw mode rather than canonical: macOS truncates canonical lines at 1024
// bytes, which a pasted JWT or PEM can exceed.
func readValue(key string) (string, error) {
	fd := int(os.Stdin.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		b, err := io.ReadAll(os.Stdin)
		return strings.TrimRight(string(b), "\r\n"), err
	}
	raw := *old
	raw.Lflag &^= unix.ECHO | unix.ICANON | unix.ISIG
	raw.Cc[unix.VMIN], raw.Cc[unix.VTIME] = 1, 0
	if err := unix.IoctlSetTermios(fd, unix.TIOCSETA, &raw); err != nil {
		return "", err
	}
	defer unix.IoctlSetTermios(fd, unix.TIOCSETA, old)
	fmt.Fprintf(os.Stderr, "paste value for %s (hidden, Enter to save, Ctrl-C to cancel): ", key)
	defer fmt.Fprintln(os.Stderr)
	var val []byte
	buf := make([]byte, 4096)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil {
			return "", err
		}
		for _, c := range buf[:n] {
			switch c {
			case '\r', '\n', 4:
				return string(val), nil
			case 3:
				return "", errors.New("cancelled")
			case 127, 8:
				if len(val) > 0 {
					val = val[:len(val)-1]
				}
			default:
				val = append(val, c)
			}
		}
	}
}

func cmdExposed(args []string) error {
	o, err := parseOpts(args)
	if err != nil {
		return err
	}
	req, err := baseRequest("exposed", o)
	if err != nil {
		return err
	}
	resp, err := call(req)
	if err != nil {
		return err
	}
	for _, k := range resp.Rotated {
		fmt.Printf("rotated since exposure, cleared: %s\n", k)
	}
	if len(resp.Exposed) == 0 {
		fmt.Println("no keys in this vault have been printed since their last rotation")
		return nil
	}
	fmt.Println("printed to a transcript and not rotated since:")
	for _, e := range resp.Exposed {
		fmt.Printf("  %-40s first %s  requests %s\n", e.Key, e.FirstExposed.Local().Format("2006-01-02 15:04"), strings.Join(e.Requests, ","))
	}
	return nil
}

func cmdStatus() error {
	resp, err := call(Request{Op: "status"})
	if err != nil {
		return err
	}
	fmt.Printf("daemon: up at %s\nrecipient: %s\nlog: %s\n", socketPath(), resp.Recipient, filepath.Join(rootDir(), "log", "access.jsonl"))
	return nil
}
