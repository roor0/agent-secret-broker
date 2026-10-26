package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type logEvent struct {
	TS      string `json:"ts"`
	Event   string `json:"event"`
	Request string `json:"request"`
	Reason  string `json:"reason"`
	Account struct {
		Email     string `json:"email"`
		Name      string `json:"name"`
		ConfigDir string `json:"config_dir"`
	} `json:"account"`
	Session struct {
		ID       string `json:"id"`
		Verified bool   `json:"claude_pid_verified"`
		Bridge   string `json:"bridge"`
	} `json:"session"`
	Repo   string `json:"repo"`
	Branch string `json:"branch"`
	PR     *struct {
		Number int    `json:"number"`
		Title  string `json:"title"`
	} `json:"pr"`
	Key   string `json:"key"`
	Mode  string `json:"mode"`
	Cmd   string `json:"cmd"`
	Error string `json:"error"`
}

type requestView struct {
	head logEvent
	uses []logEvent
}

func cmdLog(args []string) error {
	n, keyF, sessF, raw := 20, "", "", false
	var since time.Duration
	for i := 0; i < len(args); i++ {
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch args[i] {
		case "-n":
			n, _ = strconv.Atoi(next())
		case "--key":
			keyF = next()
		case "--session":
			sessF = next()
		case "--since":
			since, _ = time.ParseDuration(next())
		case "--json":
			raw = true
		default:
			return fmt.Errorf("usage: agent-secret-broker log [-n N] [--key K] [--session ID] [--since 24h] [--json]")
		}
	}
	path := filepath.Join(rootDir(), "log", "access.jsonl")
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	byID := map[string]*requestView{}
	var order []string
	var other []logEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if raw {
			fmt.Println(sc.Text())
			continue
		}
		var e logEvent
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		switch e.Event {
		case "request":
			byID[e.Request] = &requestView{head: e}
			order = append(order, e.Request)
		case "set", "use":
			if e.Request == "" {
				other = append(other, e)
				continue
			}
			if e.Event == "set" {
				e.Mode = "set"
			}
			if rv := byID[e.Request]; rv != nil {
				rv.uses = append(rv.uses, e)
			}
		default:
			other = append(other, e)
		}
	}
	if raw {
		return nil
	}
	var shown []*requestView
	for _, id := range order {
		rv := byID[id]
		if sessF != "" && !strings.HasPrefix(rv.head.Session.ID, sessF) {
			continue
		}
		if keyF != "" && !usesKey(rv, keyF) {
			continue
		}
		if since > 0 {
			if t, err := time.Parse(time.RFC3339, rv.head.TS); err == nil && time.Since(t) > since {
				continue
			}
		}
		shown = append(shown, rv)
	}
	if n > 0 && len(shown) > n {
		shown = shown[len(shown)-n:]
	}
	for _, rv := range shown {
		printRequest(rv)
	}
	if keyF == "" && sessF == "" {
		for _, e := range other {
			if e.Event == "rotated" {
				fmt.Printf("%s  rotated  %s\n", fmtTS(e.TS), e.Key)
			} else if e.Event == "set" {
				fmt.Printf("%s  set      %s\n", fmtTS(e.TS), e.Key)
			} else if e.Event == "denied" {
				fmt.Printf("%s  DENIED   %s\n", fmtTS(e.TS), e.Error)
			}
		}
	}
	return nil
}

func usesKey(rv *requestView, k string) bool {
	for _, u := range rv.uses {
		if strings.Contains(u.Key, k) {
			return true
		}
	}
	return false
}

func fmtTS(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	return t.Local().Format("2006-01-02 15:04")
}

func printRequest(rv *requestView) {
	h := rv.head
	who := "human/shell"
	if h.Session.ID != "" {
		who = h.Account.Name
		if h.Account.Email != "" {
			who += " <" + h.Account.Email + ">"
		}
		if h.Account.ConfigDir != "" {
			who += " (" + filepath.Base(h.Account.ConfigDir) + ")"
		}
	}
	fmt.Printf("%s  %s  %s\n", fmtTS(h.TS), h.Request, who)
	where := h.Repo
	if h.Branch != "" {
		where += " @ " + h.Branch
	}
	if h.PR != nil {
		where += fmt.Sprintf("  PR #%d %s", h.PR.Number, h.PR.Title)
	}
	if h.Session.ID != "" {
		v := "unverified"
		if h.Session.Verified {
			v = "verified"
		}
		fmt.Println(strings.TrimRight(fmt.Sprintf("  session %s (%s)  %s", h.Session.ID, v, where), " "))
	} else if where != "" {
		fmt.Printf("  %s\n", where)
	}
	fmt.Printf("  why: %s\n", h.Reason)
	modes := map[string][]string{}
	var keys []string
	for _, u := range rv.uses {
		if _, ok := modes[u.Key]; !ok {
			keys = append(keys, u.Key)
		}
		m := u.Mode
		if m == "print" {
			m = "PRINTED"
		}
		modes[u.Key] = append(modes[u.Key], m)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s [%s]", k, strings.Join(modes[k], ",")))
	}
	if len(parts) == 0 {
		parts = []string{"(none yet)"}
	}
	fmt.Printf("  keys: %s\n\n", strings.Join(parts, ", "))
}
