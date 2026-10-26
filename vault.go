package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// listKeys reads the encrypted file directly: sops leaves key names in
// plaintext, so listing needs neither the daemon nor any key.
func listKeys(data []byte) ([]string, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	if len(root.Content) == 0 {
		return nil, nil
	}
	var out []string
	var walk func(n *yaml.Node, prefix string)
	walk = func(n *yaml.Node, prefix string) {
		switch n.Kind {
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				k := n.Content[i].Value
				if prefix == "" && k == "sops" {
					continue
				}
				walk(n.Content[i+1], joinPath(prefix, k))
			}
		case yaml.SequenceNode:
			for i, c := range n.Content {
				walk(c, joinPath(prefix, strconv.Itoa(i)))
			}
		default:
			out = append(out, prefix)
		}
	}
	walk(root.Content[0], "")
	return out, nil
}

func joinPath(prefix, k string) string {
	if prefix == "" {
		return k
	}
	return prefix + "." + k
}

func splitPath(p string) []string {
	return strings.Split(strings.TrimPrefix(p, "."), ".")
}

// lookupLeaf refuses anything but a scalar, so one call can never return a
// whole subtree of secrets.
func lookupLeaf(doc any, path string) (string, error) {
	cur := doc
	for _, seg := range splitPath(path) {
		switch v := cur.(type) {
		case map[string]any:
			next, ok := v[seg]
			if !ok {
				return "", fmt.Errorf("no key %q", path)
			}
			cur = next
		case []any:
			i, err := strconv.Atoi(seg)
			if err != nil || i < 0 || i >= len(v) {
				return "", fmt.Errorf("no key %q", path)
			}
			cur = v[i]
		default:
			return "", fmt.Errorf("no key %q", path)
		}
	}
	switch v := cur.(type) {
	case map[string]any:
		kids := make([]string, 0, len(v))
		for k := range v {
			kids = append(kids, joinPath(strings.TrimPrefix(path, "."), k))
		}
		sort.Strings(kids)
		return "", fmt.Errorf("%q is a group, not a single secret; ask for one of: %s", path, strings.Join(kids, ", "))
	case []any:
		return "", fmt.Errorf("%q is a list, not a single secret; ask for %s.0 etc.", path, path)
	case string:
		return v, nil
	case nil:
		return "", nil
	default:
		return fmt.Sprint(v), nil
	}
}

func vaultType(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return "json"
	case ".env":
		return "dotenv"
	default:
		return "yaml"
	}
}

// findVault resolves --vault, then $AGENT_SECRET_BROKER_VAULT, then the nearest
// .agent-secret-broker file walking up from the working directory. That file holds
// one path, relative to the file.
func findVault(flagVal string) (string, error) {
	if flagVal != "" {
		return filepath.Abs(flagVal)
	}
	if v := os.Getenv("AGENT_SECRET_BROKER_VAULT"); v != "" {
		return filepath.Abs(v)
	}
	dir, _ := os.Getwd()
	for {
		f := filepath.Join(dir, ".agent-secret-broker")
		if b, err := os.ReadFile(f); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if !filepath.IsAbs(line) {
					line = filepath.Join(dir, line)
				}
				return line, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no vault: pass --vault, set AGENT_SECRET_BROKER_VAULT, or add a .agent-secret-broker file naming the sops file")
		}
		dir = parent
	}
}
