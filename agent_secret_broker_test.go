package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestListKeysSkipsSopsMetadata(t *testing.T) {
	in := []byte(`
cloudflare:
    account_id: ENC[AES256_GCM,data:x,type:str]
    tokens:
        - ENC[AES256_GCM,data:y,type:str]
span: ENC[AES256_GCM,data:z,type:str]
sops:
    age:
        - recipient: age1abc
`)
	got, err := listKeys(in)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"cloudflare.account_id", "cloudflare.tokens.0", "span"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestLookupLeafRefusesGroups(t *testing.T) {
	var doc any
	json.Unmarshal([]byte(`{"cloudflare":{"a":"1","b":"2"},"list":["x"],"n":42}`), &doc)
	if v, err := lookupLeaf(doc, ".cloudflare.a"); err != nil || v != "1" {
		t.Fatalf("leaf: %q %v", v, err)
	}
	if v, _ := lookupLeaf(doc, "list.0"); v != "x" {
		t.Fatalf("list index: %q", v)
	}
	if v, _ := lookupLeaf(doc, "n"); v != "42" {
		t.Fatalf("number: %q", v)
	}
	_, err := lookupLeaf(doc, "cloudflare")
	if err == nil || !strings.Contains(err.Error(), "cloudflare.a, cloudflare.b") {
		t.Fatalf("group should be refused with children listed, got %v", err)
	}
	if _, err := lookupLeaf(doc, "nope"); err == nil {
		t.Fatal("missing key should error")
	}
}

func TestRedactorAcrossWrites(t *testing.T) {
	var out bytes.Buffer
	r := newRedactor(&out, map[string]string{"cf.token": "SECRETVALUE123", "short": "ab"})
	for _, chunk := range []string{"token=SECR", "ETVAL", "UE123 done\n", "ab stays\n", "trailing SEC"} {
		r.Write([]byte(chunk))
	}
	if !strings.HasSuffix(out.String(), "trailing ") {
		t.Fatalf("only the possible secret prefix should be held back: %q", out.String())
	}
	r.Flush()
	want := "token=***cf.token*** done\nab stays\ntrailing SEC"
	if out.String() != want {
		t.Fatalf("got %q want %q", out.String(), want)
	}
}

func TestRedactorDoesNotDelayUnrelatedOutput(t *testing.T) {
	var out bytes.Buffer
	r := newRedactor(&out, map[string]string{"k": "SECRETVALUE"})
	r.Write([]byte("hello world\n"))
	if out.String() != "hello world\n" {
		t.Fatalf("unrelated output was held: %q", out.String())
	}
}

func TestRepoSlug(t *testing.T) {
	for in, want := range map[string]string{
		"git@github.com:example/infra.git":  "example/infra",
		"https://github.com/example/tools":  "example/tools",
		"https://github.com/owner/repo.git": "owner/repo",
	} {
		if got := repoSlug(in); got != want {
			t.Errorf("%s: got %q want %q", in, got, want)
		}
	}
}
