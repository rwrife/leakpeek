package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// decodeProfile pulls the "profile" field out of a --json run.
func decodeProfile(t *testing.T, jsonOut string) string {
	t.Helper()
	var doc struct {
		Profile string `json:"profile"`
	}
	if err := json.Unmarshal([]byte(jsonOut), &doc); err != nil {
		t.Fatalf("decoding json %q: %v", jsonOut, err)
	}
	return doc.Profile
}

func TestStrictAndChillMutuallyExclusive(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--strict", "--chill"}, strings.NewReader("hi"), &out, &errBuf)
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d (usage error) — err=%q", code, exitUsage, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "mutually exclusive") {
		t.Errorf("stderr = %q, want a 'mutually exclusive' message", errBuf.String())
	}
}

func TestProfileEmittedInJSON(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--stdin", "--json"}, "default"},
		{[]string{"--stdin", "--json", "--strict"}, "strict"},
		{[]string{"--stdin", "--json", "--chill"}, "chill"},
	}
	for _, c := range cases {
		var out, errBuf bytes.Buffer
		run(c.args, strings.NewReader("just some words here"), &out, &errBuf)
		if got := decodeProfile(t, out.String()); got != c.want {
			t.Errorf("args %v: profile = %q, want %q", c.args, got, c.want)
		}
	}
}

func TestChillDropsNetworkFindings(t *testing.T) {
	// A bare internal IP is a KindNetwork hit under default but must be
	// suppressed under --chill.
	in := "server at 192.168.1.100 is up\n"

	var defOut, defErr bytes.Buffer
	defCode := run([]string{"--stdin", "--no-ignore"}, strings.NewReader(in), &defOut, &defErr)
	if defCode != exitFound {
		t.Fatalf("default: exit = %d, want %d (ipv4 found) — out=%q", defCode, exitFound, defOut.String())
	}

	var chillOut, chillErr bytes.Buffer
	chillCode := run([]string{"--stdin", "--no-ignore", "--chill"}, strings.NewReader(in), &chillOut, &chillErr)
	if chillCode != exitClean {
		t.Fatalf("chill: exit = %d, want %d (ipv4 dropped) — out=%q", chillCode, exitClean, chillOut.String())
	}
}

func TestChillKeepsStructuredSecrets(t *testing.T) {
	// --chill must not soften structured detectors: a real AWS key still fires.
	in := "key " + fakeAWSKey + " and ip 10.0.0.1\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--no-ignore", "--chill"}, strings.NewReader(in), &out, &errBuf)
	if code != exitFound {
		t.Fatalf("chill: exit = %d, want %d (aws key still found) — out=%q", code, exitFound, out.String())
	}
}
