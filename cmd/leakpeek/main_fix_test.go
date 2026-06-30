package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// In these tests stdin is a strings.Reader (not an *os.File), so the CLI
// treats input as piped and --fix prints the redacted payload to stdout while
// routing the report to stderr. That makes stdout assertable as the clean
// text and stderr as the human report.

func TestFixPipeRedactsToStdout(t *testing.T) {
	const in = "key=AKIAIOSFODNN7EXAMPLE\nmail=jane.doe@corp.internal\nip=10.0.12.34\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--fix", "--quiet"}, strings.NewReader(in), &out, &errBuf)
	if code != exitFound {
		t.Fatalf("exit = %d, want %d (found); stderr=%q", code, exitFound, errBuf.String())
	}
	got := out.String()

	// Shape-preserving stand-ins are present...
	for _, want := range []string{"AKIAREDACTED", "REDACTED@corp.internal", "x.x.x.x"} {
		if !strings.Contains(got, want) {
			t.Errorf("stdout = %q, want it to contain %q", got, want)
		}
	}
	// ...and none of the original secret material survives.
	for _, secret := range []string{"AKIAIOSFODNN7EXAMPLE", "jane.doe", "10.0.12.34"} {
		if strings.Contains(got, secret) {
			t.Errorf("stdout leaked %q: %q", secret, got)
		}
	}
	// Untouched surrounding structure is preserved verbatim.
	for _, frag := range []string{"key=", "mail=", "ip="} {
		if !strings.Contains(got, frag) {
			t.Errorf("stdout = %q, want it to preserve %q", got, frag)
		}
	}
}

func TestFixPipeCleanPassesThrough(t *testing.T) {
	const in = "nothing sensitive at all here\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--fix", "--quiet"}, strings.NewReader(in), &out, &errBuf)
	if code != exitClean {
		t.Fatalf("exit = %d, want %d (clean)", code, exitClean)
	}
	// Clean input flows through byte-for-byte so the tool composes in pipes.
	if out.String() != in {
		t.Errorf("clean --fix passthrough = %q, want %q", out.String(), in)
	}
}

func TestFixStrategyFull(t *testing.T) {
	const in = "k=sk-proj-abcdefghijklmnopqrstuvwxyz0123\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--fix", "--quiet", "--strategy", "full"}, strings.NewReader(in), &out, &errBuf)
	if code != exitFound {
		t.Fatalf("exit = %d, want %d", code, exitFound)
	}
	if !strings.Contains(out.String(), "[REDACTED-SECRET]") {
		t.Errorf("full strategy stdout = %q, want [REDACTED-SECRET]", out.String())
	}
	if strings.Contains(out.String(), "sk-") {
		t.Errorf("full strategy leaked scheme hint: %q", out.String())
	}
}

func TestFixStrategyHashInlineValue(t *testing.T) {
	// Same secret twice → same tag; exercise the --strategy=hash inline form.
	const in = "a=AKIAIOSFODNN7EXAMPLE b=AKIAIOSFODNN7EXAMPLE\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--fix", "--quiet", "--strategy=hash"}, strings.NewReader(in), &out, &errBuf)
	if code != exitFound {
		t.Fatalf("exit = %d, want %d", code, exitFound)
	}
	got := out.String()
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("hash strategy leaked secret: %q", got)
	}
	if !strings.Contains(got, "[SECRET:") {
		t.Errorf("hash strategy stdout = %q, want a [SECRET:<hash>] tag", got)
	}
}

func TestFixReportGoesToStderrNotStdout(t *testing.T) {
	// Without --quiet, the human report must land on stderr so it never
	// contaminates the redacted payload on stdout.
	const in = "key=AKIAIOSFODNN7EXAMPLE\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--fix"}, strings.NewReader(in), &out, &errBuf)
	if code != exitFound {
		t.Fatalf("exit = %d, want %d", code, exitFound)
	}
	if !strings.Contains(errBuf.String(), "aws-access-key") {
		t.Errorf("stderr = %q, want the report there", errBuf.String())
	}
	// stdout is the payload only: the redacted token, no table header.
	if strings.Contains(out.String(), "TYPE") || strings.Contains(out.String(), "things you'd regret") {
		t.Errorf("stdout = %q, should not contain the human report", out.String())
	}
	if !strings.Contains(out.String(), "AKIAREDACTED") {
		t.Errorf("stdout = %q, want the redacted payload", out.String())
	}
}

func TestFixJSONReportToStderr(t *testing.T) {
	// In pipe --fix mode with --json, stdout is the redacted text and the JSON
	// report goes to stderr (and must still be valid, leak-free JSON).
	const in = "key=AKIAIOSFODNN7EXAMPLE\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--fix", "--json"}, strings.NewReader(in), &out, &errBuf)
	if code != exitFound {
		t.Fatalf("exit = %d, want %d", code, exitFound)
	}
	if !strings.Contains(out.String(), "AKIAREDACTED") {
		t.Errorf("stdout payload = %q, want redacted token", out.String())
	}
	var doc struct {
		Tool  string `json:"tool"`
		Total int    `json:"total"`
	}
	if err := json.Unmarshal(errBuf.Bytes(), &doc); err != nil {
		t.Fatalf("stderr is not valid JSON: %v\n%s", err, errBuf.String())
	}
	if doc.Tool != "leakpeek" || doc.Total != 1 {
		t.Errorf("json report = %q/%d, want leakpeek/1", doc.Tool, doc.Total)
	}
}

func TestStrategyRequiresValue(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--strategy"}, strings.NewReader(""), &out, &errBuf)
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d (usage)", code, exitUsage)
	}
	if !strings.Contains(errBuf.String(), "--strategy needs a value") {
		t.Errorf("stderr = %q, want a missing-value message", errBuf.String())
	}
}

func TestStrategyRejectsUnknownValue(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--strategy", "rot13"}, strings.NewReader(""), &out, &errBuf)
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d (usage)", code, exitUsage)
	}
	if !strings.Contains(errBuf.String(), "unknown --strategy") {
		t.Errorf("stderr = %q, want an unknown-strategy message", errBuf.String())
	}
}
