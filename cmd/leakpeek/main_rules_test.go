package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRuleFile drops a rule file in a temp dir and returns its path.
func writeRuleFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing rule file: %v", err)
	}
	return path
}

func TestRulesFlagDetectsCustomToken(t *testing.T) {
	rulePath := writeRuleFile(t, `
[[rule]]
name  = "acme-employee-id"
regex = "EMP-[0-9]{6}"
`)
	const in = "ping EMP-123456 about the ticket\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--rules", rulePath}, strings.NewReader(in), &out, &errBuf)
	if code != exitFound {
		t.Fatalf("exit = %d, want %d found (stderr: %q)", code, exitFound, errBuf.String())
	}
	if !strings.Contains(out.String(), "acme-employee-id") {
		t.Errorf("report = %q, want it to name the custom detector", out.String())
	}
	// Must not echo the raw match back into the report.
	if strings.Contains(out.String(), "EMP-123456") {
		t.Errorf("report leaked the raw match: %q", out.String())
	}
}

func TestRulesFlagInlineValueForm(t *testing.T) {
	rulePath := writeRuleFile(t, "[[rule]]\nname=\"tok\"\nregex=\"ZZZ-[0-9]+\"\n")
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--rules=" + rulePath}, strings.NewReader("ZZZ-42\n"), &out, &errBuf)
	if code != exitFound {
		t.Fatalf("exit = %d, want %d found (stderr: %q)", code, exitFound, errBuf.String())
	}
	if !strings.Contains(out.String(), "tok") {
		t.Errorf("report = %q, want the custom detector name", out.String())
	}
}

func TestRulesFlagFixRedactsCustom(t *testing.T) {
	rulePath := writeRuleFile(t, "[[rule]]\nname=\"tok\"\nregex=\"ZZZ-[0-9]+\"\n")
	var out, errBuf bytes.Buffer
	// Pipe mode: redacted text goes to stdout.
	code := run([]string{"--rules", rulePath, "--fix"}, strings.NewReader("val=ZZZ-42 done"), &out, &errBuf)
	if code != exitFound {
		t.Fatalf("exit = %d, want %d (stderr: %q)", code, exitFound, errBuf.String())
	}
	if strings.Contains(out.String(), "ZZZ-42") {
		t.Errorf("redacted stdout still contains the secret: %q", out.String())
	}
	if !strings.Contains(out.String(), "REDACTED") {
		t.Errorf("redacted stdout = %q, want a REDACTED marker", out.String())
	}
}

func TestRulesFlagMissingValueIsUsageError(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--rules"}, strings.NewReader(""), &out, &errBuf)
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d usage", code, exitUsage)
	}
	if !strings.Contains(errBuf.String(), "--rules needs a path") {
		t.Errorf("stderr = %q, want a --rules usage message", errBuf.String())
	}
}

func TestRulesFlagBadFileIsOperationalError(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--rules", "/no/such/rules.toml"}, strings.NewReader("x\n"), &out, &errBuf)
	if code != exitError {
		t.Fatalf("exit = %d, want %d error", code, exitError)
	}
	if !strings.Contains(errBuf.String(), "leakpeek:") {
		t.Errorf("stderr = %q, want a leakpeek error prefix", errBuf.String())
	}
}

func TestRulesFlagBadRegexReportsFileLine(t *testing.T) {
	rulePath := writeRuleFile(t, "[[rule]]\nname=\"x\"\nregex=\"([oops\"\n")
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--rules", rulePath}, strings.NewReader("x\n"), &out, &errBuf)
	if code != exitError {
		t.Fatalf("exit = %d, want %d error", code, exitError)
	}
	if !strings.Contains(errBuf.String(), "invalid regexp") {
		t.Errorf("stderr = %q, want an invalid-regexp diagnostic", errBuf.String())
	}
}

func TestHelpMentionsRulesFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--help"}, strings.NewReader(""), &out, &errBuf)
	if code != exitClean {
		t.Fatalf("exit = %d, want %d", code, exitClean)
	}
	if !strings.Contains(out.String(), "--rules") {
		t.Errorf("help text = %q, want it to document --rules", out.String())
	}
}
