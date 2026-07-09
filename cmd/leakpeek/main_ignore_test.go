package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeIgnore creates a temp ignore file with the given lines and returns its
// path, for driving --ignore in the run() integration tests.
func writeIgnore(t *testing.T, lines string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "test.leakpeekignore")
	if err := os.WriteFile(p, []byte(lines), 0o644); err != nil {
		t.Fatalf("writing ignore file: %v", err)
	}
	return p
}

// A synthetic AKIA-shaped key: matches the detector without being a real
// credential, so push protection stays quiet.
const fakeAWSKey = "AKIAIOSFODNN7EXAMPLE"

func TestIgnoreSuppressesSingleFindingCleanExit(t *testing.T) {
	// The ONLY finding is the fake AWS key; allowlisting it must yield a clean
	// exit (acceptance: "if all findings are suppressed, exit clean").
	ig := writeIgnore(t, "/^AKIA[0-9A-Z]+$/\n")
	in := "leak: " + fakeAWSKey + " here\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--no-ignore", "--ignore", ig}, strings.NewReader(in), &out, &errBuf)
	if code != exitClean {
		t.Fatalf("exit = %d, want %d (all findings suppressed) — out=%q", code, exitClean, out.String())
	}
	// The human report should note the suppression.
	if !strings.Contains(out.String(), "suppressed by .leakpeekignore") {
		t.Errorf("output = %q, want a suppression footer", out.String())
	}
}

func TestIgnoreLiteralSuppression(t *testing.T) {
	ig := writeIgnore(t, "# known-safe placeholder\nuser@example.com\n")
	in := "contact user@example.com for details\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--no-ignore", "--ignore", ig}, strings.NewReader(in), &out, &errBuf)
	if code != exitClean {
		t.Fatalf("exit = %d, want %d (email suppressed) — out=%q", code, exitClean, out.String())
	}
}

func TestIgnoreLeavesOtherFindings(t *testing.T) {
	// Two findings; suppress only the email. The AWS key must still fire and
	// the process still exits "found".
	ig := writeIgnore(t, "safe@example.com\n")
	in := "mail safe@example.com key " + fakeAWSKey + "\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--no-ignore", "--ignore", ig}, strings.NewReader(in), &out, &errBuf)
	if code != exitFound {
		t.Fatalf("exit = %d, want %d (aws key still found)", code, exitFound)
	}
	if !strings.Contains(out.String(), "aws-access-key") {
		t.Errorf("report = %q, want it to still name aws-access-key", out.String())
	}
	if !strings.Contains(out.String(), "suppressed by .leakpeekignore") {
		t.Errorf("report = %q, want a suppression footer for the email", out.String())
	}
	// The email detector must be gone from the report.
	if strings.Contains(out.String(), "email") {
		t.Errorf("report = %q, want the suppressed email finding to be absent", out.String())
	}
}

func TestIgnoreJSONReportsIgnoredCount(t *testing.T) {
	ig := writeIgnore(t, "safe@example.com\n")
	in := "mail safe@example.com key " + fakeAWSKey + "\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--json", "--no-ignore", "--ignore", ig}, strings.NewReader(in), &out, &errBuf)
	if code != exitFound {
		t.Fatalf("exit = %d, want %d", code, exitFound)
	}
	var doc struct {
		Total   int  `json:"total"`
		Clean   bool `json:"clean"`
		Ignored int  `json:"ignored"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("json unmarshal: %v — raw=%q", err, out.String())
	}
	if doc.Ignored != 1 {
		t.Errorf("json ignored = %d, want 1", doc.Ignored)
	}
	if doc.Total != 1 {
		t.Errorf("json total = %d, want 1 (only the surviving aws key)", doc.Total)
	}
}

func TestFixDoesNotRedactAllowlistedToken(t *testing.T) {
	// With --fix, an allowlisted token must be left verbatim: suppression
	// happens before redaction, so --fix never scrubs a known-safe value.
	ig := writeIgnore(t, "/^AKIA[0-9A-Z]+$/\n")
	in := "key " + fakeAWSKey + " end"
	var out, errBuf bytes.Buffer
	// Piped input → redacted text goes to stdout; report goes to stderr.
	code := run([]string{"--stdin", "--fix", "--no-ignore", "--ignore", ig}, strings.NewReader(in), &out, &errBuf)
	if code != exitClean {
		t.Fatalf("exit = %d, want %d (all findings suppressed) — stderr=%q", code, exitClean, errBuf.String())
	}
	// stdout is the redacted payload; the key must survive untouched.
	if !strings.Contains(out.String(), fakeAWSKey) {
		t.Errorf("--fix stdout = %q, want the allowlisted key left verbatim", out.String())
	}
}

func TestNoIgnoreDisablesDiscovery(t *testing.T) {
	// Sanity: --no-ignore with no --ignore path behaves like plain scan.
	in := "key " + fakeAWSKey + "\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--no-ignore"}, strings.NewReader(in), &out, &errBuf)
	if code != exitFound {
		t.Fatalf("exit = %d, want %d", code, exitFound)
	}
}

func TestIgnoreEmptyPathIsUsageError(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--ignore", ""}, strings.NewReader(""), &out, &errBuf)
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d for empty --ignore path", code, exitUsage)
	}
}

func TestIgnoreMissingValueIsUsageError(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--ignore"}, strings.NewReader(""), &out, &errBuf)
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d for --ignore with no value", code, exitUsage)
	}
}

func TestIgnoreBadFileIsError(t *testing.T) {
	// A present-but-unparseable ignore file must fail loudly (exit 1), not
	// silently fail open.
	ig := writeIgnore(t, "/pk_(unterminated/\n")
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--ignore", ig}, strings.NewReader("x\n"), &out, &errBuf)
	if code != exitError {
		t.Fatalf("exit = %d, want %d for a broken ignore file", code, exitError)
	}
}
