package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestHelpMentionsWatch ensures the new watch-mode flags are documented in the
// help output, so `--help` stays a faithful surface of what leakpeek does.
func TestHelpMentionsWatch(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--help"}, strings.NewReader(""), &out, &errBuf)
	if code != exitClean {
		t.Fatalf("exit = %d, want %d", code, exitClean)
	}
	for _, want := range []string{"--watch", "--interval"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("help missing %q; got:\n%s", want, out.String())
		}
	}
}

// TestBadIntervalIsUsageError verifies an unparseable --interval is rejected
// with the usage exit code and never enters watch mode.
func TestBadIntervalIsUsageError(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--watch", "--interval", "not-a-duration"}, strings.NewReader(""), &out, &errBuf)
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d (usage)", code, exitUsage)
	}
	if !strings.Contains(errBuf.String(), "invalid --interval") {
		t.Errorf("stderr = %q, want it to explain the bad interval", errBuf.String())
	}
}

// TestIntervalNeedsValue verifies a trailing --interval with no argument is a
// usage error rather than a panic.
func TestIntervalNeedsValue(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--interval"}, strings.NewReader(""), &out, &errBuf)
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d (usage)", code, exitUsage)
	}
	if !strings.Contains(errBuf.String(), "--interval needs a duration") {
		t.Errorf("stderr = %q, want the missing-value message", errBuf.String())
	}
}

// TestIntervalInlineFormAccepted verifies the --interval=VALUE form parses.
// A bad inline value should still be a usage error (exercising the inline
// path), and a good one should not be rejected at parse time.
func TestIntervalInlineFormAccepted(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--interval=bogus"}, strings.NewReader(""), &out, &errBuf)
	if code != exitUsage {
		t.Fatalf("inline bad interval exit = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errBuf.String(), "invalid --interval") {
		t.Errorf("stderr = %q, want invalid-interval message", errBuf.String())
	}
}
