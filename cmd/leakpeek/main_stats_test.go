package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// statsPath points XDG_STATE_HOME at a temp dir so stats tests never touch the
// real user state dir, and returns where the file will land.
func statsPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", dir)
	return filepath.Join(dir, "leakpeek", "stats.json")
}

func TestStatsRecordOptInWritesFile(t *testing.T) {
	path := statsPath(t)
	const in = "leak: AKIAIOSFODNN7EXAMPLE here\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--stats-record"}, strings.NewReader(in), &out, &errBuf)
	if code != exitFound {
		t.Fatalf("exit = %d, want found (stderr %q)", code, errBuf.String())
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stats file not written: %v", err)
	}
}

func TestStatsNotRecordedByDefault(t *testing.T) {
	path := statsPath(t)
	const in = "leak: AKIAIOSFODNN7EXAMPLE here\n"
	var out, errBuf bytes.Buffer
	_ = run([]string{"--stdin"}, strings.NewReader(in), &out, &errBuf)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("stats recorded without opt-in (err=%v)", err)
	}
}

func TestStatsRecordViaEnv(t *testing.T) {
	path := statsPath(t)
	t.Setenv("LEAKPEEK_STATS", "1")
	const in = "leak: AKIAIOSFODNN7EXAMPLE here\n"
	var out, errBuf bytes.Buffer
	_ = run([]string{"--stdin"}, strings.NewReader(in), &out, &errBuf)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("env opt-in didn't record: %v", err)
	}
}

func TestStatsShowJSON(t *testing.T) {
	statsPath(t)
	// Record a leak first.
	var out, errBuf bytes.Buffer
	_ = run([]string{"--stdin", "--stats-record"},
		strings.NewReader("AKIAIOSFODNN7EXAMPLE\n"), &out, &errBuf)

	out.Reset()
	errBuf.Reset()
	code := run([]string{"--stats", "--json"}, strings.NewReader(""), &out, &errBuf)
	if code != exitClean {
		t.Fatalf("exit = %d, want clean (stderr %q)", code, errBuf.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("stats --json not valid JSON: %v\n%s", err, out.String())
	}
	if doc["totalLeaksStopped"].(float64) != 1 {
		t.Fatalf("totalLeaksStopped = %v, want 1", doc["totalLeaksStopped"])
	}
}

func TestStatsHumanExitsClean(t *testing.T) {
	statsPath(t)
	var out, errBuf bytes.Buffer
	code := run([]string{"--stats"}, strings.NewReader(""), &out, &errBuf)
	if code != exitClean {
		t.Fatalf("exit = %d, want clean", code)
	}
	if !strings.Contains(out.String(), "never transmitted") {
		t.Fatalf("stats output missing local-only note:\n%s", out.String())
	}
}

func TestStatsResetAndClear(t *testing.T) {
	path := statsPath(t)
	var out, errBuf bytes.Buffer
	_ = run([]string{"--stdin", "--stats-record"},
		strings.NewReader("AKIAIOSFODNN7EXAMPLE\n"), &out, &errBuf)

	// Reset keeps the file but zeroes counts.
	out.Reset()
	if code := run([]string{"--stats-reset"}, strings.NewReader(""), &out, &errBuf); code != exitClean {
		t.Fatalf("stats-reset exit = %d", code)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("reset should keep the file: %v", err)
	}

	// Clear deletes the file.
	out.Reset()
	if code := run([]string{"--stats-clear"}, strings.NewReader(""), &out, &errBuf); code != exitClean {
		t.Fatalf("stats-clear exit = %d", code)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("clear should delete the file (err=%v)", err)
	}
}

// A clean run under recording bumps runs but not leaks.
func TestStatsCleanRunRecorded(t *testing.T) {
	statsPath(t)
	var out, errBuf bytes.Buffer
	_ = run([]string{"--stdin", "--stats-record"},
		strings.NewReader("nothing sensitive here\n"), &out, &errBuf)

	out.Reset()
	_ = run([]string{"--stats", "--json"}, strings.NewReader(""), &out, &errBuf)
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if doc["totalRuns"].(float64) != 1 {
		t.Fatalf("totalRuns = %v, want 1", doc["totalRuns"])
	}
	if doc["totalLeaksStopped"].(float64) != 0 {
		t.Fatalf("totalLeaksStopped = %v, want 0 for clean run", doc["totalLeaksStopped"])
	}
}
