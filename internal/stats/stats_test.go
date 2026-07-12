package stats

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse("2006-01-02", s)
	if err != nil {
		t.Fatalf("parsing %q: %v", s, err)
	}
	return tm
}

func TestRecordLeakAndClean(t *testing.T) {
	s := newStats()
	now := mustTime(t, "2026-07-11")

	s.Record(true, []string{"secret", "pii", "secret"}, now) // dupe kind
	if s.TotalLeaksStopped != 1 {
		t.Fatalf("TotalLeaksStopped = %d, want 1", s.TotalLeaksStopped)
	}
	if s.TotalRuns != 1 {
		t.Fatalf("TotalRuns = %d, want 1", s.TotalRuns)
	}
	if got := s.ByMonth["2026-07"]; got != 1 {
		t.Fatalf("ByMonth[2026-07] = %d, want 1", got)
	}
	if got := s.ByKind["secret"]; got != 1 {
		t.Fatalf("dupe kind over-counted: ByKind[secret] = %d, want 1", got)
	}
	if got := s.ByKind["pii"]; got != 1 {
		t.Fatalf("ByKind[pii] = %d, want 1", got)
	}
	if s.FirstSeen != "2026-07-11" {
		t.Fatalf("FirstSeen = %q, want 2026-07-11", s.FirstSeen)
	}
	if s.LastLeakAt == "" {
		t.Fatalf("LastLeakAt not set")
	}

	// A clean run bumps only runs + day, not leaks.
	s.Record(false, nil, now)
	if s.TotalLeaksStopped != 1 {
		t.Fatalf("clean run changed leaks: %d", s.TotalLeaksStopped)
	}
	if s.TotalRuns != 2 {
		t.Fatalf("TotalRuns = %d, want 2", s.TotalRuns)
	}
}

func TestStreakAcrossGap(t *testing.T) {
	s := newStats()
	// Recorded days: 09, 10, 11 (consecutive), plus an earlier 07 (gap on 08).
	for _, d := range []string{"2026-07-07", "2026-07-09", "2026-07-10", "2026-07-11"} {
		s.Record(false, nil, mustTime(t, d))
	}
	now := mustTime(t, "2026-07-11")
	if got := s.Streak(now); got != 3 {
		t.Fatalf("Streak = %d, want 3 (09,10,11; gap on 08 breaks it)", got)
	}

	// If today has no run, the streak is already broken (0).
	if got := s.Streak(mustTime(t, "2026-07-12")); got != 0 {
		t.Fatalf("Streak with no run today = %d, want 0", got)
	}
}

func TestTopKinds(t *testing.T) {
	s := newStats()
	s.ByKind = map[string]int{"secret": 5, "pii": 5, "network": 2}
	top := s.TopKinds(2)
	if len(top) != 2 {
		t.Fatalf("len = %d, want 2", len(top))
	}
	// Ties broken alphabetically: pii before secret.
	if top[0].Kind != "pii" || top[1].Kind != "secret" {
		t.Fatalf("ordering = %+v, want pii then secret", top)
	}
}

func TestResetKeepsFirstSeen(t *testing.T) {
	s := newStats()
	s.Record(true, []string{"secret"}, mustTime(t, "2026-07-01"))
	s.Reset()
	if s.TotalLeaksStopped != 0 || s.TotalRuns != 0 {
		t.Fatalf("reset didn't zero counters: %+v", s)
	}
	if s.FirstSeen != "2026-07-01" {
		t.Fatalf("reset lost FirstSeen: %q", s.FirstSeen)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leakpeek", "stats.json")
	if err := RecordAndSave(path, true, []string{"secret"}, mustTime(t, "2026-07-11")); err != nil {
		t.Fatalf("RecordAndSave: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.TotalLeaksStopped != 1 {
		t.Fatalf("round-trip TotalLeaksStopped = %d, want 1", got.TotalLeaksStopped)
	}
}

func TestLoadMissingIsEmpty(t *testing.T) {
	got, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("Load missing returned error: %v", err)
	}
	if got.TotalRuns != 0 {
		t.Fatalf("missing file not empty: %+v", got)
	}
}

func TestClear(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")
	if err := Save(path, newStats()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	removed, err := Clear(path)
	if err != nil || !removed {
		t.Fatalf("Clear = (%v, %v), want (true, nil)", removed, err)
	}
	// Second clear: nothing there.
	removed, err = Clear(path)
	if err != nil || removed {
		t.Fatalf("second Clear = (%v, %v), want (false, nil)", removed, err)
	}
}

// TestRecordFailureSwallowed verifies that a write into an unwritable dir
// returns an error (which callers must swallow) rather than panicking or
// corrupting anything.
func TestRecordFailureOnReadonlyDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod-based read-only dir semantics differ on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory permissions")
	}
	base := t.TempDir()
	ro := filepath.Join(base, "ro")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatalf("mkdir ro: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })

	path := filepath.Join(ro, "sub", "stats.json")
	err := RecordAndSave(path, true, []string{"secret"}, time.Now())
	if err == nil {
		t.Fatalf("expected an error writing under a read-only dir")
	}
}

func TestDefaultPathUsesXDGState(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "/tmp/xdgstate")
	got := DefaultPath()
	want := filepath.Join("/tmp/xdgstate", "leakpeek", "stats.json")
	if got != want {
		t.Fatalf("DefaultPath = %q, want %q", got, want)
	}
}

func TestRenderHumanMentionsLocalOnly(t *testing.T) {
	s := newStats()
	s.Record(true, []string{"secret"}, mustTime(t, "2026-07-11"))
	var b strings.Builder
	Render(&b, s, mustTime(t, "2026-07-11"))
	out := b.String()
	if !strings.Contains(out, "never transmitted") {
		t.Fatalf("human render missing local-only assurance:\n%s", out)
	}
	if !strings.Contains(out, "stopped 1 leak") {
		t.Fatalf("human render missing total:\n%s", out)
	}
}
