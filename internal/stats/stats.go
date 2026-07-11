// Package stats is leakpeek's fully-local, opt-in vanity counter (PLAN.md §8
// item 10, issue #24). It remembers how many leaks the bouncer has stopped so
// it can occasionally brag — "🛡️ leakpeek has stopped 47 leaks this month." —
// without ever phoning home. Numbers live in a small JSON file on disk and
// never leave the machine.
//
// The whole package is built around leakpeek's "it forgets" ethos: recording
// is strictly opt-in, and every write is best-effort. A stats failure must
// NEVER change a scan's exit code or block a redaction — a vanity counter is
// not allowed to break the tool. Callers reflect that by ignoring the error
// from Record (or logging it at most).
package stats

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	filePerm os.FileMode = 0o600
	dirPerm  os.FileMode = 0o700

	// dayFmt / monthFmt are the calendar bucket keys. Local time is used so a
	// "day" matches the user's wall clock, which is what a streak should track.
	dayFmt   = "2006-01-02"
	monthFmt = "2006-01"
)

// Stats is the persisted counter document. It is intentionally a flat set of
// counters — no per-detector history, no charts (out of scope in #24) — just
// enough to answer "how much has this saved me?".
type Stats struct {
	TotalLeaksStopped int            `json:"totalLeaksStopped"`
	TotalRuns         int            `json:"totalRuns"`
	ByMonth           map[string]int `json:"byMonth"` // "2026-07" -> leaks stopped that month
	ByKind            map[string]int `json:"byKind"`  // "secret" -> leaks stopped involving that kind
	ByDay             map[string]int `json:"byDay"`   // "2026-07-11" -> runs recorded that day (for streaks)
	FirstSeen         string         `json:"firstSeen,omitempty"`
	LastLeakAt        string         `json:"lastLeakAt,omitempty"`
}

// newStats returns an empty, fully-initialized Stats so callers never have to
// nil-check the maps.
func newStats() *Stats {
	return &Stats{
		ByMonth: map[string]int{},
		ByKind:  map[string]int{},
		ByDay:   map[string]int{},
	}
}

// ensureMaps defends against a hand-edited or partial file that decoded with
// nil maps, so Record can always write into them.
func (s *Stats) ensureMaps() {
	if s.ByMonth == nil {
		s.ByMonth = map[string]int{}
	}
	if s.ByKind == nil {
		s.ByKind = map[string]int{}
	}
	if s.ByDay == nil {
		s.ByDay = map[string]int{}
	}
}

// DefaultPath returns the stats file location:
// $XDG_STATE_HOME/leakpeek/stats.json, falling back to
// ~/.local/state/leakpeek/stats.json when XDG_STATE_HOME is unset. If even the
// home directory can't be determined, it returns "" and callers treat stats as
// unavailable (a silent no-op, per the never-break-a-scan rule).
func DefaultPath() string {
	dir := stateDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "leakpeek", "stats.json")
}

// stateDir resolves the XDG state base dir with the documented fallback.
func stateDir() string {
	if x := os.Getenv("XDG_STATE_HOME"); x != "" {
		return x
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".local", "state")
}

// Load reads and decodes the stats file at path. A missing file is not an
// error — it returns a fresh, empty Stats so a first run starts from zero.
// Callers that care about I/O failures (e.g. --stats) get the error; the
// recording path swallows it.
func Load(path string) (*Stats, error) {
	if path == "" {
		return newStats(), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return newStats(), nil
		}
		return nil, fmt.Errorf("reading stats: %w", err)
	}
	s := newStats()
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("parsing stats %s: %w", path, err)
	}
	s.ensureMaps()
	return s, nil
}

// Save atomically writes s to path, creating parent dirs as needed. It writes
// to a temp file and renames, so a crash mid-write can't corrupt the counter.
func Save(path string, s *Stats) error {
	if path == "" {
		return errors.New("no stats path available")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("creating stats dir: %w", err)
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding stats: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "stats-*.tmp")
	if err != nil {
		return fmt.Errorf("creating stats temp file: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we bail before the rename.
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(filePerm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod stats temp file: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing stats: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing stats temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("finalizing stats: %w", err)
	}
	return nil
}

// Record folds a single run's outcome into s. leaked reports whether the run
// stopped at least one leak (>=1 finding); kinds is the set of distinct
// finding kinds present in that run (only consulted when leaked). now is the
// run time (injected for testability). Every run bumps TotalRuns and the
// per-day counter (which powers the streak); a leaking run additionally bumps
// TotalLeaksStopped, the current month, each present kind, and LastLeakAt.
func (s *Stats) Record(leaked bool, kinds []string, now time.Time) {
	s.ensureMaps()

	day := now.Format(dayFmt)
	if s.FirstSeen == "" {
		s.FirstSeen = day
	}
	s.TotalRuns++
	s.ByDay[day]++

	if !leaked {
		return
	}
	s.TotalLeaksStopped++
	s.ByMonth[now.Format(monthFmt)]++
	// Dedupe kinds defensively so a caller passing repeats can't over-count.
	seen := map[string]struct{}{}
	for _, k := range kinds {
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		s.ByKind[k]++
	}
	s.LastLeakAt = now.UTC().Format(time.RFC3339)
}

// RecordAndSave loads the stats at path, folds in one run, and saves. It is the
// one call the scan path makes. It is best-effort: ANY failure (no path,
// unwritable dir, parse error) is returned but callers must NOT let it affect
// the scan's exit code. On a load failure it does not attempt a save (we won't
// clobber an unreadable-but-present file with a fresh zero doc).
func RecordAndSave(path string, leaked bool, kinds []string, now time.Time) error {
	if path == "" {
		return errors.New("no stats path available")
	}
	s, err := Load(path)
	if err != nil {
		return err
	}
	s.Record(leaked, kinds, now)
	return Save(path, s)
}

// ThisMonth returns the leaks-stopped count for now's month.
func (s *Stats) ThisMonth(now time.Time) int {
	return s.ByMonth[now.Format(monthFmt)]
}

// Streak returns the number of consecutive calendar days, ending at now's day,
// on which at least one run was recorded. If today has no recorded run the
// streak is 0 (the chain is already broken). A gap of one or more days breaks
// it. This is the "consecutive days with >=1 recorded run" metric from #24.
func (s *Stats) Streak(now time.Time) int {
	if len(s.ByDay) == 0 {
		return 0
	}
	streak := 0
	day := now
	for {
		if s.ByDay[day.Format(dayFmt)] > 0 {
			streak++
			day = day.AddDate(0, 0, -1)
			continue
		}
		break
	}
	return streak
}

// TopKinds returns the byKind buckets sorted by descending count (ties broken
// alphabetically for stable output), capped at n entries. n <= 0 returns all.
func (s *Stats) TopKinds(n int) []KindCount {
	out := make([]KindCount, 0, len(s.ByKind))
	for k, c := range s.ByKind {
		out = append(out, KindCount{Kind: k, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Kind < out[j].Kind
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// KindCount is one entry in a TopKinds ranking.
type KindCount struct {
	Kind  string
	Count int
}

// Reset zeroes all counters but keeps the FirstSeen date, so a reset run still
// remembers when leakpeek first started counting for this user.
func (s *Stats) Reset() {
	first := s.FirstSeen
	*s = *newStats()
	s.FirstSeen = first
}

// Clear deletes the stats file at path. A missing file is fine (returns
// removed=false, nil). It returns removed=true when a file was actually
// deleted.
func Clear(path string) (removed bool, err error) {
	if path == "" {
		return false, nil
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("clearing stats: %w", err)
	}
	return true, nil
}

// RenderJSON writes the raw stats object as pretty JSON — the machine-readable
// form of `leakpeek --stats --json`.
func RenderJSON(w io.Writer, s *Stats) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}

// Render writes a human-friendly summary of s to w — the body of
// `leakpeek --stats`. now sets "this month" and the streak's anchor day. It is
// deliberately calm and local-only in tone; the closing line reminds the user
// the numbers never leave the machine.
func Render(w io.Writer, s *Stats, now time.Time) {
	total := s.TotalLeaksStopped
	noun := "leak"
	if total != 1 {
		noun = "leaks"
	}
	fmt.Fprintf(w, "🛡️  leakpeek has stopped %d %s (across %d runs).\n", total, noun, s.TotalRuns)

	month := s.ThisMonth(now)
	mNoun := "leak"
	if month != 1 {
		mNoun = "leaks"
	}
	fmt.Fprintf(w, "📅 This month: %d %s stopped.\n", month, mNoun)

	streak := s.Streak(now)
	dNoun := "day"
	if streak != 1 {
		dNoun = "days"
	}
	fmt.Fprintf(w, "🔥 Streak: %d %s in a row.\n", streak, dNoun)

	if top := s.TopKinds(3); len(top) > 0 {
		fmt.Fprint(w, "🏷️  Top kinds:")
		for i, kc := range top {
			sep := " "
			if i > 0 {
				sep = ", "
			}
			fmt.Fprintf(w, "%s%s×%d", sep, kc.Kind, kc.Count)
		}
		fmt.Fprintln(w)
	}

	if s.FirstSeen != "" {
		fmt.Fprintf(w, "🗓️  Counting since %s.\n", s.FirstSeen)
	}

	fmt.Fprintln(w, "🔒 Local-only. These numbers live on this machine and are never transmitted.")
}
