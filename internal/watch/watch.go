// Package watch implements leakpeek's watch mode (PLAN.md §8 item 1): a
// foreground daemon that taps the clipboard on a debounced interval and, the
// instant a secret lands on it, raises an alert — before you ever reach the
// prompt box.
//
// The design keeps the loop pure and testable. A Watcher owns no clock, no
// clipboard, and no notifier of its own; those are injected as function
// fields, so tests drive it with a fake tick channel, an in-memory clipboard,
// and a recording notifier — no sleeping, no real processes, no flake.
//
// Privacy stays intact: watch mode stores nothing. It keeps exactly one thing
// in memory between ticks — a hash of the last clipboard value it saw — so it
// can tell "the clipboard changed" from "same text, polled again" without
// ever retaining the clipboard contents themselves. See §9 (out of scope):
// leakpeek is not a clipboard manager; it frisks once and forgets.
package watch

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/rwrife/leakpeek/internal/detect"
)

// DefaultInterval is the poll cadence when the caller doesn't specify one.
// 800ms is snappy enough to catch a paste-worthy copy almost immediately
// while keeping the shell-out cost negligible.
const DefaultInterval = 800 * time.Millisecond

// MinInterval clamps absurdly small intervals so watch mode can't busy-spin
// the clipboard tool. Anything below this is raised to it.
const MinInterval = 100 * time.Millisecond

// ScanResult is the minimal summary the watcher needs from a scan to compose
// an alert. It is produced by the injected Scan func so watch has no build
// dependency on the report package.
type ScanResult struct {
	Total int      // number of findings
	Kinds []string // distinct kinds present, e.g. ["secret","pii"]
}

// Watcher polls a clipboard source and alerts on findings. All collaborators
// are injected so the loop is deterministic under test.
type Watcher struct {
	// Read returns the current clipboard text. Errors are surfaced to OnError
	// and otherwise skipped — a transient clipboard hiccup must not kill the
	// watch.
	Read func() (string, error)
	// Scan runs the detection engine over text and summarizes the result.
	Scan func(text string) ScanResult
	// Notify raises the alert for a hit. It is called at most once per
	// distinct dirty clipboard value.
	Notify func(total int, kinds []string)
	// Interval is the poll cadence. Zero means DefaultInterval; values below
	// MinInterval are clamped up.
	Interval time.Duration

	// Now returns the current time; defaults to time.Now. Injected for tests
	// that assert on the startup banner without a real clock.
	Now func() time.Time

	// OnHit, if set, is called after Notify with a short human line for the
	// foreground log (e.g. written to stderr). Optional.
	OnHit func(total int, kinds []string, at time.Time)
	// OnClean, if set, is called when a changed clipboard scans clean, for an
	// optional quiet "all good" log line. Optional; off by default to keep
	// watch mode silent until it has something to say.
	OnClean func(at time.Time)
	// OnError, if set, receives non-fatal read/scan errors. Optional.
	OnError func(err error)
}

// Run watches until ctx is canceled, driving the loop from ticks delivered on
// tick. Production callers pass a time.Ticker's channel; tests pass a channel
// they control. Run returns ctx.Err() when canceled (nil on a clean external
// stop is the caller's choice of context).
//
// Semantics per tick:
//   - read the clipboard (skip on error, reporting via OnError),
//   - if the value is unchanged since last tick, do nothing (debounce),
//   - if it changed, scan it; on a hit, Notify once; on clean, OnClean.
//
// The very first observed value is scanned too, so starting watch mode with a
// secret already sitting on the clipboard alerts immediately rather than
// waiting for the next copy.
func (w *Watcher) Run(ctx context.Context, tick <-chan time.Time) error {
	var (
		haveLast bool
		lastSum  [32]byte
	)

	step := func() {
		text, err := w.Read()
		if err != nil {
			if w.OnError != nil {
				w.OnError(err)
			}
			return
		}
		sum := sha256.Sum256([]byte(text))
		if haveLast && sum == lastSum {
			return // unchanged since last observation; nothing to do
		}
		haveLast = true
		lastSum = sum

		res := w.Scan(text)
		now := w.now()
		if res.Total > 0 {
			w.Notify(res.Total, res.Kinds)
			if w.OnHit != nil {
				w.OnHit(res.Total, res.Kinds, now)
			}
			return
		}
		if w.OnClean != nil {
			w.OnClean(now)
		}
	}

	// Observe the initial clipboard state immediately, before the first tick,
	// so a pre-existing secret is caught at startup.
	step()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case _, ok := <-tick:
			if !ok {
				return nil // ticker closed: treat as a clean stop
			}
			step()
		}
	}
}

// now returns the injected clock or time.Now.
func (w *Watcher) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// EngineScan adapts a *detect.Engine into the Scan func the Watcher expects.
// It runs the engine and reduces the findings to a total + distinct,
// sorted-for-stability kind list. It never retains the scanned text.
func EngineScan(engine *detect.Engine) func(string) ScanResult {
	return func(text string) ScanResult {
		findings := engine.Scan(text)
		return ScanResult{Total: len(findings), Kinds: distinctKinds(findings)}
	}
}

// distinctKinds returns the unique finding kinds in stable sorted order.
func distinctKinds(findings []detect.Finding) []string {
	if len(findings) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(findings))
	for _, f := range findings {
		seen[string(f.Kind)] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// NormalizeInterval applies the zero-default and the MinInterval floor.
func NormalizeInterval(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultInterval
	}
	if d < MinInterval {
		return MinInterval
	}
	return d
}

// Banner returns the one-line startup message for watch mode, naming the poll
// interval and how to stop. Kept here so main.go and tests agree on wording.
func Banner(interval time.Duration) string {
	return fmt.Sprintf("👀 leakpeek is watching your clipboard every %s. Press Ctrl-C to stop.", interval)
}

// WriteBanner writes Banner(interval) followed by a newline to w. A tiny
// convenience so callers don't re-add the newline.
func WriteBanner(w io.Writer, interval time.Duration) {
	fmt.Fprintln(w, Banner(interval))
}
