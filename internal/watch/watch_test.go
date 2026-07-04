package watch

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rwrife/leakpeek/internal/detect"
)

// drive runs w.Run against a manually-fed tick channel in a goroutine and
// returns a function to deliver a tick and a function to stop the watcher and
// wait for Run to return. It lets each test step the loop deterministically
// with no real clock.
func drive(t *testing.T, w *Watcher) (tickOnce func(), stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		_ = w.Run(ctx, ticks)
		close(done)
	}()
	tickOnce = func() {
		select {
		case ticks <- time.Now():
		case <-time.After(time.Second):
			t.Fatal("timed out delivering tick")
		}
	}
	stop = func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for Run to return")
		}
	}
	return tickOnce, stop
}

// recorder captures Notify calls under a mutex so the test goroutine can read
// them safely while the watch goroutine writes them.
type recorder struct {
	mu    sync.Mutex
	hits  []int      // total per Notify call
	kinds [][]string // kinds per Notify call
	clean int        // OnClean call count
}

func (r *recorder) notify(total int, kinds []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hits = append(r.hits, total)
	r.kinds = append(r.kinds, kinds)
}

func (r *recorder) onClean(time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clean++
}

func (r *recorder) snapshot() (hits []int, clean int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]int(nil), r.hits...), r.clean
}

// clip is a tiny mutable clipboard stand-in for tests.
type clip struct {
	mu   sync.Mutex
	text string
	err  error
}

func (c *clip) set(text string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.text = text
}

func (c *clip) setErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.err = err
}

func (c *clip) read() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.text, c.err
}

// scanContains flags a hit whenever the text contains "SECRET", returning a
// fixed kind set. Keeps watch-loop tests independent of the real detectors.
func scanContains(text string) ScanResult {
	if containsSecret(text) {
		return ScanResult{Total: 1, Kinds: []string{"secret"}}
	}
	return ScanResult{}
}

func containsSecret(s string) bool {
	return len(s) >= 6 && (indexOf(s, "SECRET") >= 0)
}

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

func TestInitialDirtyClipboardAlertsAtStartup(t *testing.T) {
	rec := &recorder{}
	c := &clip{text: "here is a SECRET already"}
	w := &Watcher{Read: c.read, Scan: scanContains, Notify: rec.notify, OnClean: rec.onClean}

	tickOnce, stop := drive(t, w)
	defer stop()

	// The initial observation happens before any tick, so give the loop a
	// moment then assert a single hit without ticking.
	waitFor(t, func() bool { h, _ := rec.snapshot(); return len(h) == 1 })
	_ = tickOnce
}

func TestUnchangedClipboardDoesNotReAlert(t *testing.T) {
	rec := &recorder{}
	c := &clip{text: "a SECRET sits here"}
	w := &Watcher{Read: c.read, Scan: scanContains, Notify: rec.notify}

	tickOnce, stop := drive(t, w)
	defer stop()

	waitFor(t, func() bool { h, _ := rec.snapshot(); return len(h) == 1 })

	// Several ticks with identical content must not produce more alerts.
	for i := 0; i < 3; i++ {
		tickOnce()
	}
	// Allow ticks to be processed.
	time.Sleep(20 * time.Millisecond)
	if h, _ := rec.snapshot(); len(h) != 1 {
		t.Fatalf("re-alerted on unchanged clipboard: got %d hits, want 1", len(h))
	}
}

func TestChangeToDirtyThenCleanThenDirty(t *testing.T) {
	rec := &recorder{}
	c := &clip{text: "clean start"}
	w := &Watcher{Read: c.read, Scan: scanContains, Notify: rec.notify, OnClean: rec.onClean}

	tickOnce, stop := drive(t, w)
	defer stop()

	// Initial clean observation → one OnClean, no hits.
	waitFor(t, func() bool { _, cl := rec.snapshot(); return cl == 1 })

	// Change to dirty → one hit.
	c.set("now a SECRET appears")
	tickOnce()
	waitFor(t, func() bool { h, _ := rec.snapshot(); return len(h) == 1 })

	// Change to a different clean value → OnClean increments to 2.
	c.set("cleaned up")
	tickOnce()
	waitFor(t, func() bool { _, cl := rec.snapshot(); return cl == 2 })

	// Change to a different dirty value → second hit.
	c.set("another SECRET here")
	tickOnce()
	waitFor(t, func() bool { h, _ := rec.snapshot(); return len(h) == 2 })
}

func TestReadErrorIsNonFatalAndReported(t *testing.T) {
	rec := &recorder{}
	var mu sync.Mutex
	var errs int
	c := &clip{err: errors.New("clipboard boom")}
	w := &Watcher{
		Read:   c.read,
		Scan:   scanContains,
		Notify: rec.notify,
		OnError: func(error) {
			mu.Lock()
			errs++
			mu.Unlock()
		},
	}

	tickOnce, stop := drive(t, w)
	defer stop()

	// Initial read errors once; a tick errors again. The loop must survive.
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return errs >= 1 })
	tickOnce()
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return errs >= 2 })

	// Now recover: set clean text; no hit, no further error.
	c.setErr(nil)
	c.set("recovered SECRET now")
	tickOnce()
	waitFor(t, func() bool { h, _ := rec.snapshot(); return len(h) == 1 })

	if h, _ := rec.snapshot(); len(h) != 1 {
		t.Fatalf("hits after recovery = %d, want 1", len(h))
	}
}

func TestCanceledContextStopsRun(t *testing.T) {
	c := &clip{text: "idle"}
	w := &Watcher{Read: c.read, Scan: scanContains, Notify: func(int, []string) {}}

	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time)
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx, ticks) }()

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestClosedTickerStopsRunCleanly(t *testing.T) {
	c := &clip{text: "idle"}
	w := &Watcher{Read: c.read, Scan: scanContains, Notify: func(int, []string) {}}

	ticks := make(chan time.Time)
	done := make(chan error, 1)
	go func() { done <- w.Run(context.Background(), ticks) }()

	close(ticks)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil on closed ticker", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return after ticker close")
	}
}

func TestNormalizeInterval(t *testing.T) {
	cases := []struct {
		in, want time.Duration
	}{
		{0, DefaultInterval},
		{-5 * time.Second, DefaultInterval},
		{10 * time.Millisecond, MinInterval},
		{MinInterval, MinInterval},
		{2 * time.Second, 2 * time.Second},
	}
	for _, c := range cases {
		if got := NormalizeInterval(c.in); got != c.want {
			t.Errorf("NormalizeInterval(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestBannerMentionsIntervalAndStop(t *testing.T) {
	b := Banner(2 * time.Second)
	if indexOf(b, "2s") < 0 {
		t.Errorf("banner %q missing interval", b)
	}
	if indexOf(b, "Ctrl-C") < 0 {
		t.Errorf("banner %q missing stop hint", b)
	}
}

// TestEngineScanSummarizes verifies the adapter reduces real engine findings
// to a total + distinct sorted kinds, using a synthetic AKIA-shaped key plus
// an email so two kinds are present.
func TestEngineScanSummarizes(t *testing.T) {
	scan := EngineScan(detect.Default())
	// AKIA…EXAMPLE avoids being a real credential; the email adds a pii kind.
	res := scan("key AKIAIOSFODNN7EXAMPLE and mail j@example.com")
	if res.Total < 2 {
		t.Fatalf("Total = %d, want >= 2", res.Total)
	}
	// Kinds must be sorted and contain both buckets.
	if !contains(res.Kinds, "secret") || !contains(res.Kinds, "pii") {
		t.Errorf("kinds = %v, want to include secret and pii", res.Kinds)
	}
	if !sorted(res.Kinds) {
		t.Errorf("kinds = %v, want sorted", res.Kinds)
	}
}

func TestEngineScanCleanIsEmpty(t *testing.T) {
	scan := EngineScan(detect.Default())
	res := scan("just some ordinary words here")
	if res.Total != 0 || len(res.Kinds) != 0 {
		t.Errorf("clean scan = %+v, want zero total and no kinds", res)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func sorted(xs []string) bool {
	for i := 1; i < len(xs); i++ {
		if xs[i-1] > xs[i] {
			return false
		}
	}
	return true
}

// waitFor polls cond up to ~1s, failing the test if it never becomes true.
// Used instead of fixed sleeps so tests are fast and non-flaky.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}
