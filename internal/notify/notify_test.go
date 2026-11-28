package notify

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testCommand(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name+".exe")
	if err := os.WriteFile(path, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNotifyAlwaysRingsBell(t *testing.T) {
	// A toaster with no candidates still must ring the bell and report no
	// desktop notification.
	var bell bytes.Buffer
	tr := &toaster{goos: "linux", candidates: nil, run: func(command, string, string) error { return nil }}
	desktop := tr.Notify("t", "b", &bell)
	if desktop {
		t.Errorf("desktop = true, want false with no candidates")
	}
	if bell.String() != "\a" {
		t.Errorf("bell = %q, want the BEL byte", bell.String())
	}
}

func TestNotifyNilBellDoesNotPanic(t *testing.T) {
	tr := &toaster{goos: "linux", candidates: nil, run: func(command, string, string) error { return nil }}
	// Must not panic with a nil bell writer.
	if got := tr.Notify("t", "b", nil); got {
		t.Errorf("desktop = %v, want false", got)
	}
}

func TestNotifyReportsDesktopWhenRunSucceeds(t *testing.T) {
	// LookPath checks a test-owned executable; run remains a fake.
	commandPath := testCommand(t, "success")
	var gotName string
	var gotTitle, gotBody string
	tr := &toaster{
		goos:       "linux",
		candidates: []command{{commandPath, []string{"{title}", "{body}"}}},
		run: func(c command, title, body string) error {
			gotName = c.name
			gotTitle, gotBody = title, body
			return nil
		},
	}
	var bell bytes.Buffer
	if !tr.Notify("Leak!", "3 secrets", &bell) {
		t.Fatal("desktop = false, want true when run succeeds")
	}
	if gotName != commandPath {
		t.Errorf("ran %q, want %q", gotName, commandPath)
	}
	if gotTitle != "Leak!" || gotBody != "3 secrets" {
		t.Errorf("run got (%q,%q), want (Leak!,3 secrets)", gotTitle, gotBody)
	}
}

func TestNotifyFallsThroughOnFailure(t *testing.T) {
	// First candidate exists but fails; second exists and succeeds. Notify
	// must try the second and report success.
	var calls []string
	first, second := testCommand(t, "first"), testCommand(t, "second")
	tr := &toaster{
		goos: "linux",
		candidates: []command{
			{first, nil},
			{second, nil},
		},
		run: func(c command, _, _ string) error {
			calls = append(calls, c.name)
			if c.name == first {
				return errors.New("headless")
			}
			return nil
		},
	}
	var bell bytes.Buffer
	if !tr.Notify("t", "b", &bell) {
		t.Fatal("desktop = false, want true after fallthrough")
	}
	if len(calls) != 2 || calls[0] != first || calls[1] != second {
		t.Errorf("call order = %v, want [%s %s]", calls, first, second)
	}
}

func TestNotifySkipsMissingBinaries(t *testing.T) {
	// A candidate that certainly isn't installed must be skipped without
	// calling run for it.
	var ran bool
	tr := &toaster{
		goos:       "linux",
		candidates: []command{{"definitely-not-a-real-binary-xyz", nil}},
		run:        func(command, string, string) error { ran = true; return nil },
	}
	var bell bytes.Buffer
	if tr.Notify("t", "b", &bell) {
		t.Errorf("desktop = true, want false when the only tool is missing")
	}
	if ran {
		t.Errorf("run was called for a missing binary")
	}
}

func TestRenderArgsSubstitutesTokens(t *testing.T) {
	tmpl := []string{"-e", `display notification "{body}" with title "{title}"`, "{title}"}
	got := renderArgs(tmpl, "TT", "BB")
	want := []string{"-e", `display notification "BB" with title "TT"`, "TT"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("arg[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestMessagePhrasing(t *testing.T) {
	cases := []struct {
		total    int
		kinds    []string
		wantBody string
	}{
		{1, []string{"secret"}, "1 secret (secret) on your clipboard"},
		{3, []string{"secret", "pii"}, "3 secrets (secret, pii) on your clipboard"},
		{2, nil, "2 secrets on your clipboard"},
		{1, nil, "1 secret on your clipboard"},
	}
	for _, c := range cases {
		title, body := Message(c.total, c.kinds)
		if title == "" {
			t.Errorf("Message(%d,%v) empty title", c.total, c.kinds)
		}
		if body != c.wantBody {
			t.Errorf("Message(%d,%v) body = %q, want %q", c.total, c.kinds, body, c.wantBody)
		}
	}
}

func TestCandidatesForKnownOSes(t *testing.T) {
	if got := candidatesFor("darwin"); len(got) == 0 || got[0].name != "osascript" {
		t.Errorf("darwin candidates = %v, want osascript first", got)
	}
	if got := candidatesFor("windows"); len(got) == 0 || got[0].name != "powershell" {
		t.Errorf("windows candidates = %v, want powershell first", got)
	}
	lin := candidatesFor("linux")
	if len(lin) == 0 || lin[0].name != "notify-send" {
		t.Errorf("linux candidates = %v, want notify-send first", lin)
	}
	// The Windows script must read its text from the environment, since the
	// toast body isn't passed as an arg token.
	if !strings.Contains(winToastScript, "LEAKPEEK_TITLE") || !strings.Contains(winToastScript, "LEAKPEEK_BODY") {
		t.Errorf("winToastScript must read text from env vars")
	}
}
