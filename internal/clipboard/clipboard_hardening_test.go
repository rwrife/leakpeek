package clipboard

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// --- Pure helper unit tests (run on every OS) ---

func TestFirstLine(t *testing.T) {
	cases := map[string]string{
		"":              "",
		"one line":      "one line",
		"first\nsecond": "first",
		"a\nb\nc":       "a",
		"trailing\n":    "trailing",
	}
	for in, want := range cases {
		if got := firstLine(in); got != want {
			t.Errorf("firstLine(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsEmptyWlClipboard(t *testing.T) {
	empty := []string{
		"Nothing is copied",
		"nothing is copied\n",
		"No selection",
		"The clipboard is empty",
	}
	for _, s := range empty {
		if !isEmptyWlClipboard(s) {
			t.Errorf("isEmptyWlClipboard(%q) = false, want true", s)
		}
	}
	notEmpty := []string{
		"",
		"failed to connect to wayland display",
		"some other error",
	}
	for _, s := range notEmpty {
		if isEmptyWlClipboard(s) {
			t.Errorf("isEmptyWlClipboard(%q) = true, want false", s)
		}
	}
}

func TestCmdErrPrefersStderr(t *testing.T) {
	err := errors.New("exit status 1")
	if got := cmdErr(err, "boom: display not found\nmore detail"); got != "boom: display not found" {
		t.Errorf("cmdErr with stderr = %q, want first stderr line", got)
	}
	if got := cmdErr(err, "   \n  "); got != "exit status 1" {
		t.Errorf("cmdErr with blank stderr = %q, want exec error", got)
	}
}

// TestReadWriteErrorNoToolWrapsSentinel verifies the tried==0 branch wraps
// ErrNoClipboardTool and mentions --stdin, for both ops.
func TestReadWriteErrorNoToolWrapsSentinel(t *testing.T) {
	for _, op := range []string{"read", "write"} {
		err := readWriteError(op, 0, nil)
		if !errors.Is(err, ErrNoClipboardTool) {
			t.Errorf("readWriteError(%q, 0, nil) = %v, want ErrNoClipboardTool", op, err)
		}
		if !strings.Contains(err.Error(), "--stdin") {
			t.Errorf("readWriteError(%q, 0, nil) = %q, want it to mention --stdin", op, err)
		}
	}
}

// TestReadWriteErrorAllFailedDoesNotWrapSentinel verifies that when tools were
// present but every one failed, the error is aggregated and does NOT wrap the
// sentinel (so callers can distinguish "broken tool" from "no tool").
func TestReadWriteErrorAllFailedDoesNotWrapSentinel(t *testing.T) {
	err := readWriteError("read", 2, []string{"wl-paste: no display", "xclip: cannot open"})
	if errors.Is(err, ErrNoClipboardTool) {
		t.Errorf("readWriteError with failures wrapped ErrNoClipboardTool; want a distinct error: %v", err)
	}
	msg := err.Error()
	for _, want := range []string{"wl-paste: no display", "xclip: cannot open"} {
		if !strings.Contains(msg, want) {
			t.Errorf("aggregated error %q missing %q", msg, want)
		}
	}
}

// --- Cascade integration tests via fake tools on PATH (Linux only) ---
//
// These build tiny shell-script stand-ins for the Linux clipboard tools so we
// can drive Read/Write's fall-through logic deterministically without a real
// display server. They exercise the linux candidate order
// (wl-paste → xclip → xsel), so they're gated to linux: on macOS/Windows the
// per-OS candidate list is pbpaste/pbcopy or PowerShell/clip, which would
// ignore these fakes and hit the real (or absent) system clipboard instead.

// requireLinuxFakeTools skips a cascade test anywhere the Linux adapter chain
// isn't what Read/Write will actually consult.
func requireLinuxFakeTools(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("linux-adapter cascade test; GOOS=%s uses a different tool chain", runtime.GOOS)
	}
}

// writeFakeTool creates an executable script named `name` in dir that runs
// `body` (a /bin/sh snippet). It returns nothing; failures fail the test.
func writeFakeTool(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	script := "#!/bin/sh\n" + body + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("writing fake tool %s: %v", name, err)
	}
}

// fakeToolPATH prepends dir to the current PATH and installs it for the test.
// Prepending (rather than replacing) keeps coreutils like `cat` resolvable
// for the fake scripts while still shadowing any real clipboard tool of the
// same name, since the temp dir is searched first.
func fakeToolPATH(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestReadCascadesPastFailingTool(t *testing.T) {
	requireLinuxFakeTools(t)
	dir := t.TempDir()
	// wl-paste is installed but "fails" (simulating no Wayland display);
	// xclip is installed and succeeds. Read must fall through to xclip.
	writeFakeTool(t, dir, "wl-paste", `echo "cannot open display" 1>&2; exit 1`)
	writeFakeTool(t, dir, "xclip", `echo "from-xclip"`)
	fakeToolPATH(t, dir)

	got, err := Read()
	if err != nil {
		t.Fatalf("Read() error = %v, want fall-through success", err)
	}
	if strings.TrimSpace(got) != "from-xclip" {
		t.Errorf("Read() = %q, want it to come from the xclip fallback", got)
	}
}

func TestReadEmptyWaylandClipboardIsEmptyNotError(t *testing.T) {
	requireLinuxFakeTools(t)
	dir := t.TempDir()
	// wl-paste reports the documented "empty clipboard" condition: it should
	// read as "" with no error, and must NOT fall through to xclip.
	writeFakeTool(t, dir, "wl-paste", `echo "Nothing is copied" 1>&2; exit 1`)
	writeFakeTool(t, dir, "xclip", `echo "should-not-be-used"`)
	fakeToolPATH(t, dir)

	got, err := Read()
	if err != nil {
		t.Fatalf("Read() on empty wl clipboard error = %v, want nil", err)
	}
	if got != "" {
		t.Errorf("Read() on empty wl clipboard = %q, want empty string", got)
	}
}

func TestReadAllToolsFailAggregatesError(t *testing.T) {
	requireLinuxFakeTools(t)
	dir := t.TempDir()
	writeFakeTool(t, dir, "wl-paste", `echo "wl broke" 1>&2; exit 1`)
	writeFakeTool(t, dir, "xclip", `echo "xclip broke" 1>&2; exit 1`)
	writeFakeTool(t, dir, "xsel", `echo "xsel broke" 1>&2; exit 1`)
	fakeToolPATH(t, dir)

	_, err := Read()
	if err == nil {
		t.Fatal("Read() with all tools failing returned nil error")
	}
	if errors.Is(err, ErrNoClipboardTool) {
		t.Errorf("Read() error wrapped ErrNoClipboardTool despite tools being present: %v", err)
	}
	for _, want := range []string{"wl broke", "xclip broke", "xsel broke"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("aggregated Read error %q missing %q", err.Error(), want)
		}
	}
}

func TestWriteCascadesPastFailingTool(t *testing.T) {
	requireLinuxFakeTools(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "written.txt")
	// wl-copy fails; xclip succeeds and records that it ran. Write must
	// fall through and succeed via xclip.
	writeFakeTool(t, dir, "wl-copy", `echo "no wayland" 1>&2; exit 1`)
	writeFakeTool(t, dir, "xclip", `cat > `+marker)
	fakeToolPATH(t, dir)

	if err := Write("payload"); err != nil {
		t.Fatalf("Write() error = %v, want fall-through success", err)
	}
	b, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("reading marker file: %v", err)
	}
	if strings.TrimSpace(string(b)) != "payload" {
		t.Errorf("xclip fallback wrote %q, want %q", strings.TrimSpace(string(b)), "payload")
	}
}
