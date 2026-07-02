// Package clipboard reads and writes the OS clipboard.
//
// It shells out to the native clipboard tool for the host OS, trying an
// ordered per-OS candidate list and moving on to the next tool when one is
// missing *or* fails at runtime. This is the M5 hardening: a Wayland box with
// wl-clipboard installed but no compositor running still falls through to
// xclip/xsel; an empty Wayland clipboard (where wl-paste exits non-zero)
// reads as empty text rather than an error. When nothing on the host can
// serve the request, callers get one clear, friendly error that lists what
// was tried and points at --stdin. See PLAN.md (M5) for the roadmap.
package clipboard

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// ErrNoClipboardTool is returned when no supported clipboard utility is
// installed on the host (every candidate binary is missing from PATH).
// Callers should suggest piping via --stdin instead. When a tool *is*
// present but fails at runtime, the returned error will not wrap this
// sentinel — the distinction lets callers tell "install a tool" apart from
// "your clipboard tool broke".
var ErrNoClipboardTool = errors.New("no clipboard tool found")

// reader pairs a candidate command with the args used to read the clipboard.
type reader struct {
	name string
	args []string
}

// writer pairs a candidate command with the args used to write the clipboard.
// The text to copy is piped to the command's stdin.
type writer struct {
	name string
	args []string
}

// readersFor returns the ordered list of clipboard-read candidates for the
// current OS. The first one whose binary exists on PATH *and* succeeds wins.
func readersFor(goos string) []reader {
	switch goos {
	case "darwin":
		return []reader{{"pbpaste", nil}}
	case "windows":
		// PowerShell's Get-Clipboard is the most reliable text reader.
		// -Raw keeps multi-line content intact instead of splitting lines.
		return []reader{{"powershell", []string{"-NoProfile", "-Command", "Get-Clipboard", "-Raw"}}}
	default: // linux, *bsd, etc.
		return []reader{
			{"wl-paste", []string{"--no-newline"}},               // Wayland
			{"xclip", []string{"-selection", "clipboard", "-o"}}, // X11
			{"xsel", []string{"--clipboard", "--output"}},        // X11 alt
		}
	}
}

// writersFor returns the ordered list of clipboard-write candidates for the
// current OS. The first one whose binary exists on PATH *and* succeeds wins.
// Each command reads the text to copy from stdin.
func writersFor(goos string) []writer {
	switch goos {
	case "darwin":
		return []writer{{"pbcopy", nil}}
	case "windows":
		// clip.exe copies whatever it reads on stdin to the clipboard.
		return []writer{{"clip", nil}}
	default: // linux, *bsd, etc.
		return []writer{
			{"wl-copy", nil}, // Wayland
			{"xclip", []string{"-selection", "clipboard"}}, // X11
			{"xsel", []string{"--clipboard", "--input"}},   // X11 alt
		}
	}
}

// Read returns the current clipboard contents as text.
//
// It walks the per-OS candidate list, skipping tools that aren't installed
// and trying the next tool when one is installed but fails at runtime (e.g.
// wl-paste on a host with no Wayland display). If none is installed it
// returns an error wrapping ErrNoClipboardTool (suggesting --stdin). If tools
// were present but all failed, it returns an aggregated error naming each
// failure — without ErrNoClipboardTool, so callers can tell the two apart.
func Read() (string, error) {
	candidates := readersFor(runtime.GOOS)

	var (
		failures []string // "tool: reason" for each installed-but-failed tool
		tried    int      // how many candidates were actually installed
	)
	for _, c := range candidates {
		path, err := exec.LookPath(c.name)
		if err != nil {
			continue // tool not installed; try the next candidate
		}
		tried++

		var stdout, stderr bytes.Buffer
		cmd := exec.Command(path, c.args...)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			// wl-paste exits non-zero on an *empty* clipboard with a
			// telltale message; treat that as legitimately empty rather
			// than a failure worth falling through for.
			if c.name == "wl-paste" && isEmptyWlClipboard(stderr.String()) {
				return "", nil
			}
			failures = append(failures, fmt.Sprintf("%s: %s", c.name, cmdErr(err, stderr.String())))
			continue // this tool broke; give the next one a shot
		}
		return stdout.String(), nil
	}

	return "", readWriteError("read", tried, failures)
}

// Write replaces the clipboard contents with text.
//
// Like Read, it tries each candidate in order, skipping missing tools and
// falling through to the next tool when one fails at runtime, and returns nil
// on the first success. If no tool is installed it returns an error wrapping
// ErrNoClipboardTool (suggesting --stdin). If tools were present but all
// failed, it returns an aggregated error naming each failure.
func Write(text string) error {
	candidates := writersFor(runtime.GOOS)

	var (
		failures []string
		tried    int
	)
	for _, c := range candidates {
		path, err := exec.LookPath(c.name)
		if err != nil {
			continue // tool not installed; try the next candidate
		}
		tried++

		var stderr bytes.Buffer
		cmd := exec.Command(path, c.args...)
		cmd.Stdin = strings.NewReader(text)
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %s", c.name, cmdErr(err, stderr.String())))
			continue // this tool broke; try the next writer
		}
		return nil
	}

	return readWriteError("write", tried, failures)
}

// readWriteError builds the terminal error for Read/Write once every
// candidate has been exhausted. op is "read" or "write". When no tool was
// installed (tried == 0) it wraps ErrNoClipboardTool and steers the user to
// --stdin. When tools were installed but all failed, it returns an
// aggregated, non-sentinel error listing each failure so the user sees which
// tool broke and why.
func readWriteError(op string, tried int, failures []string) error {
	if tried == 0 {
		hint := "pipe text in with --stdin instead"
		if op == "write" {
			hint = "print the redacted text with --stdin instead"
		}
		return fmt.Errorf("%w for %s; %s", ErrNoClipboardTool, runtime.GOOS, hint)
	}
	return fmt.Errorf("clipboard %s failed on %s; tried %s", op, runtime.GOOS, strings.Join(failures, "; "))
}

// cmdErr renders a failed command's error for the aggregated message,
// preferring the tool's own stderr (trimmed to one line) when it wrote
// something, and falling back to the exec error otherwise.
func cmdErr(err error, stderr string) string {
	if s := firstLine(strings.TrimSpace(stderr)); s != "" {
		return s
	}
	return err.Error()
}

// firstLine returns s up to (not including) the first newline. Used to keep
// aggregated multi-tool errors to a single readable line per tool.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// isEmptyWlClipboard reports whether wl-paste's stderr indicates the
// clipboard is simply empty (its documented non-zero-exit case) rather than a
// real failure. wl-paste prints a message like "Nothing is copied" /
// "No selection" to stderr in that situation.
func isEmptyWlClipboard(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "nothing is copied") ||
		strings.Contains(s, "no selection") ||
		strings.Contains(s, "clipboard is empty")
}

// StdinIsPiped reports whether stdin appears to be a pipe or redirect rather
// than an interactive terminal. Used to auto-detect `cat file | leakpeek`.
// Anything that isn't an *os.File (e.g. test buffers) is treated as piped.
func StdinIsPiped(stdin any) bool {
	f, ok := stdin.(*os.File)
	if !ok {
		return true
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	// If the character-device bit is unset, stdin is a pipe/regular file.
	return (info.Mode() & os.ModeCharDevice) == 0
}
