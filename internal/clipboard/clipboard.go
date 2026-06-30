// Package clipboard reads and writes the OS clipboard.
//
// It shells out to the native clipboard tool for the host OS. Read (M1) and
// Write (M4, for --fix) both pick the first available tool from an ordered
// per-OS candidate list. Robust cross-platform hardening — richer fallbacks
// and clearer multi-tool errors — is M5 (see PLAN.md). When no clipboard
// tool is available, both return a clear, actionable error pointing at
// --stdin.
package clipboard

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// ErrNoClipboardTool is returned when no supported clipboard utility is
// found on the host. Callers should suggest piping via --stdin instead.
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
// current OS. The first one whose binary exists on PATH wins.
func readersFor(goos string) []reader {
	switch goos {
	case "darwin":
		return []reader{{"pbpaste", nil}}
	case "windows":
		// PowerShell's Get-Clipboard is the most reliable text reader.
		return []reader{{"powershell", []string{"-NoProfile", "-Command", "Get-Clipboard"}}}
	default: // linux, *bsd, etc.
		return []reader{
			{"wl-paste", []string{"--no-newline"}},               // Wayland
			{"xclip", []string{"-selection", "clipboard", "-o"}}, // X11
			{"xsel", []string{"--clipboard", "--output"}},        // X11 alt
		}
	}
}

// writersFor returns the ordered list of clipboard-write candidates for the
// current OS. The first one whose binary exists on PATH wins. Each command
// reads the text to copy from stdin.
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

// Read returns the current clipboard contents as text. If no clipboard tool
// is available it returns an error wrapping ErrNoClipboardTool.
func Read() (string, error) {
	candidates := readersFor(runtime.GOOS)
	for _, c := range candidates {
		path, err := exec.LookPath(c.name)
		if err != nil {
			continue // tool not installed; try the next candidate
		}
		out, err := exec.Command(path, c.args...).Output()
		if err != nil {
			return "", fmt.Errorf("clipboard read via %s failed: %w", c.name, err)
		}
		return string(out), nil
	}
	return "", fmt.Errorf("%w for %s; pipe text in with --stdin instead", ErrNoClipboardTool, runtime.GOOS)
}

// Write replaces the clipboard contents with text. It tries each write
// candidate for the host OS in order, piping text to the tool's stdin, and
// returns nil on the first success. If no clipboard tool is available it
// returns an error wrapping ErrNoClipboardTool so callers can suggest
// printing the redacted text to stdout (via --stdin) instead.
func Write(text string) error {
	candidates := writersFor(runtime.GOOS)
	for _, c := range candidates {
		path, err := exec.LookPath(c.name)
		if err != nil {
			continue // tool not installed; try the next candidate
		}
		cmd := exec.Command(path, c.args...)
		cmd.Stdin = strings.NewReader(text)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("clipboard write via %s failed: %w", c.name, err)
		}
		return nil
	}
	return fmt.Errorf("%w for %s; print the redacted text with --stdin instead", ErrNoClipboardTool, runtime.GOOS)
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
