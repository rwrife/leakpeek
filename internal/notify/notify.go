// Package notify raises a best-effort desktop notification and/or a terminal
// bell. It is the alerting half of watch mode (PLAN.md §8 item 1): when the
// watcher spots a secret land on the clipboard, it calls Notify to get the
// user's attention without printing a wall of text.
//
// Design principles that match leakpeek's ethos:
//
//   - Best-effort, never fatal. A missing notifier is not an error — the
//     terminal bell always fires as a floor, and a missing desktop tool just
//     means no toast. Watch mode must keep running regardless.
//   - No new dependencies. Like the clipboard layer, we shell out to the
//     native tool per OS (notify-send / osascript / PowerShell), trying an
//     ordered candidate list and skipping tools that aren't installed.
//   - Zero storage, zero network. A notification is fire-and-forget.
package notify

import (
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strings"
)

// Notifier delivers an alert. The concrete implementation shells out to a
// native desktop tool; tests substitute a fake. It is safe for concurrent
// use.
type Notifier interface {
	// Notify rings the terminal bell (writing "\a" to bell) as a guaranteed
	// floor, then makes a best-effort attempt at a desktop notification. It
	// reports whether a desktop notification was delivered. A simply-absent
	// desktop notifier is not an error — desktop is reported false instead.
	Notify(title, body string, bell io.Writer) (desktop bool)
}

// toaster is the default Notifier: it rings the bell and shells out to the
// first available per-OS desktop notification tool.
type toaster struct {
	goos       string
	candidates []command // desktop notifiers to try, in order
	// run executes a resolved notifier with the alert text; swapped in tests
	// to avoid launching real processes. Defaults to runCmd.
	run func(c command, title, body string) error
}

// command names a desktop-notifier binary and the argument template used to
// invoke it. The literal tokens "{title}" and "{body}" in args are replaced
// with the actual title/body at call time, so a tool's arg order is fully
// data-driven. Tools that instead read the text from the environment (the
// Windows toast) leave the tokens out and rely on runCmd exporting them.
type command struct {
	name string
	args []string
}

// New returns the default Notifier for the current OS.
func New() Notifier {
	return &toaster{
		goos:       runtime.GOOS,
		candidates: candidatesFor(runtime.GOOS),
		run:        runCmd,
	}
}

// candidatesFor returns the ordered desktop-notifier candidates for goos.
// The first one whose binary exists on PATH and runs without error wins.
func candidatesFor(goos string) []command {
	switch goos {
	case "darwin":
		// osascript posts a Notification Center banner. title/body stay as
		// separate {tokens} so argument passing (no shell) escapes them.
		return []command{
			{"osascript", []string{"-e", `display notification "{body}" with title "{title}"`}},
		}
	case "windows":
		// A minimal PowerShell balloon via the classic NotifyIcon, reading the
		// text from the environment (see winToastScript). Avoids external
		// modules; best-effort and silently no-ops on headless hosts.
		return []command{
			{"powershell", []string{"-NoProfile", "-Command", winToastScript}},
		}
	default: // linux, *bsd, etc.
		return []command{
			{"notify-send", []string{"{title}", "{body}"}},                               // freedesktop
			{"kdialog", []string{"--passivepopup", "{body}", "5", "--title", "{title}"}}, // KDE
		}
	}
}

// winToastScript posts a balloon tip using the classic System.Windows.Forms
// NotifyIcon. It reads $env:LEAKPEEK_TITLE / $env:LEAKPEEK_BODY so the text
// travels via the environment rather than being interpolated into the script,
// keeping quoting simple and safe.
const winToastScript = `
Add-Type -AssemblyName System.Windows.Forms
$n = New-Object System.Windows.Forms.NotifyIcon
$n.Icon = [System.Drawing.SystemIcons]::Warning
$n.BalloonTipTitle = $env:LEAKPEEK_TITLE
$n.BalloonTipText = $env:LEAKPEEK_BODY
$n.Visible = $true
$n.ShowBalloonTip(5000)
Start-Sleep -Milliseconds 200
$n.Dispose()
`

// Notify rings the bell then makes a best-effort desktop notification.
func (t *toaster) Notify(title, body string, bell io.Writer) bool {
	// The terminal bell is the guaranteed floor: even with no desktop tool,
	// an attended terminal still audibly/visually flags the hit. Ignore the
	// write error deliberately — a broken stderr must not abort watch mode.
	if bell != nil {
		_, _ = io.WriteString(bell, "\a")
	}

	for _, c := range t.candidates {
		if _, err := exec.LookPath(c.name); err != nil {
			continue // not installed; try the next candidate
		}
		if err := t.run(c, title, body); err != nil {
			continue // installed but failed (e.g. headless); try the next
		}
		return true
	}
	// No desktop notifier available or all failed. Not an error: the bell
	// already fired and watch mode should keep going.
	return false
}

// runCmd runs the notifier command with {title}/{body} substituted into its
// args, and also exports LEAKPEEK_TITLE/LEAKPEEK_BODY so tools that read the
// text from the environment (the Windows toast) get it. It waits for
// completion so a failing tool can be detected and the next candidate tried.
// stdout/stderr are discarded so a notifier's chatter can't pollute output.
func runCmd(c command, title, body string) error {
	args := renderArgs(c.args, title, body)
	cmd := exec.Command(c.name, args...)
	cmd.Env = append(cmd.Environ(),
		"LEAKPEEK_TITLE="+title,
		"LEAKPEEK_BODY="+body,
	)
	return cmd.Run()
}

// renderArgs substitutes the {title}/{body} tokens in an argument template.
// Substitution also replaces the tokens when embedded in a larger string (as
// in the osascript -e expression), not just whole-token.
func renderArgs(tmpl []string, title, body string) []string {
	out := make([]string, len(tmpl))
	for i, a := range tmpl {
		a = strings.ReplaceAll(a, "{title}", title)
		a = strings.ReplaceAll(a, "{body}", body)
		out[i] = a
	}
	return out
}

// Message builds the standard watch-mode alert from a scan summary: a count
// and the distinct kinds involved, e.g. body "3 secrets (secret, pii) on your
// clipboard". Keeping it here means the watcher and any future caller phrase
// the alert identically.
func Message(total int, kinds []string) (title, body string) {
	noun := "secret"
	if total != 1 {
		noun = "secrets"
	}
	title = "leakpeek: clipboard leak"
	if len(kinds) == 0 {
		body = fmt.Sprintf("%d %s on your clipboard", total, noun)
		return title, body
	}
	body = fmt.Sprintf("%d %s (%s) on your clipboard", total, noun, strings.Join(kinds, ", "))
	return title, body
}
