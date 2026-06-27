// Command leakpeek is a paranoid bouncer for your clipboard.
//
// M1 scaffold: this version proves the plumbing only. It reads your
// clipboard (or stdin) and echoes the text back unchanged. Detection,
// redaction, and reporting arrive in later milestones (see PLAN.md).
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/rwrife/leakpeek/internal/clipboard"
)

// version is the leakpeek release. Overridable at build time via:
//
//	go build -ldflags "-X main.version=v0.1.0"
var version = "0.0.0-dev"

const usage = `leakpeek %s — a paranoid bouncer for your clipboard.

Usage:
  leakpeek [flags]

Flags:
  --version    Print the leakpeek version and exit.
  --stdin      Read text from stdin instead of the clipboard.
  -h, --help   Show this help and exit.

M1 scaffold: leakpeek currently echoes your clipboard (or stdin) back
unchanged. Detection and redaction land in later milestones — see PLAN.md.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run is the testable entry point. It returns the process exit code.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var (
		showVersion bool
		useStdin    bool
	)

	// Minimal stdlib-style flag parsing. We hand-roll it for M1 to keep
	// the binary dependency-free and the flag surface tiny. When the flag
	// set grows (M3+), this can move to the stdlib flag package or Cobra.
	for _, arg := range args {
		switch arg {
		case "--version", "-version", "-v":
			showVersion = true
		case "--stdin", "-stdin":
			useStdin = true
		case "-h", "--help", "-help":
			fmt.Fprintf(stdout, usage, version)
			return 0
		default:
			fmt.Fprintf(stderr, "leakpeek: unknown flag %q\n\n", arg)
			fmt.Fprintf(stderr, usage, version)
			return 2
		}
	}

	if showVersion {
		fmt.Fprintf(stdout, "leakpeek %s\n", version)
		return 0
	}

	// Source the text: explicit --stdin, an incoming pipe, or the clipboard.
	text, err := readInput(useStdin, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "leakpeek: %v\n", err)
		return 1
	}

	// M1 behavior: echo it straight back. No frisking yet.
	if _, err := io.WriteString(stdout, text); err != nil {
		fmt.Fprintf(stderr, "leakpeek: write failed: %v\n", err)
		return 1
	}

	return 0
}

// readInput decides where the text comes from. If --stdin is set, or stdin
// is a pipe/redirect (not a terminal), we read stdin. Otherwise we ask the
// clipboard adapter, which falls back to stdin if no clipboard tool exists.
func readInput(useStdin bool, stdin io.Reader) (string, error) {
	if useStdin || clipboard.StdinIsPiped(stdin) {
		b, err := io.ReadAll(stdin)
		if err != nil {
			return "", fmt.Errorf("reading stdin: %w", err)
		}
		return string(b), nil
	}
	return clipboard.Read()
}
