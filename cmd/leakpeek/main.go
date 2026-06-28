// Command leakpeek is a paranoid bouncer for your clipboard.
//
// M3: leakpeek now reads your clipboard (or stdin), runs the M2 detection
// engine, and prints a findings report — a grouped table with masked
// previews and a personality verdict — exiting non-zero when it finds
// something. `--json` emits a machine-readable document instead; `--quiet`
// suppresses output on a clean scan. Redaction / clipboard write-back is M4
// (see PLAN.md).
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/rwrife/leakpeek/internal/clipboard"
	"github.com/rwrife/leakpeek/internal/detect"
	"github.com/rwrife/leakpeek/internal/report"
)

// version is the leakpeek release. Overridable at build time via:
//
//	go build -ldflags "-X main.version=v0.1.0"
var version = "0.0.0-dev"

// Exit codes. These are part of leakpeek's contract so CI jobs and shell
// aliases can branch on them:
//
//	0 → clean (no findings)
//	1 → an error occurred (couldn't read input, write failed, …)
//	2 → bad usage (unknown flag)
//	3 → scan completed and FOUND something
//
// Using a distinct code (3) for "found" keeps it separate from operational
// errors (1) so `leakpeek && pbpaste | …` style guards are unambiguous.
const (
	exitClean = 0
	exitError = 1
	exitUsage = 2
	exitFound = 3
)

const usage = `leakpeek %s — a paranoid bouncer for your clipboard.

Usage:
  leakpeek [flags]

Scans your clipboard (or stdin) for secrets, keys, and PII and prints what
it found. Exits %d when something is found, %d when clean.

Flags:
  --json       Emit machine-readable JSON instead of the human report.
  --quiet      Print nothing on a clean scan (still reports on a hit).
  --stdin      Read text from stdin instead of the clipboard.
  --version    Print the leakpeek version and exit.
  -h, --help   Show this help and exit.

Redaction and clipboard write-back (--fix) arrive in M4 — see PLAN.md.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run is the testable entry point. It returns the process exit code.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var (
		showVersion bool
		useStdin    bool
		asJSON      bool
		quiet       bool
	)

	// Minimal stdlib-style flag parsing. We hand-roll it to keep the binary
	// dependency-free and the flag surface tiny. If the flag set grows much
	// past this, switching to the stdlib flag package is the natural step.
	for _, arg := range args {
		switch arg {
		case "--version", "-version", "-v":
			showVersion = true
		case "--stdin", "-stdin":
			useStdin = true
		case "--json", "-json":
			asJSON = true
		case "--quiet", "-quiet", "-q":
			quiet = true
		case "-h", "--help", "-help":
			fmt.Fprintf(stdout, usage, version, exitFound, exitClean)
			return exitClean
		default:
			fmt.Fprintf(stderr, "leakpeek: unknown flag %q\n\n", arg)
			fmt.Fprintf(stderr, usage, version, exitFound, exitClean)
			return exitUsage
		}
	}

	if showVersion {
		fmt.Fprintf(stdout, "leakpeek %s\n", version)
		return exitClean
	}

	// Source the text: explicit --stdin, an incoming pipe, or the clipboard.
	text, err := readInput(useStdin, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "leakpeek: %v\n", err)
		return exitError
	}

	// Frisk it.
	findings := detect.Default().Scan(text)
	res := report.Build(text, findings)

	if asJSON {
		if err := report.RenderJSON(stdout, res); err != nil {
			fmt.Fprintf(stderr, "leakpeek: rendering json: %v\n", err)
			return exitError
		}
	} else {
		report.Render(stdout, res, quiet)
	}

	if res.Clean {
		return exitClean
	}
	return exitFound
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
