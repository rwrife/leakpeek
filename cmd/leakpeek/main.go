// Command leakpeek is a paranoid bouncer for your clipboard.
//
// M3 made it *report*: read the clipboard (or stdin), run the M2 detection
// engine, print a grouped findings table with masked previews and a
// personality verdict, and exit non-zero on a hit. M4 makes it *fix*: with
// `--fix`, leakpeek redacts the findings and writes a paste-safe copy back to
// the clipboard — or, when the input came from a pipe, prints the redacted
// text to stdout so `cat secrets.env | leakpeek --fix > clean.env` works.
// `--json` emits a machine-readable document; `--quiet` suppresses the report
// on a clean scan. See PLAN.md for the roadmap.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/rwrife/leakpeek/internal/clipboard"
	"github.com/rwrife/leakpeek/internal/detect"
	"github.com/rwrife/leakpeek/internal/redact"
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

With --fix it also hands back a redacted copy: written to the clipboard, or
printed to stdout when the input came from a pipe.

Flags:
  --fix              Redact the findings. Writes a safe copy back to the
                     clipboard, or prints redacted text to stdout when reading
                     a pipe/--stdin.
  --strategy <name>  How to redact with --fix: shape (default, keeps a scheme
                     hint like sk-REDACTED), full ([REDACTED-<KIND>]), or hash
                     ([<KIND>:<8hex>], stable & non-reversible).
  --json             Emit machine-readable JSON instead of the human report.
  --quiet            Print nothing on a clean scan (still reports on a hit).
  --stdin            Read text from stdin instead of the clipboard.
  --version          Print the leakpeek version and exit.
  -h, --help         Show this help and exit.
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
		fix         bool
		strategy    = redact.Shape
	)

	// Minimal stdlib-style flag parsing. We hand-roll it to keep the binary
	// dependency-free and the flag surface tiny. --strategy is the one flag
	// that takes a value; we accept both `--strategy hash` and
	// `--strategy=hash`. If the flag set grows much past this, switching to
	// the stdlib flag package is the natural step.
	for i := 0; i < len(args); i++ {
		arg := args[i]

		// Split an inline value off a `--flag=value` form once, up front.
		name, inlineVal, hasInline := splitFlag(arg)

		switch name {
		case "--version", "-version", "-v":
			showVersion = true
		case "--stdin", "-stdin":
			useStdin = true
		case "--json", "-json":
			asJSON = true
		case "--quiet", "-quiet", "-q":
			quiet = true
		case "--fix", "-fix":
			fix = true
		case "--strategy", "-strategy":
			val := inlineVal
			if !hasInline {
				// Consume the following argument as the value.
				if i+1 >= len(args) {
					fmt.Fprintf(stderr, "leakpeek: --strategy needs a value (shape|full|hash)\n\n")
					fmt.Fprintf(stderr, usage, version, exitFound, exitClean)
					return exitUsage
				}
				i++
				val = args[i]
			}
			s, ok := redact.ParseStrategy(val)
			if !ok {
				fmt.Fprintf(stderr, "leakpeek: unknown --strategy %q (want shape|full|hash)\n\n", val)
				fmt.Fprintf(stderr, usage, version, exitFound, exitClean)
				return exitUsage
			}
			strategy = s
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
	// piped tells us whether the input arrived on stdin, which decides where
	// --fix sends its redacted output (stdout for a pipe, clipboard otherwise).
	text, piped, err := readInput(useStdin, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "leakpeek: %v\n", err)
		return exitError
	}

	// Frisk it.
	findings := detect.Default().Scan(text)
	res := report.Build(text, findings)

	// --fix: redact and hand back a safe copy. When the input came from a
	// pipe we print the (possibly unchanged) redacted text to stdout so the
	// tool composes in shell pipelines even on a clean input. When it came
	// from the clipboard we only write back if we actually found something,
	// to avoid needlessly churning the clipboard on a clean scan. The human
	// report then goes to stderr so it never contaminates piped stdout.
	if fix {
		return runFix(res, findings, text, strategy, piped, asJSON, quiet, stdout, stderr)
	}

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

// runFix performs the --fix path: it redacts text and either prints the
// result to stdout (pipe input) or writes it to the clipboard (clipboard
// input), then emits the report to stderr. It returns the process exit code
// (exitFound on a hit, exitClean when clean, exitError if a clipboard write
// fails). Splitting it out of run keeps the flag-handling readable.
func runFix(
	res report.Result,
	findings []detect.Finding,
	text string,
	strategy redact.Strategy,
	piped, asJSON, quiet bool,
	stdout, stderr io.Writer,
) int {
	redacted := redact.Redact(text, findings, strategy)

	if piped {
		// Pipe mode: redacted text is the payload, so it owns stdout. Print it
		// verbatim (no trailing newline added) and route any report to stderr.
		if _, err := io.WriteString(stdout, redacted); err != nil {
			fmt.Fprintf(stderr, "leakpeek: writing redacted output: %v\n", err)
			return exitError
		}
		emitFixReport(res, asJSON, quiet, stderr, stderr, false)
	} else {
		// Clipboard mode: only write back when we changed something, so a clean
		// scan leaves the clipboard untouched.
		if !res.Clean {
			if err := clipboard.Write(redacted); err != nil {
				fmt.Fprintf(stderr, "leakpeek: %v\n", err)
				return exitError
			}
		}
		emitFixReport(res, asJSON, quiet, stdout, stderr, true)
	}

	if res.Clean {
		return exitClean
	}
	return exitFound
}

// emitFixReport writes the findings report for a --fix run to out (JSON or the
// human table). On a hit in human mode it adds a short confirmation line; the
// wording depends on where the redacted copy went — the clipboard (toClipboard
// true) or stdout (false) — so the message never claims a clipboard write that
// didn't happen.
func emitFixReport(res report.Result, asJSON, quiet bool, out, jsonErr io.Writer, toClipboard bool) {
	if asJSON {
		if err := report.RenderJSON(out, res); err != nil {
			fmt.Fprintf(jsonErr, "leakpeek: rendering json: %v\n", err)
		}
		return
	}
	report.Render(out, res, quiet)
	if !res.Clean && !quiet {
		if toClipboard {
			fmt.Fprintln(out, "✍️  Redacted copy is on your clipboard.")
		} else {
			fmt.Fprintln(out, "✍️  Redacted copy written to stdout.")
		}
	}
}

// splitFlag splits a `--name=value` argument into its name and value. For a
// bare `--name` (no '='), it returns (arg, "", false). The split happens on
// the first '=' only, so values containing '=' survive intact.
func splitFlag(arg string) (name, value string, hasValue bool) {
	for i := 0; i < len(arg); i++ {
		if arg[i] == '=' {
			return arg[:i], arg[i+1:], true
		}
	}
	return arg, "", false
}

// readInput decides where the text comes from and reports whether it arrived
// on stdin. If --stdin is set, or stdin is a pipe/redirect (not a terminal),
// we read stdin and return piped=true. Otherwise we ask the clipboard adapter
// (piped=false). The piped flag lets --fix choose its output sink: stdout for
// a pipe so the tool composes in shell pipelines, the clipboard otherwise.
func readInput(useStdin bool, stdin io.Reader) (text string, piped bool, err error) {
	if useStdin || clipboard.StdinIsPiped(stdin) {
		b, err := io.ReadAll(stdin)
		if err != nil {
			return "", true, fmt.Errorf("reading stdin: %w", err)
		}
		return string(b), true, nil
	}
	text, err = clipboard.Read()
	return text, false, err
}
