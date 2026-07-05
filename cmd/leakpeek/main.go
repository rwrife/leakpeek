// Command leakpeek is a paranoid bouncer for your clipboard.
//
// M3 made it *report*: read the clipboard (or stdin), run the M2 detection
// engine, print a grouped findings table with masked previews and a
// personality verdict, and exit non-zero on a hit. M4 makes it *fix*: with
// `--fix`, leakpeek redacts the findings and writes a paste-safe copy back to
// the clipboard — or, when the input came from a pipe, prints the redacted
// text to stdout so `cat secrets.env | leakpeek --fix > clean.env` works.
// `--json` emits a machine-readable document; `--quiet` suppresses the report
// on a clean scan. With `--watch`, leakpeek stays resident and taps the
// clipboard on an interval, alerting the instant a secret lands on it. See
// PLAN.md for the roadmap.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rwrife/leakpeek/internal/clipboard"
	"github.com/rwrife/leakpeek/internal/detect"
	"github.com/rwrife/leakpeek/internal/notify"
	"github.com/rwrife/leakpeek/internal/redact"
	"github.com/rwrife/leakpeek/internal/report"
	"github.com/rwrife/leakpeek/internal/rules"
	"github.com/rwrife/leakpeek/internal/watch"
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

With --watch it stays resident, taps the clipboard on an interval, and alerts
the instant a secret lands on it (desktop notification + terminal bell).

Flags:
  --watch            Stay resident and watch the clipboard, alerting on any
                     secret the moment it's copied. Press Ctrl-C to stop.
                     Stores nothing; scans in memory only.
  --interval <dur>   Poll cadence for --watch (default 800ms, min 100ms).
                     Accepts Go durations like 500ms, 2s.
  --fix              Redact the findings. Writes a safe copy back to the
                     clipboard, or prints redacted text to stdout when reading
                     a pipe/--stdin.
  --strategy <name>  How to redact with --fix: shape (default, keeps a scheme
                     hint like sk-REDACTED), full ([REDACTED-<KIND>]), or hash
                     ([<KIND>:<8hex>], stable & non-reversible).
  --rules <path>     Load extra detectors from a TOML rule file or a directory
                     of *.toml files. Custom rules run alongside the built-ins.
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
		rulesPath   string
		watchMode   bool
		interval    time.Duration
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
		case "--watch", "-watch":
			watchMode = true
		case "--interval", "-interval":
			val := inlineVal
			if !hasInline {
				// Consume the following argument as the value.
				if i+1 >= len(args) {
					fmt.Fprintf(stderr, "leakpeek: --interval needs a duration (e.g. 800ms, 2s)\n\n")
					fmt.Fprintf(stderr, usage, version, exitFound, exitClean)
					return exitUsage
				}
				i++
				val = args[i]
			}
			d, err := time.ParseDuration(strings.TrimSpace(val))
			if err != nil {
				fmt.Fprintf(stderr, "leakpeek: invalid --interval %q (want a Go duration like 800ms, 2s)\n\n", val)
				fmt.Fprintf(stderr, usage, version, exitFound, exitClean)
				return exitUsage
			}
			interval = d
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
		case "--rules", "-rules":
			val := inlineVal
			if !hasInline {
				// Consume the following argument as the path.
				if i+1 >= len(args) {
					fmt.Fprintf(stderr, "leakpeek: --rules needs a path (file or directory)\n\n")
					fmt.Fprintf(stderr, usage, version, exitFound, exitClean)
					return exitUsage
				}
				i++
				val = args[i]
			}
			if strings.TrimSpace(val) == "" {
				fmt.Fprintf(stderr, "leakpeek: --rules path must not be empty\n\n")
				fmt.Fprintf(stderr, usage, version, exitFound, exitClean)
				return exitUsage
			}
			rulesPath = val
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

	// Build the detection engine: always the built-in pack, plus any custom
	// rules the user pointed --rules at. Custom detectors are appended after
	// the built-ins so a real credential still reports under its precise
	// built-in name during dedupe, while user rules claim spans nothing else
	// did. A bad rules path/file is an operational error (exit 1), reported
	// before we scan so the user knows their rules never loaded. The engine is
	// built before we touch any input because --watch never reads a one-shot
	// input at all — it polls the clipboard on its own schedule.
	engine := detect.Default()
	if rulesPath != "" {
		custom, err := rules.LoadPath(rulesPath)
		if err != nil {
			fmt.Fprintf(stderr, "leakpeek: %v\n", err)
			return exitError
		}
		engine = engine.WithDetectors(custom...)
	}

	// --watch: hand off to the resident clipboard watcher. It owns its own
	// read loop, so none of the one-shot input/report machinery below runs.
	if watchMode {
		return runWatch(engine, interval, stderr)
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
	findings := engine.Scan(text)
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

// runWatch runs the resident clipboard watcher until interrupted (Ctrl-C /
// SIGTERM). It prints a startup banner to stderr, then on each debounced
// change scans the clipboard and, on a hit, raises a desktop notification +
// terminal bell and logs a one-line alert to stderr. It stores nothing beyond
// an in-memory hash of the last-seen clipboard value. It returns exitClean on
// a clean stop; watch mode's exit code intentionally reflects the run, not the
// findings (a long-lived watcher has no single verdict to return).
//
// stderr is used for all human output so that, even under --watch, stdout
// stays clean for any future piping and the alerts never race with a report.
func runWatch(engine *detect.Engine, interval time.Duration, stderr io.Writer) int {
	iv := watch.NormalizeInterval(interval)

	// Fail fast when the host has no clipboard tool at all: there's nothing to
	// watch, and looping would just spam the same error forever. A transient
	// read failure (tool present but momentarily broken) is NOT fatal here —
	// only the "no tool installed" sentinel is — so a flaky compositor still
	// lets watch mode start and recover.
	if _, err := clipboard.Read(); err != nil && errors.Is(err, clipboard.ErrNoClipboardTool) {
		fmt.Fprintf(stderr, "leakpeek: watch needs a clipboard tool: %v\n", err)
		return exitError
	}

	// Ctrl-C / SIGTERM cancels the context, which unwinds the watch loop.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	notifier := notify.New()

	ticker := time.NewTicker(iv)
	defer ticker.Stop()

	// lastErr throttles error spam: a recurring identical failure (e.g. the
	// clipboard tool intermittently unavailable) is logged once, not on every
	// tick, and re-logs only when the message changes or after a recovery.
	var lastErr string

	w := &watch.Watcher{
		Read:     clipboard.Read,
		Scan:     watch.EngineScan(engine),
		Interval: iv,
		Notify: func(total int, kinds []string) {
			title, body := notify.Message(total, kinds)
			notifier.Notify(title, body, stderr)
			lastErr = "" // a successful read/scan clears the throttle
		},
		OnHit: func(total int, kinds []string, at time.Time) {
			noun := "secret"
			if total != 1 {
				noun = "secrets"
			}
			kindStr := ""
			if len(kinds) > 0 {
				kindStr = " (" + strings.Join(kinds, ", ") + ")"
			}
			fmt.Fprintf(stderr, "🚫 %s  %d %s%s on your clipboard — don't paste that.\n",
				at.Format("15:04:05"), total, noun, kindStr)
		},
		OnClean: func(time.Time) { lastErr = "" },
		OnError: func(err error) {
			// Clipboard read hiccups are non-fatal; note them but keep watching.
			// Collapse repeats so a persistent transient failure doesn't flood.
			msg := err.Error()
			if msg == lastErr {
				return
			}
			lastErr = msg
			fmt.Fprintf(stderr, "leakpeek: watch: %v (will keep trying)\n", err)
		},
	}

	watch.WriteBanner(stderr, iv)
	if err := w.Run(ctx, ticker.C); err != nil && err != context.Canceled {
		fmt.Fprintf(stderr, "leakpeek: watch: %v\n", err)
		return exitError
	}
	fmt.Fprintln(stderr, "👋 leakpeek stopped watching.")
	return exitClean
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
