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
// clipboard on an interval, alerting the instant a secret lands on it. With
// `--fix --format-aware`, redaction is structure-aware: for JSON/YAML/.env
// input it scrubs the values that carry a secret and keeps keys and shape.
//
// The reversible vault closes the loop with an AI: `--fix --strategy vault`
// swaps each secret for an opaque, restorable placeholder and remembers the
// mapping in a short-lived, owner-only session file; later, `--unredact`
// reads the AI's reply (clipboard or pipe) and splices your originals back
// in. `--vault-clear` wipes the session so nothing lingers. See PLAN.md for
// the roadmap.
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

	"github.com/rwrife/leakpeek/internal/allow"
	annotatepkg "github.com/rwrife/leakpeek/internal/annotate"
	"github.com/rwrife/leakpeek/internal/clipboard"
	"github.com/rwrife/leakpeek/internal/detect"
	"github.com/rwrife/leakpeek/internal/notify"
	"github.com/rwrife/leakpeek/internal/redact"
	"github.com/rwrife/leakpeek/internal/report"
	"github.com/rwrife/leakpeek/internal/rules"
	"github.com/rwrife/leakpeek/internal/stats"
	"github.com/rwrife/leakpeek/internal/vault"
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
  leakpeek scan [flags] <path>...   Frisk files/folders before you share them.

Scans your clipboard (or stdin) for secrets, keys, and PII and prints what
it found. Exits %d when something is found, %d when clean.

With --fix it also hands back a redacted copy: written to the clipboard, or
printed to stdout when the input came from a pipe.

With --strategy vault the redaction is *reversible*: secrets become opaque
[LEAKPEEK:…] placeholders and the mapping is saved to a short-lived,
owner-only session. After the AI replies, run --unredact to restore your
originals from its response.

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
                     hint like sk-REDACTED), full ([REDACTED-<KIND>]), hash
                     ([<KIND>:<8hex>], stable & non-reversible), or vault
                     ([LEAKPEEK:<hex>], reversible via --unredact).
  --unredact         Reverse a previous --strategy vault redaction: read the
                     AI's reply (clipboard or pipe) and restore the original
                     secrets from the saved session. Clears the session on a
                     successful restore unless --keep-vault is given.
  --vault-clear      Delete the saved reversible-redaction session and exit.
                     Use this to forget stored secrets on demand.
  --keep-vault       With --unredact, keep the session afterward (default is
                     to clear it once restored) so you can un-redact again.
  --no-vault         With --fix --strategy vault, do NOT persist the mapping
                     to disk. The redaction still works, but --unredact in a
                     later run won't be able to reverse it.
  --format-aware     With --fix, redact structure-aware: for JSON/YAML/.env
                     input, scrub the *values* that hold a secret and keep the
                     keys and shape, so the AI still sees the structure. Falls
                     back to normal redaction for plain text. (Aka --format.)
  --annotate         With --fix, append a short provenance footer summarizing
                     what was redacted by kind/count (never values), e.g.
                     [leakpeek: redacted 2 API keys, 1 email]. --json mirrors
                     it in an "annotation" field.
  --rules <path>     Load extra detectors from a TOML rule file or a directory
                     of *.toml files. Custom rules run alongside the built-ins.
  --ignore <path>    Load allowlist entries from an ignore file (repeatable).
                     Layered on top of any discovered .leakpeekignore files;
                     honored even with --no-ignore.
  --no-ignore        Don't auto-discover .leakpeekignore / global ignore files
                     for this run. Explicit --ignore paths still apply.
  --strict           Paranoid entropy tuning: flag more generic high-entropy
                     tokens (lower entropy floor). Best before pasting into a
                     public forum. Mutually exclusive with --chill.
  --chill            Relaxed entropy tuning: flag fewer generic tokens (higher
                     floor) and drop bare internal-IP hits. Best for trusted
                     internal chats. Mutually exclusive with --strict.
                     Default (neither flag) keeps the balanced tuning.
  --stats            Print leakpeek's fully-local, opt-in leak counter (total
                     stopped, this month, streak, top kinds) and exit. With
                     --json, prints the raw stats object. Numbers never leave
                     this machine.
  --stats-record     Record this run into the local stats counter. Recording
                     is otherwise off; enable it persistently with the env var
                     LEAKPEEK_STATS=1. A run that stops >=1 leak counts as a
                     stopped leak. Best-effort — never fails a scan.
  --stats-reset      Zero the local stats counters (keeps the first-seen date)
                     and exit.
  --stats-clear      Delete the local stats file entirely and exit.
  --json             Emit machine-readable JSON instead of the human report.
  --quiet            Print nothing on a clean scan (still reports on a hit).
  --stdin            Read text from stdin instead of the clipboard.
  --version          Print the leakpeek version and exit.
  -h, --help         Show this help and exit.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// dropKind returns findings with every entry of the given kind removed. It
// backs --chill's default suppression of bare network (IPv4) hits without
// mutating the input slice.
func dropKind(findings []detect.Finding, kind detect.Kind) []detect.Finding {
	out := findings[:0:0]
	for _, f := range findings {
		if f.Kind == kind {
			continue
		}
		out = append(out, f)
	}
	return out
}

// appendFooter attaches the provenance footer to redacted text on its own
// trailing line. If the text already ends in a newline the footer slots right
// after it (preserving that newline); otherwise a separating newline is
// inserted first. The footer itself gets a trailing newline so the payload
// stays line-clean for pipes and clipboard alike.
func appendFooter(redacted, footer string) string {
	if footer == "" {
		return redacted
	}
	if redacted == "" {
		return footer + "\n"
	}
	if strings.HasSuffix(redacted, "\n") {
		return redacted + footer + "\n"
	}
	return redacted + "\n" + footer + "\n"
}

// run is the testable entry point. It returns the process exit code.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	// Subcommand dispatch. `leakpeek scan <path>...` frisks files/folders and
	// owns its own flag parsing (it takes positional path args, which the
	// clipboard path's hand-rolled parser doesn't). We intercept it before the
	// flag loop so a leading `scan` token is never misread as an unknown flag.
	if len(args) > 0 && args[0] == "scan" {
		return runScan(args[1:], stdout, stderr)
	}

	var (
		showVersion bool
		useStdin    bool
		asJSON      bool
		quiet       bool
		fix         bool
		strategy    = redact.Shape
		rulesPath   string
		ignorePaths []string
		noIgnore    bool
		watchMode   bool
		interval    time.Duration
		unredact    bool
		vaultClear  bool
		keepVault   bool
		noVault     bool
		formatAware bool
		annotate    bool
		strict      bool
		chill       bool
		showStats   bool
		statsRecord bool
		statsReset  bool
		statsClear  bool
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
		case "--unredact", "-unredact":
			unredact = true
		case "--vault-clear", "-vault-clear":
			vaultClear = true
		case "--keep-vault", "-keep-vault":
			keepVault = true
		case "--no-vault", "-no-vault":
			noVault = true
		case "--format-aware", "-format-aware", "--format", "-format":
			formatAware = true
		case "--annotate", "-annotate":
			annotate = true
		case "--strict", "-strict":
			strict = true
		case "--chill", "-chill":
			chill = true
		case "--stats", "-stats":
			showStats = true
		case "--stats-record", "-stats-record":
			statsRecord = true
		case "--stats-reset", "-stats-reset":
			statsReset = true
		case "--stats-clear", "-stats-clear":
			statsClear = true
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
		case "--ignore", "-ignore":
			val := inlineVal
			if !hasInline {
				// Consume the following argument as the path.
				if i+1 >= len(args) {
					fmt.Fprintf(stderr, "leakpeek: --ignore needs a path to an ignore file\n\n")
					fmt.Fprintf(stderr, usage, version, exitFound, exitClean)
					return exitUsage
				}
				i++
				val = args[i]
			}
			if strings.TrimSpace(val) == "" {
				fmt.Fprintf(stderr, "leakpeek: --ignore path must not be empty\n\n")
				fmt.Fprintf(stderr, usage, version, exitFound, exitClean)
				return exitUsage
			}
			// --ignore is repeatable: every path is loaded and merged, so a
			// user can layer a scratch allowlist on top of their project one.
			ignorePaths = append(ignorePaths, val)
		case "--no-ignore", "-no-ignore":
			noIgnore = true
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

	// --vault-clear is a standalone lifecycle command: wipe the saved
	// reversible-redaction session and exit. It reads no input and runs no
	// detectors — it exists purely so a user can say "forget my stored secrets
	// now" without redacting or un-redacting anything.
	if vaultClear {
		return runVaultClear(stdout, stderr)
	}

	// Stats lifecycle commands are standalone, like --vault-clear: they read no
	// scan input and run no detectors. --stats prints the counter, --stats-reset
	// zeroes it, --stats-clear deletes it. They short-circuit before any
	// detection wiring.
	if statsClear {
		return runStatsClear(stdout, stderr)
	}
	if statsReset {
		return runStatsReset(stdout, stderr)
	}
	if showStats {
		return runStats(asJSON, stdout, stderr)
	}

	// Build the detection engine: always the built-in pack, plus any custom
	// rules the user pointed --rules at. Custom detectors are appended after
	// the built-ins so a real credential still reports under its precise
	// built-in name during dedupe, while user rules claim spans nothing else
	// did. A bad rules path/file is an operational error (exit 1), reported
	// before we scan so the user knows their rules never loaded. The engine is
	// built before we touch any input because --watch never reads a one-shot
	// input at all — it polls the clipboard on its own schedule.
	// Resolve the entropy sensitivity profile from --strict / --chill. The two
	// are mutually exclusive named dials over the generic high-entropy gate;
	// passing both is a usage error. Only the entropy detector's thresholds
	// change — structured detectors are identical across all three profiles.
	// --chill additionally suppresses bare-IP (KindNetwork) findings, since
	// internal IPs are the most common low-value hit.
	if strict && chill {
		fmt.Fprintf(stderr, "leakpeek: --strict and --chill are mutually exclusive; pick one\n\n")
		fmt.Fprintf(stderr, usage, version, exitFound, exitClean)
		return exitUsage
	}
	profile := detect.ProfileDefault
	profileName := "default"
	switch {
	case strict:
		profile, profileName = detect.ProfileStrict, "strict"
	case chill:
		profile, profileName = detect.ProfileChill, "chill"
	}

	engine := detect.DefaultProfile(profile)
	if rulesPath != "" {
		custom, err := rules.LoadPath(rulesPath)
		if err != nil {
			fmt.Fprintf(stderr, "leakpeek: %v\n", err)
			return exitError
		}
		engine = engine.WithDetectors(custom...)
	}

	// Build the allowlist (PLAN.md §8.2): a post-detection filter that drops
	// findings the user marked known-safe. Unless --no-ignore is set, we
	// discover .leakpeekignore files by walking up from cwd and merge the
	// global config-dir ignore; explicit --ignore paths are layered on top and
	// are always honored even with --no-ignore (an explicit path is an explicit
	// request). A present-but-broken ignore file is an operational error (exit
	// 1), reported before we scan so the user knows their allowlist never
	// loaded rather than silently failing open.
	var allowSet allow.Set
	if !noIgnore {
		discovered, err := allow.Discover("")
		if err != nil {
			fmt.Fprintf(stderr, "leakpeek: %v\n", err)
			return exitError
		}
		allowSet = discovered
	}
	if len(ignorePaths) > 0 {
		explicit, err := allow.LoadFiles(ignorePaths)
		if err != nil {
			fmt.Fprintf(stderr, "leakpeek: %v\n", err)
			return exitError
		}
		allowSet = allowSet.Merge(explicit)
	}

	// --watch: hand off to the resident clipboard watcher. It owns its own
	// read loop, so none of the one-shot input/report machinery below runs.
	if watchMode {
		return runWatch(engine, allowSet, interval, stderr)
	}

	// --unredact is the reverse of --fix --strategy vault: it reads the AI's
	// reply (clipboard or pipe), loads the saved session, and splices the
	// original secrets back over their placeholders. It runs no detectors —
	// there's nothing to detect, only placeholders to restore — so it
	// short-circuits before the scan machinery below. It honors --stdin/pipe
	// for input the same way the scan path does, and (like --fix) sends its
	// restored payload to stdout when piped, or back to the clipboard
	// otherwise.
	if unredact {
		text, piped, err := readInput(useStdin, stdin)
		if err != nil {
			fmt.Fprintf(stderr, "leakpeek: %v\n", err)
			return exitError
		}
		return runUnredact(text, piped, keepVault, quiet, stdout, stderr)
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
	// --chill suppresses bare network (IPv4) findings by default: internal IPs
	// are the most common "meh" hit, and a relaxed run shouldn't nag about
	// them. Structured secrets are untouched. (#22 allowlist work can later
	// override this per-value.)
	if chill {
		findings = dropKind(findings, detect.KindNetwork)
	}
	// Allowlist post-filter: drop known-safe findings before anything reports
	// or redacts them, so a suppressed token is neither counted nor scrubbed by
	// --fix. ignored feeds the report's suppression footer / --json count.
	findings, ignored := allowSet.Filter(findings)
	res := report.Build(text, findings, ignored)
	res.Profile = profileName

	// --fix: redact and hand back a safe copy. When the input came from a
	// pipe we print the (possibly unchanged) redacted text to stdout so the
	// tool composes in shell pipelines even on a clean input. When it came
	// from the clipboard we only write back if we actually found something,
	// to avoid needlessly churning the clipboard on a clean scan. The human
	// report then goes to stderr so it never contaminates piped stdout.
	if fix {
		recordStats(statsRecord, res, findings)
		return runFix(res, findings, text, strategy, piped, asJSON, quiet, noVault, formatAware, annotate, stdout, stderr)
	}

	// Best-effort stats recording (opt-in). Do this before we render/return so
	// both --fix and plain paths could share it — here it covers the report
	// path; runFix records separately. A failure is swallowed: a vanity counter
	// must never change a scan's exit code.
	recordStats(statsRecord, res, findings)

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

// statsEnabled reports whether recording should happen this run: either the
// per-run --stats-record flag, or the persistent LEAKPEEK_STATS env opt-in.
// Any "truthy" value for the env var (1/true/yes/on) enables it.
func statsEnabled(flag bool) bool {
	if flag {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("LEAKPEEK_STATS"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// resultKinds returns the distinct finding kinds present in a result, for the
// stats byKind tally.
func resultKinds(res report.Result) []string {
	out := make([]string, 0, len(res.Groups))
	seen := map[string]struct{}{}
	for _, g := range res.Groups {
		k := string(g.Kind)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}

// recordStats folds one scan into the local counter when recording is enabled.
// It is strictly best-effort: any error is intentionally discarded so a stats
// hiccup can never affect the scan's exit code (issue #24's hard rule).
func recordStats(flag bool, res report.Result, findings []detect.Finding) {
	if !statsEnabled(flag) {
		return
	}
	_ = stats.RecordAndSave(stats.DefaultPath(), !res.Clean, resultKinds(res), time.Now())
}

// runStats prints the local leak counter (human or JSON) and exits clean. A
// read failure is a real error (exit 1) here because the user explicitly asked
// to see the numbers — unlike the recording path, silence would be confusing.
func runStats(asJSON bool, stdout, stderr io.Writer) int {
	s, err := stats.Load(stats.DefaultPath())
	if err != nil {
		fmt.Fprintf(stderr, "leakpeek: %v\n", err)
		return exitError
	}
	if asJSON {
		if err := stats.RenderJSON(stdout, s); err != nil {
			fmt.Fprintf(stderr, "leakpeek: rendering json: %v\n", err)
			return exitError
		}
		return exitClean
	}
	stats.Render(stdout, s, time.Now())
	return exitClean
}

// runStatsReset zeroes the local counters (keeping the first-seen date) and
// confirms. A missing file just starts and stays at zero.
func runStatsReset(stdout, stderr io.Writer) int {
	path := stats.DefaultPath()
	s, err := stats.Load(path)
	if err != nil {
		fmt.Fprintf(stderr, "leakpeek: %v\n", err)
		return exitError
	}
	s.Reset()
	if err := stats.Save(path, s); err != nil {
		fmt.Fprintf(stderr, "leakpeek: %v\n", err)
		return exitError
	}
	fmt.Fprintln(stdout, "🧮 leakpeek stats reset to zero. (Local-only; nothing was ever transmitted.)")
	return exitClean
}

// runStatsClear deletes the local stats file and confirms. A missing file is a
// fine "already clean" outcome.
func runStatsClear(stdout, stderr io.Writer) int {
	removed, err := stats.Clear(stats.DefaultPath())
	if err != nil {
		fmt.Fprintf(stderr, "leakpeek: %v\n", err)
		return exitError
	}
	if removed {
		fmt.Fprintln(stdout, "🧹 leakpeek stats file deleted. The counter is gone.")
	} else {
		fmt.Fprintln(stdout, "✨ No leakpeek stats file to clear — nothing stored.")
	}
	return exitClean
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
func runWatch(engine *detect.Engine, allowSet allow.Set, interval time.Duration, stderr io.Writer) int {
	iv := watch.NormalizeInterval(interval)

	// Adapt the allowlist into the filter shape the watcher expects: drop the
	// suppressed-count (watch mode's per-hit alert doesn't surface it) and keep
	// only the survivors, so an allowlisted token never triggers a watch alert.
	var filter func([]detect.Finding) []detect.Finding
	if !allowSet.Empty() {
		filter = func(fs []detect.Finding) []detect.Finding {
			kept, _ := allowSet.Filter(fs)
			return kept
		}
	}
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
		Scan:     watch.EngineScanFiltered(engine, filter),
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
//
// When strategy is redact.Vault the redaction is reversible: secrets become
// [LEAKPEEK:…] placeholders and, unless noVault is set, the placeholder→secret
// mapping is persisted to a private session so a later --unredact can reverse
// it. Persisting is best-effort in the sense that a save failure is surfaced
// as an error (the user asked for reversibility and should know it didn't
// stick), but the redacted text is still delivered first so the secret is
// never left on the clipboard.
func runFix(
	res report.Result,
	findings []detect.Finding,
	text string,
	strategy redact.Strategy,
	piped, asJSON, quiet, noVault, formatAware, annotate bool,
	stdout, stderr io.Writer,
) int {
	var (
		redacted  string
		vaultSave *vault.Vault // non-nil only when we should persist a session
	)
	switch {
	case strategy == redact.Vault:
		v := vault.New()
		redacted = redact.RedactWithVault(text, findings, v)
		// Only persist when we actually captured mappings and the user didn't
		// opt out. An empty vault (clean scan) has nothing to save.
		if !noVault && !v.Empty() {
			vaultSave = v
		}
	case formatAware:
		// Structure-preserving redaction: for JSON/YAML/.env input, scrub the
		// values that carry a secret and leave keys/structure intact, so the AI
		// still sees the shape. Falls back to span-based redaction for plain
		// text (and for any finding outside a recognized value).
		redacted = redact.FormatAwareOrPlain(text, findings, strategy)
	default:
		redacted = redact.Redact(text, findings, strategy)
	}

	// --annotate: append a provenance footer summarizing what was redacted, by
	// kind/count (never values). Only when we actually redacted something. The
	// footer notes reversibility when the vault strategy persisted a session.
	var footer string
	if annotate && !res.Clean {
		footer = annotatepkg.Footer(findings, strategy == redact.Vault)
		if footer != "" {
			redacted = appendFooter(redacted, footer)
		}
	}

	if piped {
		// Pipe mode: redacted text is the payload, so it owns stdout. Print it
		// verbatim (no trailing newline added) and route any report to stderr.
		if _, err := io.WriteString(stdout, redacted); err != nil {
			fmt.Fprintf(stderr, "leakpeek: writing redacted output: %v\n", err)
			return exitError
		}
		if err := persistVault(vaultSave); err != nil {
			fmt.Fprintf(stderr, "leakpeek: %v\n", err)
			return exitError
		}
		emitFixReport(res, asJSON, quiet, stderr, stderr, false, vaultSave != nil, footer)
	} else {
		// Clipboard mode: only write back when we changed something, so a clean
		// scan leaves the clipboard untouched.
		if !res.Clean {
			if err := clipboard.Write(redacted); err != nil {
				fmt.Fprintf(stderr, "leakpeek: %v\n", err)
				return exitError
			}
		}
		if err := persistVault(vaultSave); err != nil {
			fmt.Fprintf(stderr, "leakpeek: %v\n", err)
			return exitError
		}
		emitFixReport(res, asJSON, quiet, stdout, stderr, true, vaultSave != nil, footer)
	}

	if res.Clean {
		return exitClean
	}
	return exitFound
}

// persistVault saves v to the default session directory when v is non-nil.
// A nil v (non-vault strategy, opted out, or empty) is a no-op returning nil.
func persistVault(v *vault.Vault) error {
	if v == nil {
		return nil
	}
	if err := v.Save(vault.DefaultDir()); err != nil {
		return fmt.Errorf("saving reversible-redaction session: %w", err)
	}
	return nil
}

// emitFixReport writes the findings report for a --fix run to out (JSON or the
// human table). On a hit in human mode it adds a short confirmation line; the
// wording depends on where the redacted copy went — the clipboard (toClipboard
// true) or stdout (false). When savedVault is true it also notes that the
// mapping was stored and how to reverse it, so the reversible workflow is
// discoverable right where it's used.
func emitFixReport(res report.Result, asJSON, quiet bool, out, jsonErr io.Writer, toClipboard, savedVault bool, footer string) {
	if asJSON {
		// Mirror the human footer into the machine-readable document so --json
		// consumers see the same provenance summary.
		res.Annotation = footer
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
		if footer != "" {
			fmt.Fprintf(out, "🏷️  %s\n", footer)
		}
		if savedVault {
			fmt.Fprintln(out, "🔐 Reversible: after the AI replies, run `leakpeek --unredact` to restore your secrets.")
		}
	}
}

// runUnredact reverses a prior reversible redaction. It loads the saved
// session, restores the original secrets over their placeholders in text, and
// delivers the result to stdout (pipe input) or the clipboard (otherwise).
// Unless keepVault is set, it clears the session after a successful restore so
// the stored secrets don't linger past their single intended use.
//
// Exit codes: exitClean on success (including the benign "nothing to restore"
// cases, which are informational, not failures) and exitError only on a real
// I/O failure (couldn't read the session for a non-"missing"/non-"expired"
// reason, or couldn't write the restored text back).
func runUnredact(text string, piped, keepVault, quiet bool, stdout, stderr io.Writer) int {
	dir := vault.DefaultDir()

	v, err := vault.Load(dir)
	if err != nil {
		switch {
		case errors.Is(err, vault.ErrNoSession):
			fmt.Fprintln(stderr, "leakpeek: no reversible-redaction session to restore from.")
			fmt.Fprintln(stderr, "  (Redact with `--fix --strategy vault` first, and don't pass --no-vault.)")
			return exitClean
		case errors.Is(err, vault.ErrExpired):
			fmt.Fprintln(stderr, "leakpeek: your reversible-redaction session expired and was cleared.")
			fmt.Fprintln(stderr, "  Re-redact the original text to un-redact a fresh reply.")
			return exitClean
		default:
			fmt.Fprintf(stderr, "leakpeek: %v\n", err)
			return exitError
		}
	}

	restored, n := v.Restore(text)

	if n == 0 {
		// The session loaded but none of its placeholders appear in the input.
		// Don't touch the clipboard or emit the (unchanged) text to a pipe's
		// stdout would be harmless, but for clipboard mode we deliberately
		// leave things be. Tell the user why nothing happened.
		if piped {
			_, _ = io.WriteString(stdout, restored)
		}
		if !quiet {
			msg := "leakpeek: no leakpeek placeholders found in the input — nothing to un-redact."
			if !vault.LooksLikePlaceholder(text) {
				msg += "\n  (Did you paste the AI's reply that still contains the [LEAKPEEK:…] tokens?)"
			}
			fmt.Fprintln(stderr, msg)
		}
		return exitClean
	}

	// Deliver the restored text.
	if piped {
		if _, err := io.WriteString(stdout, restored); err != nil {
			fmt.Fprintf(stderr, "leakpeek: writing restored output: %v\n", err)
			return exitError
		}
	} else {
		if err := clipboard.Write(restored); err != nil {
			fmt.Fprintf(stderr, "leakpeek: %v\n", err)
			return exitError
		}
	}

	// Lifecycle: clear the session after a successful restore unless asked to
	// keep it. Clearing is the safe default — the secrets have served their
	// purpose — but a clear failure is non-fatal: the un-redaction already
	// succeeded, so we warn rather than fail the whole command.
	cleared := false
	if !keepVault {
		if _, cerr := vault.Clear(dir); cerr != nil {
			fmt.Fprintf(stderr, "leakpeek: warning: %v (session left in place)\n", cerr)
		} else {
			cleared = true
		}
	}

	if !quiet {
		noun := "secret"
		if n != 1 {
			noun = "secrets"
		}
		dest := "clipboard"
		if piped {
			dest = "stdout"
		}
		fmt.Fprintf(stderr, "🔓 Restored %d %s to your %s.\n", n, noun, dest)
		if cleared {
			fmt.Fprintln(stderr, "🧹 Session cleared. (Pass --keep-vault to un-redact again.)")
		} else if keepVault {
			fmt.Fprintln(stderr, "📌 Session kept (--keep-vault). Run --vault-clear when you're done.")
		}
	}
	return exitClean
}

// runVaultClear wipes the saved reversible-redaction session and reports what
// happened. It always returns exitClean unless the removal itself failed
// (exitError); a missing session is a perfectly fine "already clean" outcome.
func runVaultClear(stdout, stderr io.Writer) int {
	removed, err := vault.Clear(vault.DefaultDir())
	if err != nil {
		fmt.Fprintf(stderr, "leakpeek: %v\n", err)
		return exitError
	}
	if removed {
		fmt.Fprintln(stdout, "🧹 Reversible-redaction session cleared. Stored secrets are gone.")
	} else {
		fmt.Fprintln(stdout, "✨ No reversible-redaction session to clear — nothing stored.")
	}
	return exitClean
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
