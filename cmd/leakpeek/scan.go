package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rwrife/leakpeek/internal/allow"
	"github.com/rwrife/leakpeek/internal/detect"
	"github.com/rwrife/leakpeek/internal/rules"
	"github.com/rwrife/leakpeek/internal/scan"
)

const scanUsage = `leakpeek scan %s — frisk files and folders before you share them.

Usage:
  leakpeek scan [flags] <path>...

Walks each path (files directly, directories recursively), runs the detector
engine over every text file, and reports findings grouped per file. Binary
files are skipped. Honors .leakpeekignore / --ignore allowlists and the custom
--rules and --rule-pack bundles, exactly like the clipboard path.

Exits %d when any file has a finding, %d when everything is clean.

Flags:
  --rules <path>     Load extra detectors from a TOML file or directory.
  --rule-pack <name> Load a named local rule pack (repeatable).
  --ignore <path>    Load allowlist entries from an ignore file (repeatable).
  --no-ignore        Don't auto-discover .leakpeekignore files for this run.
  --strict           Paranoid entropy tuning (flag more generic tokens).
  --chill            Relaxed entropy tuning (flag fewer; drop bare IPs).
  --json             Emit a machine-readable files[] document.
  --quiet            Print only files that have hits (silent on a clean scan).
  -h, --help         Show this help and exit.
`

// skipDirNames are directories scan mode prunes by default: version-control
// and dependency dirs that are huge, noisy, and rarely the thing you're about
// to hand to an AI. .leakpeekignore can't express "skip this dir from the
// walk" (it suppresses findings, not traversal), so this is a separate, small,
// conservative list.
var skipDirNames = map[string]struct{}{
	".git":         {},
	".hg":          {},
	".svn":         {},
	"node_modules": {},
	".venv":        {},
	"vendor":       {},
}

// runScan implements `leakpeek scan <path>...`. It parses scan-mode flags,
// builds the engine + allowlist the same way the main path does, walks the
// paths, and renders the per-file report (human or JSON). It returns the
// process exit code: exitFound if any file had a finding, exitClean when clean,
// exitUsage on a flag error, exitError on an operational failure. args is the
// argument slice *after* the `scan` subcommand token.
func runScan(args []string, stdout, stderr io.Writer) int {
	var (
		asJSON      bool
		quiet       bool
		rulesPath   string
		rulePacks   []string
		ignorePaths []string
		noIgnore    bool
		strict      bool
		chill       bool
		paths       []string
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		name, inlineVal, hasInline := splitFlag(arg)

		needsValue := func(label string) (string, bool) {
			if hasInline {
				return inlineVal, true
			}
			if i+1 >= len(args) {
				fmt.Fprintf(stderr, "leakpeek: %s needs a value\n\n", label)
				fmt.Fprintf(stderr, scanUsage, version, exitFound, exitClean)
				return "", false
			}
			i++
			return args[i], true
		}

		switch name {
		case "--json", "-json":
			asJSON = true
		case "--quiet", "-quiet", "-q":
			quiet = true
		case "--no-ignore", "-no-ignore":
			noIgnore = true
		case "--strict", "-strict":
			strict = true
		case "--chill", "-chill":
			chill = true
		case "--rule-pack", "-rule-pack":
			v, ok := needsValue("--rule-pack")
			if !ok {
				return exitUsage
			}
			if strings.TrimSpace(v) == "" || !hasInline && strings.HasPrefix(v, "-") {
				fmt.Fprintln(stderr, "leakpeek: --rule-pack needs a non-empty pack name")
				return exitUsage
			}
			rulePacks = append(rulePacks, v)
		case "--rules", "-rules":
			v, ok := needsValue("--rules")
			if !ok {
				return exitUsage
			}
			if strings.TrimSpace(v) == "" {
				fmt.Fprintf(stderr, "leakpeek: --rules path must not be empty\n")
				return exitUsage
			}
			rulesPath = v
		case "--ignore", "-ignore":
			v, ok := needsValue("--ignore")
			if !ok {
				return exitUsage
			}
			if strings.TrimSpace(v) == "" {
				fmt.Fprintf(stderr, "leakpeek: --ignore path must not be empty\n")
				return exitUsage
			}
			ignorePaths = append(ignorePaths, v)
		case "-h", "--help", "-help":
			fmt.Fprintf(stdout, scanUsage, version, exitFound, exitClean)
			return exitClean
		default:
			if strings.HasPrefix(arg, "-") && arg != "-" {
				fmt.Fprintf(stderr, "leakpeek: unknown flag %q\n\n", arg)
				fmt.Fprintf(stderr, scanUsage, version, exitFound, exitClean)
				return exitUsage
			}
			// A bare (non-flag) argument is a path to scan.
			paths = append(paths, arg)
		}
	}

	if len(paths) == 0 {
		fmt.Fprintf(stderr, "leakpeek: %v\n\n", scan.ErrNoPaths)
		fmt.Fprintf(stderr, scanUsage, version, exitFound, exitClean)
		return exitUsage
	}

	if strict && chill {
		fmt.Fprintf(stderr, "leakpeek: --strict and --chill are mutually exclusive; pick one\n")
		return exitUsage
	}
	profile := detect.ProfileDefault
	switch {
	case strict:
		profile = detect.ProfileStrict
	case chill:
		profile = detect.ProfileChill
	}

	engine := detect.DefaultProfile(profile)
	custom, err := rules.LoadExtras(rulesPath, rulePacks)
	if err != nil {
		fmt.Fprintf(stderr, "leakpeek: %v\n", err)
		return exitError
	}
	engine = engine.WithDetectors(custom...)

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

	opts := scan.Options{
		Engine: engine,
		SkipDir: func(base, _ string) bool {
			_, skip := skipDirNames[base]
			return skip
		},
	}
	if !allowSet.Empty() {
		opts.Filter = func(fs []detect.Finding) ([]detect.Finding, int) {
			kept, ignored := allowSet.Filter(fs)
			// --chill suppresses bare network (IPv4) hits by default, matching
			// the clipboard path's behavior.
			if chill {
				kept = dropKind(kept, detect.KindNetwork)
			}
			return kept, ignored
		}
	} else if chill {
		opts.Filter = func(fs []detect.Finding) ([]detect.Finding, int) {
			return dropKind(fs, detect.KindNetwork), 0
		}
	}

	res, walkErr := scan.Walk(paths, opts)
	if walkErr != nil {
		// Non-fatal: some path was unreadable. We still report what we scanned,
		// but warn so the user knows coverage was incomplete.
		fmt.Fprintf(stderr, "leakpeek: warning: %v\n", walkErr)
	}

	// readText re-reads a file for masking previews at render time. A file that
	// vanished between walk and render yields empty text (previews degrade to
	// empty rather than crashing) — acceptable for a best-effort report.
	readText := func(path string) string {
		b, err := os.ReadFile(path)
		if err != nil {
			return ""
		}
		return string(b)
	}

	if asJSON {
		if err := scan.RenderJSON(stdout, res, readText); err != nil {
			fmt.Fprintf(stderr, "leakpeek: rendering json: %v\n", err)
			return exitError
		}
	} else {
		scan.Render(stdout, res, readText, quiet)
	}

	if res.Clean() {
		return exitClean
	}
	return exitFound
}
