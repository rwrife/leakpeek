package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/rwrife/leakpeek/internal/detect"
	"github.com/rwrife/leakpeek/internal/rules"
	"github.com/rwrife/leakpeek/internal/verify"
)

const verifyUsage = `Usage:
  leakpeek verify [--json] [--rules <path>]

Self-test every detector independently against an embedded offline corpus.
No clipboard, stdin, allowlist, or network access is used.
Custom rules require <file>.fixtures.json, or <directory>/fixtures.json.
Every detector needs at least one positive and one negative fixture.
Exits 0 on PASS, 1 on FAIL or an operational error, 2 on bad usage.

Flags:
  --rules <path>     Include custom TOML rules and their fixture document.
  --json             Emit a versioned machine-readable verification result.
  -h, --help         Show this help and exit.
`

func runVerify(args []string, stdout, stderr io.Writer) int {
	var asJSON bool
	var rulesPath string
	for i := 0; i < len(args); i++ {
		name, value, inline := splitFlag(args[i])
		switch name {
		case "--json", "-json":
			if inline {
				fmt.Fprintln(stderr, "leakpeek: --json takes no value")
				return exitUsage
			}
			asJSON = true
		case "--rules", "-rules":
			if !inline {
				if i+1 == len(args) {
					fmt.Fprintln(stderr, "leakpeek: --rules needs a value")
					return exitUsage
				}
				i++
				value = args[i]
			}
			if strings.TrimSpace(value) == "" || strings.HasPrefix(value, "-") {
				fmt.Fprintln(stderr, "leakpeek: --rules needs a nonempty path")
				return exitUsage
			}
			rulesPath = value
		case "-h", "--help", "-help":
			if _, err := io.WriteString(stdout, verifyUsage); err != nil {
				fmt.Fprintf(stderr, "leakpeek: writing verification help: %v\n", err)
				return exitError
			}
			return exitClean
		default:
			fmt.Fprintf(stderr, "leakpeek: unknown verify argument %q\n%s", args[i], verifyUsage)
			return exitUsage
		}
	}

	corpus, err := verify.Bundled()
	if err != nil {
		fmt.Fprintf(stderr, "leakpeek: %v\n", err)
		return exitError
	}
	detectors := detect.DefaultDetectors()
	if rulesPath != "" {
		custom, err := rules.LoadPath(rulesPath)
		if err != nil {
			fmt.Fprintf(stderr, "leakpeek: %v\n", err)
			return exitError
		}
		fixtures, err := verify.LoadCustom(rulesPath)
		if err != nil {
			fmt.Fprintf(stderr, "leakpeek: %v\n", err)
			return exitError
		}
		detectors = append(detectors, custom...)
		corpus = append(corpus, fixtures...)
	}
	result, err := verify.Run(detectors, corpus)
	if err != nil {
		fmt.Fprintf(stderr, "leakpeek: %v\n", err)
		return exitError
	}
	if err := renderVerification(stdout, result, asJSON); err != nil {
		fmt.Fprintf(stderr, "leakpeek: writing verification result: %v\n", err)
		return exitError
	}
	if !result.Passed {
		return exitError
	}
	return exitClean
}

func renderVerification(w io.Writer, result verify.Result, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "DETECTOR\tPOSITIVES CAUGHT/TOTAL\tFALSE POSITIVES\tVERDICT")
	for _, row := range result.Detectors {
		fmt.Fprintf(tw, "%s\t%d/%d\t%d\t%s\n", row.Detector,
			row.PositivesCaught, row.PositivesTotal, row.FalsePositives, verificationVerdict(row.Passed))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	for _, row := range result.Detectors {
		for _, failure := range row.Failures {
			fmt.Fprintf(&b, "%s: %s\n", row.Detector, failure)
		}
	}
	fmt.Fprintf(&b, "Overall: %s\n", verificationVerdict(result.Passed))
	_, err := io.WriteString(w, b.String())
	return err
}

func verificationVerdict(passed bool) string {
	if passed {
		return "PASS"
	}
	return "FAIL"
}
