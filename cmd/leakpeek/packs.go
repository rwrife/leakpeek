package main

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/rwrife/leakpeek/internal/rules"
)

const packsUsage = `Usage:
  leakpeek packs list          List local packs (name, version, rules, path).
  leakpeek packs show <name>   Show a pack's detectors.

Search order (first match wins): LEAKPEEK_PACKS, ~/.config/leakpeek/packs/,
then ./.leakpeek/packs/. Packs are entirely local; no registry or network.
`

func runPacks(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprint(stdout, packsUsage)
		return exitClean
	}
	if !(len(args) == 1 && args[0] == "list" || len(args) == 2 && args[0] == "show") {
		fmt.Fprint(stderr, packsUsage)
		return exitUsage
	}
	roots, err := rules.PackSearchPaths()
	if err != nil {
		fmt.Fprintf(stderr, "leakpeek: %v\n", err)
		return exitError
	}
	w := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	if args[0] == "list" {
		packs, err := rules.ListPacks(roots)
		if err != nil {
			fmt.Fprintf(stderr, "leakpeek: %v\n", err)
			return exitError
		}
		fmt.Fprintln(w, "NAME\tVERSION\tRULES\tPATH")
		for _, pack := range packs {
			fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", pack.Name, pack.Version, len(pack.Detectors), pack.Path)
		}
	} else {
		pack, err := rules.ResolvePack(args[1], roots)
		if err != nil {
			fmt.Fprintf(stderr, "leakpeek: %v\n", err)
			return exitError
		}
		fmt.Fprintf(w, "%s %s\n%s\n", pack.Name, pack.Version, pack.Path)
		if pack.Description != "" {
			fmt.Fprintln(w, pack.Description)
		}
		fmt.Fprintln(w, "DETECTOR\tKIND")
		for _, d := range pack.Detectors {
			fmt.Fprintf(w, "%s\t%s\n", d.Name(), d.Kind())
		}
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintf(stderr, "leakpeek: writing packs output: %v\n", err)
		return exitError
	}
	return exitClean
}
