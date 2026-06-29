// Package report turns a slice of detect.Findings into something a human (or
// a script) can read: a grouped findings table with masked previews and a
// one-line personality verdict, or a stable machine-readable JSON document.
//
// It is the M3 half of leakpeek — the part that makes the M2 engine's output
// legible. It deliberately knows nothing about clipboards or flags; it takes
// findings + the original text and writes bytes. main.go wires it up and
// decides the process exit code (see PLAN.md §6).
//
// Two render paths share one prepared view of the data (Result):
//
//	Render      → the pretty, colorless-by-default human table + verdict
//	RenderJSON  → a versioned JSON object for --json consumers
//
// Byte offsets from detect.Finding are mapped to 1-based line/column here so
// nothing downstream has to re-derive positions, and previews are masked so
// the report itself never re-leaks the secret it just caught.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/rwrife/leakpeek/internal/detect"
)

// Item is one finding, enriched for output: the raw byte span from the engine
// plus a human 1-based line/column and a masked, paste-safe preview. The
// `Match` is intentionally NOT included so the report can never re-leak it.
type Item struct {
	Detector string      `json:"detector"`
	Kind     detect.Kind `json:"kind"`
	Line     int         `json:"line"`   // 1-based line of the match start
	Column   int         `json:"column"` // 1-based column (rune) of the match start
	Start    int         `json:"start"`  // inclusive byte offset
	End      int         `json:"end"`    // exclusive byte offset
	Preview  string      `json:"preview"`
}

// Group aggregates all items produced by a single detector, so the human
// table can show one row per type with a count and the worst offenders.
type Group struct {
	Detector string      `json:"detector"`
	Kind     detect.Kind `json:"kind"`
	Count    int         `json:"count"`
	Items    []Item      `json:"items"`
}

// Result is the prepared, render-ready view of a scan. Build it once with
// Build, then hand it to Render or RenderJSON.
type Result struct {
	Total   int     `json:"total"` // total number of findings
	Clean   bool    `json:"clean"` // true when Total == 0
	Items   []Item  `json:"findings"`
	Groups  []Group `json:"groups"`
	Verdict string  `json:"verdict"` // the one-line personality summary
}

// Build maps raw findings against the scanned text into a Result: it computes
// line/column, masks each preview, groups by detector, and composes the
// verdict line. text must be the exact string that was scanned so byte
// offsets line up.
func Build(text string, findings []detect.Finding) Result {
	lines := newLineIndex(text)

	items := make([]Item, 0, len(findings))
	for _, f := range findings {
		line, col := lines.position(f.Start)
		items = append(items, Item{
			Detector: f.Detector,
			Kind:     f.Kind,
			Line:     line,
			Column:   col,
			Start:    f.Start,
			End:      f.End,
			Preview:  Mask(f.Kind, f.Match),
		})
	}

	res := Result{
		Total:  len(items),
		Clean:  len(items) == 0,
		Items:  items,
		Groups: group(items),
	}
	res.Verdict = verdict(res)
	return res
}

// group buckets items by detector, preserving first-seen order of detectors
// (items arrive already sorted by position from the engine).
func group(items []Item) []Group {
	if len(items) == 0 {
		return nil
	}
	order := make([]string, 0)
	byName := make(map[string]*Group)
	for _, it := range items {
		g, ok := byName[it.Detector]
		if !ok {
			g = &Group{Detector: it.Detector, Kind: it.Kind}
			byName[it.Detector] = g
			order = append(order, it.Detector)
		}
		g.Count++
		g.Items = append(g.Items, it)
	}
	out := make([]Group, 0, len(order))
	for _, name := range order {
		out = append(out, *byName[name])
	}
	return out
}

// Render writes the human-facing report to w. When quiet is true and the scan
// is clean, it writes nothing at all (the silent-success path for aliases).
//
// Layout:
//
//	🚫 3 things you'd regret pasting:
//	   TYPE              COUNT  WHERE        PREVIEW
//	   aws-access-key        1  line 4:7     AKIA…EX4MPLE
//	   email                 2  line 12:3    j…@example.com (+1 more)
//	<verdict line>
func Render(w io.Writer, res Result, quiet bool) {
	if res.Clean {
		if quiet {
			return
		}
		fmt.Fprintln(w, res.Verdict)
		return
	}

	noun := "thing"
	if res.Total != 1 {
		noun = "things"
	}
	fmt.Fprintf(w, "🚫 %d %s you'd regret pasting:\n", res.Total, noun)

	rows := tableRows(res.Groups)
	writeTable(w, rows)

	fmt.Fprintln(w, res.Verdict)
}

// row is a single rendered table line (pre-formatting), kept as columns so we
// can size them to the widest cell.
type row struct{ typ, count, where, preview string }

// tableRows turns groups into aligned-table source rows. Each detector gets
// one row; "where" points at the first occurrence and the preview shows the
// first match with a "(+N more)" suffix when the detector fired repeatedly.
func tableRows(groups []Group) []row {
	rows := make([]row, 0, len(groups)+1)
	rows = append(rows, row{typ: "TYPE", count: "COUNT", where: "WHERE", preview: "PREVIEW"})
	for _, g := range groups {
		first := g.Items[0]
		preview := first.Preview
		if g.Count > 1 {
			preview = fmt.Sprintf("%s (+%d more)", preview, g.Count-1)
		}
		rows = append(rows, row{
			typ:     g.Detector,
			count:   fmt.Sprintf("%d", g.Count),
			where:   fmt.Sprintf("line %d:%d", first.Line, first.Column),
			preview: preview,
		})
	}
	return rows
}

// writeTable prints rows with two-space gutters, left-aligning text columns
// and right-aligning the count, indented under the header line.
func writeTable(w io.Writer, rows []row) {
	if len(rows) == 0 {
		return
	}
	var wType, wCount, wWhere int
	for _, r := range rows {
		wType = max(wType, len(r.typ))
		wCount = max(wCount, len(r.count))
		wWhere = max(wWhere, len(r.where))
	}
	for i, r := range rows {
		// Header row's count label is left-aligned for readability; data
		// rows right-align the numeric count under it.
		if i == 0 {
			fmt.Fprintf(w, "   %-*s  %-*s  %-*s  %s\n",
				wType, r.typ, wCount, r.count, wWhere, r.where, r.preview)
			continue
		}
		fmt.Fprintf(w, "   %-*s  %*s  %-*s  %s\n",
			wType, r.typ, wCount, r.count, wWhere, r.where, r.preview)
	}
}

// verdict composes the one-line personality summary. Dirty scans name the
// damage; clean scans wave you through.
func verdict(res Result) string {
	if res.Clean {
		return "✅ Clean. Paste away."
	}
	kinds := distinctKinds(res.Groups)
	noun := "secret"
	if res.Total != 1 {
		noun = "secrets"
	}
	return fmt.Sprintf("🚫 %d %s across %s. Don't paste that.",
		res.Total, noun, humanizeList(kinds))
}

// distinctKinds returns the set of finding categories present, in a stable
// (sorted) order, as their string form.
func distinctKinds(groups []Group) []string {
	seen := make(map[string]struct{})
	for _, g := range groups {
		seen[string(g.Kind)] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// humanizeList renders a string slice as "a", "a and b", or "a, b and c".
func humanizeList(xs []string) string {
	switch len(xs) {
	case 0:
		return "nothing"
	case 1:
		return xs[0]
	case 2:
		return xs[0] + " and " + xs[1]
	default:
		return strings.Join(xs[:len(xs)-1], ", ") + " and " + xs[len(xs)-1]
	}
}

// jsonVersion is bumped if the --json shape ever changes incompatibly, so
// scripts can guard on it.
const jsonVersion = 1

// jsonDoc is the top-level --json document. It embeds Result (findings,
// groups, totals, verdict) and stamps a schema version + tool name.
type jsonDoc struct {
	Tool    string `json:"tool"`
	Version int    `json:"version"`
	Result
}

// RenderJSON writes the machine-readable document to w. Unlike the human
// path, --json always emits (even when clean and quiet) so a consumer can
// always parse a result; quiet is intentionally ignored here.
func RenderJSON(w io.Writer, res Result) error {
	doc := jsonDoc{Tool: "leakpeek", Version: jsonVersion, Result: res}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
