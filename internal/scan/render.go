package scan

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/rwrife/leakpeek/internal/report"
)

// jsonVersion mirrors report.jsonVersion for the scan document; bump on any
// incompatible shape change so scripts can guard on it.
const jsonVersion = 1

// fileDoc is one file's entry in the --json files[] array: its path plus the
// same prepared report.Result the single-blob path emits, so a consumer parses
// per-file findings with the identical schema they already know.
type fileDoc struct {
	Path    string `json:"path"`
	Skipped bool   `json:"skipped,omitempty"`
	Reason  string `json:"reason,omitempty"`
	// report.Result is embedded so its fields (total, findings, groups, verdict)
	// are promoted inline into this file's JSON object — the same schema the
	// clipboard path emits, per file.
	report.Result
}

// scanDoc is the top-level scan --json document.
type scanDoc struct {
	Tool          string    `json:"tool"`
	Version       int       `json:"version"`
	Mode          string    `json:"mode"`
	Total         int       `json:"total"`
	FilesScanned  int       `json:"filesScanned"`
	FilesWithHits int       `json:"filesWithHits"`
	Clean         bool      `json:"clean"`
	Files         []fileDoc `json:"files"`
}

// buildResult turns one file's raw findings into a render-ready report.Result,
// reusing the same masking/grouping/verdict logic as the clipboard path so
// previews and kinds are identical across entry points.
func buildResult(text string, fr FileResult) report.Result {
	return report.Build(text, fr.Findings, fr.Ignored)
}

// RenderJSON writes the machine-readable scan document: a files[] array where
// each element carries the per-file report.Result. It always emits, even when
// clean, so a consumer can always parse a result. text is looked up per file
// via readText so previews can be masked; a file we can't re-read (already
// gone) still appears with its findings but empty previews are acceptable.
func RenderJSON(w io.Writer, res Result, readText func(path string) string) error {
	doc := scanDoc{
		Tool:          "leakpeek",
		Version:       jsonVersion,
		Mode:          "scan",
		Total:         res.Total(),
		FilesWithHits: res.FilesWithHits(),
		Clean:         res.Clean(),
	}
	for _, fr := range res.Files {
		fd := fileDoc{Path: fr.Path, Skipped: fr.Skipped, Reason: fr.Reason}
		if !fr.Skipped {
			doc.FilesScanned++
			fd.Result = buildResult(readText(fr.Path), fr)
		}
		doc.Files = append(doc.Files, fd)
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// Render writes the human-facing scan report to w. Layout: one block per file
// that has findings, showing the path then its grouped table; a summary line
// closes the report. When quiet is true, only files with hits are printed (and
// skipped/clean files stay silent); a fully clean scan prints just the summary
// unless quiet suppresses even that.
func Render(w io.Writer, res Result, readText func(path string) string, quiet bool) {
	printed := 0
	for _, fr := range res.Files {
		if fr.Skipped {
			continue
		}
		if len(fr.Findings) == 0 {
			continue // clean files are summarized, not listed
		}
		if printed > 0 {
			fmt.Fprintln(w)
		}
		printed++
		fmt.Fprintf(w, "📄 %s\n", fr.Path)
		rr := buildResult(readText(fr.Path), fr)
		// Reuse the single-blob renderer for the table + verdict, indented
		// under the filename by the report package's own layout.
		report.Render(w, rr, false)
	}

	if quiet {
		// In quiet mode a clean scan says nothing at all.
		if res.Clean() {
			return
		}
	}

	if printed > 0 {
		fmt.Fprintln(w)
	}
	writeSummary(w, res)
}

// writeSummary prints the one-line scan verdict across all files.
func writeSummary(w io.Writer, res Result) {
	scanned := 0
	for _, fr := range res.Files {
		if !fr.Skipped {
			scanned++
		}
	}
	if res.Clean() {
		fmt.Fprintf(w, "✅ Clean. Scanned %s, nothing to regret.\n", plural(scanned, "file"))
		return
	}
	fmt.Fprintf(w, "🚫 %s across %s (%s scanned). Don't ship that.\n",
		plural(res.Total(), "secret"),
		plural(res.FilesWithHits(), "file"),
		plural(scanned, "file"))
}

// plural renders "1 file" / "3 files".
func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
