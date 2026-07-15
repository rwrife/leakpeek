// Package scan implements leakpeek's file/directory scan mode (PLAN.md §8:
// "scan <path...>"): a fast, local pre-share gut-check for the ad-hoc files
// and folders you're about to zip up and hand to an AI or a vendor.
//
// Where the clipboard/stdin path frisks a single blob of text, scan mode walks
// one or more paths — files and directories, recursively — runs the same
// detection engine over each file's contents, and reports findings grouped per
// file. It deliberately reuses the existing engine, allowlist, and report
// primitives so a secret is detected, masked, and suppressed identically no
// matter which entry point found it.
//
// # What it skips
//
// scan mode is meant for the human-readable stuff you'd actually paste, so it
// skips files that aren't text:
//
//   - Binary files, detected by a NUL byte or invalid UTF-8 in the leading
//     sniff window. Scanning a JPEG for "secrets" is noise.
//   - Files whose contents the caller's allowlist has fully suppressed simply
//     report zero findings (they're walked, just clean).
//
// Directory traversal honors a caller-supplied skip predicate (used to prune
// .git and friends) and never follows symlinks out of the tree.
package scan

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"unicode/utf8"

	"github.com/rwrife/leakpeek/internal/detect"
)

// sniffLen is how many leading bytes we inspect to decide whether a file is
// binary. A NUL byte anywhere in this window, or invalid UTF-8 that isn't just
// a multi-byte rune truncated at the boundary, marks the file binary.
const sniffLen = 8000

// FileResult is the outcome of scanning one file: its path plus the findings
// that survived the allowlist. Findings is nil (not empty) for a clean file so
// callers can cheaply test `len(fr.Findings) == 0`.
type FileResult struct {
	Path     string
	Findings []detect.Finding
	Ignored  int // findings suppressed by the allowlist for this file
	Skipped  bool
	Reason   string // why it was skipped (binary, unreadable), empty otherwise
}

// Result aggregates a whole scan run: one FileResult per file actually visited
// (in stable, sorted path order), plus a count of files that were skipped.
type Result struct {
	Files []FileResult
}

// Total returns the number of surviving findings across every file.
func (r Result) Total() int {
	n := 0
	for _, f := range r.Files {
		n += len(f.Findings)
	}
	return n
}

// FilesWithHits returns how many scanned files had at least one finding.
func (r Result) FilesWithHits() int {
	n := 0
	for _, f := range r.Files {
		if len(f.Findings) > 0 {
			n++
		}
	}
	return n
}

// Clean reports whether the whole run found nothing.
func (r Result) Clean() bool { return r.Total() == 0 }

// Filter is the allowlist hook: given a file's raw findings it returns the
// survivors and how many were suppressed. A nil Filter suppresses nothing.
type Filter func([]detect.Finding) (kept []detect.Finding, ignored int)

// Options configure a scan run.
type Options struct {
	// Engine runs the detectors. Required.
	Engine *detect.Engine
	// Filter applies the allowlist per file. Optional (nil = no suppression).
	Filter Filter
	// SkipDir, if non-nil, is consulted for each directory entry during the
	// walk; returning true prunes it (e.g. .git, node_modules). The base name
	// and full path are both provided.
	SkipDir func(name, path string) bool
}

// Walk scans every path in paths — files directly, directories recursively —
// and returns the aggregated Result. Missing paths and unreadable files are
// reported as skipped FileResults with a Reason rather than aborting the whole
// run, so one bad path doesn't sink a scan of a hundred good files; the first
// such error is also returned so callers can surface a non-fatal warning and
// still adjust their exit code. A genuinely fatal error (e.g. a walk that the
// OS refuses) is returned with a partial Result.
func Walk(paths []string, opts Options) (Result, error) {
	var res Result
	var firstErr error
	noteErr := func(e error) {
		if firstErr == nil {
			firstErr = e
		}
	}

	// De-dupe files that arrive via overlapping paths (e.g. `scan . ./cmd`),
	// keeping the first-seen ordering deterministic by sorting at the end.
	seen := map[string]struct{}{}

	visit := func(path string) {
		abs, err := filepath.Abs(path)
		if err != nil {
			abs = path
		}
		if _, ok := seen[abs]; ok {
			return
		}
		seen[abs] = struct{}{}
		res.Files = append(res.Files, scanFile(path, opts))
	}

	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			res.Files = append(res.Files, FileResult{Path: p, Skipped: true, Reason: "unreadable: " + err.Error()})
			noteErr(err)
			continue
		}
		if !info.IsDir() {
			visit(p)
			continue
		}
		werr := filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				// Report the offending entry but keep walking the rest.
				res.Files = append(res.Files, FileResult{Path: path, Skipped: true, Reason: "unreadable: " + err.Error()})
				noteErr(err)
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				if opts.SkipDir != nil && opts.SkipDir(d.Name(), path) {
					return fs.SkipDir
				}
				return nil
			}
			// Only walk regular files; skip symlinks, sockets, devices.
			if !d.Type().IsRegular() {
				return nil
			}
			visit(path)
			return nil
		})
		if werr != nil {
			noteErr(werr)
		}
	}

	sort.Slice(res.Files, func(i, j int) bool { return res.Files[i].Path < res.Files[j].Path })
	return res, firstErr
}

// scanFile reads and scans a single regular file. Binary files are skipped;
// text files are run through the engine and allowlist.
func scanFile(path string, opts Options) FileResult {
	data, err := os.ReadFile(path)
	if err != nil {
		return FileResult{Path: path, Skipped: true, Reason: "unreadable: " + err.Error()}
	}
	if isBinary(data) {
		return FileResult{Path: path, Skipped: true, Reason: "binary"}
	}
	findings := opts.Engine.Scan(string(data))
	ignored := 0
	if opts.Filter != nil {
		findings, ignored = opts.Filter(findings)
	}
	if len(findings) == 0 {
		findings = nil
	}
	return FileResult{Path: path, Findings: findings, Ignored: ignored}
}

// isBinary heuristically classifies a byte slice as binary. A NUL byte in the
// sniff window is the classic, cheap signal; failing that, invalid UTF-8 in
// the window (that isn't merely a rune truncated at the sniff boundary) marks
// it binary too. Empty files are text.
func isBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	window := data
	if len(window) > sniffLen {
		window = window[:sniffLen]
	}
	if bytes.IndexByte(window, 0) >= 0 {
		return true
	}
	if utf8.Valid(window) {
		return false
	}
	// The window may have chopped a multi-byte rune; retry on a trimmed tail so
	// we don't false-positive a perfectly good UTF-8 file at the boundary.
	trimmed := trimPartialRune(window)
	return !utf8.Valid(trimmed)
}

// trimPartialRune drops up to 3 trailing bytes that could be the front of a
// multi-byte rune cut off by the sniff window, so a boundary split doesn't get
// misread as invalid UTF-8.
func trimPartialRune(b []byte) []byte {
	for i := 0; i < 3 && len(b) > 0; i++ {
		if utf8.Valid(b) {
			return b
		}
		b = b[:len(b)-1]
	}
	return b
}

// ErrNoPaths is returned by the caller when scan mode is invoked without any
// path arguments. Defined here so tests can assert on it.
var ErrNoPaths = errors.New("scan needs at least one path")
