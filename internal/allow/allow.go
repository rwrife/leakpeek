// Package allow implements leakpeek's allowlist: a post-detection filter that
// suppresses findings the user has explicitly marked known-safe, delivering
// backlog item PLAN.md §8.2 ("Allowlist / ignore — per-project
// .leakpeekignore for known-safe tokens").
//
// leakpeek is a frisker, and some tokens are legitimately safe: public sandbox
// keys (Stripe pk_test_…), documented example IPs (192.0.2.0/24), placeholder
// emails (user@example.com). Firing on those every paste is noise. An
// allowlist lets a user say "yes, I know, shut up about this one" without
// disabling a whole detector.
//
// # Design: a pure post-filter
//
// The engine (internal/detect) stays dumb: it detects everything, and this
// package drops the suppressed spans *after* the scan and *before* the
// report/redactor ever see them. That mirrors how the engine already dedupes
// overlapping spans — suppression is just another post-pass over a
// []detect.Finding. A dropped finding is never reported, never counted toward
// the exit code, and never redacted by --fix, so an allowlisted token is left
// verbatim in a --fix copy.
//
// # File format
//
// An ignore file is line-oriented. Blank lines and lines whose first
// non-space character is '#' are ignored. Every other line is one entry, in
// one of two forms:
//
//	user@example.com                 # literal — an exact Match to suppress
//	/^pk_test_[A-Za-z0-9]+$/         # regex   — /…/-wrapped Go/RE2 pattern\n//
//
// A literal entry suppresses a finding whose Match equals the entry exactly
// (after trimming surrounding whitespace on the entry). A regex entry
// suppresses a finding whose *entire* Match the pattern matches (the pattern
// is anchored with \A…\z so a partial hit doesn't accidentally suppress a
// longer secret — false negatives should be predictable). There is no fuzzy
// matching by design.
//
// # Discovery
//
// Set.Discover walks up from a starting directory (cwd, like .gitignore),
// collecting every .leakpeekignore it finds, nearest first, and then merges a
// global file at $XDG_CONFIG_HOME/leakpeek/ignore (falling back to
// ~/.config/leakpeek/ignore). Explicit --ignore paths are loaded on top.
// Order only affects which file a diagnostic points at; suppression itself is
// set-like (an entry either matches or it doesn't), so merge order can't
// change *which* findings survive.
package allow

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"

	"github.com/rwrife/leakpeek/internal/detect"
)

// entry is one compiled allowlist rule. Exactly one of literal/re is active:
// a literal entry carries its exact token in literal; a regex entry carries a
// compiled, whole-match-anchored pattern in re (and keeps its source in raw
// for diagnostics only).
type entry struct {
	literal string         // exact Match to suppress (regex entries leave this "")
	re      *regexp.Regexp // whole-Match pattern (literal entries leave this nil)
	raw     string         // original line text, for error messages
}

// matches reports whether this entry suppresses a finding with the given
// Match. A literal entry compares byte-for-byte; a regex entry tests the whole
// Match (the pattern was anchored at compile time).
func (e entry) matches(match string) bool {
	if e.re != nil {
		return e.re.MatchString(match)
	}
	return e.literal == match
}

// Set is a compiled collection of allowlist entries. The zero value is a valid
// empty Set that suppresses nothing, so callers can always Filter through it
// without a nil check. Build one with Parse (from text) or Load/Discover (from
// files), then combine with Merge.
type Set struct {
	entries []entry
}

// Len is the number of compiled entries in the Set.
func (s Set) Len() int { return len(s.entries) }

// Empty reports whether the Set has no entries (and so suppresses nothing).
func (s Set) Empty() bool { return len(s.entries) == 0 }

// Suppresses reports whether any entry in the Set would drop a finding with
// the given match string. It's the single decision predicate Filter is built
// on, exported so tests (and any future consumer) can probe a token directly.
func (s Set) Suppresses(match string) bool {
	for _, e := range s.entries {
		if e.matches(match) {
			return true
		}
	}
	return false
}

// Filter partitions findings into those that survive the allowlist and a count
// of those suppressed. Input order is preserved among the survivors; the
// returned slice is freshly allocated and never nil. A finding is suppressed
// when its Match is allowlisted by any entry (literal equality or a regex
// whole-Match). On an empty Set this is a cheap copy with ignored == 0.
func (s Set) Filter(findings []detect.Finding) (kept []detect.Finding, ignored int) {
	kept = make([]detect.Finding, 0, len(findings))
	for _, f := range findings {
		if s.Suppresses(f.Match) {
			ignored++
			continue
		}
		kept = append(kept, f)
	}
	return kept, ignored
}

// Merge returns a new Set containing this Set's entries followed by other's.
// Neither receiver is mutated. Duplicate entries are harmless (a token can
// only be suppressed once per Filter pass regardless of how many entries
// match it), so no de-duplication is attempted — keeping every entry means a
// future "which file suppressed this?" diagnostic stays possible.
func (s Set) Merge(other Set) Set {
	if s.Empty() {
		return other
	}
	if other.Empty() {
		return s
	}
	merged := make([]entry, 0, len(s.entries)+len(other.entries))
	merged = append(merged, s.entries...)
	merged = append(merged, other.entries...)
	return Set{entries: merged}
}

// Parse compiles ignore-file text into a Set. source is treated line by line
// per the package's documented grammar: blank lines and '#' comments are
// skipped, /…/-wrapped lines compile as whole-Match regexes, and every other
// non-empty line is a literal token.
//
// origin labels the source in error messages (e.g. a filename, or "--ignore");
// pass "" when there's no meaningful source. A malformed regex entry produces
// an "<origin>:<line>: ..." error and aborts the parse, so a typo fails loudly
// instead of silently letting a secret through.
func Parse(source, origin string) (Set, error) {
	var entries []entry
	sc := bufio.NewScanner(strings.NewReader(source))
	// Allow long lines (a big regex or URL) without the default 64 KiB token
	// cap tripping on a legitimate entry.
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)

	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		e, err := parseEntry(line, origin, lineNo)
		if err != nil {
			return Set{}, err
		}
		entries = append(entries, e)
	}
	if err := sc.Err(); err != nil {
		return Set{}, fmt.Errorf("%s: reading ignore entries: %w", labelOrigin(origin), err)
	}
	return Set{entries: entries}, nil
}

// parseEntry compiles a single already-trimmed, non-comment line into an entry.
// A line of the form /pattern/ (at least "//", i.e. a leading and trailing
// slash) is a regex; the inner pattern is anchored to the whole Match with
// \A…\z so it can never suppress a mere substring of a longer secret. Anything
// else is taken verbatim as a literal token.
func parseEntry(line, origin string, lineNo int) (entry, error) {
	if len(line) >= 2 && strings.HasPrefix(line, "/") && strings.HasSuffix(line, "/") {
		pattern := line[1 : len(line)-1]
		if strings.TrimSpace(pattern) == "" {
			return entry{}, fmt.Errorf("%s:%d: empty regex between the slashes", labelOrigin(origin), lineNo)
		}
		// Anchor to the entire Match. \A and \z bind to the start/end of the
		// text (not line boundaries), so a whole-token match is required.
		re, err := regexp.Compile(`\A(?:` + pattern + `)\z`)
		if err != nil {
			return entry{}, fmt.Errorf("%s:%d: invalid regex %s: %w", labelOrigin(origin), lineNo, line, err)
		}
		return entry{re: re, raw: line}, nil
	}
	return entry{literal: line, raw: line}, nil
}

// labelOrigin renders a source label for diagnostics, substituting a generic
// name when the caller passed an empty origin so an error never reads
// ":12: ...".
func labelOrigin(origin string) string {
	if strings.TrimSpace(origin) == "" {
		return "ignore"
	}
	return origin
}
