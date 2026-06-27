// Package detect is the brains of leakpeek: a small engine that runs a set
// of Detectors over a blob of text and returns the secrets / PII / infra it
// finds.
//
// The contract is intentionally tiny so adding a new secret type is a one-
// struct change (see PLAN.md §6):
//
//	a Detector is { Name, Kind, Find(text) []Finding }
//
// The engine (Engine.Scan) runs every detector, then de-duplicates
// overlapping spans so a token matched by two detectors (or matched twice)
// is reported once. No detection logic lives here — only the interface,
// the result types, and the merge/dedupe machinery. The concrete detector
// pack lives in detectors.go; the entropy helper in entropy.go.
package detect

import "sort"

// Kind is a coarse category for a Finding, used by the reporter (M3) to
// group and colorize output and by the redactor (M4) to pick a masking
// strategy. It is deliberately a small, closed-ish set of strings.
type Kind string

const (
	KindSecret     Kind = "secret"      // API keys, tokens, credentials
	KindPrivateKey Kind = "private-key" // PEM/OpenSSH private-key material
	KindPII        Kind = "pii"         // personal data (e.g. email)
	KindNetwork    Kind = "network"     // network/infra (e.g. IPv4)
	KindEntropy    Kind = "entropy"     // generic high-entropy token
)

// Finding is a single hit: which detector fired, what category it is, the
// exact byte span [Start,End) in the scanned text, and the matched
// substring. Start/End are byte offsets (not rune offsets) so they line up
// with Go string slicing and with the redactor's splice logic in M4.
type Finding struct {
	Detector string // name of the detector that produced this (e.g. "aws-access-key")
	Kind     Kind   // category bucket
	Start    int    // inclusive byte offset of the match
	End      int    // exclusive byte offset of the match
	Match    string // the matched text (text[Start:End])

	// order is an internal tie-breaker carried during a scan so the engine
	// can prefer earlier-registered detectors when two cover the same span.
	// It is unexported so it never leaks into JSON/report output.
	order int
}

// Len is the byte length of the matched span.
func (f Finding) Len() int { return f.End - f.Start }

// Detector sniffs a single class of sensitive data out of text.
//
// Implementations must be safe for concurrent use (the engine may, in a
// later milestone, run them in parallel) and must return Findings whose
// Start/End are valid byte offsets into the text passed to Find, with
// Match == text[Start:End].
type Detector interface {
	// Name is a short, stable identifier (e.g. "github-pat"). It appears in
	// reports and is how custom-rule overrides will key off built-ins.
	Name() string
	// Kind is the category this detector produces.
	Kind() Kind
	// Find returns every match in text. An empty slice (or nil) means
	// "nothing found". Findings need not be sorted; the engine sorts them.
	Find(text string) []Finding
}

// Engine holds an ordered set of detectors and runs them as a unit.
type Engine struct {
	detectors []Detector
}

// New builds an Engine from the given detectors. Order only affects tie-
// breaking during de-duplication (earlier detectors win equal-span ties).
func New(detectors ...Detector) *Engine {
	return &Engine{detectors: detectors}
}

// Default returns an Engine loaded with the v0.1 core secret pack.
func Default() *Engine {
	return New(DefaultDetectors()...)
}

// Detectors exposes the engine's detector set (read-only use).
func (e *Engine) Detectors() []Detector { return e.detectors }

// Scan runs every detector over text, sorts the combined findings by
// position, and removes overlapping spans so each region of text is
// reported at most once. The returned slice is sorted by Start (then by
// descending length, then detector order) and is never nil.
func (e *Engine) Scan(text string) []Finding {
	var all []Finding
	for i, d := range e.detectors {
		for _, f := range d.Find(text) {
			// Stamp the detector identity from the engine's view so a
			// detector can't misreport its own name/kind, and so we can
			// break ties deterministically by registration order.
			f.Detector = d.Name()
			f.Kind = d.Kind()
			f.order = i
			all = append(all, f)
		}
	}
	return dedupe(all)
}

// dedupe sorts findings and drops any whose span overlaps one already kept.
// Preference order for which span "wins" an overlap:
//  1. earliest Start,
//  2. longest match (a broader detector beats a fragment of it),
//  3. lowest detector registration order (stable, deterministic).
func dedupe(in []Finding) []Finding {
	if len(in) == 0 {
		return []Finding{}
	}
	sort.SliceStable(in, func(i, j int) bool {
		a, b := in[i], in[j]
		if a.Start != b.Start {
			return a.Start < b.Start
		}
		if a.Len() != b.Len() {
			return a.Len() > b.Len() // longer span first
		}
		return a.order < b.order
	})

	out := make([]Finding, 0, len(in))
	lastEnd := -1
	for _, f := range in {
		if f.Start < lastEnd {
			continue // overlaps a span we already kept; skip the fragment
		}
		out = append(out, f)
		if f.End > lastEnd {
			lastEnd = f.End
		}
	}
	return out
}
