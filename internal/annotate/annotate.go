// Package annotate builds a short, human-readable provenance footer that
// summarizes what a --fix pass redacted, grouped by detector Kind and count.
//
// The footer exists so a downstream reader (you, or an AI you paste into)
// knows redaction happened and roughly what was removed — without ever
// leaking an original value. It never includes matched text, only kinds and
// counts, e.g.:
//
//	[leakpeek: redacted 2 API keys, 1 email]
//
// When the redaction is reversible (--strategy vault) the note says so, so a
// reader understands the placeholders can be restored:
//
//	[leakpeek: reversibly redacted 2 API keys, 1 email — run `leakpeek --unredact` to restore]
package annotate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rwrife/leakpeek/internal/detect"
)

// kindLabel maps a detector Kind to a friendly singular/plural noun pair used
// in the footer. Unknown kinds fall back to the raw kind string.
var kindLabel = map[detect.Kind][2]string{
	detect.KindSecret:     {"API key", "API keys"},
	detect.KindPrivateKey: {"private key", "private keys"},
	detect.KindPII:        {"email", "emails"},
	detect.KindPayment:    {"payment card", "payment cards"},
	detect.KindNetwork:    {"network address", "network addresses"},
	detect.KindEntropy:    {"high-entropy token", "high-entropy tokens"},
}

// stableKindOrder is the display order for kinds in the footer, so the note
// reads the same way every run regardless of detector-firing order.
var stableKindOrder = []detect.Kind{
	detect.KindSecret,
	detect.KindPrivateKey,
	detect.KindPII,
	detect.KindPayment,
	detect.KindNetwork,
	detect.KindEntropy,
}

// Summary returns just the count phrase (e.g. "2 API keys, 1 email") for the
// given findings, grouped by Kind. It returns "" when there are no findings.
// It never includes any matched value.
func Summary(findings []detect.Finding) string {
	counts := make(map[detect.Kind]int)
	for _, f := range findings {
		counts[f.Kind]++
	}
	if len(counts) == 0 {
		return ""
	}

	parts := make([]string, 0, len(counts))
	seen := make(map[detect.Kind]bool, len(counts))
	emit := func(k detect.Kind) {
		n := counts[k]
		if n == 0 || seen[k] {
			return
		}
		seen[k] = true
		parts = append(parts, fmt.Sprintf("%d %s", n, label(k, n)))
	}
	// Known kinds first, in a stable order, then any unknown kinds sorted so
	// output stays deterministic.
	for _, k := range stableKindOrder {
		emit(k)
	}
	rest := make([]detect.Kind, 0)
	for k := range counts {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Slice(rest, func(i, j int) bool { return rest[i] < rest[j] })
	for _, k := range rest {
		emit(k)
	}
	return strings.Join(parts, ", ")
}

// Footer returns the full bracketed annotation line for the given findings.
// reversible=true switches the wording to reflect vault mode and appends the
// restore hint. It returns "" when there are no findings.
func Footer(findings []detect.Finding, reversible bool) string {
	summary := Summary(findings)
	if summary == "" {
		return ""
	}
	if reversible {
		return fmt.Sprintf(
			"[leakpeek: reversibly redacted %s — run `leakpeek --unredact` to restore]",
			summary,
		)
	}
	return fmt.Sprintf("[leakpeek: redacted %s]", summary)
}

// label returns the singular or plural noun for a Kind given a count. Unknown
// kinds fall back to the raw kind string (never pluralized, to avoid
// mangling an arbitrary label).
func label(k detect.Kind, n int) string {
	pair, ok := kindLabel[k]
	if !ok {
		return string(k)
	}
	if n == 1 {
		return pair[0]
	}
	return pair[1]
}
