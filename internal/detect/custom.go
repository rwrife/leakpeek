package detect

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// This file is the extensibility surface of the detect package: everything a
// caller outside the built-in pack needs to turn a user-supplied rule into a
// real Detector. It lets the internal/rules loader (M6, "custom rules") build
// detectors from rules/*.toml without duplicating the regex-adapter or the
// Kind vocabulary that detectors.go already defines.
//
// Design note: the regexDetector type stays unexported on purpose — it is an
// implementation detail of the pack. Custom rules don't need the struct, only
// a constructor that yields the Detector interface, so that's all we export.

// KnownKinds returns the Kinds leakpeek understands, sorted for stable output
// (help text, error messages, tests). A custom rule may only declare one of
// these; an unknown kind is rejected at load time so a typo can't silently
// produce findings the reporter/redactor don't know how to categorize.
func KnownKinds() []Kind {
	ks := []Kind{
		KindSecret,
		KindPrivateKey,
		KindPII,
		KindNetwork,
		KindEntropy,
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i] < ks[j] })
	return ks
}

// ParseKind maps a case-insensitive string to a known Kind. An empty string
// defaults to KindSecret, which is the safe assumption for a user rule that
// only gave a name and a pattern (they're almost always flagging a credential).
// It reports ok=false for any non-empty value that isn't a known Kind.
func ParseKind(s string) (kind Kind, ok bool) {
	if strings.TrimSpace(s) == "" {
		return KindSecret, true
	}
	want := strings.ToLower(strings.TrimSpace(s))
	for _, k := range KnownKinds() {
		if string(k) == want {
			return k, true
		}
	}
	return "", false
}

// NewRegexDetector builds a Detector from a name, a Kind, and a regular
// expression, reusing the same regex adapter the built-in pack uses so custom
// rules behave identically to core detectors (same scan, same dedupe, same
// reporting). It compiles pattern with Go's regexp/RE2 engine and returns an
// error — rather than panicking like the internal reEntry helper — because the
// pattern comes from user input and a bad regex should surface as a friendly
// load-time error, not a crash.
//
// name must be non-empty (it's how findings are labeled and how a rule can
// intentionally shadow a built-in). kind must be a known Kind; pass "" to
// default to KindSecret via ParseKind at the call site, or a validated Kind
// here.
func NewRegexDetector(name string, kind Kind, pattern string) (Detector, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("detector name must not be empty")
	}
	if strings.TrimSpace(pattern) == "" {
		return nil, fmt.Errorf("detector %q: pattern must not be empty", name)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("detector %q: invalid regexp: %w", name, err)
	}
	return regexDetector{name: name, kind: kind, re: re}, nil
}

// WithDetectors returns a new Engine holding this engine's detectors followed
// by extra. It's the compose hook for custom rules: main.go builds the default
// engine, then appends user detectors so built-ins keep priority during
// dedupe (a real AWS key still reports as "aws-access-key", not a user's
// broad catch-all) while custom rules can still claim spans nothing else did.
// The receiver is not mutated; a fresh detector slice is allocated.
func (e *Engine) WithDetectors(extra ...Detector) *Engine {
	merged := make([]Detector, 0, len(e.detectors)+len(extra))
	merged = append(merged, e.detectors...)
	merged = append(merged, extra...)
	return &Engine{detectors: merged}
}
