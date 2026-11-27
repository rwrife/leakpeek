// Package rules loads user-supplied detection rules from TOML and turns them
// into detect.Detectors, delivering the extensibility hook PLAN.md §6 (M6)
// promises: "Load custom rules from rules/*.toml (name + regex + kind)" behind
// a --rules flag. A rule is the same {name, kind, regex} triple a built-in
// detector is, so a loaded rule behaves identically to a core one — same
// engine, same dedupe, same report/redact treatment.
//
// # File format
//
// A rule file is an array of tables, each a [[rule]] with three string keys:
//
//	# rules/acme.toml — flag Acme's internal stuff before it hits a chatbot.
//	[[rule]]
//	name  = "acme-internal-host"
//	kind  = "network"                 # optional; defaults to "secret"
//	regex = '[a-z0-9-]+\.acme\.internal'
//
//	[[rule]]
//	name  = "acme-employee-id"
//	regex = 'EMP-[0-9]{6}'
//
// kind must be one of leakpeek's known kinds (secret, private-key, pii,
// network, entropy); an empty/absent kind defaults to "secret". regex is a
// Go/RE2 pattern (the same engine the built-ins use).
//
// # Why a hand-rolled parser
//
// leakpeek is a "single static binary, minimal deps" tool (PLAN.md §5) and
// already hand-rolls its flag parsing for exactly that reason. The rule
// schema is a tiny, closed subset of TOML — an array of tables with string
// values, comments, and single/double/triple-quoted strings — so we parse
// that subset directly instead of taking on a TOML dependency (and the
// module-download/build-network cost that comes with it). Anything outside
// the documented subset is rejected with a line-numbered error rather than
// silently ignored.
package rules

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rwrife/leakpeek/internal/detect"
)

// Rule is one parsed [[rule]] table: the raw fields before compilation. It is
// exported so tests (and any future consumer) can construct rules directly
// without going through TOML.
type Rule struct {
	Name  string // detector name (required); labels findings, can shadow a built-in
	Kind  string // one of detect.KnownKinds; empty defaults to "secret"
	Regex string // Go/RE2 pattern (required)

	// line is the 1-based line of this rule's [[rule]] header, used to make
	// compile/validation errors point at the offending rule. Unexported: it's
	// diagnostic metadata, not part of the rule's identity.
	line int
}

// Detector compiles a Rule into a detect.Detector, validating its kind and
// regexp. Errors are friendly and, when the rule came from a file, carry the
// source line via the caller wrapping in LoadPath.
func (r Rule) Detector() (detect.Detector, error) {
	if strings.TrimSpace(r.Name) == "" {
		return nil, errors.New("rule is missing a name")
	}
	kind, ok := detect.ParseKind(r.Kind)
	if !ok {
		return nil, fmt.Errorf("rule %q: unknown kind %q (want one of %s)",
			r.Name, r.Kind, joinKinds())
	}
	return detect.NewRegexDetector(r.Name, kind, r.Regex)
}

// LoadPath loads rules from a file or directory and returns their detectors,
// in a stable order. If path is a directory, every *.toml file directly inside
// it is loaded (sorted by filename, non-recursive) and their rules are
// concatenated; files matching *.local.toml are honored too so a user can keep
// private rules that .gitignore already excludes. If path is a single file, it
// is loaded regardless of extension.
//
// The returned detectors are ordered file-by-file, then by their order within
// each file, so results are deterministic. An empty but valid rule set returns
// an empty slice and no error. Any parse, kind, or regexp error is returned
// with a "<file>:<line>: ..." prefix so the user can fix the exact rule.
func LoadPath(path string) ([]detect.Detector, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading rules path %q: %w", path, err)
	}

	var files []string
	if info.IsDir() {
		files, err = directoryRuleFiles(path, "")
		if err != nil {
			return nil, err
		}
	} else {
		files = []string{path}
	}

	var detectors []detect.Detector
	for _, f := range files {
		ds, err := loadFile(f)
		if err != nil {
			return nil, err
		}
		detectors = append(detectors, ds...)
	}
	return detectors, nil
}

func directoryRuleFiles(path, exclude string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("reading rules dir %q: %w", path, err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && e.Name() != exclude && strings.HasSuffix(strings.ToLower(e.Name()), ".toml") {
			files = append(files, filepath.Join(path, e.Name()))
		}
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("no .toml rule files found in directory %q", path)
	}
	return files, nil
}

// loadFile reads and compiles a single rule file, prefixing every error with
// the filename (and, where known, the line) so diagnostics are actionable.
func loadFile(file string) ([]detect.Detector, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("reading rules file %q: %w", file, err)
	}
	parsed, err := parse(string(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	out := make([]detect.Detector, 0, len(parsed))
	for _, r := range parsed {
		d, err := r.Detector()
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", file, r.line, err)
		}
		out = append(out, d)
	}
	return out, nil
}

// joinKinds renders the known kinds as a comma-separated list for error text.
func joinKinds() string {
	ks := detect.KnownKinds()
	parts := make([]string, len(ks))
	for i, k := range ks {
		parts[i] = string(k)
	}
	return strings.Join(parts, ", ")
}
