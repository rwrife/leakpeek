package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rwrife/leakpeek/internal/detect"
)

// findingNames scans text with the given detectors and returns the set of
// detector names that fired, so tests can assert on *which* rules matched
// without depending on span offsets.
func findingNames(t *testing.T, ds []detect.Detector, text string) map[string]int {
	t.Helper()
	eng := detect.New(ds...)
	got := map[string]int{}
	for _, f := range eng.Scan(text) {
		got[f.Detector]++
	}
	return got
}

func TestParseValidRules(t *testing.T) {
	src := `
# A couple of Acme rules.
[[rule]]
name  = "acme-internal-host"
kind  = "network"
regex = '[a-z0-9-]+\.acme\.internal'   # literal string keeps the backslash

[[rule]]
name  = "acme-employee-id"     # no kind → defaults to secret
regex = "EMP-[0-9]{6}"
`
	got, err := parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("parsed %d rules, want 2: %+v", len(got), got)
	}
	if got[0].Name != "acme-internal-host" || got[0].Kind != "network" {
		t.Errorf("rule[0] = %+v, want name=acme-internal-host kind=network", got[0])
	}
	if got[0].Regex != `[a-z0-9-]+\.acme\.internal` {
		t.Errorf("rule[0].Regex = %q, want the backslash preserved verbatim", got[0].Regex)
	}
	if got[1].Name != "acme-employee-id" || got[1].Kind != "" {
		t.Errorf("rule[1] = %+v, want name=acme-employee-id kind empty", got[1])
	}
	// Header line numbers are tracked for diagnostics.
	if got[1].line == 0 {
		t.Errorf("rule[1].line = 0, want the [[rule]] header line to be recorded")
	}
}

func TestParseStringQuotingForms(t *testing.T) {
	src := `
[[rule]]
name  = 'literal-name'
kind  = """network"""
regex = '''a#b'''
`
	got, err := parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("parsed %d rules, want 1", len(got))
	}
	if got[0].Name != "literal-name" {
		t.Errorf("Name = %q, want literal-name", got[0].Name)
	}
	if got[0].Kind != "network" {
		t.Errorf("Kind = %q, want network (triple-quoted)", got[0].Kind)
	}
	// The '#' lives inside a literal string, so comment-stripping must not eat it.
	if got[0].Regex != "a#b" {
		t.Errorf("Regex = %q, want a#b ('#' inside quotes preserved)", got[0].Regex)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		wantSub string
	}{
		{"key before rule", "name = \"x\"\n", "before any [[rule]]"},
		{"unknown key", "[[rule]]\nfoo = \"bar\"\n", "unknown key"},
		{"unsupported table", "[server]\n", "only [[rule]] is allowed"},
		{"duplicate key", "[[rule]]\nname=\"a\"\nname=\"b\"\n", "duplicate key"},
		{"unquoted value", "[[rule]]\nname = bare\n", "must be a quoted string"},
		{"no equals", "[[rule]]\nname\n", "expected key = value"},
		{"missing value", "[[rule]]\nname =\n", "missing value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(tc.src)
			if err == nil {
				t.Fatalf("parse(%q) = nil error, want one containing %q", tc.src, tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestRuleDetectorValidation(t *testing.T) {
	if _, err := (Rule{Name: "", Regex: "a"}).Detector(); err == nil {
		t.Error("empty name: want error, got nil")
	}
	if _, err := (Rule{Name: "x", Kind: "nope", Regex: "a"}).Detector(); err == nil {
		t.Error("unknown kind: want error, got nil")
	} else if !strings.Contains(err.Error(), "unknown kind") {
		t.Errorf("kind error = %q, want it to mention the unknown kind", err.Error())
	}
	if _, err := (Rule{Name: "x", Regex: "([bad"}).Detector(); err == nil {
		t.Error("bad regexp: want error, got nil")
	}
	// A minimal valid rule (no kind) compiles and defaults to KindSecret.
	d, err := (Rule{Name: "ok", Regex: "abc"}).Detector()
	if err != nil {
		t.Fatalf("valid rule: %v", err)
	}
	if d.Kind() != detect.KindSecret {
		t.Errorf("default kind = %q, want %q", d.Kind(), detect.KindSecret)
	}
}

func TestLoadPathFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "acme.toml")
	writeFile(t, file, `
[[rule]]
name  = "acme-employee-id"
regex = "EMP-[0-9]{6}"
`)
	ds, err := LoadPath(file)
	if err != nil {
		t.Fatalf("LoadPath: %v", err)
	}
	names := findingNames(t, ds, "contact EMP-123456 for access")
	if names["acme-employee-id"] != 1 {
		t.Errorf("names = %v, want acme-employee-id to fire once", names)
	}
}

func TestLoadPathDirectoryOrderedAndFiltered(t *testing.T) {
	dir := t.TempDir()
	// Two .toml files load in filename order; a non-.toml file is ignored.
	writeFile(t, filepath.Join(dir, "01-a.toml"), "[[rule]]\nname=\"aaa\"\nregex=\"AAA\"\n")
	writeFile(t, filepath.Join(dir, "02-b.toml"), "[[rule]]\nname=\"bbb\"\nregex=\"BBB\"\n")
	writeFile(t, filepath.Join(dir, "notes.txt"), "this is not a rule file")
	writeFile(t, filepath.Join(dir, "team.local.toml"), "[[rule]]\nname=\"ccc\"\nregex=\"CCC\"\n")

	ds, err := LoadPath(dir)
	if err != nil {
		t.Fatalf("LoadPath dir: %v", err)
	}
	if len(ds) != 3 {
		t.Fatalf("loaded %d detectors, want 3 (aaa,bbb,ccc; notes.txt ignored)", len(ds))
	}
	// First two by filename order.
	if ds[0].Name() != "aaa" || ds[1].Name() != "bbb" {
		t.Errorf("order = %q,%q, want aaa,bbb (sorted by filename)", ds[0].Name(), ds[1].Name())
	}
	names := findingNames(t, ds, "AAA BBB CCC")
	for _, want := range []string{"aaa", "bbb", "ccc"} {
		if names[want] != 1 {
			t.Errorf("detector %q fired %d times, want 1 (%v)", want, names[want], names)
		}
	}
}

func TestLoadPathErrors(t *testing.T) {
	if _, err := LoadPath(filepath.Join(t.TempDir(), "nope.toml")); err == nil {
		t.Error("missing path: want error, got nil")
	}

	emptyDir := t.TempDir()
	if _, err := LoadPath(emptyDir); err == nil {
		t.Error("dir with no .toml: want error, got nil")
	} else if !strings.Contains(err.Error(), "no .toml") {
		t.Errorf("empty-dir error = %q, want it to mention no .toml files", err.Error())
	}

	// A bad rule surfaces with a file:line prefix.
	dir := t.TempDir()
	file := filepath.Join(dir, "bad.toml")
	writeFile(t, file, "[[rule]]\nname=\"x\"\nregex=\"([oops\"\n")
	_, err := LoadPath(file)
	if err == nil {
		t.Fatal("bad regexp in file: want error, got nil")
	}
	if !strings.Contains(err.Error(), "bad.toml:") {
		t.Errorf("error = %q, want a bad.toml:<line> prefix", err.Error())
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}
