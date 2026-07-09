package allow

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rwrife/leakpeek/internal/detect"
)

// mkFinding builds a Finding with just the fields the allowlist cares about
// (Match); Start/End/Detector/Kind are set to plausible values so the filter's
// preservation of the rest of the struct can be spot-checked.
func mkFinding(match string) detect.Finding {
	return detect.Finding{Detector: "test", Kind: detect.KindSecret, Match: match, Start: 0, End: len(match)}
}

func TestParseLiteralAndRegexAndComments(t *testing.T) {
	src := `
# a comment line
   # an indented comment

user@example.com
/^pk_test_[A-Za-z0-9]+$/
   trailing-and-leading-space-token   
`
	set, err := Parse(src, "test.ignore")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// Two comment lines and two blank lines are skipped; three real entries.
	if got, want := set.Len(), 3; got != want {
		t.Fatalf("Len = %d, want %d", got, want)
	}

	// Literal match is exact.
	if !set.Suppresses("user@example.com") {
		t.Errorf("literal user@example.com should be suppressed")
	}
	if set.Suppresses("user@example.org") {
		t.Errorf("literal must not suppress a different token")
	}

	// A literal entry with surrounding whitespace is trimmed to its token.
	if !set.Suppresses("trailing-and-leading-space-token") {
		t.Errorf("whitespace-trimmed literal should be suppressed")
	}

	// Regex match tests the whole token.
	if !set.Suppresses("pk_test_abc123XYZ") {
		t.Errorf("regex pk_test_… should be suppressed")
	}
	if set.Suppresses("pk_live_abc123XYZ") {
		t.Errorf("regex must not suppress a pk_live_ token")
	}
}

func TestRegexIsWholeMatchAnchored(t *testing.T) {
	// Without anchoring, this pattern would match a substring of a longer
	// secret and suppress it — a dangerous false negative. The anchoring must
	// require the *entire* Match to satisfy the pattern.
	set, err := Parse("/pk_test_[a-z]+/", "test.ignore")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !set.Suppresses("pk_test_abc") {
		t.Errorf("exact token should match the anchored regex")
	}
	if set.Suppresses("pk_test_abc_TRAILING_SECRET") {
		t.Errorf("anchored regex must not suppress a longer token that merely contains the pattern")
	}
	if set.Suppresses("prefix_pk_test_abc") {
		t.Errorf("anchored regex must not suppress a token with leading junk")
	}
}

func TestParseBadRegexErrors(t *testing.T) {
	_, err := Parse("/pk_test_([a-z/", "bad.ignore")
	if err == nil {
		t.Fatalf("expected an error for an unterminated regex group")
	}
	// Error should be actionable: name the file and line.
	if got := err.Error(); !contains(got, "bad.ignore:1") {
		t.Errorf("error = %q, want it to point at bad.ignore:1", got)
	}
}

func TestParseEmptyRegexErrors(t *testing.T) {
	if _, err := Parse("//", "e.ignore"); err == nil {
		t.Fatalf("expected an error for an empty // regex")
	}
}

func TestFilterDropsSuppressedPreservesOrder(t *testing.T) {
	set, err := Parse("safe@example.com\n/^AKIA[0-9A-Z]+$/", "test.ignore")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	in := []detect.Finding{
		mkFinding("realsecret1"),
		mkFinding("safe@example.com"), // literal-suppressed
		mkFinding("realsecret2"),
		mkFinding("AKIAIOSFODNN7EXAMPLE"), // regex-suppressed
		mkFinding("realsecret3"),
	}
	kept, ignored := set.Filter(in)
	if ignored != 2 {
		t.Fatalf("ignored = %d, want 2", ignored)
	}
	wantOrder := []string{"realsecret1", "realsecret2", "realsecret3"}
	if len(kept) != len(wantOrder) {
		t.Fatalf("kept %d findings, want %d: %+v", len(kept), len(wantOrder), kept)
	}
	for i, w := range wantOrder {
		if kept[i].Match != w {
			t.Errorf("kept[%d].Match = %q, want %q", i, kept[i].Match, w)
		}
	}
}

func TestFilterEmptySetSuppressesNothing(t *testing.T) {
	var empty Set
	in := []detect.Finding{mkFinding("a"), mkFinding("b")}
	kept, ignored := empty.Filter(in)
	if ignored != 0 || len(kept) != 2 {
		t.Fatalf("empty set: kept=%d ignored=%d, want kept=2 ignored=0", len(kept), ignored)
	}
	// A never-nil result even on empty input keeps callers from nil-checking.
	if got, _ := empty.Filter(nil); got == nil {
		t.Errorf("Filter(nil) returned nil, want a non-nil empty slice")
	}
}

func TestMergeCombinesEntries(t *testing.T) {
	a, _ := Parse("a@x.com", "a")
	b, _ := Parse("b@x.com", "b")
	m := a.Merge(b)
	if !m.Suppresses("a@x.com") || !m.Suppresses("b@x.com") {
		t.Errorf("merged set should suppress both a@x.com and b@x.com")
	}
	// Merging with an empty set returns the other side unchanged.
	var empty Set
	if got := a.Merge(empty); got.Len() != a.Len() {
		t.Errorf("Merge with empty changed Len: got %d, want %d", got.Len(), a.Len())
	}
}

// --- discovery ---

func TestDiscoverWalksUpFromCwd(t *testing.T) {
	// Layout:
	//   root/.git                (repo boundary)
	//   root/.leakpeekignore     -> root-token
	//   root/a/b/.leakpeekignore -> nested-token
	// Discovering from root/a/b should pick up BOTH files (walk-up), and stop
	// at root because of the .git marker.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, IgnoreFileName), "root-token\n")
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(nested, IgnoreFileName), "nested-token\n")

	// Isolate discovery from the real user config dir so a developer's global
	// ignore can't influence the test.
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "xdg-empty"))

	set, err := Discover(nested)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !set.Suppresses("root-token") {
		t.Errorf("discovery should include the root .leakpeekignore token")
	}
	if !set.Suppresses("nested-token") {
		t.Errorf("discovery should include the nested .leakpeekignore token")
	}
}

func TestDiscoverStopsAtRepoRoot(t *testing.T) {
	// A .leakpeekignore ABOVE the repo root must NOT be picked up: discovery
	// bounds itself to the project so it never inherits a stranger's config.
	above := t.TempDir()
	writeFile(t, filepath.Join(above, IgnoreFileName), "above-repo-token\n")
	repo := filepath.Join(above, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(above, "xdg-empty"))

	set, err := Discover(repo)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if set.Suppresses("above-repo-token") {
		t.Errorf("discovery escaped the repo root and read a parent's ignore file")
	}
}

func TestDiscoverMergesGlobalIgnore(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	xdg := filepath.Join(root, "xdg")
	if err := os.MkdirAll(filepath.Join(xdg, "leakpeek"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(xdg, "leakpeek", "ignore"), "global-token\n")
	t.Setenv("XDG_CONFIG_HOME", xdg)

	set, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !set.Suppresses("global-token") {
		t.Errorf("discovery should merge the global $XDG_CONFIG_HOME/leakpeek/ignore token")
	}
}

func TestDiscoverMissingFilesAreNotErrors(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "nope"))
	set, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover with no ignore files should not error: %v", err)
	}
	if !set.Empty() {
		t.Errorf("no ignore files should yield an empty set, got Len=%d", set.Len())
	}
}

func TestDiscoverBrokenFileErrors(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, IgnoreFileName), "/pk_(unterminated/\n")
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "nope"))
	if _, err := Discover(root); err == nil {
		t.Fatalf("a present-but-broken .leakpeekignore should surface an error, not fail open")
	}
}

func TestLoadFilesMergesExplicitPaths(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "one.ignore")
	f2 := filepath.Join(dir, "two.ignore")
	writeFile(t, f1, "tok1\n")
	writeFile(t, f2, "tok2\n")
	set, err := LoadFiles([]string{f1, f2})
	if err != nil {
		t.Fatalf("LoadFiles: %v", err)
	}
	if !set.Suppresses("tok1") || !set.Suppresses("tok2") {
		t.Errorf("LoadFiles should merge both explicit ignore files")
	}
}

// --- helpers ---

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
