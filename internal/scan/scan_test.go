package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rwrife/leakpeek/internal/detect"
)

// writeTree materializes a map of relative-path→contents under a temp dir and
// returns the dir. Parent directories are created as needed.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return root
}

func defaultOpts() Options {
	return Options{Engine: detect.Default()}
}

// A known AWS access key id shape the built-in detector fires on.
const awsKey = "AKIAIOSFODNN7EXAMPLE"

func TestWalk_FindsSecretsPerFile(t *testing.T) {
	root := writeTree(t, map[string]string{
		"clean.txt":     "nothing to see here\n",
		"secrets.env":   "AWS_KEY=" + awsKey + "\n",
		"sub/creds.txt": "key = " + awsKey + "\n",
		"sub/readme.md": "# hello\njust docs\n",
	})

	res, err := Walk([]string{root}, defaultOpts())
	if err != nil {
		t.Fatalf("walk error: %v", err)
	}
	if res.Clean() {
		t.Fatal("expected findings, got clean")
	}
	if got := res.FilesWithHits(); got != 2 {
		t.Fatalf("FilesWithHits = %d, want 2", got)
	}
	if got := res.Total(); got != 2 {
		t.Fatalf("Total = %d, want 2", got)
	}
}

func TestWalk_SkipsBinary(t *testing.T) {
	// A "binary" file that happens to contain the key bytes but also a NUL.
	root := writeTree(t, map[string]string{
		"blob.bin": "AWS=" + awsKey + "\x00\x01\x02binary",
		"ok.txt":   "AWS=" + awsKey + "\n",
	})
	res, err := Walk([]string{root}, defaultOpts())
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	var binSkipped bool
	for _, fr := range res.Files {
		if strings.HasSuffix(fr.Path, "blob.bin") {
			if !fr.Skipped || fr.Reason != "binary" {
				t.Fatalf("blob.bin: skipped=%v reason=%q, want skipped binary", fr.Skipped, fr.Reason)
			}
			binSkipped = true
		}
	}
	if !binSkipped {
		t.Fatal("expected blob.bin in results")
	}
	if res.FilesWithHits() != 1 {
		t.Fatalf("FilesWithHits = %d, want 1 (only ok.txt)", res.FilesWithHits())
	}
}

func TestWalk_SkipDirPrunes(t *testing.T) {
	root := writeTree(t, map[string]string{
		".git/config": "AWS=" + awsKey + "\n",
		"keep.txt":    "AWS=" + awsKey + "\n",
	})
	opts := defaultOpts()
	opts.SkipDir = func(base, _ string) bool { return base == ".git" }
	res, err := Walk([]string{root}, opts)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if res.FilesWithHits() != 1 {
		t.Fatalf("FilesWithHits = %d, want 1 (.git pruned)", res.FilesWithHits())
	}
	for _, fr := range res.Files {
		if strings.Contains(fr.Path, ".git") {
			t.Fatalf("did not expect .git file in results: %s", fr.Path)
		}
	}
}

func TestWalk_MissingPathIsNonFatal(t *testing.T) {
	root := writeTree(t, map[string]string{"a.txt": "AWS=" + awsKey + "\n"})
	res, err := Walk([]string{filepath.Join(root, "nope"), root}, defaultOpts())
	if err == nil {
		t.Fatal("expected a non-fatal error for the missing path")
	}
	// The good path should still have been scanned.
	if res.FilesWithHits() != 1 {
		t.Fatalf("FilesWithHits = %d, want 1 despite missing path", res.FilesWithHits())
	}
}

func TestWalk_SingleFileArg(t *testing.T) {
	root := writeTree(t, map[string]string{"one.txt": "AWS=" + awsKey + "\n"})
	res, err := Walk([]string{filepath.Join(root, "one.txt")}, defaultOpts())
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if res.Total() != 1 || len(res.Files) != 1 {
		t.Fatalf("got total=%d files=%d, want 1/1", res.Total(), len(res.Files))
	}
}

func TestWalk_DedupesOverlappingPaths(t *testing.T) {
	root := writeTree(t, map[string]string{"dup.txt": "AWS=" + awsKey + "\n"})
	file := filepath.Join(root, "dup.txt")
	res, err := Walk([]string{root, file}, defaultOpts())
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	// dup.txt reached via both the dir walk and the explicit file arg, but must
	// appear once.
	count := 0
	for _, fr := range res.Files {
		if strings.HasSuffix(fr.Path, "dup.txt") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("dup.txt appears %d times, want 1", count)
	}
}

func TestIsBinary(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"empty", nil, false},
		{"plain text", []byte("hello world\n"), false},
		{"utf8 multibyte", []byte("héllo café ☕\n"), false},
		{"nul byte", []byte("abc\x00def"), true},
		{"invalid utf8", []byte{0xff, 0xfe, 0xfd, 0xfc}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isBinary(c.data); got != c.want {
				t.Fatalf("isBinary(%q) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}
