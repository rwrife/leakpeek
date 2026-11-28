package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rwrife/leakpeek/internal/detect"
)

func writePack(t *testing.T, root, name, version string, files map[string]string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	writePackFile(t, filepath.Join(path, packManifest),
		fmt.Sprintf("name = %q\nversion = %q\ndescription = 'Test pack'\n", name, version))
	for name, content := range files {
		writePackFile(t, filepath.Join(path, name), content)
	}
	return path
}

func writePackFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const packRule = "[[rule]]\nname = 'employee'\nregex = 'EMP-[0-9]{6}'\n"

func TestManifest(t *testing.T) {
	pack, err := parseManifest("name = 'acme' # comment\nversion = \"1.2.3\"\ndescription = 'Internal # rules'\n")
	if err != nil {
		t.Fatal(err)
	}
	if pack.Name != "acme" || pack.Version != "1.2.3" || pack.Description != "Internal # rules" {
		t.Fatalf("manifest = %+v", pack)
	}
	for _, tc := range []struct {
		src, want string
	}{
		{"version = '1'", "name is required"},
		{"name = 'acme'", "version is required"},
		{"name = ''\nversion = '1'", "name is required"},
		{"name = 'acme'\nversion = ' '", "version is required"},
		{"name = '../acme'\nversion = '1'", "name is required"},
		{"name = 'acme'\nname = 'other'", "line 2: duplicate"},
		{"unknown = 'x'", "line 1: unknown"},
		{"name = 123", "line 1: value must be a quoted string"},
		{"[pack]", "line 1: expected key = value"},
	} {
		t.Run(tc.src, func(t *testing.T) {
			_, err := parseManifest(tc.src)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
	if _, err := parseManifest("name = 'acme'\nversion = 'release-one'"); err != nil {
		t.Fatalf("optional description / non-semver label: %v", err)
	}
}

func TestPackResolutionAndPrecedence(t *testing.T) {
	roots := []string{t.TempDir(), t.TempDir(), t.TempDir()}
	for i, root := range roots {
		writePack(t, root, "acme", fmt.Sprint(i), map[string]string{"rules.toml": packRule})
	}
	for i := range roots {
		pack, err := ResolvePack("acme", roots[i:])
		if err != nil {
			t.Fatal(err)
		}
		if pack.Version != fmt.Sprint(i) || pack.Path != filepath.Join(roots[i], "acme") {
			t.Fatalf("resolved pack = %+v, want root %d", pack, i)
		}
	}
	writePackFile(t, filepath.Join(roots[0], "acme", packManifest), "name = 'acme'")
	if _, err := ResolvePack("acme", roots); err == nil || !strings.Contains(err.Error(), "version is required") {
		t.Fatalf("broken override must fail, got %v", err)
	}
}

func TestPackSearchPaths(t *testing.T) {
	home, cwd, override := t.TempDir(), t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(old); err != nil {
			t.Error(err)
		}
	})
	for _, env := range []string{override, "", "relative-packs"} {
		t.Setenv("LEAKPEEK_PACKS", env)
		got, err := PackSearchPaths()
		if err != nil {
			t.Fatal(err)
		}
		actualCwd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		want := []string{filepath.Join(home, ".config", "leakpeek", "packs"), filepath.Join(actualCwd, ".leakpeek", "packs")}
		if env != "" {
			abs, err := filepath.Abs(env)
			if err != nil {
				t.Fatal(err)
			}
			want = append([]string{abs}, want...)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("paths = %v, want %v", got, want)
		}
	}
}

func TestPackLoadsAllRuleFilesInOrder(t *testing.T) {
	root := t.TempDir()
	path := writePack(t, root, "acme", "1", map[string]string{
		"z.local.toml": "[[rule]]\nname = 'project'\nregex = 'PROJECT-[0-9]+'\n",
		"a.toml":       packRule,
		"README.txt":   "not a rule",
	})
	if err := os.Mkdir(filepath.Join(path, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	writePackFile(t, filepath.Join(path, "nested", "bad.toml"), "invalid")
	pack, err := ResolvePack("acme", []string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(pack.Detectors) != 2 || pack.Detectors[0].Name() != "employee" || pack.Detectors[1].Name() != "project" {
		t.Fatalf("wrong detector order: %+v", pack.Detectors)
	}
	names := findingNames(t, pack.Detectors, "EMP-123456 PROJECT-42")
	if names["employee"] != 1 || names["project"] != 1 {
		t.Fatalf("findings = %v", names)
	}
}

func TestInvalidPacksFailExplicitly(t *testing.T) {
	for _, tc := range []struct {
		name, manifest, rule, want string
	}{
		{"bad regex", "name='acme'\nversion='1'", "[[rule]]\nname='bad'\nregex='['", "rules.toml:1:"},
		{"no rules", "name='acme'\nversion='1'", "", "contains no rules"},
		{"wrong name", "name='other'\nversion='1'", packRule, "must match pack directory"},
		{"bad manifest", "name='acme'\nversion=1", packRule, "leakpeek-pack.toml: line 2:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			path := writePack(t, root, "acme", "1", map[string]string{"rules.toml": tc.rule})
			writePackFile(t, filepath.Join(path, packManifest), tc.manifest)
			_, err := ResolvePack("acme", []string{root})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
	root := t.TempDir()
	writePack(t, root, "empty", "1", nil)
	if _, err := ResolvePack("empty", []string{root}); err == nil || !strings.Contains(err.Error(), "no .toml rule files") {
		t.Fatalf("manifest-only pack: %v", err)
	}
}

func TestMissingAndInvalidPackNames(t *testing.T) {
	roots := []string{t.TempDir(), filepath.Join(t.TempDir(), "absent")}
	_, err := ResolvePack("missing", roots)
	if err == nil {
		t.Fatal("expected missing pack error")
	}
	for _, want := range []string{"not found", filepath.Join(roots[0], "missing"), filepath.Join(roots[1], "missing"), "LEAKPEEK_PACKS"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q must include %q", err, want)
		}
	}
	for _, name := range []string{"", ".", "..", "../acme", `..\acme`, "C:\\acme", "acme/other"} {
		if _, err := ResolvePack(name, roots); err == nil || !strings.Contains(err.Error(), "invalid rule pack name") {
			t.Errorf("name %q: %v", name, err)
		}
	}
}

func TestListPacksShadowsAndSorts(t *testing.T) {
	roots := []string{t.TempDir(), t.TempDir(), filepath.Join(t.TempDir(), "missing")}
	writePack(t, roots[0], "zeta", "2", map[string]string{"rules.toml": packRule})
	writePack(t, roots[1], "alpha", "1", map[string]string{"rules.toml": packRule})
	shadowed := writePack(t, roots[1], "zeta", "1", map[string]string{"rules.toml": "invalid"})
	writePackFile(t, filepath.Join(shadowed, packManifest), "invalid")
	if err := os.Mkdir(filepath.Join(roots[0], "not-a-pack"), 0o755); err != nil {
		t.Fatal(err)
	}
	packs, err := ListPacks(roots)
	if err != nil {
		t.Fatal(err)
	}
	if len(packs) != 2 || packs[0].Name != "alpha" || packs[1].Name != "zeta" ||
		packs[1].Version != "2" || len(packs[1].Detectors) != 1 || packs[1].Path != filepath.Join(roots[0], "zeta") {
		t.Fatalf("list = %+v", packs)
	}
	// Discovery must agree with resolution if a higher-priority directory is
	// present but lacks its manifest.
	if err := os.Mkdir(filepath.Join(roots[0], "alpha"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ListPacks(roots); err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("expected broken override error, got %v", err)
	}
}

func TestLoadExtrasCompositionAndDedupe(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LEAKPEEK_PACKS", root)
	writePack(t, root, "acme", "1", map[string]string{
		"rules.toml": packRule + "\n[[rule]]\nname='pack-aws'\nregex='AKIA[0-9A-Z]{16}'\n",
	})
	writePack(t, root, "infra", "1", map[string]string{
		"rules.toml": "[[rule]]\nname='infra'\nregex='INFRA-[0-9]+'\n",
	})
	file := filepath.Join(t.TempDir(), "custom.toml")
	writePackFile(t, file, "[[rule]]\nname='explicit'\nregex='EMP-[0-9]{6}'\n")
	ds, err := LoadExtras(file, []string{"acme", "infra", "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 4 {
		t.Fatalf("detector count = %d, want 4 (duplicate pack loaded once)", len(ds))
	}
	fs := detect.Default().WithDetectors(ds...).Scan("AKIAIOSFODNN7EXAMPLE EMP-123456 INFRA-42")
	if len(fs) != 3 || fs[0].Detector != "aws-access-key" || fs[1].Detector != "explicit" || fs[2].Detector != "infra" {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestExamplePack(t *testing.T) {
	pack, err := ResolvePack("acme", []string{filepath.Join("..", "..", "rules")})
	if err != nil {
		t.Fatal(err)
	}
	names := findingNames(t, pack.Detectors, "db.acme.internal ACME-PROJECT-0042")
	if len(names) != 2 || names["acme-internal-host"] != 1 || names["acme-project-code"] != 1 {
		t.Fatalf("example findings = %v", names)
	}
}
