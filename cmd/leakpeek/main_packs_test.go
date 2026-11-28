package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupCLIPack(t *testing.T, root, name, detector, pattern string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	for file, content := range map[string]string{
		"leakpeek-pack.toml": fmt.Sprintf("name=%q\nversion='1.2.3'\ndescription='Team rules'\n", name),
		"rules.toml":         fmt.Sprintf("[[rule]]\nname=%q\nregex='%s'\n", detector, pattern),
	} {
		if err := os.WriteFile(filepath.Join(path, file), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestRulePacksComposeWithRules(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LEAKPEEK_PACKS", root)
	setupCLIPack(t, root, "acme", "employee", "EMP-[0-9]{6}")
	setupCLIPack(t, root, "infra", "infra", "INFRA-[0-9]+")
	custom := writeRuleFile(t, "[[rule]]\nname='custom'\nregex='CUSTOM-[0-9]+'\n")
	input := "EMP-123456 INFRA-42 CUSTOM-7"
	base := []string{"--no-ignore", "--rule-pack", "acme", "--rule-pack=infra", "--rules", custom}
	for _, fix := range []bool{false, true} {
		args := append([]string{"--stdin"}, base...)
		if fix {
			args = append(args, "--fix", "--quiet")
		}
		var out, errOut bytes.Buffer
		if code := run(args, strings.NewReader(input), &out, &errOut); code != exitFound {
			t.Fatalf("fix=%v: code %d, stderr %s", fix, code, errOut.String())
		}
		report := out.String()
		if fix {
			report = errOut.String()
			for _, value := range strings.Fields(input) {
				if strings.Contains(out.String(), value) {
					t.Errorf("redaction retained %q: %s", value, out.String())
				}
			}
		}
		for _, name := range []string{"employee", "infra", "custom"} {
			if !strings.Contains(report, name) {
				t.Errorf("report lacks %q: %s", name, report)
			}
		}
	}

	file := filepath.Join(t.TempDir(), "input.txt")
	if err := os.WriteFile(file, []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	args := append([]string{"scan"}, base...)
	args = append(args, file)
	if code := run(args, strings.NewReader(""), &out, &errOut); code != exitFound {
		t.Fatalf("scan code %d, stderr %s", code, errOut.String())
	}
	for _, name := range []string{"employee", "infra", "custom"} {
		if !strings.Contains(out.String(), name) {
			t.Errorf("scan report lacks %q: %s", name, out.String())
		}
	}
}

func TestPacksListAndShow(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	t.Setenv("LEAKPEEK_PACKS", root)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	path := setupCLIPack(t, root, "acme", "employee", "EMP-[0-9]{6}")
	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"packs", "list"}, []string{"NAME", "VERSION", "RULES", "PATH", "acme", "1.2.3", "1", path}},
		{[]string{"packs", "show", "acme"}, []string{"acme", "1.2.3", path, "Team rules", "DETECTOR", "KIND", "employee", "secret"}},
		{[]string{"packs", "--help"}, []string{"packs list", "packs show", "LEAKPEEK_PACKS"}},
	} {
		var out, errOut bytes.Buffer
		if code := run(tc.args, nil, &out, &errOut); code != exitClean {
			t.Fatalf("%v: code %d, stderr %s", tc.args, code, errOut.String())
		}
		for _, want := range tc.want {
			if !strings.Contains(out.String(), want) {
				t.Errorf("%v: output %q lacks %q", tc.args, out.String(), want)
			}
		}
	}
}

func TestRulePackNameStartingWithDash(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LEAKPEEK_PACKS", root)
	setupCLIPack(t, root, "-acme", "employee", "EMP-[0-9]{6}")
	var out, errOut bytes.Buffer
	if code := run([]string{"--stdin", "--no-ignore", "--rule-pack=-acme"},
		strings.NewReader("EMP-123456"), &out, &errOut); code != exitFound {
		t.Fatalf("code %d, stderr %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "employee") {
		t.Fatalf("report lacks employee detector: %s", out.String())
	}
}

func TestPackCLIErrors(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LEAKPEEK_PACKS", root)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	for _, args := range [][]string{
		{"--rule-pack"}, {"--rule-pack="}, {"--rule-pack", "--stdin"},
		{"scan", "--rule-pack"}, {"scan", "--rule-pack=", "."},
		{"packs"}, {"packs", "show"}, {"packs", "list", "extra"}, {"packs", "unknown"},
	} {
		var out, errOut bytes.Buffer
		if code := run(args, nil, &out, &errOut); code != exitUsage {
			t.Errorf("%v: code %d, want usage; stderr %s", args, code, errOut.String())
		}
	}
	for _, args := range [][]string{
		{"--stdin", "--rule-pack", "missing"},
		{"scan", "--rule-pack", "missing", "."},
		{"packs", "show", "missing"},
	} {
		var out, errOut bytes.Buffer
		if code := run(args, nil, &out, &errOut); code != exitError {
			t.Fatalf("%v: code %d, stderr %s", args, code, errOut.String())
		}
		for _, want := range []string{"not found", filepath.Join(root, "missing"), "LEAKPEEK_PACKS"} {
			if !strings.Contains(errOut.String(), want) {
				t.Errorf("%v: stderr %q lacks %q", args, errOut.String(), want)
			}
		}
	}
	path := setupCLIPack(t, root, "broken", "bad", "[")
	for _, args := range [][]string{{"packs", "list"}, {"packs", "show", "broken"}} {
		var out, errOut bytes.Buffer
		if code := run(args, nil, &out, &errOut); code != exitError ||
			!strings.Contains(errOut.String(), filepath.Join(path, "rules.toml")) {
			t.Errorf("%v: code %d, stderr %s", args, code, errOut.String())
		}
	}
}
