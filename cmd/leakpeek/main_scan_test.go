package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const scanAWSKey = "AKIAIOSFODNN7EXAMPLE"

func writeScanTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	return root
}

func TestRun_ScanSubcommand_FoundExit(t *testing.T) {
	root := writeScanTree(t, map[string]string{"secrets.env": "AWS=" + scanAWSKey + "\n"})
	var out, errb bytes.Buffer
	code := run([]string{"scan", root}, nil, &out, &errb)
	if code != exitFound {
		t.Fatalf("exit = %d, want %d (found)\nstdout:%s\nstderr:%s", code, exitFound, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "secrets.env") {
		t.Errorf("expected file listed:\n%s", out.String())
	}
}

func TestRun_ScanSubcommand_CleanExit(t *testing.T) {
	root := writeScanTree(t, map[string]string{"a.txt": "totally clean\n"})
	var out, errb bytes.Buffer
	code := run([]string{"scan", root}, nil, &out, &errb)
	if code != exitClean {
		t.Fatalf("exit = %d, want %d (clean)", code, exitClean)
	}
}

func TestRun_ScanSubcommand_JSON(t *testing.T) {
	root := writeScanTree(t, map[string]string{"a.txt": "AWS=" + scanAWSKey + "\n"})
	var out, errb bytes.Buffer
	code := run([]string{"scan", "--json", root}, nil, &out, &errb)
	if code != exitFound {
		t.Fatalf("exit = %d, want found", code)
	}
	if !strings.Contains(out.String(), `"mode": "scan"`) {
		t.Errorf("expected scan json doc:\n%s", out.String())
	}
	if strings.Contains(out.String(), scanAWSKey) {
		t.Errorf("raw key leaked into json:\n%s", out.String())
	}
}

func TestRun_ScanSubcommand_NoPathsIsUsage(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"scan"}, nil, &out, &errb)
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d (usage)", code, exitUsage)
	}
}

func TestRun_ScanSubcommand_QuietClean(t *testing.T) {
	root := writeScanTree(t, map[string]string{"a.txt": "clean\n"})
	var out, errb bytes.Buffer
	code := run([]string{"scan", "--quiet", root}, nil, &out, &errb)
	if code != exitClean {
		t.Fatalf("exit = %d, want clean", code)
	}
	if out.Len() != 0 {
		t.Errorf("quiet clean should print nothing, got:\n%s", out.String())
	}
}

func TestRun_ScanSubcommand_StrictChillConflict(t *testing.T) {
	root := writeScanTree(t, map[string]string{"a.txt": "clean\n"})
	var out, errb bytes.Buffer
	code := run([]string{"scan", "--strict", "--chill", root}, nil, &out, &errb)
	if code != exitUsage {
		t.Fatalf("exit = %d, want usage for strict+chill", code)
	}
}
