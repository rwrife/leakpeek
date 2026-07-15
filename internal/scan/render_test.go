package scan

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rwrife/leakpeek/internal/detect"
)

func scanTree(t *testing.T, files map[string]string) (Result, func(string) string) {
	t.Helper()
	root := writeTree(t, files)
	res, err := Walk([]string{root}, defaultOpts())
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	read := func(p string) string {
		for rel, c := range files {
			if strings.HasSuffix(p, rel) {
				return c
			}
		}
		return ""
	}
	return res, read
}

func TestRender_HumanListsFilesWithHits(t *testing.T) {
	res, read := scanTree(t, map[string]string{
		"a.txt": "AWS=" + awsKey + "\n",
		"b.txt": "clean content\n",
	})
	var buf bytes.Buffer
	Render(&buf, res, read, false)
	out := buf.String()
	if !strings.Contains(out, "a.txt") {
		t.Errorf("expected a.txt in output:\n%s", out)
	}
	if strings.Contains(out, "b.txt") {
		t.Errorf("clean b.txt should not be listed:\n%s", out)
	}
	if !strings.Contains(out, "🚫") {
		t.Errorf("expected a dirty summary line:\n%s", out)
	}
}

func TestRender_CleanSummary(t *testing.T) {
	res, read := scanTree(t, map[string]string{"a.txt": "all clean\n"})
	var buf bytes.Buffer
	Render(&buf, res, read, false)
	if !strings.Contains(buf.String(), "✅ Clean") {
		t.Errorf("expected clean summary, got:\n%s", buf.String())
	}
}

func TestRender_QuietCleanSilent(t *testing.T) {
	res, read := scanTree(t, map[string]string{"a.txt": "all clean\n"})
	var buf bytes.Buffer
	Render(&buf, res, read, true)
	if buf.Len() != 0 {
		t.Errorf("quiet clean scan should be silent, got:\n%s", buf.String())
	}
}

func TestRenderJSON_Shape(t *testing.T) {
	res, read := scanTree(t, map[string]string{
		"a.txt": "AWS=" + awsKey + "\n",
		"b.txt": "clean\n",
	})
	var buf bytes.Buffer
	if err := RenderJSON(&buf, res, read); err != nil {
		t.Fatalf("render json: %v", err)
	}
	var doc struct {
		Tool          string `json:"tool"`
		Mode          string `json:"mode"`
		Total         int    `json:"total"`
		FilesScanned  int    `json:"filesScanned"`
		FilesWithHits int    `json:"filesWithHits"`
		Clean         bool   `json:"clean"`
		Files         []struct {
			Path  string `json:"path"`
			Total int    `json:"total"`
		} `json:"files"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, buf.String())
	}
	if doc.Tool != "leakpeek" || doc.Mode != "scan" {
		t.Errorf("tool/mode = %q/%q", doc.Tool, doc.Mode)
	}
	if doc.Total != 1 || doc.FilesWithHits != 1 || doc.FilesScanned != 2 {
		t.Errorf("counts total=%d hits=%d scanned=%d, want 1/1/2", doc.Total, doc.FilesWithHits, doc.FilesScanned)
	}
	if doc.Clean {
		t.Error("expected clean=false")
	}
	if len(doc.Files) != 2 {
		t.Fatalf("files len = %d, want 2", len(doc.Files))
	}
}

func TestRenderJSON_PreviewMasked(t *testing.T) {
	res, read := scanTree(t, map[string]string{"a.txt": "AWS=" + awsKey + "\n"})
	var buf bytes.Buffer
	if err := RenderJSON(&buf, res, read); err != nil {
		t.Fatalf("render json: %v", err)
	}
	// The full raw key must never appear in output — previews are masked.
	if strings.Contains(buf.String(), awsKey) {
		t.Errorf("raw secret leaked into JSON output:\n%s", buf.String())
	}
}

var _ = detect.Default
