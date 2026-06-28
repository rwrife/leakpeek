package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rwrife/leakpeek/internal/detect"
)

// mkFinding is a tiny constructor for table-driven tests. It sets Match to the
// substring of text so callers can keep cases readable.
func mkFinding(text, detector string, kind detect.Kind, start, end int) detect.Finding {
	return detect.Finding{
		Detector: detector,
		Kind:     kind,
		Start:    start,
		End:      end,
		Match:    text[start:end],
	}
}

func TestBuildComputesLineAndColumn(t *testing.T) {
	text := "line one\nsecond AKIAIOSFODNN7EXAMPLE line\n"
	start := strings.Index(text, "AKIA")
	end := start + len("AKIAIOSFODNN7EXAMPLE")
	f := mkFinding(text, "aws-access-key", detect.KindSecret, start, end)

	res := Build(text, []detect.Finding{f})
	if res.Total != 1 || res.Clean {
		t.Fatalf("total/clean = %d/%v, want 1/false", res.Total, res.Clean)
	}
	it := res.Items[0]
	if it.Line != 2 {
		t.Errorf("line = %d, want 2", it.Line)
	}
	// "second " is 7 chars, so the key starts at column 8 (1-based).
	if it.Column != 8 {
		t.Errorf("column = %d, want 8", it.Column)
	}
}

func TestBuildColumnCountsRunesNotBytes(t *testing.T) {
	// "café " has a multibyte é; the email after it should still be column 6.
	text := "café a@b.com"
	// Locate the email by '@' and back up to its single-char local part.
	at := strings.IndexByte(text, '@')
	start := at - 1
	end := len(text)
	f := mkFinding(text, "email", detect.KindPII, start, end)

	res := Build(text, []detect.Finding{f})
	it := res.Items[0]
	if it.Line != 1 {
		t.Fatalf("line = %d, want 1", it.Line)
	}
	// "café " = 5 runes, email starts at rune column 6.
	if it.Column != 6 {
		t.Errorf("column = %d, want 6 (rune-based)", it.Column)
	}
}

func TestBuildGroupsByDetector(t *testing.T) {
	text := "a@x.com b@y.com 10.0.0.1"
	f1 := mkFinding(text, "email", detect.KindPII, 0, 7)
	f2 := mkFinding(text, "email", detect.KindPII, 8, 15)
	f3 := mkFinding(text, "ipv4", detect.KindNetwork, 16, 24)

	res := Build(text, []detect.Finding{f1, f2, f3})
	if len(res.Groups) != 2 {
		t.Fatalf("group count = %d, want 2", len(res.Groups))
	}
	if res.Groups[0].Detector != "email" || res.Groups[0].Count != 2 {
		t.Errorf("group[0] = %s/%d, want email/2", res.Groups[0].Detector, res.Groups[0].Count)
	}
	if res.Groups[1].Detector != "ipv4" || res.Groups[1].Count != 1 {
		t.Errorf("group[1] = %s/%d, want ipv4/1", res.Groups[1].Detector, res.Groups[1].Count)
	}
}

func TestBuildEmptyIsClean(t *testing.T) {
	res := Build("nothing sensitive", nil)
	if !res.Clean || res.Total != 0 {
		t.Errorf("clean/total = %v/%d, want true/0", res.Clean, res.Total)
	}
	if !strings.Contains(res.Verdict, "Clean") {
		t.Errorf("verdict = %q, want a clean verdict", res.Verdict)
	}
}

func TestMaskNeverEchoesRawSecret(t *testing.T) {
	cases := []struct {
		name   string
		kind   detect.Kind
		match  string
		wantIn string // a fragment the preview SHOULD contain
		hidden string // a fragment it must NOT contain
	}{
		{"aws", detect.KindSecret, "AKIAIOSFODNN7EXAMPLE", "AKIA", "IOSFODNN7"},
		{"openai", detect.KindSecret, "sk-proj-abcdef0123456789ABCDEF", "sk-proj", "abcdef0123456789"},
		{"github", detect.KindSecret, "ghp_0123456789ABCDEFabcdef0123456789ABCD", "ghp_", "0123456789ABCDEFabcdef"},
		{"email", detect.KindPII, "jane.doe@example.com", "@example.com", "jane.doe"},
		{"ipv4", detect.KindNetwork, "10.0.12.34", "10.", "12.34"},
		{"privkey", detect.KindPrivateKey, "-----BEGIN RSA PRIVATE KEY-----", "BEGIN", "MIIE"},
		{"entropy", detect.KindEntropy, "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5", "Zm", "YmFyYmF6cXV4"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Mask(c.kind, c.match)
			if !strings.Contains(got, c.wantIn) {
				t.Errorf("Mask(%s) = %q, want it to contain %q", c.name, got, c.wantIn)
			}
			if c.hidden != "" && strings.Contains(got, c.hidden) {
				t.Errorf("Mask(%s) = %q leaked hidden fragment %q", c.name, got, c.hidden)
			}
			if got == c.match {
				t.Errorf("Mask(%s) returned the input unmasked", c.name)
			}
		})
	}
}

func TestMaskMultibyteSafe(t *testing.T) {
	// A token with multibyte runes must not be sliced mid-character (which
	// would produce invalid UTF-8 / a panic-adjacent mess).
	got := Mask(detect.KindEntropy, "αβγδεζηθικλμνξοπρστυφχψω0123456789")
	if !utf8Valid(got) {
		t.Errorf("masked preview is not valid UTF-8: %q", got)
	}
}

func TestRenderQuietCleanWritesNothing(t *testing.T) {
	res := Build("all good", nil)
	var b bytes.Buffer
	Render(&b, res, true)
	if b.Len() != 0 {
		t.Errorf("quiet clean render = %q, want empty", b.String())
	}
}

func TestRenderCleanNotQuietWritesVerdict(t *testing.T) {
	res := Build("all good", nil)
	var b bytes.Buffer
	Render(&b, res, false)
	if !strings.Contains(b.String(), "Clean") {
		t.Errorf("clean render = %q, want a verdict", b.String())
	}
}

func TestRenderDirtyHasHeaderTableAndVerdict(t *testing.T) {
	text := "a@x.com\nb@y.com"
	res := Build(text, []detect.Finding{
		mkFinding(text, "email", detect.KindPII, 0, 7),
		mkFinding(text, "email", detect.KindPII, 8, 15),
	})
	var b bytes.Buffer
	Render(&b, res, false)
	out := b.String()
	for _, want := range []string{"regret pasting", "TYPE", "COUNT", "WHERE", "PREVIEW", "email", "(+1 more)", "Don't paste"} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q\n---\n%s", want, out)
		}
	}
}

func TestRenderJSONShape(t *testing.T) {
	text := "AKIAIOSFODNN7EXAMPLE"
	res := Build(text, []detect.Finding{
		mkFinding(text, "aws-access-key", detect.KindSecret, 0, 20),
	})
	var b bytes.Buffer
	if err := RenderJSON(&b, res); err != nil {
		t.Fatalf("RenderJSON error: %v", err)
	}

	var doc struct {
		Tool     string `json:"tool"`
		Version  int    `json:"version"`
		Total    int    `json:"total"`
		Clean    bool   `json:"clean"`
		Findings []struct {
			Detector string `json:"detector"`
			Kind     string `json:"kind"`
			Line     int    `json:"line"`
			Start    int    `json:"start"`
			End      int    `json:"end"`
			Preview  string `json:"preview"`
		} `json:"findings"`
		Verdict string `json:"verdict"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, b.String())
	}
	if doc.Tool != "leakpeek" || doc.Version != jsonVersion {
		t.Errorf("tool/version = %q/%d, want leakpeek/%d", doc.Tool, doc.Version, jsonVersion)
	}
	if doc.Total != 1 || doc.Clean {
		t.Errorf("total/clean = %d/%v, want 1/false", doc.Total, doc.Clean)
	}
	if len(doc.Findings) != 1 {
		t.Fatalf("findings len = %d, want 1", len(doc.Findings))
	}
	got := doc.Findings[0]
	if got.Detector != "aws-access-key" || got.Kind != "secret" {
		t.Errorf("finding detector/kind = %s/%s", got.Detector, got.Kind)
	}
	if got.Line != 1 || got.Start != 0 || got.End != 20 {
		t.Errorf("finding pos = line %d [%d,%d), want 1 [0,20)", got.Line, got.Start, got.End)
	}
	if strings.Contains(got.Preview, "IOSFODNN7") {
		t.Errorf("json preview leaked secret: %q", got.Preview)
	}
	if doc.Verdict == "" {
		t.Error("verdict is empty")
	}
}

// utf8Valid reports whether s is valid UTF-8 (tiny local helper to avoid an
// import just for one check).
func utf8Valid(s string) bool {
	for _, r := range s {
		if r == '\uFFFD' {
			return false
		}
	}
	return true
}
