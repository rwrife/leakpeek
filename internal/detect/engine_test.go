package detect

import (
	"os"
	"path/filepath"
	"testing"
)

// staticDetector is a tiny test double that returns a fixed set of findings,
// letting us exercise Engine.Scan's merge/dedupe logic deterministically.
type staticDetector struct {
	name  string
	kind  Kind
	finds []Finding
}

func (s staticDetector) Name() string { return s.name }
func (s staticDetector) Kind() Kind   { return s.kind }
func (s staticDetector) Find(string) []Finding {
	// Return copies so the engine's field-stamping can't mutate our fixtures.
	out := make([]Finding, len(s.finds))
	copy(out, s.finds)
	return out
}

func TestEngine_Scan_SortsAndStampsFindings(t *testing.T) {
	// Two non-overlapping findings returned out of order should come back
	// sorted by Start, with Detector/Kind stamped from the engine's view.
	d := staticDetector{
		name: "demo", kind: KindSecret,
		finds: []Finding{
			{Start: 10, End: 14, Match: "late"},
			{Start: 0, End: 5, Match: "early"},
		},
	}
	got := New(d).Scan("ignored input text padding padding")
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}
	if got[0].Start != 0 || got[1].Start != 10 {
		t.Errorf("findings not sorted by Start: %+v", got)
	}
	for _, f := range got {
		if f.Detector != "demo" || f.Kind != KindSecret {
			t.Errorf("finding not stamped with engine identity: %+v", f)
		}
	}
}

func TestEngine_Scan_DedupesOverlappingSpans(t *testing.T) {
	// A "broad" detector (registered first) covers [0,20); a "narrow" one
	// covers [5,12) inside it. The broad span must win and the fragment drop.
	broad := staticDetector{
		name: "broad", kind: KindSecret,
		finds: []Finding{{Start: 0, End: 20, Match: "01234567890123456789"}},
	}
	narrow := staticDetector{
		name: "narrow", kind: KindEntropy,
		finds: []Finding{{Start: 5, End: 12, Match: "5678901"}},
	}
	got := New(broad, narrow).Scan("01234567890123456789 trailing context here")
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1 after dedupe: %+v", len(got), got)
	}
	if got[0].Detector != "broad" || got[0].Start != 0 || got[0].End != 20 {
		t.Errorf("wrong span survived dedupe: %+v", got[0])
	}
}

func TestEngine_Scan_KeepsAdjacentNonOverlapping(t *testing.T) {
	// Spans that merely touch ([0,5) and [5,10)) do NOT overlap and both
	// survive — guards against an off-by-one in the half-open interval logic.
	a := staticDetector{name: "a", kind: KindSecret, finds: []Finding{{Start: 0, End: 5, Match: "aaaaa"}}}
	b := staticDetector{name: "b", kind: KindSecret, finds: []Finding{{Start: 5, End: 10, Match: "bbbbb"}}}
	got := New(a, b).Scan("aaaaabbbbb plus more text to be safe here")
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2 (adjacent spans must both survive): %+v", len(got), got)
	}
}

func TestEngine_Scan_EmptyInputIsNonNilEmpty(t *testing.T) {
	got := Default().Scan("")
	if got == nil {
		t.Fatal("Scan returned nil; callers expect a non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("empty input produced findings: %+v", got)
	}
}

// TestEngine_Scan_Fixture is the milestone's definition of done: the default
// engine returns the right set of findings for a realistic fixture file, with
// specific detectors winning over the generic entropy catch-all.
func TestEngine_Scan_Fixture(t *testing.T) {
	path := filepath.Join("testdata", "sample.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	findings := Default().Scan(string(data))

	// Every finding must accurately reference its byte span in the source.
	src := string(data)
	for _, f := range findings {
		if f.Start < 0 || f.End > len(src) || f.Start >= f.End {
			t.Errorf("finding has invalid span: %+v", f)
			continue
		}
		if f.Match != src[f.Start:f.End] {
			t.Errorf("Match %q != source slice %q", f.Match, src[f.Start:f.End])
		}
	}

	// Spans must be sorted and non-overlapping after dedupe.
	for i := 1; i < len(findings); i++ {
		if findings[i].Start < findings[i-1].End {
			t.Errorf("overlapping/unsorted findings: %+v then %+v", findings[i-1], findings[i])
		}
	}

	// Count findings per detector to assert the expected secret pack fired.
	byDetector := map[string]int{}
	for _, f := range findings {
		byDetector[f.Detector]++
	}

	wantAtLeast := map[string]int{
		"aws-access-key": 1,
		"openai-key":     1,
		"github-pat":     1,
		"slack-token":    1,
		"jwt":            1,
		"private-key":    1,
		"email":          1,
		"ipv4":           1,
	}
	for name, min := range wantAtLeast {
		if byDetector[name] < min {
			t.Errorf("detector %q fired %d times, want >= %d\nall findings: %v",
				name, byDetector[name], min, summarize(findings))
		}
	}

	// The high-entropy catch-all must NOT re-report the AWS/GitHub/etc. keys
	// it overlaps — they should be claimed by their specific detectors. We
	// allow it to fire on the PEM body, so just assert it didn't swallow the
	// AWS key span.
	for _, f := range findings {
		if f.Detector == "high-entropy-token" && f.Match == "AKIAIOSFODNN7EXAMPLE" {
			t.Errorf("generic detector claimed the AWS key; specific detector should win")
		}
	}
}

func summarize(fs []Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Detector + ":" + f.Match
	}
	return out
}
