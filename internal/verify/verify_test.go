package verify

import (
	"strings"
	"testing"

	"github.com/rwrife/leakpeek/internal/detect"
)

func TestBundledCorpusPasses(t *testing.T) {
	corpus, err := Bundled()
	if err != nil {
		t.Fatal(err)
	}
	detectors := detect.DefaultDetectors()
	result, err := Run(detectors, corpus)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Passed || len(result.Detectors) != len(detectors) {
		t.Fatalf("bundled corpus did not pass every built-in detector: %+v", result)
	}
}

func TestRunCountsMissesAndFalsePositivesIndependently(t *testing.T) {
	first, err := detect.NewRegexDetector("first", detect.KindSecret, "hit")
	if err != nil {
		t.Fatal(err)
	}
	second, err := detect.NewRegexDetector("second", detect.KindSecret, "hit")
	if err != nil {
		t.Fatal(err)
	}
	result, err := Run([]detect.Detector{first, second}, []DetectorFixtures{
		{Detector: "first",
			Positives: []Fixture{{Name: "caught", Text: "hit"}, {Name: "missed", Text: "absent"}},
			Negatives: []Fixture{{Name: "clean", Text: "absent"}, {Name: "trap", Text: "hit hit"}}},
		{Detector: "second",
			Positives: []Fixture{{Name: "overlapping hit", Text: "hit"}},
			Negatives: []Fixture{{Name: "clean", Text: "absent"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	firstRow := result.Detectors[0]
	if result.Passed || firstRow.Passed || firstRow.PositivesCaught != 1 ||
		firstRow.PositivesTotal != 2 || firstRow.FalsePositives != 1 ||
		firstRow.NegativesTotal != 2 || len(firstRow.Failures) != 2 ||
		!result.Detectors[1].Passed {
		t.Fatalf("unexpected verification result: %+v", result)
	}
}

func TestRunRejectsIncompleteOrAmbiguousCorpus(t *testing.T) {
	d, err := detect.NewRegexDetector("custom", detect.KindSecret, "hit")
	if err != nil {
		t.Fatal(err)
	}
	valid := DetectorFixtures{
		Detector:  "custom",
		Positives: []Fixture{{Name: "hit", Text: "hit"}},
		Negatives: []Fixture{{Name: "miss", Text: "miss"}},
	}
	tests := []struct {
		name      string
		detectors []detect.Detector
		corpus    []DetectorFixtures
		want      string
	}{
		{"missing fixtures", []detect.Detector{d}, nil, "no verification fixtures"},
		{"duplicate fixtures", []detect.Detector{d}, []DetectorFixtures{valid, valid}, "duplicate fixtures"},
		{"duplicate detectors", []detect.Detector{d, d}, []DetectorFixtures{valid}, "unique detector names"},
		{"unknown detector", nil, []DetectorFixtures{valid}, "unknown detector"},
		{"no positive", []detect.Detector{d}, []DetectorFixtures{{Detector: "custom", Negatives: valid.Negatives}}, "positive and one negative"},
		{"no negative", []detect.Detector{d}, []DetectorFixtures{{Detector: "custom", Positives: valid.Positives}}, "positive and one negative"},
		{"empty fixture", []detect.Detector{d}, []DetectorFixtures{{Detector: "custom", Positives: []Fixture{{Name: "empty"}}, Negatives: valid.Negatives}}, "nonempty text"},
		{"duplicate fixture name", []detect.Detector{d}, []DetectorFixtures{{Detector: "custom", Positives: valid.Positives, Negatives: valid.Positives}}, "unique nonempty names"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Run(tt.detectors, tt.corpus)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestDecodeRejectsMalformedCorpus(t *testing.T) {
	for _, input := range []string{
		`not json`,
		`[{"detector":"custom","positive":[]}]`,
		`[] []`,
		`[] trailing`,
		`{"detector":"custom"}`,
	} {
		t.Run(input, func(t *testing.T) {
			if _, err := decode([]byte(input)); err == nil {
				t.Fatal("accepted malformed corpus")
			}
		})
	}
}
