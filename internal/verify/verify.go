// Package verify self-tests detectors against an embedded offline corpus.
package verify

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/rwrife/leakpeek/internal/detect"
)

//go:embed corpus.json
var bundled []byte

type Fixture struct {
	Name string `json:"name"`
	Text string `json:"text"`
}

type DetectorFixtures struct {
	Detector  string    `json:"detector"`
	Positives []Fixture `json:"positives"`
	Negatives []Fixture `json:"negatives"`
}

type Row struct {
	Detector        string   `json:"detector"`
	PositivesCaught int      `json:"positives_caught"`
	PositivesTotal  int      `json:"positives_total"`
	FalsePositives  int      `json:"false_positives"`
	NegativesTotal  int      `json:"negatives_total"`
	Failures        []string `json:"failures"`
	Passed          bool     `json:"passed"`
}

type Result struct {
	SchemaVersion int    `json:"schema_version"`
	Mode          string `json:"mode"`
	Detectors     []Row  `json:"detectors"`
	Passed        bool   `json:"passed"`
}

func Bundled() ([]DetectorFixtures, error) {
	return decode(bundled)
}

// LoadCustom reads one fixture document for the rule file or directory.
func LoadCustom(rulesPath string) ([]DetectorFixtures, error) {
	info, err := os.Stat(rulesPath)
	if err != nil {
		return nil, err
	}
	path := rulesPath + ".fixtures.json"
	if info.IsDir() {
		path = filepath.Join(rulesPath, "fixtures.json")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading verification fixtures %q: %w", path, err)
	}
	fixtures, err := decode(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return fixtures, nil
}

func decode(b []byte) ([]DetectorFixtures, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var fixtures []DetectorFixtures
	if err := dec.Decode(&fixtures); err != nil {
		return nil, fmt.Errorf("invalid verification corpus: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("verification corpus must contain exactly one JSON array")
	}
	return fixtures, nil
}

// Run calls detectors independently so overlap de-duplication cannot hide a
// detector's miss or attribute another detector's hit to it.
func Run(detectors []detect.Detector, corpus []DetectorFixtures) (Result, error) {
	byName := make(map[string]DetectorFixtures, len(corpus))
	for _, fixtures := range corpus {
		if _, exists := byName[fixtures.Detector]; exists {
			return Result{}, fmt.Errorf("duplicate fixtures for detector %q", fixtures.Detector)
		}
		if len(fixtures.Positives) == 0 || len(fixtures.Negatives) == 0 {
			return Result{}, fmt.Errorf("detector %q needs at least one positive and one negative fixture", fixtures.Detector)
		}
		names := make(map[string]bool)
		for _, group := range [][]Fixture{fixtures.Positives, fixtures.Negatives} {
			for _, f := range group {
				if f.Name == "" || f.Text == "" || names[f.Name] {
					return Result{}, fmt.Errorf("detector %q: fixtures need unique nonempty names and nonempty text", fixtures.Detector)
				}
				names[f.Name] = true
			}
		}
		byName[fixtures.Detector] = fixtures
	}
	result := Result{SchemaVersion: 1, Mode: "verify", Detectors: []Row{}, Passed: true}
	seen := make(map[string]bool)
	for _, d := range detectors {
		if seen[d.Name()] {
			return Result{}, fmt.Errorf("verification requires unique detector names: %q", d.Name())
		}
		seen[d.Name()] = true
		fixtures, ok := byName[d.Name()]
		if !ok {
			return Result{}, fmt.Errorf("no verification fixtures for detector %q", d.Name())
		}
		row := Row{
			Detector: d.Name(), PositivesTotal: len(fixtures.Positives),
			NegativesTotal: len(fixtures.Negatives), Failures: []string{},
		}
		for _, f := range fixtures.Positives {
			if len(d.Find(f.Text)) > 0 {
				row.PositivesCaught++
			} else {
				row.Failures = append(row.Failures, "missed positive: "+f.Name)
			}
		}
		for _, f := range fixtures.Negatives {
			if len(d.Find(f.Text)) > 0 {
				row.FalsePositives++
				row.Failures = append(row.Failures, "false positive: "+f.Name)
			}
		}
		row.Passed = len(row.Failures) == 0
		result.Passed = result.Passed && row.Passed
		result.Detectors = append(result.Detectors, row)
	}
	for _, fixtures := range corpus {
		if !seen[fixtures.Detector] {
			return Result{}, fmt.Errorf("fixtures reference unknown detector %q", fixtures.Detector)
		}
	}
	return result, nil
}
