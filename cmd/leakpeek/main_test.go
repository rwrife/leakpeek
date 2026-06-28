package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestVersionFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--version"}, strings.NewReader(""), &out, &errBuf)
	if code != exitClean {
		t.Fatalf("exit code = %d, want %d", code, exitClean)
	}
	if !strings.HasPrefix(out.String(), "leakpeek ") {
		t.Errorf("version output = %q, want it to start with %q", out.String(), "leakpeek ")
	}
}

func TestCleanScanExitsZero(t *testing.T) {
	const in = "just some normal prose, nothing sensitive here\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin"}, strings.NewReader(in), &out, &errBuf)
	if code != exitClean {
		t.Fatalf("exit code = %d, want %d (stderr: %q)", code, exitClean, errBuf.String())
	}
	if !strings.Contains(out.String(), "Clean") {
		t.Errorf("clean output = %q, want a clean verdict", out.String())
	}
}

func TestDirtyScanExitsFound(t *testing.T) {
	// Synthetic AKIA-shaped key: matches the detector's shape without being a
	// real credential (…EXAMPLE), so push protection stays quiet.
	const in = "leak: AKIAIOSFODNN7EXAMPLE here\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin"}, strings.NewReader(in), &out, &errBuf)
	if code != exitFound {
		t.Fatalf("exit code = %d, want %d (found)", code, exitFound)
	}
	if !strings.Contains(out.String(), "aws-access-key") {
		t.Errorf("report = %q, want it to name the detector", out.String())
	}
	// The report must NOT echo the raw secret back.
	if strings.Contains(out.String(), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("report leaked the raw secret: %q", out.String())
	}
}

func TestQuietSuppressesCleanOutput(t *testing.T) {
	const in = "totally fine text\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--quiet"}, strings.NewReader(in), &out, &errBuf)
	if code != exitClean {
		t.Fatalf("exit code = %d, want %d", code, exitClean)
	}
	if out.String() != "" {
		t.Errorf("quiet clean output = %q, want empty", out.String())
	}
}

func TestQuietStillReportsOnHit(t *testing.T) {
	const in = "AKIAIOSFODNN7EXAMPLE\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--quiet"}, strings.NewReader(in), &out, &errBuf)
	if code != exitFound {
		t.Fatalf("exit code = %d, want %d", code, exitFound)
	}
	if out.String() == "" {
		t.Errorf("quiet hit output is empty, want a report")
	}
}

func TestJSONOutputIsValidAndStamped(t *testing.T) {
	const in = "AKIAIOSFODNN7EXAMPLE and jane@example.com\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--json"}, strings.NewReader(in), &out, &errBuf)
	if code != exitFound {
		t.Fatalf("exit code = %d, want %d", code, exitFound)
	}

	var doc struct {
		Tool     string `json:"tool"`
		Version  int    `json:"version"`
		Total    int    `json:"total"`
		Clean    bool   `json:"clean"`
		Findings []struct {
			Detector string `json:"detector"`
			Preview  string `json:"preview"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out.String())
	}
	if doc.Tool != "leakpeek" || doc.Version != 1 {
		t.Errorf("tool/version = %q/%d, want leakpeek/1", doc.Tool, doc.Version)
	}
	if doc.Total != 2 || doc.Clean {
		t.Errorf("total/clean = %d/%v, want 2/false", doc.Total, doc.Clean)
	}
	for _, f := range doc.Findings {
		if strings.Contains(f.Preview, "IOSFODNN7") {
			t.Errorf("json preview leaked raw secret material: %q", f.Preview)
		}
	}
}

func TestJSONEmitsEvenWhenCleanAndQuiet(t *testing.T) {
	// --json overrides --quiet: a consumer must always be able to parse a doc.
	const in = "nothing here\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--json", "--quiet"}, strings.NewReader(in), &out, &errBuf)
	if code != exitClean {
		t.Fatalf("exit code = %d, want %d", code, exitClean)
	}
	var doc struct {
		Clean bool `json:"clean"`
		Total int  `json:"total"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("clean+quiet --json not parseable: %v\n%s", err, out.String())
	}
	if !doc.Clean || doc.Total != 0 {
		t.Errorf("clean/total = %v/%d, want true/0", doc.Clean, doc.Total)
	}
}

func TestUnknownFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--frobnicate"}, strings.NewReader(""), &out, &errBuf)
	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errBuf.String(), "unknown flag") {
		t.Errorf("stderr = %q, want it to mention %q", errBuf.String(), "unknown flag")
	}
}

func TestHelpFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--help"}, strings.NewReader(""), &out, &errBuf)
	if code != exitClean {
		t.Fatalf("exit code = %d, want %d", code, exitClean)
	}
	if !strings.Contains(out.String(), "Usage:") {
		t.Errorf("help output = %q, want it to contain %q", out.String(), "Usage:")
	}
}
