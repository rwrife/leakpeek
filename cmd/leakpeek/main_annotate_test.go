package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// --annotate appends a provenance footer to the redacted pipe output that
// summarizes what was scrubbed by kind/count, without ever leaking a value.
func TestFixAnnotatePipeFooter(t *testing.T) {
	const in = "key=AKIAIOSFODNN7EXAMPLE\nmail=jane.doe@corp.internal\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--fix", "--quiet", "--annotate"}, strings.NewReader(in), &out, &errBuf)
	if code != exitFound {
		t.Fatalf("exit = %d, want %d; stderr=%q", code, exitFound, errBuf.String())
	}
	got := out.String()

	if !strings.Contains(got, "[leakpeek: redacted") {
		t.Errorf("stdout missing annotation footer: %q", got)
	}
	if !strings.Contains(got, "1 API key") || !strings.Contains(got, "1 email") {
		t.Errorf("annotation footer wrong counts: %q", got)
	}
	// The footer must never re-leak the values it summarizes.
	for _, secret := range []string{"AKIAIOSFODNN7EXAMPLE", "jane.doe"} {
		if strings.Contains(got, secret) {
			t.Errorf("stdout leaked %q: %q", secret, got)
		}
	}
	// Redacted structure is still present above the footer.
	if !strings.Contains(got, "key=") || !strings.Contains(got, "mail=") {
		t.Errorf("stdout lost structure: %q", got)
	}
}

// Without --annotate, no footer is emitted (opt-in, off by default).
func TestFixNoAnnotateByDefault(t *testing.T) {
	const in = "key=AKIAIOSFODNN7EXAMPLE\n"
	var out, errBuf bytes.Buffer
	run([]string{"--stdin", "--fix", "--quiet"}, strings.NewReader(in), &out, &errBuf)
	if strings.Contains(out.String(), "leakpeek: redacted") {
		t.Errorf("footer emitted without --annotate: %q", out.String())
	}
}

// A clean scan with --annotate leaves output byte-for-byte untouched (no
// footer when nothing was redacted).
func TestFixAnnotateCleanNoFooter(t *testing.T) {
	const in = "nothing sensitive here\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--fix", "--quiet", "--annotate"}, strings.NewReader(in), &out, &errBuf)
	if code != exitClean {
		t.Fatalf("exit = %d, want clean", code)
	}
	if out.String() != in {
		t.Errorf("clean --annotate passthrough = %q, want %q", out.String(), in)
	}
}

// --json --annotate mirrors the footer in an "annotation" field.
func TestFixAnnotateJSONField(t *testing.T) {
	const in = "key=AKIAIOSFODNN7EXAMPLE\n"
	var out, errBuf bytes.Buffer
	run([]string{"--stdin", "--fix", "--annotate", "--json"}, strings.NewReader(in), &out, &errBuf)

	var doc struct {
		Annotation string `json:"annotation"`
	}
	if err := json.Unmarshal(errBuf.Bytes(), &doc); err != nil {
		// In pipe mode the redacted payload owns stdout and JSON report goes to
		// stderr. Try stdout as a fallback in case wiring changes.
		if err2 := json.Unmarshal(out.Bytes(), &doc); err2 != nil {
			t.Fatalf("json parse failed: stderr=%q stdout=%q", errBuf.String(), out.String())
		}
	}
	if !strings.Contains(doc.Annotation, "1 API key") {
		t.Errorf("annotation field = %q, want it to mention 1 API key", doc.Annotation)
	}
}

// --annotate --strategy vault notes reversibility in the footer.
func TestFixAnnotateVaultReversible(t *testing.T) {
	const in = "key=AKIAIOSFODNN7EXAMPLE\n"
	var out, errBuf bytes.Buffer
	run([]string{"--stdin", "--fix", "--quiet", "--annotate", "--strategy", "vault", "--no-vault"},
		strings.NewReader(in), &out, &errBuf)
	got := out.String()
	if !strings.Contains(got, "reversibly redacted") {
		t.Errorf("vault footer not reversible: %q", got)
	}
}
