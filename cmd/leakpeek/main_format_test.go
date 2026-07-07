package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// Like the other --fix pipe tests, stdin is a strings.Reader so the CLI treats
// input as piped: --fix prints the redacted payload to stdout and the report
// goes to stderr. --format-aware should redact structural *values* and keep
// keys/shape.

// TestFixFormatAwareJSONPipe: JSON in, structure-preserving redaction out, and
// the result is still valid JSON with keys intact and no secret material.
func TestFixFormatAwareJSONPipe(t *testing.T) {
	const in = `{"api_key":"AKIAIOSFODNN7EXAMPLE","port":8080,"host":"db.internal"}`
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--fix", "--format-aware", "--quiet"}, strings.NewReader(in), &out, &errBuf)
	if code != exitFound {
		t.Fatalf("exit = %d, want %d (found); stderr=%q", code, exitFound, errBuf.String())
	}
	got := out.String()

	// Secret gone.
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("stdout leaked secret: %q", got)
	}
	// Key preserved.
	if !strings.Contains(got, `"api_key":`) {
		t.Errorf("json key not preserved: %q", got)
	}
	// Non-secret value untouched.
	if !strings.Contains(got, `"port":8080`) {
		t.Errorf("non-secret value changed: %q", got)
	}
	// Output is still valid JSON (the redacted string value stayed quoted).
	var v map[string]any
	if err := json.Unmarshal([]byte(got), &v); err != nil {
		t.Errorf("format-aware JSON output is not valid JSON: %v\n  out: %q", err, got)
	}
}

// TestFixFormatAwareDotenvPipe: .env in, KEY=... preserved, value redacted.
func TestFixFormatAwareDotenvPipe(t *testing.T) {
	const in = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nPORT=8080\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--fix", "--format-aware", "--quiet"}, strings.NewReader(in), &out, &errBuf)
	if code != exitFound {
		t.Fatalf("exit = %d, want %d; stderr=%q", code, exitFound, errBuf.String())
	}
	got := out.String()
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("stdout leaked secret: %q", got)
	}
	if !strings.Contains(got, "AWS_ACCESS_KEY_ID=") {
		t.Errorf("dotenv key/`=` not preserved: %q", got)
	}
	if !strings.Contains(got, "PORT=8080") {
		t.Errorf("non-secret line changed: %q", got)
	}
}

// TestFixFormatAwareFallsBackOnPlain: a --format-aware run over unstructured
// text still redacts, using the ordinary span-based path.
func TestFixFormatAwareFallsBackOnPlain(t *testing.T) {
	const in = "here is a stray key AKIAIOSFODNN7EXAMPLE in a sentence\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--fix", "--format-aware", "--quiet"}, strings.NewReader(in), &out, &errBuf)
	if code != exitFound {
		t.Fatalf("exit = %d, want %d; stderr=%q", code, exitFound, errBuf.String())
	}
	got := out.String()
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("stdout leaked secret: %q", got)
	}
	// Plain fallback keeps the shape hint.
	if !strings.Contains(got, "AKIAREDACTED") {
		t.Errorf("plain fallback token missing: %q", got)
	}
}

// TestFixFormatAliasFlag: --format is accepted as an alias for --format-aware.
func TestFixFormatAliasFlag(t *testing.T) {
	const in = `{"tok":"AKIAIOSFODNN7EXAMPLE"}`
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--fix", "--format", "--quiet"}, strings.NewReader(in), &out, &errBuf)
	if code != exitFound {
		t.Fatalf("exit = %d, want %d; stderr=%q", code, exitFound, errBuf.String())
	}
	if strings.Contains(out.String(), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("stdout leaked secret: %q", out.String())
	}
	if !strings.Contains(out.String(), `"tok":`) {
		t.Errorf("key not preserved via --format alias: %q", out.String())
	}
}
