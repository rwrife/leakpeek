package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--version"}, strings.NewReader(""), &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.HasPrefix(out.String(), "leakpeek ") {
		t.Errorf("version output = %q, want it to start with %q", out.String(), "leakpeek ")
	}
}

func TestStdinEchoesUnchanged(t *testing.T) {
	const in = "hello AKIAEXAMPLE world\nsecond line\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin"}, strings.NewReader(in), &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, errBuf.String())
	}
	if out.String() != in {
		t.Errorf("echo = %q, want %q (M1 must not alter text)", out.String(), in)
	}
}

func TestPipedStdinAutoDetected(t *testing.T) {
	// A non-*os.File reader is treated as piped, so no --stdin needed.
	const in = "piped text"
	var out, errBuf bytes.Buffer
	code := run(nil, strings.NewReader(in), &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, errBuf.String())
	}
	if out.String() != in {
		t.Errorf("echo = %q, want %q", out.String(), in)
	}
}

func TestUnknownFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--frobnicate"}, strings.NewReader(""), &out, &errBuf)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "unknown flag") {
		t.Errorf("stderr = %q, want it to mention %q", errBuf.String(), "unknown flag")
	}
}

func TestHelpFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--help"}, strings.NewReader(""), &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "Usage:") {
		t.Errorf("help output = %q, want it to contain %q", out.String(), "Usage:")
	}
}
