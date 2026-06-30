package clipboard

import (
	"errors"
	"testing"
)

func TestWritersForOS(t *testing.T) {
	cases := map[string]string{
		"darwin":  "pbcopy",
		"windows": "clip",
		"linux":   "wl-copy",
	}
	for goos, wantFirst := range cases {
		writers := writersFor(goos)
		if len(writers) == 0 {
			t.Errorf("writersFor(%q) returned no candidates", goos)
			continue
		}
		if writers[0].name != wantFirst {
			t.Errorf("writersFor(%q)[0] = %q, want %q", goos, writers[0].name, wantFirst)
		}
	}
}

// TestWriteNoToolErrors verifies Write reports a clear, wrapped error when no
// clipboard utility is on PATH. We empty PATH so exec.LookPath fails for every
// candidate, then assert the error chains ErrNoClipboardTool (so callers can
// detect the "no tool" condition) and steers the user toward --stdin.
func TestWriteNoToolErrors(t *testing.T) {
	t.Setenv("PATH", "") // no executables discoverable

	err := Write("anything")
	if err == nil {
		t.Fatal("Write with empty PATH returned nil error, want a no-tool error")
	}
	if !errors.Is(err, ErrNoClipboardTool) {
		t.Errorf("Write error = %v, want it to wrap ErrNoClipboardTool", err)
	}
}

// TestWriteCandidatesAreNonEmpty guards the per-OS mapping: every supported
// platform must offer at least one clipboard-write tool so Write can degrade
// to a clear error rather than an index panic. The end-to-end pipe (stdin →
// tool) is covered by the cmd-level --fix tests that run the real binary.
func TestWriteCandidatesAreNonEmpty(t *testing.T) {
	for _, goos := range []string{"darwin", "windows", "linux", "freebsd"} {
		if len(writersFor(goos)) == 0 {
			t.Errorf("writersFor(%q) is empty; every OS needs at least one writer", goos)
		}
	}
}
