package clipboard

import (
	"strings"
	"testing"
)

func TestReadersForOS(t *testing.T) {
	cases := map[string]string{
		"darwin":  "pbpaste",
		"windows": "powershell",
		"linux":   "wl-paste",
	}
	for goos, wantFirst := range cases {
		readers := readersFor(goos)
		if len(readers) == 0 {
			t.Errorf("readersFor(%q) returned no candidates", goos)
			continue
		}
		if readers[0].name != wantFirst {
			t.Errorf("readersFor(%q)[0] = %q, want %q", goos, readers[0].name, wantFirst)
		}
	}
}

func TestStdinIsPipedNonFile(t *testing.T) {
	// Non-*os.File readers are always treated as piped.
	if !StdinIsPiped(strings.NewReader("x")) {
		t.Error("StdinIsPiped(strings.Reader) = false, want true")
	}
}
