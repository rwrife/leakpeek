//go:build !windows

package diff

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSnapshotRefusesUnsafePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := Save(dir, "secret", time.Now()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "snapshot.json")
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot permission = %v, %v", info, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, time.Now()); err == nil {
		t.Fatal("accepted readable snapshot")
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Save(dir, "must not write", time.Now()); err == nil {
		t.Fatal("saved in shared directory")
	}
	if _, err := Load(dir, time.Now()); err == nil {
		t.Fatal("read from shared directory")
	}
}
