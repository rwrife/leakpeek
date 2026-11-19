package diff

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSnapshotLifecycle(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	now := time.Now().UTC()
	s, err := Load(dir, now)
	if err != nil || s != nil {
		t.Fatalf("missing snapshot = %v, %v", s, err)
	}
	if err := Save(dir, "sensitive input", now); err != nil {
		t.Fatal(err)
	}
	s, err = Load(dir, now.Add(time.Second))
	if err != nil || s == nil || s.Text != "sensitive input" || !s.Created.Equal(now) {
		t.Fatalf("load = %v, %v", s, err)
	}
	if err := Save(dir, "", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	s, err = Load(dir, now.Add(time.Second))
	if err != nil || s == nil || s.Text != "" {
		t.Fatalf("empty replacement = %v, %v", s, err)
	}
	for i := 0; i < 2; i++ {
		if err := Clear(dir); err != nil {
			t.Fatal(err)
		}
	}
	if s, err := Load(dir, now); err != nil || s != nil {
		t.Fatalf("cleared load = %v, %v", s, err)
	}
}

func TestSnapshotExpiry(t *testing.T) {
	for _, age := range []time.Duration{TTL, TTL + time.Second, -time.Second} {
		t.Run(age.String(), func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "private")
			now := time.Now()
			if err := Save(dir, "secret", now.Add(-age)); err != nil {
				t.Fatal(err)
			}
			if s, err := Load(dir, now); s != nil || !errors.Is(err, ErrExpired) {
				t.Fatalf("expired load = %v, %v", s, err)
			}
			if _, err := os.Stat(filepath.Join(dir, "snapshot.json")); !os.IsNotExist(err) {
				t.Fatalf("expired snapshot not wiped: %v", err)
			}
		})
	}
}

func TestSnapshotRejectsCorruptAndLinkedFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := Save(dir, "secret", time.Now()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "snapshot.json")
	if err := os.WriteFile(path, []byte("PRIVATE-CONTENT"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, time.Now()); err == nil || strings.Contains(err.Error(), "PRIVATE-CONTENT") {
		t.Fatalf("corrupt snapshot diagnostic = %v", err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("do not modify"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Clear(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := Load(dir, time.Now()); err == nil {
		t.Fatal("accepted linked snapshot")
	}
	if err := Clear(dir); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "do not modify" {
		t.Fatalf("clear touched symlink target: %q, %v", data, err)
	}
}
