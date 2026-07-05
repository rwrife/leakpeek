package vault

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestPlaceholderRoundTrip is the headline guarantee: a secret turned into a
// placeholder can be turned back, and the placeholder itself leaks nothing.
func TestPlaceholderRoundTrip(t *testing.T) {
	v := New()
	secret := "AKIAIOSFODNN7EXAMPLE"
	p := v.Placeholder(secret)

	if p == "" {
		t.Fatal("Placeholder returned empty for a non-empty secret")
	}
	if strings.Contains(p, secret) {
		t.Errorf("placeholder %q leaks the secret", p)
	}
	if !strings.HasPrefix(p, placeholderPrefix) || !strings.HasSuffix(p, placeholderSuffix) {
		t.Errorf("placeholder %q not in expected [LEAKPEEK:…] shape", p)
	}

	text := "before " + p + " after"
	got, n := v.Restore(text)
	if n != 1 {
		t.Errorf("Restore count = %d, want 1", n)
	}
	if got != "before "+secret+" after" {
		t.Errorf("Restore = %q, want the secret spliced back", got)
	}
}

// TestPlaceholderStablePerSecret: the same secret always yields the same
// placeholder (so a reader can see two spots share a value), and distinct
// secrets get distinct placeholders.
func TestPlaceholderStablePerSecret(t *testing.T) {
	v := New()
	a1 := v.Placeholder("secret-one")
	a2 := v.Placeholder("secret-one")
	b := v.Placeholder("secret-two")

	if a1 != a2 {
		t.Errorf("same secret produced different placeholders: %q vs %q", a1, a2)
	}
	if a1 == b {
		t.Errorf("distinct secrets collided on placeholder %q", a1)
	}
	if v.Len() != 2 {
		t.Errorf("Len = %d, want 2 distinct secrets", v.Len())
	}
}

// TestPlaceholderEmptySecret: an empty secret is never stored or tokenized.
func TestPlaceholderEmptySecret(t *testing.T) {
	v := New()
	if p := v.Placeholder(""); p != "" {
		t.Errorf("Placeholder(\"\") = %q, want empty", p)
	}
	if !v.Empty() {
		t.Error("empty secret should not populate the vault")
	}
}

// TestRestoreRepeatedAndUnknown: repeated placeholders are all restored, and
// unknown placeholders (or plain text) pass through untouched.
func TestRestoreRepeatedAndUnknown(t *testing.T) {
	v := New()
	p := v.Placeholder("sekret")

	text := p + " and again " + p + " but [LEAKPEEK:deadbeef] is unknown"
	got, n := v.Restore(text)
	if n != 2 {
		t.Errorf("Restore count = %d, want 2 (the two known placeholders)", n)
	}
	if strings.Count(got, "sekret") != 2 {
		t.Errorf("expected the secret twice in %q", got)
	}
	if !strings.Contains(got, "[LEAKPEEK:deadbeef]") {
		t.Errorf("unknown placeholder should survive untouched: %q", got)
	}
}

// TestRestoreEmptyVault: restoring against an empty vault is a no-op.
func TestRestoreEmptyVault(t *testing.T) {
	v := New()
	text := "nothing [LEAKPEEK:abc123] here"
	got, n := v.Restore(text)
	if n != 0 || got != text {
		t.Errorf("empty-vault Restore changed text: got %q n=%d", got, n)
	}
}

// TestLooksLikePlaceholder recognizes the token shape and rejects non-matches.
func TestLooksLikePlaceholder(t *testing.T) {
	cases := map[string]bool{
		"here is [LEAKPEEK:ab12cd34] token": true,
		"[LEAKPEEK:x]":                      true,
		"no tokens here at all":             false,
		"[LEAKPEEK: unterminated":           false, // no closing ]
		"":                                  false,
	}
	for in, want := range cases {
		if got := LooksLikePlaceholder(in); got != want {
			t.Errorf("LooksLikePlaceholder(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestSaveLoadRoundTrip: a saved session reloads with the same mappings, so a
// later process can un-redact what an earlier one redacted.
func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	v := New()
	p := v.Placeholder("top-secret-value")

	if err := v.Save(dir); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, n := loaded.Restore("x " + p + " y")
	if n != 1 || got != "x top-secret-value y" {
		t.Errorf("reloaded Restore = %q n=%d, want the secret back", got, n)
	}
}

// TestSaveEmptyIsNoOp: saving an empty vault writes no file, so we never leave
// an empty secret-store on disk.
func TestSaveEmptyIsNoOp(t *testing.T) {
	dir := t.TempDir()
	v := New()
	if err := v.Save(dir); err != nil {
		t.Fatalf("Save(empty): %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, sessionFile)); !os.IsNotExist(err) {
		t.Errorf("empty Save should not create a session file (stat err=%v)", err)
	}
}

// TestSaveFilePerms: the persisted session must be owner-only (0600). Secrets
// live in it while it exists.
func TestSaveFilePerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file mode not meaningful on Windows")
	}
	dir := t.TempDir()
	v := New()
	v.Placeholder("secret")
	if err := v.Save(dir); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, sessionFile))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != filePerm {
		t.Errorf("session file perm = %o, want %o", perm, filePerm)
	}
}

// TestLoadNoSession returns the benign sentinel when nothing was saved.
func TestLoadNoSession(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); !errors.Is(err, ErrNoSession) {
		t.Errorf("Load(empty dir) err = %v, want ErrNoSession", err)
	}
}

// TestLoadExpired: a session older than its TTL is refused and removed.
func TestLoadExpired(t *testing.T) {
	dir := t.TempDir()
	v := New()
	v.Placeholder("secret")
	v.ttl = time.Second                    // tight TTL for the test
	v.created = time.Now().Add(-time.Hour) // already stale
	if err := v.Save(dir); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if _, err := Load(dir); !errors.Is(err, ErrExpired) {
		t.Errorf("Load(stale) err = %v, want ErrExpired", err)
	}
	// And the stale file must have been wiped as a side effect.
	if _, err := os.Stat(filepath.Join(dir, sessionFile)); !os.IsNotExist(err) {
		t.Errorf("expired session file should be removed; stat err=%v", err)
	}
}

// TestClear removes a saved session and reports whether one existed.
func TestClear(t *testing.T) {
	dir := t.TempDir()

	// Nothing to clear yet.
	removed, err := Clear(dir)
	if err != nil || removed {
		t.Errorf("Clear(empty) = (%v,%v), want (false,nil)", removed, err)
	}

	v := New()
	v.Placeholder("secret")
	if err := v.Save(dir); err != nil {
		t.Fatalf("Save: %v", err)
	}
	removed, err = Clear(dir)
	if err != nil || !removed {
		t.Errorf("Clear(existing) = (%v,%v), want (true,nil)", removed, err)
	}
	if _, err := os.Stat(filepath.Join(dir, sessionFile)); !os.IsNotExist(err) {
		t.Errorf("session file should be gone after Clear; stat err=%v", err)
	}
}

// TestDefaultDir points under the OS temp dir, keeping sessions disposable.
func TestDefaultDir(t *testing.T) {
	got := DefaultDir()
	if !strings.HasPrefix(got, os.TempDir()) {
		t.Errorf("DefaultDir = %q, want it under TempDir %q", got, os.TempDir())
	}
	if filepath.Base(got) != "leakpeek" {
		t.Errorf("DefaultDir base = %q, want \"leakpeek\"", filepath.Base(got))
	}
}

// TestLoadCorruptSession surfaces a decode error rather than pretending the
// session is empty.
func TestLoadCorruptSession(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, sessionFile), []byte("{not json"), filePerm); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := Load(dir)
	if err == nil || errors.Is(err, ErrNoSession) || errors.Is(err, ErrExpired) {
		t.Errorf("Load(corrupt) err = %v, want a decode error", err)
	}
}
