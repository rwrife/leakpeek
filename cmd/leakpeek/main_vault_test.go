package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rwrife/leakpeek/internal/vault"
)

// isolateVault points vault.DefaultDir() at a throwaway temp dir for the test
// by overriding TMPDIR (which os.TempDir honors on Linux/macOS). It returns
// the resolved vault dir. This keeps the reversible-session tests hermetic:
// they never touch a real user's temp session, and they can run in parallel.
//
// On platforms where os.TempDir ignores TMPDIR we skip, since these tests are
// about the CLI wiring, which the vault package's own tests already cover
// portably.
func isolateVault(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	if !strings.HasPrefix(vault.DefaultDir(), dir) {
		t.Skip("os.TempDir does not honor TMPDIR on this platform; covered by vault package tests")
	}
	return vault.DefaultDir()
}

// TestVaultRedactUnredactRoundTrip is the end-to-end reversible flow through
// the CLI: redact with --strategy vault (persisting a session), then simulate
// the AI echoing the placeholders and un-redact them back to the originals.
func TestVaultRedactUnredactRoundTrip(t *testing.T) {
	vaultDir := isolateVault(t)

	const in = "here is my key AKIAIOSFODNN7EXAMPLE and email jane.doe@corp.internal\n"

	// Step 1: reversible redaction. Piped input → redacted text on stdout.
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--fix", "--strategy", "vault", "--quiet"},
		strings.NewReader(in), &out, &errBuf)
	if code != exitFound {
		t.Fatalf("redact exit = %d, want %d; stderr=%q", code, exitFound, errBuf.String())
	}
	redacted := out.String()
	if strings.Contains(redacted, "AKIAIOSFODNN7EXAMPLE") || strings.Contains(redacted, "jane.doe") {
		t.Fatalf("vault redaction leaked a secret: %q", redacted)
	}
	if !strings.Contains(redacted, "[LEAKPEEK:") {
		t.Fatalf("vault redaction produced no placeholder: %q", redacted)
	}
	// A session file must now exist.
	if _, err := os.Stat(filepath.Join(vaultDir, "session.json")); err != nil {
		t.Fatalf("expected a persisted session, stat err=%v", err)
	}

	// Step 2: the AI "replies" with the redacted text (placeholders intact).
	// Un-redact should restore the originals. Because clearing is the default,
	// the session should be gone afterward.
	var out2, err2 bytes.Buffer
	code = run([]string{"--stdin", "--unredact"}, strings.NewReader(redacted), &out2, &err2)
	if code != exitClean {
		t.Fatalf("unredact exit = %d, want %d; stderr=%q", code, exitClean, err2.String())
	}
	restored := out2.String()
	if restored != in {
		t.Errorf("unredact restored = %q, want original %q", restored, in)
	}
	if !strings.Contains(err2.String(), "Restored") {
		t.Errorf("unredact stderr = %q, want a restore confirmation", err2.String())
	}
	// Default lifecycle clears the session after a successful restore.
	if _, err := os.Stat(filepath.Join(vaultDir, "session.json")); !os.IsNotExist(err) {
		t.Errorf("session should be cleared after unredact; stat err=%v", err)
	}
}

// TestVaultNoVaultSkipsPersistence: --no-vault redacts reversibly-shaped
// placeholders but stores nothing, so a later --unredact has nothing to do.
func TestVaultNoVaultSkipsPersistence(t *testing.T) {
	vaultDir := isolateVault(t)

	const in = "key AKIAIOSFODNN7EXAMPLE\n"
	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--fix", "--strategy", "vault", "--no-vault", "--quiet"},
		strings.NewReader(in), &out, &errBuf)
	if code != exitFound {
		t.Fatalf("redact exit = %d, want %d", code, exitFound)
	}
	if _, err := os.Stat(filepath.Join(vaultDir, "session.json")); !os.IsNotExist(err) {
		t.Errorf("--no-vault should not persist a session; stat err=%v", err)
	}
}

// TestUnredactNoSession reports the benign "nothing to restore" case and exits
// clean rather than erroring.
func TestUnredactNoSession(t *testing.T) {
	isolateVault(t)

	var out, errBuf bytes.Buffer
	code := run([]string{"--stdin", "--unredact"},
		strings.NewReader("some [LEAKPEEK:deadbeef] text"), &out, &errBuf)
	if code != exitClean {
		t.Fatalf("unredact(no session) exit = %d, want %d", code, exitClean)
	}
	if !strings.Contains(errBuf.String(), "no reversible-redaction session") {
		t.Errorf("stderr = %q, want a no-session explanation", errBuf.String())
	}
}

// TestVaultClearRemovesSession: --vault-clear wipes a saved session.
func TestVaultClearRemovesSession(t *testing.T) {
	vaultDir := isolateVault(t)

	// Seed a session via a reversible redaction.
	var out, errBuf bytes.Buffer
	if code := run([]string{"--stdin", "--fix", "--strategy", "vault", "--quiet"},
		strings.NewReader("key AKIAIOSFODNN7EXAMPLE\n"), &out, &errBuf); code != exitFound {
		t.Fatalf("seed redact exit = %d, want %d", code, exitFound)
	}
	if _, err := os.Stat(filepath.Join(vaultDir, "session.json")); err != nil {
		t.Fatalf("expected a session to clear, stat err=%v", err)
	}

	var cOut, cErr bytes.Buffer
	code := run([]string{"--vault-clear"}, strings.NewReader(""), &cOut, &cErr)
	if code != exitClean {
		t.Fatalf("vault-clear exit = %d, want %d", code, exitClean)
	}
	if !strings.Contains(cOut.String(), "cleared") {
		t.Errorf("vault-clear stdout = %q, want a cleared confirmation", cOut.String())
	}
	if _, err := os.Stat(filepath.Join(vaultDir, "session.json")); !os.IsNotExist(err) {
		t.Errorf("session should be gone after --vault-clear; stat err=%v", err)
	}
}

// TestVaultClearWhenEmpty is a friendly no-op.
func TestVaultClearWhenEmpty(t *testing.T) {
	isolateVault(t)
	var out, errBuf bytes.Buffer
	code := run([]string{"--vault-clear"}, strings.NewReader(""), &out, &errBuf)
	if code != exitClean {
		t.Fatalf("vault-clear(empty) exit = %d, want %d", code, exitClean)
	}
	if !strings.Contains(out.String(), "No reversible-redaction session") {
		t.Errorf("vault-clear(empty) stdout = %q, want a nothing-to-clear note", out.String())
	}
}

// TestUnredactKeepVaultRetainsSession: --keep-vault leaves the session in
// place so it can be reused for a second un-redaction.
func TestUnredactKeepVaultRetainsSession(t *testing.T) {
	vaultDir := isolateVault(t)

	const in = "key AKIAIOSFODNN7EXAMPLE\n"
	var out, errBuf bytes.Buffer
	if code := run([]string{"--stdin", "--fix", "--strategy", "vault", "--quiet"},
		strings.NewReader(in), &out, &errBuf); code != exitFound {
		t.Fatalf("seed redact exit = %d, want %d", code, exitFound)
	}
	redacted := out.String()

	var out2, err2 bytes.Buffer
	code := run([]string{"--stdin", "--unredact", "--keep-vault"},
		strings.NewReader(redacted), &out2, &err2)
	if code != exitClean {
		t.Fatalf("unredact --keep-vault exit = %d, want %d", code, exitClean)
	}
	if out2.String() != in {
		t.Errorf("restored = %q, want %q", out2.String(), in)
	}
	// Session must still be present for a second pass.
	if _, err := os.Stat(filepath.Join(vaultDir, "session.json")); err != nil {
		t.Errorf("--keep-vault should retain the session; stat err=%v", err)
	}
	// Second un-redaction still works.
	var out3, err3 bytes.Buffer
	if code := run([]string{"--stdin", "--unredact", "--keep-vault"},
		strings.NewReader(redacted), &out3, &err3); code != exitClean {
		t.Fatalf("second unredact exit = %d, want %d", code, exitClean)
	}
	if out3.String() != in {
		t.Errorf("second restore = %q, want %q", out3.String(), in)
	}
}

// TestUnredactNoPlaceholders: a session exists but the pasted text has none of
// its placeholders — report it gently, don't error, and leave the session.
func TestUnredactNoPlaceholders(t *testing.T) {
	isolateVault(t)

	var out, errBuf bytes.Buffer
	if code := run([]string{"--stdin", "--fix", "--strategy", "vault", "--quiet"},
		strings.NewReader("key AKIAIOSFODNN7EXAMPLE\n"), &out, &errBuf); code != exitFound {
		t.Fatalf("seed redact exit = %d, want %d", code, exitFound)
	}

	var out2, err2 bytes.Buffer
	code := run([]string{"--stdin", "--unredact"},
		strings.NewReader("the AI replied with no placeholders\n"), &out2, &err2)
	if code != exitClean {
		t.Fatalf("unredact(no placeholders) exit = %d, want %d", code, exitClean)
	}
	if !strings.Contains(err2.String(), "nothing to un-redact") {
		t.Errorf("stderr = %q, want a nothing-to-un-redact note", err2.String())
	}
}

// TestVaultStrategyInUsage: the help text advertises the vault strategy and
// the un-redact flow so the feature is discoverable.
func TestVaultStrategyInUsage(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--help"}, strings.NewReader(""), &out, &errBuf)
	if code != exitClean {
		t.Fatalf("--help exit = %d, want %d", code, exitClean)
	}
	for _, want := range []string{"--unredact", "--vault-clear", "vault"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("help text missing %q", want)
		}
	}
}
