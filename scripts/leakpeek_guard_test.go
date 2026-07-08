package scripts

// Integration tests for the leakpeek-guard pre-paste hook (issue #10).
//
// The guard is a POSIX-sh wrapper that frisks a prompt on stdin with leakpeek
// before handing it to an AI CLI, enforcing a block-or-redact policy. These
// tests drive the real script through /bin/sh with a real leakpeek binary,
// substituting a harmless inner command (usually `cat`) for the "AI CLI" so we
// can observe exactly what the guard would have sent it.
//
// They are skipped on Windows (the wrapper is /bin/sh) and whenever `sh` isn't
// on PATH, mirroring how the clipboard/vault tests skip on platforms that
// can't exercise the behavior. The Go CI matrix runs Linux + macOS, so the
// feature stays covered there.

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// guardScript resolves the path to the scripts/leakpeek-guard wrapper relative
// to this test file's directory (the test runs with its package dir as CWD).
func guardScript(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs("leakpeek-guard")
	if err != nil {
		t.Fatalf("resolving guard path: %v", err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("guard script not found at %s: %v", abs, err)
	}
	return abs
}

// buildLeakpeek compiles the leakpeek binary once per test run into a temp dir
// and returns its path. Building from source keeps the test hermetic — it
// exercises the guard against the exact code in the tree, not whatever happens
// to be installed on the machine.
func buildLeakpeek(t *testing.T) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("go toolchain not found; cannot build leakpeek for guard tests: %v", err)
	}
	bin := filepath.Join(t.TempDir(), "leakpeek")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	// The module root is the parent of this scripts/ directory.
	cmd := exec.Command(goBin, "build", "-o", bin, "./cmd/leakpeek")
	cmd.Dir = ".."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building leakpeek: %v\n%s", err, out)
	}
	return bin
}

// guardResult holds the outcome of one guard invocation.
type guardResult struct {
	stdout string
	stderr string
	code   int
}

// runGuard executes the guard via `sh <script> <args...>` with the given stdin,
// pointing LEAKPEEK_BIN at a freshly built binary. Extra env entries (KEY=VAL)
// can be appended. It returns captured stdout/stderr and the exit code.
func runGuard(t *testing.T, leakpeekBin, stdin string, args []string, extraEnv ...string) guardResult {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("sh not found; guard is a POSIX-sh wrapper: %v", err)
	}

	full := append([]string{guardScript(t)}, args...)
	cmd := exec.Command(sh, full...)
	cmd.Stdin = strings.NewReader(stdin)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	cmd.Env = append(os.Environ(), "LEAKPEEK_BIN="+leakpeekBin)
	cmd.Env = append(cmd.Env, extraEnv...)

	code := 0
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if !asExitError(err, &ee) {
			t.Fatalf("running guard: %v (stderr: %s)", err, errBuf.String())
		}
		code = ee.ExitCode()
	}
	return guardResult{stdout: outBuf.String(), stderr: errBuf.String(), code: code}
}

// asExitError is a tiny errors.As shim kept local so the test file has no extra
// imports beyond the standard set already used above.
func asExitError(err error, target **exec.ExitError) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		*target = ee
		return true
	}
	return false
}

func skipIfNoSh(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("leakpeek-guard is a POSIX-sh wrapper; not applicable on Windows")
	}
}

// A canonical secret used across the tests: the well-known AWS example key,
// which leakpeek's aws-access-key detector flags.
const secretPrompt = "deploy with AKIAIOSFODNN7EXAMPLE now"

// TestGuardCleanPromptPassesThrough verifies a clean prompt is forwarded to the
// inner command verbatim under the default (block) policy, exiting 0.
func TestGuardCleanPromptPassesThrough(t *testing.T) {
	skipIfNoSh(t)
	bin := buildLeakpeek(t)

	res := runGuard(t, bin, "tell me a joke about cats", []string{"--", "cat"})
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}
	if res.stdout != "tell me a joke about cats" {
		t.Errorf("inner command got %q, want the prompt unchanged", res.stdout)
	}
}

// TestGuardBlocksSecretsByDefault verifies the default policy refuses to run
// the inner command when a secret is present: nothing on stdout, exit 3, and a
// clear block message on stderr.
func TestGuardBlocksSecretsByDefault(t *testing.T) {
	skipIfNoSh(t)
	bin := buildLeakpeek(t)

	res := runGuard(t, bin, secretPrompt, []string{"--", "cat"})
	if res.code != 3 {
		t.Fatalf("exit = %d, want 3 (blocked); stderr: %s", res.code, res.stderr)
	}
	if strings.Contains(res.stdout, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("secret reached the inner command's stdin; stdout = %q", res.stdout)
	}
	if res.stdout != "" {
		t.Errorf("inner command should not have run; stdout = %q", res.stdout)
	}
	if !strings.Contains(res.stderr, "blocked") {
		t.Errorf("stderr = %q, want a 'blocked' explanation", res.stderr)
	}
}

// TestGuardRedactPolicySendsScrubbed verifies --policy redact hands the inner
// command a redacted prompt (no raw secret), while still exiting 0 so the AI
// call proceeds.
func TestGuardRedactPolicySendsScrubbed(t *testing.T) {
	skipIfNoSh(t)
	bin := buildLeakpeek(t)

	res := runGuard(t, bin, secretPrompt, []string{"--policy", "redact", "--", "cat"})
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", res.code, res.stderr)
	}
	if strings.Contains(res.stdout, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("raw secret leaked to inner command; stdout = %q", res.stdout)
	}
	if !strings.Contains(res.stdout, "REDACTED") {
		t.Errorf("expected a redacted marker in the forwarded prompt; stdout = %q", res.stdout)
	}
}

// TestGuardWarnPolicySendsOriginal verifies --policy warn forwards the original
// (unredacted) prompt but still surfaces a warning on stderr.
func TestGuardWarnPolicySendsOriginal(t *testing.T) {
	skipIfNoSh(t)
	bin := buildLeakpeek(t)

	res := runGuard(t, bin, secretPrompt, []string{"--policy", "warn", "--", "cat"})
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", res.code, res.stderr)
	}
	if res.stdout != secretPrompt {
		t.Errorf("warn policy should forward the original prompt; stdout = %q", res.stdout)
	}
	if !strings.Contains(res.stderr, "warn") {
		t.Errorf("stderr = %q, want a warning note", res.stderr)
	}
}

// TestGuardOffPolicyNeedsNoLeakpeek verifies --policy off forwards the prompt
// untouched and does not even require a working leakpeek binary.
func TestGuardOffPolicyNeedsNoLeakpeek(t *testing.T) {
	skipIfNoSh(t)

	res := runGuard(t, "/nonexistent/leakpeek", secretPrompt, []string{"--policy", "off", "--", "cat"})
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", res.code, res.stderr)
	}
	if res.stdout != secretPrompt {
		t.Errorf("off policy should forward the original prompt; stdout = %q", res.stdout)
	}
}

// TestGuardForwardsInnerCommandArgs verifies the guard preserves the inner
// command's own arguments (as with `-- ollama run llama3`).
func TestGuardForwardsInnerCommandArgs(t *testing.T) {
	skipIfNoSh(t)
	bin := buildLeakpeek(t)

	// `sh -c 'printf ARG=%s ...' _ marker` proves argv is passed through.
	res := runGuard(t, bin, "just a normal prompt",
		[]string{"--", "sh", "-c", `printf 'ARG=%s;' "$1"; cat`, "_", "marker"})
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", res.code, res.stderr)
	}
	if !strings.HasPrefix(res.stdout, "ARG=marker;") {
		t.Errorf("inner command args not forwarded; stdout = %q", res.stdout)
	}
	if !strings.HasSuffix(res.stdout, "just a normal prompt") {
		t.Errorf("prompt not forwarded on stdin; stdout = %q", res.stdout)
	}
}

// TestGuardMissingSeparatorIsUsageError verifies omitting `--` is a usage error
// (exit 2) rather than silently doing something surprising.
func TestGuardMissingSeparatorIsUsageError(t *testing.T) {
	skipIfNoSh(t)
	bin := buildLeakpeek(t)

	res := runGuard(t, bin, "hi", []string{"cat"})
	if res.code != 2 {
		t.Fatalf("exit = %d, want 2 (usage); stderr: %s", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "--") {
		t.Errorf("stderr = %q, want it to mention the missing '--'", res.stderr)
	}
}

// TestGuardUnknownPolicyIsUsageError verifies an invalid policy name is rejected
// before anything runs.
func TestGuardUnknownPolicyIsUsageError(t *testing.T) {
	skipIfNoSh(t)
	bin := buildLeakpeek(t)

	res := runGuard(t, bin, "hi", []string{"--policy", "nuke", "--", "cat"})
	if res.code != 2 {
		t.Fatalf("exit = %d, want 2 (usage); stderr: %s", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "policy") {
		t.Errorf("stderr = %q, want it to name the bad policy", res.stderr)
	}
}

// TestGuardHelpExitsClean verifies --help prints usage and exits 0 without
// needing stdin or an inner command.
func TestGuardHelpExitsClean(t *testing.T) {
	skipIfNoSh(t)

	res := runGuard(t, "/nonexistent/leakpeek", "", []string{"--help"})
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "pre-paste hook") {
		t.Errorf("help text missing; stdout = %q", res.stdout)
	}
}
