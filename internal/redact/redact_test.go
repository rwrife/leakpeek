package redact

import (
	"strings"
	"testing"

	"github.com/rwrife/leakpeek/internal/detect"
	"github.com/rwrife/leakpeek/internal/vault"
)

// scan is a tiny helper: run the default engine over text and return the
// findings, so redact tests exercise the same input the real CLI sees.
func scan(t *testing.T, text string) []detect.Finding {
	t.Helper()
	return detect.Default().Scan(text)
}

func TestParseStrategy(t *testing.T) {
	cases := map[string]struct {
		want Strategy
		ok   bool
	}{
		"":       {Shape, true},
		"shape":  {Shape, true},
		"SHAPE":  {Shape, true},
		" full ": {Full, true},
		"full":   {Full, true},
		"hash":   {Hash, true},
		"Hash":   {Hash, true},
		"vault":  {Vault, true},
		"VAULT":  {Vault, true},
		"bogus":  {Shape, false},
	}
	for in, want := range cases {
		got, ok := ParseStrategy(in)
		if got != want.want || ok != want.ok {
			t.Errorf("ParseStrategy(%q) = (%v,%v), want (%v,%v)", in, got, ok, want.want, want.ok)
		}
	}
}

func TestStrategyString(t *testing.T) {
	for s, want := range map[Strategy]string{Shape: "shape", Full: "full", Hash: "hash", Vault: "vault"} {
		if got := s.String(); got != want {
			t.Errorf("Strategy(%d).String() = %q, want %q", s, got, want)
		}
	}
}

// TestRedactEmptyAndClean: no findings ⇒ text returned unchanged.
func TestRedactEmptyAndClean(t *testing.T) {
	text := "just some perfectly innocent prose with no secrets in it at all"
	for _, s := range []Strategy{Shape, Full, Hash} {
		if got := Redact(text, nil, s); got != text {
			t.Errorf("Redact(clean, nil, %v) changed text: %q", s, got)
		}
		if got := Redact(text, scan(t, text), s); got != text {
			t.Errorf("Redact(clean, scan, %v) changed text: %q", s, got)
		}
	}
}

// secretSamples are realistic-shaped (synthetic) secrets, one per detector,
// embedded in surrounding text. The substrings we must never see in output
// are listed alongside so every strategy can be checked for leaks.
var secretSamples = []struct {
	name    string
	text    string
	secrets []string // raw fragments that must be ABSENT from any redaction
}{
	{
		"aws",
		"export AWS_KEY=AKIAIOSFODNN7EXAMPLE done",
		[]string{"AKIAIOSFODNN7EXAMPLE", "IOSFODNN7EXAMPLE"},
	},
	{
		"openai",
		"token: sk-proj-abcdefghijklmnopqrstuvwxyz0123456789",
		[]string{"sk-proj-abcdefghijklmnopqrstuvwxyz0123456789", "abcdefghijklmnopqrstuvwxyz0123456789"},
	},
	{
		"github",
		"GH=ghp_0123456789abcdefghijklmnopqrstuvwxyz tail",
		[]string{"ghp_0123456789abcdefghijklmnopqrstuvwxyz", "0123456789abcdefghijklmnopqrstuvwxyz"},
	},
	{
		"slack",
		"slack xoxb-EXAMPLE-PLACEHOLDER-TOKEN now",
		[]string{"xoxb-EXAMPLE-PLACEHOLDER-TOKEN", "EXAMPLE-PLACEHOLDER-TOKEN"},
	},
	{
		"jwt",
		"auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dummysignature123 end",
		[]string{"eyJzdWIiOiIxMjM0NTY3ODkwIn0", "dummysignature123"},
	},
	{
		"email",
		"contact jane.doe@corp.internal for help",
		[]string{"jane.doe", "jane.doe@corp.internal"},
	},
	{
		"ipv4",
		"host 10.0.12.34 is internal",
		[]string{"10.0.12.34", "0.12.34"},
	},
	{
		// Card: the last four legitimately survive (receipt convention), so the
		// forbidden fragments are the leading digits only.
		"credit-card",
		"pay 4012 8888 8888 1881 now",
		[]string{"4012 8888 8888", "40128888", "888818"},
	},
	{
		"iban",
		"send to DE89370400440532013000 please",
		[]string{"DE89370400440532013000", "370400440532013000"},
	},
	{
		"ssn",
		"ssn 078-05-1120 on file",
		[]string{"078-05-1120", "078051120"},
	},
	{
		"phone",
		"call +1 202-555-0100 today",
		[]string{"202-555-0100", "2025550100"},
	},
}

// TestRedactNeverLeaks is the headline guarantee: for every detector and
// every strategy, the redacted output contains none of the original secret
// material. This is the contract M4's definition-of-done hangs on.
func TestRedactNeverLeaks(t *testing.T) {
	for _, tc := range secretSamples {
		findings := scan(t, tc.text)
		if len(findings) == 0 {
			t.Fatalf("%s: sample produced no findings; fixture is wrong: %q", tc.name, tc.text)
		}
		for _, s := range []Strategy{Shape, Full, Hash} {
			out := Redact(tc.text, findings, s)
			for _, secret := range tc.secrets {
				if strings.Contains(out, secret) {
					t.Errorf("%s/%v: redacted output leaked %q\n  out: %q", tc.name, s, secret, out)
				}
			}
			if out == tc.text {
				t.Errorf("%s/%v: redaction was a no-op", tc.name, s)
			}
		}
	}
}

// TestShapePreservesHints checks the friendly half of the contract: shape
// mode keeps a recognizable scheme so the AI still understands the token's
// kind, even though the secret itself is gone.
func TestShapePreservesHints(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string // substring expected in the shape-redacted output
	}{
		{"aws", "k=AKIAIOSFODNN7EXAMPLE", "AKIAREDACTED"},
		{"openai", "k=sk-proj-abcdefghijklmnopqrstuvwxyz0123", "sk-proj-REDACTED"},
		{"github", "k=ghp_0123456789abcdefghijklmnopqrstuvwxyz", "ghp_REDACTED"},
		{"slack", "k=xoxb-EXAMPLE-PLACEHOLDER-TOKEN", "xoxb-REDACTED"},
		{"email", "m=jane.doe@corp.internal", "REDACTED@corp.internal"},
		{"ipv4", "ip=10.0.12.34", "x.x.x.x"},
		{"card", "pay 4012 8888 8888 1881 now", "1881"},
	}
	for _, tc := range cases {
		out := Redact(tc.text, scan(t, tc.text), Shape)
		if !strings.Contains(out, tc.want) {
			t.Errorf("%s: shape redaction = %q, want it to contain %q", tc.name, out, tc.want)
		}
	}
}

// TestFullStrategyLabels confirms Full uses the kind label and reveals no
// scheme hint (e.g. no "sk-" survives).
func TestFullStrategyLabels(t *testing.T) {
	text := "k=sk-proj-abcdefghijklmnopqrstuvwxyz0123"
	out := Redact(text, scan(t, text), Full)
	if !strings.Contains(out, "[REDACTED-SECRET]") {
		t.Errorf("Full: want [REDACTED-SECRET] in %q", out)
	}
	if strings.Contains(out, "sk-") {
		t.Errorf("Full: leaked scheme hint sk- in %q", out)
	}
}

// TestHashIsStableAndScoped: identical secrets hash to the same tag (so a
// reader can correlate repeats) and different secrets differ. The tag must
// not contain the secret.
func TestHashIsStableAndScoped(t *testing.T) {
	// Same AWS key twice, plus a different one.
	text := "a=AKIAIOSFODNN7EXAMPLE b=AKIAIOSFODNN7EXAMPLE c=AKIA1234567890ABCDEF"
	out := Redact(text, scan(t, text), Hash)

	fpDup := fingerprint("AKIAIOSFODNN7EXAMPLE")
	fpOther := fingerprint("AKIA1234567890ABCDEF")
	if fpDup == fpOther {
		t.Fatalf("distinct secrets collided on fingerprint %q", fpDup)
	}
	if strings.Count(out, fpDup) != 2 {
		t.Errorf("Hash: expected the repeated secret's tag %q twice in %q", fpDup, out)
	}
	if !strings.Contains(out, fpOther) {
		t.Errorf("Hash: expected the other secret's tag %q in %q", fpOther, out)
	}
	if len(fpDup) != 8 {
		t.Errorf("fingerprint length = %d, want 8", len(fpDup))
	}
}

// TestRedactPreservesSurroundingText: only the spans change; the bytes
// around each finding are byte-for-byte preserved, including a trailing
// segment after the last finding.
func TestRedactPreservesSurroundingText(t *testing.T) {
	text := "before AKIAIOSFODNN7EXAMPLE middle 10.0.12.34 after"
	out := Redact(text, scan(t, text), Full)
	for _, frag := range []string{"before ", " middle ", " after"} {
		if !strings.Contains(out, frag) {
			t.Errorf("surrounding fragment %q missing from %q", frag, out)
		}
	}
}

// TestRedactMultibyteSafe: byte-offset splicing must not corrupt multibyte
// runes sitting next to a finding. We put an emoji and accented text right
// against the secret and confirm they survive intact.
func TestRedactMultibyteSafe(t *testing.T) {
	text := "café 🔐 AKIAIOSFODNN7EXAMPLE — naïve"
	out := Redact(text, scan(t, text), Full)
	for _, frag := range []string{"café 🔐 ", " — naïve"} {
		if !strings.Contains(out, frag) {
			t.Errorf("multibyte context %q missing/corrupted in %q", frag, out)
		}
	}
	if !strings.Contains(out, "[REDACTED-SECRET]") {
		t.Errorf("expected redaction marker in %q", out)
	}
}

// TestRedactHandlesOverlappingDefensively: even if a caller passes raw,
// overlapping findings (the engine normally de-dupes), Redact must not panic
// or double-splice — it skips the overlap and still removes the secret.
func TestRedactHandlesOverlappingDefensively(t *testing.T) {
	text := "k=AKIAIOSFODNN7EXAMPLE"
	// Hand-build two overlapping findings over the same key span.
	base := detect.Finding{
		Detector: "aws-access-key", Kind: detect.KindSecret,
		Start: 2, End: len(text), Match: text[2:],
	}
	overlap := detect.Finding{
		Detector: "high-entropy-token", Kind: detect.KindEntropy,
		Start: 6, End: len(text), Match: text[6:],
	}
	out := Redact(text, []detect.Finding{base, overlap}, Full)
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("overlap case leaked the secret: %q", out)
	}
	if strings.Count(out, "[REDACTED") != 1 {
		t.Errorf("overlap case should splice once, got: %q", out)
	}
}

// TestRedactPrivateKeyHeader: the private-key header is replaced with a safe,
// same-shaped marker and never echoes the matched BEGIN line verbatim beyond
// the generic placeholder.
func TestRedactPrivateKeyHeader(t *testing.T) {
	text := "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJB...\n-----END RSA PRIVATE KEY-----"
	out := Redact(text, scan(t, text), Shape)
	if strings.Contains(out, "BEGIN RSA PRIVATE KEY") {
		t.Errorf("shape redaction kept the specific RSA header: %q", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("expected a [REDACTED] marker for the key header: %q", out)
	}
}

// TestRedactWithVaultRoundTrips is the reversible strategy's headline: the
// redacted text leaks no secret material, yet the recorded vault can restore
// the exact original from the redacted text.
func TestRedactWithVaultRoundTrips(t *testing.T) {
	for _, tc := range secretSamples {
		findings := scan(t, tc.text)
		if len(findings) == 0 {
			t.Fatalf("%s: sample produced no findings: %q", tc.name, tc.text)
		}
		v := vault.New()
		redacted := RedactWithVault(tc.text, findings, v)

		// No secret material may survive in the redacted text.
		for _, secret := range tc.secrets {
			if strings.Contains(redacted, secret) {
				t.Errorf("%s: vault redaction leaked %q\n  out: %q", tc.name, secret, redacted)
			}
		}
		if redacted == tc.text {
			t.Errorf("%s: vault redaction was a no-op", tc.name)
		}

		// Restoring the redacted text must reproduce the original byte-for-byte.
		restored, n := v.Restore(redacted)
		if n == 0 {
			t.Errorf("%s: Restore found no placeholders to reverse", tc.name)
		}
		if restored != tc.text {
			t.Errorf("%s: round-trip mismatch\n  got:  %q\n  want: %q", tc.name, restored, tc.text)
		}
	}
}

// TestRedactWithVaultEmptyAndNil: no findings, or a nil vault, returns text
// unchanged rather than panicking.
func TestRedactWithVaultEmptyAndNil(t *testing.T) {
	text := "perfectly innocent prose"
	if got := RedactWithVault(text, nil, vault.New()); got != text {
		t.Errorf("no-findings vault redaction changed text: %q", got)
	}
	if got := RedactWithVault(text, scan(t, text), nil); got != text {
		t.Errorf("nil-vault redaction changed text: %q", got)
	}
}

// TestRedactWithVaultDedupesRepeats: the same secret appearing twice yields
// the same placeholder both times (one mapping), so the vault stays compact
// and a reader can see the two spots share a value.
func TestRedactWithVaultDedupesRepeats(t *testing.T) {
	text := "a=AKIAIOSFODNN7EXAMPLE b=AKIAIOSFODNN7EXAMPLE"
	v := vault.New()
	redacted := RedactWithVault(text, scan(t, text), v)
	if v.Len() != 1 {
		t.Errorf("repeated secret should yield 1 mapping, got %d", v.Len())
	}
	// The placeholder should appear twice in the redacted output.
	if strings.Contains(redacted, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("vault redaction leaked the repeated secret: %q", redacted)
	}
	restored, n := v.Restore(redacted)
	if n != 2 || restored != text {
		t.Errorf("round-trip of repeated secret failed: got %q n=%d", restored, n)
	}
}

// TestVaultStrategyViaReplacementFallsBackSafely: if the Vault strategy ever
// reaches the pure Redact path (which has no vault), it must fall back to a
// non-reversible redaction rather than echo the secret.
func TestVaultStrategyViaReplacementFallsBackSafely(t *testing.T) {
	text := "k=AKIAIOSFODNN7EXAMPLE"
	out := Redact(text, scan(t, text), Vault)
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("Vault-through-Redact leaked the secret: %q", out)
	}
	if !strings.Contains(out, "[REDACTED-") {
		t.Errorf("Vault-through-Redact should fall back to a full redaction: %q", out)
	}
}
