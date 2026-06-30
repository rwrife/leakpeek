package redact

import (
	"strings"
	"testing"

	"github.com/rwrife/leakpeek/internal/detect"
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
	for s, want := range map[Strategy]string{Shape: "shape", Full: "full", Hash: "hash"} {
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
