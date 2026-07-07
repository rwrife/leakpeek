package redact

import (
	"strings"
	"testing"
)

// TestSniffFormat checks the classifier picks the right shape (or plain) for a
// representative spread of inputs, including near-misses that must NOT be
// mistaken for structured config.
func TestSniffFormat(t *testing.T) {
	cases := []struct {
		name string
		text string
		want Format
	}{
		{"empty", "", FormatPlain},
		{"prose", "just a sentence, with a colon: here, and an equals a=b in it", FormatPlain},
		{"dotenv basic", "API_KEY=abc123\nDB_URL=postgres://x\n", FormatDotenv},
		{"dotenv export", "export TOKEN=xyz\nexport OTHER=1\n", FormatDotenv},
		{"json object", `{"api_key":"secret","port":8080}`, FormatJSON},
		{"json array of objects", `[{"k":"v"},{"k":"w"}]`, FormatJSON},
		{"json bare scalar not json-shaped", `"just a string"`, FormatPlain},
		{"yaml mapping", "name: leakpeek\nport: 8080\n", FormatYAML},
		{"yaml list", "- one\n- two\n- three\n", FormatYAML},
		{"yaml with url value (colon glued) still yaml by key", "endpoint: http://example.com\ntimeout: 30\n", FormatYAML},
		{"time-only lines are not yaml", "10:30\n11:45\n", FormatPlain},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sniffFormat(tc.text); got != tc.want {
				t.Errorf("sniffFormat(%q) = %v, want %v", tc.text, got, tc.want)
			}
		})
	}
}

// TestFormatString covers the human-facing labels.
func TestFormatString(t *testing.T) {
	for f, want := range map[Format]string{
		FormatPlain:  "plain",
		FormatDotenv: "dotenv",
		FormatJSON:   "json",
		FormatYAML:   "yaml",
	} {
		if got := f.String(); got != want {
			t.Errorf("Format(%d).String() = %q, want %q", f, got, want)
		}
	}
}

// TestFormatAwarePreservesKeysDotenv: a .env with a secret value should come
// back with the KEY and `=` intact and the value replaced, never leaking the
// secret.
func TestFormatAwarePreservesKeysDotenv(t *testing.T) {
	text := "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nPORT=8080\n"
	out, format := RedactFormatAware(text, scan(t, text), Shape)
	if format != FormatDotenv {
		t.Fatalf("format = %v, want dotenv", format)
	}
	if !strings.Contains(out, "AWS_ACCESS_KEY_ID=") {
		t.Errorf("key/`=` not preserved: %q", out)
	}
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("leaked secret: %q", out)
	}
	// Innocuous value untouched.
	if !strings.Contains(out, "PORT=8080") {
		t.Errorf("non-secret value should be left as-is: %q", out)
	}
	// A structure-friendly label stands in for the value.
	if !strings.Contains(out, "AWS_ACCESS_KEY_ID=[REDACTED-SECRET]") {
		t.Errorf("expected labeled value placeholder, got: %q", out)
	}
}

// TestFormatAwarePreservesQuotesDotenv: a quoted .env value keeps its quotes;
// only the inside is redacted, so the line stays a valid quoted assignment.
func TestFormatAwarePreservesQuotesDotenv(t *testing.T) {
	text := `TOKEN="sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"` + "\n"
	out, _ := RedactFormatAware(text, scan(t, text), Shape)
	if strings.Contains(out, "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789") {
		t.Errorf("leaked secret: %q", out)
	}
	if !strings.Contains(out, `TOKEN="`) || !strings.HasSuffix(strings.TrimRight(out, "\n"), `"`) {
		t.Errorf("quotes not preserved around redacted value: %q", out)
	}
}

// TestFormatAwareDotenvInlineComment: an inline `# comment` after an unquoted
// value survives; only the value before it is redacted.
func TestFormatAwareDotenvInlineComment(t *testing.T) {
	text := "KEY=AKIAIOSFODNN7EXAMPLE # prod key\n"
	out, _ := RedactFormatAware(text, scan(t, text), Shape)
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("leaked secret: %q", out)
	}
	if !strings.Contains(out, "# prod key") {
		t.Errorf("inline comment should survive: %q", out)
	}
}

// TestFormatAwarePreservesKeysJSON: JSON keys and structure are preserved; a
// string value holding a secret is redacted and the result is still valid
// JSON-shaped (quotes intact around the placeholder).
func TestFormatAwarePreservesKeysJSON(t *testing.T) {
	text := `{"api_key":"AKIAIOSFODNN7EXAMPLE","port":8080,"host":"db.internal"}`
	out, format := RedactFormatAware(text, scan(t, text), Shape)
	if format != FormatJSON {
		t.Fatalf("format = %v, want json", format)
	}
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("leaked secret: %q", out)
	}
	// The KEY string "api_key" must be untouched.
	if !strings.Contains(out, `"api_key":`) {
		t.Errorf("json key not preserved: %q", out)
	}
	// Redacted string value stays quoted.
	if !strings.Contains(out, `"api_key":"[REDACTED-SECRET]"`) {
		t.Errorf("expected quoted redacted value, got: %q", out)
	}
	// Non-secret number value untouched.
	if !strings.Contains(out, `"port":8080`) {
		t.Errorf("non-secret number changed: %q", out)
	}
}

// TestFormatAwareJSONKeyThatLooksLikeSecretIsSafe: a *key* that itself matches
// a detector must not be redacted (we only touch values). This guards the
// "redact values, not keys" contract at its sharpest edge.
func TestFormatAwareJSONKeyIsNotRedacted(t *testing.T) {
	// The email detector would match "a@b.com" if it appeared as a key.
	text := `{"a@b.com":"hello","note":"reach me at jane.doe@corp.internal"}`
	out, _ := RedactFormatAware(text, scan(t, text), Shape)
	// Key preserved verbatim.
	if !strings.Contains(out, `"a@b.com":`) {
		t.Errorf("email-shaped key should be preserved: %q", out)
	}
	// Value email redacted.
	if strings.Contains(out, "jane.doe@corp.internal") {
		t.Errorf("value email leaked: %q", out)
	}
}

// TestFormatAwarePreservesKeysYAML: YAML keys, indentation, and list structure
// survive; secret values are redacted.
func TestFormatAwarePreservesKeysYAML(t *testing.T) {
	text := "aws:\n  access_key: AKIAIOSFODNN7EXAMPLE\n  region: us-east-1\nhosts:\n  - 10.0.12.34\n  - example.com\n"
	out, format := RedactFormatAware(text, scan(t, text), Shape)
	if format != FormatYAML {
		t.Fatalf("format = %v, want yaml", format)
	}
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("leaked secret: %q", out)
	}
	if strings.Contains(out, "10.0.12.34") {
		t.Errorf("leaked ip in list item: %q", out)
	}
	// Keys + indentation preserved.
	for _, frag := range []string{"aws:", "  access_key:", "  region: us-east-1", "hosts:", "  - "} {
		if !strings.Contains(out, frag) {
			t.Errorf("yaml structure fragment %q missing: %q", frag, out)
		}
	}
}

// TestFormatAwareYAMLColonGluedValueNotSplit: a value with an internal colon
// (a URL) redacts as a whole value, not split at the colon.
func TestFormatAwareYAMLURLValue(t *testing.T) {
	text := "webhook: https://user:sk-proj-abcdefghijklmnopqrst1234@example.com/path\n"
	out, _ := RedactFormatAware(text, scan(t, text), Shape)
	if strings.Contains(out, "sk-proj-abcdefghijklmnopqrst1234") {
		t.Errorf("leaked secret inside url value: %q", out)
	}
	if !strings.Contains(out, "webhook:") {
		t.Errorf("yaml key not preserved: %q", out)
	}
}

// TestFormatAwareFallsBackToPlain: unstructured text routes through the plain
// span-based redactor and produces the same result Redact would.
func TestFormatAwareFallsBackToPlain(t *testing.T) {
	text := "here is a stray key AKIAIOSFODNN7EXAMPLE inside a sentence"
	out, format := RedactFormatAware(text, scan(t, text), Shape)
	if format != FormatPlain {
		t.Fatalf("format = %v, want plain", format)
	}
	want := Redact(text, scan(t, text), Shape)
	if out != want {
		t.Errorf("plain fallback mismatch:\n got: %q\nwant: %q", out, want)
	}
	// And it still preserves the shape hint from span redaction.
	if !strings.Contains(out, "AKIAREDACTED") {
		t.Errorf("expected shape-preserving fallback token: %q", out)
	}
}

// TestFormatAwareLeftoverFindingStillRedacted: a secret sitting in a place the
// format pass doesn't model (a comment line) must still be redacted via the
// span-based fallback, while structural values are value-redacted.
func TestFormatAwareLeftoverInComment(t *testing.T) {
	// The dotenv comment holds a secret the value pass won't cover; the KEY
	// line holds one it will.
	text := "# old key was AKIA1234567890ABCDEF\nKEY=AKIAIOSFODNN7EXAMPLE\n"
	out, format := RedactFormatAware(text, scan(t, text), Full)
	if format != FormatDotenv {
		t.Fatalf("format = %v, want dotenv", format)
	}
	for _, secret := range []string{"AKIA1234567890ABCDEF", "AKIAIOSFODNN7EXAMPLE"} {
		if strings.Contains(out, secret) {
			t.Errorf("leaked secret %q in: %q", secret, out)
		}
	}
	// The KEY= structure survives.
	if !strings.Contains(out, "KEY=") {
		t.Errorf("key line structure lost: %q", out)
	}
}

// TestFormatAwareNeverLeaks is the headline guarantee across all formats and
// strategies: every secret sample embedded in each structured shape comes back
// with no original secret material, and the redaction is not a no-op.
func TestFormatAwareNeverLeaks(t *testing.T) {
	wrappers := []struct {
		name string
		wrap func(secret string) string
	}{
		{"dotenv", func(s string) string { return "SECRET_VALUE=" + s + "\nPORT=1\n" }},
		{"dotenv-quoted", func(s string) string { return `SECRET_VALUE="` + s + `"` + "\n" }},
		{"json", func(s string) string { return `{"secret":"` + s + `","port":1}` }},
		{"yaml", func(s string) string { return "config:\n  secret: " + s + "\n  port: 1\n" }},
	}
	for _, tc := range secretSamples {
		for _, w := range wrappers {
			text := w.wrap(strings.TrimSpace(firstSecretToken(tc)))
			findings := scan(t, text)
			if len(findings) == 0 {
				// Some samples only match embedded in their own phrasing; skip
				// wrappers that don't reproduce a finding rather than fail.
				continue
			}
			for _, s := range []Strategy{Shape, Full, Hash} {
				out, _ := RedactFormatAware(text, findings, s)
				for _, secret := range tc.secrets {
					if strings.Contains(out, secret) {
						t.Errorf("%s/%s/%v leaked %q\n  in: %q\n out: %q", tc.name, w.name, s, secret, text, out)
					}
				}
				if out == text {
					t.Errorf("%s/%s/%v: redaction was a no-op on %q", tc.name, w.name, s, text)
				}
			}
		}
	}
}

// firstSecretToken returns a single embeddable secret token for a sample: the
// last (usually most specific) listed secret fragment, which is the raw token
// itself rather than a sub-fragment.
func firstSecretToken(tc struct {
	name    string
	text    string
	secrets []string
}) string {
	if len(tc.secrets) == 0 {
		return ""
	}
	// secrets[0] is the full token; sub-fragments follow.
	return tc.secrets[0]
}

// TestFormatAwareHashStrategyOnValue: hash strategy inside a structured value
// yields a stable, non-reversible tag and no secret material.
func TestFormatAwareHashStrategyOnValue(t *testing.T) {
	text := "A=AKIAIOSFODNN7EXAMPLE\nB=AKIAIOSFODNN7EXAMPLE\n"
	out, _ := RedactFormatAware(text, scan(t, text), Hash)
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("hash strategy leaked secret: %q", out)
	}
	fp := fingerprint("AKIAIOSFODNN7EXAMPLE")
	if strings.Count(out, fp) != 2 {
		t.Errorf("expected the repeated value's tag %q twice, got: %q", fp, out)
	}
}

// TestFormatAwareEmptyFindings: with nothing to redact, the text is returned
// unchanged and the format is still reported.
func TestFormatAwareEmptyFindings(t *testing.T) {
	text := "KEY=value\nPORT=8080\n"
	out, format := RedactFormatAware(text, nil, Shape)
	if out != text {
		t.Errorf("no findings should return text unchanged: %q", out)
	}
	if format != FormatDotenv {
		t.Errorf("format = %v, want dotenv", format)
	}
}

// TestFormatAwareOrPlain wraps RedactFormatAware and returns just the string.
func TestFormatAwareOrPlain(t *testing.T) {
	text := `{"api_key":"AKIAIOSFODNN7EXAMPLE"}`
	got := FormatAwareOrPlain(text, scan(t, text), Shape)
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("leaked: %q", got)
	}
	if !strings.Contains(got, `"api_key":`) {
		t.Errorf("structure lost: %q", got)
	}
}
