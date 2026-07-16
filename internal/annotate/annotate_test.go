package annotate

import (
	"strings"
	"testing"

	"github.com/rwrife/leakpeek/internal/detect"
)

func f(k detect.Kind) detect.Finding { return detect.Finding{Kind: k} }

func TestSummaryEmpty(t *testing.T) {
	if got := Summary(nil); got != "" {
		t.Errorf("Summary(nil) = %q, want empty", got)
	}
}

func TestSummaryGroupsAndPluralizes(t *testing.T) {
	findings := []detect.Finding{
		f(detect.KindSecret), f(detect.KindSecret),
		f(detect.KindPII),
	}
	got := Summary(findings)
	if got != "2 API keys, 1 email" {
		t.Errorf("Summary = %q, want %q", got, "2 API keys, 1 email")
	}
}

func TestSummaryStableOrder(t *testing.T) {
	// Kinds provided out of display order should still render in the stable
	// order (secret, private-key, pii, payment, network, entropy).
	findings := []detect.Finding{
		f(detect.KindNetwork),
		f(detect.KindSecret),
		f(detect.KindEntropy),
		f(detect.KindPII),
	}
	got := Summary(findings)
	want := "1 API key, 1 email, 1 network address, 1 high-entropy token"
	if got != want {
		t.Errorf("Summary = %q, want %q", got, want)
	}
}

func TestSummaryUnknownKindFallsBack(t *testing.T) {
	got := Summary([]detect.Finding{{Kind: detect.Kind("mystery")}})
	if got != "1 mystery" {
		t.Errorf("Summary = %q, want %q", got, "1 mystery")
	}
}

func TestFooterPlain(t *testing.T) {
	got := Footer([]detect.Finding{f(detect.KindSecret)}, false)
	if got != "[leakpeek: redacted 1 API key]" {
		t.Errorf("Footer = %q", got)
	}
}

func TestFooterReversible(t *testing.T) {
	got := Footer([]detect.Finding{f(detect.KindSecret), f(detect.KindPII)}, true)
	if !strings.HasPrefix(got, "[leakpeek: reversibly redacted 1 API key, 1 email") {
		t.Errorf("Footer = %q, missing reversible prefix", got)
	}
	if !strings.Contains(got, "--unredact") {
		t.Errorf("Footer = %q, want restore hint", got)
	}
}

func TestFooterEmpty(t *testing.T) {
	if got := Footer(nil, false); got != "" {
		t.Errorf("Footer(nil) = %q, want empty", got)
	}
}

// The footer must never contain matched values — only kinds and counts.
func TestFooterNeverLeaksValue(t *testing.T) {
	findings := []detect.Finding{
		{Kind: detect.KindSecret, Match: "AKIAIOSFODNN7EXAMPLE"},
		{Kind: detect.KindPII, Match: "jane.doe@corp.internal"},
	}
	got := Footer(findings, false)
	for _, secret := range []string{"AKIAIOSFODNN7EXAMPLE", "jane.doe"} {
		if strings.Contains(got, secret) {
			t.Errorf("Footer leaked %q: %q", secret, got)
		}
	}
}
