package report

import (
	"strings"

	"github.com/rwrife/leakpeek/internal/detect"
)

// Mask produces a short, paste-safe preview of a matched secret for the
// report. The whole point of the report is to warn you WITHOUT re-printing the
// thing you're trying not to leak, so every strategy keeps just enough context
// to recognize the finding (its shape / a couple of edge characters) and
// replaces the sensitive middle with an ellipsis.
//
// Strategies are chosen by Kind, with a couple of detector-shape special cases
// the kind alone can't capture (a known key prefix, an email's @domain). This
// is preview masking only; the shape-preserving clipboard redaction that M4
// writes back lives in its own package.
func Mask(kind detect.Kind, match string) string {
	switch kind {
	case detect.KindPrivateKey:
		// Never echo key material; the BEGIN line is identification enough.
		return "-----BEGIN PRIVATE KEY----- […]"
	case detect.KindPII:
		if e := maskEmail(match); e != "" {
			return e
		}
		return keepEnds(match, 1, 0)
	case detect.KindNetwork:
		// IPs aren't secret like a key, but they're still infra you may not
		// want to share; reveal the first octet only.
		return maskIP(match)
	default:
		// secrets / entropy tokens: keep a recognizable prefix (incl. known
		// key schemes like sk-/AKIA) and the last few chars.
		return maskToken(match)
	}
}

// maskToken keeps a leading hint and a short tail, masking the middle. For
// tokens with a well-known scheme prefix (sk-, sk-proj-, AKIA…, ghp_, xoxb-,
// github_pat_) we preserve the prefix so the reader instantly knows the type;
// otherwise we keep the first few characters.
func maskToken(s string) string {
	if s == "" {
		return ""
	}
	if p := knownPrefix(s); p != "" {
		return p + "…" + tail(s, 4)
	}
	// Short tokens: don't reveal much. Keep 2 lead + 2 tail when long enough.
	if len(s) <= 8 {
		return keepEnds(s, 1, 1)
	}
	return keepEnds(s, 4, 4)
}

// knownPrefix returns a recognizable scheme prefix of s, or "" if none match.
// Order matters: longer/more specific prefixes are checked first.
func knownPrefix(s string) string {
	prefixes := []string{
		"github_pat_", "sk-proj-", "xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-",
		"sk-", "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return strings.TrimSuffix(p, "-") // drop trailing '-' so we render "sk…" cleanly
		}
	}
	// AWS-style uppercase key IDs (AKIA…, ASIA…): keep the 4-letter class.
	if len(s) >= 4 && isAWSPrefix(s[:4]) {
		return s[:4]
	}
	return ""
}

func isAWSPrefix(p string) bool {
	switch p {
	case "AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ABIA", "ACCA":
		return true
	}
	return false
}

// maskEmail reveals the first character of the local part and the full domain,
// e.g. "jane.doe@example.com" → "j…@example.com". Returns "" if s isn't an
// email shape so the caller can fall back.
func maskEmail(s string) string {
	at := strings.LastIndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return ""
	}
	local, domain := s[:at], s[at+1:]
	lead := local[:1]
	return lead + "…@" + domain
}

// maskIP reveals only the first octet of a dotted IPv4 address:
// "10.0.12.34" → "10.x.x.x".
func maskIP(s string) string {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return keepEnds(s, 1, 0)
	}
	return parts[0] + ".x.x.x"
}

// keepEnds keeps lead leading and tailN trailing runes, joining with an
// ellipsis when anything is hidden. Operates on runes so multibyte input
// isn't sliced mid-character.
func keepEnds(s string, lead, tailN int) string {
	r := []rune(s)
	if lead+tailN >= len(r) {
		return s
	}
	head := string(r[:lead])
	t := ""
	if tailN > 0 {
		t = string(r[len(r)-tailN:])
	}
	return head + "…" + t
}

// tail returns the last n runes of s (or all of s if shorter).
func tail(s string, n int) string {
	r := []rune(s)
	if n >= len(r) {
		return s
	}
	return string(r[len(r)-n:])
}
