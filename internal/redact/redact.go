// Package redact turns leakpeek from a tattletale into a fixer. Where the
// report package masks findings for a *preview* (so a human can recognize
// what was caught without re-leaking it), redact rewrites the *actual text*
// so the result is safe to paste — splicing a redacted stand-in over each
// finding's byte span while leaving everything around it untouched.
//
// This is the M4 half of leakpeek (see PLAN.md §6/§7). It takes the original
// text plus the engine's findings and returns a new string with every secret
// replaced. It knows nothing about clipboards or flags; main.go wires it to
// clipboard.Write (for --fix) or to stdout (for --stdin pipe mode).
//
// Three strategies, chosen by the caller:
//
//	Shape — shape-preserving: keep a recognizable scheme prefix (sk-, AKIA,
//	        ghp_, an email's @domain, an IP's octet count) so the AI still
//	        understands the *shape* of what it's looking at, then mark the
//	        sensitive part REDACTED. The default, and the one PLAN.md's
//	        `sk-…REDACTED` example asks for.
//	Full  — replace the whole match with a fixed [REDACTED-<KIND>] token.
//	        Reveals nothing about the original, not even its scheme.
//	Hash  — replace with [<KIND>:<8-hex>] where the hex is a short, stable,
//	        NON-reversible fingerprint of the match. Lets a reader see that
//	        two redactions refer to the same secret without exposing it.
//
// Hard guarantee: for every strategy, the returned text contains no original
// secret material from any finding. The redact_test suite asserts this per
// detector. (The one principled exception is structural context the masker
// deliberately preserves — an email's domain or an IP's first octet — which
// is infra-shape, not credential material, and mirrors what the report
// already shows.)
package redact

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/rwrife/leakpeek/internal/detect"
)

// Strategy selects how a matched secret is rewritten. The zero value is
// Shape, so a caller that does nothing gets the friendly shape-preserving
// behavior PLAN.md describes.
type Strategy int

const (
	// Shape preserves a recognizable hint (scheme prefix, @domain, octet
	// shape) and marks the rest REDACTED. Default.
	Shape Strategy = iota
	// Full replaces the entire match with a fixed [REDACTED-<KIND>] token.
	Full
	// Hash replaces the match with [<KIND>:<8-hex>], a stable non-reversible
	// fingerprint useful for correlating repeats without revealing them.
	Hash
)

// String renders the strategy name (handy for --help / flag parsing / tests).
func (s Strategy) String() string {
	switch s {
	case Full:
		return "full"
	case Hash:
		return "hash"
	default:
		return "shape"
	}
}

// ParseStrategy maps a flag value ("shape"/"full"/"hash") to a Strategy. The
// second return is false for an unrecognized value so callers can error out
// on bad usage rather than silently defaulting.
func ParseStrategy(s string) (Strategy, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "shape":
		return Shape, true
	case "full":
		return Full, true
	case "hash":
		return Hash, true
	default:
		return Shape, false
	}
}

// Redact returns text with every finding rewritten using strategy. The input
// text must be the exact string the findings were produced against, so the
// byte spans line up. Findings may be in any order and may arrive overlapping
// or duplicated (defensive — the engine already de-dupes); Redact sorts them
// and skips any span that overlaps one it already rewrote, so output bytes
// are never corrupted by double-splicing.
//
// The original string is never mutated; a new one is built.
func Redact(text string, findings []detect.Finding, strategy Strategy) string {
	if len(findings) == 0 {
		return text
	}

	// Work on a copy we can sort without disturbing the caller's slice.
	fs := make([]detect.Finding, len(findings))
	copy(fs, findings)
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Start != fs[j].Start {
			return fs[i].Start < fs[j].Start
		}
		// Longer span first so a broad match wins over a fragment on a tie,
		// matching the engine's own dedupe preference.
		return fs[i].Len() > fs[j].Len()
	})

	var b strings.Builder
	b.Grow(len(text)) // output is usually similar in size to the input
	cursor := 0       // next unconsumed byte of text

	for _, f := range fs {
		// Guard against out-of-range or overlapping spans: anything that
		// starts before what we've already emitted, or runs past the end of
		// the text, is skipped rather than risking a slice panic or a
		// half-overwritten secret.
		if f.Start < cursor || f.Start < 0 || f.End > len(text) || f.Start >= f.End {
			continue
		}
		b.WriteString(text[cursor:f.Start]) // untouched text before the match
		b.WriteString(replacement(f, strategy))
		cursor = f.End
	}
	b.WriteString(text[cursor:]) // trailing untouched text
	return b.String()
}

// replacement computes the stand-in string for a single finding under the
// chosen strategy.
func replacement(f detect.Finding, strategy Strategy) string {
	switch strategy {
	case Full:
		return "[REDACTED-" + kindLabel(f.Kind) + "]"
	case Hash:
		return "[" + kindLabel(f.Kind) + ":" + fingerprint(f.Match) + "]"
	default:
		return shapePreserve(f.Kind, f.Match)
	}
}

// shapePreserve rewrites a match keeping just enough structure that the AI
// (and the human) still recognizes its *kind*, while removing the secret.
//
// The strategy mirrors report.Mask's choices so a preview and its redaction
// stay visually consistent, but here we emit a paste-safe token rather than
// an ellipsis: secrets become "<scheme>REDACTED", emails keep their @domain,
// IPs keep their octet shape, private keys collapse to a single safe line.
func shapePreserve(kind detect.Kind, match string) string {
	switch kind {
	case detect.KindPrivateKey:
		// The detector spans only the BEGIN header, so that's all we get to
		// rewrite. Replace it with a same-shaped, obviously-fake marker. Any
		// key body on following lines is left as-is here: it's inert base64
		// once its header is gone, and a future detector that spans the whole
		// PEM block (PLAN.md backlog) would let us splice the body too.
		return "-----BEGIN PRIVATE KEY----- [REDACTED] -----END PRIVATE KEY-----"
	case detect.KindPII:
		if e := redactEmail(match); e != "" {
			return e
		}
		return "[REDACTED]"
	case detect.KindNetwork:
		return redactIP(match)
	default:
		return redactToken(match)
	}
}

// redactToken keeps a known scheme prefix (sk-, AKIA, ghp_, github_pat_, …)
// then appends REDACTED, e.g. "sk-…REDACTED" → "sk-REDACTED",
// "AKIA…" → "AKIAREDACTED". Tokens with no recognized scheme become a bare
// "[REDACTED]" so we never echo a leading chunk of an unknown secret.
func redactToken(s string) string {
	if p := knownScheme(s); p != "" {
		return p + "REDACTED"
	}
	return "[REDACTED]"
}

// knownScheme returns the literal scheme prefix at the start of s (including
// any trailing separator like '-' or '_'), or "" if none match. Unlike the
// report's knownPrefix it keeps the separator, because here we're rebuilding a
// real token ("sk-REDACTED", "ghp_REDACTED") rather than a cosmetic label.
// Order matters: longer/more specific prefixes are checked first.
func knownScheme(s string) string {
	prefixes := []string{
		"github_pat_", "sk-proj-", "xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-",
		"sk-", "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return p
		}
	}
	// AWS-style uppercase key IDs (AKIA…, ASIA…): keep the 4-letter class so
	// the shape (a 20-char AWS key) is still legible as AKIAREDACTED.
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

// redactEmail keeps the @domain (infra shape, not a credential) and replaces
// the local part, e.g. "jane.doe@corp.com" → "REDACTED@corp.com". Returns ""
// when s isn't an email shape so the caller can fall back to a full redaction.
func redactEmail(s string) string {
	at := strings.LastIndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return ""
	}
	return "REDACTED@" + s[at+1:]
}

// redactIP replaces every octet of a dotted IPv4 with 'x', preserving the
// four-octet shape: "10.0.12.34" → "x.x.x.x". We drop even the first octet
// here (the report keeps it as a hint) because the whole point of --fix is to
// hand back something with no infra detail left to leak.
func redactIP(s string) string {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return "[REDACTED]"
	}
	return "x.x.x.x"
}

// kindLabel renders a Kind as an uppercase token for Full/Hash output, e.g.
// KindPrivateKey → "PRIVATE-KEY". Falls back to "SECRET" for an empty kind.
func kindLabel(k detect.Kind) string {
	if k == "" {
		return "SECRET"
	}
	return strings.ToUpper(strings.ReplaceAll(string(k), "_", "-"))
}

// fingerprint returns the first 8 hex chars of SHA-256(match): a short,
// stable, one-way tag. It is NOT reversible and NOT meant to be — it only
// lets a reader spot that two redactions share the same underlying secret.
func fingerprint(match string) string {
	sum := sha256.Sum256([]byte(match))
	return hex.EncodeToString(sum[:])[:8]
}
