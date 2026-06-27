package detect

import "regexp"

// DefaultDetectors returns the v0.1 core secret pack in priority order.
//
// Order matters for de-duplication: when two detectors match the same span,
// the engine keeps the one registered first (after the longer-span rule).
// We therefore list the specific, high-confidence credential detectors
// before the broad generic-entropy catch-all, so a real AWS key is reported
// as "aws-access-key" rather than the generic "high-entropy-token".
func DefaultDetectors() []Detector {
	return []Detector{
		awsAccessKey,
		openAIKey,
		githubPAT,
		slackToken,
		jwt,
		privateKey,
		email,
		ipv4,
		highEntropyToken, // broad catch-all, registered last on purpose
	}
}

// regexDetector adapts a compiled regexp into a Detector. Most of the pack
// is "find all matches of this pattern", so we factor it out. An optional
// validate hook lets a detector reject matches the regex can't cheaply
// exclude (e.g. IPv4 octets > 255, or low-entropy generic tokens).
type regexDetector struct {
	name     string
	kind     Kind
	re       *regexp.Regexp
	validate func(match string) bool // nil ⇒ accept every regex match
}

func (d regexDetector) Name() string { return d.name }
func (d regexDetector) Kind() Kind   { return d.kind }

func (d regexDetector) Find(text string) []Finding {
	locs := d.re.FindAllStringIndex(text, -1)
	if locs == nil {
		return nil
	}
	out := make([]Finding, 0, len(locs))
	for _, loc := range locs {
		m := text[loc[0]:loc[1]]
		if d.validate != nil && !d.validate(m) {
			continue
		}
		out = append(out, Finding{Start: loc[0], End: loc[1], Match: m})
	}
	return out
}

// reEntry builds a regexDetector with no validation hook.
func reEntry(name string, kind Kind, pattern string) regexDetector {
	return regexDetector{name: name, kind: kind, re: regexp.MustCompile(pattern)}
}

// ---- The core pack ---------------------------------------------------------
//
// Patterns favor precision over recall for v0.1: we'd rather miss an exotic
// token than cry wolf on every base64 blob. \b anchors keep us from matching
// substrings inside longer identifiers. Detectors are package-level vars so
// their regexps compile exactly once at init.

var (
	// AWS access key IDs: AKIA/ASIA/AGPA/… + 16 uppercase-alnum chars.
	awsAccessKey = reEntry(
		"aws-access-key", KindSecret,
		`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16}\b`,
	)

	// OpenAI-style keys: sk- (optionally sk-proj-) then a long token. Length
	// kept generous to survive OpenAI's evolving key formats.
	openAIKey = reEntry(
		"openai-key", KindSecret,
		`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b`,
	)

	// GitHub personal access / app tokens: ghp_, gho_, ghu_, ghs_, ghr_, and
	// fine-grained github_pat_. The classic tokens are 36 base62 chars.
	githubPAT = reEntry(
		"github-pat", KindSecret,
		`\b(?:gh[posru]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b`,
	)

	// Slack tokens: xox[baprs]- followed by digit/hex groups.
	slackToken = reEntry(
		"slack-token", KindSecret,
		`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`,
	)

	// JSON Web Tokens: three base64url segments separated by dots. The header
	// segment realistically starts with eyJ (base64 of `{"`), which we anchor
	// on to avoid matching arbitrary dotted tokens.
	jwt = reEntry(
		"jwt", KindSecret,
		`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b`,
	)

	// Private-key headers (PEM / OpenSSH). Matching the BEGIN line is enough
	// to flag the block; the redactor (M4) will mask the body.
	privateKey = reEntry(
		"private-key", KindPrivateKey,
		`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----`,
	)

	// Email addresses: a pragmatic, non-RFC-perfect pattern that catches the
	// common shapes without melting on edge cases.
	email = reEntry(
		"email", KindPII,
		`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`,
	)
)

// ipv4 needs octet-range validation the regex alone can't express cheaply.
var ipv4 = regexDetector{
	name:     "ipv4",
	kind:     KindNetwork,
	re:       regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
	validate: validIPv4,
}

// highEntropyToken is the generic safety net: long, random-looking tokens
// that none of the specific detectors claimed. The entropy gate lives in the
// validate hook (looksHighEntropy) so prose and structured IDs slip through.
//
// The character class deliberately excludes '=' from a token's interior so we
// don't bridge an identifier into its value (e.g. KEY_ID=AKIA... must not
// match as one blob); '=' is allowed only as trailing base64 padding. Any
// real key this catches that also matches a specific detector loses to that
// detector during dedupe, because the specific match starts at or after the
// '=' while this one would have started earlier.
var highEntropyToken = regexDetector{
	name:     "high-entropy-token",
	kind:     KindEntropy,
	re:       regexp.MustCompile(`[A-Za-z0-9+/_-]{20,}={0,2}`),
	validate: looksHighEntropy,
}

// validIPv4 confirms each dotted octet is 0–255, rejecting things like
// 999.1.1.1 or version strings that pass the shape check.
func validIPv4(s string) bool {
	octet := 0
	seen := false // at least one digit in the current octet
	groups := 1
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' {
			if !seen || octet > 255 {
				return false
			}
			groups++
			octet, seen = 0, false
			continue
		}
		octet = octet*10 + int(c-'0')
		seen = true
		if octet > 255 {
			return false
		}
	}
	return groups == 4 && seen
}
