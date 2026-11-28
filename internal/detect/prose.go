package detect

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	secretAssignment = regexp.MustCompile(`(?i)\b(?:api[_ -]?key|access[_ -]?key|secret(?:[_ -]?key)?|token|password|passwd|passphrase|credential|authorization)\b[^:=\r\n]{0,20}[:=]\s*(?:bearer\s+)?$`)
	secretLanguage   = regexp.MustCompile(`(?i)\b(?:password|passphrase|secret|token|credential|api[-_ ]?key|private key|authorization)\b`)
)

func isEncodedProse(token, source string, start int) bool {
	decoded, ok := decodeBase64(token)
	if !ok || !looksLikeEnglishProse(decoded) || hasSecretAssignment(source, start) {
		return false
	}
	if secretLanguage.Match(decoded) {
		return false
	}
	sensitiveDetectors := []Detector{
		awsAccessKey, openAIKey, githubPAT, slackToken, jwt, privateKey, email, ipv4,
	}
	sensitiveDetectors = append(sensitiveDetectors, DefaultPIIDetectors()...)
	for _, detector := range sensitiveDetectors {
		if len(detector.Find(string(decoded))) > 0 {
			return false
		}
	}
	for _, loc := range highEntropyTokenPattern.FindAllStringIndex(string(decoded), -1) {
		if ProfileDefault.accepts(string(decoded[loc[0]:loc[1]])) {
			return false
		}
	}
	return true
}

func decodeBase64(token string) ([]byte, bool) {
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if decoded, err := encoding.DecodeString(token); err == nil {
			return decoded, true
		}
	}
	return nil, false
}

func hasSecretAssignment(source string, start int) bool {
	lineStart := strings.LastIndexAny(source[:start], "\r\n") + 1
	return secretAssignment.MatchString(source[lineStart:start])
}

func looksLikeEnglishProse(text []byte) bool {
	if !utf8.Valid(text) || len(text) < 24 {
		return false
	}
	for _, c := range text {
		if c < 0x20 && c != '\n' && c != '\r' && c != '\t' || c > 0x7e {
			return false
		}
	}
	words := strings.FieldsFunc(string(text), func(r rune) bool {
		return !isASCIIAlpha(r)
	})
	if len(words) < 4 {
		return false
	}
	common := map[string]bool{
		"a": true, "an": true, "and": true, "are": true, "as": true,
		"be": true, "but": true, "by": true, "can": true, "for": true,
		"from": true, "has": true, "have": true, "he": true, "her": true,
		"in": true, "is": true, "it": true, "of": true, "on": true,
		"or": true, "our": true, "that": true, "the": true, "their": true,
		"this": true, "to": true, "was": true, "we": true, "with": true,
		"you": true,
	}
	letters, vowels, commonWords := 0, 0, 0
	for _, word := range words {
		if len(word) > 16 {
			return false
		}
		for i := 0; i < len(word); i++ {
			c := word[i]
			letters++
			if strings.ContainsRune("aeiou", rune(c|0x20)) {
				vowels++
			}
		}
		if common[strings.ToLower(word)] {
			commonWords++
		}
	}
	return letters >= 20 && commonWords >= 2 && float64(vowels)/float64(letters) >= 0.12
}

func isASCIIAlpha(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
}
