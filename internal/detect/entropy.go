package detect

import "math"

// ShannonEntropy returns the Shannon entropy of s in bits per byte, on a
// scale of 0 (all one symbol) to 8 (uniform over all byte values). It is the
// classic measure leakpeek uses to tell a random-looking token (high
// entropy) from English prose or a structured identifier (lower entropy).
//
// The empty string has entropy 0 by definition.
func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	// Frequency of each distinct byte. Operating on bytes (not runes) keeps
	// this allocation-light and is the right granularity for the ASCII-ish
	// tokens we care about (base64/hex keys).
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}

	n := float64(len(s))
	var bits float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		bits -= p * math.Log2(p)
	}
	return bits
}

// EntropyProfile bundles the two tunable knobs of the generic high-entropy
// token gate: the minimum token length and the minimum Shannon entropy (in
// bits per byte) a token must clear to be flagged as a random-looking
// credential. Lower values are more sensitive (more hits, more false
// positives); higher values are calmer (fewer hits). See PLAN.md §8.
type EntropyProfile struct {
	MinLen         int     // shorter tokens are never flagged generically
	MinBitsPerChar float64 // bits/byte the token must reach to count
}

// The three named sensitivity presets exposed via --strict / --chill and the
// default (no flag). ProfileDefault MUST hold the historical production
// values so existing behavior — and every existing fixture test — is
// byte-for-byte unchanged. strict lowers both dials (flags more); chill
// raises both (flags fewer).
var (
	// ProfileStrict is the paranoid preset: catch more, tolerate more noise.
	ProfileStrict = EntropyProfile{MinLen: 16, MinBitsPerChar: 3.0}
	// ProfileDefault is the unchanged v0.1 production tuning.
	ProfileDefault = EntropyProfile{MinLen: 20, MinBitsPerChar: 3.5}
	// ProfileChill is the relaxed preset: fewer interruptions.
	ProfileChill = EntropyProfile{MinLen: 28, MinBitsPerChar: 4.0}
)

// accepts reports whether tok clears this profile's length + entropy gate,
// applying the same character-class sanity check the default gate always has
// (see looksHighEntropy). It is the profile-aware core the entropy detector
// uses; looksHighEntropy is the default-profile shorthand kept for callers
// and tests that predate profiles.
func (p EntropyProfile) accepts(tok string) bool {
	if len(tok) < p.MinLen {
		return false
	}
	if !mixedAlphabet(tok) {
		return false // looks like a single-case word run, not a key
	}
	return ShannonEntropy(tok) >= p.MinBitsPerChar
}

// looksHighEntropy reports whether tok is long enough and random enough to
// be a credential rather than an ordinary word, using the DEFAULT profile.
// It is preserved as the zero-config entry point so the default detector and
// existing tests keep their exact behavior.
//
// Plain English defeats a naive entropy gate (a 25-letter run of distinct
// lowercase words can score ~4.2 bits), so we add a cheap character-class
// test: real keys mix alphabets (upper+lower) or include digits/symbols,
// whereas prose tokens are almost always a single case of letters. A token
// drawn from just one letter case with no digits is treated as a word.
func looksHighEntropy(tok string) bool {
	return ProfileDefault.accepts(tok)
}

// mixedAlphabet reports whether tok draws from more than one obvious symbol
// class (lowercase, uppercase, digit, or other). A run of only lowercase
// letters — the shape of concatenated English — returns false; anything that
// mixes case or includes a digit/symbol returns true.
func mixedAlphabet(tok string) bool {
	var hasLower, hasUpper, hasDigit, hasOther bool
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		switch {
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= '0' && c <= '9':
			hasDigit = true
		default:
			hasOther = true
		}
	}
	classes := 0
	for _, present := range []bool{hasLower, hasUpper, hasDigit, hasOther} {
		if present {
			classes++
		}
	}
	return classes >= 2
}
