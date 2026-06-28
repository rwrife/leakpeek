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

// looksHighEntropy reports whether tok is long enough and random enough to
// be a credential rather than an ordinary word. The thresholds are tuned for
// the v0.1 generic-token detector: short or low-entropy strings are rejected
// to keep false positives down (PLAN.md §8 adds tunable profiles later).
//
// Plain English defeats a naive entropy gate (a 25-letter run of distinct
// lowercase words can score ~4.2 bits), so we add a cheap character-class
// test: real keys mix alphabets (upper+lower) or include digits/symbols,
// whereas prose tokens are almost always a single case of letters. A token
// drawn from just one letter case with no digits is treated as a word.
func looksHighEntropy(tok string) bool {
	const (
		minLen     = 20  // shorter tokens are too noisy to flag generically
		minEntropy = 3.5 // bits/byte; prose sits below this, keys above
	)
	if len(tok) < minLen {
		return false
	}
	if !mixedAlphabet(tok) {
		return false // looks like a single-case word run, not a key
	}
	return ShannonEntropy(tok) >= minEntropy
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
