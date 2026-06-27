package detect

import (
	"math"
	"testing"
)

func TestShannonEntropy(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want float64 // exact where known; otherwise checked via bounds below
		// when exact is false we only assert lo <= entropy <= hi.
		exact  bool
		lo, hi float64
	}{
		{name: "empty", in: "", want: 0, exact: true},
		{name: "single-symbol", in: "aaaaaaaa", want: 0, exact: true},
		// Two equally-likely symbols ⇒ exactly 1 bit/byte.
		{name: "two-symbols-balanced", in: "abababab", want: 1, exact: true},
		// Four equally-likely symbols ⇒ exactly 2 bits/byte.
		{name: "four-symbols-balanced", in: "abcdabcd", want: 2, exact: true},
		// English-ish prose: low-ish entropy, comfortably under the key gate.
		{name: "prose", in: "the quick brown fox", lo: 2.5, hi: 4.0},
		// A random base64-looking token: high entropy, above the gate.
		{name: "random-token", in: "aB3xZ9qLמ", lo: 2.0, hi: 8.0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ShannonEntropy(tc.in)
			if tc.exact {
				if math.Abs(got-tc.want) > 1e-9 {
					t.Errorf("ShannonEntropy(%q) = %v, want %v", tc.in, got, tc.want)
				}
				return
			}
			if got < tc.lo || got > tc.hi {
				t.Errorf("ShannonEntropy(%q) = %v, want in [%v, %v]", tc.in, got, tc.lo, tc.hi)
			}
		})
	}
}

func TestLooksHighEntropy(t *testing.T) {
	cases := []struct {
		name string
		tok  string
		want bool
	}{
		{name: "short-random-rejected", tok: "aB3xZ9", want: false},
		{name: "long-prose-rejected", tok: "aaaaaaaaaaaaaaaaaaaaaaaa", want: false},
		{name: "long-random-accepted", tok: "wJalrXUtnFEMI7K8MDENGbPxRfiCYEXAMPLEKEY", want: true},
		{name: "english-words-rejected", tok: "thequickbrownfoxjumpsover", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksHighEntropy(tc.tok); got != tc.want {
				t.Errorf("looksHighEntropy(%q) = %v, want %v (entropy=%.3f, len=%d)",
					tc.tok, got, tc.want, ShannonEntropy(tc.tok), len(tc.tok))
			}
		})
	}
}

// TestHighEntropyDetector_FindsGenericSecret ensures the catch-all flags a
// long random token that no specific detector would claim (e.g. an AWS
// *secret* access key, which has no fixed prefix).
func TestHighEntropyDetector_FindsGenericSecret(t *testing.T) {
	const secret = "wJalrXUtnFEMI7K8MDENGbPxRfiCYEXAMPLEKEY"
	text := "AWS_SECRET_ACCESS_KEY=" + secret + " and that's it"
	got := highEntropyToken.Find(text)
	if !containsMatch(got, secret) {
		t.Errorf("high-entropy detector missed %q; got %v", secret, matches(got))
	}
}
