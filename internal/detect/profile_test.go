package detect

import "testing"

// countEntropyHits scans text with the given profile and returns how many
// generic high-entropy-token findings it produced. Structured hits are
// ignored so the count isolates the entropy dial.
func countEntropyHits(t *testing.T, p EntropyProfile, text string) int {
	t.Helper()
	eng := DefaultProfile(p)
	n := 0
	for _, f := range eng.Scan(text) {
		if f.Kind == KindEntropy {
			n++
		}
	}
	return n
}

// A token that clears strict's entropy floor but not the default's, used to
// prove the dial actually moves. ~3.15 bits/byte, 24 chars, mixed case+digit:
// above strict's 3.0 floor, below default's 3.5 and chill's 4.0.
const midEntropyToken = "aA1bB2cC3aA1bB2cC3aA1bB2"

func TestEntropyProfileMovesSensitivity(t *testing.T) {
	text := "token=" + midEntropyToken + " end"

	strict := countEntropyHits(t, ProfileStrict, text)
	def := countEntropyHits(t, ProfileDefault, text)
	chill := countEntropyHits(t, ProfileChill, text)

	if !(strict >= def && def >= chill) {
		t.Fatalf("expected strict >= default >= chill hit counts, got strict=%d default=%d chill=%d",
			strict, def, chill)
	}
	if strict <= chill {
		t.Fatalf("expected strict to flag strictly MORE than chill on a mid-entropy token, got strict=%d chill=%d",
			strict, chill)
	}
}

func TestEntropyProfileDefaultUnchanged(t *testing.T) {
	// DefaultProfile(ProfileDefault) must be indistinguishable from Default()
	// across a spread of inputs: same behavior, no regression.
	inputs := []string{
		"nothing to see here, just words and prose",
		"AKIAIOSFODNN7EXAMPLE and sk-abcdefghijklmnop1234567890",
		"a high entropy blob dGhpcyBpcyBub3QgYSBzZWNyZXQgYnV0IGxvbmc",
		"ip 10.0.0.1 email a@b.com",
	}
	base := Default()
	prof := DefaultProfile(ProfileDefault)
	for _, in := range inputs {
		a := base.Scan(in)
		b := prof.Scan(in)
		if len(a) != len(b) {
			t.Fatalf("default profile diverged from Default() on %q: %d vs %d findings", in, len(a), len(b))
		}
		for i := range a {
			if a[i].Detector != b[i].Detector || a[i].Start != b[i].Start || a[i].End != b[i].End {
				t.Fatalf("finding %d mismatch on %q: %+v vs %+v", i, in, a[i], b[i])
			}
		}
	}
}

func TestStructuredDetectorsProfileInvariant(t *testing.T) {
	// Every structured (non-entropy) detector must produce identical findings
	// across all three profiles: a real key is a real key regardless of dial.
	text := "AKIAIOSFODNN7EXAMPLE sk-proj-abcdefghijklmnop1234567890 " +
		"ghp_012345678901234567890123456789012345 " +
		"eyJhbGciOi.eyJzdWIiOi.abcdef user@example.com 192.168.1.1"

	structured := func(fs []Finding) []Finding {
		var out []Finding
		for _, f := range fs {
			if f.Kind != KindEntropy {
				out = append(out, f)
			}
		}
		return out
	}

	ref := structured(DefaultProfile(ProfileDefault).Scan(text))
	for _, p := range []EntropyProfile{ProfileStrict, ProfileChill} {
		got := structured(DefaultProfile(p).Scan(text))
		if len(got) != len(ref) {
			t.Fatalf("structured finding count changed under profile %+v: %d vs %d", p, len(got), len(ref))
		}
		for i := range ref {
			if got[i].Detector != ref[i].Detector || got[i].Start != ref[i].Start || got[i].End != ref[i].End {
				t.Fatalf("structured finding %d changed under profile %+v: %+v vs %+v", i, p, got[i], ref[i])
			}
		}
	}
}
