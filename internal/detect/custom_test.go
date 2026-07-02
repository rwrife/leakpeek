package detect

import "testing"

func TestParseKind(t *testing.T) {
	cases := []struct {
		in       string
		wantKind Kind
		wantOK   bool
	}{
		{"", KindSecret, true},         // empty defaults to secret
		{"   ", KindSecret, true},      // whitespace-only too
		{"secret", KindSecret, true},   //
		{"NETWORK", KindNetwork, true}, // case-insensitive
		{" pii ", KindPII, true},       // trimmed
		{"private-key", KindPrivateKey, true},
		{"entropy", KindEntropy, true},
		{"bogus", "", false},
	}
	for _, tc := range cases {
		k, ok := ParseKind(tc.in)
		if ok != tc.wantOK || (ok && k != tc.wantKind) {
			t.Errorf("ParseKind(%q) = (%q,%v), want (%q,%v)", tc.in, k, ok, tc.wantKind, tc.wantOK)
		}
	}
}

func TestKnownKindsSortedAndComplete(t *testing.T) {
	ks := KnownKinds()
	if len(ks) != 5 {
		t.Fatalf("KnownKinds len = %d, want 5", len(ks))
	}
	for i := 1; i < len(ks); i++ {
		if ks[i-1] > ks[i] {
			t.Errorf("KnownKinds not sorted: %q before %q", ks[i-1], ks[i])
		}
	}
}

func TestNewRegexDetector(t *testing.T) {
	if _, err := NewRegexDetector("", KindSecret, "a"); err == nil {
		t.Error("empty name: want error")
	}
	if _, err := NewRegexDetector("x", KindSecret, ""); err == nil {
		t.Error("empty pattern: want error")
	}
	if _, err := NewRegexDetector("x", KindSecret, "([bad"); err == nil {
		t.Error("invalid regexp: want error")
	}

	d, err := NewRegexDetector("emp-id", KindPII, `EMP-[0-9]{3}`)
	if err != nil {
		t.Fatalf("valid: %v", err)
	}
	if d.Name() != "emp-id" || d.Kind() != KindPII {
		t.Errorf("detector = (%q,%q), want (emp-id,pii)", d.Name(), d.Kind())
	}
	got := d.Find("id EMP-123 here")
	if len(got) != 1 || got[0].Match != "EMP-123" {
		t.Errorf("Find = %+v, want one match EMP-123", got)
	}
}

func TestWithDetectorsAppendsAndPreservesBuiltins(t *testing.T) {
	custom, err := NewRegexDetector("emp-id", KindPII, `EMP-[0-9]{3}`)
	if err != nil {
		t.Fatal(err)
	}
	base := Default()
	baseLen := len(base.Detectors())

	eng := base.WithDetectors(custom)
	if len(eng.Detectors()) != baseLen+1 {
		t.Fatalf("engine has %d detectors, want %d", len(eng.Detectors()), baseLen+1)
	}
	// Receiver must not be mutated.
	if len(base.Detectors()) != baseLen {
		t.Errorf("WithDetectors mutated the receiver: now %d detectors", len(base.Detectors()))
	}

	// Both a built-in (email) and the custom rule fire.
	got := map[string]int{}
	for _, f := range eng.Scan("mail me at a@b.com about EMP-123") {
		got[f.Detector]++
	}
	if got["email"] != 1 {
		t.Errorf("built-in email fired %d times, want 1 (%v)", got["email"], got)
	}
	if got["emp-id"] != 1 {
		t.Errorf("custom emp-id fired %d times, want 1 (%v)", got["emp-id"], got)
	}
}
