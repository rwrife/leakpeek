package detect

import "testing"

// detectorByName pulls a single named detector out of the default pack so we
// can exercise it in isolation, independent of dedupe/engine behavior.
func detectorByName(t *testing.T, name string) Detector {
	t.Helper()
	for _, d := range DefaultDetectors() {
		if d.Name() == name {
			return d
		}
	}
	t.Fatalf("detector %q not found in DefaultDetectors()", name)
	return nil
}

// findInText is a helper: it asserts the detector finds exactly the wanted
// substrings (in any order) and that every Finding's Match equals the
// reported byte span of the input — the core invariant the engine relies on.
func assertFinds(t *testing.T, d Detector, text string, want []string) {
	t.Helper()
	got := d.Find(text)
	if len(got) != len(want) {
		t.Fatalf("%s: got %d findings %v, want %d %v", d.Name(), len(got), matches(got), len(want), want)
	}
	for _, f := range got {
		if f.Match != text[f.Start:f.End] {
			t.Errorf("%s: Match %q != text[%d:%d]=%q", d.Name(), f.Match, f.Start, f.End, text[f.Start:f.End])
		}
	}
	for _, w := range want {
		if !containsMatch(got, w) {
			t.Errorf("%s: missing expected match %q in %v", d.Name(), w, matches(got))
		}
	}
}

func matches(fs []Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Match
	}
	return out
}

func containsMatch(fs []Finding, want string) bool {
	for _, f := range fs {
		if f.Match == want {
			return true
		}
	}
	return false
}

func TestDetectors_PositiveAndNegative(t *testing.T) {
	cases := []struct {
		detector string
		text     string
		want     []string // expected matched substrings
	}{
		{
			detector: "aws-access-key",
			text:     "id=AKIAIOSFODNN7EXAMPLE and ASIAY34FZKBOKMUTVV7A here",
			want:     []string{"AKIAIOSFODNN7EXAMPLE", "ASIAY34FZKBOKMUTVV7A"},
		},
		{
			detector: "aws-access-key",
			text:     "not a key: AKIA123 too short, and lowercase akiaiosfodnn7example",
			want:     nil,
		},
		{
			detector: "openai-key",
			text:     "OPENAI_API_KEY=sk-proj-abc123DEF456ghi789JKL012mno345PQR done",
			want:     []string{"sk-proj-abc123DEF456ghi789JKL012mno345PQR"},
		},
		{
			detector: "openai-key",
			text:     "the word sketchy and sk-short should not match",
			want:     nil,
		},
		{
			detector: "github-pat",
			text:     "token ghp_1234567890abcdefABCDEF1234567890abcd ok",
			want:     []string{"ghp_1234567890abcdefABCDEF1234567890abcd"},
		},
		{
			detector: "github-pat",
			text:     "fine grained github_pat_11ABCDE0Y0abcdefghij_klmnopqrstuvwxyz here",
			want:     []string{"github_pat_11ABCDE0Y0abcdefghij_klmnopqrstuvwxyz"},
		},
		{
			detector: "github-pat",
			text:     "ghp_tooshort and a random word github are fine",
			want:     nil,
		},
		{
			detector: "slack-token",
			text:     "SLACK=xoxb-EXAMPLEfake-EXAMPLEfake-NOTaRealSlackToken end",
			want:     []string{"xoxb-EXAMPLEfake-EXAMPLEfake-NOTaRealSlackToken"},
		},
		{
			detector: "slack-token",
			text:     "xoxz-not-a-real-prefix should be ignored",
			want:     nil,
		},
		{
			detector: "jwt",
			text:     "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N done",
			want:     []string{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N"},
		},
		{
			detector: "jwt",
			text:     "a.b.c is not a jwt and neither is foo.bar.baz",
			want:     nil,
		},
		{
			detector: "private-key",
			text:     "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
			want:     []string{"-----BEGIN RSA PRIVATE KEY-----"},
		},
		{
			detector: "private-key",
			text:     "-----BEGIN OPENSSH PRIVATE KEY-----\nbase64\n",
			want:     []string{"-----BEGIN OPENSSH PRIVATE KEY-----"},
		},
		{
			detector: "private-key",
			text:     "-----BEGIN CERTIFICATE----- is public, not a private key",
			want:     nil,
		},
		{
			detector: "email",
			text:     "ping oncall@corp.example.com or me+filter@sub.domain.io please",
			want:     []string{"oncall@corp.example.com", "me+filter@sub.domain.io"},
		},
		{
			detector: "email",
			text:     "not@an and missing-tld@host are not full emails",
			want:     nil,
		},
		{
			detector: "ipv4",
			text:     "box at 10.0.42.17 and gw 192.168.1.1 are internal",
			want:     []string{"10.0.42.17", "192.168.1.1"},
		},
		{
			detector: "ipv4",
			text:     "version 1.22.333 and 999.1.1.1 are not valid IPv4",
			want:     nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.detector+"/"+shortText(tc.text), func(t *testing.T) {
			d := detectorByName(t, tc.detector)
			assertFinds(t, d, tc.text, tc.want)
		})
	}
}

// shortText makes a compact, readable subtest name from sample input.
func shortText(s string) string {
	const max = 24
	r := []rune(s)
	for i, c := range r {
		if c == '\n' {
			r[i] = ' '
		}
	}
	if len(r) > max {
		return string(r[:max])
	}
	return string(r)
}
