package detect

import "testing"

// TestPIIDetectors exercises each named-entity PII detector against valid,
// invalid, and near-miss fixtures. The valid cases must match exactly (byte
// span == Match); the invalid/near-miss cases must produce zero findings so we
// keep the false-positive rate low, which is the whole reason these detectors
// carry checksums (Luhn, mod-97) and group/serial filters.
func TestPIIDetectors(t *testing.T) {
	cases := []struct {
		detector string
		text     string
		want     []string
	}{
		// ---- credit-card (Luhn) ----
		{
			detector: "credit-card",
			// Valid test PANs: Visa, Visa-16, Amex, Mastercard (all Luhn-OK).
			text: "card 4111 1111 1111 1111 or 4012888888881881 here",
			want: []string{"4111 1111 1111 1111", "4012888888881881"},
		},
		{
			detector: "credit-card",
			text:     "amex 378282246310005 and mc 5555555555554444 too",
			want:     []string{"378282246310005", "5555555555554444"},
		},
		{
			detector: "credit-card",
			// Near-miss: right length/shape but fails Luhn (last digit off).
			text: "not a card 4111 1111 1111 1112 nor 1234567890123456",
			want: nil,
		},
		{
			detector: "credit-card",
			// Too short / too long runs are ignored.
			text: "ref 4111 and serial 41111111111111111111111 nope",
			want: nil,
		},

		// ---- IBAN (mod-97) ----
		{
			detector: "iban",
			text:     "pay to GB82 WEST 1234 5698 7654 32 today",
			want:     []string{"GB82 WEST 1234 5698 7654 32"},
		},
		{
			detector: "iban",
			text:     "acct DE89370400440532013000 confirmed",
			want:     []string{"DE89370400440532013000"},
		},
		{
			detector: "iban",
			// Near-miss: valid shape but wrong check digits (mod-97 fails).
			text: "bad GB00 WEST 1234 5698 7654 32 rejected",
			want: nil,
		},

		// ---- US SSN ----
		{
			detector: "ssn",
			text:     "ssn 123-45-6789 and 078-05-1120 on file",
			want:     []string{"123-45-6789", "078-05-1120"},
		},
		{
			detector: "ssn",
			// Invalid area (000, 666, 9xx) and zero group/serial are filtered.
			text: "bad 000-12-3456, 666-12-3456, 900-12-3456, 123-00-4567, 123-45-0000",
			want: nil,
		},
		{
			detector: "ssn",
			// Bare 9-digit run (no separators) must not be an SSN.
			text: "order 123456789 is not an ssn",
			want: nil,
		},

		// ---- phone ----
		{
			detector: "phone",
			text:     "call +1 202-555-0100 or (415) 555-2671 anytime",
			want:     []string{"+1 202-555-0100", "(415) 555-2671"},
		},
		{
			detector: "phone",
			// A bare long integer with no formatting is not a phone number.
			text: "id 12345678 and code 4242 stay clean",
			want: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.detector+"/"+shortText(tc.text), func(t *testing.T) {
			d := detectorByName(t, tc.detector)
			assertFinds(t, d, tc.text, tc.want)
		})
	}
}

func TestLuhnValid(t *testing.T) {
	valid := []string{"4111111111111111", "4012888888881881", "378282246310005", "5555555555554444"}
	invalid := []string{"4111111111111112", "1234567890123456", "0000000000000001"}
	for _, s := range valid {
		if !luhnValid(s) {
			t.Errorf("luhnValid(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if luhnValid(s) {
			t.Errorf("luhnValid(%q) = true, want false", s)
		}
	}
}

func TestValidateIBAN(t *testing.T) {
	valid := []string{"GB82WEST12345698765432", "DE89370400440532013000", "FR1420041010050500013M02606"}
	invalid := []string{"GB00WEST12345698765432", "XX00", "GB82WEST1234569876543Z!"}
	for _, s := range valid {
		if !validateIBAN(s) {
			t.Errorf("validateIBAN(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if validateIBAN(s) {
			t.Errorf("validateIBAN(%q) = true, want false", s)
		}
	}
}

// TestPIIDetectorsRegistered confirms the new detectors are actually wired into
// the default pack (so reports/--json see them) and that dedupe still labels a
// card as credit-card rather than a generic high-entropy token.
func TestPIIDetectorsRegistered(t *testing.T) {
	names := map[string]bool{}
	for _, d := range DefaultDetectors() {
		names[d.Name()] = true
	}
	for _, want := range []string{"credit-card", "iban", "ssn", "phone"} {
		if !names[want] {
			t.Errorf("default pack missing detector %q", want)
		}
	}

	findings := Default().Scan("pay 4012888888881881 now")
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %v", len(findings), matches(findings))
	}
	if findings[0].Detector != "credit-card" || findings[0].Kind != KindPayment {
		t.Errorf("got %s/%s, want credit-card/%s", findings[0].Detector, findings[0].Kind, KindPayment)
	}
}
