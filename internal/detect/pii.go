// pii.go adds named-entity PII detectors to leakpeek's core pack: credit-card
// numbers, phone numbers, US Social Security numbers, and IBANs (issue #28).
//
// These are the shapes people paste into AI chats without thinking — an order
// confirmation with a card number, a support ticket with a phone and SSN, a
// bank detail with an IBAN. They stay true to the v0.1 "regex-first, no ML"
// philosophy (PLAN.md §5): every detector is a regexp for the *shape* plus a
// cheap *checksum* to keep false positives down. Cards are Luhn-checked, IBANs
// are mod-97-checked, SSNs reject obviously-invalid groups, and phone numbers
// require enough digits in a plausible arrangement.
//
// Card numbers get their own Kind (KindPayment) so the redactor can apply the
// "mask all but last 4" convention people expect from receipts; phone, SSN,
// and IBAN are plain KindPII. Each detector has a distinct Name so reports and
// --json label them clearly (see the acceptance criteria on #28).
package detect

import (
	"regexp"
	"strings"
)

// DefaultPIIDetectors returns the named-entity PII pack. It is folded into the
// default engine ahead of the generic high-entropy catch-all (see
// DefaultDetectorsProfile) so a card/SSN/IBAN is labeled as such rather than
// as an anonymous high-entropy blob.
//
// Order within the pack favors the most structurally distinctive shapes first
// (IBAN's country prefix, the credit-card digit runs) so dedupe's earlier-wins
// tie-break keeps the precise label when spans coincide.
func DefaultPIIDetectors() []Detector {
	return []Detector{
		creditCard,
		iban,
		ssn,
		phone,
	}
}

// ---- Credit card (Luhn) ----------------------------------------------------

// creditCard matches candidate 13–19 digit runs (optionally grouped by spaces
// or hyphens, as printed on a card) and keeps only those that pass the Luhn
// checksum. The regex is deliberately loose on grouping; validateCard does the
// real filtering.
var creditCard = regexDetector{
	name: "credit-card",
	kind: KindPayment,
	// A run of 13–19 digits, allowing single space/hyphen separators between
	// digit groups. Word boundaries keep us from biting into a longer number.
	re:       regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`),
	validate: validateCard,
}

// validateCard strips separators and accepts the match only if it is a 13–19
// digit number that satisfies the Luhn checksum. This is what turns a random
// 16-digit order ID into a non-match while catching real PANs.
func validateCard(match string) bool {
	digits := onlyDigits(match)
	if n := len(digits); n < 13 || n > 19 {
		return false
	}
	return luhnValid(digits)
}

// luhnValid runs the Luhn (mod-10) checksum over a pure-digit string.
func luhnValid(digits string) bool {
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// ---- IBAN (mod-97) ---------------------------------------------------------

// iban matches the IBAN shape — two letters (country), two check digits, then
// up to 30 alphanumerics — and validates it with the ISO 13616 mod-97 check.
var iban = regexDetector{
	name:     "iban",
	kind:     KindPII,
	re:       regexp.MustCompile(`\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{1,4}){2,8}\b`),
	validate: validateIBAN,
}

// validateIBAN performs the standard IBAN mod-97 validation: strip spaces,
// bail on an implausible length, move the first four chars to the end, map
// letters to numbers (A=10…Z=35), and check the big number ≡ 1 (mod 97).
func validateIBAN(match string) bool {
	s := strings.ToUpper(strings.ReplaceAll(match, " ", ""))
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	// First two must be letters (country), next two digits (check).
	if !isAlpha(s[0]) || !isAlpha(s[1]) || !isDigit(s[2]) || !isDigit(s[3]) {
		return false
	}
	rearranged := s[4:] + s[:4]
	// Compute the numeric string mod 97 incrementally so we never build a
	// huge integer: letters expand to two digits, digits to one.
	rem := 0
	for i := 0; i < len(rearranged); i++ {
		c := rearranged[i]
		switch {
		case c >= '0' && c <= '9':
			rem = (rem*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			v := int(c-'A') + 10 // A=10 … Z=35, a two-digit value
			rem = (rem*100 + v) % 97
		default:
			return false
		}
	}
	return rem == 1
}

// ---- US SSN -----------------------------------------------------------------

// ssn matches the US pattern AAA-GG-SSSS (hyphens or spaces) and filters the
// obviously-invalid groups the SSA never issues, to cut down on false hits
// from arbitrary 9-digit sequences typed with dashes.
var ssn = regexDetector{
	name:     "ssn",
	kind:     KindPII,
	re:       regexp.MustCompile(`\b\d{3}[- ]\d{2}[- ]\d{4}\b`),
	validate: validateSSN,
}

// validateSSN rejects the well-known invalid area/group/serial patterns:
// area 000, 666, or 900–999; group 00; serial 0000. It intentionally keeps
// the required separators (from the regex) so a bare 9-digit number — far more
// likely to be an order or account number — isn't flagged.
func validateSSN(match string) bool {
	d := onlyDigits(match)
	if len(d) != 9 {
		return false
	}
	area := d[:3]
	group := d[3:5]
	serial := d[5:]
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	if group == "00" || serial == "0000" {
		return false
	}
	return true
}

// ---- Phone ------------------------------------------------------------------

// phone matches E.164 and common national formats: an optional leading + and
// country code, then groups of digits separated by spaces, hyphens, dots, or
// parenthesized area codes. validatePhone enforces a plausible digit count so
// short numeric runs and long IDs don't masquerade as phone numbers.
var phone = regexDetector{
	name: "phone",
	kind: KindPII,
	re: regexp.MustCompile(
		`(?:\+\d{1,3}[ .-]?)?(?:\(\d{1,4}\)[ .-]?)?\d{2,4}(?:[ .-]?\d{2,4}){1,4}`,
	),
	validate: validatePhone,
}

// validatePhone accepts a match only when it has a realistic number of digits
// (7–15, matching E.164's max) and, when no country code/parenthesis is
// present, at least one separator — so a bare run like "12345678" (an ID) is
// not treated as a phone number, while "123-4567" and "+1 202 555 0100" are.
func validatePhone(match string) bool {
	d := onlyDigits(match)
	if len(d) < 7 || len(d) > 15 {
		return false
	}
	hasSep := strings.ContainsAny(match, " .-()")
	hasCC := strings.HasPrefix(strings.TrimSpace(match), "+")
	// Require some formatting signal so we don't flag a plain long integer.
	return hasSep || hasCC
}

// ---- shared helpers ---------------------------------------------------------

func onlyDigits(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func isAlpha(c byte) bool { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
