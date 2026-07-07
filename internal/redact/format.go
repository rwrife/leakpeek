// format.go adds *format-aware* redaction to leakpeek (PLAN.md §8 backlog
// item 7). The one-way strategies in redact.go splice a stand-in over each
// finding's exact byte span — great for prose and log lines, but blunt for
// structured config. When you paste a `.env`, a JSON blob, or a chunk of
// YAML into an AI, what you want back is the *shape* — the keys, the nesting,
// the punctuation — with only the *values* scrubbed. That's what this file
// does: it finds the structural values that carry a secret and rewrites the
// whole value, leaving keys and structure byte-for-byte intact, so the AI
// still understands "there's a DATABASE_URL here, it's just redacted."
//
// The design deliberately reuses the detection findings rather than trusting
// a parser to tell secrets from innocuous config. A key named `password`
// isn't proof of a secret, and a key named `note` might still hold one. So a
// value is only redacted when a real Finding lands inside it. Two payoffs:
//
//  1. Leak-safety is inherited from the finding contract. We replace the
//     *entire* value span that contains a finding (not a shape-preserving
//     fragment of it), so no original secret material can survive — the same
//     hard guarantee redact.go makes, proven the same way in the tests.
//  2. We don't over-redact. A config value with no secret in it is left
//     exactly as written, so the AI sees the real structure and the real
//     non-sensitive values around the holes.
//
// When the text isn't recognizably structured — or the chosen format leaves
// some findings outside any value it understood (e.g. a secret sitting in a
// comment, or a format we sniffed wrong) — we fall back to the plain,
// span-based Redact for exactly those leftover findings. That fallback is the
// safety net PLAN.md's acceptance criteria ask for: format-aware first, regex
// redaction for anything the format pass didn't cover, so a secret is never
// silently left in place just because it wasn't in a tidy `key: value`.
package redact

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/rwrife/leakpeek/internal/detect"
)

// Format is a coarse label for the structured text shapes leakpeek knows how
// to value-mask. FormatPlain means "not (confidently) structured" — the
// caller should fall back to span-based redaction.
type Format int

const (
	// FormatPlain is unstructured text (or something we couldn't confidently
	// classify). Format-aware redaction degrades to plain Redact for it.
	FormatPlain Format = iota
	// FormatDotenv is shell/.env style: `KEY=value` lines, optional `export`,
	// `#` comments, quoted or bare values.
	FormatDotenv
	// FormatJSON is a JSON document (object or array) that parses cleanly.
	FormatJSON
	// FormatYAML is YAML-ish `key: value` / list text handled line-by-line
	// (no external YAML dependency — leakpeek stays single-binary, stdlib-only).
	FormatYAML
)

// String renders the format name for help text, logs, and tests.
func (f Format) String() string {
	switch f {
	case FormatDotenv:
		return "dotenv"
	case FormatJSON:
		return "json"
	case FormatYAML:
		return "yaml"
	default:
		return "plain"
	}
}

// valueSpan is a half-open byte range [Start,End) covering a structural
// *value* (never its key or the surrounding punctuation) that we may redact.
type valueSpan struct {
	Start int
	End   int
}

// RedactFormatAware redacts text with awareness of its structure. If text is
// recognizably a `.env`, JSON, or YAML document, it rewrites the *values*
// that contain a finding — preserving keys, nesting, and punctuation — using
// strategy to build the replacement token. Any finding that doesn't fall
// inside a recognized value (or when the text isn't structured at all) is
// handled by the ordinary span-based Redact, so nothing sensitive is left
// behind.
//
// The returned Format tells the caller what shape was detected (handy for a
// one-line "redacted as json" note and for tests). The original string is
// never mutated.
//
// Leak-safety: because a covered value is replaced in full, the output can
// contain no original secret material from any finding — identical to the
// guarantee Redact makes. The redact_test suite asserts this across formats.
func RedactFormatAware(text string, findings []detect.Finding, strategy Strategy) (string, Format) {
	if len(findings) == 0 {
		// Even with nothing to redact, report the shape so callers/tests get a
		// consistent classification of the input.
		return text, sniffFormat(text)
	}

	format := sniffFormat(text)
	if format == FormatPlain {
		// Unstructured: the span-based redactor is exactly right here.
		return Redact(text, findings, strategy), FormatPlain
	}

	values, keys := structuralSpans(text, format)
	if len(values) == 0 {
		// We classified a structure but found no value spans to key off (e.g.
		// an empty object). Fall back so any stray finding is still handled.
		return Redact(text, findings, strategy), format
	}

	// Split findings three ways: those inside a structural value (redacted as a
	// whole value), those inside a KEY (left completely alone — we redact
	// values, not keys), and everything else (redacted span-based as a
	// fallback, for secrets sitting in comments or unmodeled regions). Then
	// apply the value + leftover edits in one ordered splice pass.
	covered, leftover := partitionFindings(findings, values, keys)
	out := redactComposite(text, values, covered, leftover, strategy)
	return out, format
}

// FormatAwareOrPlain is a convenience for callers that only want the string.
func FormatAwareOrPlain(text string, findings []detect.Finding, strategy Strategy) string {
	s, _ := RedactFormatAware(text, findings, strategy)
	return s
}

// sniffFormat classifies text into one of the known structured shapes, or
// FormatPlain when nothing fits confidently. The order reflects confidence:
// JSON is unambiguous (it parses or it doesn't); dotenv has a strong `KEY=`
// signature; YAML is the loosest, so it's tried last and gated on a majority
// of non-blank lines looking like `key:` / list entries.
func sniffFormat(text string) Format {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return FormatPlain
	}

	// JSON: must parse as an object or array. A bare number/string/bool is
	// valid JSON but has no keys to preserve, so we don't treat it as JSON
	// here — the span redactor handles those fine.
	if b := trimmed[0]; b == '{' || b == '[' {
		var js any
		if json.Unmarshal([]byte(trimmed), &js) == nil {
			switch js.(type) {
			case map[string]any, []any:
				return FormatJSON
			}
		}
	}

	// Dotenv vs YAML: both are line-oriented. Count the signal per non-blank,
	// non-comment line and pick the stronger. `KEY=value` ⇒ dotenv-ish;
	// `key: value` or `- item` ⇒ yaml-ish.
	var envLines, yamlLines, meaningful int
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		meaningful++
		if looksDotenvLine(line) {
			envLines++
		}
		if looksYAMLLine(line) {
			yamlLines++
		}
	}
	if meaningful == 0 {
		return FormatPlain
	}

	// Require a clear majority so a stray `a=b` in prose doesn't flip the whole
	// blob to dotenv. Dotenv wins ties because `=` is a stronger secret-config
	// signal than `:` (URLs, times, and prose use `:` constantly).
	if envLines*2 >= meaningful && envLines >= yamlLines {
		return FormatDotenv
	}
	if yamlLines*2 >= meaningful {
		return FormatYAML
	}
	return FormatPlain
}

// looksDotenvLine reports whether a trimmed line looks like a `.env`
// assignment: an optional `export`, then a KEY, then `=`. We don't require a
// value (an empty value is legal) but we do require a plausible key so a line
// that merely contains `=` inside prose doesn't count.
func looksDotenvLine(line string) bool {
	line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
	eq := strings.IndexByte(line, '=')
	if eq <= 0 {
		return false
	}
	return isEnvKey(line[:eq])
}

// looksYAMLLine reports whether a trimmed line looks like a YAML mapping entry
// (`key: value`) or a list item (`- ...`). The `key:` form must have a space
// or end-of-line after the colon so we don't mistake `http://` or `10:30` for
// a mapping.
func looksYAMLLine(line string) bool {
	if strings.HasPrefix(line, "- ") || line == "-" {
		return true
	}
	key, _, ok := splitYAMLKey(line)
	return ok && isYAMLKey(key)
}

// isEnvKey validates a dotenv key: letters, digits, underscores, not starting
// with a digit, non-empty. Trailing spaces around the key are tolerated.
func isEnvKey(k string) bool {
	k = strings.TrimSpace(k)
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c == '_':
			// ok anywhere
		case c >= '0' && c <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// isYAMLKey validates a YAML mapping key conservatively: a non-empty,
// unquoted-ish scalar without spaces (quoted or multiword keys are rare in the
// config people paste and safely fall through to plain redaction).
func isYAMLKey(k string) bool {
	k = strings.TrimSpace(k)
	if k == "" || strings.ContainsAny(k, " \t") {
		return false
	}
	// Reject obvious non-keys.
	return !strings.HasPrefix(k, "#")
}

// structuralSpans returns, for the given format, the byte spans of every
// redactable *value* and every *key* in text, each sorted by Start. Values
// are what we may redact; keys are what we must never touch (we redact
// values, not keys), so the caller uses the key spans to drop any finding
// that landed inside a key — e.g. an email-shaped JSON key — from the
// span-based fallback. Punctuation is in neither set.
func structuralSpans(text string, format Format) (values, keys []valueSpan) {
	switch format {
	case FormatDotenv:
		return dotenvSpans(text)
	case FormatYAML:
		return yamlSpans(text)
	case FormatJSON:
		return jsonSpans(text)
	default:
		return nil, nil
	}
}

// structuralValues returns just the value spans (see structuralSpans). Kept as
// a thin helper for readability where keys aren't needed.
func structuralValues(text string, format Format) []valueSpan {
	v, _ := structuralSpans(text, format)
	return v
}

// dotenvSpans walks each line and, for `KEY=value` lines, records the value
// portion (with surrounding matching quotes trimmed off the span so the quotes
// themselves survive and only the inside is redacted) and the key portion. An
// inline ` # comment` after an *unquoted* value is left outside the value span.
func dotenvSpans(text string) (values, keys []valueSpan) {
	offset := 0
	for _, raw := range splitKeepOffsets(text) {
		line := raw.s
		base := offset
		offset += len(line) + 1 // +1 for the '\n' we split on

		// `body` is the meaningful part of the line; `lead` is how many bytes of
		// the original line precede it, so absolute offsets stay exact even after
		// trimming indentation and an optional `export `.
		body := strings.TrimLeft(line, " \t")
		if body == "" || strings.HasPrefix(body, "#") {
			continue
		}
		if strings.HasPrefix(body, "export ") {
			body = strings.TrimLeft(body[len("export "):], " \t")
		}
		// Recompute lead as the distance from the line start to `body` — this is
		// robust to whatever we trimmed above, no running arithmetic to drift.
		lead := len(line) - len(body)

		eq := strings.IndexByte(body, '=')
		if eq <= 0 || !isEnvKey(body[:eq]) {
			continue
		}
		keyStart := base + lead
		keys = append(keys, valueSpan{Start: keyStart, End: keyStart + eq})

		valStart := base + lead + eq + 1
		val := body[eq+1:]
		s, e := valueInnerSpan(val, valStart, true)
		if s < e {
			values = append(values, valueSpan{Start: s, End: e})
		}
	}
	return values, keys
}

// yamlSpans records the value span for each `key: value` line and each
// `- item` list entry, plus the key span for each mapping line. Block scalars,
// anchors, and deep flow structures are out of scope for the line-based pass;
// anything it doesn't cover is caught by the plain-redaction fallback.
func yamlSpans(text string) (values, keys []valueSpan) {
	offset := 0
	for _, raw := range splitKeepOffsets(text) {
		line := raw.s
		base := offset
		offset += len(line) + 1

		trimmedLeft := strings.TrimLeft(line, " \t")
		lead := len(line) - len(trimmedLeft)
		body := trimmedLeft
		if body == "" || strings.HasPrefix(body, "#") {
			continue
		}

		// List item: `- value`
		if strings.HasPrefix(body, "- ") {
			valStart := base + lead + 2
			val := body[2:]
			s, e := valueInnerSpan(val, valStart, false)
			if s < e {
				values = append(values, valueSpan{Start: s, End: e})
			}
			continue
		}

		key, after, ok := splitYAMLKey(body)
		if !ok || !isYAMLKey(key) {
			continue
		}
		keyStart := base + lead
		keys = append(keys, valueSpan{Start: keyStart, End: keyStart + len(key)})

		// after is the substring following "key:" within body. Its value may be
		// empty (a nested block follows) — skip those.
		valOffsetInBody := len(body) - len(after)
		valStart := base + lead + valOffsetInBody
		s, e := valueInnerSpan(after, valStart, false)
		if s < e {
			values = append(values, valueSpan{Start: s, End: e})
		}
	}
	return values, keys
}

// jsonSpans re-parses text and records the byte span of every scalar leaf
// value (string, number, bool, null) reachable in the document, plus the span
// of every object key. We use a streaming token scan so we get positions, and
// track whether the next string is a key (right after `{` or a `,` inside an
// object) or a value.
//
// Only string/number/bool/null leaves become value spans; container
// punctuation is in neither set. Key spans are returned separately so the
// caller can leave key-embedded findings untouched.
func jsonSpans(text string) (values, keys []valueSpan) {
	// Find where the JSON actually starts (there may be leading whitespace we
	// trimmed for sniffing) so offsets map back to the original text.
	start := indexTrimStart(text)
	dec := json.NewDecoder(strings.NewReader(text[start:]))
	dec.UseNumber()

	// Stack of container types: true = object, false = array. We also track,
	// per object, whether the next string token is a key.
	type frame struct {
		isObject  bool
		expectKey bool // only meaningful for objects
	}

	// src is the exact slice handed to the decoder; token offsets are relative
	// to it, so we map back to original coordinates by adding `start`.
	src := text[start:]
	var stack []frame

	for {
		prevOffset := dec.InputOffset()
		tok, err := dec.Token()
		if err != nil {
			break // end of input or malformed tail; we've recorded what we could
		}
		tokEnd := int(dec.InputOffset())

		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, frame{isObject: true, expectKey: true})
			case '[':
				stack = append(stack, frame{isObject: false})
			case '}', ']':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
			}
		default:
			// A scalar token (string, json.Number, bool, or nil).
			top := len(stack) - 1
			isKey := false
			if top >= 0 && stack[top].isObject {
				if stack[top].expectKey {
					isKey = true
					stack[top].expectKey = false // the value comes next
				} else {
					stack[top].expectKey = true // after a value, next string is a key
				}
			}
			// InputOffset() taken *before* Token() points just past the
			// previous token/delimiter, so it can include a leading `:` / `,`
			// and whitespace. Advance to the true first byte of this token's
			// serialized form; tokEnd (taken after) is exact.
			s := tokValueStart(src, int(prevOffset))
			e := tokEnd
			if _, ok := tok.(string); ok {
				// Trim the JSON quotes so `"…"` keeps its quotes and only the
				// interior is redacted (keys are labels we won't touch, but we
				// trim theirs too so a key span maps to its text precisely).
				if e-s >= 2 && s < len(src) && src[s] == '"' && src[e-1] == '"' {
					s++
					e--
				}
			}
			if s < e {
				span := valueSpan{Start: s + start, End: e + start}
				if isKey {
					keys = append(keys, span)
				} else {
					values = append(values, span)
				}
			}
		}
	}
	// Decoder tokens arrive in document order, so spans are already sorted.
	return values, keys
}

// tokValueStart returns the index (relative to src) of the first byte of a
// JSON token beginning at or after `from`, skipping the structural bytes a
// value may be preceded by: whitespace, a name-separator ':' and a
// value-separator ','. The next non-skippable byte is where the token itself
// starts (a '"' for strings, a digit/'-' for numbers, a letter for
// true/false/null).
func tokValueStart(src string, from int) int {
	i := from
	for i < len(src) {
		switch src[i] {
		case ' ', '\t', '\n', '\r', ':', ',':
			i++
		default:
			return i
		}
	}
	return i
}

// splitYAMLKey splits a trimmed YAML line body into (key, afterColon, ok).
// afterColon is everything following the first `key:` delimiter, INCLUDING the
// leading space(s), so the caller can compute the value's offset precisely.
// ok is false when there's no top-level `key:` delimiter (a space or EOL must
// follow the colon to qualify, so `http://x` and `12:30` don't match).
func splitYAMLKey(body string) (key, afterColon string, ok bool) {
	for i := 0; i < len(body); i++ {
		if body[i] != ':' {
			continue
		}
		// Must be followed by a space or end-of-line to be a mapping colon.
		if i+1 == len(body) || body[i+1] == ' ' || body[i+1] == '\t' {
			return body[:i], body[i+1:], true
		}
		// A colon glued to non-space (URL, time) — not a mapping delimiter;
		// stop scanning so we don't split mid-value on a later colon either.
		return "", "", false
	}
	return "", "", false
}

// valueInnerSpan computes the [start,end) span of the *content* of a raw value
// string val, whose first byte sits at absStart in the original text. It:
//   - trims leading whitespace (advancing the start),
//   - for dotenv/yaml, drops an inline ` # comment` on *unquoted* values,
//   - trims trailing whitespace,
//   - if the remainder is wrapped in matching quotes, moves the span inside
//     them so the quotes survive and only the inside is redacted.
//
// stripHashComment controls the inline-comment trimming (dotenv & yaml want
// it; it's harmless for values that have no ` #`). Returns start>=end when the
// value is empty, signaling "nothing to redact here".
func valueInnerSpan(val string, absStart int, stripHashComment bool) (int, int) {
	// Leading whitespace.
	i := 0
	for i < len(val) && (val[i] == ' ' || val[i] == '\t') {
		i++
	}
	start := absStart + i
	rest := val[i:]

	// Quoted value: keep quotes outside the span, everything inside is content
	// (an inline # inside quotes is part of the value, so we don't strip it).
	if len(rest) >= 2 && (rest[0] == '"' || rest[0] == '\'') {
		q := rest[0]
		if close := strings.IndexByte(rest[1:], q); close >= 0 {
			innerStart := start + 1
			innerEnd := start + 1 + close
			return innerStart, innerEnd
		}
		// Unterminated quote: fall through and treat as a bare value.
	}

	// Bare value: optionally drop an inline comment (must be preceded by
	// whitespace to count as a comment, so `a#b` stays whole).
	end := absStart + len(val)
	if stripHashComment {
		if h := inlineHashIndex(rest); h >= 0 {
			end = start + h
		}
	}
	// Trim trailing whitespace off the [start,end) window.
	for end > start {
		c := textByteAt(val, absStart, end-1)
		if c == ' ' || c == '\t' || c == '\r' {
			end--
			continue
		}
		break
	}
	return start, end
}

// inlineHashIndex returns the index within rest of the start of an inline
// ` #` comment (a '#' preceded by whitespace), or -1 if none. A leading '#'
// (index 0) doesn't count here because a value starting with '#' would be odd
// and is better left whole for the fallback.
func inlineHashIndex(rest string) int {
	for i := 1; i < len(rest); i++ {
		if rest[i] == '#' && (rest[i-1] == ' ' || rest[i-1] == '\t') {
			return i
		}
	}
	return -1
}

// textByteAt returns the byte at absolute offset abs, given that val begins at
// absStart. It's a tiny helper so the trailing-trim loop reads clearly.
func textByteAt(val string, absStart, abs int) byte {
	return val[abs-absStart]
}

// indexTrimStart returns the byte offset of the first non-whitespace byte in
// text (0 if it starts non-blank). Used to map a trimmed JSON parse back onto
// original coordinates.
func indexTrimStart(text string) int {
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case ' ', '\t', '\n', '\r':
			continue
		default:
			return i
		}
	}
	return len(text)
}

// offsetLine is one line of the input (without its trailing '\n'). Callers
// reconstruct absolute byte offsets by advancing a running counter by
// len(line)+1 per entry, so per-line value spans land in original-text
// coordinates.
type offsetLine struct {
	s string
}

// splitKeepOffsets splits text on '\n' but keeps enough to reconstruct
// absolute offsets: the caller advances a running offset by len(line)+1 per
// entry. We return the raw line content (without the trailing '\n').
func splitKeepOffsets(text string) []offsetLine {
	parts := strings.Split(text, "\n")
	out := make([]offsetLine, len(parts))
	for i, p := range parts {
		out[i] = offsetLine{s: p}
	}
	return out
}

// partitionFindings splits findings into those wholly inside some value span
// (covered, redacted as a whole value) and those that are not (leftover,
// redacted span-based). A finding that lands inside a KEY span is dropped from
// both: keys are labels we preserve verbatim, so a secret-shaped key (e.g. an
// email used as a JSON key) is neither value-redacted nor fallback-redacted.
// A finding straddling a value boundary (rare, e.g. a bad sniff) is treated as
// leftover so the fallback handles it without half-redacting a value.
//
// values and keys must each be sorted by Start (structuralSpans guarantees it).
func partitionFindings(findings []detect.Finding, values, keys []valueSpan) (covered, leftover []detect.Finding) {
	for _, f := range findings {
		if f.Start >= f.End {
			continue
		}
		switch {
		case spanContains(values, f.Start, f.End):
			covered = append(covered, f)
		case spanOverlaps(keys, f.Start, f.End):
			// Inside (or overlapping) a key — leave it entirely alone.
		default:
			leftover = append(leftover, f)
		}
	}
	return covered, leftover
}

// spanOverlaps reports whether any span in spans overlaps [start,end). spans is
// sorted by Start; we check the candidate at or before start and its neighbor,
// which is sufficient because spans within one format pass never overlap each
// other. Used for keys so a finding touching a key at all is excluded.
func spanOverlaps(spans []valueSpan, start, end int) bool {
	if len(spans) == 0 {
		return false
	}
	i := sort.Search(len(spans), func(i int) bool { return spans[i].Start > start }) - 1
	for j := i; j <= i+1; j++ {
		if j < 0 || j >= len(spans) {
			continue
		}
		if start < spans[j].End && spans[j].Start < end {
			return true
		}
	}
	return false
}

// spanContains reports whether some span in values fully contains [start,end).
// values is sorted by Start, so we binary-search to the last span starting at
// or before start and check containment.
func spanContains(values []valueSpan, start, end int) bool {
	i := sort.Search(len(values), func(i int) bool { return values[i].Start > start }) - 1
	if i < 0 {
		return false
	}
	return values[i].Start <= start && end <= values[i].End
}

// redactComposite applies both kinds of redaction in one ordered pass over
// the original text, so offsets stay valid regardless of length changes:
//
//   - each covered finding contributes a rewrite of the *entire value span*
//     it lives in (keys/structure preserved, no secret fragment survives),
//   - each leftover finding contributes a span-based rewrite of its own span
//     (the plain-redaction fallback for anything outside a known value).
//
// covered and leftover come from a single deduped scan, so their spans don't
// overlap; value spans are disjoint by construction. We coalesce multiple
// findings that share one value into a single value rewrite, sort all edits by
// position, and splice left-to-right, skipping any defensive overlap so bytes
// are never double-written. The original string is not mutated.
func redactComposite(text string, values []valueSpan, covered, leftover []detect.Finding, strategy Strategy) string {
	type edit struct {
		start, end int
		repl       string
	}

	var edits []edit
	seenValue := map[int]bool{}
	for _, f := range covered {
		idx := sort.Search(len(values), func(i int) bool { return values[i].Start > f.Start }) - 1
		if idx < 0 {
			continue
		}
		vs := values[idx]
		if !(vs.Start <= f.Start && f.End <= vs.End) || seenValue[vs.Start] {
			continue
		}
		seenValue[vs.Start] = true
		edits = append(edits, edit{start: vs.Start, end: vs.End, repl: valueReplacement(f, strategy)})
	}
	for _, f := range leftover {
		if f.Start >= f.End {
			continue
		}
		edits = append(edits, edit{start: f.Start, end: f.End, repl: replacement(f, strategy)})
	}

	sort.Slice(edits, func(i, j int) bool {
		if edits[i].start != edits[j].start {
			return edits[i].start < edits[j].start
		}
		return edits[i].end-edits[i].start > edits[j].end-edits[j].start
	})

	var b strings.Builder
	b.Grow(len(text))
	cursor := 0
	for _, e := range edits {
		if e.start < cursor || e.end > len(text) || e.start >= e.end {
			continue // defensive: skip overlaps / out-of-range
		}
		b.WriteString(text[cursor:e.start])
		b.WriteString(e.repl)
		cursor = e.end
	}
	b.WriteString(text[cursor:])
	return b.String()
}

// valueReplacement builds the stand-in for a redacted structural value. It
// reuses the one-way strategy tokens (Full/Hash) directly, and for the default
// Shape strategy emits a compact, structure-friendly `[REDACTED-<KIND>]` token
// rather than a shape-preserving splice — inside `"…"` or after `KEY=`, a
// clean labeled placeholder reads better and still tells the AI the value's
// kind. Vault falls back to Full here (the reversible path routes through
// RedactWithVault, not this function), so a secret is never echoed.
func valueReplacement(f detect.Finding, strategy Strategy) string {
	switch strategy {
	case Hash:
		return "[" + kindLabel(f.Kind) + ":" + fingerprint(f.Match) + "]"
	default: // Shape, Full, Vault
		return "[REDACTED-" + kindLabel(f.Kind) + "]"
	}
}
