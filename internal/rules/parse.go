package rules

import (
	"fmt"
	"strconv"
	"strings"
)

// parse reads the documented TOML subset (see the package doc) into a slice of
// Rules in file order. The grammar it accepts, line by line:
//
//   - blank lines and comments (# to end of line, outside strings) → ignored
//   - a [[rule]] header → starts a new rule (any other [table] is rejected)
//   - key = value, where key ∈ {name, kind, regex} and value is a string in
//     '…', "…", ”'…”', or """…""" quoting (single-line)
//
// It is deliberately strict: an unknown key, a value before any [[rule]]
// header, a duplicate key within a rule, a non-string value, or a bare table
// header all produce a line-numbered error. Being strict means a typo fails
// loudly instead of silently dropping a rule the user thought was active.
func parse(src string) ([]Rule, error) {
	var (
		rules   []Rule
		cur     *Rule // rule currently being filled (nil until first [[rule]])
		curSeen map[string]bool
	)

	flush := func() {
		if cur != nil {
			rules = append(rules, *cur)
		}
	}

	lines := strings.Split(src, "\n")
	for i, raw := range lines {
		lineNo := i + 1
		line := stripComment(raw)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Table header?
		if strings.HasPrefix(line, "[") {
			switch line {
			case "[[rule]]":
				flush()
				r := Rule{line: lineNo}
				cur = &r
				curSeen = map[string]bool{}
			default:
				return nil, fmt.Errorf("line %d: unsupported table header %q (only [[rule]] is allowed)", lineNo, line)
			}
			continue
		}

		// Otherwise it must be key = value, and we must be inside a rule.
		key, val, err := splitKeyValue(line, lineNo)
		if err != nil {
			return nil, err
		}
		if cur == nil {
			return nil, fmt.Errorf("line %d: %q appears before any [[rule]] header", lineNo, key)
		}
		if curSeen[key] {
			return nil, fmt.Errorf("line %d: duplicate key %q in this rule", lineNo, key)
		}
		switch key {
		case "name":
			cur.Name = val
		case "kind":
			cur.Kind = val
		case "regex":
			cur.Regex = val
		default:
			return nil, fmt.Errorf("line %d: unknown key %q (want name, kind, or regex)", lineNo, key)
		}
		curSeen[key] = true
	}
	flush()
	return rules, nil
}

// splitKeyValue parses a `key = "value"` line into its bare key and decoded
// string value. It enforces that the value is a quoted string (the only value
// type a rule field can take), returning a line-numbered error otherwise.
func splitKeyValue(line string, lineNo int) (key, value string, err error) {
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return "", "", fmt.Errorf("line %d: expected key = value, got %q", lineNo, line)
	}
	key = strings.TrimSpace(line[:eq])
	rest := strings.TrimSpace(line[eq+1:])
	if key == "" {
		return "", "", fmt.Errorf("line %d: empty key before '='", lineNo)
	}
	value, err = decodeString(rest, lineNo)
	if err != nil {
		return "", "", err
	}
	return key, value, nil
}

// decodeString unquotes a single-line TOML string value. It supports:
//
//   - basic strings:   "…"    (escapes processed via strconv.Unquote)
//   - literal strings: '…'    (no escapes; contents taken verbatim)
//   - triple-quoted:   """…""" and ”'…”'  on one line (their multi-line
//     form is out of scope for the rule subset)
//
// Anything else — an unquoted token, a number, a bare bool, mismatched quotes,
// trailing junk after the closing quote — is a line-numbered error, so a rule
// value is always an explicit string.
func decodeString(s string, lineNo int) (string, error) {
	if s == "" {
		return "", fmt.Errorf("line %d: missing value after '='", lineNo)
	}

	// Triple-quoted (single-line) first, so we don't mis-handle the outer pair.
	for _, q := range []string{`"""`, "'''"} {
		if strings.HasPrefix(s, q) {
			if len(s) >= 2*len(q) && strings.HasSuffix(s, q) {
				return s[len(q) : len(s)-len(q)], nil
			}
			return "", fmt.Errorf("line %d: unterminated %s string (multi-line values aren't supported for rule fields)", lineNo, q)
		}
	}

	switch s[0] {
	case '"':
		v, err := strconv.Unquote(s)
		if err != nil {
			return "", fmt.Errorf("line %d: invalid double-quoted string: %v", lineNo, err)
		}
		return v, nil
	case '\'':
		// Literal string: verbatim between the single quotes, no escapes.
		if len(s) >= 2 && strings.HasSuffix(s, "'") {
			return s[1 : len(s)-1], nil
		}
		return "", fmt.Errorf("line %d: unterminated literal string", lineNo)
	default:
		return "", fmt.Errorf("line %d: value must be a quoted string, got %q", lineNo, s)
	}
}

// stripComment removes a trailing `# …` comment from a line while respecting
// quoting, so a '#' inside a regex value (common in patterns) is preserved. It
// tracks whether we're inside a single- or double-quoted run and only honors a
// '#' that appears outside quotes. This is a line-level pass; the rule subset
// has no multi-line strings, so per-line comment stripping is sufficient.
func stripComment(line string) string {
	inSingle, inDouble := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch c {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return line[:i]
			}
		}
	}
	return line
}
