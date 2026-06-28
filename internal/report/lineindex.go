package report

import "unicode/utf8"

// lineIndex maps a byte offset in the scanned text to a 1-based line and
// column. It precomputes the byte offset at which each line starts so each
// lookup is a binary search plus a rune count, rather than rescanning the
// whole prefix every time.
//
// Columns are counted in runes (not bytes) so a multibyte character counts as
// one column — that's what a human reading the line expects. Newlines are '\n';
// a '\r' before it is treated as part of the previous line's content, which is
// fine for positioning.
type lineIndex struct {
	text  string
	start []int // start[i] = byte offset where line (i+1) begins
}

// newLineIndex builds the per-line start table for text.
func newLineIndex(text string) *lineIndex {
	starts := []int{0}
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return &lineIndex{text: text, start: starts}
}

// position returns the 1-based (line, column) for byte offset off. Offsets at
// or past the end clamp to the final position; negative offsets clamp to the
// start. Column is the rune distance from the start of the line to off.
func (li *lineIndex) position(off int) (line, col int) {
	if off < 0 {
		off = 0
	}
	if off > len(li.text) {
		off = len(li.text)
	}

	// Find the last line start <= off via binary search.
	lo, hi := 0, len(li.start)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if li.start[mid] <= off {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	lineStart := li.start[lo]
	col = utf8.RuneCountInString(li.text[lineStart:off]) + 1
	return lo + 1, col
}
