// Package diff scans added or changed lines without losing full-input offsets.
package diff

import (
	"strings"

	"github.com/rwrife/leakpeek/internal/detect"
)

// Scan runs detectors on contiguous changed-line ranges, never joining lines
// across unchanged gaps. A nil baseline means that every line is new.
func Scan(engine *detect.Engine, text string, baseline *string) []detect.Finding {
	lines := strings.SplitAfter(text, "\n")
	changed := make([]bool, len(lines))
	for i := range changed {
		changed[i] = true
	}
	if baseline != nil {
		markUnchanged(strings.SplitAfter(*baseline, "\n"), lines, changed)
	}
	var findings []detect.Finding
	offset := 0
	for i := 0; i < len(lines); {
		if !changed[i] {
			offset += len(lines[i])
			i++
			continue
		}
		start := offset
		for i < len(lines) && changed[i] {
			offset += len(lines[i])
			i++
		}
		for _, f := range engine.Scan(text[start:offset]) {
			f.Start += start
			f.End += start
			findings = append(findings, f)
		}
	}
	return findings
}

// markUnchanged uses a linear-space Myers bisect. Trimming equal ends keeps
// the common append/edit-a-few-lines case cheap even for large inputs.
func markUnchanged(a, b []string, changed []bool) {
	for len(a) > 0 && len(b) > 0 && a[0] == b[0] {
		changed[0] = false
		a, b, changed = a[1:], b[1:], changed[1:]
	}
	for len(a) > 0 && len(b) > 0 && a[len(a)-1] == b[len(b)-1] {
		changed[len(b)-1] = false
		a, b, changed = a[:len(a)-1], b[:len(b)-1], changed[:len(changed)-1]
	}
	if len(a) == 0 || len(b) == 0 {
		return
	}
	x, y := bisect(a, b)
	if (x == 0 && y == 0) || (x == len(a) && y == len(b)) {
		return
	}
	markUnchanged(a[:x], b[:y], changed[:y])
	markUnchanged(a[x:], b[y:], changed[y:])
}

func bisect(a, b []string) (int, int) {
	n, m := len(a), len(b)
	limit := (n + m + 1) / 2
	offset := limit + 1
	forward, reverse := make([]int, 2*limit+3), make([]int, 2*limit+3)
	for i := range forward {
		forward[i], reverse[i] = -1, -1
	}
	forward[offset+1], reverse[offset+1] = 0, 0
	delta := n - m
	odd := delta%2 != 0
	for d := 0; d <= limit; d++ {
		for k := -d; k <= d; k += 2 {
			index := offset + k
			x := forward[index-1] + 1
			if k == -d || (k != d && forward[index-1] < forward[index+1]) {
				x = forward[index+1]
			}
			y := x - k
			for x < n && y < m && x >= 0 && y >= 0 && a[x] == b[y] {
				x++
				y++
			}
			forward[index] = x
			other := offset + delta - k
			if odd && other >= 0 && other < len(reverse) && reverse[other] >= 0 && x >= n-reverse[other] {
				return x, y
			}
		}
		for k := -d; k <= d; k += 2 {
			index := offset + k
			x := reverse[index-1] + 1
			if k == -d || (k != d && reverse[index-1] < reverse[index+1]) {
				x = reverse[index+1]
			}
			y := x - k
			for x < n && y < m && x >= 0 && y >= 0 && a[n-x-1] == b[m-y-1] {
				x++
				y++
			}
			reverse[index] = x
			other := offset + delta - k
			if !odd && other >= 0 && other < len(forward) && forward[other] >= 0 && forward[other] >= n-x {
				return forward[other], forward[other] - (delta - k)
			}
		}
	}
	return n, m
}
