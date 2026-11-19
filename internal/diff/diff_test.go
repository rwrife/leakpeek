package diff

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/rwrife/leakpeek/internal/detect"
)

func TestScanChangedLines(t *testing.T) {
	const key = "AKIAIOSFODNN7EXAMPLE"
	tests := []struct {
		name, baseline, text string
		want                 []int
	}{
		{"unchanged", key + "\n", key + "\n", nil},
		{"added", key + "\n", key + "\nprefix " + key + "\n", []int{len(key) + 8}},
		{"changed", "safe\n", "prefix " + key + "\n", []int{7}},
		{"shifted", key + "\n", "safe\n" + key + "\n", nil},
		{"deleted", "safe\n" + key + "\n", key + "\n", nil},
		{"duplicate added", key + "\n", key + "\n" + key + "\n", []int{len(key) + 1}},
		{"separate ranges", "a\nstable\nz\n", key + "\nstable\n" + key + "\n", []int{0, len(key) + len("\nstable\n")}},
		{"crlf unicode", key + "\r\n", key + "\r\n\u03bb " + key + "\r\n", []int{len(key) + 5}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Scan(detect.Default(), tt.text, &tt.baseline)
			var starts []int
			for _, f := range findings {
				starts = append(starts, f.Start)
				if f.Match != tt.text[f.Start:f.End] {
					t.Fatal("finding does not reference original text")
				}
			}
			if !reflect.DeepEqual(starts, tt.want) {
				t.Fatalf("starts = %v, want %v", starts, tt.want)
			}
		})
	}
	if got := Scan(detect.Default(), key, nil); len(got) != 1 {
		t.Fatalf("first scan findings = %v", got)
	}
}

func TestScanDoesNotJoinUnchangedGaps(t *testing.T) {
	d, err := detect.NewRegexDetector("multiline", detect.KindSecret, "start\\nend")
	if err != nil {
		t.Fatal(err)
	}
	baseline := "unchanged\n"
	if got := Scan(detect.New(d), "start\nunchanged\nend", &baseline); len(got) != 0 {
		t.Fatalf("matched across unchanged gap: %v", got)
	}
	if got := Scan(detect.New(d), "start\nend", &baseline); len(got) != 1 {
		t.Fatalf("adjacent changed lines did not match: %v", got)
	}
}

// Compare all small duplicate-line inputs with an independent quadratic LCS.
func TestUnchangedIsLongestCommonSubsequence(t *testing.T) {
	var inputs [][]string
	for length := 0; length <= 6; length++ {
		for bits := 0; bits < 1<<length; bits++ {
			lines := make([]string, length)
			for i := range lines {
				lines[i] = fmt.Sprint((bits >> i) & 1)
			}
			inputs = append(inputs, lines)
		}
	}
	for _, a := range inputs {
		for _, b := range inputs {
			changed := make([]bool, len(b))
			for i := range changed {
				changed[i] = true
			}
			markUnchanged(a, b, changed)
			previous := make([]int, len(b)+1)
			for _, line := range a {
				next := make([]int, len(b)+1)
				for j, other := range b {
					next[j+1] = max(previous[j+1], next[j])
					if line == other {
						next[j+1] = previous[j] + 1
					}
				}
				previous = next
			}
			count, at := 0, 0
			for i, line := range b {
				if changed[i] {
					continue
				}
				for at < len(a) && a[at] != line {
					at++
				}
				if at == len(a) {
					t.Fatalf("not a common subsequence: %v, %v, %v", a, b, changed)
				}
				at++
				count++
			}
			if count != previous[len(b)] {
				t.Fatalf("LCS(%v,%v): got %d unchanged, want %d", a, b, count, previous[len(b)])
			}
		}
	}
}

func TestLargeAppend(t *testing.T) {
	baseline := strings.Repeat("safe log line\n", 100000)
	got := Scan(detect.Default(), baseline+"AKIAIOSFODNN7EXAMPLE", &baseline)
	if len(got) != 1 || got[0].Start != len(baseline) {
		t.Fatalf("large append findings: %v", got)
	}
}
