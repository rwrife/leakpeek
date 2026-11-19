package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	diffscan "github.com/rwrife/leakpeek/internal/diff"
	"github.com/rwrife/leakpeek/internal/report"
)

func isolateDiff(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	t.Setenv("TMP", dir)
	t.Setenv("TEMP", dir)
	path, err := diffscan.DefaultDir()
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func diffRun(t *testing.T, text string, extra ...string) (report.Result, int, string) {
	t.Helper()
	var out, stderr bytes.Buffer
	args := append([]string{"--stdin", "--diff", "--json", "--no-ignore"}, extra...)
	code := run(args, strings.NewReader(text), &out, &stderr)
	var res report.Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("invalid JSON %q: %v; stderr=%s", out.String(), err, &stderr)
	}
	if strings.Contains(out.String(), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("report leaked raw input")
	}
	return res, code, stderr.String()
}

func TestDiffCLIReportsNewFindingsAndOriginalOffsets(t *testing.T) {
	dir := isolateDiff(t)
	const key = "AKIAIOSFODNN7EXAMPLE"
	initial := key + "\r\nstable\r\n"
	res, code, stderr := diffRun(t, initial)
	if code != exitFound || stderr != "" || res.Total != 1 || res.BaselineAgeSeconds != nil || !res.Items[0].NewSince {
		t.Fatalf("initial result = %+v, code=%d, stderr=%s", res, code, stderr)
	}
	text := "inserted\r\n" + initial + "\u03bb key=" + key + "\r\n"
	res, code, stderr = diffRun(t, text)
	start := strings.LastIndex(text, key)
	if code != exitFound || stderr != "" || res.Total != 1 || res.BaselineAgeSeconds == nil {
		t.Fatalf("diff result = %+v, code=%d, stderr=%s", res, code, stderr)
	}
	item := res.Items[0]
	if item.Line != 4 || item.Column != 7 || item.Start != start || item.End != start+len(key) || !res.Groups[0].Items[0].NewSince {
		t.Fatalf("wrong full-input offsets/metadata: %+v", res)
	}
	res, code, _ = diffRun(t, text)
	if code != exitClean || !res.Clean || res.Total != 0 || !strings.Contains(res.Verdict, "No new secrets") {
		t.Fatalf("unchanged result = %+v, code=%d", res, code)
	}
	s, err := diffscan.Load(dir, time.Now())
	if err != nil || s == nil || s.Text != text {
		t.Fatalf("snapshot did not advance: %v", err)
	}
}

func TestDiffNoSnapshotAndExpiry(t *testing.T) {
	dir := isolateDiff(t)
	const key = "AKIAIOSFODNN7EXAMPLE"
	diffRun(t, key, "--no-snapshot")
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("--no-snapshot wrote a directory: %v", err)
	}
	created := time.Now().Add(-time.Minute)
	if err := diffscan.Save(dir, "baseline\n", created); err != nil {
		t.Fatal(err)
	}
	diffRun(t, key, "--no-snapshot")
	s, err := diffscan.Load(dir, time.Now())
	if err != nil || s == nil || s.Text != "baseline\n" || !s.Created.Equal(created) {
		t.Fatalf("--no-snapshot changed baseline: %v, %v", s, err)
	}
	if err := diffscan.Save(dir, key, time.Now().Add(-diffscan.TTL)); err != nil {
		t.Fatal(err)
	}
	res, code, stderr := diffRun(t, key, "--no-snapshot")
	if code != exitFound || res.Total != 1 || res.BaselineAgeSeconds != nil || !strings.Contains(stderr, "expired") {
		t.Fatalf("expiry result=%+v code=%d stderr=%s", res, code, stderr)
	}
	if s, err := diffscan.Load(dir, time.Now()); s != nil || err != nil {
		t.Fatalf("expired snapshot not removed: %v, %v", s, err)
	}
	diffRun(t, key)
	var out, errOut bytes.Buffer
	if code := run([]string{"--diff-clear"}, nil, &out, &errOut); code != exitClean {
		t.Fatalf("clear failed: %d %s", code, &errOut)
	}
	if s, err := diffscan.Load(dir, time.Now()); s != nil || err != nil {
		t.Fatalf("clear retained snapshot: %v, %v", s, err)
	}
}

type failingDiffWriter struct{}

func (failingDiffWriter) Write([]byte) (int, error) { return 0, errors.New("output failed") }

func TestDiffOutputFailureDoesNotAdvanceSnapshot(t *testing.T) {
	dir := isolateDiff(t)
	for _, flags := range [][]string{{"--stdin", "--diff"}, {"--stdin", "--diff", "--json"}} {
		var stderr bytes.Buffer
		if code := run(flags, strings.NewReader("safe"), failingDiffWriter{}, &stderr); code != exitError {
			t.Fatalf("write failure exit = %d", code)
		}
		if s, err := diffscan.Load(dir, time.Now()); s != nil || err != nil {
			t.Fatalf("failed report advanced baseline: %v, %v", s, err)
		}
	}
}

func TestDiffIncompatibleFlags(t *testing.T) {
	for _, flags := range [][]string{
		{"--no-snapshot"}, {"--diff", "--fix"}, {"--diff", "--watch"},
		{"--diff", "--unredact"}, {"--diff", "--stats"}, {"--diff", "--vault-clear"},
		{"--diff-clear", "--stdin"},
	} {
		var out, stderr bytes.Buffer
		if code := run(flags, nil, &out, &stderr); code != exitUsage {
			t.Fatalf("%v exit = %d, stderr=%s", flags, code, &stderr)
		}
	}
}
