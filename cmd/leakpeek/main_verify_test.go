package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rwrife/leakpeek/internal/detect"
	"github.com/rwrife/leakpeek/internal/verify"
)

func TestRunVerifyOffline(t *testing.T) {
	for _, asJSON := range []bool{false, true} {
		var out, errb bytes.Buffer
		args := []string{"verify"}
		if asJSON {
			args = append(args, "--json")
		}
		// A nil stdin also guards against accidentally entering clipboard mode.
		code := run(args, nil, &out, &errb)
		if code != exitClean || errb.Len() != 0 {
			t.Fatalf("code=%d stderr=%s stdout=%s", code, &errb, &out)
		}
		if asJSON {
			var result verify.Result
			if err := json.Unmarshal(out.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if !result.Passed || result.Mode != "verify" || result.SchemaVersion != 1 ||
				len(result.Detectors) != len(detect.DefaultDetectors()) {
				t.Fatalf("unexpected JSON: %+v", result)
			}
		} else if !strings.Contains(out.String(), "Overall: PASS") ||
			!strings.Contains(out.String(), "FALSE POSITIVES") {
			t.Fatalf("missing matrix or overall verdict: %s", &out)
		}
	}
}

func TestRunVerifyCustomFixtures(t *testing.T) {
	for _, directory := range []bool{false, true} {
		for _, scenario := range []struct {
			name, pattern string
			passed        bool
			caught, fp    int
		}{
			{"passing", `EMP-[0-9]{6}`, true, 1, 0},
			{"missed positive", `NEVER`, false, 0, 0},
			{"false positive", `EMP-.*`, false, 1, 1},
		} {
			t.Run(scenario.name+map[bool]string{true: "/directory", false: "/file"}[directory], func(t *testing.T) {
				root := t.TempDir()
				ruleFile := filepath.Join(root, "mine.toml")
				content := "[[rule]]\nname = 'employee'\nregex = '" + scenario.pattern + "'\n"
				if err := os.WriteFile(ruleFile, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
				rulesPath := ruleFile
				fixturesPath := ruleFile + ".fixtures.json"
				if directory {
					rulesPath = root
					fixturesPath = filepath.Join(root, "fixtures.json")
				}
				fixtures := `[{"detector":"employee","positives":[{"name":"ID","text":"EMP-123456"}],"negatives":[{"name":"short","text":"EMP-12"}]}]`
				if err := os.WriteFile(fixturesPath, []byte(fixtures), 0o600); err != nil {
					t.Fatal(err)
				}
				var out, errb bytes.Buffer
				code := run([]string{"verify", "--json", "--rules=" + rulesPath}, nil, &out, &errb)
				wantCode := exitError
				if scenario.passed {
					wantCode = exitClean
				}
				if code != wantCode || errb.Len() != 0 {
					t.Fatalf("code=%d want=%d stderr=%s stdout=%s", code, wantCode, &errb, &out)
				}
				var result verify.Result
				if err := json.Unmarshal(out.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				row := result.Detectors[len(result.Detectors)-1]
				if result.Passed != scenario.passed || row.Passed != scenario.passed ||
					row.PositivesCaught != scenario.caught || row.FalsePositives != scenario.fp {
					t.Fatalf("unexpected result: %+v", result)
				}
				if strings.Contains(out.String(), "EMP-123456") {
					t.Fatal("result contains raw custom fixture text")
				}
				out.Reset()
				code = run([]string{"verify", "--rules", rulesPath}, nil, &out, &errb)
				if code != wantCode || !strings.Contains(out.String(), "Overall: "+verificationVerdict(scenario.passed)) {
					t.Fatalf("unexpected human result: code=%d stdout=%s stderr=%s", code, &out, &errb)
				}
			})
		}
	}
}

func TestRunVerifyBadUsage(t *testing.T) {
	for _, args := range [][]string{
		{"--rules"}, {"--rules="}, {"--rules", "--json"},
		{"--json=false"}, {"--stdin"}, {"--fix"}, {"path"},
	} {
		var out, errb bytes.Buffer
		if code := run(append([]string{"verify"}, args...), nil, &out, &errb); code != exitUsage || errb.Len() == 0 {
			t.Fatalf("args=%v code=%d stderr=%s", args, code, &errb)
		}
	}
}

func TestRunVerifyCustomLoadErrors(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "mine.toml")
	for _, tt := range []struct {
		name, rule, fixtures, want string
	}{
		{"invalid rule", "[[rule]]\nname='custom'\nregex='['", "", "invalid regexp"},
		{"missing fixtures", "[[rule]]\nname='custom'\nregex='hit'", "", "reading verification fixtures"},
		{"invalid fixtures", "[[rule]]\nname='custom'\nregex='hit'", "not json", "invalid verification corpus"},
		{"uncovered custom", "[[rule]]\nname='custom'\nregex='hit'", "[]", "no verification fixtures"},
		{"unknown fixture field", "[[rule]]\nname='custom'\nregex='hit'", `[{"detector":"custom","positive":[]}]`, "unknown field"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tt.rule), 0o600); err != nil {
				t.Fatal(err)
			}
			if tt.fixtures != "" {
				if err := os.WriteFile(path+".fixtures.json", []byte(tt.fixtures), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var out, errb bytes.Buffer
			if code := run([]string{"verify", "--rules", path}, nil, &out, &errb); code != exitError ||
				!strings.Contains(errb.String(), tt.want) || out.Len() != 0 {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, &out, &errb)
			}
		})
	}
}

type verificationBrokenWriter struct{}

func (verificationBrokenWriter) Write([]byte) (int, error) {
	return 0, errors.New("output unavailable")
}

func TestRunVerifyOutputFailure(t *testing.T) {
	for _, args := range [][]string{{"verify"}, {"verify", "--json"}, {"verify", "--help"}} {
		var errb bytes.Buffer
		if code := run(args, nil, verificationBrokenWriter{}, &errb); code != exitError ||
			!strings.Contains(errb.String(), "output unavailable") {
			t.Fatalf("code=%d stderr=%s", code, &errb)
		}
	}
}
