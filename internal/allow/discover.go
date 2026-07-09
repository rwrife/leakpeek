package allow

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// IgnoreFileName is the per-project allowlist filename leakpeek looks for when
// walking up from the working directory, mirroring how tools like git find
// .gitignore.
const IgnoreFileName = ".leakpeekignore"

// LoadFile reads and compiles a single ignore file into a Set. A read error is
// wrapped with the path; a parse error already carries "<path>:<line>: ...".
// It is the primitive the discovery and --ignore paths both build on.
func LoadFile(path string) (Set, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Set{}, fmt.Errorf("reading ignore file %q: %w", path, err)
	}
	return Parse(string(b), path)
}

// LoadFiles loads and merges several ignore files in order, so a caller can
// pass a list of explicit --ignore paths and get one combined Set. The first
// read/parse error aborts and is returned; a nil/empty list yields an empty
// Set and no error.
func LoadFiles(paths []string) (Set, error) {
	var set Set
	for _, p := range paths {
		s, err := LoadFile(p)
		if err != nil {
			return Set{}, err
		}
		set = set.Merge(s)
	}
	return set, nil
}

// Discover builds the ambient allowlist for a run: every .leakpeekignore found
// by walking up from startDir (nearest first), merged with the global ignore
// file under the user's config dir. Missing files are not errors — discovery
// is best-effort, so a project simply without a .leakpeekignore suppresses
// nothing — but a file that exists and fails to parse *is* returned as an
// error, because the user wrote it expecting it to take effect.
//
// startDir is typically the process working directory. Pass "" to use it. The
// walk stops at the filesystem root (or a git repository root, whichever comes
// first), so discovery never escapes the project into a stranger's home dir
// config it didn't intend.
func Discover(startDir string) (Set, error) {
	dir := startDir
	if strings.TrimSpace(dir) == "" {
		wd, err := os.Getwd()
		if err != nil {
			return Set{}, fmt.Errorf("locating working directory for ignore discovery: %w", err)
		}
		dir = wd
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return Set{}, fmt.Errorf("resolving %q for ignore discovery: %w", dir, err)
	}

	// Collect candidate project files from the start dir upward. We gather
	// nearest-first so the merged Set lists closer overrides before farther
	// ones (only diagnostics care about order; suppression is set-like).
	var set Set
	for cur := abs; ; {
		candidate := filepath.Join(cur, IgnoreFileName)
		s, err := loadIfPresent(candidate)
		if err != nil {
			return Set{}, err
		}
		set = set.Merge(s)

		// Stop climbing at a repo boundary so discovery stays inside the
		// project the user is actually working in.
		if isRepoRoot(cur) {
			break
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break // reached the filesystem root
		}
		cur = parent
	}

	// Global user-level allowlist, merged last (farthest, lowest precedence in
	// diagnostics; still fully effective).
	if gp := globalIgnorePath(); gp != "" {
		s, err := loadIfPresent(gp)
		if err != nil {
			return Set{}, err
		}
		set = set.Merge(s)
	}

	return set, nil
}

// loadIfPresent loads an ignore file, treating "does not exist" as an empty
// Set rather than an error. Any other read error (permission denied, a
// directory where a file was expected) or a parse error is surfaced, so a
// broken-but-present allowlist never fails open silently.
func loadIfPresent(path string) (Set, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Set{}, nil
		}
		return Set{}, fmt.Errorf("checking ignore file %q: %w", path, err)
	}
	if info.IsDir() {
		// A directory named .leakpeekignore isn't something we can parse;
		// skip it rather than erroring, so an oddly-named dir up the tree
		// doesn't break every scan.
		return Set{}, nil
	}
	return LoadFile(path)
}

// isRepoRoot reports whether dir contains a .git entry (dir or file — a file
// covers git worktrees/submodules), marking the top of the project tree. Used
// to bound Discover's upward walk so it doesn't wander above the repo.
func isRepoRoot(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil
}

// globalIgnorePath returns the path to the user-level ignore file, honoring
// $XDG_CONFIG_HOME (leakpeek/ignore) and falling back to ~/.config/leakpeek/
// ignore. It returns "" when neither a config home nor a home directory can be
// determined, in which case discovery simply skips the global file.
func globalIgnorePath() string {
	if xdg := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); xdg != "" {
		return filepath.Join(xdg, "leakpeek", "ignore")
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return ""
	}
	return filepath.Join(home, ".config", "leakpeek", "ignore")
}
