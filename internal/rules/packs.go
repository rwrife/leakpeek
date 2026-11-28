package rules

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rwrife/leakpeek/internal/detect"
)

const packManifest = "leakpeek-pack.toml"

// Pack is a validated, locally loaded bundle. Detectors retain filename and
// rule order, just like LoadPath.
type Pack struct {
	Name        string
	Version     string
	Description string
	Path        string
	Detectors   []detect.Detector
}

// PackSearchPaths returns pack roots in priority order: LEAKPEEK_PACKS (one
// directory), ~/.config/leakpeek/packs, then ./.leakpeek/packs.
func PackSearchPaths() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("finding rule pack home directory: %w", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("finding rule pack working directory: %w", err)
	}
	var paths []string
	if root := os.Getenv("LEAKPEEK_PACKS"); root != "" {
		root, err = filepath.Abs(root)
		if err != nil {
			return nil, fmt.Errorf("resolving LEAKPEEK_PACKS: %w", err)
		}
		paths = append(paths, root)
	}
	return append(paths, filepath.Join(home, ".config", "leakpeek", "packs"),
		filepath.Join(cwd, ".leakpeek", "packs")), nil
}

func validPackName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func parseManifest(src string) (Pack, error) {
	var pack Pack
	seen := map[string]bool{}
	for i, raw := range strings.Split(src, "\n") {
		line := strings.TrimSpace(stripComment(raw))
		if line == "" {
			continue
		}
		key, value, err := splitKeyValue(line, i+1)
		if err != nil {
			return Pack{}, err
		}
		if seen[key] {
			return Pack{}, fmt.Errorf("line %d: duplicate key %q", i+1, key)
		}
		switch key {
		case "name":
			pack.Name = value
		case "version":
			pack.Version = value
		case "description":
			pack.Description = value
		default:
			return Pack{}, fmt.Errorf("line %d: unknown manifest key %q (want name, version, or description)", i+1, key)
		}
		seen[key] = true
	}
	if !validPackName(pack.Name) {
		return Pack{}, errors.New("manifest name is required and must contain only letters, digits, '.', '_' or '-' (not '.' or '..')")
	}
	if strings.TrimSpace(pack.Version) == "" {
		return Pack{}, errors.New("manifest version is required")
	}
	return pack, nil
}

func loadPack(path, name string) (Pack, error) {
	manifest := filepath.Join(path, packManifest)
	data, err := os.ReadFile(manifest)
	if err != nil {
		return Pack{}, fmt.Errorf("reading rule pack manifest %q: %w", manifest, err)
	}
	pack, err := parseManifest(string(data))
	if err != nil {
		return Pack{}, fmt.Errorf("%s: %w", manifest, err)
	}
	if pack.Name != name {
		return Pack{}, fmt.Errorf("%s: manifest name %q must match pack directory name %q", manifest, pack.Name, name)
	}
	pack.Path = path
	files, err := directoryRuleFiles(path, packManifest)
	if err != nil {
		return Pack{}, err
	}
	for _, file := range files {
		ds, err := loadFile(file)
		if err != nil {
			return Pack{}, err
		}
		pack.Detectors = append(pack.Detectors, ds...)
	}
	if len(pack.Detectors) == 0 {
		return Pack{}, fmt.Errorf("rule pack %q at %q contains no rules; add a [[rule]] to a .toml file", name, path)
	}
	return pack, nil
}

// ResolvePack selects the first existing named directory. A broken higher
// priority pack is an error, never a reason to silently use another version.
func ResolvePack(name string, roots []string) (Pack, error) {
	if !validPackName(name) {
		return Pack{}, fmt.Errorf("invalid rule pack name %q: use a name, not a path (letters, digits, '.', '_' or '-')", name)
	}
	var searched []string
	for _, root := range roots {
		path := filepath.Join(root, name)
		searched = append(searched, path)
		_, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return Pack{}, fmt.Errorf("reading rule pack %q: %w", path, err)
		}
		return loadPack(path, name)
	}
	return Pack{}, fmt.Errorf("rule pack %q not found; searched:\n  %s\ninstall %s%c%s under one of these pack roots or set LEAKPEEK_PACKS to its parent directory",
		name, strings.Join(searched, "\n  "), name, filepath.Separator, packManifest)
}

// ListPacks discovers named packs, keeping only the highest-priority version
// of each name. Missing roots and directories without manifests are ignored;
// malformed packs and unreadable roots fail explicitly.
func ListPacks(roots []string) ([]Pack, error) {
	var packs []Pack
	seen := map[string]bool{}
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("reading rule pack root %q: %w", root, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if seen[name] {
				continue
			}
			path := filepath.Join(root, name)
			info, err := os.Stat(path)
			if err != nil {
				return nil, fmt.Errorf("reading rule pack directory %q: %w", path, err)
			}
			if !info.IsDir() {
				continue
			}
			_, err = os.Stat(filepath.Join(path, packManifest))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("reading rule pack manifest in %q: %w", path, err)
			}
			pack, err := ResolvePack(name, roots)
			if err != nil {
				return nil, err
			}
			seen[name] = true
			packs = append(packs, pack)
		}
	}
	sort.Slice(packs, func(i, j int) bool { return packs[i].Name < packs[j].Name })
	return packs, nil
}

// LoadExtras composes --rules with repeatable --rule-pack names. Explicit
// rules precede packs; packs follow flag order, with duplicate names loaded once.
func LoadExtras(path string, names []string) ([]detect.Detector, error) {
	var detectors []detect.Detector
	if path != "" {
		ds, err := LoadPath(path)
		if err != nil {
			return nil, err
		}
		detectors = append(detectors, ds...)
	}
	if len(names) == 0 {
		return detectors, nil
	}
	roots, err := PackSearchPaths()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			continue
		}
		pack, err := ResolvePack(name, roots)
		if err != nil {
			return nil, err
		}
		seen[name] = true
		detectors = append(detectors, pack.Detectors...)
	}
	return detectors, nil
}
