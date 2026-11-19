package diff

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"time"
)

const TTL = 15 * time.Minute

var ErrExpired = errors.New("diff snapshot expired and was cleared")

type Snapshot struct {
	Created time.Time `json:"created"`
	Text    string    `json:"text"`
}

// DefaultDir separates users even on hosts with a shared temp directory.
func DefaultDir() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("identifying diff snapshot owner: %w", err)
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("leakpeek-diff-%x", sha256.Sum256([]byte(u.Uid)))), nil
}

func checkDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("diff snapshot directory is not a private directory")
	}
	return checkPrivate(dir, info, true)
}

// Load never accepts an expired, future-dated, corrupt or non-private baseline.
// Missing snapshots are represented by nil; callers must do a full scan.
func Load(dir string, now time.Time) (*Snapshot, error) {
	if err := checkDir(dir); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("checking diff snapshot directory: %w", err)
	}
	path := filepath.Join(dir, "snapshot.json")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("checking diff snapshot: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("diff snapshot is not a regular file")
	}
	if err := checkPrivate(path, info, false); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading diff snapshot: %w", err)
	}
	var s Snapshot
	// Do not include decoder errors: they can quote sensitive snapshot bytes.
	if json.Unmarshal(data, &s) != nil || s.Created.IsZero() {
		return nil, errors.New("invalid diff snapshot; use --diff-clear to remove it")
	}
	if age := now.Sub(s.Created); age < 0 || age >= TTL {
		if err := Clear(dir); err != nil {
			return nil, err
		}
		return nil, ErrExpired
	}
	return &s, nil
}

func Save(dir, text string, now time.Time) error {
	if err := os.Mkdir(dir, 0o700); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("creating diff snapshot directory: %w", err)
		}
	} else if err := secure(dir, true); err != nil {
		return err
	}
	if err := checkDir(dir); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "snapshot-*")
	if err != nil {
		return fmt.Errorf("creating diff snapshot: %w", err)
	}
	defer os.Remove(f.Name())
	if err := secure(f.Name(), false); err != nil {
		f.Close()
		return err
	}
	if err := json.NewEncoder(f).Encode(Snapshot{Created: now, Text: text}); err != nil {
		f.Close()
		return errors.New("writing diff snapshot failed")
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing diff snapshot: %w", err)
	}
	if err := os.Rename(f.Name(), filepath.Join(dir, "snapshot.json")); err != nil {
		return fmt.Errorf("saving diff snapshot: %w", err)
	}
	return nil
}

func Clear(dir string) error {
	if err := checkDir(dir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := os.Remove(filepath.Join(dir, "snapshot.json")); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clearing diff snapshot: %w", err)
	}
	return nil
}
