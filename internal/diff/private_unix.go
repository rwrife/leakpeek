//go:build !windows

package diff

import (
	"errors"
	"os"
	"syscall"
)

func secure(path string, dir bool) error {
	mode := os.FileMode(0o600)
	if dir {
		mode = 0o700
	}
	return os.Chmod(path, mode)
}

func checkPrivate(_ string, info os.FileInfo, dir bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	want := os.FileMode(0o600)
	if dir {
		want = 0o700
	}
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != want {
		return errors.New("diff snapshot requires owner-only permissions (directory 0700, file 0600)")
	}
	return nil
}
