package diff

import (
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestSnapshotRefusesUnsafeACL(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := Save(dir, "secret", time.Now()); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(dir, "snapshot.json"), dir} {
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir, time.Now()); err == nil {
			t.Fatal("accepted shared snapshot or directory")
		}
	}
	if err := Save(dir, "must not write", time.Now()); err == nil {
		t.Fatal("saved in shared directory")
	}
}
