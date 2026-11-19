package diff

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func ownerSID() (*windows.SID, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return u.User.Sid, nil
}

func privateDACL(dir bool) (string, error) {
	sid, err := ownerSID()
	if err != nil {
		return "", err
	}
	flags := ""
	if dir {
		flags = "OICI"
	}
	return "D:P(A;" + flags + ";FA;;;" + sid.String() + ")", nil
}

func secure(path string, dir bool) error {
	sid, err := ownerSID()
	if err != nil {
		return err
	}
	sddl, err := privateDACL(dir)
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		sid, nil, acl, nil)
}

func checkPrivate(path string, _ os.FileInfo, dir bool) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	sid, err := ownerSID()
	if err != nil {
		return err
	}
	dacl, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	// Windows may retain this informational flag after inheritance is disabled.
	// Normalize the in-memory descriptor, not the file's actual permissions.
	if err := dacl.SetControl(windows.SE_DACL_AUTO_INHERITED, 0); err != nil {
		return err
	}
	want, err := privateDACL(dir)
	if err != nil {
		return err
	}
	if !owner.Equals(sid) || dacl.String() != want {
		return errors.New("diff snapshot requires an owner-only Windows ACL")
	}
	return nil
}
