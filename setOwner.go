package acl

import (
	"fmt"

	"github.com/KuoKongQingYun/go-acl/api"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

//
func SetOwner(name string, inherit bool, owner *windows.SID) error {
	fmt.Println(winio.EnableProcessPrivileges([]string{`SeTakeOwnershipPrivilege`}))
	var securityDescriptor windows.Handle
	var oldDacl windows.Handle
	err := api.GetNamedSecurityInfo(
		name,
		api.SE_FILE_OBJECT,
		api.DACL_SECURITY_INFORMATION,
		nil,
		nil,
		&oldDacl,
		nil,
		&securityDescriptor,
	)
	defer windows.LocalFree(securityDescriptor)
	if err != nil {
		return err
	}
	var secInfo uint32
	if !inherit {
		secInfo = api.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		secInfo = api.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	err = api.SetNamedSecurityInfo(
		name,
		api.SE_FILE_OBJECT,
		secInfo|api.OWNER_SECURITY_INFORMATION,
		owner,
		nil,
		0,
		0,
	)
	if err != nil {
		return err
	}
	return api.SetFileSecurity(
		name,
		api.OWNER_SECURITY_INFORMATION,
		(*api.SECURITY_DESCRIPTOR)(owner),
	)
}
