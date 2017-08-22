package acl

import (
	"github.com/KuoKongQingYun/go-acl/api"
	"golang.org/x/sys/windows"
)

//
func SetOwner(name string, inherit bool, owner *windows.SID) error {
	var secDesc *api.SECURITY_DESCRIPTOR
	api.GetNamedSecurityInfo(
		name,
		api.SE_FILE_OBJECT,
		api.DACL_SECURITY_INFORMATION,
		nil,
		nil,
		nil,
		nil,
		&secDesc,
	)
	var secInfo uint32
	if !inherit {
		secInfo = api.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		secInfo = api.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	return api.SetNamedSecurityInfo(
		name,
		api.SE_FILE_OBJECT,
		secInfo|api.OWNER_SECURITY_INFORMATION,
		owner,
		nil,
		0,
		0,
	)
}
