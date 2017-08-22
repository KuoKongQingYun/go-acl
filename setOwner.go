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
	err := api.SetSecurityDescriptorOwner(secDesc, owner, true)
	if err != nil {
		return err
	}
	return api.SetFileSecurity(name, api.OWNER_SECURITY_INFORMATION, secDesc)
}
