package acl

import (
	"fmt"
	"testing"
	"unsafe"

	"github.com/KuoKongQingYun/go-acl/api"

	"golang.org/x/sys/windows"
)

func TestSetOwner(t *testing.T) {
	var (
		sid    = make([]byte, api.SECURITY_MAX_SID_SIZE)
		sidLen = uint32(unsafe.Sizeof(sid))
	)
	err := api.CreateWellKnownSid(
		api.WinBuiltinAdministratorsSid,
		nil,
		(*windows.SID)(unsafe.Pointer(&sid[0])),
		&sidLen,
	)
	fmt.Println(err)
	fmt.Println(sid)
	fmt.Println(sidLen)
	fmt.Println(SetOwner(`D:\1.txt`, true, (*windows.SID)(unsafe.Pointer(&sid[0]))))
}
