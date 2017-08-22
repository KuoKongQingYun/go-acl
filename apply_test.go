package acl

import (
	"fmt"
	"testing"

	"golang.org/x/sys/windows"
)

func TestApply(t *testing.T) {
	if err := Apply(
		`D:\1.txt`,
		true,
		true,
		GrantName(windows.GENERIC_ALL, "CREATOR OWNER"),
	); err != nil {
		fmt.Println(err)
		t.Fatal(err)
	}
}
