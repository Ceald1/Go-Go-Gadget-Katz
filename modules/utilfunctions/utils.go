package utilfunctions

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modnetapi32 = windows.NewLazySystemDLL("netapi32.dll")
procDsGetDcName = modnetapi32.NewProc("DsGetDcNameW")
)

func GetDCName(domainName string) (dcName string){
	var ret uintptr
	var cInfo *DOMAIN_CONTROLLER_INFO
	var flags uint32
	dnp := windows.StringToUTF16Ptr(domainName)
	flags = DS_IS_DNS_NAME | DS_RETURN_DNS_NAME
	ret, _, _ = procDsGetDcName.Call(
		0,
		uintptr(unsafe.Pointer(dnp)),
		0,
		0,
		
		uintptr(flags),
		uintptr(unsafe.Pointer(&cInfo)),
	)
	if ret != 0 {
		fmt.Printf("0x%x\n",ret)
		return
	}
	valuePtr := (*uintptr)(unsafe.Pointer(&cInfo.DomainControllerName))
	value := (*[1 << 20]uint16)(unsafe.Pointer(*valuePtr))
	dcName = windows.UTF16ToString(value[:])
	dcName = strings.Replace(dcName,`\\`, "", -1)
	fmt.Println(dcName)
	return
}