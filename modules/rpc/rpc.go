package rpc

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)


var (
	modRPC = windows.NewLazySystemDLL("rpc.dll")
	modMidles = windows.NewLazySystemDLL("midles.dll")
	modNTSecAPI = windows.NewLazySystemDLL("NTSecAPI.dll")
	modsspi = windows.NewLazySystemDLL("sspi.dll")
	modsddl = windows.NewLazySystemDLL("sddl.dll")
	modmsasn1 = windows.NewLazySystemDLL("msasn1.dll")

	RpcStringBindingCompose = modRPC.NewProc("RpcStringBindingComposeW")
	RpcBindingFromStringBinding = modRPC.NewProc("RpcBindingFromStringBindingW")
	RpcBindingFree = modRPC.NewProc("RpcBindingFree")
	RpcBindingSetOption = modRPC.NewProc("RpcBindingSetOption")
)


func CreateBind(uuid, protSeq, networkAddr, endpoint, service string, 
				addServiceToNetworkAddr bool, authnSvc uint32, 
				hAuth *windows.Handle, impersonationType uint32, 
				hBinding *windows.Handle, rpcSecurityCallback uintptr) {
	// Create RPC Bind
	var (
		// status bool
		rpcStatus uintptr
		stringBinding *uint16
	)
	SecurityQOS := RPC_SECURITY_QOS{
		Version:RPC_C_SECURITY_QOS_VERSION ,
		Capabilities:     RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH,
		IdentityTracking: RPC_C_QOS_IDENTITY_STATIC,
		ImpersonationType: impersonationType,
	}
	if impersonationType == RPC_C_IMP_LEVEL_DELEGATE {
		SecurityQOS.Capabilities |= RPC_C_QOS_CAPABILITIES_IGNORE_DELEGATE_FAILURE
	}
	rpcStatus, _, _ = RpcStringBindingCompose.Call(
		uintptr(unsafe.Pointer(&uuid)),
		uintptr(unsafe.Pointer(&protSeq)),
		uintptr(unsafe.Pointer(&networkAddr)),
		uintptr(unsafe.Pointer(&endpoint)),
		0,
		uintptr(unsafe.Pointer(stringBinding)),
	)
	fmt.Printf("ComposeBinding 0x%x", rpcStatus)
	if rpcStatus == 0 {
		rpcStatus, _, _ = RpcBindingFromStringBinding.Call(
			uintptr(unsafe.Pointer(stringBinding)),
			uintptr(unsafe.Pointer(&hBinding)),
		)
		fmt.Printf("StringBinding 0x%x", rpcStatus)
	}
	

}