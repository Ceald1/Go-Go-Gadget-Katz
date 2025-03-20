package rpc

import (
	"golang.org/x/sys/windows"
)


var (
	modRPC = windows.NewLazySystemDLL("rpc.dll")
	modMidles = windows.NewLazySystemDLL("midles.dll")
	modDsGetDC = windows.NewLazySystemDLL("DsGetDC.dll")
	modNTSecAPI = windows.NewLazySystemDLL("NTSecAPI.dll")
	modsspi = windows.NewLazySystemDLL("sspi.dll")
	modsddl = windows.NewLazySystemDLL("sddl.dll")
	modmsasn1 = windows.NewLazySystemDLL("msasn1.dll")

	RpcStringBindingCompose = modRPC.NewProc("RpcStringBindingComposeW")
	RpcBindingFromStringBinding = modRPC.NewProc("RpcBindingFromStringBindingW")
	RpcBindingFree = modRPC.NewProc("RpcBindingFree")
	RpcBindingSetOption = modRPC.NewProc("RpcBindingSetOption")
)


func CreateBind()