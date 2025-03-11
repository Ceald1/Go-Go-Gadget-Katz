package kerb

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unsafe"

)

var (

	procAcquireCredentialsHandleA  = modSecur32.NewProc("AcquireCredentialsHandleA")
	procInitializeSecurityContextA = modSecur32.NewProc("InitializeSecurityContextA")

)


type SEC_WINNT_AUTH_IDENTITY_A struct {
	User           *byte
	UserLength     uint32
	Domain         *byte
	DomainLength   uint32
	Password       *byte
	PasswordLength uint32
	Flags          uint32
}

const (

	SEC_WINNT_AUTH_IDENTITY_ANSI = 1

)

func stringToAnsiPointer(s string) *byte {
	if s == "" {
		return nil
	}
	b := append([]byte(s), 0)
	return &b[0]
}

func TGT(domain, username, password string) (string, error) {
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
		return "", fmt.Errorf("AcquireCredentialsHandleA failed: status=0x%x, winErr=0x%x, err=%v", status, winErr, errCall)
	}

	targetName := fmt.Sprintf("krbtgt/%s", strings.ToUpper(domain))
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
	contextReqFlags := ISC_REQ_MUTUAL_AUTH | ISC_REQ_CONFIDENTIALITY

	status, _, errCall = procInitializeSecurityContextA.Call(
		uintptr(unsafe.Pointer(&credHandle)),
		0,
		uintptr(unsafe.Pointer(targetPtr)),
		uintptr(contextReqFlags),
		0,
		SECURITY_NATIVE_DREP,
		0,
		0,
		uintptr(unsafe.Pointer(&contextHandle)),
		uintptr(unsafe.Pointer(&outBufferDesc)),
		uintptr(unsafe.Pointer(&contextAttributes)),
		uintptr(unsafe.Pointer(&timeStamp)),
	)

	if status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED {
		winErr, _, _ := procGetLastError.Call()
		return "", fmt.Errorf("InitializeSecurityContextA failed: status=0x%x, winErr=0x%x, err=%v", status, winErr, errCall)
	}

	defer procDeleteSecurityContext.Call(uintptr(unsafe.Pointer(&contextHandle)))
	defer procFreeCredentialsHandle.Call(uintptr(unsafe.Pointer(&credHandle)))

	ticketData := unsafe.Slice((*byte)(unsafe.Pointer(outBuf.pvBuffer)), outBuf.cbBuffer)
	ticketCopy := append([]byte(nil), ticketData...)
	encodedTicket := base64.StdEncoding.EncodeToString(ticketCopy)
	return encodedTicket, nil
}
