package kerb // this shit don't work. DO NOT USE!

import (
	"encoding/base64"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modSecur32  = windows.NewLazySystemDLL("secur32.dll")
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")
	procAcquireCredentialsHandle  = modSecur32.NewProc("AcquireCredentialsHandleW")
	procInitializeSecurityContextW = modSecur32.NewProc("InitializeSecurityContextw")
	procGetLastError              = modKernel32.NewProc("GetLastError")
	procFreeContextBuffer         = modSecur32.NewProc("FreeContextBuffer")
	procDeleteSecurityContext     = modSecur32.NewProc("DeleteSecurityContext")
	procFreeCredentialsHandle     = modSecur32.NewProc("FreeCredentialsHandle")
	procExportSecurityContext     = modSecur32.NewProc("ExportSecurityContext")
)

type SECURITY_HANDLE struct {
	dwLower uintptr
	dwUpper uintptr
}

type TimeStamp windows.Filetime

type SecBuffer struct {
	cbBuffer   uint32
	BufferType uint32
	pvBuffer   uintptr
}

type SecBufferDesc struct {
	ulVersion uint32
	cBuffers  uint32
	pBuffers  uintptr
}

type SEC_WINNT_AUTH_IDENTITY_W struct {
	User           *uint16
	UserLength     uint32
	Domain         *uint16
	DomainLength   uint32
	Password       *uint16
	PasswordLength uint32
	Flags          uint32
}

const (
	SEC_E_OK                        = 0
	SEC_I_CONTINUE_NEEDED           = 0x00090312
	SECPKG_CRED_OUTBOUND            = 2
	SEC_WINNT_AUTH_IDENTITY_UNICODE = 2
	SECBUFFER_VERSION               = 0
	SECBUFFER_TOKEN                 = 2
	SECURITY_NATIVE_DREP            = 0x10
	ISC_REQ_DELEGATE               = 0x00000001
	ISC_REQ_MUTUAL_AUTH            = 0x00000002
	ISC_REQ_REPLAY_DETECT          = 0x00000004
	ISC_REQ_SEQUENCE_DETECT        = 0x00000008
	ISC_REQ_CONFIDENTIALITY        = 0x00000010
	ISC_REQ_ALLOCATE_MEMORY        = 0x00000100
	SECPKG_CONTEXT_EXPORT_OPEN     = 0x00000001
)

// ASN.1 tag constants
const (
	ASN1_SEQUENCE           = 0x30
	ASN1_APPLICATION        = 0x60
	ASN1_CONTEXT_SPECIFIC   = 0xA0
	ASN1_INTEGER            = 0x02
	ASN1_OCTET_STRING       = 0x04
	ASN1_BIT_STRING         = 0x03
	ASN1_OBJECT_IDENTIFIER  = 0x06
	ASN1_ENUMERATED         = 0x0A
	ASN1_GENERALSTRING      = 0x1B
	ASN1_GENERALIZEDTIME    = 0x18
)

// TGT attempts to acquire a Kerberos Ticket Granting Ticket and returns it in kirbi format
func TGTBrokenShit(domain, username, password string) (string, error) {
    fmt.Println("Starting TGT acquisition process...")

    var credHandle SECURITY_HANDLE
    var timeStamp TimeStamp

    domainPtr, err := syscall.UTF16PtrFromString(domain)
    if err != nil {
        return "", fmt.Errorf("error converting domain to UTF16: %v", err)
    }
    
    userPtr, err := syscall.UTF16PtrFromString(username)
    if err != nil {
        return "", fmt.Errorf("error converting username to UTF16: %v", err)
    }
    
    passPtr, err := syscall.UTF16PtrFromString(password)
    if err != nil {
        return "", fmt.Errorf("error converting password to UTF16: %v", err)
    }

    fmt.Println("Credentials converted to UTF16")

    authIdentity := SEC_WINNT_AUTH_IDENTITY_W{
        User:           userPtr,
        UserLength:     uint32(len(username)),
        Domain:         domainPtr,
        DomainLength:   uint32(len(domain)),
        Password:       passPtr,
        PasswordLength: uint32(len(password)),
        Flags:          SEC_WINNT_AUTH_IDENTITY_UNICODE,
    }

    var success bool
    var lastError uintptr
    
    // Use only Kerberos authentication package
    packageNames := []string{"Kerberos"}
    
    for _, packageName := range packageNames {
        fmt.Printf("Trying authentication package: %s\n", packageName)
        
        packagePtr, err := syscall.UTF16PtrFromString(packageName)
        if err != nil {
            fmt.Printf("Error converting package name: %v\n", err)
            continue
        }
        
        credHandle = SECURITY_HANDLE{0, 0}
        
        status, _, errCall := procAcquireCredentialsHandle.Call(
            0, 
            uintptr(unsafe.Pointer(packagePtr)),
            SECPKG_CRED_OUTBOUND,
            0, 
            uintptr(unsafe.Pointer(&authIdentity)),
            0, 
            0, 
            uintptr(unsafe.Pointer(&credHandle)),
            uintptr(unsafe.Pointer(&timeStamp)),
        )
        
        if status == SEC_E_OK {
            fmt.Printf("Successfully acquired credentials using %s\n", packageName)
            success = true
            break
        } else {
            winErr, _, _ := procGetLastError.Call()
            fmt.Printf("Failed to acquire credentials using %s: status=0x%x, winErr=0x%x, err=%v\n", 
                packageName, status, winErr, errCall)
            lastError = status
        }
    }
    
    if !success {
        return "", fmt.Errorf("failed to acquire credentials, last error: 0x%x", lastError)
    }

    targetName := fmt.Sprintf("krbtgt/%s", strings.ToUpper(domain))
    targetPtr, err := syscall.UTF16PtrFromString(targetName)
    if err != nil {
        return "", fmt.Errorf("error converting target name to UTF16: %v", err)
    }

    fmt.Printf("Requesting TGT for: %s\n", targetName)

    // Increase buffer size
    var outBuf SecBuffer
    outBuf.cbBuffer = 2048  // Set a larger buffer size
    outBuf.BufferType = SECBUFFER_TOKEN
    outBuf.pvBuffer = uintptr(unsafe.Pointer(&make([]byte, outBuf.cbBuffer)[0]))  // Use a slice as buffer

    var outBufferDesc SecBufferDesc
    outBufferDesc.ulVersion = SECBUFFER_VERSION
    outBufferDesc.cBuffers = 1
    outBufferDesc.pBuffers = uintptr(unsafe.Pointer(&outBuf))

    var contextHandle SECURITY_HANDLE
    var contextAttributes uint32
    contextReqFlags := ISC_REQ_MUTUAL_AUTH | ISC_REQ_CONFIDENTIALITY

    fmt.Println("Calling InitializeSecurityContextA...")
    
    status, _, errCall := procInitializeSecurityContextW.Call(
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
        return "", fmt.Errorf("InitializeSecurityContextA failed: status=0x%x, winErr=0x%x, err=%v", 
            status, winErr, errCall)
    }

    fmt.Println("Security context initialized successfully!")
	defer procDeleteSecurityContext.Call(uintptr(unsafe.Pointer(&contextHandle)))
	defer procFreeCredentialsHandle.Call(uintptr(unsafe.Pointer(&credHandle)))

        // fmt.Printf("Ticket data received. Buffer size: %d bytes\n", outBuf.cbBuffer)
        // Base64 encode the data
        tickData := unsafe.Slice((*byte)(unsafe.Pointer(outBuf.pvBuffer)), outBuf.cbBuffer)
        ticketCopy := append([]byte(nil), tickData...) // Create a copy

		// Now you can safely return the copy and access it after the function
		encodedTicket := base64.StdEncoding.EncodeToString(ticketCopy)
		return encodedTicket, nil
}
