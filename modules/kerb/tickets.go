package kerb

import (
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

func TGT(domain, username, password string) ([]byte, error) {
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
	contextReqFlags := SECPKG_CRED_OUTBOUND

	status, _, errCall = procInitializeSecurityContextA.Call(
		uintptr(unsafe.Pointer(&credHandle)),
		0,
		uintptr(unsafe.Pointer(targetPtr)),
		uintptr(contextReqFlags),
		0,
		ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH | ISC_REQ_ALLOCATE_MEMORY , // Kerberos Flags
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

	defer procDeleteSecurityContext.Call(uintptr(unsafe.Pointer(&contextHandle)))
	defer procFreeCredentialsHandle.Call(uintptr(unsafe.Pointer(&credHandle)))

	ticketData := unsafe.Slice((*byte)(unsafe.Pointer(outBuf.pvBuffer)), outBuf.cbBuffer)
	ticketCopy := append([]byte(nil), ticketData...)
	return ticketCopy, nil
}

type KRBCred struct {
	Ticket    []byte `asn1:"tag:0,optional"`
	Encrypted []byte `asn1:"tag:1"`
}
<<<<<<< HEAD
=======


func KerberosInit() (hLsaConnection *windows.Handle, kerberosPackageName *UNICODE_STRING, err error) {
	var status uintptr
	var MICROSOFT_KERBEROS_NAME_A *uint16
	MICROSOFT_KERBEROS_NAME_A, err = windows.UTF16PtrFromString("Kerberos")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert Kerberos string to UTF16: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(MICROSOFT_KERBEROS_NAME_A)))

	status, _, err = procLsaConnectUntrusted.Call(uintptr(unsafe.Pointer(&hLsaConnection)))
	if status != 0 {
		return nil, nil, fmt.Errorf("LsaConnectUntrusted failed with status 0x%x: %w", status, err)
	}

	kerberosPackageName = &UNICODE_STRING{
		Length:        uint16(len("Kerberos") * 2),
		MaximumLength: uint16((len("Kerberos") + 1) * 2),
		Buffer:        MICROSOFT_KERBEROS_NAME_A,
	}

	return hLsaConnection, kerberosPackageName, nil
}

type KERB_RETRIEVE_TKT_REQUEST struct {
	MessageType 		uint32
	LogonId				windows.LUID
	TargetName			UNICODE_STRING
	TicketFlags			uint32
	CacheOptions		uint32
	EncryptionType		int32
	CredentialHandle	SECURITY_HANDLE
	UNK					uintptr
	TargetNameData		[]byte
}

type KERB_RETRIEVE_TKT_RESPONSE struct {
	Ticket KERB_EXTERNAL_TICKET
}
func (r *KERB_RETRIEVE_TKT_RESPONSE) From_buffer_copy(buffer []byte) {
	reader := bytes.NewReader(buffer)
	_ = reader
	binary.Read(reader, binary.LittleEndian, &r.Ticket)
}

type PKERB_EXTERNAL_NAME struct {
	NameType int16
	NameCount uint16
	Names UNICODE_STRING
}
type KERB_CRYPTO_KEY struct {
	KeyType int32 
	Length uint32
	Value uintptr
}
type KERB_EXTERNAL_TICKET struct {
	ServiceName *PKERB_EXTERNAL_NAME
	TargetName *PKERB_EXTERNAL_NAME
	ClientName *PKERB_EXTERNAL_NAME
	DomainName UNICODE_STRING
	TargetDomainName UNICODE_STRING
	AltTargetDomainName UNICODE_STRING
	SessionKey KERB_CRYPTO_KEY
	TicketFlags uint32
	Flags uint32
	KeyExpirationTime int64
	StartTime int64
	EndTime int64
	RenewUntil int64
	TimeSkew int64
	EncodedTicketSize uint32
	EncodedTicket uintptr
}

func Retrieve_tick_Helper(targetname string, logonid int, temp_offset int) (KERB_RETRIEVE_TKT_REQUEST){
	TickFlags := ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH | ISC_REQ_ALLOCATE_MEMORY // Kerberos Flags
	CacheOptions := 0x8
	EncryptionType := 0x0
	targetNameEnc, _ := windows.UTF16PtrFromString(targetname)
	targData := make([]byte, len(targetname))
	var Handle SECURITY_HANDLE
	targetNameUnicode := &UNICODE_STRING{ // convert target name bs
		Length:        uint16(len(targetname)),
		MaximumLength: uint16(len(targetname) + 1),
		Buffer:        targetNameEnc,
	}
	req := KERB_RETRIEVE_TKT_REQUEST{
		MessageType: 8, // retrieve ticket
		// LogonId: windows.LUID(0), // current logon
		TargetName: *targetNameUnicode,
		TicketFlags: uint32(TickFlags),
		CacheOptions: uint32(CacheOptions),
		EncryptionType: int32(EncryptionType),
		CredentialHandle: Handle,
		TargetNameData: targData,

	}
	return req
}

func Extract_Tick(lsa_handle *windows.Handle, package_id *UNICODE_STRING, target_name string) (*KERB_RETRIEVE_TKT_RESPONSE, error) {
	message := Retrieve_tick_Helper(target_name, 0, 0)
	var responseSize uint32
	var responseBuffer *byte

	status, _, err := procLsaCallAuthenticationPackage.Call(
		uintptr(*lsa_handle),
		uintptr(unsafe.Pointer(package_id)),
		uintptr(unsafe.Pointer(&message)),
		uintptr(unsafe.Pointer(&responseSize)),
		uintptr(unsafe.Pointer(&responseBuffer)),
	)
	
	if status != 0 {
		return nil, fmt.Errorf("LsaCallAuthenticationPackage failed with status 0x%x: %w", status, err)
	}

	if responseBuffer == nil {
		return nil, fmt.Errorf("no response data received from LsaCallAuthenticationPackage")
	}

	// Make sure we free the response buffer when we're done
	// defer procLsaFreeReturnBuffer.Call(uintptr(unsafe.Pointer(responseBuffer)))

	// Convert the response buffer to our response type
	response := (*KERB_RETRIEVE_TKT_RESPONSE)(unsafe.Pointer(&responseBuffer))
	
	// Create a copy of the response data since the buffer will be freed
	responseCopy := *response
	
	return &responseCopy, nil
}

func TGS(tgt []byte, hLsaConnection windows.Handle) (ticket []byte, err error){
	// Get a TGS using LsaCallAuthenticationPackage

	if err != nil {
		return
	}
	return
}
>>>>>>> d9d4d23 (writing functions for exporting TGTs)
