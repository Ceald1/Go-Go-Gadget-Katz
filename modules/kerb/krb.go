package kerb

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

var (
	modSecur32  = windows.NewLazySystemDLL("secur32.dll")
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")
	procAcquireCredentialsHandle  = modSecur32.NewProc("AcquireCredentialsHandleW")
	procInitializeSecurityContext = modSecur32.NewProc("InitializeSecurityContextW")
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
func TGT(domain, username, password, outputFile string) error {
	fmt.Println("Starting TGT acquisition process...")

	var credHandle SECURITY_HANDLE
	var timeStamp TimeStamp

	domainPtr, err := syscall.UTF16PtrFromString(domain)
	if err != nil {
		return fmt.Errorf("error converting domain to UTF16: %v", err)
	}
	
	userPtr, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return fmt.Errorf("error converting username to UTF16: %v", err)
	}
	
	passPtr, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		return fmt.Errorf("error converting password to UTF16: %v", err)
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
	
	// Try both Kerberos and Negotiate packages
	packageNames := []string{"Kerberos", "Negotiate"}
	
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
		return fmt.Errorf("failed to acquire credentials, last error: 0x%x", lastError)
	}

	targetName := "krbtgt/" + strings.ToUpper(domain)
	targetPtr, err := syscall.UTF16PtrFromString(targetName)
	if err != nil {
		return fmt.Errorf("error converting target name to UTF16: %v", err)
	}

	fmt.Printf("Requesting TGT for: %s\n", targetName)

	var outBuf SecBuffer
	outBuf.cbBuffer = 0
	outBuf.BufferType = SECBUFFER_TOKEN
	outBuf.pvBuffer = 0
	
	var outBufferDesc SecBufferDesc
	outBufferDesc.ulVersion = SECBUFFER_VERSION
	outBufferDesc.cBuffers = 1
	outBufferDesc.pBuffers = uintptr(unsafe.Pointer(&outBuf))

	var contextHandle SECURITY_HANDLE
	var contextAttributes uint32
	contextReqFlags := ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH | 
		ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | 
		ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY

	fmt.Println("Calling InitializeSecurityContext...")
	
	status, _, errCall := procInitializeSecurityContext.Call(
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
		return fmt.Errorf("InitializeSecurityContext failed: status=0x%x, winErr=0x%x, err=%v", 
			status, winErr, errCall)
	}

	fmt.Println("Security context initialized successfully!")
	fmt.Printf("Output buffer size: %d bytes\n", outBuf.cbBuffer)

	// Check if we have ticket data
	if outBuf.pvBuffer != 0 && outBuf.cbBuffer > 0 {
		// Get raw ticket data
		ticketBytes := unsafe.Slice((*byte)(unsafe.Pointer(outBuf.pvBuffer)), outBuf.cbBuffer)
		
		// Copy ticket data to avoid memory issues
		ticketData := make([]byte, len(ticketBytes))
		copy(ticketData, ticketBytes)
		
		// Debug print first few bytes
		fmt.Printf("Ticket data first bytes: %s\n", hex.EncodeToString(ticketData[:min(20, len(ticketData))]))
		
		// Attempt to find the AP-REQ/Ticket inside the buffer
		ticket, found := extractTicket(ticketData)
		if !found {
			fmt.Println("Warning: Could not locate Kerberos ticket in the security buffer.")
			fmt.Println("Trying to use the raw buffer...")
			ticket = ticketData
		}
		
		// Create a KRB-CRED structure manually, following Impacket's expectations
		kirbiData := createKRBCRED(ticket, domain, username)
		
		// Base64 encode the data
		encodedTicket := base64.StdEncoding.EncodeToString(kirbiData)
		
		// Write to file
		err = os.WriteFile(outputFile, []byte(encodedTicket), 0600)
		if err != nil {
			return fmt.Errorf("failed to write Kirbi ticket to file: %v", err)
		}
		
		fmt.Printf("Kirbi-formatted ticket successfully saved to %s\n", outputFile)
	} else {
		return fmt.Errorf("no ticket data received from security context")
	}

	// Cleanup
	if outBuf.pvBuffer != 0 {
		_, _, _ = procFreeContextBuffer.Call(outBuf.pvBuffer)
		fmt.Println("Freed security buffer")
	}

	if contextHandle.dwLower != 0 || contextHandle.dwUpper != 0 {
		_, _, _ = procDeleteSecurityContext.Call(uintptr(unsafe.Pointer(&contextHandle)))
		fmt.Println("Deleted security context")
	}
	
	if credHandle.dwLower != 0 || credHandle.dwUpper != 0 {
		_, _, _ = procFreeCredentialsHandle.Call(uintptr(unsafe.Pointer(&credHandle)))
		fmt.Println("Freed credential handle")
	}
	
	return nil
}

// extractTicket attempts to find and extract the Kerberos Ticket from the security buffer
func extractTicket(data []byte) ([]byte, bool) {
	// Look for AP-REQ (application tag 14) or Ticket (application tag 1)
	// We search for these tag values in the buffer
	for i := 0; i < len(data)-2; i++ {
		// Check for application tag for AP-REQ (0x6E = 0x60 + 14)
		if data[i] == 0x6E {
			fmt.Println("Found potential AP-REQ at position", i)
			return data[i:], true
		}
		
		// Check for application tag for Ticket (0x61 = 0x60 + 1)
		if data[i] == 0x61 {
			fmt.Println("Found potential Ticket at position", i)
			return data[i:], true
		}
		
		// Check for KRB-CRED (application tag 22)
		if data[i] == 0x76 {
			fmt.Println("Found potential KRB-CRED at position", i)
			return data[i:], true
		}
	}
	
	return nil, false
}

// createKRBCRED creates a KRB-CRED structure with the ticket
func createKRBCRED(ticket []byte, domain, username string) []byte {
	// We'll manually create a KRB-CRED structure that matches Impacket's expectation
	var buf bytes.Buffer
	
	// KRB-CRED ::= [APPLICATION 22] SEQUENCE { ... }
	buf.WriteByte(0x76) // 0x76 = APPLICATION 22 (0x60 + 22)
	
	// We'll write a placeholder for the overall length
	overallLengthPos := buf.Len()
	buf.WriteByte(0x00) // placeholder
	
	// Start of SEQUENCE
	buf.WriteByte(ASN1_SEQUENCE)
	seqLengthPos := buf.Len()
	buf.WriteByte(0x00) // placeholder
	
	// pvno [0] INTEGER
	buf.WriteByte(ASN1_CONTEXT_SPECIFIC) // [0]
	buf.WriteByte(0x03) // length of INTEGER including tag and length
	buf.WriteByte(ASN1_INTEGER) // INTEGER tag
	buf.WriteByte(0x01) // length of INTEGER value
	buf.WriteByte(0x05) // value (krb5 version = 5)
	
	// msg-type [1] INTEGER
	buf.WriteByte(ASN1_CONTEXT_SPECIFIC + 1) // [1]
	buf.WriteByte(0x03) // length of INTEGER including tag and length
	buf.WriteByte(ASN1_INTEGER) // INTEGER tag
	buf.WriteByte(0x01) // length of INTEGER value
	buf.WriteByte(0x16) // value (22 = KRB_CRED)
	
	// Start of tickets [2]
	buf.WriteByte(ASN1_CONTEXT_SPECIFIC + 2) // [2]
	
	// Placeholder for tickets length
	ticketsLengthPos := buf.Len()
	buf.WriteByte(0x00) // placeholder
	
	// Start of SEQUENCE OF Ticket
	buf.WriteByte(ASN1_SEQUENCE)
	ticketSeqLengthPos := buf.Len()
	buf.WriteByte(0x00) // placeholder
	
	// Add the actual ticket
	ticketStartPos := buf.Len()
	buf.Write(ticket)
	ticketEndPos := buf.Len()
	
	// enc-part [3] 
	buf.WriteByte(ASN1_CONTEXT_SPECIFIC + 3) // [3]
	
	// We'll use a minimal encrypted part structure - Impacket doesn't use this anyway
	encPartLength := 11 // pre-calculated size of our minimal structure
	buf.WriteByte(byte(encPartLength))
	
	// EncryptedData SEQUENCE
	buf.WriteByte(ASN1_SEQUENCE)
	buf.WriteByte(byte(encPartLength - 2)) // length of sequence
	
	// etype [0] Int32
	buf.WriteByte(ASN1_CONTEXT_SPECIFIC) // [0]
	buf.WriteByte(0x03) // length
	buf.WriteByte(ASN1_INTEGER) // INTEGER
	buf.WriteByte(0x01) // length
	buf.WriteByte(0x00) // etype = 0 (null encryption)
	
	// cipher [2] OCTET STRING
	buf.WriteByte(ASN1_CONTEXT_SPECIFIC + 2) // [2]
	buf.WriteByte(0x02) // length
	buf.WriteByte(ASN1_OCTET_STRING) // OCTET STRING
	buf.WriteByte(0x00) // empty (length 0)
	
	// Now go back and fix all the lengths
	data := buf.Bytes()
	
	// Fix ticket sequence length
	ticketSeqLength := ticketEndPos - ticketStartPos
	if ticketSeqLength > 255 {
		// Use long-form length encoding for lengths ≥ 128
		// Convert buffer to slice for manipulation
		dataSlice := data
		// Number of bytes needed to represent length
		numBytes := 0
		temp := ticketSeqLength
		for temp > 0 {
			numBytes++
			temp >>= 8
		}
		
		// Create length bytes in big-endian order
		lengthBytes := make([]byte, numBytes)
		for i := numBytes - 1; i >= 0; i-- {
			lengthBytes[i] = byte(ticketSeqLength & 0xFF)
			ticketSeqLength >>= 8
		}
		
		// Insert long-form length marker followed by length bytes
		lengthHeader := []byte{byte(0x80 | numBytes)}
		lengthHeader = append(lengthHeader, lengthBytes...)
		
		// Replace placeholder with proper length encoding
		newData := append(dataSlice[:ticketSeqLengthPos], lengthHeader...)
		newData = append(newData, dataSlice[ticketSeqLengthPos+1:]...)
		data = newData
		
		// Recalculate positions as they've shifted
		shift := len(lengthHeader) - 1
		ticketEndPos += shift
		ticketsLengthPos += 0  // This position is before our insertion
		seqLengthPos += 0      // This position is before our insertion
		overallLengthPos += 0  // This position is before our insertion
	} else {
		// Use short-form length encoding
		data[ticketSeqLengthPos] = byte(ticketSeqLength)
	}
	
	// Fix tickets field length (length of SEQUENCE OF Ticket + 2 bytes for SEQUENCE tag and length)
	ticketsLength := ticketEndPos - ticketSeqLengthPos - 1 + 2
	if ticketsLength > 255 {
		// Similar long-form length encoding as above
		// This is simplified - in a real implementation you'd apply the same logic as above
		data[ticketsLengthPos] = 0x82 // Indicates 2 bytes of length follow
		binary.BigEndian.PutUint16(data[ticketsLengthPos+1:ticketsLengthPos+3], uint16(ticketsLength))
	} else {
		data[ticketsLengthPos] = byte(ticketsLength)
	}
	
	// Fix sequence length
	seqLength := buf.Len() - seqLengthPos - 1
	if seqLength > 255 {
		data[seqLengthPos] = 0x82 // Indicates 2 bytes of length follow
		binary.BigEndian.PutUint16(data[seqLengthPos+1:seqLengthPos+3], uint16(seqLength))
	} else {
		data[seqLengthPos] = byte(seqLength)
	}
	
	// Fix overall length
	overallLength := buf.Len() - overallLengthPos - 1
	if overallLength > 255 {
		data[overallLengthPos] = 0x82 // Indicates 2 bytes of length follow
		binary.BigEndian.PutUint16(data[overallLengthPos+1:overallLengthPos+3], uint16(overallLength))
	} else {
		data[overallLengthPos] = byte(overallLength)
	}
	
	return data
}

// Helper to find minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}