package ptt
import (

	// handleHelpers "katz/katz/modules/kerb/ticketdump"

	"golang.org/x/sys/windows"
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
type KerbProtocolMessageType uint32
const (
	KerbSubmitTicketMessagetype KerbProtocolMessageType = 21
)
const (
	SEC_WINNT_AUTH_IDENTITY_ANSI = 1
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


type KERB_SUBMIT_TKT_REQUEST struct {
	MessageType       KerbProtocolMessageType
	LogonId           windows.LUID
	TicketFlags       uint32

	Length			  uint32
	Value			  uintptr
	KerbCredSize	  uint32
	KerbCredOffset	  uint32
	TicketData		  []byte
	Key				  *KERB_CRYPTO_KEY

}

// MessageType       KerbProtocolMessageType
// LogonId           windows.LUID
// TargetName        LsaString
// TicketFlags       uint32
// CacheOptions      uint32
// EncryptionType    int32
// CredentialsHandle SecurityHandle


type KERB_CRYPTO_KEY struct {
	KeyType uint32
	Length uint32
	Value uintptr
}
type SECURITY_HANDLE struct {
	dwLower uintptr
	dwUpper uintptr
}
type TimeStamp windows.Filetime

type SecBufferDesc struct {
	ulVersion uint32
	cBuffers  uint32
	pBuffers  uintptr
}
type SecBuffer struct {
	cbBuffer   uint32
	BufferType uint32
	pvBuffer   uintptr
}


