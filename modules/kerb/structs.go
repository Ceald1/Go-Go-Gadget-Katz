package kerb

// import "syscall"

type SEC_WINNT_AUTH_IDENTITY struct {
	User           *uint16
	UserLength     uint32
	Domain         *uint16
	DomainLength   uint32
	Password       *uint16
	PasswordLength uint32
	Flags          uint32
}

// SecBuffer represents a security buffer
type SecBuffer struct {
	cbBuffer   uint32
	BufferType uint32
	pvBuffer   uintptr
}

// SecBufferDesc describes security buffers
type SecBufferDesc struct {
	ulVersion uint32
	cBuffers  uint32
	pBuffers  *SecBuffer
}

// SecHandle represents a security handle
type SecHandle struct {
	dwLower uintptr
	dwUpper uintptr
}

// TimeStamp represents a security timestamp
type TimeStamp struct {
	LowPart  uint32
	HighPart int32
}