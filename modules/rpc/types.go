package rpc


type RPC_SECURITY_QOS struct {
	Version            uint32
	Capabilities       uint32
	IdentityTracking   uint32
	ImpersonationType  uint32
}

const (
	RPC_C_SECURITY_QOS_VERSION              = 1
	RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH      = 0x1
	RPC_C_QOS_CAPABILITIES_IGNORE_DELEGATE_FAILURE = 0x8
	RPC_C_QOS_IDENTITY_STATIC               = 0
	RPC_C_IMP_LEVEL_DELEGATE                = 3
)

type RPC_BINDING_HANDLE uintptr
type RCP_AUTH_IDENTITY_HANDLE uintptr