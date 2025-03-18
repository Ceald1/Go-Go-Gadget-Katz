package ldap

type LDAPMessage struct {
	Lm_msgid               uint32
	Lm_msgtype             uint32
	Lm_ber                 uintptr
	Lm_chain               *LDAPMessage
	Lm_next                *LDAPMessage
	Lm_time                uintptr
	Connection             uintptr
	Request                uintptr
	Lm_returncode          uint32
	Lm_referral            uint16
	Lm_chased              uint8   // Use uint8 for boolean (0 or 1)
	Lm_eom                 uint8   // Use uint8 for boolean (0 or 1)
	ConnectionReferenced   uint8   // Use uint8 for boolean (0 or 1)
}
