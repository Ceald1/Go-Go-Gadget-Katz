package ldap

type LDAP uintptr

type LDAValues uintptr

type LDAPMessage struct {
	msg uintptr
	ldap LDAP
}

type LDAPValues uintptr