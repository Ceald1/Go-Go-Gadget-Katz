package ldap

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modLdap32          = windows.NewLazySystemDLL("Wldap32.dll")
	procLdapBindS      = modLdap32.NewProc("ldap_bind_sW")
	procLdapInitS      = modLdap32.NewProc("ldap_initW")
	procLdapSearch      = modLdap32.NewProc("ldap_search")
	procLdapUnbind     = modLdap32.NewProc("ldap_unbind_s")
	procLdapResult     = modLdap32.NewProc("ldap_result")
	procLdapFirstEntry  = modLdap32.NewProc("ldap_first_entry")
	procLdapNextEntry   = modLdap32.NewProc("ldap_next_entry")
	procLdapGetDNW     = modLdap32.NewProc("ldap_get_dnW")
	procLdapGetValues   = modLdap32.NewProc("ldap_get_valuesW")
)

func InitConn(username, domain, password, dc string) (handle uintptr, err error) {
	dnUser  := username + "@" + domain

	// Convert DN and password to UTF-16
	bindUser  := windows.StringToUTF16Ptr(dnUser )
	bindPasswd := windows.StringToUTF16Ptr(password)

	// Initialize LDAP connection
	handle = InitHandle(dc)
	if handle == 0 {
		fmt.Println("[-] Failed to initialize LDAP connection")
		return
	}

	// Try binding with credentials (simple bind)
	ret, _, _ := procLdapBindS.Call(
		handle,
		uintptr(unsafe.Pointer(bindUser )),
		uintptr(unsafe.Pointer(bindPasswd)),
		uintptr(0x80), // Simple bind
	)

	// Check the return value from bind
	fmt.Printf("[*] ldap_bind_sW returned: 0x%x\n", ret)
	if ret == 0 {
		fmt.Println("[+] Authentication successful")
		err = nil
	} else {
		if ret == 0x31 {
			err = fmt.Errorf("Invalid credentials: Check username, password, or DN format")
		} else {
			err = fmt.Errorf("Authentication failed with error: 0x%x\n", ret)
		}
	}
	return handle, err
}

// InitHandle initializes an LDAP connection handle
func InitHandle(dc string) uintptr {
	port := 389 // Use 389 for non-SSL LDAP; switch to 636 for LDAPS with proper SSL setup
	domainController := windows.StringToUTF16Ptr(dc)

	// Initialize LDAP connection
	ldapHandle, _, _ := procLdapInitS.Call(
		uintptr(unsafe.Pointer(domainController)),
		uintptr(uint32(port)), // Convert int to uint32
	)

	if ldapHandle == 0 {
		fmt.Println("[-] ldap_initW failed")
	}
	return ldapHandle
}

func LdapSearch(handle uintptr, base string, scope uint32, filter string, attrs []string, attrsonly uint32) error {
	// Constructing search request
	cBase := windows.StringToUTF16Ptr(base)
	cFilter := windows.StringToUTF16Ptr(filter)

	// Prepare attributes for ldap_search
	var cAttrs []*uint16
	for _, attr := range attrs {
		cAttr := windows.StringToUTF16Ptr(attr)
		cAttrs = append(cAttrs, cAttr)
	}
	// Append a nil pointer to terminate the array
	cAttrs = append(cAttrs, nil)

	// Call ldap_search
	for i, _ := range cAttrs {
		if cAttrs[i] != nil {
			msgID, _, err := procLdapSearch.Call(
				handle,
				uintptr(unsafe.Pointer(cBase)),
				uintptr(scope),
				uintptr(unsafe.Pointer(cFilter)),
				uintptr(unsafe.Pointer(&cAttrs[i])), // Pass the address of the elements
				uintptr(attrsonly),
			)

			if msgID == 0 {
				return fmt.Errorf("ldap_search failed with error: %v", err)
			}
		}
	}

	// Process results (this is a simplified example)
	// You should implement proper result handling here
	return nil
}

// Remember to unbind the LDAP connection when done
func Unbind(handle uintptr) {
	if handle != 0 {
		procLdapUnbind.Call(handle)
	}
}