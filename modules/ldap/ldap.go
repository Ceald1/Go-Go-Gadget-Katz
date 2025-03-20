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
	procLdapSearch     = modLdap32.NewProc("ldap_search_sW")
	procLdapUnbind     = modLdap32.NewProc("ldap_unbind_s")
	procLdapResult     = modLdap32.NewProc("ldap_result")
	procLdapFirstEntry = modLdap32.NewProc("ldap_first_entry")
	procLdapNextEntry  = modLdap32.NewProc("ldap_next_entry")
	procLdapGetDNW     = modLdap32.NewProc("ldap_get_dnW")
	procLdapGetValues  = modLdap32.NewProc("ldap_get_valuesW")
)

func InitConn(username, domain, password, dc string) (handle uintptr, err error) {
	dnUser := username + "@" + domain

	// Convert DN and password to UTF-16
	bindUser := windows.StringToUTF16Ptr(dnUser)
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
		uintptr(unsafe.Pointer(bindUser)),
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
	// Convert the base and filter to UTF-16
	cBase := windows.StringToUTF16Ptr(base)
	cFilter := windows.StringToUTF16Ptr(filter)

	// Prepare attributes for ldap_search
	var cAttrs []*uint16
	for _, attr := range attrs {
		cAttr := windows.StringToUTF16Ptr(attr)
		cAttrs = append(cAttrs, cAttr)
	}
	// Append a nil pointer to terminate the array (required by ldap_search_s)
	cAttrs = append(cAttrs, nil)

	// Call ldap_search
	var searchResult uintptr
	msgID, _, err := procLdapSearch.Call(
		handle,
		uintptr(unsafe.Pointer(cBase)),
		uintptr(scope),
		uintptr(unsafe.Pointer(cFilter)),
		uintptr(unsafe.Pointer(&cAttrs[0])), // Pass the address of the elements
		uintptr(attrsonly),
		uintptr(unsafe.Pointer(&searchResult)),
	)

	if int(msgID) == -1 {
		return fmt.Errorf("ldap_search failed with error: %v", err)
	}
	entry := LdapFirstEntry(handle, searchResult)
	// fmt.Println(entry)
	for entry != 0 {
		for _, attr := range attrs {
			values := GetValues(entry, handle, attr)
			for _, val := range values {
				fmt.Println(val)
			}
		}

		entry = LdapNextEntry(handle, entry)
		// fmt.Println(entry)
	}
	// fmt.Printf("Search result: 0x%x\n", msgID)
	// fmt.Printf("Search result pointer: 0x%x\n", searchResult)

	// Further processing of the search results would be done here
	return nil
}

// Remember to unbind the LDAP connection when done
func Unbind(handle uintptr) {
	if handle != 0 {
		procLdapUnbind.Call(handle)
	}
}

// get first entry
func LdapFirstEntry(handle, msgID uintptr) (uintptr){
	
	res, _, _ := procLdapFirstEntry.Call(
		handle,
		msgID,
	)
	return res
}
// get next entry
func LdapNextEntry(handle, msgID uintptr) (uintptr){
	res, _, _ := procLdapNextEntry.Call(
		handle,
		msgID,
	)
	return res
}

// get ldap values
func GetValues(entry, handle uintptr, attribute string) (values []string) {
	attr := windows.StringToUTF16Ptr(attribute)
	// Call ldap_get_valuesW
	res, _, _ := procLdapGetValues.Call(
		handle,
		entry,
		uintptr(unsafe.Pointer(attr)),
	)

	if res == 0 {
		return values // Return empty list if no values are found
	}

	// Process the values returned
	// The return value is a pointer to a list of UTF-16 strings.
	// The list is terminated with a nil pointer.
	for {
		// Dereference the current value
		valuePtr := (*uintptr)(unsafe.Pointer(res))
		if *valuePtr == 0 { // Null-terminated pointer
			break
		}

		// Convert the UTF-16 value to a Go string and add it to the list
		value := (*[1 << 20]uint16)(unsafe.Pointer(*valuePtr))
		values = append(values, windows.UTF16ToString(value[:]))

		// Move to the next value in the list
		res += uintptr(unsafe.Sizeof(uintptr(0))) // Move to the next pointer
	}

	// Free the memory allocated for the values

	return values
}
