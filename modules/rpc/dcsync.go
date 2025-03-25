package rpc

import (
	"fmt"
	ldap "katz/katz/modules/ldap"
)




func DCSync(username, password, dcHost, domain string, port uint32) {
	// Initialize the ldap connection to make DC sync faster
	handle, err := ldap.InitConn(username, domain, password, dcHost)
	if err != nil {
		fmt.Println("Error initializing LDAP connection:", err)
		return
	}

	// Perform the search
	attrs := []string{"sAMAccountName", "unicodePwd"} // Specify attributes you want to retrieve
	err = ldap.LdapSearch(handle, "dc=test,dc=local", 2, "(&(objectClass=Person)(objectClass=User))", attrs, 0)
	if err != nil {
		fmt.Println("Error in LDAP search:", err)
	}
}