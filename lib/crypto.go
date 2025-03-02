package lib

// lots of code used from: https://github.com/jfjallid/go-secdump.git

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
	"strings"
	"github.com/jfjallid/go-smb/smb/encoder"
)

// DecryptAES decrypts data using AES in CBC mode.
// If iv is nil, a zero IV will be used for each block.
func DecryptAES(key, ciphertext, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create new AES cipher: %w", err)
	}

	nullIV := iv == nil
	if nullIV {
		iv = make([]byte, 16)
	}

	var plaintext []byte
	var mode cipher.BlockMode
	if !nullIV {
		mode = cipher.NewCBCDecrypter(block, iv)
	}

	ciphertextLen := len(ciphertext)
	for i := 0; i < ciphertextLen; i += 16 {
		if nullIV {
			mode = cipher.NewCBCDecrypter(block, iv)
		}

		var cipherBuffer []byte
		if remaining := len(ciphertext[i:]); remaining < 16 {
			cipherBuffer = make([]byte, 16)
			copy(cipherBuffer, ciphertext[i:])
		} else {
			cipherBuffer = ciphertext[i : i+16]
		}

		decrypted := make([]byte, len(cipherBuffer))
		mode.CryptBlocks(decrypted, cipherBuffer)
		plaintext = append(plaintext, decrypted...)
	}

	return plaintext[:ciphertextLen], nil
}

// decryptNTHash decrypts NT hash using two DES keys derived from the RID
func decryptNTHash(encHash, ridBytes []byte) ([]byte, error) {
	if len(encHash) != 16 || len(ridBytes) != 4 {
		return nil, fmt.Errorf("invalid input lengths: encHash=%d, ridBytes=%d", len(encHash), len(ridBytes))
	}

	nt1 := make([]byte, 8)
	nt2 := make([]byte, 8)
	desSrc1 := make([]byte, 7)
	desSrc2 := make([]byte, 7)

	shift1 := []int{0, 1, 2, 3, 0, 1, 2}
	shift2 := []int{3, 0, 1, 2, 3, 0, 1}

	for i := 0; i < 7; i++ {
		desSrc1[i] = ridBytes[shift1[i]]
		desSrc2[i] = ridBytes[shift2[i]]
	}

	deskey1 := plusOddParity(desSrc1)
	deskey2 := plusOddParity(desSrc2)

	dc1, err := des.NewCipher(deskey1)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize first DES cipher: %w", err)
	}

	dc2, err := des.NewCipher(deskey2)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize second DES cipher: %w", err)
	}

	dc1.Decrypt(nt1, encHash[:8])
	dc2.Decrypt(nt2, encHash[8:])

	return append(nt1, nt2...), nil
}

func plusOddParity(input []byte) []byte {
	if len(input) != 7 {
		return nil
	}

	output := make([]byte, 8)
	output[0] = input[0] >> 1
	output[1] = ((input[0] & 0x01) << 6) | (input[1] >> 2)
	output[2] = ((input[1] & 0x03) << 5) | (input[2] >> 3)
	output[3] = ((input[2] & 0x07) << 4) | (input[3] >> 4)
	output[4] = ((input[3] & 0x0f) << 3) | (input[4] >> 5)
	output[5] = ((input[4] & 0x1f) << 2) | (input[5] >> 6)
	output[6] = ((input[5] & 0x3f) << 1) | (input[6] >> 7)
	output[7] = input[6] & 0x7f

	for i := 0; i < 8; i++ {
		output[i] = output[i] << 1
		if bits.OnesCount(uint(output[i]))%2 == 0 {
			output[i] |= 1
		}
	}

	return output
}

// GetNT extracts and processes NT hash information from a SAM entry
func GetNT(v []byte, rid uint32, sysKey []byte) sam_account {
	cred := &UserCreds{RID: rid} // Set RID that was missing in original
	var acc sam_account

	offsetName := binary.LittleEndian.Uint32(v[0x0c:]) + 0xcc
	szName := binary.LittleEndian.Uint32(v[0x10:])
	cred.Username, _ = encoder.FromUnicodeString(v[offsetName : offsetName+szName])

	szNT := binary.LittleEndian.Uint32(v[0xac:])
	offsetHashStruct := binary.LittleEndian.Uint32(v[0xa8:]) + 0xcc

	if szNT == 0 {
		return acc
	}

	switch szNT {
	case 0x14:
		offsetNTHash := offsetHashStruct + 4
		cred.AES = false
		cred.Data = make([]byte, 16)
		copy(cred.Data, v[offsetNTHash:offsetNTHash+16])
	case 0x38:
		offsetIV := offsetHashStruct + 8
		offsetNTHash := offsetHashStruct + 24
		cred.AES = true
		cred.Data = make([]byte, 16)
		cred.IV = make([]byte, 16)
		copy(cred.Data, v[offsetNTHash:offsetNTHash+16])
		copy(cred.IV, v[offsetIV:offsetIV+16])
	case 0x18:
		cred.AES = true
		cred.Data = []byte{} // Empty Hash
		return acc
	default:
		return acc
	}

	acc = sam_account{
		Name: cred.Username,
		Rid:  cred.RID,
	}

	if cred.AES {
		hash, err := DecryptAESHash(cred.Data, cred.IV, sysKey, cred.RID)
		if err == nil && ValidateDecryptedHash(hash){
			acc.Nthash = hex.EncodeToString(hash)
		}
	}

	return acc
}

// DecryptAESHash decrypts an AES-encrypted NT hash
func DecryptAESHash(doubleEncHash, encHashIV, syskey []byte, rid uint32) ([]byte, error) {
	ridBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ridBytes, rid)

	block, err := aes.NewCipher(syskey)
	if err != nil {
		return nil, fmt.Errorf("failed to init AES key: %w", err)
	}

	encHash := make([]byte, 16)
	mode := cipher.NewCBCDecrypter(block, encHashIV)
	mode.CryptBlocks(encHash, doubleEncHash)

	return decryptNTHash(encHash, ridBytes)
}
// IsValidNTHash checks if a hash is a valid NT hash
func IsValidNTHash(hash string) bool {
    // Check length of hex string (32 characters for 16 bytes)
    if len(hash) != 32 {
        return false
    }

    // Check if string is valid hex
    _, err := hex.DecodeString(hash)
    if err != nil {
        return false
    }

    // Check if hash is all zeros (might indicate empty/invalid hash)
    if hash == strings.Repeat("0", 32) {
        return false
    }

    return true
}

// ValidateDecryptedHash checks if the decrypted hash is valid
func ValidateDecryptedHash(hash []byte) bool {
    // Check if hash has correct length
    if len(hash) != 16 {
        return false
    }

    // Check if hash is all zeros
    allZeros := true
    for _, b := range hash {
        if b != 0 {
            allZeros = false
            break
        }
    }
    if allZeros {
        return false
    }

    return true
}