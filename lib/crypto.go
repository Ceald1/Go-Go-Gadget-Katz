package lib

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/binary"
	// "encoding/hex"
	"math/bits"
	"github.com/jfjallid/go-smb/smb/encoder"
	"fmt"
)


func DecryptAES(key, ciphertext, iv []byte) (plaintext []byte, err error) {
	nullIV := true
	var mode cipher.BlockMode
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if iv != nil {
		mode = cipher.NewCBCDecrypter(block, iv)
		nullIV = false
	} else {
		iv = make([]byte, 16)
	}
	ciphertextLen := len(ciphertext)
	var cipherBuffer []byte
	for i := 0; i < ciphertextLen; i += 16 {
		if nullIV {
			mode = cipher.NewCBCDecrypter(block, iv)
		}
		// Need to calculate 16 bytes block every time and padd with 0 if not enough bytes left
		dataLeft := len(ciphertext[i:])
		if dataLeft < 16 {
			padding := 16 - dataLeft
			cipherBuffer = ciphertext[i : i+dataLeft]
			paddBuffer := make([]byte, padding)
			cipherBuffer = append(cipherBuffer, paddBuffer...)
		} else {
			cipherBuffer = ciphertext[i : i+16]
		}
		// Decryption in-place
		mode.CryptBlocks(cipherBuffer, cipherBuffer)
		plaintext = append(plaintext, cipherBuffer...)
	}
	return plaintext, nil
}
func decryptNTHash(encHash, ridBytes []byte) (hash []byte, err error) {
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
		err = fmt.Errorf("Failed to initialize first DES cipher with error: %v\n", err)
		return nil, err
	}
	dc2, err := des.NewCipher(deskey2)
	if err != nil {
		err = fmt.Errorf("Failed to initialize second DES cipher with error: %v\n", err)
		return nil, err
	}
	dc1.Decrypt(nt1, encHash[:8])
	dc2.Decrypt(nt2, encHash[8:])
	hash = append(hash, nt1...)
	hash = append(hash, nt2...)
	return hash, nil
}
func plusOddParity(input []byte) []byte {
	output := make([]byte, 8)
	output[0] = input[0] >> 0x01
	output[1] = ((input[0] & 0x01) << 6) | (input[1] >> 2)
	output[2] = ((input[1] & 0x03) << 5) | (input[2] >> 3)
	output[3] = ((input[2] & 0x07) << 4) | (input[3] >> 4)
	output[4] = ((input[3] & 0x0f) << 3) | (input[4] >> 5)
	output[5] = ((input[4] & 0x1f) << 2) | (input[5] >> 6)
	output[6] = ((input[5] & 0x3f) << 1) | (input[6] >> 7)
	output[7] = input[6] & 0x7f
	for i := 0; i < 8; i++ {
		if (bits.OnesCount(uint(output[i])) % 2) == 0 {
			output[i] = (output[i] << 1) | 0x1
		} else {
			output[i] = (output[i] << 1) & 0xfe
		}
	}
	return output
}

func GetNT(v []byte) {
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
	
}