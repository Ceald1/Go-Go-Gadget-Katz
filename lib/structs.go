package lib
import (
	"encoding/binary"
	"fmt"
	"log"
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
type sam_account struct {
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
