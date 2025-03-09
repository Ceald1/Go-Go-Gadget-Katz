package kerb

import (
	"encoding/asn1"
	"encoding/base64"
)

func FormatToKirbi(ticketBase64 string) (result string, err error) {
	ticketData, _  := base64.StdEncoding.DecodeString(ticketBase64)
	last_kirbiData, err := asn1.Marshal(ticketData)
	
	kirbiHeader := []byte{0x76, 0x82} // Kerberos ticket ASN.1 header
	length := len(ticketData)
	lengthBytes := []byte{byte(length >> 8), byte(length & 0xFF)}
	kirbiData := append(kirbiHeader, last_kirbiData...)
	
	kirbiData = append(kirbiData, ticketData...)
	kirbiData = append(kirbiData, lengthBytes...)
	
	if err != nil {
		panic(err)
	}
	result = base64.StdEncoding.EncodeToString(kirbiData)
	return
}
