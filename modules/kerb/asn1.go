package kerb

import (
	"encoding/asn1"
	"fmt"
)

// APReq represents an ASN.1-encoded AP-REQ
type APReq struct {
	PVNO     int    `asn1:"tag:0,implicit"`
	MsgType  int    `asn1:"tag:1,implicit"`
	APOptions []byte `asn1:"tag:2,implicit"`
	Ticket   asn1.RawValue `asn1:"tag:3,implicit"` // Extract raw ticket bytes
}

// Ticket represents a Kerberos Ticket
type Ticket struct {
	TktVno  int           `asn1:"tag:0,implicit"`
	Realm   string        `asn1:"tag:1,implicit"`
	SName   PrincipalName `asn1:"tag:2,implicit"`
	EncPart EncryptedData `asn1:"tag:3,implicit"`
}

// PrincipalName represents the service principal name
type PrincipalName struct {
	NameType   int32    `asn1:"tag:0,implicit"`
	NameString []string `asn1:"tag:1,implicit,sequence"`
}

// EncryptedData represents encrypted Kerberos data
type EncryptedData struct {
	EType  int32  `asn1:"tag:0,implicit"`
	KVNO   int32  `asn1:"tag:1,optional,implicit"`
	Cipher []byte `asn1:"tag:2,implicit"`
}

// ParseAPReq extracts the Ticket from an AP-REQ message
func ParseAPReq(data []byte) (*Ticket, error) {
	var apReq APReq
	_, err := asn1.Unmarshal(data, &apReq)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AP-REQ: %v", err)
	}

	fmt.Println("Extracted Ticket Bytes:", apReq.Ticket.FullBytes) // Debugging output

	// Decode the extracted ticket
	var ticket Ticket
	_, err = asn1.Unmarshal(apReq.Ticket.FullBytes, &ticket)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Ticket: %v", err)
	}

	return &ticket, nil
}