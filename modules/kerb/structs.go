package kerb


import "unsafe"

// import (
// 	"fmt"
// 	"unsafe"
// )

// "encoding/asn1"

type krb5int32 int32
type krb5uint32 uint32
type Realm string

type KRB_CRED struct {
	pvno	   int `asn1:"explicit,tag:0"`
	msg_type   int `asn1:"explicit,tag:1"`
	tickets    SequenceOfTicket `asn1:"explicit,tag:2"`
	enc_part   EncryptedData `asn1:"explicit,tag:3"`
}


type SequenceOfTicket struct {
	Tickets []Ticket `asn1:"explicit,tag:0"`
}
type EncryptedData struct {
	etype krb5int32 `asn1:"explicit,tag:0"`
	kvno  krb5uint32 `asn1:"explicit,tag:1"`
	cipher []byte `asn1:"explicit,tag:2"`
}

type Ticket struct {
	tkt_vno krb5int32 `asn1:"explicit,tag:0"`
	realm   Realm `asn1:"explicit,tag:1"`
	sname   PrincipalName `asn1:"explicit,tag:2"`
	enc_part EncryptedData `asn1:"explicit,tag:3"`
}
type PrincipalName struct {
	name_type krb5int32 `asn1:"explicit,tag:0"`
	name_string []string `asn1:"explicit,tag:1"`
}

type KERB_RETRIEVE_TKT_RESPONSE struct {
	Ticket KERB_EXTERNAL_TICKET
}

type PVOID unsafe.Pointer
type ULONG uint32
type LARGE_INTEGER uint32
type USHORT uint16
type c_char rune
type LONG uint32

type KERB_EXTERNAL_TICKET struct {
	ServiceName         PVOID
	TargetName          PVOID
	ClientName          PVOID
	DomainName          LSA_UNICODE_STRING
	TargetDomainName    LSA_UNICODE_STRING
	AltTargetDomainName LSA_UNICODE_STRING
	SessionKey          KERB_CRYPTO_KEY
	TicketFlags         ULONG
	Flags               ULONG
	KeyExpirationTime   LARGE_INTEGER
	StartTime           LARGE_INTEGER
	EndTime             LARGE_INTEGER
	RenewUntil          LARGE_INTEGER
	TimeSkew            LARGE_INTEGER
	EncodedTicketSize   ULONG
	EncodedTicket       PVOID
}

type LSA_UNICODE_STRING struct {
	Length        USHORT
	MaximumLength USHORT
	Buffer        *c_char
}

type KERB_CRYPTO_KEY struct {
	KeyType LONG
	Length  ULONG
	Value   PVOID
}

func (k *KERB_CRYPTO_KEY) to_dict() map[string]interface{} {
	return map[string]interface{}{
		"KeyType": k.KeyType,
		"Length": k.Length,
		"Value": k.Value,
	}
}
func (k *KERB_EXTERNAL_TICKET) Get_data() map[string]interface{} {
	return map[string]interface{}{
		"Key": k.SessionKey.to_dict(),
		"Ticket": k.EncodedTicket,
	}
}