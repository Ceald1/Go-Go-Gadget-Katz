package utilfunctions

import "github.com/google/uuid"

const (
	DS_AVOID_SELF                   = 0x00004000
	DS_BACKGROUND_ONLY              = 0x00000100
	DS_DIRECTORY_SERVICE_PREFERRED  = 0x00000020
	DS_DIRECTORY_SERVICE_REQUIRED   = 0x00000010
	DS_DIRECTORY_SERVICE_6_REQUIRED = 0x00080000
	DS_DIRECTORY_SERVICE_8_REQUIRED = 0x00200000
	DS_FORCE_REDISCOVERY            = 0x00000001
	DS_GC_SERVER_REQUIRED           = 0x00000040
	DS_GOOD_TIMESERV_PREFERRED      = 0x00002000
	DS_IP_REQUIRED                  = 0x00000200
	DS_IS_DNS_NAME                  = 0x00020000
	DS_IS_FLAT_NAME                 = 0x00010000
	DS_KDC_REQUIRED                 = 0x00000400
	DS_ONLY_LDAP_NEEDED             = 0x00008000
	DS_PDC_REQUIRED                 = 0x00000080
	DS_RETURN_DNS_NAME              = 0x40000000
	DS_RETURN_FLAT_NAME             = 0x80000000
	DS_TIMESERV_REQUIRED            = 0x00000800
	DS_TRY_NEXTCLOSEST_SITE         = 0x00040000
	DS_WRITABLE_REQUIRED            = 0x00001000
	DS_WEB_SERVICE_REQUIRED         = 0x00100000
)

type DOMAIN_CONTROLLER_INFO struct {
	DomainControllerName    string
	DomainControllerAddress string
	DomainControllerAddressType uint32
	DomainGuid              uuid.UUID
	DomainName              string
	DnsForestName           string
	Flags                   uint32
	DcSiteName              string
	ClientSiteName          string
}