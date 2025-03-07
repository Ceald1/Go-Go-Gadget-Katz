package kerb
import (
	"github.com/alexbrainman/sspi"
)

func PKGInfo() (result[]string, err error){
	pkgNames := []string{
		sspi.NTLMSP_NAME,
		sspi.MICROSOFT_KERBEROS_NAME,
		sspi.NEGOSSP_NAME,
		sspi.UNISP_NAME,
	}
	for _, name := range pkgNames{
		pi, err := sspi.QueryPackageInfo(name)
		if err != nil {
			return result, err
		}else if pi.Name != name {
			return result, err
		}else{
			result = append(result, name)
		}
	}
	return
}