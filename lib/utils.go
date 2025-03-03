package lib

import (
	// "bytes"
	"fmt"
	// "strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func parseSecret(){}


func getServiceUser(token windows.Token) (result string, err error){
	err = InjectToken(token) // inject token
    if err != nil {
        return "", fmt.Errorf("failed to inject token: %w", err)
    }
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`, registry.READ)
	fmt.Println(key.ReadSubKeyNames(-1))
	return "",nil
}