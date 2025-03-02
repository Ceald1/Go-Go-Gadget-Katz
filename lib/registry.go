package lib

import (
	"fmt"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows"
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

func SAM(token windows.Token) (registry.Key, error){
	err := InjectToken(token)
	if err != nil {
		return 0,fmt.Errorf("failed to impersonate logged on user: %v", err)
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SAM\SAM`, registry.READ)
	if err != nil {
		return 0,fmt.Errorf("failed to open registry key: %v", err)
	}
	return key, nil
}