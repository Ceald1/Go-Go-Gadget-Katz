package lib

// Referenced from: https://gist.github.com/thewh1teagle/f9d73348f326b332cd0cdb6c35b7e724/revisions

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32                    = syscall.NewLazyDLL("advapi32.dll")
	procImpersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf            = advapi32.NewProc("RevertToSelf")
	ntdll                       = syscall.NewLazyDLL("ntdll.dll")
	procRtlAdjustPrivilege      = ntdll.NewProc("RtlAdjustPrivilege")
)

func enablePrivilege() error {
	var privilege uint32 = 20
	var previousValue uint32 = 0

	ret, _, _ := procRtlAdjustPrivilege.Call(
		uintptr(privilege),
		uintptr(1),
		uintptr(0),
		uintptr(unsafe.Pointer(&previousValue)),
	)

	if ret != 0 {
		return fmt.Errorf("RtlAdjustPrivilege failed with status: %x", ret)
	}

	return nil
}

func findSystemProcess() (*windows.Handle, error) {
	h, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot failed: %v", err)
	}
	defer windows.CloseHandle(h)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	if err = windows.Process32First(h, &pe); err != nil {
		return nil, fmt.Errorf("Process32First failed: %v", err)
	}

	systemProcesses := []string{"lsass.exe", "winlogon.exe", "services.exe"}

	for {
		name := windows.UTF16ToString(pe.ExeFile[:])
		for _, procName := range systemProcesses {
			if name == procName {
				handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pe.ProcessID)
				if err != nil {
					return nil, fmt.Errorf("OpenProcess failed for %s: %v", procName, err)
				}
				return &handle, nil
			}
		}

		err = windows.Process32Next(h, &pe)
		if err != nil {
			if err == syscall.ERROR_NO_MORE_FILES {
				break
			}
			return nil, fmt.Errorf("Process32Next failed: %v", err)
		}
	}

	return nil, fmt.Errorf("No suitable system process found")
}

func getSystemToken() (windows.Token, error) {
	if err := enablePrivilege(); err != nil {
		return 0, fmt.Errorf("failed to enable privileges: %v", err)
	}

	processHandle, err := findSystemProcess()
	if err != nil {
		return 0, fmt.Errorf("failed to find a system process: %v", err)
	}
	defer windows.CloseHandle(*processHandle)

	var token windows.Token
	err = windows.OpenProcessToken(*processHandle, windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &token)
	if err != nil {
		return 0, fmt.Errorf("OpenProcessToken failed: %v", err)
	}

	var duplicatedToken windows.Token
	err = windows.DuplicateTokenEx(token, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation, windows.TokenPrimary, &duplicatedToken)
	if err != nil {
		token.Close()
		return 0, fmt.Errorf("DuplicateTokenEx failed: %v", err)
	}
	token.Close()

	return duplicatedToken, nil
}

func impersonateSystem() (windows.Token, error) {
	token, err := getSystemToken()
	if err != nil {
		return 0, err
	}

	ret, _, err := procImpersonateLoggedOnUser.Call(uintptr(token))
	if ret == 0 {
		token.Close()
		return 0, fmt.Errorf("ImpersonateLoggedOnUser failed: %v", err)
	}

	return token, nil
}

func getTokenUser(token windows.Token) (string, error) {
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("GetTokenUser failed: %v", err)
	}
	sid := tokenUser.User.Sid.String()

	return sid, nil
}

func getCurrentProcessTokenUser() (string, error) {
	var token windows.Token
	// Get the current process token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return "", fmt.Errorf("OpenProcessToken failed: %v", err)
	}
	defer token.Close()

	// Retrieve the token user
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("GetTokenUser failed: %v", err)
	}

	// Convert SID to a readable string
	sid := tokenUser.User.Sid.String()
	return sid, nil
}

func GetSystem() (windows.Token, error) {
	_, err := getCurrentProcessTokenUser()
	if err != nil {
		return 0, fmt.Errorf("Failed to get current process token user: %v", err)
	}
	// log.Printf("Current process user before impersonation: %s", currentUser)

	token, err := impersonateSystem()
	if err != nil {
		return 0, fmt.Errorf("failed to impersonate SYSTEM: %v", err)
	}

	_, err = getTokenUser(token)
	if err != nil {
		return 0, fmt.Errorf("Failed to retrieve impersonated token user: %v", err)
	}
	return token, nil
}

func InjectToken(token windows.Token) error {
	_, _, err := procImpersonateLoggedOnUser.Call(uintptr(token))
	if err != nil && err.Error() != "The operation completed successfully." {
		return fmt.Errorf("failed to impersonate logged on user: %v", err)
	}
	return nil
}