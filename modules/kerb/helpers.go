package kerb

import (
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)
const (
	windowsToUnixEpochIntervals = 116444736000000000
	ProcessQueryInformation = 0x0400
	ProcessVmRead           = 0x0010
)


func FileTimeToTime(fileTime int64) time.Time {
	nsec := (fileTime - windowsToUnixEpochIntervals) * 100
	return time.Unix(0, nsec).Local()
}

func IsHighIntegrity() bool {
	var token windows.Token
	h := windows.CurrentProcess()
	err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	var isElevated uint32
	var returnedLen uint32
	err = windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&isElevated)), uint32(unsafe.Sizeof(isElevated)), &returnedLen)
	if err != nil {
		return false
	}

	return isElevated != 0
}
func IsSystem() bool {
	// Try thread token first
	var token windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
	if err != nil {
		// fmt.Printf("OpenThreadToken failed: %v, falling back to process token\n", err)
		// Fall back to process token
		procHandle := windows.CurrentProcess()
		err = windows.OpenProcessToken(procHandle, windows.TOKEN_QUERY, &token)
		if err != nil {
			// fmt.Printf("OpenProcessToken failed: %v\n", err)
			return false
		}
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil {
		// fmt.Printf("GetTokenUser failed: %v\n", err)
		return false
	}

	systemSid, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		// fmt.Printf("CreateWellKnownSid failed: %v\n", err)
		return false
	}

	// userSidStr := user.User.Sid.String()
	// systemSidStr := systemSid.String()
	// fmt.Printf("Comparing current token SID: %s with SYSTEM SID: %s\n", userSidStr, systemSidStr)

	return windows.EqualSid(user.User.Sid, systemSid)
}
func GetSystem() bool {
	isHighIntegrity := IsHighIntegrity()
	if !isHighIntegrity {
		// fmt.Println("Not running with high integrity")
		return false
	}

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		// fmt.Printf("CreateToolhelp32Snapshot failed: %v\n", err)
		return false
	}
	defer windows.CloseHandle(snapshot)

	var procEntry windows.ProcessEntry32
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))
	if err := windows.Process32First(snapshot, &procEntry); err != nil {
		// fmt.Printf("Process32First failed: %v\n", err)
		return false
	}

	for {
		processName := windows.UTF16ToString(procEntry.ExeFile[:])
		if processName == "winlogon.exe" {
			handle, err := windows.OpenProcess(
				ProcessQueryInformation|ProcessVmRead,
				false,
				procEntry.ProcessID,
			)
			if err != nil {
				// fmt.Printf("OpenProcess failed: %v\n", err)
				return false
			}
			defer windows.CloseHandle(handle)

			// fmt.Printf("winlogon handle obtained\n")

			var token windows.Token
			err = windows.OpenProcessToken(handle, windows.TOKEN_DUPLICATE, &token)
			if err != nil {
				// fmt.Printf("OpenProcessToken failed: %v\n", err)
				return false
			}
			defer token.Close()

			// fmt.Printf("token obtained: %v\n", token)

			var duplicateToken windows.Token
			err = windows.DuplicateTokenEx(
				token,
				windows.MAXIMUM_ALLOWED,
				nil,
				windows.SecurityImpersonation,
				windows.TokenImpersonation,
				&duplicateToken,
			)
			if err != nil {
				// fmt.Printf("DuplicateTokenEx failed: %v\n", err)
				return false
			}
			defer duplicateToken.Close()

			fmt.Printf("duplicate token obtained: %v\n", duplicateToken)

			ret, _, _ := procImpersonateLoggedOnUser.Call(uintptr(duplicateToken))
			if ret == 0 {
				// fmt.Printf("ImpersonateLoggedOnUser failed with error: %v\n", errNo)
				return false
			}

			// Verify impersonation worked
			isSystem := IsSystem()
			if !isSystem {
				// fmt.Println("Impersonation failed - not running as SYSTEM")
				return false
			}

			// fmt.Println("Successfully impersonated SYSTEM")
			return true
		}

		err = windows.Process32Next(snapshot, &procEntry)
		if err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			// fmt.Printf("Process32Next failed: %v\n", err)
			return false
		}
	}

	// fmt.Println("Failed to find winlogon.exe")
	return false
}