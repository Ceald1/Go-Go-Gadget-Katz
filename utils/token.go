package utils

import (
	"golang.org/x/sys/windows"
)

func Elevate(winToken windows.Token) {
	// Elevate win token
	err := SetTokenInformation(winToken, windows.TokenElevationType, windows.TokenElevationTypeFull)
}

