#!/bin/bash

mkdir output 2>/dev/null
cd output
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" ../ 
upx katz.exe