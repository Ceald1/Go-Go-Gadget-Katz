#!/bin/bash

mkdir output
cd output
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" ../ 
upx katz.exe