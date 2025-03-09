#!/bin/bash

# Ensure UPX is installed
if ! command -v upx &> /dev/null
then
    echo "UPX could not be found, please install UPX to continue."
    exit 1
fi

# Ensure Go is installed and available in the path
if ! command -v go &> /dev/null
then
    echo "Go is not installed or not available in the path."
    exit 1
fi

# Ensure mingw-w64 is installed (cross-compiler for Windows)
if ! command -v x86_64-w64-mingw32-gcc &> /dev/null
then
    echo "mingw-w64 is not installed, please install it to continue."
    exit 1
fi

# Create the output directory if it doesn't exist
mkdir -p output

# Change to the output directory
cd output || exit

# Set up the Go cross-compilation environment
export CC=x86_64-w64-mingw32-gcc  # Set the C compiler to the Windows cross-compiler

# Cross-compile Go binary for Windows
CC=x86_64-w64-mingw32-gcc GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" ../

# Check if build was successful
if [ $? -ne 0 ]; then
    echo "Go build failed."
    exit 1
fi

# Compress the executable with UPX (optional)
upx katz.exe

# Check if UPX compression was successful
if [ $? -eq 0 ]; then
    echo "Build and compression successful!"
else
    echo "UPX compression failed."
    exit 1
fi
