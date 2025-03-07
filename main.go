package main

import (
	// "fmt"
	// "katz/katz/modules"
	// "katz/katz/style"
	// "katz/katz/utils"
	// "log"
	// "strings"
	"fmt"
	"katz/katz/cli"
	test "katz/katz/modules/kerb"
	"os"
)


func main() {
	args := os.Args
	if len(args) < 1{
	cli.Run()
	}else {
		t, err := test.PKGInfo()
		fmt.Printf("%s\n\n%v", t, err)
	}
}