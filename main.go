package main

import (
	// "fmt"
	// "katz/katz/modules"
	// "katz/katz/style"
	// "katz/katz/utils"
	// "log"
	// "strings"
	// "fmt"

	"fmt"
	"katz/katz/cli"
	test "katz/katz/modules/kerb"
	"os"
)


func main() {
	args := os.Args
	if len(args) <= 1{
	cli.Run()
	}else {

		ticketData, err := test.TGT("test.local", "Administrator", "password")
		if err != nil {
			panic(err)
		}
		fmt.Println(ticketData)
	}
}