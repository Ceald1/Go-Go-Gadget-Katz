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
		// t, err := test.PKGInfo()
		// fmt.Printf("%s\n\n%v", t, err)
		err := test.TGT("test.local", "Administrator", "password", "test.kirbi")
		if err != nil {
			fmt.Println(err)
		}
		// fmt.Println(tgt, err)
	}
}