package main

import (
	// "fmt"
	// "katz/katz/modules"
	// "katz/katz/style"
	"katz/katz/utils"
	// "log"
	// "strings"
	// "fmt"

	// "encoding/base64"
	"fmt"
	test "katz/katz/modules/kerb"
	// "os"
	// "katz/katz/cli"
)


func main() {
	// args := os.Args
	// if len(args) <= 1{
	// cli.Run()
	// }else {
		systoken, _ := utils.GetSystem()
		defer systoken.Close()
		utils.InjectToken(systoken)

		ticketData, _ := test.TGT("test.local", "Administrator", "password")
		// if err != nil {
		// 	panic(err)
		// }
		fmt.Println(ticketData)

	// }
}