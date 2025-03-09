package main

import (
	// "fmt"
	// "katz/katz/modules"
	// "katz/katz/style"
	// "katz/katz/utils"
	// "log"
	// "strings"
	// "fmt"
	"encoding/base64"
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
		tickData, err := test.TGT("test.local", "Administrator", "password", "test.kirbi")
		if err != nil {
			panic(err)
		}
		tick, err := test.FormatToKirbi(tickData)
		if err != nil {
			
			fmt.Println(err)
		}
		fmt.Println(tick)
		decoded, _ := base64.StdEncoding.DecodeString(tick)
		os.WriteFile("test.kirbi", decoded, 0644)
		// test.OutputTick(tickData, "Administrator", "test.local")
		// fmt.Println(tgt, err)
	}
}