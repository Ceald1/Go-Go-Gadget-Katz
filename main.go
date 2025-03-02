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
	key,err := lib.SAM(system)
	if err != nil {
		err = fmt.Errorf(style.ErrorTextStyle.Render(err.Error()))
		panic(err)
	}
	fmt.Println(key.ReadSubKeyNames(-1))

	
	
}