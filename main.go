package main

import (
	// "fmt"
	// "katz/katz/modules"
	// "katz/katz/style"
	// "katz/katz/utils"
	// "log"
	// "strings"
	"katz/katz/cli"

)

// func main(){
// 	system, err := utils.GetSystem()
// 	if err != nil {
// 		err = fmt.Errorf(style.ErrorTextStyle.Render(err.Error()))
// 		panic(err)
// 	}
// 	// err = lib.InjectToken(system)
// 	err = utils.InjectToken(system)

// 	err = utils.TestRegAccess(system)
// 	if err != nil {
// 		err = fmt.Errorf(style.ErrorTextStyle.Render(err.Error()))
// 		panic(err)
// 	}
// 	info := style.SuccessTextStyle.Render("\nSYSTEM access!")
// 	log.Println(info)
// 	data, err := modules.DumpSAM(system)
// 	if err != nil {
// 		fmt.Println(err)
// 	}else {
// 		for _, d := range data {
// 			rid := d.Rid
// 			Name := d.Name
// 			nt := d.Nthash
// 			d_str := fmt.Sprint(Name,":",rid,":",nt)
// 			d_str = strings.Replace(d_str, " ", "", -1)
// 			if Name != ""{
// 			fmt.Println(d_str)
// 			}
// 		}
// 	}
// }
func main() {
	cli.Run()
}